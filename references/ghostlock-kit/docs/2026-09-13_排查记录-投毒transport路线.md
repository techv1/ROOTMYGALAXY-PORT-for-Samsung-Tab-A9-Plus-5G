# 投毒 transport 路线排查记录

> 日期：2026-09-13
> 关联：[利用报告](2026-09-13_利用报告-iqooneo9s-ghostlock.md) · [历史调试报告 v3](../build/GhostLock/DEBUG_REPORT.md)
> 结论：在 8 种候选栈拷贝原语中，只有 MCAST source-group（0x108 字节 @ `do_ip_setsockopt sp+0x18`）能达到 stale waiter 的深度；TCP/pselect 等均差 0xF8~0x2D0。

## 1. 问题定义

利用需要在 waiter 线程的内核栈上重写一个固定位置的 `rt_mutex_waiter`（`task->pi_blocked_on` 悬挂目标）。约束：

1. 窗口极短：`CONFIG_INIT_STACK_ALL_ZERO=y`，线程返回用户态后任何覆盖该区间的 syscall 都会清零/破坏残留；投毒 syscall 与 walk 触发必须在同一“尝试”内完成。
2. 深度固定：waiter 位于系统调用函数入口 S' 下方 `0x2D8`；投毒拷贝必须覆盖 `[S'−0x2D8, S'−0x280)`（至少 `lock +0x38`、`prio +0x44`、`deadline +0x48`、树节点）。
3. 内容可控：拷贝必须由 `copy_from_user` 且长度/内容可由调用方控制。

## 2. 统一基准（重要）

历史记录中数字互相矛盾，根因是**基准不统一**。本文件统一采用：

| 基准 | 定义 | 本机值（panic #8 实测） |
|------|------|--------------------------|
| `top` | 内核栈顶（栈基址 + THREAD_SIZE 16K） | `ffffffc09bad9000` |
| `entry` | pt_regs 底 = `top−0x110` | `ffffffc09bad8ef0` |
| `S'` | 系统调用函数入口（`__arm64_sys_*` 的 SP），= `entry − 公共 SVC 路径帧` | `top−0x1E0`（公共路径约 0xD0，未逐帧核对） |
| waiter | stale `rt_mutex_waiter` | `top−0x4B8 = S'−0x2D8` |

> 历史 “TCP zc −720 vs waiter −728 精确对齐”的结论混用了基准（去程与回程、是否含间接 dispatch 帧），且 `sk_getsockopt` 0xf0 帧在本次复核中被证伪（实际链为 0x220，见 §3.2）。

## 3. 候选总表

| # | 原语 | 链/帧 | 最深可控拷贝落点 | 相对 waiter | 判定 |
|---|------|-------|------------------|-------------|------|
| 1 | pselect `core_sys_select` fd_set | futex 768 / pselect 592 | word0 = entry−512 | 浅 216 | ❌ 不可行（无 word 偏移可补） |
| 2 | `getsockopt(TCP_ZEROCOPY_RECEIVE)` | 0x220 | `do_tcp_getsockopt sp+0x40` = S'−0x1E0 | 浅 **0xF8** | ❌ 实测 NULL-lock panic |
| 3 | `sendmsg` msg_control cmsg | `0x10+0x1c0+0x80` | `____sys_sendmsg sp+0` = entry−592 | 浅 344 | ❌ 且 ≥37B 走 kmalloc |
| 4 | `recvmmsg` | `0x60+0x190` + `____sys_recvmsg 0xe0` | 内层 iov 栈缓冲 ≈ entry−712 | 浅 224 | ❌ 与 TCP 同量级 |
| 5 | `io_uring_enter` | `0xc0` + … | `io_uring_getevents_arg` sp+0x20 = entry−160 | 浅 776 | ❌ |
| 6 | `epoll_wait/pwait2` | `0x60` / `do_epoll_wait 0x110` | timespec sp+0x8 = entry−88；events 为 copy_to_user | 浅 848+ | ❌ 方向错误 |
| 7 | `do_tcp_setsockopt` | 0x80 | sp+0x8 | 浅 | ❌ |
| 8 | **MCAST source-group setsockopt** | **0x350** | **`do_ip_setsockopt sp+0x18` = S'−0x338（区间 S'−0x338…S'−0x230）** | **覆盖 waiter（waiter=+0x60）** | ✅ **实测成功** |

## 4. 关键候选细节

### 4.1 TCP zerocopy（失败根因）

本次复核的完整链（E-003）：

| 层 | 帧 |
|----|----|
| `__arm64_sys_getsockopt` | 0x10 |
| `__sys_getsockopt` | 0x60 |
| `sock_common_getsockopt` | 0x10 |
| `tcp_getsockopt` | 0x10 |
| `do_tcp_getsockopt` | 0x190 |
| **合计** | **0x220** |

`TCP_ZEROCOPY_RECEIVE` 路径把用户 `struct tcp_zerocopy_receive`（≤0x40 字节）拷到 `do_tcp_getsockopt` 帧 `sp+0x40`，即 **S'−0x1E0**；waiter 在 S'−0x2D8，需要 zc 偏移 −0xC8（不可能）→ `waiter->lock` 保持 0。panic 现场 `x24=0` 与之一致。

> 历史测量误把 `sk_getsockopt` 0xf0 计入链（0x310），得出 “−720 与 −728 精确对齐”的结论；实测 8 次 panic 后由崩溃现场回归，确认投毒从未命中。本次以 `getsock_dis.txt` 逐条反汇编纠正为 0x220/0xF8。

### 4.2 pselect

- futex 链 768（`112+208+448`），pselect 链 592（`144+448`，`do_pselect` 被 PGO 内联，无独立符号）。
- fd_set 拷贝 word0 位于 `entry−512`，waiter 在 `entry−728`：差 **216**；fd_set 的字索引只能平移 8 字节单位，无法桥接（需要 −27 个字）。
- 结论：该路由在本内核几何不可行（PR#127 的 pselect 修复针对的是能在 GKI 几何下命中的设备）。

### 4.3 sendmsg / recvmmsg（DEBUG_REPORT Phase 2e/2f 复述）

- sendmsg 小 cmsg（<37B）拷贝到 `____sys_sendmsg sp+0`（entry−592）；大 cmsg 走 `sock_kmalloc`（堆，不可用）。
- recvmmsg 最深用户可控缓冲 ≈ entry−712（`____sys_recvmsg` 栈 iov），与 TCP zc 同量级，仍浅 224。
- io_uring/epoll 要么太浅，要么方向为 `copy_to_user`。

## 5. MCAST 的发现路径

1. 排除所有“已知浅”候选后，改在 `do_ip_setsockopt`（IPv4 setsockopt 主入口）中搜索**深拷贝且长度固定**的 `copy_from_sockptr` 调用。
2. 跳表（base `0xed7628`，表 `0x12c9224`）显示 source-group 家族 optname（43/44/46/47）指向同一分支 `0xed7684`；直接反汇编确认：`memset(sp+0x18, 0, 0x108)` + `copy_from_sockptr(sp+0x18, optval, 0x108)`。
3. 链几何（0x350）与 futex waiter（0x300+0x28）对表：waiter 恰好落在拷贝缓冲偏移 **0x60**，且 0x108 长度覆盖 waiter 全字段（还多出前后余量）。
4. 校验路径允许“拷贝后早退”：零化 `gsr_group.ss_family` → 返回 `-EADDRNOTAVAIL`，无组播副作用。
5. observe 冒烟（`errno=99` 恒定 32 次、无 panic）→ live 实测 `mcast route won seq=16` → 全链打通。

## 6. 失败 Panic 汇总（2026-09-08 ~ 09-10）

| 阶段 | 路线 | 次数 | 签名 |
|------|------|------|------|
| 初始移植 | TCP ×5 + pselect ×1 | 6 | `_raw_spin_trylock+0x1c ← rt_mutex_adjust_prio_chain+0x130`，x24=0 |
| PR#115 验证 | TCP（col 验证版本） | 1（#7） | 同上 |
| preinit walk | TCP（预建资源） | 1（#8） | 同上；新增实测 waiter 栈地址 |
| 变量排除 | phys 三态 × 路由 × app/adb × 大小核 × hold×100 | — | 签名不变 → 非时序/非环境 |

现场文件：`tmpbuild/ramoops_p2..p8_preinit.txt`（E-009 为 `ramoops_p8_preinit.txt`）。

## 7. 经验与复用边界

1. **几何必须按内核实测**：厂商 +pgo,+bolt 构建与 GKI 参照可差数百字节；任何“参考设备可用”的路线在本机都需要重新对表。
2. **明确基准**：记录“相对 top / entry / S'”三者中的哪一个；混用会产生 ±0xD0 级的错误结论。
3. **优先固定长度深拷贝**：`memset + copy_from_sockptr(定长)` 是理想形态；MCAST 家族的 `struct group_source_req`（0x108）在 6.1 上是少见的“够深”原语。
4. **payload 形状与投毒方式解耦**：本次只替换投毒通道（zc → MCAST），waiter 内容沿用已验证的 pselect 值形状，显著降低试错成本。
5. **零成本冒烟**：observe 模式 + 错误码（`-EADDRNOTAVAIL`）可在不触发 walk 的情况下验证拷贝路径可达。
6. **MCAST 原语可移植**：其他内核上如遇同类栈几何问题，可优先测量 `do_ip_setsockopt` 的 source-group 分支（注意：换内核需重新测链长与缓冲偏移）。
