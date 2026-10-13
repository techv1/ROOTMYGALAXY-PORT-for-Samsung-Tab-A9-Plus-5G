# GhostLock 项目文档索引（iQOO Neo9S Pro / MT6989）

> 更新：2026-09-13
> 目标设备：vivo V2339FA（iQOO Neo9S Pro，MT6989 / Dimensity 9300+）
> 状态：**已取得 root**（KernelSU late-load 成功，`su` 可用；late-load 非持久，重启后需重跑）

本目录汇总 GhostLock（CVE-2026-43499，futex PI 等待者 UAF 利用）在该设备上的移植、核心原语分析与操作手册。信息来源于本机反汇编测量、panic 现场（pstore/ramoops）与实测运行日志。

## 文档

| 文档 | 内容 |
|------|------|
| [利用报告](2026-09-13_利用报告-iqooneo9s-ghostlock.md) | 结果、证据链（E/F/P）、时间线、复现命令与遗留问题 |
| [MCAST transport 技术分析](2026-09-13_技术分析-mcast-transport.md) | `setsockopt` 0x108 栈拷贝原语的链几何、buffer 布点与实现 |
| [waiter 与 PI walk 技术分析](2026-09-13_技术分析-rtmutex-waiter与PI-walk.md) | `rt_mutex_waiter` 布局、`rt_mutex_adjust_prio_chain` 读字段与写原语 |
| [设备与测试手册](2026-09-13_操作手册-iqooneo9s-设备与测试.md) | 构建、推送、运行、日志取证、offsets 导入与排坑 |
| [投毒 transport 路线排查](2026-09-13_排查记录-投毒transport路线.md) | TCP/pselect/sendmsg/recvmmsg 等候选的几何对照与失败原因 |
| [历史调试报告 v3](../build/GhostLock/DEBUG_REPORT.md) | 2026-09-08 ~ 09-10 阶段性排查记录（TCP 几何错位时期，结论已被本文档集修正） |

## 关键结论（一页版）

1. **失败根因**：厂商 +pgo,+bolt 内核改变了栈帧几何，原 TCP `TCP_ZEROCOPY_RECEIVE` transport 的 0x40 字节拷贝落点比 stale waiter 浅 **0xF8**，`waiter->lock` 读 0 → PI walk 在 `_raw_spin_trylock(NULL)` 处 panic（多次复现，签名一致）。
2. **新原语**：`setsockopt(SOL_IP, MCAST_JOIN_SOURCE_GROUP=46, buf, 0x108)` 在 `do_ip_setsockopt` 中执行 `memset(0x108)` + `copy_from_user(0x108)`，拷贝区间 **完整覆盖** stale waiter（waiter 位于拷贝缓冲偏移 `0x60`）。
3. **Payload 形状**：沿用 PR#127 的 compact 6.1 值形状（`tree/pi = {pc=value, right=0, left=target}`、`task=fake_task`、`lock=fake_lock`、`wake_state=3`、`prio=140`），页面布局切到 pselect 模式。
4. **实测结果**：多次 `mcast route won seq=16`；root 脚本以 uid=0 运行；`kernelsu` 模块 Live；`su -c id` → `uid=0(root) ... u:r:ksu:s0`；SELinux 恢复 Enforcing。
5. **KernelSU 配对**：最终采用官方 KernelSU 成对（管理器 v3.3.0/32601 + 官方 APK 提取的 ksud 3.3.0 → 驱动 32601）；ReSukiSU 35061 组合打开管理器会卡死（watchdog），已弃用。运行时机建议 `uptime>5min` 且负载 `<10`（详见操作手册）。

## 快速导航

- 只想复现：见[利用报告 §8](2026-09-13_利用报告-iqooneo9s-ghostlock.md)
- 想看原语原理：见 [MCAST transport](2026-09-13_技术分析-mcast-transport.md) 与 [waiter/PI walk](2026-09-13_技术分析-rtmutex-waiter与PI-walk.md)
- 想搭环境：见[设备与测试手册](2026-09-13_操作手册-iqooneo9s-设备与测试.md)
- 想了解踩过的坑：见[路线排查](2026-09-13_排查记录-投毒transport路线.md)
