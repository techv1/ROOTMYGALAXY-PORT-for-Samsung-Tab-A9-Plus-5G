# GhostLock Kit — vivo iQOO Neo9S Pro (V2339FA / MT6989)

适用于 **vivo iQOO Neo9S Pro（V2339FA，MediaTek MT6989）** 的 GhostLock 一键 root 套件。
本仓库包含：**MCAST transport 移植补丁**、一键脚本、完整分析文档；完整可运行套件（含二进制与 KernelSU）见 [Releases](../../releases)。

> Device: vivo iQOO Neo9S Pro (V2339FA / PD2339, MT6989)
> Firmware: PD2339_A_16.2.12.1.W10.V000L1 (Android 16)
> Kernel: 6.1.145-android14-11-maybe-dirty
> Vulnerability: CVE-2026-43499 (futex PI requeue UAF)
> **For device owners / security research only. Use on your own device.**

## 亮点（TL;DR）

- 原版 GhostLock 的 TCP/pselect transport 在该机型（厂商 +pgo,+bolt 内核）上栈帧错位，**必崩**；
  本移植发现并改用了 `setsockopt(SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, 0x108)` 的 **0x108 字节栈拷贝** 作为投毒原语，完整覆盖 stale `rt_mutex_waiter`，打通全链（W1→W2→W3→KernelSU）。
- 实测**成功率技巧**：设备**重启后停留在锁屏、不要解锁**，此时系统用户态服务最少，几乎一次成功。
- 采用**官方 KernelSU v3.3.0 成对版本**（管理器 32601 + 驱动 32601），无版本不匹配告警。
  （实测 ReSukiSU 4.2.0-rc1 管理器在本机会打开即内核卡死，已弃用。）

## 快速开始

1. 从 [Releases](../../releases) 下载 `ghostlock-kit-20260913.zip` 并解压。
2. 手机 USB 连接电脑（已授权 adb）。
3. 运行：

```powershell
cd <解压目录>\ghostlock-kit
powershell -ExecutionPolicy Bypass -File .\scripts\run-at-lockscreen.ps1 -Reboot
```

4. 看到 `[+] Root 成功！` 即完成（**运行期间不要解锁手机**）。验证：

```bash
adb shell su -c id
# uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

> 失败会触发内核 panic 自动重启，脚本会自动等待并重试（成功率约 25–30%/次；锁屏时机几乎一次成功）。
> root 为**临时**（KernelSU late-load），手机重启后需重跑脚本。

## 仓库结构

```text
.
├── scripts/
│   ├── run-at-lockscreen.ps1   # 一键：重启→锁屏等待→推送校验→运行→自动重试（推荐）
│   └── retry-if-needed.ps1     # 通用重试（不强制重启）
├── src/
│   └── ghostlock-mcast.patch   # 源码改动（基线 ghostlock-app @ 50d2b72）
├── docs/                       # 分析文档（利用报告/transport 分析/waiter 与 PI walk/设备手册/排查记录）
└── LICENSE                     # Apache-2.0（继承上游）
```

二进制与完整套件（`files/ghostlock`、`files/ksud`、`files/offsets.json`、KernelSU APK）不放在 git 仓库内，
请从 [Releases](../../releases) 下载 `ghostlock-kit-20260913.zip`。

## Release 资产与校验

| 资产 | 说明 | SHA-256 |
|------|------|---------|
| `ghostlock-kit-20260913.zip` | 完整套件（脚本+二进制+APK+文档） | `df547f6b2852a0d86582958e049ef5a44599a5a91ce0dace2162fb7d0fcab11d` |

套件内关键文件（MD5）：

| 文件 | MD5 |
|------|-----|
| `files/ghostlock`（利用程序） | `e581609ed114d33efa3b8a1958f85637` |
| `files/ksud`（官方 KernelSU v3.3.0 用户态） | `de059ed8ffd896129a0a4bbe338c946a` |
| `files/offsets.json`（本机型偏移） | `a2498197161b01bdcc5dffc0614fbfbd` |

## 原理简述

- **漏洞**：CVE-2026-43499——waiter 线程从 `FUTEX_WAIT_REQUEUE_PI` 返回后，`task->pi_blocked_on` 仍悬挂指向其栈上的 `rt_mutex_waiter`。
- **投毒（本移植的核心）**：`setsockopt(SOL_IP, MCAST_JOIN_SOURCE_GROUP, buf, 0x108)` 使 `do_ip_setsockopt` 执行
  `memset(0x108) + copy_from_user(0x108)`，拷贝区间 `[S'−0x338, S'−0x230)` 完整覆盖该 waiter（waiter 位于缓冲偏移 `0x60`）；
  置 `buf[8]=0` 使族校验失败，syscall 在拷贝后干净返回。
- **触发**：consumer 线程 `sched_setattr` → `rt_mutex_adjust_prio_chain` 读取伪造 waiter → `rb_erase` left-only relink
  形成 `*(target) := value` 写原语。
- **利用链**：W1 关 SELinux → W2 子进程 `cred = init_cred` → W3 清 seccomp（shell 流程跳过）→ root 脚本 late-load KernelSU。
- **失败机理**：skb 页回收竞争偶发失败 → walk 崩溃（内核 panic 自动重启），属概率事件；锁屏状态命中率最高。

详见 [`docs/`](docs/)（含证据链、反汇编分析与崩溃现场）。

## 常见问题

| 问题 | 处理 |
|------|------|
| 失败后手机重启 | 正常（概率事件）；重启后**不要解锁**，直接重跑脚本 |
| 管理器显示"未安装/未工作" | 先确认 `su -c id` 可用；打开管理器刷新，**不要**划掉/强停 |
| root 重启后消失 | 正常（late-load 非持久）；重跑脚本 |
| 想用 ReSukiSU | 本机不可用（打开管理器即卡死重启），如需请另配匹配版本 |
| 系统更新后 | `offsets.json` 可能失效，需重新生成/导入 |

## 构建（源码重建）

```bash
# 基线：ghostlock-app @ 50d2b72（含 PR#127）
git clone https://github.com/YuKongA/ghostlock-app.git
cd ghostlock-app && git checkout 50d2b72
git apply /path/to/src/ghostlock-mcast.patch
make NDK_ROOT=<your-ndk> ghostlock
```

补丁内容：MCAST transport（`do_mcast_fake_lock_route`）、路由选择、observe/预建逻辑、
`GHOSTLOCK_WALK_LOG`（consumer 侧 walk 定位）、root 脚本 pstore 备份、`GHOSTLOCK_SKIP_VR`。

## 致谢与许可

- 上游项目：[YuKongA/ghostlock-app](https://github.com/YuKongA/ghostlock-app)（Apache-2.0）
- [KernelSU](https://github.com/tiann/KernelSU)（GPLv3）——本套件中的 `ksud` 与 APK 来自官方 v3.3.0 发布，版权归其作者所有
- [ReSukiSU](https://github.com/ReSukiSU/ReSukiSU)（GPLv3）——早期适配参考
- 本仓库改动以 Apache-2.0 发布（见 [LICENSE](LICENSE)）

## 免责声明

仅供设备所有者对**自有设备**进行本地安全研究与自用 root；请勿用于任何未授权设备或非法用途。
使用本工具可能造成设备不稳定或数据风险，请自行备份并承担相应后果。
