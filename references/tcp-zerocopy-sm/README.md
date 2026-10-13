# Investigation is closed. Working fork: https://github.com/soumarcelino/Root-My-Galaxy-SM-S918B

Read this -> https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/issues/160#issuecomment-5227077583


[![Version](https://img.shields.io/badge/version-0.02--research-blue)](https://github.com/Meowkis/tcp-zerocopy-sm/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![License](https://img.shields.io/badge/license-Apache-red)](LICENSE-APACHE)

## Attempts to cause rights elevation w GhostLock via TCP Zerocopy.

### Designed expecially for 5.15.\* samsung kernel

> [!WARNING]
> Do not rely on current payload tests.
> After reviewing the exploit code more carefully, I realized I had misidentified the CVEs associated with the TCP zerocopy path. The standalone payload tests I ran were incorrect.
> Isolated payload tests without the full exploit chain prove nothing. I will update this issue once the complete port is tested.

> [!IMPORTANT]
> The only reliable way to determine if this vector still works on the SM-S918B is to port the full Pixel 9 exploit (including the GhostLock dangling waiter setup, CFI stage, and configfs R/W primitives) and observe whether it reaches main tcp route done=1. I will continue working on this port, but there is no ETA.

> 🚧 **Work in progress (`v0.1`):**  
> Investigating the flow to build porting strategy .

## Project

[`CyberMeowfia/exploit/src/`](CyberMeowfia/exploit/src/) is reference only! Samsung device config was added for testing here and doesn't mean anything. The actual port will be in [`src/`](src/)

## Current target

| Property                     | Value                                                                     |
| ---------------------------- | ------------------------------------------------------------------------- |
| Device                       | Samsung Galaxy S23 Ultra, `dm3q` / SM-S918B                               |
| Build                        | `S918BXXSAFZF5`                                                           |
| Android version              | 16                                                                        |
| Kernel                       | 5.15.189-android13-8-33413713-abS918BXXSAFZF5                             |
| Fingerprint                  | `samsung/dm3qxxx/dm3q:16/BP4A.251205.006/S918BXXSAFZF5:user/release-keys` |
| Architecture                 | ARM64                                                                     |
| Kernel text base             | `0xffffffc008000000`                                                      |
| Physical base                | `0x80000000`                                                              |
| Physical kernel load address | `0x80080000`                                                              |

Test payloads are stored in [`payloads/`](payloads/).
The active constants are stored in [`target.h`](target.h).

You can verify if your S23 family phone is vulnerable by compiling and running [`test_tcp_zc.c`](payloads/test_tcp_zc.c)

**Compiling**

```sh
export NDK=~/Android/Sdk/ndk/android-ndk-r29 #path_to_ndk

$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang -static -O2 test_tcp_zc.c -o test_tcp_z
```

**Running the penetration test**

```sh
adb push test_tcp_zc /data/local/tmp/
adb shell chmod +x /data/local/tmp/test_tcp_zc
adb shell /data/local/tmp/test_tcp_zc
```

**What should be happened**

```
If kernel panics then is vulnerable to this exploit!
```

## Kimi's analyzed fops.c

<details>
<summary>Click to view</summary>

| Step | Stage   | Syscall / Primitive                | What Happens                                              | Data / Target                                                                  |
| ---- | ------- | ---------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------ |
| 1    | Setup   | —                                  | Validate `page_base`, `fake_lock`, `fake_fops`            | Abort if any is zero                                                           |
| 2    | Setup   | `socket()` ×2                      | `main_tcp_make_pair()` creates connected TCP pair         | `client_fd` + `server_fd` on `127.0.0.1`                                       |
| 3    | Setup   | `memfd_create()`                   | Create anonymous memfd for punch                          | `punch_fd`                                                                     |
| 4    | Setup   | `fallocate()`                      | Pre-allocate 16 MiB on memfd                              | `MAIN_TCP_PUNCH_SHMEM_LEN`                                                     |
| 5    | Setup   | `mmap()`                           | Map memfd R/W into userspace                              | `map` pointer                                                                  |
| 6    | Setup   | `pthread_create()`                 | Start `main_tcp_punch_thread`                             | Loop: alloc → `PUNCH_HOLE` → free pages                                        |
| 7    | Race    | `send()`                           | Send 64-byte `sendbuf` to server socket                   | `MSG_DONTWAIT`, no `MSG_ZEROCOPY`                                              |
| 8    | Race    | —                                  | Spin until `main_tcp_punch_phase == 0`                    | Sync with punch thread                                                         |
| 9    | Race    | —                                  | Build `zc[0x40]` buffer for `getsockopt`                  | `zc[0x18]=map+ps`, `zc[0x20]=64`, `zc[0x28]=waiter_task`, `zc[0x30]=fake_lock` |
| 10   | Race    | `getsockopt()`                     | `TCP_ZEROCOPY_RECEIVE` on client socket                   | Kernel reads/writes `zc` structure                                             |
| 11   | Race    | —                                  | If `i >= arm_seq` (default 16): arm consumer              | `punch_consume_go = i` → trigger GhostLock consumer                            |
| 12   | Race    | —                                  | `wait_for_consumer_idle()` + spin                         | Wait for consumer to process dangling waiter                                   |
| 13   | Trigger | —                                  | Check `consumer_calls` / `consumer_success`               | If counters increased → race hit                                               |
| 14   | CFI     | —                                  | `run_cfi_stage_on_worker()` → `try_cfi_stage()`           | Enter arbitrary R/W stage                                                      |
| 15   | CFI     | `open()`                           | `open_ashmem_device()` → open `/dev/ashmem`               | `fd` for hijacked fops                                                         |
| 16   | CFI     | `configfs_write_once()`            | Arbitrary write test payload to `binwrite_target`         | `"CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK"`                                         |
| 17   | CFI     | `configfs_write_once()`            | If `MAIN_TCP_PAYLOAD`: zero `fake_fops + FOPS_READ_OFF`   | Disable read slot                                                              |
| 18   | CFI     | `configfs_read_once()`             | Read back payload from `binwrite_target`                  | Verify arbitrary read works                                                    |
| 19   | CFI     | `configfs_read_once()`             | Read `misc_fops` (ashmem fops pointer)                    | Verify it equals `fake_fops`                                                   |
| 20   | CFI     | `configfs_write_once()`            | `restore_slide_boot_id()` — overwrite boot ID             | `SLIDE_RANDOM_BOOT_ID_DATA` → `SLIDE_SYSCTL_BOOTID`                            |
| 21   | CFI     | `configfs_read_once()` ×4          | `leak_kernel_base()` — read ashmem fops slots             | `open`/`ioctl`/`mmap`/`release`/`show_fdinfo`                                  |
| 22   | CFI     | —                                  | Compute `kaslr_base` / `kaslr_slide` from leaked pointers | Validate against expected offsets                                              |
| 23   | Privesc | `pipe()` + `configfs_write_once()` | `install_pipe_physrw()` — stable pipe-based R/W           | `anon_pipe_buf_ops` manipulation                                               |
| 24   | Privesc | —                                  | `cleanup_main_waiter_pi_state()`                          | Fix PI state of dangling waiter                                                |
| 25   | Privesc | —                                  | `install_android_root()`                                  | Overwrite `current->cred` with `init_cred`                                     |
| 26   | Restore | `configfs_write_once()`            | Restore original `ashmem_fops` pointer                    | `canon_addr(ASHMEM_FOPS)`                                                      |
| 27   | Restore | `configfs_write_once()`            | Zero out `fake_fops` owner field                          | Prevent UAF reuse                                                              |
| 28   | Cleanup | `close()`                          | Close ashmem fd                                           | Return success / fail                                                          |

</details>

## Other stuff

<details>
<summary>Click to view</summary>
Reference:
https://github.com/NebuSec/CyberMeowfia/blob/main/IonStack/CVE-2026-43499/exploit/src/targets/tokay-CP2A.260605.012 especially /fops.c

Build [`CyberMeowfia`](CyberMeowfia/exploit/)

```sh
export ANDROID_NDK_HOME=/root/Android/Sdk/ndk/android-ndk-r29 #path_to_ndk
make clean
make PROJECT=tokay-CP2A.260605.012 API=36
```

```sh
adb push preload.so /data/local/tmp/
adb shell chmod +x /data/local/tmp/preload.so
adb shell "LD_PRELOAD=/data/local/tmp/preload.so /system/bin/id"
```

### TODO

_basically spied from [existing S25U port](https://github.com/BuSung-dev/CVE-2026-43499-S25U) based on pselect_

```
Add tracefs-based KASLR slide recovery for this Samsung kernel.
Port CFI/FOPS stage, physical read/write primitive.
Add the device-specific system_unbound_wq user-mode-helper root path.
Add isolated retry processes with the device-tuned pselect delay sequence.
Retain reclaimed pages after success to avoid recycling live forged objects.
```

</details>

## Responsible use

This project is intended for education and authorized research on devices you own or have explicit permission to test. Kernel experiments can cause data loss, boot loops, or require a reflash. Use a dedicated test device, keep backups, and never carry offsets across firmware builds without revalidating them!
