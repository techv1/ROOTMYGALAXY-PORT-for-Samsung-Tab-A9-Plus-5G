# 06. Agent Next Steps & Critical Pitfalls

For any AI agent picking up this research or porting task: review this briefing before modifying or debugging the code.

---

## 1. What is Solved & Verified (DO NOT RE-INVENT)

- [x] **Target Kernel Baseline**: Linux 5.4.249-qgki (Qualcomm SM6375 Snapdragon 695).
- [x] **Symbol Table**: Complete `kallsyms.txt` (185,206 symbols) and `kernel.config` verified and stored in `kernel/`.
- [x] **`rt_mutex_waiter` Layout**: Confirmed exactly 80 bytes (`0x50`). `task` at `+0x30`, `lock` at `+0x38`, `prio` at `+0x40`.
- [x] **Stack Overlap Geometry**: Verified via GDB hardware breakpoints:
  - `do_ip_setsockopt` buffer starts at `0x3c00`.
  - Dangling futex waiter starts at `0x3cd8`.
  - Exact empirical offset is **`0xd8` (216 bytes)**.
- [x] **Carrier Primitive**: IPv4 `MCAST_BLOCK_SOURCE` (optname 43) stamps the waiter with early exit `mov w20, #-99` (`-EADDRNOTAVAIL`).
- [x] **Full Waiter Enclosure**: Sigreturn FPSIMD frame stamp (`stamp_sigreturn` via `restore_fpsimd_context`) verified in QEMU (`test_sigreturn_port.c`), providing a 528-byte window that encloses all 80 bytes of the waiter with 120 bytes of safety margin, resolving the 264-byte MCAST boundary cliff.
- [x] **CFI Enforcement**: `.cfi_jt` requirement documented and mapped in `target.h`.
- [x] **Defensive Baseline**: Knox KDP is absent; static UMH has empty path.

---

## 2. Critical Traps to Avoid

### Trap 1: The "88-Byte Waiter" Fallacy
- **The Pitfall**: Borrowing `rt_mutex_waiter` definitions from public S23/S24/A17 exploits (Linux 5.15 / 6.1 / 6.12).
- **The Consequence**: 5.15 waiter has `wake_state` at `+0x40`. Using it causes `task` and `lock` to be misaligned by 8 bytes, leading to immediate kernel panics during priority inheritance.
- **The Rule**: Always use 80-byte waiter offsets (`task +0x30`, `lock +0x38`).

### Trap 2: The "Pselect Entry" Fallacy
- **The Pitfall**: Trying to use `pselect6` / `fd_set` to stamp the stack as in `root-my-nothing`.
- **The Consequence**: On 5.4, `pselect6` zeroes out the stack region where `waiter->task` resides before returning, resulting in an immediate NULL pointer dereference crash.
- **The Rule**: Only use multicast socket options (`MCAST_BLOCK_SOURCE`) or FPSIMD `sigreturn` stack reload.

### Trap 3: The "UMH Works Out of the Box" Fallacy
- **The Pitfall**: Assuming queuing `call_usermodehelper_exec_work` will execute `/data/local/tmp/root.sh`.
- **The Consequence**: The target kernel defines `CONFIG_STATIC_USERMODEHELPER_PATH=""`. The helper immediately fails with `-ENOENT`.
- **The Rule**: For privilege escalation on SM-X216B, use the arbitrary physical memory read/write primitive (via pipe buffers) to directly patch `task_struct->cred` (UID/GID/capabilities) and `ADDR_SELINUX_ENFORCING`. Knox KDP is not active, so cred overwrites are permitted.

### Trap 4: Direct Indirect Calls Under CFI
- **The Pitfall**: Setting a function pointer directly to `call_usermodehelper_exec_work` (`0xffffffc010317274`).
- **The Consequence**: Kernel panic due to Clang Forward-Edge CFI violation.
- **The Rule**: Always point function pointers to the corresponding `.cfi_jt` entry: `CALL_USERMODEHELPER_EXEC_WORK_CFI_JT` (`0xffffffc011681870`).

---

## 3. Recommended Implementation Roadmap

1. **Phase 1: Race Timing Calibration**:
   - Run `calibrate.sh` to measure futex requeue race windows on target cores.
   - Adjust worker thread loop counts and monotonic nanosecond delays in `futex_race.c`.
2. **Phase 2: Pipe Buffer Physical R/W**:
   - Validate `pipe_rw.c` memory spray to ensure `pipe_buffer` physical mapping succeeds without triggering slab quarantine panics.
3. **Phase 3: Direct Credential Patching**:
   - Locate current thread `task_struct` via `task->comm` or PID lookup.
   - Walk `task->cred` and zero out `uid`/`gid`, grant `CAP_ALL` (`0x3fffffffff`), and zero `ADDR_SELINUX_ENFORCING`.
4. **Phase 4: Shell Verification**:
   - Spawn `/system/bin/sh` from the exploit process and confirm `id` outputs `uid=0(root) gid=0(root) context=u:r:kernel:s0`.
