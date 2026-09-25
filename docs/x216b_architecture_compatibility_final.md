# Comprehensive Architecture Compatibility Audit: SM-X216B vs Public GhostLock Implementations

**Target Device**: Samsung Galaxy Tab A9+ 5G (`SM-X216B` / `gta9p`)  
**Firmware**: `X216BXXS9DYJ7`  
**Kernel**: `5.4.249-qgki-31053672-abX216BXXS9DYJ7` (Qualcomm SM6375, AArch64 Little-Endian)  
**Compiler**: Clang 11.0.2 / LLD 11.0.2  
**Analyzed Artifacts**: `vmlinux.elf`, `kallsyms.txt` (185,206 symbols), `ikconfig` (extracted kernel config), verified Ghidra decompiler database, exact stack geometry calculations.

---

## Executive Summary & Architecture Classification Matrix

| Reference Implementation | Target Platform & Baseline | Entry Primitive / Stamping Method | Post-Primitive Strategy | Compatibility on SM-X216B | Primary Blocker / Divergence Reason |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. ang3lo-azevedo/root-my-nothing** | Nothing Phone 1 (SM7325, Linux 5.4.302) | 64-bit `pselect6` / `stack_fds` | Direct `cred` overwrites & SELinux disable | **INCOMPATIBLE** | Waiter offset lands in zeroed `res_in`/`res_out` bitmask region; `cred` layout and offsets diverge. |
| **2. sarabpal-dev/IonStack-S22U** | Samsung S22 Ultra (SM8450/b0q, Linux 5.10.226) | `exp32` (ARM32 compat `setsockopt` `MCAST_JOIN_SOURCE_GROUP`) | Fake `ashmem_fops` → `configfs` r/w → pipe phys r/w → UMH daemon | **PARTIALLY COMPATIBLE** *(Highest structural match)* | ARM32 compat execution supported (`CONFIG_COMPAT=y`), requires geometry recalculation (`EXP32_STAMP_OFF`) and 72-byte `rt_mutex_waiter` adjustment. |
| **3. soumarcelino/Root-My-Galaxy-SM-S918B** | Samsung S23 Ultra (SM8550/dm3q, Linux 6.1.x) | 64-bit `pselect6` + `sigreturn` stack alignment | Precompiled closed-engine (`cve-2026-43499-app.so`) → KernelSU | **INCOMPATIBLE** | Binary payload hardcodes Linux 6.1 88-byte waiter (`0x58`) and 64-bit `pselect6` entry geometry. |
| **4. BuSung-dev/Root-My-Galaxy-Payloads** | Samsung Multi-Device (S24, S25, Tab S9, A15) | Multi-target profiles (mostly 6.1/6.6; A15 is 5.10) | `cve-2026-43499-app.so` closed payload + KSU daemon | **INCOMPATIBLE** | Precompiled engine cannot run on Linux 5.4 72-byte structs (`0x48`); A15 profile is 5.10 with different struct offsets. |
| **5. mobilehackinglab/ghostlock-a17** | Samsung Galaxy A17 (MT6789, Linux 6.12.23) | `pselect6` reclaim | UMH root daemon (`pipe_physrw` bypasses Samsung KDP) | **INCOMPATIBLE** | Built entirely around Linux 6.12 BTF layouts and KDP bypass; `pselect` geometry fails on 5.4. |
| **6. NebuSec/CyberMeowfia** | Generic Linux / Android Reference (v6.x) | 64-bit `pselect6` | `pipe_buffer` corruption → arbitrary phys r/w → task cred patch | **PARTIALLY COMPATIBLE** (Conceptually) / **INCOMPATIBLE** (As-Is) | General pipe phys r/w concept is valid, but implementation hardcodes 64-bit `pselect` and 6.x struct offsets. |

---

## Detailed Comparative Analysis by Architecture

### 1. ang3lo-azevedo/root-my-nothing
* **Target Baseline**: Nothing Phone 1 (Spacewar), Snapdragon 778G+ (SM7325), Linux `5.4.302-qgki`.
* **Required Kernel APIs**: `sys_futex` (`FUTEX_WAIT_REQUEUE_PI`, `FUTEX_CMP_REQUEUE_PI`), `sys_pselect6`, `sched_setattr`, `sys_open`, `sys_read`, `sys_write`.
* **Required Structures**:
  * Linux 5.4 `rt_mutex_waiter` (72 bytes / `0x48`).
  * Linux 5.4 `task_struct` (offsets: `pi_lock` 0x8c4, `pi_blocked_on` 0x8e8, `cred` 0x7f0).
* **Required Symbols & Availability on SM-X216B**:
  * `anon_pipe_buf_ops`: Present (`0xffffffc0121f55b8`).
  * `ashmem_fops`: Present (`0xffffffc0121cee28`).
  * `configfs_read_file`: Present (`0xffffffc0105d924c`).
  * `configfs_write_bin_file`: Present (`0xffffffc0105d9784`).
  * `generic_file_splice_read`: Present (`0xffffffc0105650e4`).
  * `noop_llseek`: Present (`0xffffffc01051cbd0`).
  * `init_task`: Present (`0xffffffc0129e0280`).
  * `init_cred`: Present (`0xffffffc0129ec740`).
* **Stack Prerequisites**: Relies on 64-bit `pselect6` stack layout with `SLIDE_PSELECT_WORD_SHIFT = 2` and `SLIDE_PSELECT_NFDS = 320`.
* **Evaluation on SM-X216B**:
  * **FATAL FLAW**: As proved by disassembly analysis of `core_sys_select` (`0xffffffc010543e54`), the X216B kernel places `stack_fds` 120 bytes below the waiter base (`+0x78`). Offsets +120 to +240 are the output bitmasks (`res_in`, `res_out`, `res_ex`), which are zeroed out via `memset`.
  * **Structure Drift**: `task_struct::pi_lock` on X216B is at `0x8dc` (vs `0x8c4` on Nothing), and `pi_blocked_on` is at `0x900` (vs `0x8e8`).
  * **Verdict**: **INCOMPATIBLE** in its current form due to entry primitive failure and struct mismatch.

---

### 2. sarabpal-dev/IonStack-S22U (exp32 / MCAST_JOIN_SOURCE_GROUP)
* **Target Baseline**: Samsung Galaxy S22 Ultra (`SM-S908W` / `b0q`), Snapdragon 8 Gen 1 (SM8450), Linux `5.10.226-android12-9-30958166`.
* **Core Breakthrough**: Replaced the fragile `pselect6` entry route with an ARM32 compat thread (`exp32`) executing:
  ```c
  setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_SOURCE_GROUP, buffer, 260);
  ```
  This systematically overwrites the stale kernel stack waiter frame via `compat_ipv6_setsockopt()` / `do_ipv6_setsockopt()`, parking in a userspace spin loop to prevent stack tearing.
* **Required Kernel APIs & Architecture Features**:
  * 32-bit Compatibility Layer: `CONFIG_COMPAT=y` (Verified present in X216B `ikconfig`).
  * `compat_ipv6_setsockopt`: Present in X216B (`0xffffffc011472188`).
  * `do_ipv6_setsockopt`: Present in X216B (`0xffffffc0114710b0`).
  * `__arm64_compat_sys_setsockopt`: Present in X216B (`0xffffffc0113628c0`).
* **Required Symbols & Post-Primitive Primitives**:
  * `ashmem_misc`: Present in X216B (`0xffffffc0129cbae0`). `ashmem_misc.fops` sits at `+0x10` (`0xffffffc0129cbaf0`).
  * `configfs_read_file` / `configfs_write_bin_file`: Present in X216B (`0xffffffc0105d924c` / `0xffffffc0105d9784`).
  * `call_usermodehelper_exec_work`: Present in X216B (`0xffffffc010317274`).
  * `system_unbound_wq`: Present in X216B (`0xffffffc01296f9c8`).
* **Kernel Version Assumptions vs SM-X216B**:
  * S22U targets Linux 5.10 (80-byte `rt_mutex_waiter`). X216B is Linux 5.4 (72-byte `rt_mutex_waiter`).
  * S22U waiter offset within `setsockopt` buffer is `buffer + 0x58` (measured for 5.10). On X216B 5.4, the stack depth of `compat_ipv6_setsockopt` vs `do_futex` will differ by a few words and must be calibrated.
* **Verdict**: **PARTIALLY COMPATIBLE** — This is the only public architecture whose entry primitive bypasses the broken `pselect` geometry.

---

### 3. soumarcelino/Root-My-Galaxy-SM-S918B
* **Target Baseline**: Samsung Galaxy S23 Ultra (`SM-S918B`), Snapdragon 8 Gen 2 (SM8550), Linux 6.1.x.
* **Architecture Design**:
  * Uses `tools/test_sigreturn_overlap.c` to measure stack overlap between `rt_sigreturn` and `pselect6`.
  * Loads a precompiled dynamic library `cve-2026-43499-app.so`.
  * Patches parameters at runtime via `patch_payload.py` using `p0_fingerprint.h`.
* **Evaluation on SM-X216B**:
  * **Binary Rigidity**: The core exploit logic is closed-source binary code compiled for 64-bit Linux 6.1 GKI.
  * **Structure Incompatibility**: Expects `sizeof(struct rt_mutex_waiter) == 0x58` (88 bytes) and reads `wake_state` at `+0x40`. On Linux 5.4, `wake_state` does not exist; feeding 88-byte structures corrupts adjacent stack variables.
  * **Primitive Incompatibility**: Relies on `pselect6` stack spraying, which cannot place data into the waiter location on X216B.
  * **Verdict**: **INCOMPATIBLE**.

---

### 4. BuSung-dev/Root-My-Galaxy-Payloads
* **Target Baseline**: 20+ profiles across Samsung devices (S24, S25, Tab S9, S918B, S911U, A15).
* **Evaluation on SM-X216B**:
  * Contains a profile for Galaxy A15 (`SM-A155N`), but A15 runs **MediaTek MT6789 on Linux 5.10.226** (`LEGACY_RT_MUTEX_WAITER 1`, 80 bytes).
  * Does not support any Linux 5.4 target or Qualcomm SM6375 platform.
  * Payloads are bound to the closed-source `cve-2026-43499-app.so` engine.
  * **Verdict**: **INCOMPATIBLE**.

---

### 5. mobilehackinglab/ghostlock-a17
* **Target Baseline**: Samsung Galaxy A17 (`SM-A175F`), MediaTek MT6789, Android 16 / Linux `6.12.23`.
* **Architecture Innovations**:
  * Demonstrates that Samsung Knox KDP / RKP prevents direct modification of task credentials (`current->cred`) via write-protection of cred slabs at EL2.
  * Introduces the **User Mode Helper (UMH) execution path**: triggers `call_usermodehelper_exec_work` on `system_unbound_wq` to spawn an unconfined root process (`u:r:kernel:s0`), evading KDP entirely.
* **Evaluation on SM-X216B**:
  * **Defensive Baseline Difference**: SM-X216B does **NOT** have Knox KDP active (`# CONFIG_RKP / KDP not set` in `ikconfig`). While UMH is viable (symbols exist in X216B), it is not strictly mandated by hardware protections.
  * **Entry Primitive**: Uses 64-bit `pselect6`, which fails on X216B.
  * **Verdict**: **INCOMPATIBLE** as an entire chain, though the UMH execution model is structurally supported by the kernel symbols.

---

### 6. NebuSec/CyberMeowfia (IonStack / CVE-2026-43499)
* **Target Baseline**: Original upstream research codebase by Nebula Security targeting Linux 6.1/6.4/6.6/6.12.
* **Architecture Strategy**:
  * `pselect6` reclaim → Fake `rt_mutex_waiter` linked into rb-tree.
  * CFI bypass via fake `ashmem_fops` table pointing `.read_iter` / `.write_iter` to `configfs_read_file` / `configfs_write_bin_file`.
  * `pipe_buffer` page reclaim: corrupts `anon_pipe_buf_ops` to obtain arbitrary physical memory read/write.
  * Scans task list via `init_task` to find `current`, overwrites `cred` and resets `selinux_enforcing`.
* **Evaluation on SM-X216B**:
  * Fails at stage 1 due to `pselect6` geometry failure.
  * Relies on 6.x struct offsets (`struct page`, `pipe_buffer`, `rt_mutex_waiter`).
  * **Verdict**: **PARTIALLY COMPATIBLE** (Conceptual post-primitive flow is identical to S22U/A17, but code is strictly 6.x).

---

## Detailed Prerequisite Comparison for SM-X216B

| Parameter / Feature | SM-X216B Kernel Status | IonStack-S22U (`exp32`) | root-my-nothing (5.4) | Standard GhostLock (6.x) |
| :--- | :--- | :--- | :--- | :--- |
| **Kernel Version** | `5.4.249-qgki` | `5.10.226` | `5.4.302-qgki` | `6.1.x` - `6.12.x` |
| **`CONFIG_COMPAT`** | **YES** (`CONFIG_COMPAT=y`) | YES | YES | YES |
| **`compat_ipv6_setsockopt`** | **0xffffffc011472188** | Present | Present | Present |
| **`rt_mutex_waiter` Size** | **72 bytes (`0x48`)** | 80 bytes (`0x50`) | 72 bytes (`0x48`) | 88 bytes (`0x58`) |
| **`wake_state` field** | **ABSENT** | ABSENT | ABSENT | Present (+0x40) |
| **`task_struct::pi_lock`** | **0x8dc** | 0x86c | 0x8c4 | 0x930+ |
| **`task_struct::pi_blocked_on`** | **0x900** | 0x898 | 0x8e8 | 0x950+ |
| **`ashmem_misc` address** | **0xffffffc0129cbae0** | Dynamic / Symbol | Dynamic / Symbol | Dynamic / Symbol |
| **`configfs` r/w helpers** | `configfs_read_file` / `bin_write` | Present | Present | `configfs_read_iter` |
| **`anon_pipe_buf_ops`** | **0xffffffc0121f55b8** | Present | Present | Present |
| **Knox KDP (Cred Protect)** | **ABSENT** | Present | ABSENT | Present |
| **Samsung DEFEX** | **Present** (`CONFIG_SECURITY_DEFEX=y`) | Present | ABSENT | Present |
| **Entry Primitive** | Broken `pselect6` → **Requires `exp32`** | `exp32` (MCAST) | `pselect6` | `pselect6` |

---

## Final Synthesis & Strategic Assessment

### 1. Closest 5.4 Reference
* **ang3lo-azevedo/root-my-nothing**:
  * **Why**: Exact same kernel release family (Linux 5.4 QGKI on Qualcomm AArch64).
  * **What matches**: Struct layouts (`sizeof(rt_mutex_waiter) == 72`, field order, lack of `wake_state`/`ww_ctx`), identical function naming (`configfs_read_file` vs `configfs_read_iter`).
  * **What diverges**: The Nothing Phone 1 kernel had different compiler optimization / inlining in `core_sys_select`, allowing its `pselect6` frame to overlap the waiter. On SM-X216B, `pselect6` places the waiter in zeroed memory.

### 2. Closest Qualcomm Reference
* **ang3lo-azevedo/root-my-nothing** (Snapdragon 778G+ / SM7325 vs SM-X216B Snapdragon 695 / SM6375). Both share Qualcomm QGKI kernel configurations and Clang-based compiler builds.

### 3. Closest Samsung Reference
* **sarabpal-dev/IonStack-S22U**:
  * **Why**: It is an official Samsung-ported codebase targeting older kernel generations (5.10) that explicitly solves Samsung DEFEX, Samsung SELinux (`selinux_state.enforcing`), and Samsung stack spray constraints.

### 4. Closest Alternative to `pselect`
* **`exp32` via `compat_ipv6_setsockopt(MCAST_JOIN_SOURCE_GROUP)` (from `IonStack-S22U`)**:
  * This is the proven, public alternative to `pselect6`.
  * Because SM-X216B has `CONFIG_COMPAT=y` and includes `compat_ipv6_setsockopt` at `0xffffffc011472188`, a 32-bit child thread can issue this syscall to spray up to 260 bytes of user data across the kernel stack frame, avoiding the `memset` bitmask destruction inherent to `core_sys_select`.

### 5. Exact Missing Evidence
To prove static compatibility with the `exp32` method, the following must be measured:
1. **Stack Frame Geometry of `compat_ipv6_setsockopt` / `do_ipv6_setsockopt` on X216B**:
   * Specifically, disassembling `0xffffffc0114710b0` to determine the exact stack allocation of `group_source_req` (`gr32`) relative to the stack pointer.
2. **Relative Offset Calculation**:
   $$\Delta = \text{SP}_{\text{compat\_setsockopt}} - \text{SP}_{\text{do\_futex}}$$
   $$\text{Offset} = (\text{SP}_{\text{futex}} - 0x198) - (\text{SP}_{\text{setsockopt}} - \text{FrameSize}_{\text{gr32}})$$
   This will yield the exact `EXP32_STAMP_OFF` for X216B (replacing the S22U value of `0x58`).

### 6. Single Next Research Task
* **Perform Static Disassembly & Geometry Audit of `do_ipv6_setsockopt` on `vmlinux.elf`**:
  * Analyze `do_ipv6_setsockopt` (`0xffffffc0114710b0`) and `compat_ipv6_setsockopt` (`0xffffffc011472188`) to locate where `copy_group_source_from_sockptr` / `compat_copy_from_sockptr` writes the user buffer to the kernel stack, and compute the static delta to `do_futex` waiter base (`x29 - 0xc8`).
