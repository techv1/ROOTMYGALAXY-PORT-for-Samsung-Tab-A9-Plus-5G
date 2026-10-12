# SM-X216B Alternative-Architecture & Cross-Device Porting Matrix

**Target Device**: Samsung Galaxy Tab A9+ 5G (`SM-X216B` / `gta9p`)  
**Firmware**: `X216BXXS9DYJ7`  
**Target Kernel**: `5.4.249-qgki-31053672-abX216BXXS9DYJ7` (AArch64 / Qualcomm SM6375)  

> **Target-specific correction (2026-09-27):** the target waiter is 80 bytes
> (`0x50`): task `+0x30`, lock `+0x38`, prio `+0x40`, alignment `+0x44`, and
> deadline `+0x48`. Generic claims of 72 bytes / `deadlocked +0x44` are wrong
> for X216B. See
> `reference_flow_adaptation.md` and `qemu-rbtrace-gdb.log`.

---

## 1. Five Reference Research Profiles Comparison

### 1. Nothing Phone (1) (`ang3lo-azevedo/root-my-nothing`)
* **Platform**: Qualcomm Snapdragon 778G+ (SM7325), **Linux 5.4 AArch64**, Nothing OS (Clean CAF).
* **Architecture**: Open-architecture `KernelSnitch` implementation. Relies on futex timing side-channels to discover `mm_struct`, pipe oracle for KASLR resolution, `pipe_buffer` (`anon_pipe_buf_ops`) write primitive, and direct `task_struct->cred` overwrites.
* **Direct Relevance to SM-X216B**:
  - Shares the identical **Linux 5.4 + Qualcomm + AArch64** kernel generation.
  - Provides a generic Linux 5.4 comparison: `prio` at `0x40` and no `wake_state`. It does not establish the exact target waiter tail or extent.
  - Contrasting constraint: Nothing OS lacks Samsung DEFEX, Samsung Knox, and Samsung-specific `task_struct` field shifts.

### 2. Samsung Galaxy S23 Ultra (`soumarcelino/Root-My-Galaxy-SM-S918B`)
* **Platform**: Qualcomm Snapdragon 8 Gen 2 (SM8550), **Linux 5.15.189 AArch64**, One UI 6.x (Flagship Knox).
* **Architecture**: Closed-engine binary patch architecture (`cve-2026-43499-app.so` via `patch_payload.py` and `spec.json`).
  - Abandons `KernelSnitch` because futex timing side-channels are unstable on Samsung's scheduler.
  - Locates `mm_struct` directly via `/proc/slabinfo`.
  - Resolves KASLR via `/proc/sys/kernel/random/boot_id` sysctl + `p0_fingerprint` table.
  - Employs an `ashmem` / `configfs` write primitive.
  - Bypasses Knox KDP (Kernel Data Protection) by avoiding direct `cred` writes; instead invokes `call_usermodehelper` or loads KernelSU (`ksud-f731u-kdp`).
* **Direct Relevance to SM-X216B**: Defines a modern Samsung porting workflow for named S918B builds, but its profile assumptions are for Linux 5.15 and do not transfer to X216B 5.4.249. X216B also has an empty static UMH path, so UMH symbol presence does not make its helper route available.

### 3. Samsung Galaxy A15 (`SM-A155` / `SM-A156` / `a15-A155NKSS6BYH1`)
* **Platform**: MediaTek Helio G99 / Dimensity 6100+, **Linux 5.10 / 5.15 AArch64**, stripped budget firmware.
* **Architecture**: Profile in `BuSung-dev/Root-My-Galaxy-Payloads` using `#define LEGACY_RT_MUTEX_WAITER 1`.
  - In `a15`'s `target.h`: `FAKE_WAITER_PRIO_OFF` is placed at `0x40` (size `0x50`), proving that budget Samsung devices retain legacy rtmutex layouts.
  - Lacks BTF debug info (`CONFIG_DEBUG_INFO_BTF` disabled); demonstrates symbol extraction via `vmlinux-to-elf` and relative kallsyms table parsing.
* **Direct Relevance to SM-X216B**: Demonstrates how Samsung budget devices without BTF require exact ELF disassembly verification rather than assuming flagship GKI offsets.

### 4. Samsung Galaxy A17 (`mobilehackinglab/ghostlock-a17`)
* **Platform**: Samsung entry-tier, Android 14 / One UI 6, **Linux 5.15/6.1 AArch64**.
* **Architecture**: Detailed characterization of Samsung post-primitive defensive barriers:
  - **Samsung DEFEX**: Intercepts unauthorized binary execution in `/data/local/tmp` and monitors process tree parenting.
  - **SELinux Transitions**: Blocks direct `untrusted_app` to `kernel` or `su` transitions, requiring domain hopping or daemon sockets.
* **Direct Relevance to SM-X216B**: Provides security-architecture context only. The X216B firmware's empty static UMH path disables standard UMH launches; this target-specific config must be checked before applying the A17 post-primitive model.

### 5. Samsung Galaxy S22 Ultra (`SM-S908B` / `SM-S908U`)
* **Platform**: Qualcomm Snapdragon 8 Gen 1 (SM8450) / Exynos 2200, **Linux 5.10 AArch64**.
* **Architecture**: Intermediate generation between 5.4 and 5.15. Demonstrates that compiler version differences (Clang 11 vs 12 vs 14) shift stack frame sizes and `task_struct` offsets across consecutive Samsung generations.
* **Direct Relevance to SM-X216B**: Proves that offsets from S22/S23 cannot be ported without disassembly verification.

---

## 2. Eight Core Technical Questions Across Projects

> **Target evidence update (2026-09-30):** bounded QEMU checks confirm the
> X216B 64-bit `mmsghdr` ABI and ordinary ARM32 IPv4 multicast syscall
> behavior. They do not show waiter overlap or a controlled write. A benign
> module-autoload check did not invoke a sentinel helper, consistent with the
> stock config's empty static UMH path. See
> [`verified_findings_2026-09-30.md`](verified_findings_2026-09-30.md).

### 1. What part is reusable architecture?
- **Trigger**: The `FUTEX_CMP_REQUEUE_PI` deadlock race triggering `remove_waiter()` rollback is identical across all vulnerable kernels.
- **Dangling Pointer Mechanics**: The waiter object left dangling on `waiter->task->pi_blocked_on` behaves identically.
- **`p0_fingerprint` Concept**: The 8-word memory table (`Image[0x1f0000 - slide]`) accurately resolves KASLR without side-channel timing leaks.
- **State Machine**: The phased lifecycle (`preparing-kernel-access` → `locating-kernel` → `verifying-kernel-access` → `starting-temporary-root`).
- **Binary Patch Methodology**: Modifying pre-compiled engine instructions (`mov wN, #imm16`) via `patch_payload.py`.

### 2. What part is firmware-specific?
- Exact kernel image virtual base (`KIMAGE_TEXT_BASE`): `0xffffffc010080000` on X216B vs `0xffffffc008000000` on S918B.
- Kernel symbol addresses (`init_task`, `commit_creds`, `anon_pipe_buf_ops`, `call_usermodehelper_exec_work`, `ashmem_fops`).
- Exact `p0_fingerprint` 64-bit word constants derived from the specific kernel `Image`.
- Stack frame dimensions in `do_futex` (528 bytes / `0x210` on X216B) and waiter coordinate (`[x29 - 0xc8]`).

### 3. What part is kernel-generation-specific?
- **`rt_mutex_waiter` Structure Layout**:
  - **SM-X216B Android 5.4 target**: Size `0x50`; fields include `task` (0x30), `lock` (0x38), `prio` (0x40), alignment padding (0x44), and `deadline` (0x48). No `wake_state`/`ww_ctx` in this profile.
  - **Linux 5.15 (S918B)**: Size `0x58` (88 bytes). Adds `wake_state` (0x40), `prio` (0x44), `deadline` (0x48), `ww_ctx` (0x50).
  - **Linux 6.1 / 6.6 (S24/S25 series in `targets-v3.json`)**: Adds lockless wait flags and timer struct modifications.
- **`task_struct` Offsets**:
  - Linux 5.4 (SM-X216B): `pi_lock` = `0x8dc`, `pi_waiters` = `0x8e8`, `pi_blocked_on` = `0x900`.
  - Linux 5.15 (S918B): `pi_lock` = `0x884`, `pi_waiters` = `0x898`, `pi_blocked_on` = `0x8b0`.
- **Kernel Module Subsystem**:
  - Linux 5.15 / 6.1: Uses standardized Android GKI 2.0 kprobe/module ABI (`android13-5.15.189_kernelsu.ko`).
  - Linux 5.4 QGKI: Vendor-customized module loading with distinct symbol version CRCs.

### 4. What information must be extracted from the target vmlinux?
- Symbol virtual addresses:
  - `init_task`: `0xffffffc0129e0280`
  - `selinux_state`: `0xffffffc012b9f000`
  - `commit_creds`: `0xffffffc010327184`
  - `anon_pipe_buf_ops`: `0xffffffc0121f55b8`
  - `call_usermodehelper_exec_work`: `0xffffffc010317274`
  - `ashmem_fops`: `0xffffffc0121cee28`
  - `configfs_bin_file_operations`: `0xffffffc012201620`
  - `cached_stacks`: `0xffffffc012668be0`
- Structure offsets: `task_struct::pi_lock` (`0x8dc`), `pi_blocked_on` (`0x900`), `rt_mutex_waiter` (`0x30`, `0x38`, `0x40`).
- Stack frame layouts: `do_futex` (`0x210` bytes, waiter at `[x29 - 0xc8]`), `core_sys_select` (`0x1c0` bytes, `stack_fds` at `[sp + 0x50]`).

### 5. What runtime prerequisites exist?
- **Stack Zeroing on Allocation**: `dup_task_struct` executes `memset(stack, 0, 16KB)` on reused thread stacks. Cross-thread stack spraying is neutralized; reclamation must occur within in-thread nested syscall stacks.
- **Zero-Tolerance Panic**: `CONFIG_PANIC_ON_OOPS=y`, `CONFIG_PANIC_TIMEOUT=5`. Any pointer fault triggers an instant hard reboot within 5 seconds.
- **RCU Grace Period**: Thread stacks are released asynchronously through `delayed_put_task_struct` after an RCU grace period.

### 6. What Samsung-specific prerequisites exist?
- **Samsung DEFEX**: `CONFIG_SECURITY_DEFEX=y` restricts binary execution paths and process parenting.
- **Knox KDP (Kernel Data Protection)**: Active on flagship S23/S24/S25, but verified **ABSENT** on SM-X216B (`# CONFIG_RKP / KDP not set` in `ikconfig`), which significantly simplifies memory permissions.
- **`userfaultfd`**: Verified **ABSENT** (`# CONFIG_USERFAULTFD is not set`).

### 7. Which assumptions can plausibly exist on Linux 5.4.249?
- Vulnerable `remove_waiter()` logic operating on `current` instead of `waiter->task`.
- Predictable stack placement of `rt_mutex_waiter` in `do_futex`.
- Stack overlap with `core_sys_select`'s `stack_fds` buffer.
- `p0_fingerprint` KASLR resolution from `Image` bytes.
- Direct credential write via kernel write primitives (since KDP is disabled).

### 8. Which assumptions definitely require 5.10/5.15/6.x APIs?
- Precompiled closed-engine binaries (`cve-2026-43499-app.so` from S918B/F731U/S25), which assume an 88-byte (`0x58`) `rt_mutex_waiter` structure with `wake_state` at `+0x40`.
- Standardized Android GKI 2.0 KernelSU loadable modules (`android13-5.15.189_kernelsu.ko` or `ksud-s25u-kdp`).
- Standard GKI virtual address base (`0xffffffc008000000`).

---

## 3. Deep-Dive: S918B / BuSung-Payloads Tooling & Artifacts

### 1. `PORTING.md` (from `soumarcelino/Root-My-Galaxy-SM-S918B`)
- Documents adapting the closed-engine `cve-2026-43499-app.so` (131,072 bytes) by patching 16-bit immediate constants in ARM64 `mov wN, #imm` instructions.
- Bypasses `KernelSnitch` using `/proc/slabinfo` direct reading and `boot_id` sysctl KASLR calculation.

### 2. `target.h` Structure
- Defines base addresses (`KIMAGE_TEXT_BASE`, `P0_PAGE_OFFSET`), candidate KASLR slide offsets (`SLIDE_P0_OFFSET_CANDIDATES`), and struct offsets.
- Shows that `task_struct::pi_lock` (0x884 on S918B) and `pi_blocked_on` (0x8b0 on S918B) differ from Linux 5.4 (0x8dc and 0x900 on X216B).

### 3. `p0_fingerprint.h` & `generate_p0_fingerprint.pl`
- Contains precomputed 8-word fingerprints (`0x000`, `0x200`, `0x400`, `0x600`, `0x800`, `0xa00`, `0xc00`, `0xe00`) sampled from `Image[0x1f0000 - slide]` across 32 candidate slides (`slide * 0x10000`).

### 4. `tools/patch_payload.py` & Spec JSON
- Automates rewriting ARM64 `movz wN, #imm16` opcodes (`0x52800000 | (imm16 << 5) | rd`) and replacing conditional branch checks with NOPs (`0x1f2003d5`).

### 5. Profile Schema (`targets-v3.json`)
- JSON feed mapping device fingerprints to payload URLs and checksums.
- Contains 20 target families across modern Galaxy lines:
  * Galaxy S25 series (`galaxy-s25-series-2026-06-07` on Kernel 6.6.98)
  * Galaxy S24 FE / S25 FE (`r12s-S721BXXSCDZF3` on Kernel 6.1.157)
  * Galaxy Tab S9 (`gts9-X710XXS6EZF1` on Kernel 5.15.189)
  * Galaxy A15 (`a15-A155NKSS6BYH1` with `LEGACY_RT_MUTEX_WAITER 1`)

### 6. Helper & Audit Tooling (`test_sigreturn_overlap.c`)
- Inspects signal frame (`rt_sigframe`) and FPSIMD context restoration overlap against kernel stack allocations to evaluate stack reclamation without triggering panics.

---

## 4. SM-X216B Requirements Classification Matrix

| Requirement / Parameter | Target Value / Implementation | Classification | Technical Evidence |
| :--- | :--- | :--- | :--- |
| **Vulnerable `remove_waiter()`** | Present (uses `current` via `sp_el0`) | **VERIFIED** | Disassembly of `0xffffffc010376418` |
| **`KIMAGE_TEXT_BASE`** | `0xffffffc010080000` | **VERIFIED** | Kernel header & ELF program headers |
| **`task_struct::pi_lock`** | `0x8dc` | **VERIFIED** | Disassembly cross-check (3 independent functions) |
| **`task_struct::pi_blocked_on`** | `0x900` | **VERIFIED** | `remove_waiter @ 0x10376498` |
| **`rt_mutex_waiter` Size** | **0x50 (80 bytes)** | **KERNEL-VERSION DEPENDENT** | X216B target source/disassembly; see correction above |
| **`rt_mutex_waiter::wake_state`** | Absent in Linux 5.4 | **NOT APPLICABLE** | 5.15+ only field |
| **`do_futex` Frame / Waiter** | `0x210` frame, waiter at `[x29 - 0xc8]` | **VERIFIED** | `do_futex @ 0x103c0a64` |
| **`pselect6` `stack_fds` Overlap** | Statically verified (+120B offset) | **VERIFIED** | `core_sys_select @ 0x1053c34c` |
| **Stack Zeroing on Reuse** | `memset(stack, 0, 16KB)` in `dup_task_struct` | **VERIFIED** | `dup_task_struct @ 0x102f4158` |
| **Samsung DEFEX Policy** | Active (`CONFIG_SECURITY_DEFEX=y`) | **SAMSUNG-SPECIFIC** | `ikconfig` |
| **Samsung KDP / RKP Protection** | Inactive (`# CONFIG_RKP / KDP not set`) | **SAMSUNG-SPECIFIC** | `ikconfig` (simpler model than S918B/S25) |
| **`p0_fingerprint` Slide Logic** | Derivable from `Image` bytes | **POSSIBLY APPLICABLE** | Reusable methodology from S918B |
| **S918B/S25 Precompiled Engine** | Incompatible ABI (hardcodes 5.15/6.x structs) | **NOT APPLICABLE** | Struct size & member mismatch |
| **In-Thread Syscall Stack Timing** | Requires on-device physical measurement | **UNKNOWN** | Hardware scheduler telemetry required |

---

## 5. Bottom Line

1. **Vulnerability & Geometry Are 100% Confirmed on SM-X216B**:
   The SM-X216B kernel contains the unpatched, vulnerable `remove_waiter()` logic of CVE-2026-43499. The stack placement of `rt_mutex_waiter` in `do_futex` and its geometric overlap with `core_sys_select`'s `stack_fds` buffer are mathematically verified and confirmed.
2. **Flagship Closed-Engine Payloads (S918B / S24 / S25) Cannot Be Reused**:
   Precompiled payloads from the S23/S24/S25 family cannot simply be patched with new symbol offsets. They assume newer ABI structures (including `wake_state` at `+0x40`), whereas SM-X216B has target-confirmed `prio` at `+0x40` and deadline at `+0x48`. Any implementation requires the target-derived structure definition.
3. **Absence of Samsung KDP Simplifies the Target Context**:
   Unlike the flagship Galaxy S23 (S918B) or S25 series, the SM-X216B budget tablet does **not** have Samsung Knox Kernel Data Protection (KDP) enabled. The kernel lacks hypervisor-enforced write protection over task credentials.
4. **Decisive Runtime Constraint**:
   Because `dup_task_struct()` explicitly executes `memset(stack, 0, 16KB)` on reused thread stacks, cross-thread stack spray primitives do not function. Exploitability strictly depends on whether an in-thread syscall path can predictably reach the `[SP_entry - 0x128]` stack depth on physical hardware before the thread exits or the dangling waiter is dereferenced.
