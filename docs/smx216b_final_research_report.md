# SM-X216B Kernel Analysis: Research Report

**Device**: Samsung Galaxy Tab A9+ 5G (`SM-X216B` / `gta9p`)  
**Firmware**: `X216BXXS9DYJ7`  
**Kernel**: `5.4.249-qgki-31053672-abX216BXXS9DYJ7`  
**Architecture**: AArch64 (ARM64 Little-Endian, Qualcomm SM6375)  
**Compiler**: Android Clang 11.0.2 (`r383902b1`) / LLD 11.0.2  
**Build Date**: Wed Oct 15 23:51:00 KST 2025  
**Analysis Binary**: `vmlinux.elf` (Base `0xffffffc010080000`, SHA256 `dfc0912ee00696bed45f0852d490a75d20d336a16fc87288b155d513bbcea29f`)  
**Analysis Type**: Static reverse engineering plus bounded QEMU diagnostics; no physical-device test.

---

## 1. Target Profile & Security Configuration

### 1.1 Kernel Identity
| Parameter | Value |
|:---|:---|
| Linux Version | `5.4.249-qgki-31053672-abX216BXXS9DYJ7` |
| Kernel Variant | Qualcomm GKI (`QGKI`) — `CONFIG_QGKI_BUILD=y` |
| Symbol Count | 185,206 symbols in `kallsyms.txt` |
| Config Source | `IKCONFIG` embedded (`CONFIG_IKCONFIG=y`, `CONFIG_IKCONFIG_PROC=y`) |
| KASLR Base | `0xffffffc010080000` (verified from ELF program headers) |

### 1.2 Security Hardening Matrix
| Mitigation | Config Option | Status | Notes |
|:---|:---|:---|:---|
| KASLR | `CONFIG_RANDOMIZE_BASE` | **ENABLED** | Slide resolution required |
| CFI (Clang) | `CONFIG_CFI_CLANG` + `CFI_CLANG_SHADOW` | **ENABLED** | Protects indirect calls |
| Shadow Call Stack | `CONFIG_SHADOW_CALL_STACK` + `_VMAP` | **ENABLED** | Protects return addresses (x18) |
| PAN | `CONFIG_ARM64_PAN` | **ENABLED** | Blocks direct kernel→user deref |
| UAO | `CONFIG_ARM64_UAO` | **ENABLED** | User access override |
| Hardened Usercopy | `CONFIG_HARDENED_USERCOPY` | **ENABLED** | Bounds-checks copy_from/to_user |
| Init-on-Alloc | `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | **ENABLED** | Heap zero-init on kmalloc |
| Strict Kernel RWX | `CONFIG_STRICT_KERNEL_RWX` | **ENABLED** | W^X enforcement |
| SELinux | `CONFIG_SECURITY_SELINUX` | **ENABLED** | Mandatory access control |
| Samsung DEFEX | `CONFIG_SECURITY_DEFEX` | **ENABLED** | Process execution policy |
| Samsung KDP/RKP | `CONFIG_RKP` / `KDP` | **ABSENT** | Critical: no EL2 cred protection |
| Futex / Futex PI | `CONFIG_FUTEX` / `CONFIG_FUTEX_PI` | **ENABLED** | PI chain active |
| BTF Debug Info | `CONFIG_DEBUG_INFO_BTF` | **DISABLED** | No /sys/kernel/btf/vmlinux |
| userfaultfd | `CONFIG_USERFAULTFD` | **ABSENT** | Race-timing tool not available |
| Panic on Oops | `CONFIG_PANIC_ON_OOPS=y` | **ENABLED** | Hard reboot in 5s on fault |
| BPF Syscall | `CONFIG_BPF_SYSCALL=y` | **ENABLED** | sys_bpf present |
| Compat (32-bit) | `CONFIG_COMPAT=y` | **ENABLED** | ARM32 syscall compatibility |

---

## 2. Structure Layouts (Generic references and target-confirmed fields)

### 2.1 `struct rt_mutex_waiter` — target layout

**Correction from September 27, 2026 source/disassembly/runtime review:** the
target waiter is 80 bytes (`0x50`), not 72. It has `task +0x30`, `lock +0x38`,
`prio +0x40`, alignment padding at `+0x44`, and `deadline +0x48`. The target's
PI-walk stores and compares the deadline; a QEMU GDB capture is saved at
`/root/s/qemu-rbtrace-gdb.log`. The table below records the corrected X216B
layout.

| Field | Offset | Size | Type | Notes |
|:---|:---|:---|:---|:---|
| `tree_entry` | `+0x00` | 24 B | `struct rb_node` | Red-black tree for lock->waiters |
| `pi_tree_entry` | `+0x18` | 24 B | `struct rb_node` | Red-black tree for task->pi_waiters |
| `task` | `+0x30` | 8 B | `struct task_struct *` | **Primary target** |
| `lock` | `+0x38` | 8 B | `struct rt_mutex *` | **Primary target** |
| `prio` | `+0x40` | 4 B | `int` | Waiter priority |
| `alignment padding` | `+0x44` | 4 B | — | aligns deadline |
| `deadline` | `+0x48` | 8 B | `u64` | deadline scheduling comparison |

> **Note:** Linux 5.10+ adds `wake_state` at `+0x40` making the structure 88 bytes (`0x58`). This field does NOT exist in 5.4. All public payloads targeting 5.10/5.15/6.x are ABI-incompatible with SM-X216B.

### 2.2 `struct rt_mutex` — Size: 32 bytes (`0x20`)
| Field | Offset | Size | Type |
|:---|:---|:---|:---|
| `wait_lock` | `+0x00` | 8 B | `raw_spinlock_t` |
| `waiters` | `+0x08` | 16 B | `struct rb_root_cached` |
| `owner` | `+0x18` | 8 B | `struct task_struct *` |

### 2.3 `struct futex_pi_state` — Size: 56 bytes (`0x38`)
| Field | Offset | Size | Type |
|:---|:---|:---|:---|
| `list` | `+0x00` | 16 B | `struct list_head` |
| `pi_mutex` | `+0x10` | 32 B | `struct rt_mutex` |
| `owner` | `+0x30` | 8 B | `struct task_struct *` |
| `refcount` | `+0x38` | 4 B | `refcount_t` |

### 2.4 `struct task_struct` — Critical Offsets (Verified)
| Field | Offset | Verification Source |
|:---|:---|:---|
| `pi_lock` | `+0x8dc` | Cross-checked at `remove_waiter`, `rt_mutex_adjust_prio_chain` |
| `pi_blocked_on` | `+0x900` | `remove_waiter @ 0xffffffc010376498`: `str xzr, [x20, #0x900]` |
| `pi_waiters` | `+0x908` | Derived from `pi_blocked_on` + sizeof(pointer) |

---

## 3. Vulnerable Code Path Analysis (CVE-2026-43499)

### 3.1 Call Chain

```
el0_svc (SP = SP_sys)
  └─ __arm64_sys_futex @ 0xffffffc0103c3498  [frame: sub sp,sp,#0x70]
       └─ do_futex @ 0xffffffc0103c02dc      [frame: 0x210 total]
            └─ [inlined] futex_wait_requeue_pi
                 ├─ rt_mutex_init_waiter(&rt_waiter)  @ [x29-0xc8]
                 └─ futex_requeue @ 0xffffffc0103c162c
                      └─ rt_mutex_start_proxy_lock @ 0xffffffc010376380
                           └─ remove_waiter @ 0xffffffc010376418  ← VULNERABLE
```

### 3.2 Stack Frame Computation (Fully Verified)

```
SP_sys        (el0_svc kernel entry)
SP_sys - 0x70 (after __arm64_sys_futex: sub sp,sp,#0x70)
SP_sys - 0xd0 (after do_futex prologue: stp x29,x30,[sp,#-0x60]!)
              x29 = SP_sys - 0xd0  ← Frame Pointer of do_futex
SP_sys - 0x280 (after do_futex: sub sp,sp,#0x1b0)
```

**Waiter location** (from `0xffffffc0103c0a64: sub x0, x29, #0xc8`):

```
waiter_base = x29 - 0xc8 = (SP_sys - 0xd0) - 0xc8 = SP_sys - 0x198
```

### 3.3 Waiter Field Absolute Coordinates

| Field | Absolute SP_sys Offset | Hex |
|:---|:---|:---|
| `waiter` (base) | `SP_sys - 408` | `- 0x198` |
| `waiter->tree_entry` | `SP_sys - 408` | `- 0x198` |
| `waiter->pi_tree_entry` | `SP_sys - 384` | `- 0x180` |
| `waiter->task` | `SP_sys - 360` | **`- 0x168`** |
| `waiter->lock` | `SP_sys - 352` | **`- 0x160`** |
| `waiter->prio` | `SP_sys - 344` | `- 0x158` |
| `waiter->deadline` | `SP_sys - 336` | `- 0x150` |
| `waiter` (end) | `SP_sys - 328` | `- 0x148` |

### 3.4 `remove_waiter` Vulnerability — Verified Disassembly

At `0xffffffc010376418` (inside `rt_mutex_start_proxy_lock`):

```armasm
0xffffffc010376450: mrs  x20, sp_el0          ; x20 = current (thread_info/task)
0xffffffc010376454: add  x21, x20, #0x8dc     ; &current->pi_lock
  [acquires pi_lock]
0xffffffc010376498: str  xzr, [x20, #0x900]   ; current->pi_blocked_on = NULL
```

**The vulnerability**: `remove_waiter` clears `current->pi_blocked_on` using `current` (from `sp_el0`) instead of `waiter->task`. If the racing thread has already been re-queued onto a different waiter, `waiter->task->pi_blocked_on` still points to the stale on-stack `rt_mutex_waiter` object at `SP_sys - 0x198` after `do_futex` returns and unwinds.

### 3.5 rb_erase Paths — Both Verified Present

| Symbol | Address | Role |
|:---|:---|:---|
| First `rb_erase` | `0xffffffc010375600` | Removes waiter from `lock->waiters` |
| Second `rb_erase` | `0xffffffc0103757d8` | Removes waiter from `task->pi_waiters` |

Both are inside `rt_mutex_adjust_prio_chain @ 0xffffffc01037583bc` which is reachable when the dangling `task->pi_blocked_on` is chased.

---

## 4. Stack Lifecycle — Critical Constraints

### 4.1 Stack Zeroing on Reuse (Fatal for Cross-Thread Spray)

From `dup_task_struct @ 0xffffffc0102f4158`:
```armasm
0xffffffc0102f414c: ldr  x0, [x25, #8]    ; x0 = stack base
0xffffffc0102f4150: mov  w2, #0x4000       ; 16384 bytes (16 KB)
0xffffffc0102f4154: mov  w1, wzr           ; value = 0
0xffffffc0102f4158: bl   #0xffffffc01008cb80  ; memset(stack, 0, 16KB)
```

**Every** thread stack allocated from `cached_stacks` (per-CPU cache at `0xffffffc012668be0`) is **unconditionally zeroed** before first use. Cross-thread stack spray via a newly spawned thread cannot carry stale waiter data.

### 4.2 Stack Release Timing

- Release is **delayed** through RCU grace period via `delayed_put_task_struct @ 0xffffffc0102f97d4`
- Free path: `put_task_stack()` → `release_task()` → `delayed_free_task()` → RCU callback

### 4.3 Consequence for Reclamation Strategy

> Stack reclamation of `waiter @ SP_sys-0x198` must be achieved by an **in-thread** syscall whose stack frame physically overlaps that address **within the same thread's lifetime**, before the dangling `pi_blocked_on` pointer is chased.

---

## 5. Entry Primitive Evaluation

### 5.1 Summary Table

| Primitive | Syscall | User Data Range | Covers `waiter->task` ? | Covers `waiter->lock` ? | Verdict |
|:---|:---|:---|:---:|:---:|:---|
| Native `pselect6` | `sys_pselect6` | `[SP_sys-0x210, SP_sys-0x1a8)` | ✗ (above waiter) | ✗ | **MISS + ZERO-WIPE** |
| Compat `pselect6` | `compat_pselect6` | `[SP_sys-0x220, SP_sys-0x1a8)` | ✗ (16B gap) | ✗ | **MISS + ZERO-WIPE** |
| `sys_ppoll` | `ppoll` | `[SP_sys-0x414, SP_sys-0x324)` | ✗ (396B gap) | ✗ | **MISS** |
| Compat IPv6 MCAST | `setsockopt(MCAST_JOIN_SOURCE_GROUP)` | `[SP_sys-0x350, SP_sys-0x248)` | ✗ (176B gap) | ✗ | **MISS (5.4 compat detour)** |
| Native IPv6 MCAST | `setsockopt(MCAST_JOIN_SOURCE_GROUP)` | Partial (16B near rb_parent_color) | ✗ | ✗ | **PARTIAL (wrong fields)** |
| `sys_sendmsg` | `sendmsg` (compat) | `[SP_sys-0x158, SP_sys-0xd8)` | ✗ (16B above) | ✗ | **MISS** |
| Native `__sys_sendmsg` | `sendmsg` | `[SP_sys-0x160, SP_sys-0x128)` | ✗ (starts at waiter+0x38) | Partial | **MISS: lock slot is `msg_name` user pointer; no task/tree prefix** |
| `sys_perf_event_open` | `perf_event_open` | `[SP_sys-0x118, SP_sys-0xa0)` | ✗ (56B above) | ✗ | **MISS** |
| **`sys_bpf`** | **`bpf()`** | **`[SP_sys-0x170, SP_sys-0x100)`** | **✓ `bpf_attr[+0x08]`** | **✓ `bpf_attr[+0x10]`** | **PARTIAL GEOMETRIC HIT** |

---

### 5.2 `sys_bpf` Detailed Stack Geometry

#### 5.2.1 `sys_bpf` Call Chain & Frame Analysis

```
el0_svc                (SP = SP_sys)
  └─ __arm64_sys_bpf @ 0xffffffc01043d308
       stp x29,x30,[sp,#-0x10]!
       SP_bpf_entry = SP_sys - 0x10
       └─ bl __do_sys_bpf @ 0xffffffc01043d4bc
            sub sp, sp, #0x180
            stp x29,x30,[sp,#0x120]
            add x29, sp, #0x120
            SP_do_sys_bpf_local = SP_sys - 0x10 - 0x180 = SP_sys - 0x190
            x29 = SP_sys - 0x190 + 0x120 = SP_sys - 0x070
```

#### 5.2.2 `union bpf_attr` Buffer Placement

```armasm
; From __do_sys_bpf @ 0xffffffc01043d558:
0xffffffc01043d558: add  x0, sp, #0x20     ; &bpf_attr = sp + 0x20
0xffffffc01043d55c: mov  w2, #0x70         ; size = 0x70 (112 bytes)
; Copy sequence:
; 1. memset(bpf_attr, 0, 0x70) @ 0xffffffc01043d568
; 2. copy_from_user(bpf_attr, uattr, usize) @ 0xffffffc01043d578
; 3. dispatch to bpf_cmd handler @ 0xffffffc01043d5a4
```

Buffer coordinates:
```
bpf_attr_base = SP_do_sys_bpf_local + 0x20
              = (SP_sys - 0x190) + 0x20
              = SP_sys - 0x170

bpf_attr_end  = SP_sys - 0x170 + 0x70
              = SP_sys - 0x100
```

#### 5.2.3 Overlap Matrix

```
Address     SP_sys offset   BPF buffer?   Waiter field?
─────────── ─────────────── ───────────── ──────────────────────────────
SP_sys-0x198  waiter_base       NO          waiter->tree_entry[0..7]
SP_sys-0x190                    NO          waiter->tree_entry[8..23]
SP_sys-0x180                    NO          waiter->pi_tree_entry[0..23]
SP_sys-0x170  bpf_attr[+0x00]   YES [base]  (28 bytes below waiter->task)
SP_sys-0x168  bpf_attr[+0x08]   YES         *** waiter->task ***
SP_sys-0x160  bpf_attr[+0x10]   YES         *** waiter->lock ***
SP_sys-0x158  bpf_attr[+0x18]   YES         waiter->prio
SP_sys-0x150  bpf_attr[+0x20]   YES [+40]   waiter->deadline
SP_sys-0x148  bpf_attr[+0x28]   YES [+48]   (waiter ends here)
SP_sys-0x100  bpf_end           NO
```

**Overlap**: `[SP_sys-0x170, SP_sys-0x148)` — **40 bytes**

**Coverage of critical fields**:
- `waiter->task` (`+0x30`) → `bpf_attr[+0x08]` ✅ **USER-CONTROLLED**
- `waiter->lock` (`+0x38`) → `bpf_attr[+0x10]` ✅ **USER-CONTROLLED**
- `waiter->prio` (`+0x40`) → `bpf_attr[+0x18]` ✅ **USER-CONTROLLED**
- `waiter->deadline` (`+0x48`) → `bpf_attr[+0x20]` ✅ **USER-CONTROLLED**

**Gap**: `waiter->tree_entry` and `waiter->pi_tree_entry` are 40 bytes **below** `bpf_attr_base` (not user-controlled by BPF buffer).

#### 5.2.4 Zero-Fill Risk Assessment

Unlike `pselect6`, the BPF buffer is:
1. **Pre-zeroed** via `memset(bpf_attr, 0, 0x70)` before `copy_from_user` — this is a one-way initialization, not a trailing clear of waiter fields.
2. **User-filled** via `copy_from_user(bpf_attr, uattr, usize)` — the entire 112 bytes (or user-specified `usize` up to `0x70`) is written from userspace without subsequent zeroing.

> There is **no zero-wipe of the bpf_attr region after user copy**. If the buffer physically occupies `SP_sys - 0x170` to `SP_sys - 0x100` during a same-thread reuse scenario, `waiter->task` and `waiter->lock` would contain **user-specified values**.

#### 5.2.5 Same-thread runtime check and stack lifetime

The earlier claim that same-thread BPF was impossible relied on an incorrect
reading of `remove_waiter()`. Runtime tracing shows it clears
`current->pi_blocked_on` while leaving the waiter's own field pointing at the
stack waiter. A same-thread QEMU probe measured the copied `bpf_attr` at
`waiter + 0x28`; its task, lock, and priority words appeared at `waiter +
0x30`, `+0x38`, and `+0x40` immediately after `copy_from_user`.

The copy is not durable in the tested flow. Hardware watchpoints caught normal
scheduler/context-switch code overwriting those words before the other
thread's PI walk consumed them. The consumer faulted while following the
stale/corrupted fields. GDB did not execute the target `rb_erase`, so BPF is a
verified geometric overlap but a failed backend for this timing sequence.
Captures: `/root/s/qemu-stale-waiter-bpf-watch-gdb.log` and
`/root/s/qemu-stale-waiter-bpf-serial.log`.

---

### 5.3 Native pselect6 — Eliminated (Fully Proven)

**Call chain**: `__arm64_sys_pselect6` → `core_sys_select @ 0xffffffc010543e54`

```
stack_fds_base = SP_sys - 0x210 + 0x50 = SP_sys - 0x1c0
stack_fds range: [SP_sys-0x1c0, SP_sys-0x198)   [96 bytes for N=320 bits]
res_in  range:   [SP_sys-0x198, SP_sys-0x180)   [24B, unconditionally zeroed]
res_out range:   [SP_sys-0x180, SP_sys-0x168)   [24B, unconditionally zeroed]
res_ex  range:   [SP_sys-0x168, SP_sys-0x150)   [24B, unconditionally zeroed]
```

**`waiter->task` at SP_sys-0x168** falls inside `res_out` — **zeroed by `__memset @ 0xffffffc01053e468`**. **ELIMINATED.**

### 5.4 Compat pselect6 — Eliminated (Fully Proven)

**Call chain**: `__arm64_compat_sys_pselect6_time32 @ 0xffffffc01053d38c` → `compat_core_sys_select @ 0xffffffc01053e26c`

```
Cumulative frame depth to compat_core_sys_select: 0x50 bytes
stack_fds_base = SP_sys - 0x50 - 0x1d0 + 0x10 = SP_sys - 0x210
For max N=320 bits (40 bytes per fd_set × 3 = 120B = 0x78):
  in_fds range:  [SP_sys-0x210, SP_sys-0x1b8)  user-controlled
  out_fds range: [SP_sys-0x1b8, SP_sys-0x160)  user-controlled
  ex_fds range:  [SP_sys-0x160, SP_sys-0x108)  user-controlled
res_in zeroed:   [SP_sys-0x1a8, SP_sys-0x190)
res_out zeroed:  [SP_sys-0x190, SP_sys-0x178)
res_ex zeroed:   [SP_sys-0x178, SP_sys-0x160)
```

User-controlled input ends at `SP_sys - 0x1a8`. Waiter base at `SP_sys - 0x198`: **16-byte gap**. `waiter->task` at `SP_sys - 0x168` falls inside **zeroed** `res_out`. **ELIMINATED.**

### 5.5 sys_ppoll — Eliminated

`do_sys_poll @ 0xffffffc01053dc20` allocates `0x3f0` bytes (dominated by `struct poll_wqueues` = `0x230` bytes on stack). `stack_pps` buffer at `[SP_sys-0x414, SP_sys-0x324)`. Gap to waiter: **396 bytes (`0x18c`)**. **ELIMINATED.**

### 5.6 Compat IPv6 MCAST setsockopt — Eliminated

Linux 5.4 routes `MCAST_JOIN_SOURCE_GROUP` through `compat_mc_setsockopt` which adds an extra `0x80` frame + another `0x40` frame (unlike 5.10+ which inlines). User buffer sits at `[SP_sys-0x350, SP_sys-0x248)`. Waiter ends at `SP_sys-0x150`. **Gap: 248 bytes below waiter**. **ELIMINATED.**

### 5.7 Later bounded runtime checks

- A standalone 64-bit QEMU test confirmed the `mmsghdr` ABI and a valid
  `recvmmsg` payload/source-address round trip. The `msg_len` member is at
  offset 56; a custom 128-byte header with a trailing length field does not
  match the syscall ABI.
- A standalone ARM32 binary ran on the ARM64 QEMU kernel. Its IPv4
  `MCAST_JOIN_GROUP` and `MCAST_BLOCK_SOURCE` calls both returned success.
  This is a functional compat check only; it does not establish stack
  overlap, waiter reuse, or a memory-corruption effect.
- A benign unknown-address-family socket request returned `EAFNOSUPPORT` and
  did not invoke a sentinel `/sbin/modprobe`. This is consistent with the
  stock empty static UMH path documented below.
- The saved native `recvmmsg` pre/post erase trace shows an empty waiter root
  and unchanged node/root words. The separate tree-write trace records a
  change to the right-child word at an `import_iovec` store; the other two
  tree words were already zero in the first snapshot. This does not show
  `import_iovec` clearing all three tree words or a controlled write.

The 5.15.189 S23 Ultra references do not change these X216B results. The
`tcp-zerocopy-sm` repository describes its work as incomplete and warns that
its standalone checks were incorrect. The linked S9180 profile is marked
in-progress and uses a newer target layout. Treat the references as
version-specific context, not X216B validation.

---

## 6. Symbol Availability for Post-Primitive Techniques

**UMH configuration caveat:** although `call_usermodehelper*` symbols are
present, the firmware config sets `CONFIG_STATIC_USERMODEHELPER=y` and
`CONFIG_STATIC_USERMODEHELPER_PATH=""`. Linux documents an empty static helper
path as disabling usermode-helper launches. Treat the symbol list below as
availability evidence only, not proof that an UMH daemon can be started.

All symbols verified in `kallsyms.txt`:

| Symbol | Address | Purpose |
|:---|:---|:---|
| `do_futex` | `0xffffffc0103c02dc` | Vulnerability anchor |
| `remove_waiter` | `0xffffffc010376418` | Vulnerable function |
| `rt_mutex_adjust_prio_chain` | `0xffffffc010375b3bc` | Prio-chain walker |
| `init_task` | `0xffffffc0129e0280` | Root task_struct |
| `init_cred` | `0xffffffc0129ec740` | Root credentials |
| `commit_creds` | `0xffffffc010327184` | Credential commit |
| `anon_pipe_buf_ops` | `0xffffffc0121f55b8` | Pipe buffer ops |
| `ashmem_fops` / `ashmem_misc` | `0xffffffc0121cee28` / `0xffffffc0129cbae0` | Ashmem file ops |
| `ashmem_misc.fops` | `0xffffffc0129cbaf0` | Direct fops pointer (`+0x10`) |
| `configfs_read_file` | `0xffffffc0105d924c` | configfs read primitive |
| `configfs_write_bin_file` | `0xffffffc0105d9784` | configfs write primitive |
| `call_usermodehelper_exec_work` | `0xffffffc010317274` | UMH launch work |
| `system_unbound_wq` | `0xffffffc01296f9c8` | Unbound workqueue |
| `selinux_state` | `0xffffffc012b9f000` | SELinux enforcing bit |
| `cached_stacks` | `0xffffffc012668be0` | Per-CPU stack cache |
| `dup_task_struct` | `0xffffffc0102f4068` | Stack allocation |
| `__do_sys_bpf` | `0xffffffc01043d4bc` | BPF syscall handler |
| `compat_ipv6_setsockopt` | `0xffffffc011472188` | IPv6 compat setsockopt |

---

## 7. Reference Architecture Compatibility Matrix

| Reference Repo | Target Platform | Entry Primitive | Compatibility on SM-X216B | Blocking Factor |
|:---|:---|:---|:---|:---|
| `ang3lo-azevedo/root-my-nothing` | Nothing Phone 1 (SM7325, Linux 5.4.302) | 64-bit `pselect6` | **INCOMPATIBLE** | `pselect6` fails; task_struct offset drift (`pi_lock` 0x8c4 vs 0x8dc) |
| `sarabpal-dev/IonStack-S22U` | S22 Ultra (SM8450, Linux 5.10.226) | ARM32 compat `setsockopt` (exp32) | **PARTIAL** (highest structural match) | 5.4 compat IPv6 path diverges; geometry recalibration needed |
| `soumarcelino/Root-My-Galaxy-SM-S918B` | S23 Ultra (SM8550, Linux 6.1.x) | 64-bit `pselect6` + sigreturn | **INCOMPATIBLE** | Closed binary hardcodes 88B waiter with `wake_state` |
| `BuSung-dev/Root-My-Galaxy-Payloads` | S24/S25/TabS9/A15 (5.10/5.15/6.x) | Multi-target profiles | **INCOMPATIBLE** | No X216B/SM6375 profile |
| `mobilehackinglab/ghostlock-a17` | A17 (MT6789, Linux 6.12.23) | `pselect6` + BTF | **INCOMPATIBLE** | 6.12 BTF-dependent; `pselect6` fails on 5.4 |
| `NebuSec/CyberMeowfia` | Generic Android 6.x | 64-bit `pselect6` | **INCOMPATIBLE** (as-is) | Hardcodes 6.x struct offsets; `pselect6` fails |

---

## 8. Reusable Architecture Components

### 8.1 From `ang3lo-azevedo/root-my-nothing` (5.4 baseline — closest ancestor)
- ⚠️ X216B uses an 80-byte waiter with deadline at `+0x48`; account for this target layout in any port
- ✅ `ashmem_fops` corruption post-primitive concept
- ✅ `configfs` r/w chain (`generic_file_splice_read` → arbitrary kernel read)
- ✅ KASLR slide recovery from `Image` bytes (p0 fingerprint methodology, reapplicable to SM6375)
- ✅ `FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI` race trigger
- ❌ Entry primitive (`pselect6`) — must be replaced
- ❌ `task_struct` offsets — must be recalibrated (`pi_lock` at `0x8dc`, `pi_blocked_on` at `0x900`)

### 8.2 From `sarabpal-dev/IonStack-S22U` (exp32 — compat reference only)
- ✅ ARM32 compat thread model (`exp32` paradigm) — `CONFIG_COMPAT=y` confirmed
- ✅ Concept: park a 32-bit thread in a setsockopt blocking spin to hold stack occupancy
- ⚠️ Post-primitive UMH daemon is a reference concept only; the X216B config's empty static helper path disables UMH launches
- ❌ Actual `compat_ipv6_setsockopt` geometry — 5.4 adds `compat_mc_setsockopt` detour (+0x80+0x40), making buffer miss waiter by 248B
- ❌ `EXP32_STAMP_OFF` calibration — must be re-derived from X216B binary

### 8.3 From `soumarcelino/Root-My-Galaxy-SM-S918B` (tooling only)
- ✅ `patch_payload.py` patching methodology (rewritable ARM64 `movz` immediates)
- ✅ `p0_fingerprint` KASLR resolution (reapplicable to SM6375 with new fingerprint table)
- ✅ Profile schema format (`targets-v3.json`)
- ❌ Closed-source engine binary — ABI-incompatible

---

## 9. Remaining Open Questions (Require On-Device Measurement)

| Question | Why Static Cannot Resolve | Required Method |
|:---|:---|:---|
| **Exact in-thread syscall stack depth collision** | CPU scheduling varies per hardware | On-device timing + stack pointer logging |
| **RCU grace period window duration** | Depends on CPU load, scheduler policy, preemption points | On-device profiling |
| **Stack physical page reuse timing** | `cached_stacks` slot availability is per-CPU and runtime | On-device thread spawn timing |
| **BPF CAP_BPF / CAP_SYS_ADMIN requirement** | Depends on SELinux policy + privilege context | Policy audit + capability enumeration |
| **`sys_bpf` unprivileged access from restricted context** | SELinux `bpf { map_create prog_load }` requires checking policy | Runtime SELinux audit log |

---

## 10. Final Classification

```
╔══════════════════════════════════════════════════════════════════════════════╗
║  SM-X216B KERNEL ANALYSIS — CURRENT EVIDENCE SUMMARY                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  CVE Presence:       CONFIRMED (vulnerable remove_waiter at 0x10376418)     ║
║  Waiter Geometry:    0x50 target layout; see recvmmsg coverage limitation ║
║  Second rb_erase:    CONFIRMED PRESENT (0x103757d8)                         ║
║  Samsung KDP:        ABSENT                                                  ║
║                                                                              ║
║  Entry Primitive Status:                                                     ║
║    pselect6 (native):     ELIMINATED — zero-wipe of critical fields         ║
║    pselect6 (compat):     ELIMINATED — 16B gap + zero-wipe                  ║
║    sys_ppoll:             ELIMINATED — 396B gap                             ║
║    IPv6 MCAST (compat):   ELIMINATED — 248B gap (5.4 compat detour)        ║
║    sys_bpf:               PARTIAL GEOMETRIC HIT                             ║
║                           waiter->task @ bpf_attr[+0x08] COVERED           ║
║                           waiter->lock @ bpf_attr[+0x10] COVERED           ║
║                           BLOCKER: cross-thread stack zeroing               ║
║                           BLOCKER: same-thread race window unproven         ║
║    compat IPv4 MCAST:     functional ABI only; no stack overlap measured    ║
║    standard UMH launch:   DISABLED by empty static helper path              ║
║                                                                              ║
║  Controlled Write:       NOT DEMONSTRATED                                   ║
║  Root Transition:        NOT DEMONSTRATED (initramfs starts UID 0)          ║
║  Runtime Exploitability: NOT ESTABLISHED BY CURRENT EVIDENCE                ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## Appendix A: Key Symbol Addresses

```
do_futex                          = 0xffffffc0103c02dc
__arm64_sys_futex                 = 0xffffffc0103c3498
remove_waiter                     = 0xffffffc010376418
rt_mutex_adjust_prio_chain        = 0xffffffc0103753bc
rt_mutex_start_proxy_lock         = 0xffffffc010376380
__arm64_sys_bpf                   = 0xffffffc01043d308
__do_sys_bpf                      = 0xffffffc01043d4bc
__arm64_compat_sys_pselect6_time32= 0xffffffc01053d38c
compat_core_sys_select            = 0xffffffc01053e26c
core_sys_select                   = 0xffffffc010543e54
__arm64_sys_ppoll                 = 0xffffffc01053cf6c
do_sys_poll                       = 0xffffffc01053dc20
compat_ipv6_setsockopt            = 0xffffffc011472188
do_ipv6_setsockopt                = 0xffffffc0114710b0
init_task                         = 0xffffffc0129e0280
init_cred                         = 0xffffffc0129ec740
commit_creds                      = 0xffffffc010327184
anon_pipe_buf_ops                 = 0xffffffc0121f55b8
ashmem_fops                       = 0xffffffc0121cee28
ashmem_misc                       = 0xffffffc0129cbae0
configfs_read_file                = 0xffffffc0105d924c
configfs_write_bin_file           = 0xffffffc0105d9784
call_usermodehelper_exec_work     = 0xffffffc010317274
system_unbound_wq                 = 0xffffffc01296f9c8
selinux_state                     = 0xffffffc012b9f000
cached_stacks                     = 0xffffffc012668be0
dup_task_struct                   = 0xffffffc0102f4068
```

## Appendix B: Files in This Analysis

| File | Contents |
|:---|:---|
| `vmlinux.elf` | Target kernel ELF binary |
| `kallsyms.txt` | 185,206 kernel symbol addresses |
| `raw_ikconfig.md` | Extracted `CONFIG_*` options |
| `futex_feasibility_report.txt` | Full do_futex disassembly + remove_waiter proof |
| `futex_pi_report.txt` | rt_mutex_adjust_prio_chain rb_erase verification |
| `compat_pselect_geometry_report.txt` | Complete compat pselect6 elimination proof |
| `ppoll_geometry_report.txt` | sys_ppoll/sys_poll elimination proof |
| `smx216b_runtime_gap_corrected.txt` | Stack lifecycle + dup_task_struct zeroing analysis |
| `smx216b_alternative_architecture_matrix.md` | 6-repo compatibility comparison |
| `x216b_architecture_compatibility_final.md` | Detailed per-architecture breakdown |
| `smx216b_final_research_report.md` | **This file — consolidated final report** |
