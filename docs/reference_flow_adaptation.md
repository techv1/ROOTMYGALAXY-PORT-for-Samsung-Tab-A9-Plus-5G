# Reference flow reassessment for SM-X216B

This note reassesses the X216B port using the correction and probe methods in
`references/`. It separates a route's static geometry from a runtime-tested
stamp. The existing compatibility reports should be read as static analysis
unless they cite a matching X216B runtime probe.

## What the reference repositories changed after tests

- **IonStack-S22U** records a TCG-specific failure mode: a syscall used to
  print diagnostics can reuse and overwrite the stamped stack region. Its
  exp32 stage therefore stamps a bounded number of times, parks in userspace
  without another syscall, and lets a separate consumer trigger the walk.
  Runtime attempts run in fresh child processes. See
  `references/IonStack-S22U/src/exp32/stack.c` and `MEMORY.md`.
- **GhostLockAdapt** kept multiple stamp backends, including IPv4 MCAST and
  `sendmmsg`, and added indexed sentinel probes. A fault register exposed the
  actual `sendmmsg` iovec-to-waiter mapping and corrected an earlier wrong
  field map. Its notes distinguish “copy reached stack” from “primitive
  completed.” See `references/GhostLockAdapt/poc-mcast/docs/OBSERVATIONS.md`
  and `poc_air/docs/OBSERVATIONS.md`.
- **ghostlock-a17** treats QEMU as an end-to-end validation harness for an
  exact extracted kernel and documents guest-only changes separately from
  device behavior. It found that gdbstub breakpoints were ineffective in its
  setup and used temporary kernel printk instrumentation instead. Its logs
  retain each boot's diagnostic evidence.

The reusable lesson is the test loop: one controlled stamp, a marker that
identifies the source word, one consumer walk, preserved panic/register logs,
then a fresh run after changing only one variable. Static disassembly chooses
candidate offsets; runtime markers establish whether the bytes landed.

## X216B evidence checked against `vmlinux.elf`

- Target disassembly and marker probes corroborate `task +0x30`, `lock +0x38`,
  and `prio +0x40`. Android 5.4 RT-mutex source and target disassembly identify
  `deadline +0x48`, making the target waiter 80 bytes (`0x50`) with alignment
  padding at `+0x44`. The earlier `deadlocked +0x44`/72-byte description was
  wrong for this target; see the GDB trace below and the [Android common 5.4
  RT-mutex implementation](https://android.googlesource.com/kernel/common/%2B/refs/tags/ASB-2024-02-05_12-5.4/kernel/locking/rtmutex.c),
  which compares waiter deadlines for deadline-priority tasks.
- The current `/root/s/minimal-rmg/futex_race.c` still uses the `recvmmsg`
  backend and hard-coded task/lock values. Its `EXP32_STAMP_OFF` helper is not
  used, and `spray.c` is a stub. The successful QEMU log proves the PI race
  reaches `EDEADLK` and the consumer runs; it does not prove that a stamp hit
  waiter fields.
- The archive's MCAST elimination covers IPv6 `MCAST_JOIN_SOURCE_GROUP`
  geometry, especially the 5.4 compat detour through `compat_mc_setsockopt`.
  It does not establish that the distinct IPv4 `IPPROTO_IP` MCAST route lands
  or fails at runtime. The IPv4 handler copies a 264-byte request into
  `do_ip_setsockopt`'s local frame; its exact frame-to-waiter overlap should be
  instrumented before claiming it is viable.
- The `sendmmsg` route from GhostLockAdapt is worth measuring, but the X216B
  disassembly gives it a poor initial geometry. `__sys_sendmmsg` has a local
  8-entry iovec array beginning at `SP_sys-0x210`; the X216B waiter begins at
  `SP_sys-0x198`. That array intersects only the waiter's first 8 bytes. It
  cannot directly stamp `task` or `lock` through the fast iovec array as
  currently laid out. This is a static result, not a runtime probe.
- The pselect report's zeroing/adjacency argument is much stronger than a
  mere offset mismatch, but the report still needs an X216B marker run if we
  want a runtime classification comparable to the reference repositories.

## Port order

1. Add a probe-only mode to the existing X216B `recvmmsg` stage. Fill each
   qword with a distinct harmless marker, leave the consumer sequence intact,
   and capture the first faulting register/value from QEMU. This directly
   checks the current `SP_sys-0x188` copy destination and the `+0x20/+0x28`
   field assumptions.
2. Keep the final stamp syscall as the last kernel entry by parking the
   waiter in userspace immediately after it returns. The consumer can then
   run independently, following the TCG lesson from IonStack.
3. If recvmmsg's measured map misses the required fields, add one backend at a
   time: IPv4 MCAST first (not IPv6 compat), then a deliberately adjusted
   iovec/sendmsg shape if disassembly exposes a stack array that covers the
   needed fields. A backend is retained only with a marker-confirmed overlap.
4. Build a fresh initramfs for every source revision, boot the exact X216B
   image with the corrected QEMU command from `logs/README.md`, and save the
   binary hash plus full serial log per attempt. Do not use
   `qemu-x216b-test/run_qemu_test.sh` as evidence for this kernel; it boots a
   different test environment.

## QEMU results (September 27, 2026)

The reference-style marker experiment has now been run on three fresh QEMU
boots using the exact X216B 5.4.249 kernel and a separate probe initramfs:

- With `0xdeadbeefcafebabe` in the presumed lock slot, the kernel faulted on
  that exact address in `_raw_spin_trylock` from
  `rt_mutex_adjust_prio_chain`.
- With the same marker in the presumed task slot, the fault address was
  `0xdeadbeefcafec39a`, exactly marker `+0x8dc`, the verified
  `task_struct::pi_lock` offset.
- The lock-slot result repeated on a second boot.

This confirms that the X216B `recvmmsg` copy reaches `waiter->task` and
`waiter->lock` at payload offsets `+0x20` and `+0x28`. It starts at waiter
offset `+0x10` and covers through `+0x47`, leaving the first 16 bytes of
`tree_entry` outside the copy. The fault outcomes are expected for these
intentionally invalid marker pointers.

An additional GDB-over-stdio run stopped immediately before and after the
target's `rb_erase` call at `rt_mutex_adjust_prio_chain+0x244`. The captured
waiter words were zero at `+0x00..+0x2f`, task pointer `0xffffffc0129e0280`
at `+0x30`, lock pointer `0xffffffc012f04080` at `+0x38`, priority `0x78`
at `+0x40`, and zero at `+0x48`. The exact capture is
[`qemu-rbtrace-gdb.log`](/root/s/qemu-rbtrace-gdb.log). Disassembly then
shows this path stores an eight-byte value at `+0x48` (`adjust_prio_chain`
`+0x25c`) and later reads it (`+0x2ac`). The value is copied from
`task_struct +0x428`, the task deadline field. Together with Android 5.4
RT-mutex source, this identifies waiter `deadline +0x48`, `+0x44` as alignment
padding, and size `0x50`. The QEMU snapshot establishes actual field values at
the breakpoint for this baseline execution only.

The normal baseline run also reproduced `CMP_REQUEUE_PI: EDEADLK confirmed`,
the waiter's timeout, and a successful `sched_setattr` call without a kernel
fault. Since the initramfs starts as UID 0, none of these runs establishes
privilege escalation.

## Current conclusion

The earlier report was too categorical when it treated static elimination as
the end of the investigation. Runtime evidence confirms the current recvmmsg
map for task and lock and shows zeroes in the first 16 bytes at the captured
`rb_erase` call. The payload covers through `prio` at `+0x40`, but misses the
deadline at `+0x48`. Disassembly reads the deadline for deadline-class
priorities and stores a fresh task deadline after the observed `rb_erase`;
the follow-up GDB trace with baseline prio `0x78` did not take the deadline
comparison and refreshed the field to zero after `rb_erase`. The source
`v_prio=120` matches the runtime `0x78` at waiter `+0x40` in two fresh QEMU
boots. This resolves the deadline-read question for the current
normal-priority payload;
do not change it into the deadline-class range without also controlling the
deadline. A one-run zero snapshot does not establish that stack bytes remain
safe across schedules. X216B's current sendmmsg geometry still misses
task/lock, and IPv6 compat MCAST still has the 5.4 frame detour. A distinct
IPv4 MCAST route remains a candidate for measurement, not a proven replacement.

## Reference `rb_erase` forge and X216B hybrid check

The reference folder contains useful source, not a target-ready payload:

- `references/IonStack-S22U/src/main.c` shows the fields used by its forged
  `tree_entry` (`parent_color`, `rb_right`, and `rb_left`) and describes the
  child-parent write made during erase.
- `references/GhostLockAdapt/poc-mcast/poc_mcast.c` contains its complete
  0x108-byte MCAST stamp and indexed-marker probes; its verification notes
  cover a 5.15 target with a different copy offset.

On X216B, `recvmmsg` stamps waiter `+0x10..+0x47`: it can set `rb_left` and the
task/lock/prio tail, but it cannot set `tree_entry.parent_color` or
`tree_entry.rb_right`. IPv4 MCAST's 0x108-byte copy overlaps `+0x00..+0x2f`,
but its call frames leave the later waiter words as stack residue. An isolated
hybrid build placed distinct tags in both syscall windows and confirmed each
at the copy-return breakpoint. Neither MCAST-first/recvmmsg-last nor
recvmmsg-first/MCAST-last reached the target-lock chain repeatably. The
MCAST-last trace showed stack residue at waiter `+0x30..+0x48`; a run also
reported an RCU stall in the PI chain. See `logs/README.md` for preserved
captures and the precise limitation: the copy ranges complement each other,
but the current syscall sequence does not preserve both regions through the
consumer walk.

The next backend search should favor one syscall whose copy and live stack
frame cover the fields needed at the same consumer point. Do not adapt the
reference write payload until runtime tracing confirms the full waiter state
immediately before the target `rb_erase` call.

### Single-child promotion proposal: measured status

The proposal's field ordering matches this kernel's `rb_node`: parent/color
at `+0`, right child at `+8`, left child at `+0x10`. A dedicated isolated
probe used MCAST to stamp `parent_color=0` and a mapped candidate right-child
pointer, then recvmmsg to stamp `rb_left=0` and the waiter tail. GDB confirmed
those words at the two copy-return sites. The five-second PI wait had already
timed out before the stamps, however, and the target-lock `rb_erase` callsite
was never reached. Extending that wait to 120 seconds kept execution inside
the wait until the 55-second QEMU timeout, so it did not stamp either. The
probe therefore does not validate the promotion at a live erase and does not
show a write primitive. Its GDB handler skips the erase if the target callsite
is ever reached. See `qemu-hybrid-singlechild-serial.log` and
`samsung_x216b_research/scripts/trace_hybrid_singlechild_gdb.gdb`.

A follow-up now uses the reference's process-private futex operations,
`nr_requeue=0`, and no-op `SIGUSR1` release. QEMU confirmed
`EDEADLK -> tgkill success -> EAGAIN`, followed by both stamps. The consumer's
PI walk still did not reach the candidate erase. A follow-up GDB stop at
`rt_mutex_adjust_prio_chain+0x70` saw `x25` equal to the candidate waiter but
the nonblocking version's stamped values changed before the PI check. Making
recvmmsg block preserved `rb_left`, task, lock, and priority at that check, but
the MCAST `rb_right` word became a stack pointer (`candidate+0x48`) by the
recvmmsg copy breakpoint and was zero by the PI check. The single-child shape
still does not reach the consumer intact. The trace and hashes are recorded in
`qemu-hybrid-singlechild-gdb.log` and `logs/README.md`; an earlier uninstrumented
run reported a soft lockup, while the current GDB handler stops before the
retry loop repeats.

## Original IonStack articles and methods in this port

The supplied Part I URL (`/research/ionstack-part-1/`) is not the GhostLock
background article; the published Part I URL is
`/research/ionstack-part-1-cve-2026-10702/`, about Firefox SpiderMonkey and
unrelated to this kernel port. Part II is the generic Linux GhostLock writeup;
Part III is its Android 17 adaptation.

Part II describes the stale `pi_blocked_on` after the `EDEADLK` rollback,
then reclaims the returned waiter's stack with `PR_SET_MM_MAP` and a controlled
`user_auxv` copy. It uses a crafted single-child rb-tree erase and a lock
pointer positioned relative to a target slot. Part III changes that device
path: it uses `pselect` to reclaim the waiter frame and KernelSnitch plus
cross-cache reuse to locate a sprayed `sk_buff` containing the fake lock.
Those are different stages: KernelSnitch locates kernel allocations/fake
objects; it is not the rb-tree erase primitive itself.

The local reference implementations contain those ideas in code and docs.
For example, `references/IonStack-S22U/src/main.c` documents a forged rb node
and constrained erase write (its current port uses an exp32 stamp route), and
`references/GhostLockAdapt/exploit-finale/docs/KERNELSNITCH.md` documents the
futex-hash `mm_struct` leak used to locate pipe-buffer memory. Its
`poc-mcast/docs/OBSERVATIONS.md` also records an important trigger detail:
after `FUTEX_CMP_REQUEUE_PI` returns `EDEADLK`, set `f_wait=1` and signal the
waiter with `SIGUSR1`, so the wait restarts and returns `EAGAIN` before the
stack stamp. The first X216B hybrid run omitted this and observed `ETIMEDOUT`;
the follow-up now matches the release sequence and observes `EAGAIN`, but the
consumer walk soft-locks before the candidate erase.

The current X216B test harness does **not** use KernelSnitch: its
`minimal-rmg*/target.h` values are fixed addresses for this QEMU image, and its
current work is GDB-measured `recvmmsg`/IPv4 MCAST stack-copy geometry. The
KernelSnitch headers and implementations under `references/` are reference
code only; none is linked into `minimal-rmg`, `minimal-rmg-ipv4`, or
`minimal-rmg-hybrid`. Next, stop the consumer in `rt_mutex_adjust_prio_chain`
before it loops, and inspect the active lock and PI-tree transition without
executing the candidate erase.

### X216B rollback ownership validated at runtime

The target disassembly at `remove_waiter+0x3c..+0x80` gets `current` from
`sp_el0`, takes `current->pi_lock`, and clears `current->pi_blocked_on`.
At `remove_waiter+0x208`, it passes `current` as the final task argument to
`rt_mutex_adjust_prio_chain()`. The upstream fix instead takes and updates
`waiter->task` and passes that task to the chain walk. A QEMU GDB run at
`+0x48` confirmed `waiter->task != current`; after the clear, the waiter
owner's `pi_blocked_on` still referenced the stack waiter. At the callsite,
the final task argument was the requeueing current task. The trace is
`/root/s/qemu-remove-waiter-owner-gdb.log`, with harness
`/root/s/samsung_x216b_research/scripts/trace_remove_waiter_owner_gdb.gdb`.

This confirms the vulnerable lifetime/ownership path on the QEMU image. It
does not change the separate result that `import_iovec` clears the candidate
`rb_right` in the recvmmsg overlap, nor does it prove a controlled write.

### Same-run stale waiter to consumer trace and left-field alias

The newest baseline trace saved the waiter at the EDEADLK rollback, confirmed
that `do_recvmmsg` reused that exact address, and stopped when the PI walk
passed it to the lock waiters `rb_erase` callsite. The call was not executed;
all three rb-tree words and the lock root were zero there.

A diagnostic `msg_name` input set the candidate `rb_left` to
`ADDR_VERIFIED_VLOCK`. It reached the same callsite with `rb_right=0`, but a
watchpoint caught `do_recvmmsg` storing the same `msg_name` pointer into the
aliased `rb_parent_color` slot at `0xffffffc0112ed5f4`. The current recvmmsg
path therefore cannot independently control those two fields through this
header value. Captures and hashes are recorded in the top-level
`logs/README.md`; the test stops before `rb_erase` executes.

Other syscall backends remain candidates only if measurements show that they
overlap this same waiter on its owning thread and preserve independently
controlled tree links plus the required waiter tail until this consumer call.
