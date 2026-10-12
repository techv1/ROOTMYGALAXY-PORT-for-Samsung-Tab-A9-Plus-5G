# SM-X216B GhostLock Research Roadmap

**Status date:** 2026-09-30  
**Target:** Samsung Galaxy Tab A9+ 5G, SM-X216B (`gta9p`)  
**Firmware/kernel:** `X216BXXS9DYJ7`, `5.4.249-qgki-31053672-abX216BXXS9DYJ7`  
**Current test setup:** extracted target kernel in QEMU `virt` with TCG; generic
QEMU is a diagnostic environment, not a full SM6375 hardware model.

This roadmap records what has actually been run, what the results establish,
and the remaining work in dependency order. A marker-induced kernel panic is
an expected diagnostic result; it is not a successful privilege escalation.
The dated consolidation is in
[verified_findings_2026-09-30.md](/root/s/samsung_x216b_research/docs/verified_findings_2026-09-30.md).
That note also has the QEMU-verified GDB breakpoint map, with evidence logs,
scripts, and a distinction between stops actually reached and stops merely
configured.

## Current state

The futex trigger and consumer sequence run on the target kernel in QEMU. Two
fresh-boot marker probes confirm that the 56-byte `recvmmsg` copy reaches the
stale waiter's `task` and `lock` fields at payload offsets `+0x20` and `+0x28`.
A GDB trace confirms the PI-walk passes the waiter base to `rb_erase`; the
first 16 bytes were zero in that baseline run. Target disassembly and Android
5.4 RT-mutex source establish an 80-byte (`0x50`) waiter: `prio +0x40`,
alignment at `+0x44`, and `deadline +0x48`.

No working write primitive, kernel read/write channel, or non-root-to-root
transition has been implemented. `main.c` runs as UID 0 in the initramfs, so
UID 0 there cannot be used as evidence of escalation.

A new GDB run confirms the vulnerable rollback dynamically: the stack waiter’s
`task` differs from `current`; `remove_waiter()` clears `current->pi_blocked_on`
but leaves `waiter->task->pi_blocked_on` pointing at the waiter, then passes
`current` to `rt_mutex_adjust_prio_chain()`. This validates the bug path in the
QEMU image, not an exploit primitive.

The latest run follows that same waiter through recvmmsg stack reuse to the
lock-tree erase callsite and stops before execution. A diagnostic left-child
probe reaches the callsite, but `do_recvmmsg` copies its `msg_name` input into
both the candidate `rb_left` and `rb_parent_color` slots. This path does not
independently control those fields, and no useful write has been shown.

The saved tree-write trace narrows the `import_iovec` observation: only the
right-child word changed at the recorded store; the parent and left-child
words were already zero in the first snapshot. A separate pre/post
`rb_erase` trace shows an empty waiter root and unchanged node/root words.
This is a clean baseline, not evidence of a write primitive or a general
safe-leaf property.

A BPF-only QEMU probe verified the predicted `bpf_attr` overlap at
`waiter+0x28`: task, lock, and priority appear there immediately after
`copy_from_user`. Scheduler/context-switch stack writes replace those values
before the delayed consumer reads them; the diagnostic ended in a contained
QEMU Oops and did not reach the target `rb_erase`. BPF is not viable in the
tested timing sequence. The older report's claim that same-thread BPF was
impossible is corrected; the measured blocker is stack lifetime/reuse.

Static review of the target's signal syscall wrappers also found no useful
overlap: `rt_sigprocmask` copies 8 bytes near `SP_sys-0x50`, `rt_sigaction`
copies 32 bytes near `SP_sys-0x58`, and `rt_sigqueueinfo` copies 48 bytes near
`SP_sys-0xb8`; the waiter starts at `SP_sys-0x198`. Signal delivery can help
coordinate userspace threads, but it does not supply a waiter stamp or block
the synchronous `rb_erase` path.

The native `sendmsg` path was also checked: its 56-byte `msghdr` copy lands at
`waiter+0x38..+0x70`, but its first qword is `msg_name`, a userspace pointer.
It cannot provide a valid kernel `waiter->lock`, and it does not reach the
task or tree prefix. No runtime probe is warranted for that layout.

The syscall ABI checks cover a valid 64-bit `mmsghdr` round trip, including
the returned payload length and Unix source address. The ABI places `msg_len`
immediately after the 56-byte `msghdr`; the proposed custom 128-byte header
is malformed. An isolated ARM32 binary also completed ordinary IPv4
`MCAST_JOIN_GROUP` and `MCAST_BLOCK_SOURCE` calls under the ARM64 QEMU kernel.
That confirms compat syscall functionality only; it does not measure waiter
overlap. See
[minimal-rmg-compat-ipv4](/root/s/minimal-rmg-compat-ipv4/README.md).

A benign module-autoload check in QEMU did not invoke its sentinel helper,
consistent with the stock config's empty static usermode-helper path. See
[minimal-rmg-umh-audit](/root/s/minimal-rmg-umh-audit/README.md).

Additional generic input syscalls were checked statically: `clone3` copies
into a shallow local frame, `io_uring_setup` copies at `[SP_sys-0xd0,
SP_sys-0x58)`, and `seccomp`'s small local attributes are also above the
waiter. None overlap the stale waiter. No generic syscall candidate has
emerged; the remaining search should focus on a specific socket or device
operation with a measured in-thread kernel-stack copy and a durable path.

## Completed phases

### Phase 0 — Target and reference inventory: complete

- Identified the exact kernel profile and kept its vmlinux/disassembly in
  `samsung_x216b_research/`.
- Confirmed the target waiter layout from Android 5.4 RT-mutex source,
  disassembly, and runtime probes: `task +0x30`, `lock +0x38`, `prio +0x40`,
  alignment at `+0x44`, and `deadline +0x48`; total size `0x50`.
- Reviewed IonStack-S22U, GhostLockAdapt, and ghostlock-a17 reference flows.
- Reviewed the newer S23 Ultra 5.15.189 references. They provide context only:
  their per-build layouts do not transfer to X216B 5.4.249; the
  `tcp-zerocopy-sm` README labels the work incomplete and its standalone tests
  unreliable. Details are in the dated findings note.
- Reassessed prior static eliminations: IPv6 compat MCAST and pselect
  conclusions are route-specific; they do not test the X216B `recvmmsg`
  overlap or the distinct IPv4 MCAST path.
- Recorded the adaptation in
  [reference_flow_adaptation.md](/root/s/samsung_x216b_research/docs/reference_flow_adaptation.md).

### Phase 1 — Reproducible X216B QEMU baseline: complete

- Rebuilt the normal binary/initramfs with
  [build.sh](/root/s/minimal-rmg/build.sh).
- Booted `/root/s/Image.nokdp` with the corrected QEMU command from
  [logs/README.md](/root/s/logs/README.md).
- Confirmed `CMP_REQUEUE_PI` returns `EDEADLK` (`errno=35`), the waiter times
  out (`errno=110`), enters `recvmmsg`, and the consumer's `sched_setattr`
  returns 0.
- Baseline completed without an Oops before the host timeout. Threads are
  intentionally left parked, so the timeout is expected.
- Latest baseline log:
  [qemu-boot-final-baseline.log](/root/s/qemu-boot-final-baseline.log).

### Phase 2 — Runtime `recvmmsg` field mapping: complete for task/lock

- Added probe-only marker selection to
  [futex_race.c](/root/s/minimal-rmg/futex_race.c) and the separate builder
  [build_probe.sh](/root/s/minimal-rmg/build_probe.sh). Normal artifacts are
  not replaced by probe builds.
- Lock probe: `0xdeadbeefcafebabe` in the proposed lock word faulted at that
  exact address in `_raw_spin_trylock` via `rt_mutex_adjust_prio_chain`.
  Reproduced on multiple fresh QEMU boots.
- Task probe: the task marker faulted at `0xdeadbeefcafec39a`, which equals
  `0xdeadbeefcafebabe + 0x8dc`, the target's `task_struct::pi_lock` offset.
- Probe logs:
  [qemu-boot-lock-probe-final.log](/root/s/qemu-boot-lock-probe-final.log),
  [qemu-boot-stack-probe-2.log](/root/s/qemu-boot-stack-probe-2.log), and
  [qemu-boot-task-probe.log](/root/s/qemu-boot-task-probe.log).
- Artifacts used by the reproducible probe builder:
  `/root/s/initramfs-probe-lock.cpio` and
  `/root/s/initramfs-probe-task.cpio`.

## Remaining phases and TODOs

### Phase 3 — Complete waiter map and payload safety: in progress

- [x] Map the copied interval: 56 bytes begin at waiter `+0x10` and cover
  `+0x10..+0x47`; the qword at `+0x48` is outside the copy.
- [x] Trace the baseline PI-walk at the call to `rb_erase`. In this run,
  waiter qwords `+0x00` and `+0x08` were both zero; `rb_erase` receives the
  waiter base (`x0 == x25`). The same values reproduced on a second fresh
  QEMU boot; this is baseline repeatability, not proof for every schedule.
- [x] Reconcile the waiter tail: `prio` is a 32-bit field at `+0x40`,
  `+0x44..+0x47` is alignment padding, and the 64-bit deadline is at `+0x48`.
  The target object size is `0x50`; the earlier `deadlocked +0x44` claim was
  incorrect for this target.
- [x] Extend the GDB trace to watch the deadline comparison and refresh. In
  the baseline, priority was `0x78`, the deadline-comparison breakpoint did
  not fire, and the deadline was refreshed to zero after `rb_erase`.
- [x] Confirm the `recvmmsg`-written priority: the source sets 120 and GDB
  observes `0x78` at waiter `+0x40`. The deadline comparison breakpoint does
  not fire for this value; the PI-walk refreshes deadline `+0x48` to zero
  after `rb_erase`, reproduced on two fresh QEMU boots.
- [x] Audit the waiter ordering: all `LOG`/`write` calls precede `recvmmsg`;
  it blocks, and if it returns the waiter busy-yields until `walk_done` before
  calling `pause`. QEMU serial shows consumer `sched_setattr` after the
  `recvmmsg` entry. This addresses syscall ordering in this code path; keep
  post-stamp logging out of future changes.
- [x] Record exact binary/initramfs hashes and first faulting PCs for the
  task/lock marker probes; hashes and FAR/PC values are in `logs/README.md`.
- [x] Repeat the task marker from a fresh boot. It faults again at the
  expected `pi_lock` address; see `qemu-boot-task-probe-repeat.log`. It faults
  in `try_to_wake_up` before reaching the `rb_erase` site, so no second stack
  dump is available from that intentionally invalid marker run.

**Exit condition:** every field needed by the proposed walk is either
marker-confirmed, safely initialized, or explicitly proven unnecessary.

### Phase 4 — Compare alternative stamp backends: in progress

- [x] Measure IPv4 `IPPROTO_IP` `MCAST_BLOCK_SOURCE` with an isolated build.
  GDB stopped after the target's 0x108-byte user copy and showed its kernel
  buffer at `0xffffffc0132f3c00`. In the same stack window, the target waiter
  was at `0xffffffc0132f3cd8`, a `+0xd8` difference. The copied interval ends
  exactly at waiter `+0x30`; it covers the two rb-tree nodes (`+0x00..+0x2f`)
  but does not reach `task` (`+0x30`), `lock` (`+0x38`), or `prio` (`+0x40`).
  The old GDB run's thread-switch expression error was fixed; see
  `qemu-ipv4-probe-gdb-repeat.log` and the trace script under
  `samsung_x216b_research/scripts/`.
- [x] Review reference implementations. IonStack-S22U's
  `src/main.c` and GhostLockAdapt's `poc-mcast/poc_mcast.c` contain real
  `rb_erase`-forge payloads and marker methods, but those stamp a complete
  tree node on different kernel layouts; they are design references, not
  drop-in X216B code.
- [x] Test the two X216B copy windows together in the isolated
  `minimal-rmg-hybrid` build. MCAST first, then `recvmmsg`, showed both sets of
  distinct tags at their respective copy-return breakpoints, but did not reach
  the target-lock `rb_erase` breakpoint within 55 seconds. Reversing the order
  made MCAST's active kernel frames replace `task/lock/prio` with stack residue
  after the earlier `recvmmsg` copy; that order also failed to reach the
  target-lock chain and one diagnostic run reported an RCU stall in
  `rt_mutex_adjust_prio_chain`. These runs show that matching copy ranges is
  insufficient; the two syscalls do not yet compose into a stable stamp.
- [x] Evaluate the proposed single-child shape in a dedicated probe. MCAST
  copied `parent_color=0` and `rb_right=0xffffffc012f04080`; immediately
  following recvmmsg copied `rb_left=0`, task, lock, and priority. GDB confirmed
  these values at both copy-return sites, but the five-second PI wait had
  already timed out before the stamps and the target-lock `rb_erase` was not
  reached. A 120-second wait variant did not stamp before the 55-second host
  timeout. This is copy-layout evidence only. The GDB script is set to skip
  the erase instruction if the target callsite is reached. See
  `qemu-hybrid-singlechild-serial.log` and
  `samsung_x216b_research/scripts/trace_hybrid_singlechild_gdb.gdb`.
- [x] Adapt the reference waiter-release sequence in the isolated hybrid
  probe. It now uses private PI futex operations, `FUTEX_CMP_REQUEUE_PI` with
  `nr_requeue=0`, sets `f_wait=1`, and sends `SIGUSR1` with a no-op handler.
  QEMU confirmed `EDEADLK` → successful `tgkill` → waiter `EAGAIN`, before the
  MCAST/recvmmsg stamps. A candidate `rb_erase` still did not fire. The
  follow-up breakpoint at `rt_mutex_adjust_prio_chain+0x70` found `x25` at the
  candidate address. With nonblocking recvmmsg the stamp changed before this
  check. Making recvmmsg block preserved `rb_left`, task, lock, and priority,
  but `rb_right` became a stack pointer (`candidate+0x48`) at the recvmmsg
  breakpoint and was zero at the PI check. The single-child shape still does
  not survive into the consumer. An earlier run reached a soft lockup in this
  retry loop; the current GDB trace stops before it repeats. See
  `qemu-hybrid-singlechild-serial.log`, `qemu-hybrid-singlechild-gdb.log`, the updated GDB trace, and the
  reference sequence in `references/GhostLockAdapt/poc-mcast/docs/OBSERVATIONS.md`.
- [ ] Add a pre-loop GDB stop for this exact waiter in
  `rt_mutex_adjust_prio_chain`, capture the active lock, PI-tree fields, and
  call path before the soft lockup, then correct the first invalid transition
  without allowing the candidate `rb_erase` to execute.
- [ ] Find a single X216B stamp path that reaches the needed waiter words, or
  a verified scheduling/lifetime arrangement that keeps both stamps intact.
  Do not test a real write payload until the target waiter is observed with
  controlled fields at the intended consumer entry.
- [ ] Keep the X216B `sendmmsg` path lower priority: current disassembly puts
  its fast iovec array at `SP_sys-0x210`, intersecting only the waiter's first
  8 bytes. Revisit only if a different syscall shape or a measured layout
  changes that geometry.
- [ ] For defensive root-cause work, audit ARM32 compat IPv4 MCAST separately:
  it takes a translated-copy path through `compat_mc_setsockopt`, so the
  native-ABI result does not establish equivalent behavior. Keep validation
  to crash-free tracing and kernel-side invariant checks; do not tune it into
  a controlled write primitive.
- [x] Run a standalone ARM32 QEMU functional check for IPv4 multicast setsockopt.
  `MCAST_JOIN_GROUP` and `MCAST_BLOCK_SOURCE` both returned success. This
  verifies the compat ABI path only; stack overlap was not measured.
- [x] Keep native/compat pselect as a control; existing stack and zeroing
  measurements agree with the static elimination, with no contradictory
  runtime evidence.
- [ ] Compare each candidate on copy reach, required field coverage, whether
  it returns or blocks, and whether any follow-up syscall overwrites the
  target stack window.

**Exit condition:** select a backend based on marker-confirmed runtime
coverage and a repeatable walk, not source similarity or static offsets alone.

### Phase 5 — PI-walk behavior and primitive: in progress

- [x] Repeat the normal, non-marker `recvmmsg` payload on fresh QEMU boots.
  It reaches the target's first `rb_erase` call with task=`init_task`,
  lock=`0xffffffc012f04080`, prio=`0x78`, and zero tree/deadline words. A
  second GDB stop immediately after `rb_erase` showed those waiter words
  unchanged. The race sequence completes without an Oops. See
  `qemu-recvmmsg-repeat-gdb.log`, `qemu-recvmmsg-post-gdb.log`, and the repeat
  serial log.
- [x] Inspect `lock->waiters.rb_root` before and after the erase. It is null
  in both snapshots, and remains null afterward; the tested baseline erase
  leaves the observed waiter and root words unchanged.
- [ ] Determine what the intended corruption must achieve beyond this clean
  baseline: it reaches `rb_erase` but has not demonstrated a controlled write
  or a useful read/write primitive. `recvmmsg` covers `rb_left` at waiter
  `+0x10` and task/lock/prio but leaves `parent_color` and `rb_right` untouched;
  MCAST reaches the first 0x30 bytes but cannot preserve the task/lock tail in
  the tested ordering. No hybrid arrangement has produced a stable target
  waiter at the consumer. Do not count copy hits or callsite hits alone as
  primitive evidence.
- [ ] Show that any proposed altered payload takes the intended
  `rt_mutex_adjust_prio_chain` path without an uncontrolled Oops. Use QEMU
  serial and GDB evidence on fresh boots for each change.
- [x] Measure same-thread BPF geometry and durability. The copy overlaps the
  waiter tail, but scheduler stack reuse clobbers the fields before the
  consumer; the diagnostic did not reach the target erase and is not a write
  primitive.
- [ ] Determine whether a resulting primitive is only a constrained
  `rb_erase` write or supports a stronger read/write operation on this build.
- [ ] Test timing variation and repeated clean boots under TCG. Report QEMU
  hit rate separately from any physical-device hit rate.

**Exit condition:** repeatable, bounded kernel-side behavior with a precisely
described read/write capability and no false success based on a fault alone.

### Phase 6 — Post-primitive path: currently unimplemented

The code tree currently contains stubs: `spray.c` returns failure,
`kaslr.c::resolve_slide()` returns 0, `pipe_rw.c` read/write functions return
failure, and `umh_root.c::root_via_umh()` returns failure.

Configuration audit: the stock firmware sets
`CONFIG_STATIC_USERMODEHELPER=y` with an empty
`CONFIG_STATIC_USERMODEHELPER_PATH`; this disables UMH launches. The presence
of `call_usermodehelper*` symbols does not establish an available daemon path.

- [ ] Decide which post-primitive design fits the exact X216B kernel and
  configuration. The research archive lists pipe/ashmem/configfs and UMH
  concepts, but these are not validated implementations.
- [ ] Derive all symbol and structure offsets from the exact target artifacts
  and verify them before use. Do not reuse S22/A17 offsets or assume newer
  waiter structures.
- [ ] Implement and independently test kernel address/slide discovery if the
  selected path requires it; `resolve_slide()` is currently a stub.
- [ ] Implement and validate a narrowly scoped read/write primitive if
  required; `kread64()` and `kwrite64()` are currently stubs.
- [ ] Add an explicit non-root test identity and verify the initial UID,
  resulting UID/capabilities, and SELinux context. Avoid using initramfs UID
  0 as an escalation check.
- [ ] Keep root verification separate from the trigger test so a successful
  futex walk cannot be mistaken for a complete exploit.

**Exit condition:** a non-root guest process can demonstrate the claimed
privilege change, and the result is independently verified in the guest.

### Phase 7 — QEMU hardening and device validation

- [ ] Make each QEMU run reproducible from a command/script that records
  kernel hash, initramfs hash, QEMU version/options, timeout, and full serial
  log.
- [ ] Document QEMU-only kernel patches and boot parameters separately from
  target behavior. Do not apply the A17 harness patches to X216B without
  proving they are relevant; the A17 harness expects a different kernel and
  SELinux/DEFEX setup.
- [ ] Verify the same kernel build and config on physical SM-X216B before
  making device claims. Generic QEMU `virt` does not emulate the SM6375 board
  peripherals or reproduce its scheduler and timing exactly.
- [ ] Test only after the QEMU stages are repeatable, and preserve device
  logs, exact build fingerprint, reboot state, and outcome for each attempt.

**Exit condition:** report QEMU results and physical-device results as
separate evidence sets; do not generalize one into the other.

## Reference points and repeat commands

- [X216B research archive](/root/s/samsung_x216b_research/README.md)
- [QEMU/test log and exact boot command](/root/s/logs/README.md)
- [Reference-flow reassessment and probe results](/root/s/samsung_x216b_research/docs/reference_flow_adaptation.md)
- Normal build: `bash /root/s/minimal-rmg/build.sh`
- Lock-field probe build: `PROBE_FIELD=lock bash /root/s/minimal-rmg/build_probe.sh`
- Task-field probe build: `PROBE_FIELD=task bash /root/s/minimal-rmg/build_probe.sh`
- Left-field diagnostic build: `PROBE_FIELD=left bash /root/s/minimal-rmg/build_probe.sh`
- Isolated IPv4 copy probe: `bash /root/s/minimal-rmg-ipv4/build.sh`; GDB run:
  `gdb-multiarch -q -batch -x /root/s/samsung_x216b_research/scripts/trace_ipv4_mcast_gdb.gdb`
- Run the normal image with the QEMU command in `logs/README.md`, redirecting
  output to a new per-run log. For marker runs, substitute the matching probe
  initramfs and add `-no-reboot` so the intentional panic remains captured.
