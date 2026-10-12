# SM-X216B verified findings — 2026-09-30

This note consolidates the current artifact, QEMU, ABI, and reference-repo
findings. It distinguishes direct observations from static conclusions. The
work so far has **not** demonstrated a controlled kernel write, a useful
kernel read/write primitive, or an unprivileged-to-root transition.

## Target and artifacts

- Device profile: Samsung Galaxy Tab A9+ 5G, SM-X216B (`gta9p`), firmware
  `X216BXXS9DYJ7`, kernel `5.4.249-qgki-31053672-abX216BXXS9DYJ7`.
- `boot.img` in the workspace matches the recorded firmware boot-image SHA-256
  `1efd38be0575f4f74d65af82f779f808e815bf28e7b6fc65199f6f17c01b3dda`.
- The two existing `vmlinux.elf` files are identical (SHA-256
  `dfc0912ee00696bed45f0852d490a75d20d336a16fc87288b155d513bbcea29f`). The
  saved notes associate this symbolized ELF with that firmware, but do not
  preserve enough extraction history to establish whether it was obtained
  directly or reconstructed from the kernel image.
- Generic QEMU `virt` runs the extracted target kernel for diagnostics; it is
  not a full SM6375 hardware model. The test kernel image has QEMU-specific
  SCM initialization changes documented in `logs/README.md`.

## Kernel and waiter observations

- The 80-byte (`0x50`) target `rt_mutex_waiter` layout is corroborated by
  target disassembly, source notes, and QEMU traces: `task +0x30`, `lock +0x38`,
  `prio +0x40`, and `deadline +0x48`.
- QEMU reproduced the stale-waiter sequence. In the observed rollback,
  `remove_waiter()` clears `current->pi_blocked_on` while the other task's
  field still refers to the old stack waiter. This confirms the observed bug
  path in this QEMU image; it does not prove a usable corruption primitive.
- The normal `recvmmsg` run reached the target `rb_erase` call. In the saved
  pre/post trace, the waiter-tree root was empty and the node/root words were
  unchanged after the call. The separate tree-write trace shows only the
  right-child word changing at an `import_iovec` instruction; the parent and
  left-child words were already zero in the first captured snapshot. Do not
  describe that trace as `import_iovec` clearing all three tree words, or as a
  successful write.
- Native IPv4 `MCAST_BLOCK_SOURCE` was exercised by a separate GDB probe. It
  copied the requested structure, but the observed copy did not reach the
  waiter task/lock/priority fields. This is a native-ABI result only.
- A prior BPF diagnostic briefly placed data over waiter fields, but scheduler
  and stack reuse replaced it before the consumer. It did not reach the target
  erase call in that diagnostic run.

## Safe syscall ABI checks

- A 64-bit QEMU datagram test confirmed `sizeof(struct msghdr)=56`,
  `sizeof(struct mmsghdr)=64`, and `msg_len` at offset 56. A valid
  `recvmmsg` call returned the payload and source-address metadata correctly.
- The suggested custom structure with a 128-byte `hdr` and `len` after it does
  not match the `mmsghdr` ABI: the kernel writes `msg_len` at offset 56, leaving
  the trailing field at 128 untouched. This invalid layout cannot substantiate
  the claimed stack-stamp behavior.
- A separate ARM32 binary ran under the ARM64 QEMU kernel and reported
  4-byte pointers. Ordinary IPv4 `MCAST_JOIN_GROUP` and `MCAST_BLOCK_SOURCE`
  calls both returned success. This confirms functional compat syscall
  handling; it **does not** measure kernel-stack overlap or waiter lifetime.
  Probe source and serial log are under `../../minimal-rmg-compat-ipv4/`.

## UMH configuration check

The firmware config has `CONFIG_STATIC_USERMODEHELPER=y` with an empty
`CONFIG_STATIC_USERMODEHELPER_PATH`. [Linux Kconfig](https://github.com/torvalds/linux/blob/master/security/Kconfig)
documents an empty static helper path as disabling UMH launches. The target ELF contains UMH-related symbols,
but symbol presence alone does not establish that a helper can be started.
A benign QEMU module-autoload request returned `EAFNOSUPPORT`; the packaged
sentinel `/sbin/modprobe` was not invoked. The probe is documented under
`../../minimal-rmg-umh-audit/`.

## GDB breakpoints confirmed in QEMU

The addresses below were reached in the saved QEMU runs listed in the evidence
column. They are useful observation points for reproducing the recorded
control flow and comparing stack contents. They are diagnostic stops, not
proof of a controlled write. Addresses assume the matching target image,
`nokaslr`, and the same symbolized kernel build; re-check the image and
disassembly before reusing them with another build.

| Address | Observation point | What the saved run showed | Evidence |
|---|---|---|---|
| `0xffffffc010376460` | `remove_waiter()` rollback path | Waiter owner differs from `current`; owner still points at the stack waiter. | [`qemu-remove-waiter-owner-gdb.log`](../../qemu-remove-waiter-owner-gdb.log), [`trace_remove_waiter_owner_gdb.gdb`](../scripts/trace_remove_waiter_owner_gdb.gdb) |
| `0xffffffc01037649c` | Immediately after clearing `current->pi_blocked_on` | The other task's `pi_blocked_on` still references the waiter. | Same log and script as above. |
| `0xffffffc010376620` | PI-chain dispatch arguments | Captured the task/waiter arguments passed along the rollback path. | Same log and script as above. |
| `0xffffffc0112ed380` | Return from recvmmsg header copy | Printed the candidate stack window; subsequent watchpoint observed a store to the candidate right-child word in `import_iovec`. | [`qemu-recvmmsg-tree-writes-gdb.log`](../../qemu-recvmmsg-tree-writes-gdb.log), [`trace_recvmmsg_tree_writes_gdb.gdb`](../scripts/trace_recvmmsg_tree_writes_gdb.gdb) |
| `0xffffffc0107e0be8` | Hardware watchpoint stop after the watched store | The log records the right-child word becoming zero. It does not show the other two tree words being cleared by that store. | Same tree-write log and script. |
| `0xffffffc010375600` | Before target waiter-tree `rb_erase` call | Reached by the recvmmsg and IPv4 probes. The recvmmsg baseline had a null root and zero node links at this stop. | [`qemu-recvmmsg-repeat-gdb.log`](../../qemu-recvmmsg-repeat-gdb.log), [`qemu-recvmmsg-post-gdb.log`](../../qemu-recvmmsg-post-gdb.log), [`qemu-ipv4-probe-gdb-repeat.log`](../../qemu-ipv4-probe-gdb.log); corresponding `trace_recvmmsg_repeat_gdb.gdb`, `trace_recvmmsg_post_gdb.gdb`, and `trace_ipv4_mcast_gdb.gdb` scripts. |
| `0xffffffc010375604` | Immediately after the `rb_erase` call | Pre/post snapshots show node and empty root words unchanged in the recorded baseline. | [`qemu-recvmmsg-post-gdb.log`](../../qemu-recvmmsg-post-gdb.log), [`trace_recvmmsg_post_gdb.gdb`](../scripts/trace_recvmmsg_post_gdb.gdb) |
| `0xffffffc0103753bc` | `rt_mutex_adjust_prio_chain()` entry | Captured arguments for the IPv4 MCAST PI-walk probe. | [`qemu-ipv4-probe-gdb-repeat.log`](../../qemu-ipv4-probe-gdb-repeat.log), [`trace_ipv4_mcast_gdb.gdb`](../scripts/trace_ipv4_mcast_gdb.gdb) |
| `0xffffffc01037542c` | IPv4 PI-walk waiter inspection | Printed the waiter and lock arguments; the MCAST input copy and this waiter were distinct regions in the observed run. | Same IPv4 log and script as above. |
| `0xffffffc0113b617c` | Return from IPv4 MCAST input copy | Captured the copied MCAST input bytes and confirmed they did not overlap the waiter fields in that run. | Same IPv4 log and script as above. |
| `0xffffffc01043d5a4` | BPF stack-copy observation | The BPF marker was visible briefly, then later scheduler/context-switch writes reused the stack before the consumer observation. | [`qemu-stale-waiter-bpf-watch-gdb.log`](../../qemu-stale-waiter-bpf-watch-gdb.log), [`trace_stale_waiter_bpf_gdb.gdb`](../scripts/trace_stale_waiter_bpf_gdb.gdb) |

The recvmmsg breakpoints at `0xffffffc010375498`, `0xffffffc010375618`, and
`0xffffffc01037561c` were also installed in an exploratory trace, but the saved
log only establishes hits at `+0x244`, `+0x248`, and the deadline store at
`+0x25c`; do not count the other configured stops as verified hits. Other
addresses appearing only in scripts or symbol/disassembly notes are likewise
not runtime-confirmed by this table.

For the GDB command sequences and conditional filters, see the linked scripts.
The saved logs are the record of what actually ran; avoid interpreting a
breakpoint being installed as evidence that its location was reached.

## Other syscalls and reference ports

- Existing static/runtime reviews leave no native or compat syscall path with
  a demonstrated controlled kernel write. `pselect`, polling, signal, message,
  perf, and BPF paths have the previously recorded geometry or lifetime
  blockers. The remaining compat IPv4 test establishes only that normal
  multicast calls work.
- The S23 Ultra references target Linux `5.15.189`, not X216B's 5.4.249. Their
  target profile uses a newer waiter layout, so its constants are not portable.
- The `tcp-zerocopy-sm` repository identifies itself as work in progress and
  warns that its standalone payload tests were incorrect. Treat it as an
  unverified research note, not evidence that TCP zerocopy works on X216B.
- The current Root-My-Galaxy S918B README lists working profiles for specific
  S918B firmware builds; that is evidence about those exact 5.15 targets, not
  this X216B image. The S9180 FZF5 profile is separately marked in progress in
  the payload repository.

References: [Root-My-Galaxy SM-S918B](https://github.com/soumarcelino/Root-My-Galaxy-SM-S918B),
[tcp-zerocopy-sm](https://github.com/Meowkis/tcp-zerocopy-sm),
[S9180 FZF5 target profile](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/main/src/targets/dm3q-S9180ZHS8FZF5/target.h).

## Current conclusion

The supported conclusions are kernel identity, waiter layout, the observed
stale-pointer path, syscall ABI behavior, and the UMH configuration block.
Compat IPv4 MCAST is functionally reachable but its relationship to the stale
waiter has not been measured. No root claim should be made from these tests;
the initramfs starts as UID 0, and no physical-device validation was performed.
