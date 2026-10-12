# AI Agent Technical Knowledge Base & Ground Truth Guide

Welcome, future AI agent or security researcher. This directory contains the verified ground-truth documentation, empirical measurements, GDB trace analyses, architectural blueprints, and execution guides for **Root-My-Galaxy CVE-2026-43499 local privilege escalation on the Samsung Galaxy Tab A9+ 5G (`SM-X216B`)**.

> [!IMPORTANT]
> All findings in this directory are grounded in live dynamic traces executed against `vmlinux.elf` in QEMU, Capstone disassembly audits of the kernel image, and verified hardware watchpoint logs. Do not guess or transfer assumptions from other device targets (e.g. Linux 5.15 / 6.1 devices like S23 Ultra or Galaxy A17) without reading the divergence notes here.

---

## Documentation Index

1. **[01_TARGET_ARCH_AND_KERNEL.md](01_TARGET_ARCH_AND_KERNEL.md)**  
   Device specifications, firmware baseline (`X216BXXS9DYJ7`), Snapdragon 695 SoC, kernel security flags (`CONFIG_CFI_CLANG=y`, `CONFIG_STATIC_USERMODEHELPER_PATH=""`, Knox KDP absence), and virtual address layouts.

2. **[02_GDB_VERIFIED_GROUND_TRUTH.md](02_GDB_VERIFIED_GROUND_TRUTH.md)**  
   Empirically confirmed kernel offsets and layout proofs: 80-byte `rt_mutex_waiter`, live 216-byte (`0xd8`) MCAST stack delta, `task_struct` offsets (`pi_lock`, `pi_blocked_on`, `prio`), and why legacy `pselect6` entry primitives fail.

3. **[03_EXPLOIT_PRIMITIVES_AND_CARRIERS.md](03_EXPLOIT_PRIMITIVES_AND_CARRIERS.md)**  
   Detailed mechanics of the PI futex requeue race, stack carrier selection (IPv4 `MCAST_BLOCK_SOURCE` vs IPv6 vs ARM32 vs Sigreturn), early exit via `-EADDRNOTAVAIL` (`errno=99`), and memory spraying geometry.

4. **[04_POST_CORRUPTION_AND_ROOT_CHAIN.md](04_POST_CORRUPTION_AND_ROOT_CHAIN.md)**  
   Post-primitive exploitation strategies: arbitrary physical memory read/write via pipe buffers, ashmem/configfs hijacking, Clang forward-edge CFI jump tables (`.cfi_jt`), and handling the `CONFIG_STATIC_USERMODEHELPER` restriction.

5. **[05_EMULATION_AND_DEBUGGING_PLAYBOOK.md](05_EMULATION_AND_DEBUGGING_PLAYBOOK.md)**  
   Practical commands to cross-compile test payloads with Android NDK r28, run QEMU with/without network and GDB stubs, attach `gdb-multiarch`, set hardware watchpoints, and inspect serial logs.

6. **[06_AGENT_NEXT_STEPS_AND_PITFALLS.md](06_AGENT_NEXT_STEPS_AND_PITFALLS.md)**  
   Checklists, resolved vs open problems, high-risk cognitive traps (the "88-byte waiter fallacy", the "working UMH fallacy", etc.), and recommended roadmap for achieving stable, unconfined root.
