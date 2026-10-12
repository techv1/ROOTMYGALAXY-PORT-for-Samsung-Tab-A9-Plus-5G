# ROOTMYGALAXY-PORT-for-Samsung-Tab-A9-Plus-5G
## Samsung SM-X216B Kernel Security Research & Root-My-Galaxy Port Archive

This repository contains the complete research artifacts, static disassembly audits, QEMU emulation testbeds, patched kernel images, bootloader ELFs, and the ported **minimal-rmg-ipv4** CVE-2026-43499 local privilege escalation exploit for the Samsung Galaxy Tab A9+ 5G (`SM-X216B` / `X216BXXS9DYJ7` / Linux `5.4.249-qgki-31053672-abX216BXXS9DYJ7`).

## Repository Layout

```
├── ai-docs/           # AI agent technical knowledge base & ground-truth verification guides
├── minimal-rmg-ipv4/  # Active Root-My-Galaxy IPv4 port (source, tests, scripts, docs)
├── kernel/            # Kernel binaries, boot images, bootloader ELFs, DTB, and profiles
├── scripts/           # Python tracing, patching, and GDB automation tools
├── docs/              # Research documentation and Markdown architectural reports
├── reports/           # Feasibility, validation, geometry, and runtime analysis reports
├── disasm/            # Kernel function disassembly and syscall flow listings
├── run_qemu.sh        # Self-contained QEMU SM-X216B virtual machine launcher
└── run_qemu_with_mcast.sh # QEMU launcher with multicast networking enabled
```

---

## Component Details

### 1. `minimal-rmg-ipv4/`
The complete, ported, and audited implementation of the Root-My-Galaxy local privilege escalation carrier tailored for the SM-X216B Android 5.4 kernel:
- **`src/`**: Modularized carrier source components (`pipe.c`, `fops.c`, `root.c`, `kernelsnitch`).
- **`futex_race.c`, `pipe_rw.c`, `target.h`, `common.h`**: Core exploit primitives with verified 80-byte `rt_mutex_waiter` and empirical MCAST stack geometry (`0xd8` delta).
- **`scripts/`**: Automated Capstone offset analyzers, GDB verification scripts, and diagnosis utilities.
- **`tests/`**: Dedicated isolation test harnesses (`test_sigreturn_port.c`, `benign_mcast.c`, `sigreturn_probe`).
- **`docs/`**: Comprehensive geometry reports, offset audits, and porting guides.
- **`build.sh`**: Production NDK cross-compilation script producing test initramfs.

### 2. `kernel/`
Complete firmware, kernel, boot, and bootloader artifacts:
- **`boot.img`**: Stock Samsung boot image (`96MB`, header version 3, pagesize 4096).
- **`Image.nokdp`**: Patched Samsung kernel image with Knox KDP/RKP and SCM memory protection initialization bypassed for QEMU research.
- **`vmlinux.elf`**: Uncompressed AArch64 kernel ELF (`54MB`) with full symbol tables.
- **`abl.elf`**: Android Bootloader ELF (`4.0MB`, Qualcomm ABL).
- **`xbl_config.elf`**: Qualcomm eXtensible Bootloader configuration ELF.
- **`target.dtb`**: Flattened Device Tree Blob (`319KB`) extracted from target firmware.
- **`initramfs-ipv4.cpio`**: Live test initramfs containing compiled carrier init.
- **`initramfs-sigret.cpio`**: Sigreturn probe test initramfs.
- **`kernel_profile.json` & `kernel_profile_verified.json`**: Verified symbol and struct offset tables.

### 3. `scripts/`
Automated diagnostic, tracing, and patching tools:
- `trace_sites.py`: Automated GDB tracer monitoring `rb_erase` sites.
- `trace_gdb.py`: GDB automation helper for live breakpoint logging.
- `trace_rb.py`: Real-time rbtree state observer.
- `phase4_trace.py`: Phase-4 cross-thread state transition tracer.
- `patch_defex.py`: Kernel DEFEX instrumentation patch utility.
- `qemu_gdb_*.sh`: GDB automation runners for dynamic geometry validation.

### 4. `docs/` & `reports/`
- `verified_findings_2026-09-30.md`: Consolidated evidence and technical findings.
- `smx216b_final_research_report.md`: Static and dynamic analysis report.
- `smx216b_alternative_architecture_matrix.md`: Architectural cross-reference matrix.
- `x216b_architecture_compatibility_final.md`: Kernel version compatibility evaluation.
- `smx216b_mcast_geometry_report.md`: Live MCAST stack geometry verification.

---

## Quick Start: QEMU Emulation

To launch the virtualized SM-X216B kernel with the latest IPv4 test payload:
```bash
./run_qemu.sh
```

To run with multicast loopback networking:
```bash
./run_qemu_with_mcast.sh
```

To run dynamic GDB MCAST geometry verification:
```bash
./minimal-rmg-ipv4/scripts/verify_mcast.sh
```
