# Samsung SM-X216B Kernel Research Archive

This repository contains the complete research artifacts, test harness, disassembly analyses, and diagnostic logs for the Samsung Galaxy Tab A9+ 5G (`SM-X216B`) Linux kernel (`5.4.249-qgki-31053672-abX216BXXS9DYJ7`).

## Contents

- **`minimal-rmg/`**: Clean C research test harness, build scripts, and headers.
  - `futex_race.c`: Baseline research harness testing futex PI cross-thread state transitions (`f1`, `f2`, `f3`, `recvmmsg`).
  - `main.c`: Unprivileged privilege audit runner (UID 1000).
  - `build.sh`: NDK cross-compilation and initramfs packaging script.
- **`vmlinux.elf`**: Uncompressed AArch64 kernel ELF with full symbol tables.
- **`Image.nokdp`**: Bootable kernel image configured for QEMU testing.
- **`init` / `initramfs-raw.cpio`**: Standalone research initramfs.
- **`trace_sites.py`**: Automated GDB tracer monitoring `rb_erase` sites (`0xffffffc010375600`, `0xffffffc0103757d8`, `0xffffffc010375874`).
- **Research Reports & Analyses (`.md`, `.txt`, `.json`)**:
  - `smx216b_final_research_report.md`: Final security-impact and boundary characterization.
  - `rb_erase_source_reconciliation.md`: Disassembly and call-site reconciliation.
  - `kernel_profile.json` & `kernel_profile_verified.json`: Verified kernel structure offsets and symbol mappings.
  - Detailed disassembly dumps (`do_futex.txt`, `adjust_prio_chain.txt`, `do_ipv6_so.txt`, `do_recvmmsg.txt`, etc.).
