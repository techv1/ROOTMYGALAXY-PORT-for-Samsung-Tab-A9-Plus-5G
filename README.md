# Samsung SM-X216B Kernel Research Archive

This repository contains the organized research artifacts, minimal test harness, disassembly analyses, diagnostic tooling, and reports for the Samsung Galaxy Tab A9+ 5G (`SM-X216B`) Linux kernel (`5.4.249-qgki-31053672-abX216BXXS9DYJ7`).

## Directory Structure

```
├── minimal-rmg/       # Minimal C test harness, headers, and NDK build scripts
├── scripts/           # Python tracing, patching, and GDB automation tools
├── docs/              # Research documentation and Markdown architectural reports
├── reports/           # Feasibility, validation, geometry, and runtime analysis reports
├── disasm/            # Kernel function disassembly and syscall flow listings
└── kernel/            # Kernel binaries, initramfs, and verified profile JSONs
```

### Component Details

- **`minimal-rmg/`**: Clean C research test harness, build scripts, and headers.
  - `futex_race.c`: Baseline research harness testing futex PI cross-thread state transitions.
  - `main.c`: Unprivileged privilege audit runner (UID 1000).
  - `common.h`, `p0_fingerprint.h`, `target.h`: Kernel structure offsets and target definitions.
  - `build.sh`: NDK cross-compilation and packaging script.

- **`scripts/`**: Automated diagnostic and trace scripts.
  - `trace_sites.py`: Automated GDB tracer monitoring `rb_erase` sites (`0xffffffc010375600`, `0xffffffc0103757d8`, `0xffffffc010375874`).
  - `trace_gdb.py`: GDB automation helper for live breakpoint logging.
  - `trace_rb.py`: Real-time rbtree state observer.
  - `phase4_trace.py`: Phase-4 cross-thread state transition tracer.
  - `patch_defex.py`: Kernel DEFEX instrumentation patch utility.

- **`docs/`**: Comprehensive research documentation (`.md`).
  - `smx216b_final_research_report.md`: Final security-impact and boundary characterization.
  - `smx216b_alternative_architecture_matrix.md`: Architectural cross-reference matrix.
  - `x216b_architecture_compatibility_final.md`: Kernel version compatibility assessment.
  - `rb_erase_source_reconciliation.md`: Disassembly and call-site reconciliation.

- **`reports/`**: Validation, geometry, and feasibility findings (`.txt`).
  - `profile_validation_report.txt`, `symbol_report.txt`, `structure_report.txt`.
  - `futex_feasibility_report.txt`, `futex_pi_report.txt`.
  - `smx216b_pselect_geometry_report.txt`, `smx216b_runtime_gap_corrected.txt`, `smx216b_runtime_validation_report.txt`.

- **`disasm/`**: Disassembly dumps (`.txt`).
  - `do_futex.txt`, `adjust_prio_chain.txt`, `remove_waiter.txt`, `rb_erase.txt`.
  - `do_ipv6_so.txt`, `compat_ipv6_so.txt`, `compat_setsockopt.txt`, `copy_siginfo.txt`.
  - `do_recvmmsg.txt`, `recvmmsg_entry.txt`, `sys_recvmsg.txt`, `futex_entry.txt`, `pidfd_entry.txt`, `prctl_entry.txt`.

- **`kernel/`**: Core kernel binaries and verified symbol profiles.
  - `vmlinux.elf`: Uncompressed AArch64 kernel ELF with full symbol tables.
  - `Image.nokdp`: Kernel image configured for QEMU research.
  - `init`, `initramfs-raw.cpio`: Research initramfs environment.
  - `kernel_profile.json`, `kernel_profile_verified.json`: Verified kernel structure offsets and symbol mappings.
