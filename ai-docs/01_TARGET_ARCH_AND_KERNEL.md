# 01. Target Architecture & Kernel Configuration

## Target Hardware & Firmware Baseline

- **Device Name**: Samsung Galaxy Tab A9+ 5G
- **Model Number**: `SM-X216B`
- **Device Codename**: `gta9p`
- **SoC Platform**: Qualcomm Snapdragon 695 5G (`SM6375` / `Holi`), Octa-core (2x Kryo 660 Gold / Cortex-A76 @ 2.2 GHz + 6x Kryo 660 Silver / Cortex-A55 @ 1.8 GHz)
- **Target Firmware**: `X216BXXS9DYJ7`
- **Android Version**: 14 (One UI 6.x)
- **Kernel Release**: `5.4.249-qgki-31053672-abX216BXXS9DYJ7`
- **Compiler**: Android Clang 11.0.2 + LLD 11.0.2
- **Build Timestamp**: `#1 SMP PREEMPT Wed Oct 15 23:51:00 KST 2025`

---

## Memory Model & Address Space

| Region | Virtual Address Range | Description |
| :--- | :--- | :--- |
| **`KIMAGE_TEXT_BASE`** | `0xffffffc010080000` | Kernel code segment base (`_text`) |
| **Direct Physical Map** | `0xffffff8000000000` - `0xffffffc000000000` | Linear physical memory mapping |
| **Physical RAM Base** | `0x80000000` | Physical RAM load address (`P0_PHYS_OFFSET`) |
| **Kernel Phys Load** | `0x80080000` | `P0_KERNEL_PHYS_LOAD` |
| **Kernel .bss Section** | `0xffffffc012b9ea00` | Zeroed uninitialized data section (16 MB) |

---

## Verified Kernel Security Configuration

From live `extract-ikconfig` decompilation of `kernel/Image.nokdp`:

### 1. Hardening Flags Present & Enforced
- **`CONFIG_CFI_CLANG=y`**: Clang Forward-Edge Control Flow Integrity is active. Indirect branch targets MUST target compiler-generated `.cfi_jt` jump-table thunks. Direct function calls to non-CFI targets crash with kernel panic.
- **`CONFIG_SHADOW_CALL_STACK=y`**: Return addresses are saved on a protected shadow stack register (`x18`). Return-oriented programming (ROP) stack pivots are strictly blocked.
- **`CONFIG_ARM64_PAN=y` & `CONFIG_ARM64_UAO=y`**: Privileged Access Never prevents kernel execution from reading/writing directly from userspace pointers without `copy_from_user` / `copy_to_user`.
- **`CONFIG_HARDENED_USERCOPY=y`**: Bounds checking on userspace data buffers.
- **`CONFIG_STRICT_KERNEL_RWX=y`**: W^X memory permissions enforced across kernel code and data.
- **`CONFIG_RANDOMIZE_BASE=y`**: KASLR enabled in production (disabled with `nokaslr` during QEMU debugging).

### 2. Samsung Defensive Baseline Divergences (Crucial)
- **Knox RKP / KDP is NOT Active**: `# CONFIG_RKP / KDP not set` in kernel config. Unlike Samsung flagship devices (S22/S23/S24) which enforce hypervisor write-protection on credentials at EL2, the Tab A9+ kernel does not protect `current->cred` pages via EL2 KDP! Direct credential overwrites are architecturally possible if physical memory access is achieved.
- **`CONFIG_STATIC_USERMODEHELPER=y`**: The kernel enforces static usermode helpers, but sets:
  ```
  CONFIG_STATIC_USERMODEHELPER_PATH=""
  ```
  An empty path string causes `call_usermodehelper_exec_async` to immediately fail (`-ENOENT`). Therefore, any exploit architecture relying exclusively on the public UMH execution path (`/system/bin/sh` or `/data/local/tmp/root.sh`) will fail unless the static helper path is physically patched or an alternative root mechanism is utilized.
