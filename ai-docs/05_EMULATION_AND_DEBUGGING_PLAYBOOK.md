# 05. Emulation & Debugging Playbook

A practical step-by-step guide for building, running, and debugging kernel components on the SM-X216B QEMU virtual testbed.

---

## 1. Cross-Compiling the Exploit Carrier

The build script uses Android NDK r28 (Clang 19 / API level 35):

```bash
cd /root/s/samsung_x216b_research/minimal-rmg-ipv4
./build.sh
```

### What this does:
1. Compiles static ELF binary using `-DUSE_MCAST_STAMP`:
   - `kaslr.c`, `futex_race.c`, `spray.c`, `pipe_rw.c`, `umh_root.c`, `main.c`
2. Packages the binary as `/init` inside a fresh initramfs:
   - `kernel/initramfs-ipv4.cpio`

---

## 2. Launching QEMU Emulation

### Basic Boot:
```bash
cd /root/s/samsung_x216b_research
./run_qemu.sh
```

### With Multicast Loopback Networking (Required for MCAST tests):
```bash
./run_qemu_with_mcast.sh
```

---

## 3. Dynamic GDB Tracing Pipeline

To run non-interactive verification with GDB attached to QEMU's internal GDB stub:

```bash
cd /root/s/samsung_x216b_research/minimal-rmg-ipv4
./scripts/verify_mcast.sh
```

### What this automated pipeline does:
1. Launches QEMU in the background with `-s` (`tcp::1234`).
2. Waits for port 1234 to open.
3. Attaches `gdb-multiarch` using symbols from `kernel/vmlinux.elf`.
4. Executes Python GDB script (`scripts/verify_mcast_gdb.py`).
5. Sets breakpoints on `task_blocks_on_rt_mutex` and `copy_from_user`.
6. Inspects register `$x25` (waiter), `$x0` (destination stack buffer), and computes stack deltas in real-time.
7. Logs output to `logs/qemu-mcast-verify-gdb.log` and `logs/qemu-mcast-verify-serial.log`.

---

## 4. Manual GDB Interactive Debugging

To pause execution at a panic or inspect synchronization states:

1. In Terminal 1:
   ```bash
   qemu-system-aarch64 \
       -M virt,gic-version=3 \
       -cpu cortex-a76 \
       -smp 4 \
       -m 4096 \
       -kernel kernel/Image.nokdp \
       -initrd kernel/initramfs-ipv4.cpio \
       -nographic \
       -append "console=ttyAMA0 nokaslr panic=0 rdinit=/init" \
       -s -S
   ```
   *`-s -S` freezes the CPU at reset until GDB connects.*

2. In Terminal 2:
   ```bash
   gdb-multiarch kernel/vmlinux.elf
   (gdb) target remote localhost:1234
   (gdb) b task_blocks_on_rt_mutex
   (gdb) b rt_mutex_adjust_prio_chain
   (gdb) c
   ```
