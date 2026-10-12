#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KERNEL_IMG="$SCRIPT_DIR/kernel/Image.nokdp"
INITRD_IMG="$SCRIPT_DIR/kernel/initramfs-ipv4.cpio"

if [ ! -f "$KERNEL_IMG" ]; then
    echo "ERROR: Kernel image not found at $KERNEL_IMG" >&2
    exit 1
fi

if [ ! -f "$INITRD_IMG" ]; then
    echo "ERROR: Initramfs image not found at $INITRD_IMG" >&2
    exit 1
fi

echo "[*] Killing any existing QEMU instances..."
pkill -9 -f qemu-system-aarch64 2>/dev/null || true
sleep 1

echo "[*] Launching QEMU SM-X216B emulation with multicast networking..."
exec qemu-system-aarch64 \
    -M virt,gic-version=3 \
    -cpu cortex-a76 \
    -smp 4 \
    -m 4096 \
    -kernel "$KERNEL_IMG" \
    -initrd "$INITRD_IMG" \
    -nographic \
    -netdev socket,id=net0,mcast=239.255.0.1:1234 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    -append "console=ttyAMA0 earlycon=pl011,0x09000000 nokaslr panic=1 rdinit=/init"
