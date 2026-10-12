#!/bin/bash
set -euo pipefail

exec timeout --signal=TERM 55s qemu-system-aarch64 \
    -M virt,gic_version=3 \
    -cpu cortex-a57 \
    -smp 4 \
    -m 4096 \
    -kernel /root/s/Image.nokdp \
    -initrd /root/s/hybrid-test-artifacts/initramfs-hybrid.cpio \
    -display none \
    -serial file:/root/s/qemu-hybrid-recvmmsg-first-serial.log \
    -monitor none \
    -gdb stdio \
    -S \
    -no-reboot \
    -accel tcg,thread=multi \
    -append 'console=ttyAMA0 earlycon=pl011,0x9000000 nokaslr panic=1 rdinit=/init initcall_blacklist=scm_mem_protection_init,qcom_scm_init,scm_mem_protection_init_do,fastrpc_init,adsprpc_init,msm_geni_serial_init,ehci_pci_init,cryptomgr_schedule_test,algif_init,crypto_algapi_init,audit_init,serio_init,keyboard_init,mousedev_init,phx_klog_bootstage_init'
