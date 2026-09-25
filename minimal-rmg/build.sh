#!/bin/bash
set -e

WORKDIR="/root/s/minimal-rmg"
cd "$WORKDIR"

export CC=~/android-ndk-r28/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang

echo "Compiling /root/s/init..."
$CC -static -Os -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables \
    -ffunction-sections -fdata-sections -I. \
    kaslr.c futex_race.c spray.c pipe_rw.c umh_root.c main.c \
    -o /root/s/init -Wl,--gc-sections -s

echo "Packaging /root/s/initramfs-raw.cpio..."
rm -rf /root/s/initramfs
mkdir -p /root/s/initramfs/{dev,proc,sys}
cp /root/s/init /root/s/initramfs/init
chmod 755 /root/s/initramfs/init

cd /root/s/initramfs
find . | cpio -o -H newc > /root/s/initramfs-raw.cpio

echo "Done! Output: /root/s/initramfs-raw.cpio"
ls -lh /root/s/initramfs-raw.cpio
