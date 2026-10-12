#!/usr/bin/env python3
"""
Patch to bypass QCOM SCM mem protection init for QEMU compatibility.
Replaces scm_mem_protection_init_do with a function that returns 0.
"""
import struct
import shutil
import os

KIMAGE_BASE = 0xffffffc010080000
FUNC_VA = 0xffffffc0125764d0  # scm_mem_protection_init_do
FUNC_OFFSET = FUNC_VA - KIMAGE_BASE

# Patch: make the function return 0 immediately
# 0:  sub     sp, sp, #0x30
# 4:  mov     w0, #0
# 8:  add     sp, sp, #0x30
# c:  ret
PATCH_INSTRUCTIONS = [
    0xd100c3ff,  # sub sp, sp, #0x30
    0x52800000,  # mov w0, #0
    0x9100c3ff,  # add sp, sp, #0x30
    0xd65f03c0,  # ret
]

patch_bytes = b''.join(struct.pack('<I', insn) for insn in PATCH_INSTRUCTIONS)

image_path = '/root/s/Image.nokdp'
backup_path = '/root/s/Image.nokdp.scm_bak'

if not os.path.exists(backup_path):
    shutil.copy2(image_path, backup_path)
    print(f"[+] Created backup at {backup_path}")

with open(image_path, 'r+b') as f:
    f.seek(FUNC_OFFSET)
    old_bytes = f.read(len(patch_bytes))
    print(f"[*] Original bytes at offset 0x{FUNC_OFFSET:x}: {old_bytes.hex()}")

    f.seek(FUNC_OFFSET)
    f.write(patch_bytes)
    print(f"[+] Written patch bytes: {patch_bytes.hex()}")

print(f"[✓] Successfully patched scm_mem_protection_init_do() to always return 0!")
print(f"    Function VA: 0x{FUNC_VA:x}")
print(f"    File offset: 0x{FUNC_OFFSET:x}")
