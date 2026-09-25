#!/usr/bin/env python3
import struct
import shutil
import os

KIMAGE_BASE = 0xffffffc010080000
TARGET_VA = 0xffffffc01076b978  # defex_rules_signature_check
TARGET_OFFSET = TARGET_VA - KIMAGE_BASE  # 0x6eb978

# 6 instructions (24 bytes):
# 0:  cbz     x2, 10
# 4:  subs    w3, w1, #0x100
# 8:  csel    w3, w3, w1, hi
# c:  str     w3, [x2]
# 10: mov     w0, #0
# 14: ret
PATCH_INSTRUCTIONS = [
    0xb4000082,  # cbz x2, +16
    0x71040023,  # subs w3, w1, #0x100
    0x1a818063,  # csel w3, w3, w1, hi
    0xb9000043,  # str w3, [x2]
    0x52800000,  # mov w0, #0
    0xd65f03c0,  # ret
]

patch_bytes = b''.join(struct.pack('<I', insn) for insn in PATCH_INSTRUCTIONS)

image_path = '/root/s/Image.nokdp'
backup_path = '/root/s/Image.nokdp.bak'

if not os.path.exists(backup_path):
    shutil.copy2(image_path, backup_path)
    print(f"[+] Created backup at {backup_path}")

with open(image_path, 'r+b') as f:
    f.seek(TARGET_OFFSET)
    old_bytes = f.read(len(patch_bytes))
    print(f"[*] Original bytes at 0x{TARGET_OFFSET:x} (VA 0x{TARGET_VA:x}): {old_bytes.hex()}")

    f.seek(TARGET_OFFSET)
    f.write(patch_bytes)
    print(f"[+] Written patch bytes: {patch_bytes.hex()}")

print(f"[✓] Successfully patched defex_rules_signature_check() to always return 0!")
