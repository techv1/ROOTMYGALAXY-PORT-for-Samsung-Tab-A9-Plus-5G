#!/usr/bin/env python3
import struct

KIMAGE = 0xffffffc010080000
STUB_VA = 0xffffffc010cb489c
TARGET_VA = 0xffffffc0103754c4
PRINTK_VA = 0xffffffc01037d210
FMT_3ARG_VA = 0xffffffc011ed5274  # " %lx %lx %lx"

def movz(reg, imm, shift=0):
    return 0xD2800000 | (1 << 31) | ((shift // 16) << 21) | ((imm & 0xFFFF) << 5) | reg

def movk(reg, imm, shift=0):
    return 0xF2800000 | (1 << 31) | ((shift // 16) << 21) | ((imm & 0xFFFF) << 5) | reg

def load_imm64(reg, val):
    return [
        movz(reg, val & 0xFFFF, 0),
        movk(reg, (val >> 16) & 0xFFFF, 16),
        movk(reg, (val >> 32) & 0xFFFF, 32),
        movk(reg, (val >> 48) & 0xFFFF, 48),
    ]

def enc(insns):
    return b''.join(struct.pack('<I', i) for i in insns)

def enc_bl(from_va, to_va):
    off = (to_va - from_va) >> 2
    assert -(1 << 25) <= off < (1 << 25)
    return 0x94000000 | (off & 0x3FFFFFF)

# ===== Build stub (register-only, no memory reads) =====
stub = []
stub += [0xA9BC7BFD, 0x910003FD, 0xA90107E0, 0xA9020FE2, 0xA90317E4]

# printk(" %lx %lx %lx", x23, x25, x19)
stub += load_imm64(0, FMT_3ARG_VA)
stub += [0xAA1703E1]   # mov x1, x23  (v_lock)
stub += [0xAA1903E2]   # mov x2, x25  (waiter)
stub += [0xAA1303E3]   # mov x3, x19  (task)
cur = STUB_VA + len(stub) * 4
stub += [enc_bl(cur, PRINTK_VA)]

# Epilogue
stub += [0xA94317E4, 0xA9420FE2, 0xA94107E0, 0xA8BC7BFD, 0xD65F03C0]

stub_bytes = enc(stub)
print(f"Stub size: {len(stub_bytes)} bytes (0x{len(stub_bytes):x})")

with open('/root/s/Image.nokdp', 'r+b') as f:
    f.seek(STUB_VA - KIMAGE)
    f.write(stub_bytes)
    print(f"✓ Stub written at 0x{STUB_VA:x}")

    bl_insn = enc_bl(TARGET_VA, STUB_VA)
    f.seek(TARGET_VA - KIMAGE)
    old = f.read(4)
    f.seek(TARGET_VA - KIMAGE)
    f.write(struct.pack('<I', bl_insn))
    print(f"✓ BL at 0x{TARGET_VA:x}: {old.hex()} → {struct.pack('<I', bl_insn).hex()}")
