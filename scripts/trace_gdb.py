#!/usr/bin/env python3

import gdb
import time

# ------------------------------------------------------------
# Target addresses
# ------------------------------------------------------------

RT_MUTEX = 0xffffffc0103753bc

RB_ERASE_SITES = {
    0xffffffc010375600: "RB_ERASE_SITE_1",
    0xffffffc0103757d8: "RB_ERASE_SITE_2",
    0xffffffc010375874: "RB_ERASE_SITE_3",
}

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def run(cmd):
    print(f"\n(gdb) {cmd}")
    try:
        out = gdb.execute(cmd, to_string=True)
        print(out, end="")
        return out
    except Exception as e:
        print(f"[GDB ERROR] {e}")
        return ""

def dump_state(label):
    print("\n" + "=" * 70)
    print(f"STATE: {label}")
    print("=" * 70)

    run("info registers pc cpsr")
    run("info threads")
    run("bt 8")
    run("x/12i $pc")

# ------------------------------------------------------------
# Breakpoint class
# ------------------------------------------------------------

class TraceBreakpoint(gdb.Breakpoint):

    def __init__(self, address, name):
        self.name = name
        self.address = address

        super().__init__(
            f"*{address:#x}",
            gdb.BP_BREAKPOINT,
            internal=False
        )

    def stop(self):
        print("\n")
        print("#" * 70)
        print(f"*** HIT {self.name} ***")
        print(f"PC = {self.address:#x}")
        print("#" * 70)

        dump_state(self.name)

        # Stop execution here so we can inspect the exact call site.
        return True


# ------------------------------------------------------------
# Cleanup old breakpoints
# ------------------------------------------------------------

print("\n[+] Starting diagnostic GDB tracer")

print("[+] Existing breakpoints:")
run("info break")

print("[+] Deleting existing breakpoints")
run("delete")

print("[+] Verifying breakpoint table is empty")
run("info break")

# ------------------------------------------------------------
# Install ONLY the three direct rb_erase call sites
# ------------------------------------------------------------

print("\n[+] Installing three rt_mutex_adjust_prio_chain rb_erase sites")

bps = []

for addr, name in RB_ERASE_SITES.items():
    bp = TraceBreakpoint(addr, name)
    bps.append(bp)

    print(f"[+] {name}: {addr:#x}")

# ------------------------------------------------------------
# Verify
# ------------------------------------------------------------

print("\n[+] Final breakpoint table")
run("info break")

print("\n[+] Remote/debug state")
run("show can-use-hw-watchpoints")
run("show remote hardware-breakpoint-limit")
run("show remote hardware-watchpoint-limit")

# ------------------------------------------------------------
# Start normal execution
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("CONTINUING WITHOUT SINGLE-STEP")
print("=" * 70)

print("""
The script will NOT use:
    si
    stepi
    next
    nexti

It will only use normal 'continue'.
""")

run("continue")

# ------------------------------------------------------------
# If execution stops, inspect why
# ------------------------------------------------------------

dump_state("STOP AFTER CONTINUE")

print("\n[+] Current breakpoint table")
run("maintenance info break")

print("\n[+] Diagnostic tracer finished.")
