#!/usr/bin/env python3
import gdb
import time
import os
import sys
import datetime
import threading

timestamp_str = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
LOG_FILE = f"/root/s/trace_observation_{timestamp_str}.log"
LATEST_LOG = "/root/s/trace_observation_latest.log"
MARKER_FILE = "/root/s/trace_done.marker"
OBSERVATION_TIMEOUT = 35.0  # seconds to observe execution (boot + init)

SITE_CONFIG = {
    0xffffffc010375600: ("SITE_1", "+580  (rb_erase call site 1)"),
    0xffffffc0103757d8: ("SITE_2", "+1052 (rb_erase call site 2)"),
    0xffffffc010375874: ("SITE_3", "+1208 (rb_erase call site 3)"),
}
ENTRY_ADDR = 0xffffffc0103753bc

hit_stats = {
    "SITE_1": 0,
    "SITE_2": 0,
    "SITE_3": 0,
}
fired_site = None
unexpected_sigtrap_occurred = False
timer_interrupted = False

# Clean previous marker
if os.path.exists(MARKER_FILE):
    try:
        os.remove(MARKER_FILE)
    except Exception:
        pass

log_fp = open(LOG_FILE, "w", buffering=1)

def log(msg=""):
    print(msg)
    log_fp.write(msg + "\n")
    log_fp.flush()

log("=" * 80)
log(f"Automated GDB Observation Tracer - {timestamp_str}")
log(f"Log file: {LOG_FILE}")
log("=" * 80)

# Configure GDB environment safely
gdb.execute("set architecture aarch64")
gdb.execute("set pagination off")
gdb.execute("set confirm off")

# 1. Connects to the already-running QEMU target if GDB is not already connected
def ensure_connected():
    connected = False
    try:
        threads = gdb.selected_inferior().threads()
        if len(threads) > 0:
            connected = True
    except Exception:
        connected = False

    if not connected:
        log("[1] Connecting to remote target at 127.0.0.1:1234...")
        try:
            gdb.execute("target remote 127.0.0.1:1234")
            log("    Successfully connected to 127.0.0.1:1234.")
        except Exception as e:
            log(f"    Failed to connect to 127.0.0.1:1234: {e}")
            raise
    else:
        log("[1] Already connected to target remote.")

ensure_connected()

# 2. Removes stale breakpoints/watchpoints from the current GDB session
log("\n[2] Removing stale breakpoints/watchpoints...")
try:
    gdb.execute("delete")
except Exception as e:
    log(f"    delete command notice: {e}")

bps = gdb.breakpoints()
if bps:
    for bp in list(bps):
        bp.delete()

log("    Breakpoint table after deletion:")
log(gdb.execute("info break", to_string=True).strip())

# 7. Diagnostic capture function
def record_diagnostic(label, bp_addr=None):
    log("\n" + "=" * 80)
    log(f"DIAGNOSTIC STATE CAPTURE: {label}")
    log("=" * 80)
    if bp_addr is not None:
        log(f"Breakpoint Address: 0x{bp_addr:016x}")

    # Current PC
    try:
        pc = int(gdb.parse_and_eval("$pc"))
        log(f"Current PC:         0x{pc:016x}")
    except Exception as e:
        log(f"Current PC:         Error ({e})")
        pc = None

    # Current CPSR
    try:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        ss_bit = (cpsr >> 21) & 1
        log(f"Current CPSR:       0x{cpsr:08x} (PSTATE.SS bit 21 = {ss_bit})")
    except Exception as e:
        log(f"Current CPSR:       Error ({e})")

    # Current Thread / CPU
    log("\n--- Thread / CPU Information ---")
    try:
        th = gdb.selected_thread()
        if th:
            log(f"Active Thread: ID {th.num}, PTID {th.ptid}")
        log(gdb.execute("info threads", to_string=True).strip())
    except Exception as e:
        log(f"Error querying threads: {e}")

    # Backtrace up to 8 frames
    log("\n--- Backtrace (up to 8 frames) ---")
    try:
        log(gdb.execute("bt 8", to_string=True).strip())
    except Exception as e:
        log(f"Error querying backtrace: {e}")

    # x0 through x5
    log("\n--- Registers x0 - x5 ---")
    for r in ["x0", "x1", "x2", "x3", "x4", "x5"]:
        try:
            val = int(gdb.parse_and_eval(f"${r}"))
            log(f"  {r:>3} = 0x{val:016x}")
        except Exception as e:
            log(f"  {r:>3} = Error ({e})")

    # x19 through x30
    log("\n--- Registers x19 - x30 ---")
    for i in range(19, 31):
        r = f"x{i}"
        try:
            val = int(gdb.parse_and_eval(f"${r}"))
            log(f"  {r:>3} = 0x{val:016x}")
        except Exception as e:
            log(f"  {r:>3} = Error ({e})")

    # SP
    try:
        sp = int(gdb.parse_and_eval("$sp"))
        log(f"\n--- Stack Pointer (SP) ---\n  sp  = 0x{sp:016x}")
    except Exception as e:
        log(f"\n--- Stack Pointer (SP) ---\n  sp  = Error ({e})")
        sp = None

    # 32 bytes around SP if safe to read
    log("\n--- Stack Memory (32 bytes around SP) ---")
    if sp is not None:
        try:
            sp_mem = gdb.execute(f"x/32bx 0x{sp:016x}", to_string=True).strip()
            log(f"[SP] (32 bytes):\n{sp_mem}")
            sp_words = gdb.execute(f"x/4gx 0x{sp:016x}", to_string=True).strip()
            log(f"[SP] (4 x 64-bit words):\n{sp_words}")
        except Exception as e:
            log(f"Could not read memory at SP: {e}")
        try:
            around_mem = gdb.execute(f"x/32bx 0x{(sp - 16):016x}", to_string=True).strip()
            log(f"[SP - 16] (32 bytes around SP):\n{around_mem}")
        except Exception as e:
            log(f"Could not read memory around SP: {e}")
    else:
        log("SP is unavailable; skipping stack memory read.")

    # Instruction at breakpoint
    log("\n--- Instruction at Breakpoint ---")
    try:
        log(gdb.execute("x/1i $pc", to_string=True).strip())
    except Exception as e:
        log(f"Error reading instruction at PC: {e}")

    # Next 8 instructions
    log("\n--- Next 8 Instructions ---")
    try:
        log(gdb.execute("x/8i ($pc + 4)", to_string=True).strip())
    except Exception as e:
        log(f"Error reading next 8 instructions: {e}")

    log("=" * 80 + "\n")

# 3. Installs ordinary GDB breakpoints at exactly:
#    *0xffffffc010375600
#    *0xffffffc0103757d8
#    *0xffffffc010375874
# 4. Does NOT install a breakpoint at rt_mutex_adjust_prio_chain entry.
class SiteBreakpoint(gdb.Breakpoint):
    def __init__(self, addr, site_id, desc):
        super().__init__(f"*{addr:#x}", gdb.BP_BREAKPOINT, internal=False)
        self.site_id = site_id
        self.site_addr = addr
        self.desc = desc

    def stop(self):
        global fired_site
        hit_stats[self.site_id] += 1
        fired_site = self.site_id
        log(f"\n[!!!] HIT {self.site_id} at 0x{self.site_addr:016x} ({self.desc})")
        record_diagnostic(self.site_id, self.site_addr)
        # 9. After stopping at a site, DO NOT modify execution state. Leave target stopped.
        return True

log("\n[3] Installing breakpoints at the 3 target rb_erase call sites...")
active_bps = []
for addr, (site_id, desc) in SITE_CONFIG.items():
    bp = SiteBreakpoint(addr, site_id, desc)
    active_bps.append(bp)
    log(f"    Installed {site_id} at 0x{addr:016x} ({desc})")

log("[4] Verified: No breakpoint installed at rt_mutex_adjust_prio_chain entry (0xffffffc0103753bc).")

# 12. Print info break / maintenance info break
log("\n[12] Active breakpoint tables:")
log(gdb.execute("info break", to_string=True).strip())
log(gdb.execute("maintenance info break", to_string=True).strip())

# Setup observation timer
def timeout_handler():
    global timer_interrupted
    timer_interrupted = True
    log(f"\n[!] Observation window ({OBSERVATION_TIMEOUT}s) reached.")
    log("[!] Interrupting target execution via gdb.interrupt...")
    try:
        gdb.post_event(gdb.interrupt)
    except Exception as e:
        log(f"[-] gdb.interrupt exception: {e}")

obs_timer = threading.Timer(OBSERVATION_TIMEOUT, timeout_handler)
obs_timer.daemon = True

# 5. Does NOT use: si, stepi, next, nexti, set $cpsr, memory writes, register manipulation
# 6. Uses only normal continue for execution.
log("\n" + "=" * 80)
log("[6] Resuming execution with normal 'continue'")
log("    (No single-step, no register modification, no memory writes)")
log("=" * 80)

obs_timer.start()
continue_error = None
try:
    gdb.execute("continue")
except Exception as e:
    continue_error = str(e)
    log(f"[*] continue returned: {e}")
finally:
    obs_timer.cancel()

# Post-stop evaluation
current_pc = None
try:
    current_pc = int(gdb.parse_and_eval("$pc"))
except Exception:
    pass

current_thread_desc = "Unknown"
try:
    th = gdb.selected_thread()
    if th:
        current_thread_desc = f"Thread {th.num} (PTID {th.ptid})"
except Exception:
    pass

log(f"\n[*] Stop event processed.")
log(f"    Current PC:     {f'0x{current_pc:016x}' if current_pc is not None else 'N/A'}")
log(f"    Current Thread: {current_thread_desc}")

# 11. If GDB receives SIGTRAP at 0xffffffc0103753bc, determine cause without modifying CPSR
if current_pc == ENTRY_ADDR:
    unexpected_sigtrap_occurred = True
    log("\n" + "!" * 80)
    log(f"[11] SIGTRAP / STOP AT ENTRY ADDR: 0x{ENTRY_ADDR:016x} (rt_mutex_adjust_prio_chain)!")
    log("!" * 80)
    
    # 1. Breakpoint verification
    bps_info = gdb.execute("info break", to_string=True)
    maint_bps = gdb.execute("maintenance info break", to_string=True)
    is_gdb_bp = f"{ENTRY_ADDR:x}" in bps_info or f"{ENTRY_ADDR:x}" in maint_bps
    log(f"  -> GDB breakpoint active at entry: {is_gdb_bp}")
    log(f"  -> info break:\n{bps_info.strip()}")
    log(f"  -> maintenance info break:\n{maint_bps.strip()}")

    # 2. Instruction / Memory check
    try:
        raw_words = gdb.execute(f"x/2wx 0x{ENTRY_ADDR:016x}", to_string=True).strip()
        disasm = gdb.execute(f"x/2i 0x{ENTRY_ADDR:016x}", to_string=True).strip()
        log(f"  -> Memory contents at entry:\n{raw_words}")
        log(f"  -> Disassembly at entry:\n{disasm}")
    except Exception as e:
        log(f"  -> Failed to read memory: {e}")

    # 3. CPSR Single-Step bit check
    try:
        cpsr = int(gdb.parse_and_eval("$cpsr"))
        ss_bit = (cpsr >> 21) & 1
        log(f"  -> CPSR: 0x{cpsr:08x} (PSTATE.SS bit 21: {ss_bit})")
        if ss_bit:
            log("  -> Analysis: Target was halted due to active SINGLE-STEP state (PSTATE.SS is set).")
        elif is_gdb_bp:
            log("  -> Analysis: Target was halted due to a GDB breakpoint.")
        else:
            log("  -> Analysis: Target halted due to target-side debug event or software trap.")
    except Exception as e:
        log(f"  -> Failed to check CPSR: {e}")

    log("  -> Capturing diagnostic state at entry (without modifying CPSR or registers)...")
    record_diagnostic("SIGTRAP AT ENTRY (0xffffffc0103753bc)", ENTRY_ADDR)

elif fired_site is not None:
    log(f"\n[+] Success: Execution halted at identified site {fired_site}.")
elif timer_interrupted:
    log(f"\n[10] Observation window timed out ({OBSERVATION_TIMEOUT}s). No target breakpoint was hit during this window.")
    if current_pc is not None:
        record_diagnostic("STOP AFTER TIMEOUT", current_pc)
else:
    log(f"\n[*] Execution stopped at PC {f'0x{current_pc:016x}' if current_pc is not None else 'N/A'}")
    if current_pc is not None:
        record_diagnostic("STOP AT UNEXPECTED LOCATION", current_pc)

# Final summary report
log("\n" + "=" * 80)
log("CONCISE SUMMARY REPORT")
log("=" * 80)
log(f"* SITE_1 reached: {'YES' if hit_stats['SITE_1'] > 0 else 'NO'}")
log(f"* SITE_2 reached: {'YES' if hit_stats['SITE_2'] > 0 else 'NO'}")
log(f"* SITE_3 reached: {'YES' if hit_stats['SITE_3'] > 0 else 'NO'}")
log(f"* Number of hits for each: SITE_1={hit_stats['SITE_1']}, SITE_2={hit_stats['SITE_2']}, SITE_3={hit_stats['SITE_3']}")
log(f"* Whether any unexpected SIGTRAP occurred: {'YES' if unexpected_sigtrap_occurred else 'NO'}")
log(f"* Current PC/thread when observation ended: PC={f'0x{current_pc:016x}' if current_pc is not None else 'N/A'}, Thread={current_thread_desc}")
log("=" * 80)

log(f"\nObservations saved to {LOG_FILE}.")
log_fp.close()

# Also write copy to latest log
try:
    with open(LOG_FILE, "r") as f_in, open(LATEST_LOG, "w") as f_out:
        f_out.write(f_in.read())
except Exception:
    pass

# Write completion marker
with open(MARKER_FILE, "w") as f_marker:
    f_marker.write(f"DONE:{timestamp_str}")

# 9. After stopping at a site, DO NOT modify execution state. Leave the target stopped for inspection.
log("\n[9] Target is stopped. Keeping GDB session active to leave target stopped for inspection.")
try:
    while True:
        time.sleep(3600)
except Exception:
    pass
