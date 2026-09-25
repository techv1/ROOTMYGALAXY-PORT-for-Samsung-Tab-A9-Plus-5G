import gdb

RB_ERASE = 0xffffffc011638ae8
RT_MUTEX_ADJUST = 0xffffffc0103753bc

def u64(v):
    return int(v) & 0xffffffffffffffff

def R(name):
    try:
        return u64(gdb.parse_and_eval("$" + name))
    except:
        return 0

class RBEraseFiltered(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*0x{RB_ERASE:x}", gdb.BP_BREAKPOINT)
        self.hits = 0
        self.relevant = 0

    def stop(self):
        self.hits += 1

        bt = gdb.execute("bt 6", to_string=True)

        if "remove_waiter" not in bt:
            return False

        self.relevant += 1

        print(
            f"\n========== RT RB_ERASE #{self.relevant} "
            f"(global #{self.hits}) =========="
        )

        print(
            f"PC  = 0x{R('pc'):016x}\n"
            f"LR  = 0x{R('x30'):016x}\n"
            f"X0  = 0x{R('x0'):016x}"
        )

        print(bt)

        for r in (
            "x0", "x1", "x2", "x3",
            "x19", "x20", "x21", "x22",
            "x23", "x24", "x25", "x26", "x27"
        ):
            print(f"{r:>3} = 0x{R(r):016x}")

        print("----- rb node at X0 -----")
        try:
            print(gdb.execute("x/8gx $x0", to_string=True))
        except Exception as e:
            print(e)

        print("====================================")

        return False


class RTMutexAdjust(gdb.Breakpoint):
    def __init__(self):
        super().__init__(f"*0x{RT_MUTEX_ADJUST:x}", gdb.BP_BREAKPOINT)
        self.hits = 0

    def stop(self):
        self.hits += 1

        print(f"\n========== RT_MUTEX_ADJUST #{self.hits} ==========")

        for r in (
            "x0", "x1", "x2", "x3",
            "x19", "x21", "x22", "x23",
            "x25", "x26", "x27", "x30"
        ):
            print(f"{r:>3} = 0x{R(r):016x}")

        print(gdb.execute("bt 8", to_string=True))

        print("==============================================")

        return False


RBEraseFiltered()
RTMutexAdjust()

print("[phase4] filtered tracer installed")
print("[phase4] generic rb_erase hits are suppressed")
print("[phase4] only remove_waiter() RB activity is printed")
