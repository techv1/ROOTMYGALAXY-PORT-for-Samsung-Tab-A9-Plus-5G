import gdb
import time

class RBTrace(gdb.Breakpoint):
    def __init__(self):
        super().__init__("*0xffffffc011638ae8")
        self.hit = 0

    def stop(self):
        self.hit += 1

        bt = gdb.execute("bt 5", to_string=True)

        if "rt_mutex_adjust_prio_chain" in bt:
            print("\n" + "=" * 70)
            print("[+] TARGET rb_erase CALLER FOUND")
            print(f"[+] rb_erase hit #{self.hit}")
            print(time.strftime("%Y-%m-%d %H:%M:%S"))
            print("=" * 70)
            print(bt)
            print("\n[+] STOPPING FOR MANUAL INSPECTION")
            return True

        return False

gdb.execute("set pagination off")
gdb.execute("set confirm off")
RBTrace()
gdb.execute("continue")
