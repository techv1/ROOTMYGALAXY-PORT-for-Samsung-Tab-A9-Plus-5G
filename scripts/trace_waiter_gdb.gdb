set architecture aarch64
set pagination off
set confirm off
set print address on
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_target.sh

break *0xffffffc010375600
commands
  silent
  printf "\n[RB-ERASE pre-call site +0x244] pc=%#lx x0=%#lx x1=%#lx x19(task)=%#lx x23(lock)=%#lx x25(waiter)=%#lx\n", $pc, $x0, $x1, $x19, $x23, $x25
  printf "[waiter words +0x00 through +0x48]\n"
  x/10gx $x25
  printf "[backtrace]\n"
  bt 8
  continue
end

break *0xffffffc010375604
commands
  silent
  printf "\n[RB-ERASE returned at +0x248] pc=%#lx x25(waiter)=%#lx\n", $pc, $x25
  x/10gx $x25
  bt 8
  continue
end

break *0xffffffc010375498
commands
  silent
  printf "\n[deadline compare load] pc=%#lx prio=%#x waiter=%#lx task_deadline=%#lx waiter_deadline=%#lx\n", $pc, *(unsigned int *)($x25 + 0x40), $x25, $x8, *(unsigned long *)($x25 + 0x48)
  continue
end

break *0xffffffc010375618
commands
  silent
  printf "\n[deadline refresh store] pc=%#lx waiter=%#lx new_deadline=%#lx old_deadline=%#lx\n", $pc, $x25, $x11, *(unsigned long *)($x25 + 0x48)
  continue
end

break *0xffffffc01037561c
commands
  silent
  printf "\n[deadline store completed] waiter_deadline=%#lx\n", *(unsigned long *)($x25 + 0x48)
  detach
  quit
end

continue
