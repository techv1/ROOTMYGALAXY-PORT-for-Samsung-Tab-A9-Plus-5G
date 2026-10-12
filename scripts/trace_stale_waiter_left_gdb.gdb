set architecture aarch64
set pagination off
set confirm off
set print address on
file /root/s/vmlinux.elf
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_stale_waiter_left_target.sh
set $stale_waiter = 0

break *0xffffffc010376460 if *(unsigned long *)($x23 + 0x30) != $x20
commands
  silent
  set $stale_waiter = $x23
  set $stale_task = *(unsigned long *)($x23 + 0x30)
  printf "\n[rollback] waiter=%#lx task=%#lx current=%#lx pi_blocked_on=%#lx\n", $stale_waiter, $stale_task, $x20, *(unsigned long *)($stale_task + 0x900)
  disable 1
  continue
end

break *0xffffffc0112ed380 if $sp + 0x88 == $stale_waiter
commands
  silent
  printf "\n[recvmmsg copied left-child marker] waiter=%#lx\n", $stale_waiter
  x/10gx $stale_waiter
  watch -location *(unsigned long *)$stale_waiter
  commands
    silent
    printf "[parent/color qword write] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)$stale_waiter
    bt 5
    continue
  end
  disable 2
  continue
end

break *0xffffffc010375428 if $x25 == $stale_waiter
commands
  silent
  printf "\n[PI walk loaded stale waiter] task=%#lx lock=%#lx waiter=%#lx\n", $x19, $x23, $x25
  x/10gx $x25
  disable 3
  continue
end

# Stop before rb_erase executes: the diagnostic marker is a mapped address,
# but the GDB session must not execute the erase with the forged link.
break *0xffffffc010375600 if $x25 == $stale_waiter
commands
  silent
  printf "\n[stale waiter at lock rb_erase callsite; stopped before call]\n"
  printf "node=%#lx root=%#lx task=%#lx lock=%#lx\n", $x0, $x1, $x19, $x23
  x/10gx $x25
  x/2gx $x1
  detach
  quit
end

break *0xffffffc0103757d8 if $x26 == $stale_waiter + 0x18
commands
  silent
  printf "\n[stale waiter pi_tree at rb_erase callsite; stopped before call]\n"
  printf "node=%#lx root=%#lx task=%#lx\n", $x0, $x1, $x19
  x/10gx $stale_waiter
  detach
  quit
end

break *0xffffffc010375874 if $x25 == $stale_waiter + 0x18
commands
  silent
  printf "\n[stale waiter pi_tree at rb_erase callsite; stopped before call]\n"
  printf "node=%#lx root=%#lx task=%#lx\n", $x0, $x1, $x19
  x/10gx $stale_waiter
  detach
  quit
end

continue
