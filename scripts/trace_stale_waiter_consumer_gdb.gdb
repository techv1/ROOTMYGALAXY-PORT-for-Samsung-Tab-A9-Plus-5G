set architecture aarch64
set pagination off
set confirm off
set print address on
file /root/s/vmlinux.elf
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_remove_waiter_target.sh
set $stale_waiter = 0

# Save the waiter and owning task at the vulnerable proxy-lock rollback.
break *0xffffffc010376460 if *(unsigned long *)($x23 + 0x30) != $x20
commands
  silent
  set $stale_waiter = $x23
  set $stale_task = *(unsigned long *)($x23 + 0x30)
  printf "\n[rollback] waiter=%#lx task=%#lx current=%#lx pi_blocked_on=%#lx\n", $stale_waiter, $stale_task, $x20, *(unsigned long *)($stale_task + 0x900)
  disable 1
  continue
end

# The original recvmmsg header copy returns here. It overlaps waiter+0x10
# when do_recvmmsg's SP+0x98 equals stale_waiter+0x10.
break *0xffffffc0112ed380 if $sp + 0x88 == $stale_waiter
commands
  silent
  printf "\n[matching recvmmsg copy return] sp=%#lx waiter=%#lx\n", $sp, $stale_waiter
  x/10gx $stale_waiter
  watch -location *(unsigned long *)$stale_waiter
  commands
    silent
    printf "[tree parent/color write] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)$stale_waiter
    bt 4
    continue
  end
  watch -location *(unsigned long *)($stale_waiter + 8)
  commands
    silent
    printf "[rb_right write] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)($stale_waiter + 8)
    bt 4
    continue
  end
  watch -location *(unsigned long *)($stale_waiter + 16)
  commands
    silent
    printf "[rb_left write] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)($stale_waiter + 16)
    bt 4
    continue
  end
  disable 2
  continue
end

# rt_mutex_adjust_prio_chain has just loaded task->pi_blocked_on into x25.
break *0xffffffc010375428 if $x25 == $stale_waiter
commands
  silent
  printf "\n[PI walk loaded the saved stale waiter] task=%#lx lock=%#lx waiter=%#lx\n", $x19, $x23, $x25
  x/10gx $x25
  disable 3
  continue
end

# Stop before the lock-waiters rb_erase executes.
break *0xffffffc010375600 if $x25 == $stale_waiter
commands
  silent
  printf "\n[stale waiter passed to lock rb_erase] node=%#lx root=%#lx task=%#lx lock=%#lx\n", $x0, $x1, $x19, $x23
  x/10gx $x25
  x/2gx $x1
  detach
  quit
end

# Stop before either task-PI-tree erase if it targets this waiter's pi_tree.
break *0xffffffc0103757d8 if $x26 == $stale_waiter + 0x18
commands
  silent
  printf "\n[stale waiter pi_tree passed to rb_erase] node=%#lx root=%#lx task=%#lx\n", $x0, $x1, $x19
  x/10gx $stale_waiter
  detach
  quit
end

break *0xffffffc010375874 if $x25 == $stale_waiter + 0x18
commands
  silent
  printf "\n[stale waiter pi_tree passed to rb_erase] node=%#lx root=%#lx task=%#lx\n", $x0, $x1, $x19
  x/10gx $stale_waiter
  detach
  quit
end

continue
