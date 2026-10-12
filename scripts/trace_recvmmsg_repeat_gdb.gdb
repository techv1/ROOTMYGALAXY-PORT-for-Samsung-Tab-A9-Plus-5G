set architecture aarch64
set pagination off
set confirm off
set print address on
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_recvmmsg_repeat_target.sh

# Target rt_mutex_adjust_prio_chain callsite for rb_erase(waiter->tree_entry).
break *0xffffffc010375600
commands
  silent
  printf "\n[recvmmsg PI-walk rb_erase pre-call] pc=%#lx x0(node)=%#lx x1(root)=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $pc, $x0, $x1, $x19, $x23, $x25
  x/10gx $x25
  bt 8
  detach
  quit
end

continue
