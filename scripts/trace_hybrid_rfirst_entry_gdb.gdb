set architecture aarch64
set pagination off
set confirm off
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_rfirst_target.sh

# Stop at the first rt_mutex_adjust_prio_chain entry for the candidate lock,
# before lock acquisition or rbtree processing can hang/fault.
break *0xffffffc0103753bc
condition 1 $x3 == 0xffffffc012f04080
commands
  silent
  printf "\n[recvmmsg-first target-lock chain entry] task=%#lx arg1=%#lx arg2=%#lx lock=%#lx waiter_arg=%#lx arg5=%#lx\n", $x0, $x1, $x2, $x3, $x4, $x5
  x/10gx $x4
  detach
  quit
end

continue
