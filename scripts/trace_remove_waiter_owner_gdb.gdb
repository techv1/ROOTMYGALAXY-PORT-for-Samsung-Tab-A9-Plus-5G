set architecture aarch64
set pagination off
set confirm off
set print address on
file /root/s/vmlinux.elf
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_remove_waiter_target.sh

# At +0x48, remove_waiter has lock in x19, waiter in x23, and current task
# in x20. Stop only when the waiter belongs to a different task.
break *0xffffffc010376460 if *(unsigned long *)($x23 + 0x30) != $x20
commands
  silent
  set $victim_waiter = $x23
  set $victim_task = *(unsigned long *)($x23 + 0x30)
  set $rollback_current = $x20
  disable 1
  printf "\n[proxy rollback: waiter task differs from current]\n"
  printf "pc=%#lx lock=%#lx waiter=%#lx waiter_task=%#lx current=%#lx\n", $pc, $x19, $victim_waiter, $victim_task, $rollback_current
  printf "waiter tree links:\n"
  x/3gx $victim_waiter
  printf "waiter_task->pi_blocked_on=%#lx current->pi_blocked_on=%#lx\n", *(unsigned long *)($victim_task + 0x900), *(unsigned long *)($rollback_current + 0x900)
  bt 8
  continue
end

# Stop immediately after the target clears current->pi_blocked_on.
break *0xffffffc01037649c if $victim_task != $rollback_current
commands
  silent
  printf "\n[after current->pi_blocked_on clear]\n"
  printf "pc=%#lx waiter_task=%#lx current=%#lx waiter_task->pi_blocked_on=%#lx current->pi_blocked_on=%#lx\n", $pc, $victim_task, $rollback_current, *(unsigned long *)($victim_task + 0x900), *(unsigned long *)($rollback_current + 0x900)
  x/10gx $victim_waiter
  bt 8
  continue
end

# The vulnerable target passes current (x20) as the final chain-walk task.
# Stop at the call and compare it with waiter->task.
break *0xffffffc010376620 if $x5 != $victim_task
commands
  silent
  printf "\n[rt_mutex_adjust_prio_chain arguments]\n"
  printf "pc=%#lx arg_task(x0)=%#lx original_waiter=%#lx original_waiter_task=%#lx final_task_arg(x5)=%#lx\n", $pc, $x0, $victim_waiter, $victim_task, $x5
  bt 8
  detach
  quit
end

continue
