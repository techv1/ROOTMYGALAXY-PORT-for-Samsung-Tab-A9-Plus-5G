set architecture aarch64
set pagination off
set confirm off
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_target.sh

# Inspect MCAST's copied tail and then stop only when the distinctive hybrid
# parent tag is present in a waiter loaded from task->pi_blocked_on.
break *0xffffffc0113b617c
commands
  silent
  printf "\n[hybrid MCAST copy] result=%#lx opt=%#x len=%#x sp=%#lx\n", $x0, $x22, $x23, $sp
  x/8gx ($sp + 0xf8)
  continue
end

break *0xffffffc01037542c
commands
  silent
  if *(unsigned long *)$x25 == 0x1111111111111110
    printf "\n[hybrid stamp reached consumer] pc=%#lx task=%#lx waiter=%#lx lock_arg=%#lx\n", $pc, $x19, $x25, $x23
    x/10gx $x25
    detach
    quit
  end
  continue
end

continue
