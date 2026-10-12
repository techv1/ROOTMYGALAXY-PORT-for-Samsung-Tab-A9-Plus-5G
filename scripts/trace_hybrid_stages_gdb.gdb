set architecture aarch64
set pagination off
set confirm off
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_target.sh

# Inspect the IPv4 MCAST local copy where prior target tracing located it.
break *0xffffffc0113b617c
commands
  silent
  printf "\n[hybrid MCAST copy] result=%#lx opt=%#x len=%#x sp=%#lx copy=%#lx\n", $x0, $x22, $x23, $sp, $sp+0x20
  x/8gx ($sp + 0xf8)
  continue
end

# Stop at the first PI-chain waiter load and inspect its fields before use.
break *0xffffffc01037542c
commands
  silent
  printf "\n[hybrid first PI-chain waiter] task=%#lx waiter=%#lx lock_arg=%#lx\n", $x19, $x25, $x23
  x/10gx $x25
  detach
  quit
end

continue
