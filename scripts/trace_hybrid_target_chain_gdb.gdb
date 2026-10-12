set architecture aarch64
set pagination off
set confirm off
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_target.sh

break *0xffffffc0112ed380
commands
  silent
  printf "\n[recvmmsg copy] result=%#lx local_hdr=%#lx\n", $x0, $sp+0x98
  x/7gx ($sp+0x98)
  disable 1
  continue
end

break *0xffffffc0113b617c
commands
  silent
  printf "\n[MCAST copy] result=%#lx copy=%#lx\n", $x0, $sp+0x20
  x/10gx ($sp+0xf8)
  disable 2
  continue
end

break *0xffffffc01037542c
condition 3 $x23 == 0xffffffc012f04080
commands
  silent
  printf "\n[target lock PI chain before link use] task=%#lx waiter=%#lx lock=%#lx\n", $x19, $x25, $x23
  x/10gx $x25
  detach
  quit
end

continue
