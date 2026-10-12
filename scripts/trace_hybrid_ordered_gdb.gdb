set architecture aarch64
set pagination off
set confirm off
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_target.sh

# MCAST_BLOCK_SOURCE's copy-return site; preserve its two tagged waiter words.
break *0xffffffc0113b617c
commands
  silent
  printf "\n[hybrid MCAST copy] result=%#lx opt=%#x len=%#x sp=%#lx\n", $x0, $x22, $x23, $sp
  x/8gx ($sp + 0xf8)
  disable 1
  continue
end

# do_recvmmsg returns from its 56-byte _copy_from_user at +0x148.
break *0xffffffc0112ed380
commands
  silent
  printf "\n[hybrid recvmmsg copy] result=%#lx sp=%#lx local_hdr=%#lx\n", $x0, $sp, $sp+0x98
  x/7gx ($sp + 0x98)
  enable 3
  continue
end

# First PI-chain waiter loaded after recvmmsg has stamped its stack window.
break *0xffffffc01037542c
commands
  silent
  printf "\n[hybrid post-stamp PI waiter] task=%#lx waiter=%#lx lock_arg=%#lx\n", $x19, $x25, $x23
  x/10gx $x25
  detach
  quit
end
disable 3

continue
