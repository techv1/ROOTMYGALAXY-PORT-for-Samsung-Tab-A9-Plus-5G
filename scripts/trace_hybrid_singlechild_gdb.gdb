set architecture aarch64
set pagination off
set confirm off
set logging file /root/s/qemu-hybrid-singlechild-gdb.log
set logging overwrite on
set logging enabled on
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_hybrid_singlechild_target.sh
set $candidate_waiter = 0

break *0xffffffc0113b617c
commands
  silent
  set $candidate_waiter = $sp + 0xf8
  printf "\n[single-child MCAST copy] result=%#lx copy=%#lx\n", $x0, $sp+0x20
  printf "[candidate waiter address] %#lx\n", $candidate_waiter
  x/10gx ($sp+0xf8)
  disable 1
  continue
end

break *0xffffffc0112ed380
commands
  silent
  printf "\n[single-child recvmmsg copy] result=%#lx local_hdr=%#lx\n", $x0, $sp+0x98
  printf "[candidate waiter at recvmmsg copy] %#lx\n", $candidate_waiter
  x/10gx $candidate_waiter
  x/7gx ($sp+0x98)
  disable 2
  continue
end

break *0xffffffc010375600
condition 3 $x25 == $candidate_waiter
commands
  silent
  printf "\n[single-child candidate rb_erase PRE-CALL; skipping erase] site=0 node=%#lx root=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $x0, $x1, $x19, $x23, $x25
  x/10gx $candidate_waiter
  set $pc = $pc + 4
  detach
  quit
end

break *0xffffffc0103757d8
condition 4 $x25 == $candidate_waiter
commands
  silent
  printf "\n[single-child candidate rb_erase PRE-CALL; skipping erase] site=1 node=%#lx root=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $x0, $x1, $x19, $x23, $x25
  x/10gx $candidate_waiter
  set $pc = $pc + 4
  detach
  quit
end

break *0xffffffc010375874
condition 5 $x25 == $candidate_waiter
commands
  silent
  printf "\n[single-child candidate rb_erase PRE-CALL; skipping erase] site=2 node=%#lx root=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $x0, $x1, $x19, $x23, $x25
  x/10gx $candidate_waiter
  set $pc = $pc + 4
  detach
  quit
end

# This is the retry point reached when _raw_spin_trylock(x23) fails. Stop here
# before the PI-chain loop repeats so the active lock and stale waiter can be
# compared without entering a possible soft-lockup loop again.
break *0xffffffc01037542c
condition 6 $x25 == $candidate_waiter
commands
  silent
  printf "\n[single-child PI walk FIRST candidate check] task=%#lx active_lock=%#lx waiter=%#lx waiter_lock=%#lx\n", $x19, $x23, $x25, *(unsigned long *)($candidate_waiter+0x38)
  x/10gx $candidate_waiter
  detach
  quit
end

break *0xffffffc0103754d0
condition 7 $x25 == $candidate_waiter
commands
  silent
  printf "\n[single-child PI retry PRE-LOOP] task=%#lx active_lock=%#lx waiter=%#lx waiter_lock=%#lx\n", $x19, $x23, $x25, *(unsigned long *)($candidate_waiter+0x38)
  printf "[active lock words]\n"
  x/4gx $x23
  printf "[candidate waiter words]\n"
  x/10gx $candidate_waiter
  detach
  quit
end

continue
