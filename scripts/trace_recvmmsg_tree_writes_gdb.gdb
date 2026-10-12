set architecture aarch64
set pagination off
set confirm off
set print address on
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_recvmmsg_repeat_target.sh

# do_recvmmsg copies the 56-byte userspace header to SP+0x98. On this
# measured X216B layout that begins at waiter+0x10, so waiter = SP+0x88.
# Break immediately after _copy_from_user returns.
break *0xffffffc0112ed380
commands
  silent
  set $candidate = $sp + 0x88
  printf "\n[recvmmsg copy returned] pc=%#lx sp=%#lx candidate_waiter=%#lx\n", $pc, $sp, $candidate
  x/10gx $candidate
  watch -location *(unsigned long *)$candidate
  commands
    silent
    printf "[write rb_parent_color] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)$candidate
    bt 4
    continue
  end
  watch -location *(unsigned long *)($candidate + 8)
  commands
    silent
    printf "[write rb_right] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)($candidate + 8)
    bt 4
    continue
  end
  watch -location *(unsigned long *)($candidate + 16)
  commands
    silent
    printf "[write rb_left] pc=%#lx value=%#lx\n", $pc, *(unsigned long *)($candidate + 16)
    bt 4
    continue
  end
  continue
end

break *0xffffffc010375600
commands
  silent
  printf "\n[before target rb_erase] pc=%#lx node=%#lx waiter=%#lx lock=%#lx\n", $pc, $x0, $x25, $x23
  x/10gx $x25
  printf "[lock root]\n"
  x/2gx ($x23 + 8)
  detach
  quit
end

continue
