set architecture aarch64
set pagination off
set confirm off
set print address on
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_recvmmsg_repeat_target.sh

break *0xffffffc010375600
commands
  silent
  printf "\n[before rb_erase] pc=%#lx x0(node)=%#lx x1(root)=%#lx waiter=%#lx lock=%#lx\n", $pc, $x0, $x1, $x25, $x23
  x/10gx $x25
  printf "[lock and waiter-root words before erase]\n"
  x/5gx $x23
  x/2gx $x1
  continue
end

break *0xffffffc010375604
commands
  silent
  printf "\n[after rb_erase] pc=%#lx waiter=%#lx lock=%#lx\n", $pc, $x25, $x23
  x/10gx $x25
  printf "[lock and waiter-root words after erase]\n"
  x/5gx $x23
  x/2gx ($x23 + 8)
  detach
  quit
end

continue
