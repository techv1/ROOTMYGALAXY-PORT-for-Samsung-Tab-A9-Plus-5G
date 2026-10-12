set architecture aarch64
set pagination off
set confirm off
set print address on
set $ipv4_copy = 0
target remote | /bin/bash /root/s/samsung_x216b_research/scripts/qemu_gdb_ipv4_target.sh

# do_ip_setsockopt returns from _copy_from_user at this point. Its local
# 0x108-byte scratch copy begins at SP+0x20.
break *0xffffffc0113b617c
commands
  silent
  set $ipv4_copy = $sp + 0x20
  printf "\n[IPv4 MCAST copied input] pc=%#lx sp=%#lx copy=%#lx copy_result=%#lx opt=%#x len=%#x\n", $pc, $sp, $ipv4_copy, $x0, $x22, $x23
  x/33gx $ipv4_copy
  continue
end

# Observe the chain entry and waiter pointer without relying on GDB convenience
# variables surviving QEMU's per-vCPU thread switches.
break *0xffffffc0103753bc
commands
  silent
  printf "\n[rt_mutex_adjust_prio_chain entry] pc=%#lx arg0=%#lx arg1=%#lx arg2=%#lx arg3=%#lx\n", $pc, $x0, $x1, $x2, $x3
  continue
end

break *0xffffffc01037542c
commands
  silent
  printf "\n[IPv4 PI-walk waiter] pc=%#lx task=%#lx waiter=%#lx lock_arg=%#lx\n", $pc, $x19, $x25, $x23
  x/10gx $x25
  continue
end

break *0xffffffc010375600
commands
  silent
  printf "\n[IPv4 rb_erase] pc=%#lx arg0=%#lx waiter=%#lx\n", $pc, $x0, $x25
  x/10gx $x25
  continue
end

break *0xffffffc01037561c
commands
  silent
  printf "\n[IPv4 deadline refresh complete] pc=%#lx waiter=%#lx deadline=%#lx\n", $pc, $x25, *(unsigned long *)($x25 + 0x48)
  detach
  quit
end

continue
