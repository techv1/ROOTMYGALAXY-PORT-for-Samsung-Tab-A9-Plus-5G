# 04. Post-Corruption & Root Execution Chain

Once the priority rbtree corruption primitive gives an arbitrary 8-byte write or memory tampering capability, the exploit transitions to gaining arbitrary physical read/write and escalating privileges.

---

## 1. Arbitrary Physical Memory Read/Write via Pipe Buffers

The canonical Linux Android post-exploitation technique uses corrupted `struct pipe_buffer` objects:

1. Create a large array of pipes (`pipe2(fd, O_NONBLOCK)`).
2. Write 1 page to each pipe to populate `pipe->bufs[0]`.
3. The kernel allocates `struct pipe_buffer`:
   ```c
   struct pipe_buffer {
       struct page *page;
       unsigned int offset;
       unsigned int len;
       const struct pipe_buf_operations *ops;
       unsigned int flags;
       unsigned long private;
   };
   ```
4. By corrupting `pipe_buffer.page` to point to physical address `0` (or `P0_PHYS_OFFSET = 0x80000000`), reading/writing through the pipe translates into an unconstrained physical memory read/write across all DRAM.

---

## 2. Clang CFI Jump Table (.cfi_jt) Requirement

The SM-X216B kernel is compiled with **`CONFIG_CFI_CLANG=y`**.

### The CFI Protection Mechanism:
Any indirect function pointer call (e.g. `work->func(work)` or `file->f_op->write(...)`) is checked against a Clang forward-edge jump table located in `.cfi_jt` sections:
```assembly
sub    x9, x8, #0x1166c000
ror    x9, x9, #2
cmp    x9, #0x27
b.hs   <panic_cfi_check_failed>
blr    x8
```
If a forged object points to an raw function body (`call_usermodehelper_exec_work = 0xffffffc010317274`) instead of its CFI entrypoint, the CPU jumps to the trap handler, immediately crashing the system with a Kernel CFI Panic.

### Correct CFI Targets on SM-X216B:
- **`CALL_USERMODEHELPER_EXEC_WORK_CFI_JT`**: `0xffffffc011681870`
- **`CONFIGFS_WRITE_BIN_FILE_CFI_JT`**: `0xffffffc01167595c`
- **`CONFIGFS_READ_BIN_FILE_CFI_JT`**: `0xffffffc0116738d8`

---

## 3. The UMH Limitation & Direct Credential Overwrite

### The Problem:
`CONFIG_STATIC_USERMODEHELPER_PATH=""` disables spawning external usermode binaries via `call_usermodehelper_exec_work` directly. Even if the workqueue is successfully hijacked, the helper immediately aborts with `-ENOENT`.

### The Solution:
Because **Knox RKP / KDP is NOT compiled into this kernel** (`# CONFIG_RKP / KDP not set` in kernel config):
1. **Direct Credential Modification is Permitted**:
   - The kernel does not enforce EL2 hypervisor page-table write protection on credential slabs (`struct cred`).
   - Using the arbitrary physical read/write primitive obtained via pipe buffers, locate the exploit thread's `struct task_struct`.
   - Read `task->cred` at offset `+0x808` and `task->real_cred` at `+0x800`.
   - Patch `uid`, `gid`, `euid`, `egid`, `fsuid`, `fsgid` to `0` (root).
   - Zero out `cap_inheritable`, set `cap_permitted` and `cap_effective` to `0x3fffffffff` (`CAP_ALL`).
   - Set `task->cred->security` (SELinux sid) to `SECINITSID_KERNEL` (SID 1) or disable SELinux enforcing bit via `ADDR_SELINUX_ENFORCING` (`0xffffffc012b9f001 = 0`).
2. Alternatively, physically patch `CONFIG_STATIC_USERMODEHELPER_PATH` in the kernel `.rodata` section from `""` to `"/system/bin/sh\0"` before queuing the UMH work item.
