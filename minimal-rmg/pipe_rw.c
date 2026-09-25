#include "common.h"

int pipe_rw_init(void) { return 0; }
int kwrite64(uint64_t addr, uint64_t val) { (void)addr; (void)val; return -1; }
int kread64(uint64_t addr, uint64_t *out) { (void)addr; if(out) *out = 0; return -1; }
