#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "elf.h"
#include "ptrace.h"
#include "util.h"

#define R_SYSCALL   rax
#define R_IP        rip
#define R_ARG0      rdi
#define R_ARG1      rsi
#define R_ARG2      rdx
#define R_ARG3      r10
#define R_ARG4      r8
#define R_ARG5      r9

#define SYSCALL_STUB_ADDR   0x100000
#define X64_SYSCALL_BRK     0x9090909090cc050f                // syscall; int 3
#define SYS_kill            62
#define SYS_mmap            9
#define SYS_mprotect        10
#define SYS_munmap          11

unsigned long remote_syscall_addr = 0;


int remote_syscall(pid_t pid, int syscall_id, unsigned long arg0, unsigned long arg1, unsigned long arg2, 
        unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    struct user_regs_struct saved_regs, work_regs;
    int status;
    
    // save current register state
    printf("Saving current register state for pid %d\n", pid);
    ptrace_peekregs(pid, &saved_regs);

    // setup arguments for the syscall
    work_regs = saved_regs;
    work_regs.R_IP = remote_syscall_addr;
    work_regs.R_SYSCALL = syscall_id;
    work_regs.R_ARG0 = arg0;
    work_regs.R_ARG1 = arg1;
    work_regs.R_ARG2 = arg2;
    work_regs.R_ARG3 = arg3;
    work_regs.R_ARG4 = arg4;
    work_regs.R_ARG5 = arg5;

    // set the regs
    printf("Setting registers for syscall, RIP will be %llx\n", work_regs.R_IP);
    ptrace_pokeregs(pid, &work_regs);

    // run the program until breakpoint
    printf("Running syscall\n");
    if (ptrace(PTRACE_CONT, pid, 0, SIGCONT) == -1) {
        perror("Continuing program failed: ptrace");
        exit(-1);
    }
    waitpid(pid, &status, 0);
    while (WSTOPSIG(status) == SIGSTOP && ptrace(PTRACE_CONT, pid, 0, SIGCONT) != -1) {
        waitpid(pid, &status, 0);
    }
    if (WSTOPSIG(status) == SIGTRAP) {
        printf("Hit breakpoint in syscall stub!\n");
    }
    else {
        printf("Program terminated by signal %s\n", strsignal(WTERMSIG(status)));
    }

    // gets the regs for the return value
    ptrace_peekregs(pid, &work_regs);
    printf("RIP after running syscall: %llx\n", work_regs.R_IP);
    
    // restore original regs
    ptrace_pokeregs(pid, &saved_regs);

    // send SIGSTOP to the process and resume it to deliver the signal?
    syscall(SYS_kill, pid, SIGSTOP);
    if ((ptrace(PTRACE_CONT, pid, 0, 0) == -1) || (waitpid(pid, &status, 0), WSTOPSIG(status) != SIGSTOP)) {
        printf("Failed to SIGSTOP and restart child\n");
        exit(-1);
    }

    // syscall number register holds the return value
    return work_regs.R_SYSCALL;
}


void setup_remote_syscall(pid_t pid, unsigned long start_addr) {
    int retval;
    unsigned long data;

    // write syscall stub to start_addr
    printf("Writing syscall stub to executable section...\n");
    ptrace_peek(pid, start_addr, &data);
    ptrace_poke(pid, start_addr, (unsigned long)X64_SYSCALL_BRK);
    remote_syscall_addr = start_addr;

    // make syscall to map page at SYSCALL_STUB_ADDR
    printf("Making syscall to map page at %lx\n", (unsigned long)SYSCALL_STUB_ADDR);
    retval = remote_syscall(pid, SYS_mmap, SYSCALL_STUB_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("SYS_mmap returned %d\n", retval);
    if (retval == SYSCALL_STUB_ADDR) {
        // our mapping worked, put our syscall stub at SYSCALL_STUB_ADDR and
        // change to that addr for future syscalls
        ptrace_poke(pid, SYSCALL_STUB_ADDR, (unsigned long)X64_SYSCALL_BRK);
        remote_syscall_addr = SYSCALL_STUB_ADDR;
        // restore original data
        ptrace_poke(pid, start_addr, data);
    }
}


void child(char *procname, char *argv[]) {
    printf("In child, executing %s\n", procname);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execv(procname, argv);
}


void parent(pid_t pid, char *progname) {
    int status;
    list_node *maps, *maps_ptr;
    int retval;

    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // modify process
        printf("cat /proc/%d/maps\n", pid);
        printf("Enter to continue");
        getchar();

        // find an executable mapping and setup our remote syscall stub
        maps = parse_maps(pid);
        maps_ptr = maps;
        for (maps_ptr; maps_ptr != NULL; maps_ptr = maps_ptr->next) {
            struct map *map = maps_ptr->data;
            if (map->is_x) {
                printf("Found executable section, doing remote syscall setup...\n");
                setup_remote_syscall(pid, map->start);
                break;
            }
        }

        if (remote_syscall_addr == 0) {
            printf("Did not find executable section to setup syscall? Impossible\n");
            exit(-1);
        }

        printf("Removing all mappings of original program...");
        maps_ptr = maps;
        for (maps_ptr; maps_ptr != NULL; maps_ptr = maps_ptr->next) {
            struct map *map = maps_ptr->data;
            if (strstr(map->text, progname) != NULL) {
                printf("  * Removing mapping at %lx... ", map->start);
                retval = remote_syscall(pid, SYS_munmap, map->start, (size_t)(map->end-map->start), 0, 0, 0, 0);
                if (retval == 0) {
                    printf("success\n");
                }
                else {
                    printf("failed!\n");
                }
            }
        }

        printf("About to restart process, Enter to continue....\n");
        getchar();
        ptrace(PTRACE_CONT, pid, 1, 0);
    }
}


int main(int argc, char *argv[]) {
    pid_t pid;

    pid = fork();
    switch (pid) {
        case 0:
            child(argv[1], &argv[1]);
            break;
        case -1:
            // error
            break;
        default:
            parent(pid, argv[1]);
            break;
    }

    return 0;
}
