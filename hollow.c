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

struct map {
    unsigned long start;
    unsigned long end;
    int is_r;
    int is_w;
    int is_x;
};


void parse_map(char *buf, struct map *map) {
    char *addrs;
    char *perms;
    char *start_addr, *end_addr;

    addrs = strtok(buf, " ");
    if (!addrs) {
        printf("could not parse addresses from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    perms = strtok(NULL, " ");
    if (!perms) {
        printf("could not parse permissions from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    start_addr = strtok(addrs, "-");
    if (!start_addr) {
        printf("could not parse start address from maps! line was:\n%s\n", buf);
        exit(-1);
    }
    
    end_addr = strtok(NULL, "-");
    if (!end_addr) {
        printf("could not parse end address from maps! line was:\n%s\n", buf);
        exit(-1);
    }

    map->start = strtoul(start_addr, NULL, 16);
    map->end = strtoul(end_addr, NULL, 16);
    if (perms[0] == 'r') { map->is_r = 1; }
    if (perms[1] == 'w') { map->is_w = 1; }
    if (perms[2] == 'x') { map->is_x = 1; }
}


void ptrace_peek(pid_t pid, unsigned long addr, unsigned long *out) {
    unsigned long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        perror("ptrace peek failed");
        exit(-1);
    }
    *out = data;
}


void ptrace_poke(pid_t pid, unsigned long addr, unsigned long data) {
    unsigned long status = ptrace(PTRACE_POKEDATA, pid, addr, data);
    if (status == -1) {
        perror("ptrace poke failed");
        exit(-1);
    }
}


void ptrace_peekregs(pid_t pid, struct user_regs_struct *regs) {
    printf("Peeking at regs...\n");
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        perror("Failed to peek regs: ptrace");
        exit(-1);
    }
}


void ptrace_pokeregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("Failed to poke regs: ptrace");
        exit(-1);
    }
}


int remote_syscall(pid_t pid, int syscall_id, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
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
    ptrace_poke(pid, start_addr, (unsigned long)X64_SYSCALL_BRK);
    remote_syscall_addr = start_addr;

    // check what we just did
    ptrace_peek(pid, start_addr, &data);
    printf("New data at addr %lx: %lx\n", start_addr, data);

    // make syscall to map page at SYSCALL_STUB_ADDR
    printf("Making syscall to map page at %lx\n", (unsigned long)SYSCALL_STUB_ADDR);
    retval = remote_syscall(pid, SYS_mmap, SYSCALL_STUB_ADDR, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("SYS_mmap returned %d\n", retval);
    if (retval == SYSCALL_STUB_ADDR) {
        // our mapping worked, put our syscall stub at SYSCALL_STUB_ADDR
        ptrace_poke(pid, SYSCALL_STUB_ADDR, (unsigned long)X64_SYSCALL_BRK);
        remote_syscall_addr = SYSCALL_STUB_ADDR;
    }
}


void child(char *procname, char *argv[]) {
    printf("In child, executing %s\n", procname);
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execv(procname, argv);
}


void parent(pid_t pid, char *progname) {
    int status;
    int did_syscall_setup = 0;
    char procpath[1024];
    char buf[1024];
    FILE* vmmap;

    waitpid(pid, &status, 0);
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        // modify process
        printf("cat /proc/%d/maps\n", pid);
        printf("Enter to continue");
        getchar();

        // open /proc/[pid]/maps
        memset(procpath, 0, sizeof(procpath));
        snprintf(procpath, sizeof(procpath), "/proc/%d/maps", pid);
        vmmap = fopen(procpath, "r");
        if (!vmmap) {
            perror("fopen");
            exit(-1);
        }

        // find all mappings that contain the binary path
        // TODO: this could fail for many reasons (e.g. path was a symlink and real path is different),
        //       improve someday
        while(fgets(buf, sizeof(buf), vmmap) != NULL) {
            if (strstr(buf, progname) != NULL) {
                // get the start-end address of the map, and calculate its size
                struct map map;
                int retval;

                memset(&map, 0, sizeof(map)); 
                printf("found map: %s", buf);
                parse_map(buf, &map);
                printf("start addr: %lx, end addr: %lx\n", map.start, map.end);

                if (did_syscall_setup) {
                    printf("Removing mapping at %lx... ", map.start);
                    retval = remote_syscall(pid, SYS_munmap, map.start, (map.end-map.start), 0, 0, 0, 0);
                    if (retval == 0) {
                        printf("success\n");
                    }
                    else {
                        printf("failed!\n");
                    }
                }
                
                // did we setup the remote syscall functionality yet? is this an executable section?
                if ((did_syscall_setup == 0) && map.is_x) {
                    printf("Found executable section, doing remote syscall setup...\n");
                    setup_remote_syscall(pid, map.start);
                    did_syscall_setup = 1;
                }

            }
        }
        printf("About to restart process, Enter to continue....\n");
        getchar();
        ptrace(PTRACE_CONT, pid, (caddr_t)1, 0);
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
