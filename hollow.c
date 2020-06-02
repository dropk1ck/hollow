#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
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
#define X64_SYSCALL_BRK     0xcc050f                // syscall; int 3

unsigned long remote_syscall_addr = 0;


void parse_addrs(char *buf, unsigned long *start, unsigned long *end) {
    char *addrs;
    char *start_addr, *end_addr;

    addrs = strtok(buf, " ");
    if (!addrs) {
        printf("could not parse addresses from maps! line was:\n%s\n", buf);
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

    *start = strtoul(start_addr, NULL, 16);
    *end = strtoul(end_addr, NULL, 16);
}


void ptrace_peek(pid_t pid, unsigned long addr, unsigned long *out) {
    unsigned long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        perror("ptrace");
        exit(-1);
    }
    *out = data;
}


void ptrace_poke(pid_t pid, unsigned long addr, unsigned long data) {
    unsigned long status = ptrace(PTRACE_POKEDATA, pid, addr, data);
    if (status == -1) {
        perror("ptrace");
        exit(-1);
    }
}

void ptrace_peekregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        perror("ptrace");
        exit(-1);
    }
}


void ptrace_pokeregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        perror("ptrace");
        exit(-1);
    }
}


void remote_syscall(pid_t pid, int syscall_id, int arg0, int arg1, int arg2, int arg3, int arg4, int arg5) {
    struct user_regs_struct saved_regs, work_regs;
    
    // save current register state
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
    ptrace_pokeregs(pid, &work_regs);
}


void setup_remote_syscall(pid_t pid, unsigned long start_addr) {

    // 1. write syscall stub to start_addr
    ptrace_poke(pid, start_addr, (unsigned long)X64_SYSCALL_BRK);
    remote_syscall_addr = start_addr;

    // 2. setup regs for mmap call of address 0x100000 size 0x1000 rwx perms


    // 3. write syscall stub to 0x100000
    // 4. win
    

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
        printf("This is where we would modify process\n");
        printf("Enter to continue\n");
        getchar();

        // open /proc/[pid]/maps
        memset(procpath, sizeof(procpath), 0);
        snprintf(procpath, sizeof(procpath), "/proc/%d/maps", pid);
        vmmap = fopen(procpath, "r");
        if (!vmmap) {
            perror("fopen");
            exit(-1);
        }

        // find all mappings that contain the binary path
        while(fgets(buf, sizeof(buf), vmmap) != NULL) {
            if (strstr(buf, progname) != NULL) {
                // get the start-end address of the map, and calculate its size
                unsigned long start, end, size;

                // the first time we're here, assume we've found the r-x mapping, and start this nonsense
                printf("found map: %s", buf);
                parse_addrs(buf, &start, &end);
                printf("start addr: %lx, end addr: %lx\n", start, end);
                
                // did we setup the remote syscall functionality yet?
                if (!did_syscall_setup) {
                    setup_remote_syscall(pid, start);
                    did_syscall_setup = 1;
                }

            }
        }

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
