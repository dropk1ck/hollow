#include "ptrace.h"
#include <sys/ptrace.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>


void ptrace_peek(pid_t pid, unsigned long addr, unsigned long *out) {
    unsigned long data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (data == -1) {
        // fail here, we cannot continue
        perror("ptrace peek failed");
        exit(-1);
    }
    *out = data;
}


void ptrace_poke(pid_t pid, unsigned long addr, unsigned long data) {
    unsigned long status = ptrace(PTRACE_POKEDATA, pid, addr, data);
    if (status == -1) {
        perror("ptrace poke failed");
        // fail here, we cannot continue
        exit(-1);
    }
}


void ptrace_peekregs(pid_t pid, struct user_regs_struct *regs) {
    printf("Peeking at regs...\n");
    if (ptrace(PTRACE_GETREGS, pid, 0, regs) == -1) {
        // fail here, we cannot continue
        perror("Failed to peek regs: ptrace");
        exit(-1);
    }
}


void ptrace_pokeregs(pid_t pid, struct user_regs_struct *regs) {
    if (ptrace(PTRACE_SETREGS, pid, 0, regs) == -1) {
        // fail here, we cannot continue
        perror("Failed to poke regs: ptrace");
        exit(-1);
    }
}

