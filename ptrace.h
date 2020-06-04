#ifndef __PTRACE_H
#define __PTRACE_H

#include <sys/types.h>
#include <sys/user.h>


void ptrace_peek(pid_t pid, unsigned long addr, unsigned long *out);
void ptrace_poke(pid_t pid, unsigned long addr, unsigned long data);
void ptrace_peekregs(pid_t pid, struct user_regs_struct *regs);
void ptrace_pokeregs(pid_t pid, struct user_regs_struct *regs);

#endif  // __PTRACE_H