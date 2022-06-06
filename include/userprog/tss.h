#ifndef USERPROG_TSS_H
#define USERPROG_TSS_H

#include <stdint.h>
#include "threads/thread.h"

struct task_state { 
	uint32_t res1; //syscall_entry.S에서 movq 4(%r12), %rsp하면 아래 rsp0로
	uint64_t rsp0; //tss_init에서 kernel stack을 가리키게 됨.
	uint64_t rsp1;
	uint64_t rsp2;
	uint64_t res2;
	uint64_t ist1;
	uint64_t ist2;
	uint64_t ist3;
	uint64_t ist4;
	uint64_t ist5;
	uint64_t ist6;
	uint64_t ist7;
	uint64_t res3;
	uint16_t res4;
	uint16_t iomb;
}__attribute__ ((packed));

struct task_state;
void tss_init (void);
struct task_state *tss_get (void);
void tss_update (struct thread *next);

#endif /* userprog/tss.h */
