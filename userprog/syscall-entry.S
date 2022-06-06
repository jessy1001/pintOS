#include "threads/loader.h"

.text
.globl syscall_entry
.type syscall_entry, @function
syscall_entry: /* save user registers in interrupt frame*/
	movq %rbx, temp1(%rip)
	movq %r12, temp2(%rip)     /* callee saved registers */
	movq %rsp, %rbx            /* Store userland rsp    */
	movabs $tss, %r12 /* 포인터 저장 */
	movq (%r12), %r12 /* 내용 저장 */
	movq 4(%r12), %rsp /* tss에 들어있는 rsp0(kernel stack pointer) -> rsp에 저장 Read ring0 rsp from the tss */
	/* 여기부터 kernel mode!!!!! Now we are in the kernel stack */
	push $(SEL_UDSEG)      /* if->ss */
	push %rbx              /* if->rsp */ /*유저스택탑 저장!!! */
	push %r11              /* if->eflags */
	push $(SEL_UCSEG)      /* if->cs */
	push %rcx              /* if->rip */
	subq $16, %rsp         /* skip error_code, vec_no */
	push $(SEL_UDSEG)      /* if->ds */
	push $(SEL_UDSEG)      /* if->es */
	push %rax
	movq temp1(%rip), %rbx
	push %rbx
	pushq $0
	push %rdx
	push %rbp
	push %rdi
	push %rsi
	push %r8
	push %r9
	push %r10
	pushq $0 /* skip r11 */
	movq temp2(%rip), %r12
	push %r12
	push %r13
	push %r14
	push %r15
	movq %rsp, %rdi

check_intr:
	btsq $9, %r11          /* Check whether we recover the interrupt */
	jnb no_sti
	sti                    /* restore interrupt */
no_sti:
	movabs $syscall_handler, %r12
	call *%r12
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rsi
	popq %rdi
	popq %rbp
	popq %rdx
	popq %rcx
	popq %rbx
	popq %rax
	addq $32, %rsp /*위 값들이 다 pop하면서 stack pointer가 위로 올라감 */
	popq %rcx              /* if->rip */
	addq $8, %rsp
	popq %r11              /* if->eflags */
	popq %rsp              /* if->rsp */ /*유저 스택탑을 가리키게 복귀!!! */
	sysretq /* 이거 호출한 애로 돌아감*/

.section .data
.globl temp1
temp1:
.quad	0
.globl temp2
temp2:
.quad	0
