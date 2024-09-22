#include <consts.h>

#define DPDK_STACK_SZ_BYTE_ORDER 15
#define DPDK_THD_STACK_SZ (1<<DPDK_STACK_SZ_BYTE_ORDER)

.bss;
.align COS_STACK_SZ;
.globl dpdk_static_stack;
dpdk_static_stack:
	.rep (DPDK_THD_STACK_SZ * MAX_NUM_THREADS);
	.byte 0	;
	.endr ;

.text;
.globl custom_acquire_stack;
.type custom_acquire_stack, @function;
.align 16;
custom_acquire_stack:
	/* ax holds cpuid and thread id */
	/* rax[0:15]=tid, rax[16:31]=cpuid */
	movq %rax, %rdx;
	movabs $dpdk_static_stack, %rsp;
	/* rax hols coreid and thread id, do not use other registers! */
	/* get the tid by masking rax[0:15] */
	andq $0xffff, %rax;
	/* simple math: this thread's stack offset = stack_size * tid */
	shl $DPDK_STACK_SZ_BYTE_ORDER, %rax;
	/* add the stack offset to the base to get the current thread's stack*/
	add %rax, %rsp;
	/* restore the tid in order to save it on the stack*/
	shr $DPDK_STACK_SZ_BYTE_ORDER, %rax;
	/* get the cpuid by right shifting the lower 16 bits*/
	shr $16, %rdx;
	/* on the return, rax is thread id, rdx is core id */
	jmpq %rcx;
