#include "chal_asm_inc.h"

/* Composite pt_regs save/restore */
#define SAVE_REGS_GENERAL 	\
	pushq %rax;		\
	pushq %rbp;		\
	pushq %rdi;		\
	pushq %rsi;		\
	pushq %rdx;		\
	pushq %rcx;		\
	pushq %rbx;		\
	pushq %r8;		\
	pushq %r9;		\
	pushq %r10;		\
	pushq %r11;		\
	pushq %r12;		\
	pushq %r13;		\
	pushq %r14;		\
	pushq %r15;		\

#define SAVE_REGS_ALL 		\
	subq $0x30, %rsp;	\
	SAVE_REGS_GENERAL;	\
	subq $0x20, %rsp;	\

/* When return to user: ecx => sp, edx => ip. */
#define RESTORE_REGS_GENERAL	\
	popq %r15;		\
	popq %r14;		\
	popq %r13;		\
	popq %r12;		\
	popq %r11;		\
	popq %r10;		\
	popq %r9;		\
	popq %r8;		\
	popq %rbx;		\
	popq %rcx;		\
	popq %rdx;		\
	popq %rsi;		\
	popq %rdi;		\
	popq %rbp;		\
	popq %rax;		\

#define RESTORE_REGS_ALL	\
	addq $0x20, %rsp;	\
	RESTORE_REGS_GENERAL; 	\
	addq $30, %rsp

#define RET_TO_USER \
	movq %rbp, %rsp; \
	sysretq

/* The entire IPC path should be in __ipc_entry section. */
.section __ipc_entry, "ax"
.align 16
.globl sysenter_entry
sysenter_entry:
	swapgs
	movq %gs:KERNEL_STACK_OFFSET, %rsp
	SAVE_REGS_ALL
	movq %rsp, %rdi /* pt_reg */
	call composite_syscall_handler

	swapgs
	testq %rax, %rax
	jne restore_from_thd

	RESTORE_REGS_ALL
	RET_TO_USER
/* we are changing thread contexts, reload all registers */

.align 16
.globl restore_from_vm
restore_from_vm:
	swapgs
	testq %rax, %rax
	jne restore_from_thd

	RESTORE_REGS_ALL
	RET_TO_USER

/* on restoring path, only the %ds will be taken care of. */
.align 16
restore_from_thd:
	/* %ds is constant, and %es, %fs, %gs are not used because they cannot be modified by user space and kernel also does not modify them, thus we just add 0x20 to %rsp */
	addq $0x20, %rsp
	/* user space will only use one constant %ds selector, thus we don't push/pop it, instead we just set the value in order to save some cycles. */
	movq $(SEL_UDSEG), %rax
	movq %rax, %ds
	RESTORE_REGS_GENERAL

	addq $8, %rsp

	sti
	iretq

/* %ds, %es, %fs, %gs are all ingored when saving. */
#define IRQPROC(fn)  \
	SAVE_REGS_GENERAL; 	\
	subq $0x20, %rsp;	\
	movq $(SEL_KDSEG), %rax;\
	movq %rax, %ds;		\
	movq %rsp, %rdi; 	\
	call fn;		\
	testq %rax, %rax;	\
	jne restore_from_thd;	\
	RESTORE_REGS_ALL;	\
	RET_TO_USER

/*
 * Convention:
 * C handler is IRQHANDLER_handler, and the irq assembly
 * routine is IRQHANDLER_irq.
 */
#define IRQ(fn)		 	\
.align 16;			\
.global fn##_irq;		\
fn##_irq: 			\
	cli; 			\
	push $0;  		\
	IRQPROC(fn##_handler)

#define IRQ_CODE(fn)		\
.align 16;			\
.global fn##_irq;		\
fn##_irq: 			\
	cli; 			\
	IRQPROC(fn##_handler)

#define IRQ_ID(ID)		\
.align 4;			\
.global handler_hw_##ID;	\
handler_hw_##ID:		\
	cli; 			\
	push $(ID);		\
	jmp irqproc

irqproc:
	IRQPROC(hw_handler)

.text
IRQ(div_by_zero_err_fault)
IRQ(debug_trap)
IRQ(breakpoint_trap)
IRQ(overflow_trap)
IRQ(bound_range_exceed_fault)
IRQ(invalid_opcode_fault)
IRQ(device_not_avail_fault)
IRQ_CODE(double_fault_abort)
IRQ_CODE(invalid_tss_fault)
IRQ_CODE(seg_not_present_fault)
IRQ_CODE(stack_seg_fault)
IRQ_CODE(gen_protect_fault)
IRQ_CODE(page_fault)
IRQ(x87_float_pt_except_fault)
IRQ_CODE(align_check_fault)
IRQ(machine_check_abort)
IRQ(simd_float_pt_except_fault)
IRQ(virtualization_except_fault)
IRQ_CODE(security_except_fault)

IRQ(periodic)
IRQ_ID(33)
IRQ_ID(34)
IRQ_ID(35)
IRQ(serial)
IRQ_ID(37)
IRQ_ID(38)
IRQ_ID(39)
IRQ(oneshot)
IRQ_ID(41)
IRQ_ID(42)
IRQ_ID(43)
IRQ_ID(44)
IRQ_ID(45)
IRQ_ID(46)
IRQ_ID(47)
IRQ_ID(48)
IRQ_ID(49)
IRQ_ID(50)
IRQ_ID(51)
IRQ_ID(52)
IRQ_ID(53)
IRQ_ID(54)
IRQ_ID(55)
IRQ_ID(56)
IRQ_ID(57)
IRQ_ID(58)
IRQ_ID(59)
IRQ_ID(60)
IRQ_ID(61)
IRQ_ID(62)
IRQ(lapic_spurious)
IRQ(lapic_ipi_asnd)
IRQ(lapic_timer)
IRQ(posted_intr)

/*
 * Loads the IDT into the processor
 */
.global idt_flush

idt_flush:
    movl 4(%esp), %eax
    lidt (%eax)
    ret
