/*-
 * Copyright (c) 1989, 1990 William F. Jolitz
 * Copyright (c) 1990 The Regents of the University of California.
 * Copyright (c) 2017-2022 Intel Corporation.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)segments.h	7.1 (Berkeley) 5/9/91
 * $FreeBSD$
 */

#ifndef CPU_H
#define CPU_H
#include <stdint.h>
#include <stdbool.h>
#include <acrn_types.h>
#include <asm/msr.h>

/* Define CPU stack alignment */
#define CPU_STACK_ALIGN         16UL

/* CR0 register definitions */
#define CR0_PG                  (1UL<<31U)	/* paging enable */
#define CR0_CD                  (1UL<<30U)	/* cache disable */
#define CR0_NW                  (1UL<<29U)	/* not write through */
#define CR0_AM                  (1UL<<18U)	/* alignment mask */
#define CR0_WP                  (1UL<<16U)	/* write protect */
#define CR0_NE                  (1UL<<5U)	/* numeric error */
#define CR0_ET                  (1UL<<4U)	/* extension type */
#define CR0_TS                  (1UL<<3U)	/* task switched */
#define CR0_EM                  (1UL<<2U)	/* emulation */
#define CR0_MP                  (1UL<<1U)	/* monitor coprocessor */
#define CR0_PE                  (1UL<<0U)	/* protected mode enabled */

/* CR3 register definitions */
#define CR3_PWT                 (1UL<<3U)	/* page-level write through */
#define CR3_PCD                 (1UL<<4U)	/* page-level cache disable */

/* CR4 register definitions */
#define CR4_VME                 (1UL<<0U)	/* virtual 8086 mode extensions */
#define CR4_PVI                 (1UL<<1U)	/* protected mode virtual interrupts */
#define CR4_TSD                 (1UL<<2U)	/* time stamp disable */
#define CR4_DE                  (1UL<<3U)	/* debugging extensions */
#define CR4_PSE                 (1UL<<4U)	/* page size extensions */
#define CR4_PAE                 (1UL<<5U)	/* physical address extensions */
#define CR4_MCE                 (1UL<<6U)	/* machine check enable */
#define CR4_PGE                 (1UL<<7U)	/* page global enable */
#define CR4_PCE                 (1UL<<8U)
/* performance monitoring counter enable */
#define CR4_OSFXSR              (1UL<<9U)	/* OS support for FXSAVE/FXRSTOR */
#define CR4_OSXMMEXCPT          (1UL<<10U)
/* OS support for unmasked SIMD floating point exceptions */
#define CR4_UMIP                (1UL<<11U)	/* User-Mode Inst prevention */
#define CR4_LA57                (1UL<<12U)	/* 57-bit linear address */
#define CR4_VMXE                (1UL<<13U)	/* VMX enable */
#define CR4_SMXE                (1UL<<14U)	/* SMX enable */
#define CR4_FSGSBASE            (1UL<<16U)	/* RD(FS|GS|FS)BASE inst */
#define CR4_PCIDE               (1UL<<17U)	/* PCID enable */
/* XSAVE and Processor Extended States enable bit */
#define CR4_OSXSAVE             (1UL<<18U)
#define CR4_KL                  (1UL<<19U)      /* KeyLocker enable */
#define CR4_SMEP                (1UL<<20U)
#define CR4_SMAP                (1UL<<21U)
#define CR4_PKE                 (1UL<<22U)	/* Protect-key-enable */
#define CR4_CET                 (1UL<<23U)	/* Control-flow Enforcement Technology enable */
#define CR4_PKS                 (1UL<<24U)	/* Enable protection keys for supervisor-mode pages */

/* XCR0_SSE */
#define XCR0_SSE		(1UL<<1U)
/* XCR0_AVX */
#define XCR0_AVX		(1UL<<2U)
/* XCR0_BNDREGS */
#define XCR0_BNDREGS		(1UL<<3U)
/* XCR0_BNDCSR */
#define XCR0_BNDCSR		(1UL<<4U)
/* According to SDM Vol1 13.3:
 *   XCR0[63:10] and XCR0[8] are reserved. Executing the XSETBV instruction causes
 *   a general-protection fault if ECX = 0 and any corresponding bit in EDX:EAX
 *   is not 0.
 */
#define	XCR0_RESERVED_BITS	((~((1UL << 10U) - 1UL)) | (1UL << 8U))


/*
 * Entries in the Interrupt Descriptor Table (IDT)
 */
#define IDT_DE      0U   /* #DE: Divide Error */
#define IDT_DB      1U   /* #DB: Debug */
#define IDT_NMI     2U   /* Nonmaskable External Interrupt */
#define IDT_BP      3U   /* #BP: Breakpoint */
#define IDT_OF      4U   /* #OF: Overflow */
#define IDT_BR      5U   /* #BR: Bound Range Exceeded */
#define IDT_UD      6U   /* #UD: Undefined/Invalid Opcode */
#define IDT_NM      7U   /* #NM: No Math Coprocessor */
#define IDT_DF      8U   /* #DF: Double Fault */
#define IDT_FPUGP   9U   /* Coprocessor Segment Overrun */
#define IDT_TS      10U  /* #TS: Invalid TSS */
#define IDT_NP      11U  /* #NP: Segment Not Present */
#define IDT_SS      12U  /* #SS: Stack Segment Fault */
#define IDT_GP      13U  /* #GP: General Protection Fault */
#define IDT_PF      14U  /* #PF: Page Fault */
#define IDT_MF      16U  /* #MF: FPU Floating-Point Error */
#define IDT_AC      17U  /* #AC: Alignment Check */
#define IDT_MC      18U  /* #MC: Machine Check */
#define IDT_XF      19U  /* #XF: SIMD Floating-Point Exception */
#define IDT_VE      20U  /* #VE: Virtualization Exception */

/*Bits in EFER special registers */
#define EFER_LMA 0x00000400U    /* Long mode active (R) */

#define RFLAGS_C (1U<<0U)
#define RFLAGS_P (1U<<2U)
#define RFLAGS_A (1U<<4U)
#define RFLAGS_Z (1U<<6U)
#define RFLAGS_S (1U<<7U)
#define RFLAGS_O (1U<<11U)
#define RFLAGS_VM (1U<<17U)
#define RFLAGS_AC (1U<<18U)

/* CPU clock frequencies (FSB) */
#define CPU_FSB_83KHZ           83200
#define CPU_FSB_100KHZ          99840
#define CPU_FSB_133KHZ          133200
#define CPU_FSB_166KHZ          166400

/* Time conversions */
#define CPU_GHZ_TO_HZ           1000000000
#define CPU_GHZ_TO_KHZ          1000000
#define CPU_GHZ_TO_MHZ          1000
#define CPU_MHZ_TO_HZ           1000000
#define CPU_MHZ_TO_KHZ          1000


/* Number of GPRs saved / restored for guest in VCPU structure */
#define NUM_GPRS                            16U

#define XSAVE_STATE_AREA_SIZE			4096U
#define XSAVE_LEGACY_AREA_SIZE			512U
#define XSAVE_HEADER_AREA_SIZE			64U
#define XSAVE_EXTEND_AREA_SIZE			(XSAVE_STATE_AREA_SIZE - \
						XSAVE_HEADER_AREA_SIZE - \
						XSAVE_LEGACY_AREA_SIZE)
#define XSAVE_COMPACTED_FORMAT			(1UL << 63U)

#define XSAVE_FPU				(1UL << 0U)
#define XSAVE_SSE				(1UL << 1U)

#define	CPU_CONTEXT_OFFSET_RAX			0U
#define	CPU_CONTEXT_OFFSET_RCX			8U
#define	CPU_CONTEXT_OFFSET_RDX			16U
#define	CPU_CONTEXT_OFFSET_RBX			24U
#define	CPU_CONTEXT_OFFSET_RSP			32U
#define	CPU_CONTEXT_OFFSET_RBP			40U
#define	CPU_CONTEXT_OFFSET_RSI			48U
#define	CPU_CONTEXT_OFFSET_RDI			56U
#define	CPU_CONTEXT_OFFSET_R8			64U
#define	CPU_CONTEXT_OFFSET_R9			72U
#define	CPU_CONTEXT_OFFSET_R10			80U
#define	CPU_CONTEXT_OFFSET_R11			88U
#define	CPU_CONTEXT_OFFSET_R12			96U
#define	CPU_CONTEXT_OFFSET_R13			104U
#define	CPU_CONTEXT_OFFSET_R14			112U
#define	CPU_CONTEXT_OFFSET_R15			120U
#define	CPU_CONTEXT_OFFSET_CR0			128U
#define	CPU_CONTEXT_OFFSET_CR2			136U
#define	CPU_CONTEXT_OFFSET_CR4			144U
#define	CPU_CONTEXT_OFFSET_RIP			152U
#define	CPU_CONTEXT_OFFSET_RFLAGS		160U
#define	CPU_CONTEXT_OFFSET_IA32_SPEC_CTRL	168U
#define	CPU_CONTEXT_OFFSET_IA32_EFER		176U
#define	CPU_CONTEXT_OFFSET_EXTCTX_START		184U
#define	CPU_CONTEXT_OFFSET_CR3			184U
#define	CPU_CONTEXT_OFFSET_IDTR			192U
#define	CPU_CONTEXT_OFFSET_LDTR			216U

#ifndef ASSEMBLER

#define ALL_CPUS_MASK		((1UL << get_pcpu_nums()) - 1UL)
#define AP_MASK			(ALL_CPUS_MASK & ~(1UL << BSP_CPU_ID))

/**
 *
 * Identifiers for architecturally defined registers.
 *
 * These register names is used in condition statement.
 * Within the following groups,register name need to be
 * kept in order:
 * General register names group (CPU_REG_RAX~CPU_REG_R15);
 * Non general register names group (CPU_REG_CR0~CPU_REG_GDTR);
 * Segement register names group (CPU_REG_ES~CPU_REG_GS).
 */
enum cpu_reg_name {
	/* General purpose register layout should align with
	 * struct acrn_gp_regs
	 */
	CPU_REG_RAX,
	CPU_REG_RCX,
	CPU_REG_RDX,
	CPU_REG_RBX,
	CPU_REG_RSP,
	CPU_REG_RBP,
	CPU_REG_RSI,
	CPU_REG_RDI,
	CPU_REG_R8,
	CPU_REG_R9,
	CPU_REG_R10,
	CPU_REG_R11,
	CPU_REG_R12,
	CPU_REG_R13,
	CPU_REG_R14,
	CPU_REG_R15,

	CPU_REG_CR0,
	CPU_REG_CR2,
	CPU_REG_CR3,
	CPU_REG_CR4,
	CPU_REG_DR7,
	CPU_REG_RIP,
	CPU_REG_RFLAGS,
	/*CPU_REG_NATURAL_LAST*/
	CPU_REG_EFER,
	CPU_REG_PDPTE0,
	CPU_REG_PDPTE1,
	CPU_REG_PDPTE2,
	CPU_REG_PDPTE3,
	/*CPU_REG_64BIT_LAST,*/
	CPU_REG_ES,
	CPU_REG_CS,
	CPU_REG_SS,
	CPU_REG_DS,
	CPU_REG_FS,
	CPU_REG_GS,
	CPU_REG_LDTR,
	CPU_REG_TR,
	CPU_REG_IDTR,
	CPU_REG_GDTR
	/*CPU_REG_LAST*/
};

/**********************************/
/* EXTERNAL VARIABLES             */
/**********************************/

/* In trampoline range, hold the jump target which trampline will jump to */
extern uint64_t               main_entry[1];
extern uint64_t               secondary_cpu_stack[1];

/*
 * To support per_cpu access, we use a special struct "per_cpu_region" to hold
 * the pattern of per CPU data. And we allocate memory for per CPU data
 * according to multiple this struct size and pcpu number.
 *
 *   +-------------------+------------------+---+------------------+
 *   | percpu for pcpu0  | percpu for pcpu1 |...| percpu for pcpuX |
 *   +-------------------+------------------+---+------------------+
 *   ^                   ^
 *   |                   |
 *   <per_cpu_region size>
 *
 * To access per cpu data, we use:
 *   per_cpu_base_ptr + sizeof(struct per_cpu_region) * curr_pcpu_id
 *   + offset_of_member_per_cpu_region
 * to locate the per cpu data.
 */

/* Boot CPU ID */
#define BSP_CPU_ID             0U

/**
 *The invalid cpu_id (INVALID_CPU_ID) is error
 *code for error handling, this means that
 *caller can't find a valid physical cpu
 *or virtual cpu.
 */
#define INVALID_CPU_ID 0xffffU
/**
 *The broadcast id (BROADCAST_CPU_ID)
 *used to notify all valid phyiscal cpu
 *or virtual cpu.
 */
#define BROADCAST_CPU_ID 0xfffeU

struct descriptor_table {
	uint16_t limit;
	uint64_t base;
} __packed;

/* CPU states defined */
enum pcpu_boot_state {
	PCPU_STATE_RESET = 0U,
	PCPU_STATE_INITIALIZING,
	PCPU_STATE_RUNNING,
	PCPU_STATE_HALTED,
	PCPU_STATE_DEAD,
};

#define	NEED_OFFLINE		(1U)
#define	NEED_SHUTDOWN_VM	(2U)
void make_pcpu_offline(uint16_t pcpu_id);
bool need_offline(uint16_t pcpu_id);

struct segment_sel {
	uint16_t selector;
	uint64_t base;
	uint32_t limit;
	uint32_t attr;
};
#else /* ASSEMBLER defined */

#endif /* ASSEMBLER defined */

#endif /* CPU_H */
