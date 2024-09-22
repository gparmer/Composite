#ifndef CHAL_CPU_H
#define CHAL_CPU_H

#include <pgtbl.h>
#include <thd.h>
#include <fpu.h>
#include "isr.h"
#include "tss.h"

typedef enum
{
	CR0_PE = 1 << 0,  /* Protected Mode Enable */
	CR0_MP = 1 << 1,  /* Monitor co-processor */
	CR0_EM = 1 << 2,  /* Emulation x87 FPU */
	CR0_TS = 1 << 3,  /* Task switched */
	CR0_ET = 1 << 4,  /* Extension type */
	CR0_NE = 1 << 5,  /* Numeric error */
	CR0_WP = 1 << 16, /* Write protect */
	CR0_AM = 1 << 18, /* Alignment mask */
	CR0_NW = 1 << 29, /* Not-write through */
	CR0_CD = 1 << 30, /* Cache disable */
	CR0_PG = 1 << 31  /* Paging */
} cr0_flags_t;

typedef enum
{
	CR4_TSD    = 1 << 2, /* time stamp (rdtsc) access at user-level disabled */
	CR4_PSE    = 1 << 4, /* page size extensions (superpages) */
	CR4_PGE    = 1 << 7, /* page global bit enabled */
	CR4_PCE    = 1 << 8, /* user-level access to performance counters enabled (rdpmc) */
	CR4_OSFXSR = 1 << 9, /* if set, enable SSE instructions and fast FPU save & restore, or using SSE instructions
	                        will cause #UD */
	CR4_OSXMMEXCPT = 1 << 10, /* Operating System Support for Unmasked SIMD Floating-Point Exceptions */
	CR4_FSGSBASE   = 1 << 16, /* user level fs/gs access permission bit */
	CR4_PCIDE      = 1 << 17, /* Process Context Identifiers Enable*/
	CR4_OSXSAVE    = 1 << 18, /* XSAVE and Processor Extended States Enable */
	CR4_SMEP       = 1 << 20, /* Supervisor Mode Execution Protection Enable */
	CR4_SMAP       = 1 << 21, /* Supervisor Mode Access Protection Enable */
	CR4_PKE        = 1 << 22  /* MPK Support */
} cr4_flags_t;

typedef enum
{
	XCR0 = 0, /* XCR0 register */
} xcr_regs_t;

typedef enum
{
	XCR0_x87 = 1 << 0, /* X87(must be 1) */
	XCR0_SSE = 1 << 1, /* SSE enable */
	XCR0_AVX = 1 << 2, /* AVX enable */
} xcr0_flags_t;

static inline word_t
chal_cpu_cr0_get(void)
{
	word_t config;
	asm volatile("mov %%cr0, %0" : "=r"(config));

	return config;
}

static inline void
chal_cpu_cr0_set(word_t config)
{
	asm volatile("mov %0, %%cr0" : : "r"(config));
}

static inline unsigned long
chal_cpu_cr4_get(void)
{
	unsigned long config;
#if defined(__x86_64__)
	asm volatile("movq %%cr4, %0" : "=r"(config));
#elif defined(__i386__)
	asm volatile("movl %%cr4, %0" : "=r"(config));
#endif

	return config;
}

static inline void
chal_cpu_cr4_set(cr4_flags_t flags)
{
	unsigned long config = chal_cpu_cr4_get();
	config |= (unsigned long)flags;
#if defined(__x86_64__)
	asm volatile("movq %0, %%cr4" : : "r"(config));
#elif defined(__i386__)
	asm volatile("movl %0, %%cr4" : : "r"(config));
#endif
}

static inline u64_t
chal_cpu_xgetbv(u32_t xcr_n)
{
	u32_t low, high;
	u64_t ret;

	asm volatile("xgetbv\n\t" : "=a"(low), "=d"(high) : "c"(xcr_n));

	ret = ((u64_t)high << 32) | low;
	return ret;
}

static inline void
chal_cpu_xsetbv(u32_t xcr_n, u64_t config)
{
	u32_t low, high;
	low  = (u32_t)config;
	high = config >> 32;

	asm volatile("xsetbv\n\t" ::"a"(low), "d"(high), "c"(xcr_n));
}

static inline void
chal_cpu_eflags_init(void)
{
	unsigned long val;

#if defined(__x86_64__)
	asm volatile("pushfq ; popq %0" : "=r"(val));
	val |= 3 << 12; /* iopl */
	asm volatile("pushq %0 ; popfq" : : "r"(val));
#elif defined(__i386__)
	asm volatile("pushf ; popl %0" : "=r"(val));
	val |= 3 << 12; /* iopl */
	asm volatile("pushl %0 ; popf" : : "r"(val));
#endif
}

static inline void
chal_cpu_pgtbl_activate(pgtbl_t pgtbl)
{
#if defined(__x86_64__)
	asm volatile("movq %0, %%cr3" : : "r"(pgtbl));
#elif defined(__i386__)
	asm volatile("mov %0, %%cr3" : : "r"(pgtbl));
#endif
}

#define MSR_IA32_SYSENTER_CS  0x174
#define MSR_IA32_SYSENTER_ESP 0x175
#define MSR_IA32_SYSENTER_EIP 0x176
#define MSR_PLATFORM_INFO 0x000000ce
#define MSR_APIC_BASE 0x1b
#define MSR_TSC_AUX 0xc0000103

#if defined(__x86_64__)
#define MSR_IA32_EFER 0xC0000080
#define MSR_STAR 0xC0000081
#define MSR_LSTAR 0xC0000082
#define MSR_SFMASK 0xC0000084

#define MSR_FSBASE 0xC0000100
#define MSR_USER_GSBASE 0xC0000101
#define MSR_KERNEL_GSBASE 0xC0000102
#endif

extern void sysenter_entry(void);

static inline void
writemsr(u32_t reg, u32_t low, u32_t high)
{
	__asm__ volatile("wrmsr" : : "c"(reg), "a"(low), "d"(high));
}

static inline void
readmsr(u32_t reg, u32_t *low, u32_t *high)
{
	__asm__ volatile("rdmsr" : "=a"(*low), "=d"(*high) : "c"(reg));
}

static inline void
chal_cpuid(u32_t *a, u32_t *b, u32_t *c, u32_t *d)
{
	asm volatile("cpuid" : "+a"(*a), "+b"(*b), "+c"(*c), "+d"(*d));
}

static inline void
chal_cpu_coreid_set(u32_t coreid)
{
	writemsr(MSR_TSC_AUX, coreid, 0x0u);
}

static void
chal_cpu_init(void)
{
	unsigned long cr4    = chal_cpu_cr4_get();
	cpuid_t       cpu_id = get_cpuid();

#if defined(__x86_64__)
	u32_t  low = 0, high = 0;
	u64_t  xcr0_config = 0;
	u32_t  a = 0, b = 0, c = 0, d = 0;
	word_t cr0;

	a = 0x1;
	chal_cpuid(&a, &b, &c, &d);

#ifdef MPK_ENABLED
	if (c & CR4_PKE) {
		printk("The CPU supports PKE, enabling...\n");
		cr4 |= CR4_PKE;
	} else {
		printk("ERROR: The CPU does not support MPK, but enabled in build system.\n");
		assert(0);
	}
#endif

	if (c & CR4_PCIDE) {
		cr4 |= CR4_PCIDE;
	} else {
		/*
		 * To address the issue where INVLPG may not properly
		 * flush Global entries on CPUs when PCIDs are enabled,
		 * Linux disabled PCID for certain Intel CPUs.
		 * Composite does not use INVLPG feature.
		 */
		printk("ERROR: PCID is not supported.\n");
		assert(0);
	}


	/* CR4_OSXSAVE has to be set to enable xgetbv/xsetbv */
	chal_cpu_cr4_set(cr4 | CR4_PSE | CR4_PGE | CR4_OSXSAVE);

	/* I'm not sure this is the best spot for this */
	assert(sizeof(struct ulk_invstk) == ULK_INVSTK_SZ);

	/* Check if the CPU support XSAVE and AVX */
	a = 0x01;
	c = 0;
	chal_cpuid(&a, &b, &c, &d);
	/* bit 26 is XSAVE, bit 28 is AVX */
	assert((c & (1 << 26)) && (c & (1 << 28)));
	/* Check if SSE3 and SSE4 is supported */
	assert((c & (1 << 0)) && (c & (1 << 9)) && (c & (1 << 19)) && (c & (1 << 20)));
	/* Check if AVX2 is supported */
	a = 0x07;
	c = 0;
	chal_cpuid(&a, &b, &c, &d);
	assert(b & (1 < 5));
	printk("The CPU supports SSE3, SSE4, AVX, AVX2 and XSAVE\n");

	/* Check if the CPU suppor XSAVEOPT, XSAVEC and XSAVES instructions*/
	a = 0x0d;
	c = 1;
	chal_cpuid(&a, &b, &c, &d);
	assert((a & (1 << 0)) && (a & (1 << 1)) && (a & (1 << 3)));
	printk("The CPU supports XSAVEOPT, XSAVEC and XSAVES instructions\n");

	/* Get the maximum size of XSAVE area of available XCR0 features */
	a = 0x0d;
	c = 0;
	chal_cpuid(&a, &b, &c, &d);
	assert(c > 0);
	printk("The CPU maximum XSAVE area is: %u\n", c);

	/* Check the AVX state component offset from the beginning of XSAVE Area*/
	a = 0x0d;
	c = 2;
	chal_cpuid(&a, &b, &c, &d);
	printk("The AVX area offset is: %u\n", b);

	/* Now enable SSE and AVX in XCR0, so that XSAVE features can be used */

	/* 1. Enable SSE */
	cr0 = chal_cpu_cr0_get();
	cr0 &= ~((word_t)(CR0_EM)); /* clear EM bit*/
	cr0 |= (word_t)(CR0_MP);    /* set MP bit */
	chal_cpu_cr0_set(cr0);
	chal_cpu_cr4_set(CR4_OSFXSR);

	/* 2. Enable AVX */
	xcr0_config = chal_cpu_xgetbv(XCR0);
	xcr0_config |= XCR0_x87 | XCR0_SSE | XCR0_AVX;
	chal_cpu_xsetbv(XCR0, xcr0_config);

	readmsr(MSR_IA32_EFER, &low, &high);
	writemsr(MSR_IA32_EFER, low | 0x1, high);

	writemsr(MSR_STAR, 0, SEL_KCSEG | ((SEL_UCSEG - 16) << 16));
	writemsr(MSR_LSTAR, (u32_t)((u64_t)sysenter_entry), (u32_t)((u64_t)sysenter_entry >> 32));
	writemsr(MSR_SFMASK, 512, 0);
	writemsr(MSR_USER_GSBASE, 0, 0);
	writemsr(MSR_KERNEL_GSBASE, (u32_t)((u64_t)(&kernel_stack_info[cpu_id])), (u32_t)((u64_t)(&kernel_stack_info[cpu_id]) >> 32));


#elif defined(__i386__)
	chal_cpu_cr4_set(cr4 | CR4_PSE | CR4_PGE);
	writemsr(MSR_IA32_SYSENTER_CS, SEL_KCSEG, 0);
	writemsr(MSR_IA32_SYSENTER_ESP, (u32_t)tss[cpu_id].esp0, 0);
	writemsr(MSR_IA32_SYSENTER_EIP, (u32_t)sysenter_entry, 0);
#endif

	fpu_init();
	chal_cpu_eflags_init();
	vm_env_init();
}

static inline vaddr_t
chal_cpu_fault_vaddr(struct pt_regs *r)
{
	vaddr_t fault_addr;
#if defined(__x86_64__)
	asm volatile("movq %%cr2, %0" : "=r"(fault_addr));
#elif defined(__i386__)
	asm volatile("mov %%cr2, %0" : "=r"(fault_addr));
#endif

	return fault_addr;
}

/* FIXME: I doubt these flags are really the same as the PGTBL_* macros */
static inline unsigned long
chal_cpu_fault_errcode(struct pt_regs *r)
{
	return r->orig_ax;
}

static inline unsigned long
chal_cpu_fault_ip(struct pt_regs *r)
{
	return r->ip;
}

static inline void
chal_user_upcall(void *ip, u16_t tid, u16_t cpuid)
{
#if defined(__x86_64__)
	/* rcx = user-level ip, r12 = option, rbx = arg, rax = tid + cpuid  */
	/* $0x3200 : enable interrupt, and iopl is set to 3, the same as user's CPL */
	__asm__("movq $0x3200, %%r11 ; mov %%rdx, %%ds ; movq %3, %%r12 ; sysretq"
	        :
	        : "c"(ip), "a"(tid | (cpuid << 16)), "d"(SEL_UDSEG), "i"(0), "b"(0));
#elif defined(__i386__)
	/* edx = user-level ip, ecx = option, ebx = arg, eax = tid + cpuid */
	__asm__ volatile("sti ; sysexit" : : "c"(0), "d"(ip), "b"(0), "a"(tid | (cpuid << 16)));
#endif
}

void chal_timer_thd_init(struct thread *t);

#endif /* CHAL_CPU_H */
