#ifndef COS_CONFIG_H
#define COS_CONFIG_H

/***
 * Memory information.  Included are four sections:
 * - physical memory information (PA)
 * - virtual memory addresses (VA)
 * - resource table addresses to index memory resources (RTA)
 * - the maximum number of pages of the different types of memory.
 *   See BOOT_* in cos_types.h for this information
 *
 * These exist separately for kernel-accessible memory that can be
 * typed as either kernel or user virtual memory, and
 * kernel-inaccessible memory that can only be used as user virtual
 * memory.
 */

#include "cpu_ghz.h"

#define NUM_CPU_KERNEL 1

#ifndef NUM_CPU
#define NUM_CPU NUM_CPU_KERNEL
#endif

#define NUM_CPU_BMP_BYTES ((NUM_CPU + 7) / 8)
#define NUM_CPU_BMP_WORDS ((NUM_CPU_BMP_BYTES + 3) / 4)
/*
 * FIXME: The macro to set a portion of memory of the booter to super pages -
 * should be dynamically passed from kernel to userlevel!
 */
#define NUM_SUPERPAGES 139
#define MAX_USABLE_MEMORY 1700
/* FIXME: This is a hack - was 0xD800000, now expanded to 1200MB */
#define EXTRA_MEMORY ((MAX_USABLE_MEMORY - 512) << 20)
#define EXTRA_SUPERPAGES ((MAX_USABLE_MEMORY - 808) / 4)
#define TOTAL_SUPERPAGES (NUM_SUPERPAGES + EXTRA_SUPERPAGES - 1)

/*
 * 1 MB, note that this is not the PA of kernel-usable memory, instead
 * it is the PA of the kernel.  If you change this, update the kernel
 * linker script (.ld) as well.
 */
#define COS_MEM_KERN_PA (0x00100000)
#if defined(__x86_64__)
#define COS_MEM_KERN_PA_ORDER (33)
#else
#define COS_MEM_KERN_PA_ORDER (29)
#endif
#define COS_MEM_KERN_PA_SZ                                                                                          \
	((1UL << COS_MEM_KERN_PA_ORDER)                                                                             \
	 - (1UL << 26)) /* FIXME: Need a way to get physical memory size from kernel. Cannot use a hardcoded value, \
	                   actual memory could be much lower! */

#define COS_MEM_COMP_START_VA ((1 << 30) + (1 << 22)) /* 1GB + 4MB (a relic) */

#if defined(__x86_64__)
#define COS_MEM_KERN_HIGH_ADDR_VA_PGD_MASK 0x0000ff8000000000
#define COS_MEM_KERN_START_VA (0xffff800000000000) // COS_MEM_KERN_PA     /* currently, we don't do kernel relocation */
#define COS_MEM_USER_MAX_VA 0x00007fffffffffff
#else
#define COS_MEM_USER_MAX_VA (0xc0000000 - 1)
#define COS_MEM_KERN_START_VA (0xc0000000) // COS_MEM_KERN_PA     /* currently, we don't do kernel relocation */
#endif

#define COS_HW_MMIO_MAX_SZ (1UL << 27) /* Assuming a MAX of 128MB for MMIO. */
#if defined(__x86_64__)
#define COS_PHYMEM_MAX_SZ ((1UL << 35) - (1UL << 22) - COS_HW_MMIO_MAX_SZ) /* 1GB - 4MB - MMIO sz */
#define COS_PHYMEM_END_PA ((1UL << 35) - COS_HW_MMIO_MAX_SZ)               /* Maximum usable physical memory */
#else
#define COS_PHYMEM_MAX_SZ ((1UL << 30) - (1UL << 22) - COS_HW_MMIO_MAX_SZ) /* 1GB - 4MB - MMIO sz */
#define COS_PHYMEM_END_PA ((1UL << 30) - COS_HW_MMIO_MAX_SZ)               /* Maximum usable physical memory */
#endif


#define BOOT_COMP_MAX_SZ (1 << 24) /* 16 MB for the booter component */

#define CPU_TIMER_FREQ 100 // set in your linux .config

#define RUNTIME 3 // seconds

/* The kernel quiescence period = WCET in Kernel + WCET of a CAS. */
#define KERN_QUIESCENCE_PERIOD_US 500
#define KERN_QUIESCENCE_CYCLES (KERN_QUIESCENCE_PERIOD_US * 4000)
#define TLB_QUIESCENCE_CYCLES (4000 * 1000 * (1000 / CPU_TIMER_FREQ))

// After how many seconds should schedulers print out their information?
#define SCHED_PRINTOUT_PERIOD 100000
#define COMPONENT_ASSERTIONS 1 // activate assertions in components?

/* Optional CPU features */
// #define MPK_ENABLED

#define FPU_ENABLED 1
#define FPU_SUPPORT_SSE 1
#define FPU_SUPPORT_FXSR 1 /* >0 : CPU supports FXSR. */
#define FPU_SUPPORT_XSAVE 1
#define FPU_SUPPORT_XSAVEOPT 1
#define FPU_SUPPORT_XSAVEC 1
#define FPU_SUPPORT_XSAVES 1

/* the CPU that does initialization for Composite */
#define INIT_CORE 0
#define NUM_CPU_COS (NUM_CPU > 1 ? NUM_CPU - 1 : 1)

/* Composite user memory uses physical memory above this. */
#define COS_MEM_START COS_MEM_KERN_PA

/* NUM_CPU_SOCKETS defined in cpu_ghz.h. The information is used for
 * intelligent IPI distribution. */
#define NUM_CORE_PER_SOCKET (NUM_CPU / NUM_CPU_SOCKETS)

// cos kernel settings
#define COS_PRINT_MEASUREMENTS 1
#define COS_PRINT_SCHED_EVENTS 1
#define COS_ASSERTIONS_ACTIVE 1

/*** Console and output options ***/
/*
 * Notes: If you are using composite as high priority and no idle to
 * linux, then the shell output will not appear until the Composite
 * system has exited.  Thus, you will want to make the memory size
 * large enough to buffer _all_ output.  Note that currently
 * COS_PRINT_MEM_SZ should not exceed around (1024*1024*3).
 *
 * If you have COS_PRINT_SHELL, you _will not see output_ unless you
 * run
 * $~/transfer/print
 * after
 * # make
 * but before the runscript.
 */
/* print out to the shell? */
#define COS_PRINT_SHELL 1
/* how much should we buffer before sending an event to the shell? */
#define COS_PRINT_BUF_SZ 128
/* how large should the shared memory region be that will buffer print data? */
#define COS_PRINT_MEM_SZ (4096)

/* print out to dmesg? */
/* #define COS_PRINT_DMESG 1 */

/**
 * Configuration to enable/disable functionality in Kernel.
 */
#define ENABLE_SERIAL

#if defined(__x86_64__)

#define CONFIG_VMX 1

/* root page tbale is 0, then second level page table is 1, etc.*/
#define COS_PGTBL_DEPTH 4
#define COS_PGTBL_ORDER_PTE_3 12
#define COS_PGTBL_ORDER_PTE_2 21
#define COS_PGTBL_ORDER_PTE_1 30
#define COS_PGTBL_ORDER_PTE_0 39

/* Page sizes */
#define COS_PGTBL_NUM_ORDER 2
#define COS_PGTBL_ORDERS_64 COS_PGTBL_ORDER_PTE_3, COS_PGTBL_ORDER_PTE_2, COS_PGTBL_ORDER_PTE_1, COS_PGTBL_ORDER_PTE_0
#define COS_PGTBL_ORDER2POS_64 /* 0/1B    1/2B    2/4B    3/8B   4/16B   5/32B   6/64B  7/128B  8/256B  9/512B */ \
	-1, -1, -1, -1, -1, -1, -1, -1, -1,                                                                       \
	  -1, /* 10/1K   11/2K   12/4K   13/8K  14/16K  15/32K  16/64K 17/128K 18/256K 19/512K */                 \
	  -1, -1, 4, -1, -1, -1, -1, -1, -1,                                                                      \
	  -1, /* 20/1M   21/2M   22/4M   23/8M  24/16M  25/32M  26/64M 27/128M 28/256M 29/512M */                 \
	  -1, 3, 1, -1, -1, -1, -1, -1, -1,                                                                       \
	  -1, /* 30/1G   31/2G  32/4G   33/8G   34/16G   35/32G   36/64G   37/128G   38/256G   39/512G */         \
	  2, -1, -1, -1, -1, -1, -1, -1, -1, 1

/* FIXME: we need to remove this x86_32 pgtbl definitions, now we keep it here simply because retype memory logic
 * heavily rely on it */
#define COS_PGTBL_ORDER_PTE 12
#define COS_PGTBL_ORDER_PGD 22

#define COS_PGTBL_ORDERS COS_PGTBL_ORDER_PTE, COS_PGTBL_ORDER_PGD
#define COS_PGTBL_ORDER2POS /* 0/1B    1/2B    2/4B    3/8B   4/16B   5/32B   6/64B  7/128B  8/256B  9/512B */ \
	-1, -1, -1, -1, -1, -1, -1, -1, -1,                                                                    \
	  -1, /* 10/1K   11/2K   12/4K   13/8K  14/16K  15/32K  16/64K 17/128K 18/256K 19/512K */              \
	  -1, -1, 0, -1, -1, -1, -1, -1, -1,                                                                   \
	  -1, /* 20/1M   21/2M   22/4M   23/8M  24/16M  25/32M  26/64M 27/128M 28/256M 29/512M */              \
	  -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, /* 30/1G   31/2G */                                           \
	  -1, -1

/* PTE user pagetable modifiable flags */
#define COS_PAGE_READABLE (0)
#define COS_PAGE_WRITABLE (1ul << 1)
#define COS_PAGE_PKEY0 (1ul << 59)
#define COS_PAGE_PKEY1 (1ul << 60)
#define COS_PAGE_PKEY2 (1ul << 61)
#define COS_PAGE_PKEY3 (1ul << 62)
#define COS_PAGE_XDISABLE (1ul << 63)

#elif defined(__i386__)
#define COS_PGTBL_DEPTH 2
#define COS_PGTBL_ORDER_PTE 12
#define COS_PGTBL_ORDER_PGD 22

/* Page sizes */
#define COS_PGTBL_NUM_ORDER 2
#define COS_PGTBL_ORDERS COS_PGTBL_ORDER_PTE, COS_PGTBL_ORDER_PGD
#define COS_PGTBL_ORDER2POS /* 0/1B    1/2B    2/4B    3/8B   4/16B   5/32B   6/64B  7/128B  8/256B  9/512B */ \
	-1, -1, -1, -1, -1, -1, -1, -1, -1,                                                                    \
	  -1, /* 10/1K   11/2K   12/4K   13/8K  14/16K  15/32K  16/64K 17/128K 18/256K 19/512K */              \
	  -1, -1, 0, -1, -1, -1, -1, -1, -1,                                                                   \
	  -1, /* 20/1M   21/2M   22/4M   23/8M  24/16M  25/32M  26/64M 27/128M 28/256M 29/512M */              \
	  -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, /* 30/1G   31/2G */                                           \
	  -1, -1                                 /* PTE user modifiable flags */
#define COS_PAGE_READABLE (0)
#define COS_PAGE_WRITABLE (1ul << 1)

#endif
#endif /* COS_CONFIG_H */
