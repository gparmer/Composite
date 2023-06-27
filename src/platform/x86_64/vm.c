#include <compiler.h>
#include <pgtbl.h>
#include <thread.h>

//#include "kernel.h"
//#include "string.h"
//#include "isr.h"
#include <chal_cpu.h>
#include <chal_pgtbl.h>
#include <consts.h>
#include <arch_consts.h>

struct tlb_quiescence tlb_quiescence[COS_NUM_CPU] COS_CACHE_ALIGNED;

#define KERN_INIT_PGD_IDX ((COS_MEM_KERN_START_VA & COS_MEM_KERN_HIGH_ADDR_VA_PGD_MASK) >> (PGD_SHIFT))

u64_t boot_comp_pgd[COS_PAGE_SIZE / sizeof(u64_t)] COS_PAGE_ALIGNED = {0};

u64_t boot_comp_pgt1[COS_PAGE_SIZE / sizeof(u64_t)] COS_PAGE_ALIGNED = {0};

u64_t boot_ap_pgd[COS_PAGE_SIZE / sizeof(u64_t)] COS_PAGE_ALIGNED = {
	[0]                 = 0 | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE | X86_PGTBL_SUPER,
	[KERN_INIT_PGD_IDX] = 0 | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE | X86_PGTBL_SUPER,
};

int
kern_setup_image(void)
{
	u64_t i, j;
	paddr_t       kern_pa_start, kern_pa_end;
	int cpu_id = coreid();

	printk("\tSetting up initial page directory.\n");
	kern_pa_start = round_to_pgd_page(chal_va2pa(mem_kern_start())); /* likely 0 */
	kern_pa_end   = chal_va2pa(mem_kmem_end());
	/* ASSUMPTION: The static layout of boot_comp_pgd is identical to a pgd post-pgtbl_alloc */
	/* FIXME: should use pgtbl_extend instead of directly accessing the pgd array... */
	for (i = kern_pa_start; i < (unsigned long) round_up_to_pgt1_page(kern_pa_end); i += PGT1_RANGE, j++) {
		boot_comp_pgt1[i / PGT1_RANGE] = i | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE | X86_PGTBL_SUPER | X86_PGTBL_GLOBAL;
	}
	boot_comp_pgd[0] = 0; /* unmap lower addresses */

	kernel_mapped_offset = i / PGT1_RANGE;

	chal_cpu_init();
	chal_cpu_pgtbl_activate((pgtbl_t)chal_va2pa(boot_comp_pgd));
	kern_retype_initial();

	return 0;
}

/***
 * The device API for allocating virtual memory, and accessing the
 * device. Functions to map the memory, and to translate to virtual
 * addresses. As devices are often in high physical memory, these are
 * not the typical implementations, and require a simply
 * data-structure to track the mappings. We want to avoid memory
 * allocation (e.g. for PGD nodes) here, so we map super-pages worth
 * of memory. This uses a non-trivial amount of kernel virtual memory.
 *
 * Note that this is relevant for devices that the kernel needs to
 * access (timers, ACPI, LAPIC, etc...), and NOT the devices that are
 * accessed from user-level as the hardware capability provides that
 * mappings in a more conventional way.
 *
 * Thus, this is a simple implementation that assumes that we have
 * relatively few devices that require mapping. We also bound the
 * number of regions devoted to devices so that we fail fast if
 * something strange is configured.
 */

#define DEV_MAPS_MAX 16

int dev_map_off = 0;
struct dev_map {
	paddr_t physaddr;
	void   *virtaddr;
} dev_mem[DEV_MAPS_MAX];

void *
device_pa2va(paddr_t dev_addr)
{
	int i;

	for (i = 0; i < dev_map_off; i++) {
		paddr_t rounded = round_to_pgt1_page(dev_addr);
		if (round_to_pgt1_page(dev_mem[i].physaddr) == rounded) {
			return (char *)dev_mem[i].virtaddr + (dev_addr - rounded);
		}
	}

	return NULL;
}

/*
 * For a device mapped at a physical address, map it into virtual
 * memory and return the address. This is very wasteful of physical
 * memory as it uses PGD ranges (4MB) for the allocations. For 64-bit,
 * a PGT3 is used, ranges a 1GB for allocations, but that should be OK
 * since we have already mapped all physical memory address before this
 * step, the remaining slots in page tables are free to use.
 */
void *
device_map_mem(paddr_t dev_addr, unsigned int pt_extra_flags)
{
	paddr_t rounded;
	void   *vaddr;
	unsigned long off = kernel_mapped_offset;

	boot_state_assert(INIT_UT_MEM);
	vaddr = device_pa2va(dev_addr);
	if (vaddr) {
		boot_comp_pgt1[((unsigned long)vaddr - (unsigned long)(COS_MEM_KERN_START_VA)) / PGT1_RANGE] |= pt_extra_flags; /* use the union of the flags */

		return vaddr;
	}

	/* Allocate a PGD/PGT3 region, and map it in */
	assert(off < PAGE_SIZE / sizeof(unsigned long));
	rounded = round_to_pgt1_page(dev_addr);
	boot_comp_pgt1[off] = rounded | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE | X86_PGTBL_SUPER | X86_PGTBL_GLOBAL | pt_extra_flags;
	dev_mem[dev_map_off] = (struct dev_map) {
		.physaddr = rounded,
		.virtaddr = (void *)(off * PGT1_RANGE + COS_MEM_KERN_START_VA)
	};
	dev_map_off++;
	kernel_mapped_offset++;

	assert(((unsigned long)device_pa2va(dev_addr) & (PGT1_RANGE-1)) == (dev_addr & (PGT1_RANGE-1)));

	return device_pa2va(dev_addr);
}


void
kern_paging_map_init(void *pa)
{
	u64_t i = 0;
	paddr_t       kern_pa_start = 0, kern_pa_end = (paddr_t)pa;

	/* lower mapping */
	boot_comp_pgd[0] = (u64_t)chal_va2pa(&boot_comp_pgt1) | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE;
	/* higher mapping */
	boot_comp_pgd[KERN_INIT_PGD_IDX] = (u64_t)chal_va2pa(&boot_comp_pgt1) | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE;


	for (i = kern_pa_start; i < (unsigned long)round_up_to_pgt1_page(kern_pa_end); i += PGT1_RANGE) {
		boot_comp_pgt1[i / PGT1_RANGE] = i | X86_PGTBL_PRESENT | X86_PGTBL_WRITABLE | X86_PGTBL_SUPER | X86_PGTBL_GLOBAL;
	}
}


void
paging_init(void)
{
	int ret;

	printk("Initializing virtual memory\n");
	if ((ret = kern_setup_image())) {
		die("Could not set up kernel image, errno %d.\n", ret);
	}
}
