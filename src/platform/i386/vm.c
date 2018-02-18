#include <cc.h>
#include <pgtbl.h>
#include <thd.h>

#include "kernel.h"
#include "string.h"
#include "isr.h"
#include "chal_cpu.h"
#include "mem_layout.h"

#define LARGE_BSS __attribute__((section(".largebss,\"aw\",@nobits#")))

struct tlb_quiescence tlb_quiescence[NUM_CPU] CACHE_ALIGNED LARGE_BSS;
struct liveness_entry __liveness_tbl[LTBL_ENTS] CACHE_ALIGNED LARGE_BSS;

#define KERN_INIT_PGD_IDX (COS_MEM_KERN_START_VA >> PGD_SHIFT)
u32_t boot_comp_pgd[PAGE_SIZE / sizeof(u32_t)] PAGE_ALIGNED = {[0] = 0 | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER,
                                                               [KERN_INIT_PGD_IDX] = 0 | PGTBL_PRESENT | PGTBL_WRITABLE
                                                                                     | PGTBL_SUPER};

void
kern_retype_initial(void)
{
	u8_t *k;

	assert((int)mem_bootc_start() % RETYPE_MEM_NPAGES == 0);
	assert((int)mem_bootc_end() % RETYPE_MEM_NPAGES == 0);
	for (k = mem_bootc_start(); k < mem_bootc_end(); k += PAGE_SIZE * RETYPE_MEM_NPAGES) {
		if (retypetbl_retype2user((void *)(chal_va2pa(k)))) assert(0);
	}
}

u8_t *mem_boot_alloc(int npages) /* boot-time, bump-ptr heap */
{
	u8_t *        r = glb_memlayout.kern_boot_heap;
	unsigned long i;

	assert(glb_memlayout.allocs_avail);

	glb_memlayout.kern_boot_heap += npages * (PAGE_SIZE / sizeof(u8_t));
	assert(glb_memlayout.kern_boot_heap <= mem_kmem_end());
	for (i = (unsigned long)r; i < (unsigned long)glb_memlayout.kern_boot_heap; i += PAGE_SIZE) {
		if ((unsigned long)i % RETYPE_MEM_NPAGES == 0) {
			if (retypetbl_retype2kern((void *)chal_va2pa((void *)i))) {
				die("Retyping to kernel on boot-time heap allocation failed @ 0x%x.\n", i);
			}
		}
	}

	memset((void *)r, 0, npages * (PAGE_SIZE / sizeof(u8_t)));

	return r;
}

static unsigned long vm_pgd_idx = COS_MEM_KERN_START_VA / PGD_RANGE;

int
vm_map_superpage(u32_t addr)
{
	int idx = vm_pgd_idx;
	u32_t page;
	
	page = round_to_pgd_page(addr);
	boot_comp_pgd[idx] = page | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL;
	vm_pgd_idx ++;

	return idx;
}

int
kern_setup_image(void)
{
	unsigned long i, j;
	paddr_t       kern_pa_start, kern_pa_end;

	printk("\tSetting up initial page directory.\n");
	kern_pa_start = round_to_pgd_page(chal_va2pa(mem_kern_start())); /* likely 0 */
	kern_pa_end   = chal_va2pa(mem_kmem_end());
	/* ASSUMPTION: The static layout of boot_comp_pgd is identical to a pgd post-pgtbl_alloc */
	/* FIXME: should use pgtbl_extend instead of directly accessing the pgd array... */
	for (i = kern_pa_start, j = COS_MEM_KERN_START_VA / PGD_RANGE;
	     i < (unsigned long)round_up_to_pgd_page(kern_pa_end); i += PGD_RANGE, j++) {
		assert(j != KERN_INIT_PGD_IDX
		       || ((boot_comp_pgd[j] | PGTBL_GLOBAL) & ~(PGTBL_MODIFIED | PGTBL_ACCESSED))
		            == (i | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL));
		boot_comp_pgd[j]             = i | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL;
		boot_comp_pgd[i / PGD_RANGE] = 0; /* unmap lower addresses */
	}

	vm_pgd_idx = j;

	/* FIXME: Ugly hack to get the physical page with the ACPI RSDT mapped */
	printk("ACPI initialization\n");
	void *rsdt = acpi_find_rsdt();
	if (rsdt) {
		u32_t lapic, page;
		u64_t hpet;

		page             = round_up_to_pgd_page(rsdt) - (1 << 22);
		acpi_set_rsdt_page(vm_map_superpage(page));

		hpet = hpet_find(acpi_find_hpet());
		if (hpet) hpet_set_page(vm_map_superpage(hpet));

		/* lapic memory map */
		lapic = lapic_find_localaddr(acpi_find_apic());
		if (lapic) lapic_set_page(vm_map_superpage(lapic));
	}

	j = vm_pgd_idx;
	for (; j < PAGE_SIZE / sizeof(unsigned int); i += PGD_RANGE, j++) {
		boot_comp_pgd[j] = boot_comp_pgd[i / PGD_RANGE] = 0;
	}

	chal_cpu_init();
	chal_cpu_pgtbl_activate((pgtbl_t)chal_va2pa(boot_comp_pgd));

	kern_retype_initial();

	return 0;
}

void
kern_paging_map_init(void *pa)
{
	unsigned long i, j;
	paddr_t       kern_pa_start = 0, kern_pa_end = (paddr_t)pa;

	for (i = kern_pa_start, j = COS_MEM_KERN_START_VA / PGD_RANGE;
	     i < (unsigned long)round_up_to_pgd_page(kern_pa_end); i += PGD_RANGE, j++) {
		assert(j != KERN_INIT_PGD_IDX
		       || ((boot_comp_pgd[j] | PGTBL_GLOBAL) & ~(PGTBL_MODIFIED | PGTBL_ACCESSED))
		            == (i | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL));
		/* lower mapping */
		boot_comp_pgd[i / PGD_RANGE] = i | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL;
		/* higher mapping */
		boot_comp_pgd[j] = i | PGTBL_PRESENT | PGTBL_WRITABLE | PGTBL_SUPER | PGTBL_GLOBAL;
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
