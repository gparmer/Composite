#pragma once

#include <shared/cos_config.h>
#include <chal_config.h>

struct thread;
struct cap_vm_vmcb;
#ifdef CONFIG_VMX

struct vmx_vmcs {

	/* Hardware vmcs page per vcpu */
	void *vmcs;

	/* EPT page */
	void *ept_pml4_base;

	/* Hardware vlapic per vcpu */
	void *vapic;

	void *lapic_access;

	u64_t vpid;

	/* user needs to allocate a 4K page for io bitmap0 */
	void *io_bitmap_region0;
	/* user needs to allocate a 4K page for io bitmap1 */
	void *io_bitmap_region1;

	/*
	 * MSR load and store regions are 16B aligned arrays. Its size
	 * is set by the following msr counts. The maximum should not 
	 * exceed 512. This means, for each of the region, we need:
	 * 16B * 512 = 8192B. Thus, we need maximum 2 contiguous pages for each
	 * region. However, in reality, we probably don't need this many MSRs to
	 * be saved and restored by hardware automatically.
	 * 
	 * As a result, user are allowed to allocated each retion only a page, meaning
	 * just 256 entries.
	 */

	/* MSRs that are stored on vm exit and loaded on vm entry */	
	u8_t vm_exit_store_msr_count;
	/* user needs to allocate a page for this region */
	void *vm_exit_store_msr_region;

	/* the MSRs are loaded on vm exit */
	u8_t vm_exit_load_msr_count;
	/* user needs to allocate a page for this region */
	void *vm_exit_load_msr_region; 

	/*
	 * user needs to allocate a 4K page for this MSR bitmap region,
	 * this 4K page is then devided into 4 1KB retions that are used
	 * by hardware to map MSR load and store operations.
	 */
	void *msr_bitmap;

	u64_t guest_tsc_aux;
	u64_t host_tsc_aux;

	u64_t guest_msr_gs_base;
	u64_t guest_msr_gskernel_base;

	u64_t host_msr_gs_base;
	u64_t host_msr_gskernel_base;

	u64_t guest_star; 
	u64_t host_star;
	u64_t guest_lstar;
	u64_t host_lstar;
	u64_t guest_cstar;
	u64_t host_cstar;
	u64_t guest_fmask;
	u64_t host_fmask;
};

void vmx_env_init(void);
void vmx_thd_init(struct thread *thd, void *vm_pgd, struct cap_vm_vmcb *vmcb);
void vmx_host_state_init(void);
void vmx_guest_state_init(struct thread *thd);
void vmx_thd_start_or_resume(struct thread *thd);

#else
	struct vmx_vmcs {};
#endif
