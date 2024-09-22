#include <chal_cpu.h>
#include <thd.h>
#include <cpuid.h>
#include <chal_asm_inc.h>
#include <vm.h>
#include <vmx.h>
#include <vmx_msr.h>
#include <vmx_logging.h>
#include <vmx_exit.h>
#include <vmx_utils.h>
#include <vmx_vmcs.h>

extern u64_t get_idt_base(void);
extern u64_t get_tss_base(cpuid_t cpu_id);

static inline u64_t get_fs_base(void) { return msr_get(IA32_FS_BASE); }
static inline u64_t get_gs_base(void){ return msr_get(IA32_GS_BASE); }
static inline u64_t get_efer(void) { return msr_get(IA32_EFER); }
static inline struct vmx_vmcs *get_vmcs(struct vm_vcpu_context *vcpu_ctx) { return &vcpu_ctx->vmcs; }

u64_t cr4_fixed1_bits = 0;
u64_t cr4_fixed0_bits = 0;
u64_t cr0_fixed1_bits = 0;
u64_t cr0_fixed0_bits = 0;

/* Note: this page is just used for enabling cpu vm capability, it doesn't relate to vcpu VMCS pages */
static char vm_env_page[PAGE_SIZE_4K] __attribute__((aligned(PAGE_SIZE_4K)));

void
vmx_env_init(void)
{
	assert(sizeof(struct vm_vcpu_shared_region) < PAGE_SIZE_4K);
	memset(&vm_env_page, 0, PAGE_SIZE_4K);
	vmx_on(&vm_env_page);
}

void
vmx_host_state_init(void)
{
	u64_t tmp64;
	u32_t eax, edx;

	CR_GET(cr0, &tmp64);
	vmwrite(HOST_CR0, tmp64);
	VMX_DEBUG("VMX_HOST_CR0: 0x%p\n", tmp64);

	CR_GET(cr3, &tmp64);
	vmwrite(HOST_CR3, tmp64);
	VMX_DEBUG("VMX_HOST_CR3: 0x%p\n", tmp64);

	CR_GET(cr4, &tmp64);
	vmwrite(HOST_CR4, tmp64);
	VMX_DEBUG("VMX_HOST_CR4: 0x%p\n", tmp64);

	/* The sp and ip used when VM-exit */
	vmwrite(HOST_RSP, (u64_t)kernel_stack_info[get_cpuid()].kernel_stack_addr);
	vmwrite(HOST_RIP, (u64_t)&vmx_exit_handler_asm);
	
	vmwrite(HOST_DS, SEL_KDSEG);
	vmwrite(HOST_ES, SEL_KDSEG);
	vmwrite(HOST_FS, SEL_KDSEG);
	vmwrite(HOST_GS, SEL_KDSEG);
	vmwrite(HOST_TR, SEL_TSS);
	vmwrite(HOST_FS_BASE, get_fs_base());
	vmwrite(HOST_GS_BASE, get_gs_base());
	vmwrite(HOST_TR_BASE, get_tss_base(get_cpuid()));

	vmwrite(HOST_SS, SEL_KDSEG);
	vmwrite(HOST_CS, SEL_KCSEG);
	vmwrite(HOST_IDTR_BASE, get_idt_base());
	vmwrite(HOST_GDTR_BASE, get_gdt_base());

	vmwrite(HOST_IA32_SYSENTER_CS, 0x0);
	vmwrite(HOST_IA32_SYSENTER_ESP, 0x0);
	vmwrite(HOST_IA32_SYSENTER_EIP, 0x0);

	vmwrite(HOST_IA32_EFER, get_efer());
	vmwrite(HOST_IA32_PAT, msr_get(IA32_PAT));
}

void
vmx_guest_state_init(struct thread *thd)
{
	/* Initializing guest state, this will set guest into real mode */
	u64_t tmp64;

	vmwrite(GUEST_ES, 0x0);
	vmwrite(GUEST_CS, 0x0);
	vmwrite(GUEST_DS, 0x0);
	vmwrite(GUEST_FS, 0x0);
	vmwrite(GUEST_GS, 0x0);
	vmwrite(GUEST_SS, 0x0);
	vmwrite(GUEST_TR, 0x0);
	vmwrite(GUEST_LDTR, 0x0);

	vmwrite(GUEST_CS_BASE, 0x0);
	vmwrite(GUEST_DS_BASE, 0x0);
	vmwrite(GUEST_ES_BASE, 0x0);
	vmwrite(GUEST_FS_BASE, 0x0);
	vmwrite(GUEST_GS_BASE, 0x0);
	vmwrite(GUEST_SS_BASE, 0x0);
	vmwrite(GUEST_LDTR_BASE, 0x0);
	vmwrite(GUEST_IDTR_BASE, 0x0);
	vmwrite(GUEST_GDTR_BASE, 0x0);
	vmwrite(GUEST_TR_BASE, 0x0);

	vmwrite(GUEST_CS_LIMIT, 0xFFFF);
	vmwrite(GUEST_DS_LIMIT, 0xFFFF);
	vmwrite(GUEST_ES_LIMIT, 0xFFFF);
	vmwrite(GUEST_FS_LIMIT, 0xFFFF);
	vmwrite(GUEST_GS_LIMIT, 0xFFFF);
	vmwrite(GUEST_SS_LIMIT, 0xFFFF);
	vmwrite(GUEST_LDTR_LIMIT, 0xFFFF);
	vmwrite(GUEST_TR_LIMIT, 0xFFFF);
	vmwrite(GUEST_GDTR_LIMIT, 0xFFFF);
	vmwrite(GUEST_IDTR_LIMIT, 0xFFFF);

	#define DATA_ACCESS_RIGHT (0x3 | 1 << 4 | 1 << 7)
	#define CODE_ACCESS_RIGHT (0x3 | 1 << 4 | 1 << 7 | 1 << 13)
	#define LDTR_ACCESS_RIGHT (0x2 | 1 << 7)
	#define TR_ACCESS_RIGHT (0xB | 1 << 7)
	vmwrite(GUEST_CS_ACCESS_RIGHTS, CODE_ACCESS_RIGHT);
	vmwrite(GUEST_DS_ACCESS_RIGHTS, DATA_ACCESS_RIGHT);
	vmwrite(GUEST_ES_ACCESS_RIGHTS, DATA_ACCESS_RIGHT);
	vmwrite(GUEST_FS_ACCESS_RIGHTS, DATA_ACCESS_RIGHT);
	vmwrite(GUEST_GS_ACCESS_RIGHTS, DATA_ACCESS_RIGHT);
	vmwrite(GUEST_SS_ACCESS_RIGHTS, DATA_ACCESS_RIGHT);
	vmwrite(GUEST_LDTR_ACCESS_RIGHTS, LDTR_ACCESS_RIGHT);
	vmwrite(GUEST_TR_ACCESS_RIGHTS, TR_ACCESS_RIGHT);

	vmwrite(GUEST_INTERRUPTIBILITY_STATE, 0x0);
	vmwrite(GUEST_ACTIVITY_STATE, 0x0);

	/* Needs to set the fixed bits as required, or the VM will not boot */
	tmp64 = msr_get(IA32_VMX_CR0_FIXED0);

	/* disable PE */
	tmp64 &= ~(1UL << 0); 
	/* disable PG */
	tmp64 &= ~(1UL << 31);

	cr0_fixed1_bits = tmp64;
	vmwrite(GUEST_CR0, cr0_fixed1_bits);
	VMX_DEBUG("cr0 fixed 1 bits: 0x%p\n", cr0_fixed1_bits);

	tmp64 = msr_get(IA32_VMX_CR0_FIXED1);
	cr0_fixed0_bits = tmp64;
	VMX_DEBUG("cr0 fixed 0 bits: 0x%p\n", cr0_fixed0_bits);

	vmwrite(CR0_MASK, cr0_fixed1_bits | (~cr0_fixed0_bits));
	vmwrite(CR0_READ_SHADOW, cr0_fixed1_bits);
	VMX_DEBUG("cr0 mask: 0x%p, read shadow: 0x%p\n",cr0_fixed1_bits | (~cr0_fixed0_bits), cr0_fixed1_bits);
	
	vmwrite(GUEST_CR3, 0x0);

	tmp64 = msr_get(IA32_VMX_CR4_FIXED0);
	cr4_fixed1_bits = tmp64;
	VMX_DEBUG("cr4 fixed 0 bits: 0x%p\n", cr4_fixed1_bits);

	tmp64 = msr_get(IA32_VMX_CR4_FIXED1);
	cr4_fixed0_bits = tmp64;
	VMX_DEBUG("cr4 fixed 1 bits: 0x%p\n", cr4_fixed0_bits);

	vmwrite(GUEST_CR4, cr4_fixed1_bits);
	vmwrite(CR4_READ_SHADOW, cr4_fixed1_bits);
	vmwrite(CR4_MASK, cr4_fixed1_bits | (~cr4_fixed0_bits));

	vmwrite(GUEST_DR7, 0x0);
	vmwrite(GUEST_RSP, 0x0);

	/* The initial guest ip will be at 0x1000 */
	vmwrite(GUEST_RIP, 0x1000); 

	vmwrite(GUEST_RFLAG, 0x2);

	/* Default value as required by manual */
	vmwrite(GUEST_VMCS_LINK_POINTER_FULL, 0XFFFFFFFF);
	vmwrite(GUEST_VMCS_LINK_POINTER_HIGH, 0XFFFFFFFF);

	vmwrite(GUEST_IA32_EFER, 0x0);

	/* set PAT the same as host */
	vmwrite(GUEST_IA32_PAT, msr_get(IA32_PAT));
}

void
vmx_pinbased_ctl_init(void)
{
	u32_t pinbased_execution_ctl = 0;

	pinbased_execution_ctl |= EXTERNAL_INTERRUPT_EXITING | PROCESS_POSTED_INTERRUPTS ;
	pinbased_execution_ctl = fix_reserved_ctrl_bits(IA32_VMX_PINBASED_CTLS, pinbased_execution_ctl);
	vmwrite(PIN_BASED_VM_EXECUTION_CONTROLS, pinbased_execution_ctl);
}

void
vmx_procbased_ctl_init(void)
{
	u32_t primary_procbased_ctls = 0;
	u32_t second_procbased_ctls = 0;

	primary_procbased_ctls =  HLT_EXITING | MWAIT_EXITING | RDPMC_EXITING | USE_TPR_SHADOW 
				| UNCONDITIONAL_IO_EXITING | USE_MSR_BITMAPS
				| PAUSE_EXITING | ACTIVATE_SECONDARY_CONTROLS;
	primary_procbased_ctls = fix_reserved_ctrl_bits(IA32_VMX_TRUE_PROCBASED_CTLS, primary_procbased_ctls);
	vmwrite(PRI_PROC_BASED_VM_EXECUTION_CONTROLS, primary_procbased_ctls);

	second_procbased_ctls =  VIRTUALIZE_APIC_ACCESSES | ENABLE_EPT | ENABLE_RDTSCP
				| ENABLE_VPID | UNRESTRICTED_GUEST | APIC_REGISTER_VIRTUALIZATION
				| VIRTUAL_INTERRUPT_DELIVERY | ENABLE_INVPCID
				| PAUSE_LOOP_EXITING | ENABLE_XSAVES_XRSTORS
				| ENABLE_USER_WAIT_AND_PAUSE;
	second_procbased_ctls = fix_reserved_ctrl_bits(IA32_VMX_PROCBASED_CTLS2, second_procbased_ctls);
	vmwrite(SEC_PROC_BASED_VM_EXECUTION_CONTROLS, second_procbased_ctls);
}

void
vmx_vm_exit_ctl_init(void)
{
	u32_t vm_exit_ctls = 0;

	vm_exit_ctls = HOST_ADDRESS_SPACE_SIZE | ACKNOWLEDGE_INTERRUPT_ON_EXIT
			| EXIT_SAVE_IA32_PAT | EXIT_LOAD_IA32_PAT
			| EXIT_SAVE_IA32_EFER | EXIT_LOAD_IA32_EFER;

	vm_exit_ctls = fix_reserved_ctrl_bits(IA32_VMX_EXIT_CTLS, vm_exit_ctls);
	vmwrite(PRIMARY_VM_EXIT_CONTROLS, vm_exit_ctls);
}

void
vmx_vm_entry_ctl_init(void)
{
	u32_t vm_entry_ctls = 0;

	vm_entry_ctls = ENTRY_LOAD_IA32_PAT | ENTRY_LOAD_IA32_EFER;
	vm_entry_ctls = fix_reserved_ctrl_bits(IA32_VMX_ENTRY_CTLS, vm_entry_ctls);
	vmwrite(VM_ENTRY_CONTROLS, vm_entry_ctls);

	vmwrite(VM_ENTRY_INTERRUPTION_INFORMATION_FIELD, 0x0);
}

void
vmx_msr_bitmaps_init(struct thread *thd)
{
	/* TODO: make this code more readable, this is fine now since it is not too long */
	struct vmx_vmcs *vmcs = &thd->vcpu_ctx.vmcs;

	memset(vmcs->msr_bitmap, 0xFF, PAGE_SIZE_4K);
	u8_t *read_low_msr = (u8_t *)vmcs->msr_bitmap; 
	u8_t *read_high_msr = (u8_t *)vmcs->msr_bitmap + 1024;
	u8_t *write_low_msr = (u8_t *)vmcs->msr_bitmap + 1024 * 2;
	u8_t *write_high_msr = (u8_t *)vmcs->msr_bitmap + 1024 * 3;

	/* Bypass IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GS_BASE, MSR_IA32_TSC_AUX */
	u8_t *r_fs_base = read_high_msr + 32;
	u8_t *w_fs_base = write_high_msr + 32;

	/* Bypass IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GS_BASE, MSR_IA32_TSC_AUX */
	*r_fs_base = 0XF0;
	*w_fs_base = 0XF0;

	u8_t *r_syscall_base = read_high_msr + 16;
	u8_t *w_syscall_base = write_high_msr + 16;
	*r_syscall_base = 0xE1;
	*w_syscall_base = 0xE1;

	/* Bypass MSR_IA32_ARCH_CAPABILITIES 0x10a, readonly */
	u8_t *r_arch_capabilities_base = read_low_msr + 33;
	u8_t *w_arch_capabilities_base = write_low_msr + 33;
	*r_arch_capabilities_base = 0XFB;

	vmcs->host_msr_gs_base = msr_get(IA32_GS_BASE);
	vmcs->host_msr_gskernel_base = msr_get(IA32_KERNEL_GSBASE);

	return;
}

static u64_t
get_microcode(void)
{
	/* Note: this will be a constant global value for VM */
	u64_t val;
	u32_t eax = 0, ebx = 0, ecx = 0, edx = 0;

	msr_set(IA32_BIOS_SIGN_ID, 0);
	eax = 1;
	ecx = 0;
	chal_cpuid(&eax, &ebx, &ecx, &edx);
	val = msr_get(IA32_BIOS_SIGN_ID);

	return val;
}

void
vmx_thd_state_init(struct thread *thd)
{
	struct vm_vcpu_shared_region *shared_region = thd->vm_vcpu_shared_region;

	/* Will never change the microcode later */
	shared_region->microcode_version = get_microcode();

	thd->vcpu_ctx.vmcs.host_tsc_aux = msr_get(IA32_TSC_AUX);
	thd->vcpu_ctx.vmcs.host_star = msr_get(IA32_STAR);
	thd->vcpu_ctx.vmcs.host_lstar = msr_get(IA32_LSTAR);
	thd->vcpu_ctx.vmcs.host_cstar = msr_get(IA32_CSTAR);
	thd->vcpu_ctx.vmcs.host_fmask = msr_get(IA32_FMASK);

	return;
}

void
vmx_thd_init(struct thread *thd, void *vm_pgd, struct cap_vm_vmcb *vmcb)
{
	u64_t eptp;
	struct vmx_vmcs *vmcs = get_vmcs(&thd->vcpu_ctx);
	void *vmcs_page = (void *)vmcb->vmcs->page;
	void *msr_bitmap = (void *)vmcb->msr_bitmap->page;
	void *lapic_access = (void *)vmcb->lapic_access->page;
	void *lapic = (void *)vmcb->lapic->page;
	void *shared_region = (void *)vmcb->shared_mem->page;
	u16_t vpid = vmcb->vpid;

	thd->vcpu_ctx.state = VM_THD_STATE_STOPPED;
	vmcs->ept_pml4_base = vm_pgd;

	memset(vmcs_page, 0, PAGE_SIZE_4K);
	memset(msr_bitmap, 0, PAGE_SIZE_4K);
	memset(lapic_access, 0, PAGE_SIZE_4K);
	memset(lapic, 0, PAGE_SIZE_4K);
	memset(shared_region, 0, PAGE_SIZE_4K);

	vmcs->vmcs = vmcs_page;

	*(u32_t *)vmcs_page = vmx_get_revision_id();
	load_vmcs(vmcs_page);
	VMX_DEBUG("VMCS PAGE: 0x%p\n", vmcs->vmcs);

	vmcs->vapic = lapic;
	vmwrite(VAPIC_ACCESS_ADDRESS, chal_va2pa(vmcs->vapic));
	VMX_DEBUG("VMCS VAPIC PAGE: 0x%p\n", vmcs->vapic);

	vmcs->msr_bitmap = msr_bitmap;
	vmwrite(MSR_BITMAPS_ADDRESS, chal_va2pa(vmcs->msr_bitmap));
	VMX_DEBUG("VMCS BITMAP PAGE: 0x%p\n", vmcs->msr_bitmap);

	vmcs->lapic_access = lapic_access;
	vmwrite(LAPIC_ACCESS_ADDRESS, chal_va2pa(vmcs->lapic_access));
	VMX_DEBUG("VMCS LAPIC ACCESS PAGE: 0x%p\n", vmcs->lapic_access);

	vmcs->vpid = vpid;
	vmwrite(VPID, vmcs->vpid);
	VMX_DEBUG("VMCS VPID: %u\n", vmcs->vpid);

	thd->vm_vcpu_shared_region = shared_region;
	thd->exception_handler = vmcb->handler_thd->t;

	/* TODO: Need to make this more readable, but this is fine now since the setting will never change, less likely to modify this */
	eptp = chal_va2pa(vmcs->ept_pml4_base);
	eptp |= 6;
	eptp |= (4 - 1) << 3;
	eptp |= 1 << 6;
	vmwrite(EPTP, eptp);

	vmwrite(POSTED_INTERRUPT_NOTIFICATION_VECTOR, HW_LAPIC_POSTED_INTR);
	vmwrite(POSTED_INTERRUPT_DESCRIPTOR, chal_va2pa(&((struct vm_vcpu_shared_region *)shared_region)->pi_desc));
}

static void
vmx_launch(void)
{
	#define _CARRY	0x1
	#define _ZERO	0x40

	u64_t flag, error;
	u8_t cf, zf;

	VMX_DEBUG("VMLAUNCH!\n");
	__asm__ volatile("vmlaunch; pushfq; popq %0;" :"=m"(flag)::"memory", "cc");

	cf = !!(flag & _CARRY);
	zf = !!(flag & _ZERO);

	error = vmread(VM_INSTRUCTION_ERROR);
	VMX_DEBUG("VMLAUNCH FAILED, cf: %u, zf: %u, error: %lu\n", cf, zf, error);

	/* TODO: handle error case when VM fails to launch */
	assert(0);
}

void
vmx_thd_start_or_resume(struct thread *thd)
{
	struct vmx_vmcs *vmcs = get_vmcs(&thd->vcpu_ctx);

	assert(thd->thd_type == THD_TYPE_VM);
	
	VMX_DEBUG("Starting or resuming VM thread: 0x%p, tid: %u, coreid:%u\n", thd, thd->tid, thd->cpuid);

	vmx_resume(thd);
	assert(thd->vcpu_ctx.state = VM_THD_STATE_STOPPED);

	vmx_host_state_init();
	vmx_guest_state_init(thd);
	vmx_pinbased_ctl_init();
	vmx_procbased_ctl_init();
	vmx_vm_exit_ctl_init();
	vmx_vm_entry_ctl_init();
	vmx_msr_bitmaps_init(thd);
	vmx_thd_state_init(thd);

	thd->vcpu_ctx.state = VM_THD_STATE_RUNNING;

	VMX_DEBUG("VMCS initialization done, begin to run the VM thread\n");
	vmx_launch();
}
