#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <cos_debug.h>
#include <cos_types.h>
#include <llprint.h>
#include <cos_component.h>
#include <cos_kernel_api.h>
#include <capmgr.h>

#include <sched.h>
#include <vmrt.h>
#include <vmx_msr.h>

void
vmrt_dump_vcpu(struct vmrt_vm_vcpu *vcpu)
{
	struct vm_vcpu_shared_region *regs = vcpu->shared_region;

	printc("\tRAX: %016llx\tRBX: %016llx\tRCX: %016llx\tRDX: %016llx\n",
		regs->ax, regs->bx, regs->cx, regs->dx);
	printc("\tR8:  %016llx\tR9:  %016llx\tR10: %016llx\tR11: %016llx\n",
		regs->r8, regs->r9, regs->r10, regs->r11);
	printc("\tR12: %016llx\tR13: %016llx\tR14: %016llx\tR15: %016llx\n",
		regs->r12, regs->r13, regs->r14, regs->r15);
	printc("\tRSI: %016llx\tRDI: %016llx\tRBP: %016llx\n",
		regs->si, regs->di, regs->bp);

	printc("\tRIP: %016llx\tRSP: %016llx\tInst Len: %llu\n", regs->ip, regs->sp, regs->inst_length);
	printc("\tGPA: %016llx\n", regs->gpa);
	printc("\tEFER: %016llx\t\n", regs->efer);
	printc("\tCR0: %016llx\tCR2: %016llx\tCR3: %016llx\tCR4: %016llx\n", regs->cr0, regs->cr2, regs->cr3, regs->cr4);
}

paddr_t
vmrt_vm_gva2gpa(struct vmrt_vm_vcpu *vcpu, vaddr_t gva)
{
	struct vm_vcpu_shared_region *shared_region;
	u64_t cr3;
	u64_t *hva;
	u64_t paddr;
	u64_t l4, l3, l2, l1;
	u64_t l4_entry, l3_entry, l2_entry, l1_entry; 

	shared_region = vcpu->shared_region;

	cr3 = shared_region->cr3 & ~(u64_t)0xFFF;

	hva = GPA2HVA(cr3, vcpu->vm);

	l4 = PGTBL_LVL_4_IDX(gva);
	l3 = PGTBL_LVL_3_IDX(gva);
	l2 = PGTBL_LVL_2_IDX(gva);
	l1 = PGTBL_LVL_1_IDX(gva);

	l4_entry = hva[l4];

	assert(PGTBL_ENTRY_PRESENT(l4_entry));

	paddr = (l4_entry & PGTBL_ENTRY_ADDR_MASK);
	hva = GPA2HVA(paddr, vcpu->vm);
	l3_entry = hva[l3];

	assert(PGTBL_ENTRY_PRESENT(l3_entry));

	if (PGTBL_ENTRY_SUPER_PAGE(l3_entry)) {
		return (paddr_t)(l3_entry & PGTBL_ENTRY_ADDR_MASK) + (gva & 0x3FFFFFFF);
	}

	paddr = (l3_entry & PGTBL_ENTRY_ADDR_MASK);
	hva = GPA2HVA(paddr, vcpu->vm);
	l2_entry = hva[l2];

	assert(PGTBL_ENTRY_PRESENT(l2_entry));

	if (PGTBL_ENTRY_SUPER_PAGE(l2_entry)) {
		return (paddr_t)(l2_entry & PGTBL_ENTRY_ADDR_MASK) + (gva & 0x1FFFFF);
	}

	paddr = (l2_entry & PGTBL_ENTRY_ADDR_MASK);
	hva = GPA2HVA(paddr, vcpu->vm);
	l1_entry = hva[l1];

	assert(PGTBL_ENTRY_PRESENT(l1_entry));

	return (paddr_t)(l1_entry & PGTBL_ENTRY_ADDR_MASK) + (gva & 0xFFF);
}

void
vmrt_vmcs_page_create(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->vmcs_cap = capmgr_vm_vmcs_create();
}

void
vmrt_msr_bitmap_page_create(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->msr_bitmap_cap = capmgr_vm_msr_bitmap_create();
}

void
vmrt_lapic_page_create(struct vmrt_vm_vcpu *vcpu)
{
	vaddr_t page;

	vcpu->lapic_cap = capmgr_vm_lapic_create(&page);
	vcpu->lapic_page = (void *)page;
}

void
vmrt_shared_page_create(struct vmrt_vm_vcpu *vcpu)
{
	vaddr_t page;

	vcpu->shared_mem_cap = capmgr_vm_shared_region_create(&page);
	vcpu->shared_region = (struct vm_vcpu_shared_region *)page;
}

void
vmrt_lapic_access_page_create(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->lapic_access_cap = capmgr_vm_lapic_access_create(vcpu->vm->lapic_access_page);
}

void
vmrt_vmcb_create(struct vmrt_vm_vcpu *vcpu)
{
	vcpu->vmcb_cap = capmgr_vm_vmcb_create(vcpu->vmcs_cap, vcpu->msr_bitmap_cap, vcpu->lapic_access_cap, vcpu->lapic_cap, vcpu->shared_mem_cap, vcpu->handler_tid << 16| vcpu->vpid, 0);
}

void
vmrt_vm_vcpu_init(struct vmrt_vm_comp *vm, u32_t vcpu_nr)
{
	struct vmrt_vm_vcpu *vcpu;
	thdid_t tid, handler_tid;
	thdcap_t cap;
	vaddr_t resource;
	assert(vcpu_nr < vm->num_vcpu);

	vcpu = &vm->vcpus[vcpu_nr];
	assert(!vcpu->shared_region);

	vcpu->vm = vm;

	handler_tid = sched_thd_create(vmrt_vm_exception_handler, vcpu);
	vcpu->handler_tid = handler_tid;

	vcpu->vpid = vcpu_nr + 1;
	vmrt_vmcs_page_create(vcpu);
	vmrt_msr_bitmap_page_create(vcpu);
	vmrt_lapic_page_create(vcpu);
	vmrt_shared_page_create(vcpu);
	vmrt_lapic_access_page_create(vcpu);
	vmrt_vmcb_create(vcpu);

	cap = capmgr_vm_vcpu_create(vcpu->vm->comp_id, vcpu->vmcb_cap, &tid);
	assert(tid != 0);
	vcpu->tid = tid;
	vcpu->cap = cap;
	vcpu->cpuid = vcpu_nr;
	vcpu->coreid = cos_coreid();

	vcpu->next_timer = ~0ULL;

}

void
vmrt_vm_mem_init(struct vmrt_vm_comp *vm, void *mem)
{
	vm->guest_addr = mem;

	/* Clean the memory for the VM */
	memset(mem, 0, vm->guest_mem_sz);
}

void
vmrt_vm_create(struct vmrt_vm_comp *vm, char *name, u8_t num_vcpu, u64_t vm_mem_sz)
{
	compid_t vm_id = 0;
	
	vaddr_t lapic_access_page;

	assert((vm_mem_sz % PAGE_SIZE_4K) == 0);

	vm_id = capmgr_vm_comp_create(vm_mem_sz);
	vm->comp_id = vm_id;

	/*
	 * Allocate lapic access page for the VM.
	 *
	 * This is to allocate the "lapic access page" for the VM.
	 * Simply, this is just to allocate a kernel page, mapped it
	 * into VM comp's EPT at a specified address, by default, it
	 * is LAPIC_BASE_ADDR. Then, this page needs to be also referenced
	 * by the VMCS in the kernel.
	 * 
	 * This page is only used by a VMCS to let the vcpu know
	 * it is accessing a lapic page. The real lapic page used by each vcpu
	 * to read/write data will be allocated later when initializing vcpu.
	 */
	lapic_access_page = capmgr_vm_shared_kernel_page_create_at(vm_id, LAPIC_BASE_ADDR);
	assert(lapic_access_page);
	vm->lapic_access_page = lapic_access_page;

	assert(num_vcpu < VMRT_VM_MAX_VCPU);
	vm->num_vcpu = num_vcpu;
	vm->guest_mem_sz = vm_mem_sz;  

	strcpy((char *)&vm->name, name);

	return;
}

void
vmrt_vm_data_copy_to(struct vmrt_vm_comp *vm, char *data, u64_t size, paddr_t gpa)
{
	char *host_va = GPA2HVA(gpa, vm);
	memcpy(host_va, data, size);
}

void
vmrt_vm_vcpu_resume(struct vmrt_vm_vcpu *vcpu)
{
	cos_switch(vcpu->cap, 0, 0, 0, 0, 0);
}


CWEAKSYMB void 
rdmsr_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
wrmsr_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);;
}

CWEAKSYMB void 
ept_violation_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
ept_misconfig_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
vmcall_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
xsetbv_handler(struct vmrt_vm_vcpu *vcpu)
{
	/* Note: the host uses the same xcr0 as guest, thus this can be bypassed */
	GOTO_NEXT_INST(vcpu->shared_region);
}

CWEAKSYMB void
lapic_write_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
io_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
cpuid_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

CWEAKSYMB void 
pause_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}


CWEAKSYMB void 
ctrl_register_access_handler(struct vmrt_vm_vcpu *vcpu)
{
	#define MOV_TO_CR 0x0
	#define MOV_FROM_CR 0x1

	#define RAX 0
	#define RCX 1
	#define RDX 2
	#define RBX 3
	#define RSP 4
	#define RBP 5
	#define RSI 6
	#define RDI 7
	#define R8 8 
	#define R9 9
	#define R10 10
	#define R11 11
	#define R12 12
	#define R13 13
	#define R14 14
	#define R15 15

	#define CR0 0
	#define CR4 4
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;

	u64_t qualification = regs->qualification;
	u8_t ctrl_reg_index = qualification & 0xf;
	u8_t access_type = (qualification >> 4) & 0x3;
	u8_t nr_reg = (qualification >> 8) & 0xf;

	u64_t cr_content;
	switch (nr_reg)
	{
	case RAX:
		cr_content = regs->ax;
		break;
	case RCX:
		cr_content = regs->cx;
		break;
	case RDX:
		cr_content = regs->dx;
		break;
	case RBX:
		cr_content = regs->bx;
		break;
	case RSP:
		VM_PANIC(vcpu);
		break;
	case RBP:
		cr_content = regs->bp;
		break;
	case RSI:
		cr_content = regs->si;
		break;
	case RDI:
		cr_content = regs->di;
		break;
	case R8:
		cr_content = regs->r8;
		break;
	case R9:
		cr_content = regs->r9;
		break;
	case R10:
		cr_content = regs->r10;
		break;
	case R11:
		cr_content = regs->r11;
		break;
	case R12:
		cr_content = regs->r12;
		break;
	case R13:
		cr_content = regs->r13;
		break;
	case R14:
		cr_content = regs->r14;
		break;
	case R15:
		cr_content = regs->r15;
		break;	
	default:
		VM_PANIC(vcpu);
		break;
	}

	if (ctrl_reg_index == CR0) {
		u64_t cr0_content = cr_content;
		if (access_type == MOV_TO_CR) {
			regs->cr0 = cr0_content;
			regs->efer |= (1 << 10);

			GOTO_NEXT_INST(regs);
		} else {
			VM_PANIC(vcpu);
		}
  	} else if(ctrl_reg_index == CR4) {
		u64_t cr4_content = cr_content;
		if (access_type == MOV_TO_CR) {
			regs->cr4 = cr4_content;

			GOTO_NEXT_INST(regs);
		} else {
			VM_PANIC(vcpu);
		}
	} else {
		VM_PANIC(vcpu);
	}
}

CWEAKSYMB void 
hlt_handler(struct vmrt_vm_vcpu *vcpu)
{
	VM_PANIC(vcpu);
}

static inline void
vmrt_handle_reason(struct vmrt_vm_vcpu *vcpu, u64_t reason)
{
	switch (reason)
	{
	case VM_EXIT_REASON_EXTERNAL_INTERRUPT:
		break;
	case VM_EXIT_REASON_INTERRUPT_WINDOW:
		VM_PANIC(vcpu);
		break;
	case VM_EXIT_REASON_CPUID:
		cpuid_handler(vcpu);
		break;
	case VM_EXIT_REASON_HLT:
		hlt_handler(vcpu);
		break;
	case VM_EXIT_REASON_RDTSC:
		VM_PANIC(vcpu);
		break;
	case VM_EXIT_REASON_VMCALL:
		vmcall_handler(vcpu);
		break;
	case VM_EXIT_REASON_CONTROL_REGISTER_ACCESS:
		ctrl_register_access_handler(vcpu);
		break;
	case VM_EXIT_REASON_IO_INSTRUCTION:
		io_handler(vcpu);
		break;
	case VM_EXIT_REASON_RDMSR:
		rdmsr_handler(vcpu);
		break;
	case VM_EXIT_REASON_WRMSR:
		wrmsr_handler(vcpu);
		break;
	case VM_EXIT_REASON_PAUSE:
		/* TODO: handle pause exception */
		pause_handler(vcpu);
		break;
	case VM_EXIT_REASON_EPT_VIOLATION:
		ept_violation_handler(vcpu);
		break;
	case VM_EXIT_REASON_EPT_MISCONFIG:
		ept_misconfig_handler(vcpu);
		break;
	case VM_EXIT_REASON_APIC_ACCESS:
		VM_PANIC(vcpu);
		break;
	case VM_EXIT_REASON_PREEMPTION_TIMER:
		VM_PANIC(vcpu);
		break;
	case VM_EXIT_REASON_XSETBV:
		xsetbv_handler(vcpu);
		break;
	case VM_EXIT_REASON_APIC_WRITE:
		lapic_write_handler(vcpu);
		break;
	default:
		printc("vm panic reason: %llu, vcpu tid:%lu\n", reason, vcpu->tid);
		VM_PANIC(vcpu);
		break;
	}
}

void
vmrt_vm_vcpu_start(struct vmrt_vm_vcpu *vcpu)
{
	/* This is actually just to "push" the vcpu handler thread into run queue. */
	sched_thd_param_set(vcpu->handler_tid, sched_param_pack(SCHEDP_PRIO, 31));
}

void
vmrt_vm_exception_handler(void *_vcpu)
{
	struct vmrt_vm_vcpu *vcpu = (struct vmrt_vm_vcpu *)_vcpu;
	struct vm_vcpu_shared_region *shared_region;
	u64_t reason;
	u64_t curr_tsc;

	shared_region = vcpu->shared_region;
	while (1)
	{
		vmrt_vm_vcpu_resume(vcpu);
	
		reason = shared_region->reason;

		vmrt_handle_reason(vcpu, reason);
		rdtscll(curr_tsc);
		if (curr_tsc >= vcpu->next_timer) {
#if VMX_SUPPORT_POSTED_INTR
			vlapic_timer_expired(vcpu);
#else 
			/* 236 is Linux's fixed timer interrrupt */
			lapic_intr_inject(vcpu, 236, 0);
#endif
			vcpu->next_timer = ~0ULL;
		}

#if VMX_SUPPORT_POSTED_INTR
		vlapic_inject_intr(vcpu);
#endif
	}
}
