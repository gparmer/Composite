#include <chal_cpu.h>
#include <thd.h>
#include <cpuid.h>
#include <chal_asm_inc.h>
#include <vmx.h>
#include <vmx_msr.h>
#include <vmx_logging.h>
#include <vmx_exit.h>
#include <vmx_utils.h>
#include <vmx_vmcs.h>
#include <vmx_exit.h>

void lapic_ack(void);
void restore_from_vm(void);
int cap_thd_switch(struct pt_regs *regs, struct thread *curr, struct thread *next,
			struct comp_info *ci, struct cos_cpu_local_info *cos_info);

int expended_process(struct pt_regs *regs, struct thread *thd_curr, struct comp_info *ci,
                 struct cos_cpu_local_info *cos_info, int timer_intr_context);

/* The tmp regs stack used for VM-exit switching to other threads */
static struct pt_regs tmp_regs[NUM_CPU];

/* When VMM tries to write cr0/cr4, kernel needs to take care of them */
extern u64_t cr4_fixed1_bits;
extern u64_t cr4_fixed0_bits;
extern u64_t cr0_fixed1_bits;
extern u64_t cr0_fixed0_bits;

int
posted_intr_handler(struct pt_regs *regs)
{
	/* should not come here by design */
	assert(0);
	return 0;
}

static void
posted_intr_inject(void)
{
	chal_selfipi(HW_LAPIC_POSTED_INTR);
}


void
vmx_resume(struct thread *thd)
{
	struct vm_vcpu_shared_region *shared_region;
	u64_t val;

	if (unlikely(thd->vcpu_ctx.state == VM_THD_STATE_STOPPED)) return;
	vmx_assert(thd->vcpu_ctx.state == VM_THD_STATE_RUNNING);

	shared_region = thd->vm_vcpu_shared_region;

	/* User level VMM is responsible to set vcpu's state like ip and sp, or a VM-exit will happen, the kernel should be safe */
	vmwrite(GUEST_RIP, shared_region->ip);
	vmwrite(GUEST_RSP, shared_region->sp);
	vmwrite(GUEST_IA32_EFER, shared_region->efer);

	/* TODO: maybe can put the fixed bits value to the VMM */
	val = shared_region->cr0;
	val |= cr0_fixed1_bits;
	val &= cr0_fixed0_bits;
	vmwrite(GUEST_CR0, val);

	val = shared_region->cr4;
	val |= cr4_fixed1_bits;
	val &= cr4_fixed0_bits;
	vmwrite(GUEST_CR4, val);

	/* This is awkward here, but necessary as the manual mentions that long-mode status should be put into vm entry ctl */
	if (unlikely(shared_region->efer & BIT(10))) {
		u64_t vm_entry_ctls = vmread(VM_ENTRY_CONTROLS);
		vm_entry_ctls |= BIT(9);
		vmwrite(VM_ENTRY_CONTROLS, vm_entry_ctls);
	}

	/* Used for VMM manages virtual lapic interrupts */
	if (shared_region->interrupt_status) {
		vmwrite(GUEST_INTERRUPT_STATUS, shared_region->interrupt_status);
	}

#if VMX_SUPPORT_POSTED_INTR
	/* 
	 * TODO: We definitely would like to support posted interrupt mechanism since it can reduce multi-core
	 * interrupt injection overhead. However, this currently cannot work small timer tick like 100us set up.
	 * Thus, currently just keep the legacy interrupt injection mechanism.
	 */
	if (unlikely(shared_region->inject_evt)) {
		posted_intr_inject();
		shared_region->inject_evt = 0;
	}
#endif

	/* TODO: some msrs like kernel gs are (per-core) constant, can make host saving code simpler`*/
	thd->vcpu_ctx.vmcs.host_msr_gs_base = msr_get(IA32_GS_BASE);
	thd->vcpu_ctx.vmcs.host_msr_gskernel_base = msr_get(IA32_KERNEL_GSBASE);
	thd->vcpu_ctx.vmcs.host_tsc_aux = msr_get(IA32_TSC_AUX);
	thd->vcpu_ctx.vmcs.host_star = msr_get(IA32_STAR);
	thd->vcpu_ctx.vmcs.host_lstar = msr_get(IA32_LSTAR);
	thd->vcpu_ctx.vmcs.host_cstar = msr_get(IA32_CSTAR);
	thd->vcpu_ctx.vmcs.host_fmask = msr_get(IA32_FMASK);

	msr_set(IA32_GS_BASE, thd->vcpu_ctx.vmcs.guest_msr_gs_base);
	msr_set(IA32_KERNEL_GSBASE, thd->vcpu_ctx.vmcs.guest_msr_gskernel_base);
	msr_set(IA32_TSC_AUX, thd->vcpu_ctx.vmcs.guest_tsc_aux);
	msr_set(IA32_STAR, thd->vcpu_ctx.vmcs.guest_star);
	msr_set(IA32_LSTAR, thd->vcpu_ctx.vmcs.guest_lstar);
	msr_set(IA32_CSTAR, thd->vcpu_ctx.vmcs.guest_cstar);
	msr_set(IA32_FMASK, thd->vcpu_ctx.vmcs.guest_fmask);

	/* Restore GPs for vcpu */
	__asm__ __volatile__(
				"movq %%rax, %%rsp\n\t"		\
				"popq %%rax\n\t"		\
				"movq %%rax, %%cr2\n\t"		\
				"popq %%r15\n\t"		\
				"popq %%r14\n\t"		\
				"popq %%r13\n\t"		\
				"popq %%r12\n\t"		\
				"popq %%r11\n\t"		\
				"popq %%r10\n\t"		\
				"popq %%r9\n\t"			\
				"popq %%r8\n\t"			\
				"popq %%rbx\n\t"		\
				"popq %%rcx\n\t"		\
				"popq %%rdx\n\t"		\
				"popq %%rsi\n\t"		\
				"popq %%rdi\n\t"		\
				"popq %%rbp\n\t"		\
				"popq %%rax\n\t"		\
				"vmresume\n\t"			\
				: 
				: "a"(shared_region)
				:);

	/* TODO: what if somehow vmresume fails? */
	vmx_assert(0);
}

static int 
timer_process(struct pt_regs *regs, struct thread *thd_curr)
{
	struct cos_cpu_local_info *cos_info;
	struct comp_info *         comp;
	unsigned long              ip, sp;
	cycles_t                   now;

	cos_info = cos_cpu_local_info();
	vmx_assert(cos_info);	
	comp = &thd_curr->invstk[thd_curr->invstk_top].comp_info;
	vmx_assert(comp);
	return expended_process(regs, thd_curr, comp, cos_info, 0);
}

void
vmx_exit_handler(struct vm_vcpu_shared_region *regs)
{
	u64_t reason, qualification, gla, gpa, inst_length, inst_info;
	u8_t reason_nr;
	int ret = 0;
	unsigned long cpuid;
	struct cos_cpu_local_info *cos_info;
	struct thread *thd_curr, *thd_exception_handler, *next;
	struct vm_vcpu_shared_region *shared_region;
	cos_info = cos_cpu_local_info();
	thd_curr = thd_current(cos_info);	
	cpuid = cos_info->cpuid;

	thd_curr->vcpu_ctx.vmcs.guest_msr_gs_base = msr_get(IA32_GS_BASE);
	thd_curr->vcpu_ctx.vmcs.guest_msr_gskernel_base = msr_get(IA32_KERNEL_GSBASE);
	thd_curr->vcpu_ctx.vmcs.guest_tsc_aux = msr_get(IA32_TSC_AUX);
	thd_curr->vcpu_ctx.vmcs.guest_star = msr_get(IA32_STAR);
	thd_curr->vcpu_ctx.vmcs.guest_lstar = msr_get(IA32_LSTAR);
	thd_curr->vcpu_ctx.vmcs.guest_cstar = msr_get(IA32_CSTAR);
	thd_curr->vcpu_ctx.vmcs.guest_fmask = msr_get(IA32_FMASK);
	
	msr_set(IA32_GS_BASE, thd_curr->vcpu_ctx.vmcs.host_msr_gs_base);
	msr_set(IA32_KERNEL_GSBASE, thd_curr->vcpu_ctx.vmcs.host_msr_gskernel_base);
	msr_set(IA32_TSC_AUX, thd_curr->vcpu_ctx.vmcs.host_tsc_aux);
	msr_set(IA32_STAR, thd_curr->vcpu_ctx.vmcs.host_star);
	msr_set(IA32_LSTAR, thd_curr->vcpu_ctx.vmcs.host_lstar);
	msr_set(IA32_CSTAR, thd_curr->vcpu_ctx.vmcs.host_cstar);
	msr_set(IA32_FMASK, thd_curr->vcpu_ctx.vmcs.host_fmask);

	vmx_assert(cos_info);
	vmx_assert(thd_curr && thd_curr->cpuid == get_cpuid());
	vmx_assert(thd_curr->thd_type == THD_TYPE_VM);

	shared_region = thd_curr->vm_vcpu_shared_region;
	thd_exception_handler = thd_curr->exception_handler;
	
	reason = vmread(EXIT_REASON);
	qualification = vmread(EXIT_QUALIFICATION);
	gla = vmread(EXIT_GUEST_LINEAR_ADDRESS);
	gpa = vmread(EXIT_GUEST_PHYSICAL_ADDRESS);
	inst_length = vmread(EXIT_INSTRUCTION_LENGTH);
	inst_info = vmread(EXIT_INSTRUCTION_INFORMATION);

	if (unlikely(reason & (1 << 31))) {
		/* TODO: Should not happen, but need to handle this case correctly later */
		VMX_DEBUG("exit reason:%x(%lu)\n", reason, reason);
		VMX_DEBUG("exit qualification:0x%x\n", qualification);
		vmx_assert(0);
	}

	reason_nr = reason & 0xffff;
	vmx_assert(reason_nr < MAX_VM_EXIT_REASONS);
	VMX_DEBUG("VM thd: %u on core: %u get VM-exit (reason: ) on handler: %u\n", thd_curr->tid, cos_info->cpuid, reason_nr, thd_exception_handler->tid);

	/* Share GPs with VMM */
	memcpy(shared_region, regs, sizeof(struct vm_vcpu_shared_region));

	shared_region->reason = reason_nr;
	shared_region->ip = vmread(GUEST_RIP);
	shared_region->sp = vmread(GUEST_RSP);
	shared_region->efer = vmread(GUEST_IA32_EFER);
	shared_region->cr0 = vmread(GUEST_CR0);
	shared_region->cr3 = vmread(GUEST_CR3);
	shared_region->cr4 = vmread(GUEST_CR4);
	shared_region->interrupt_status = vmread(GUEST_INTERRUPT_STATUS);
	shared_region->inst_length = inst_length;
	shared_region->gpa = gpa;
	shared_region->qualification = qualification;

	/* FIXME: handle vcpu execution time correctly, this also seems should add into VMM thread */
	thd_curr->exec += 1000;

	/* Save fs for vcpu, this will be restoed later in the thread switch path, thus safe */
	thd_curr->tls = msr_get(IA32_FS_BASE);

	/* TODO: different external interrupts should be handled by different host interrrut handlers, currently it only has timer interrupt */
	if (reason_nr == VM_EXIT_REASON_EXTERNAL_INTERRUPT) {
		lapic_ack();
		/*FIXME: might need a xsave/xrestore for sse/avx for current vcpu thd because current thd is set to be exception handler */
		copy_gp_regs(&thd_exception_handler->regs, &tmp_regs[cpuid]);
		ret = timer_process(&tmp_regs[cpuid], thd_exception_handler);
	} else {
		next = thd_exception_handler;
		ret = cap_thd_switch(&tmp_regs[cpuid], thd_curr, next, NULL, cos_info);
		vmx_assert(ret == 0);
	}

	__asm__ volatile("movq %%rbx, %%rsp; jmpq *%%rcx": : "a"(ret), "b"(&tmp_regs[cpuid]),"c"(&restore_from_vm));

	/* Should never come here */
	vmx_assert(0);
}
