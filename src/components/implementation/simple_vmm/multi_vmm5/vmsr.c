#include <vmrt.h>
#include <vmx_msr.h>

void 
rdmsr_handler(struct vmrt_vm_vcpu *vcpu)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;

	switch (regs->cx) {
	case MSR_IA32_EFER: 
	{
		u64_t guest_efer = regs->efer;
		regs->ax = (u32_t)guest_efer;
		regs->dx = (u32_t)(guest_efer >> 32);
		goto done;
	}
	case MSR_IA32_MISC_ENABLE: 
	{
		/* Note: read only MSR, and its value can be fixed for all cores */
		u64_t misc = 0x800001;
		regs->ax = (u32_t)misc;
		regs->dx = (u32_t)(misc >> 32);
		goto done;
	}
	case MSR_IA32_BIOS_SIGN_ID:
	{
		/* Note: microcode is pre-set in the kernel */
		u64_t v = regs->microcode_version;
		regs->ax = (u32_t)v;
		regs->dx = (u32_t)(v >> 32);
		goto done;
	}
	case MSR_IA32_TSC_ADJUST:
	{
		/* TODO: need to handle tsc adjustment in VM */
		u32_t ax, dx;
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}

	/* MTRRs can be ingored in Linux and Linux knows it is a virtual environment */
	case MSR_IA32_MTRR_CAP:
	case MSR_IA32_MTRR_DEF_TYPE:
	case MSR_IA32_MTRR_PHYSBASE_0:
	case MSR_IA32_MTRR_PHYSMASK_0:
	case MSR_IA32_MTRR_PHYSBASE_1:
	case MSR_IA32_MTRR_PHYSMASK_1:
	case MSR_IA32_MTRR_PHYSBASE_2:
	case MSR_IA32_MTRR_PHYSMASK_2:	
	case MSR_IA32_MTRR_PHYSBASE_3:
	case MSR_IA32_MTRR_PHYSMASK_3:
	case MSR_IA32_MTRR_PHYSBASE_4:
	case MSR_IA32_MTRR_PHYSMASK_4:
	case MSR_IA32_MTRR_PHYSBASE_5:
	case MSR_IA32_MTRR_PHYSMASK_5:
	case MSR_IA32_MTRR_PHYSBASE_6:
	case MSR_IA32_MTRR_PHYSMASK_6:
	case MSR_IA32_MTRR_PHYSBASE_7:
	case MSR_IA32_MTRR_PHYSMASK_7:
	case MSR_IA32_MTRR_PHYSBASE_8:
	case MSR_IA32_MTRR_PHYSMASK_8:
	case MSR_IA32_MTRR_PHYSBASE_9:
	case MSR_IA32_MTRR_PHYSMASK_9:	
	case MSR_IA32_MTRR_FIX64K_00000:
	case MSR_IA32_MTRR_FIX16K_80000:
	case MSR_IA32_MTRR_FIX16K_A0000:
	case MSR_IA32_MTRR_FIX4K_C0000:
	case MSR_IA32_MTRR_FIX4K_C8000:
	case MSR_IA32_MTRR_FIX4K_D0000:
	case MSR_IA32_MTRR_FIX4K_D8000:
	case MSR_IA32_MTRR_FIX4K_E0000:
	case MSR_IA32_MTRR_FIX4K_E8000:
	case MSR_IA32_MTRR_FIX4K_F0000:
	case MSR_IA32_MTRR_FIX4K_F8000:
	case MSR_IA32_PAT:
	{
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}	
	case MSR_PPERF:
	{
		/* FIXME: should inject #GP to guest, thus guest knows this MSR is not present */
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}
	case MSR_SMI_COUNT:
	{
		/* FIXME: should inject #GP to guest, thus guest knows this MSR is not present */
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}	
	case MSR_IA32_APIC_BASE:
	{
		/* TODO: for non-BSP, the BSP flag should be cleared */
		/* 0x900 : enable xapic and this is BSP */
		regs->ax = 0XFEE00000 | 0x900;
		regs->dx = 0;
		goto done;
	}
	case MSR_IA32_FEATURE_CONTROL:
	{
		/* Lock the feature control in VM */
		regs->ax = 1;
		regs->dx = 0;
		goto done;
	}	
	case MSR_MISC_FEATURE_ENABLES:
	{
		/* This MSR can be reserved to 0 */
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}
	case MSR_PLATFORM_INFO:
	{
		/* Contains power management stuff and can be ignored */
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}
	case MSR_IA32_SPEC_CTRL:
	{
		/* This MSR has a value of 0 after reset, thus just keep it ad default, don't modify */
		regs->ax = 0;
		regs->dx = 0;
		goto done;
	}	
	default:
		VM_PANIC(vcpu);
	}
done:
	GOTO_NEXT_INST(regs);
	return;
}

void 
wrmsr_handler(struct vmrt_vm_vcpu *vcpu)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;

	switch (regs->cx) {
	case MSR_IA32_EFER:
	{
		u64_t guest_efer;
		guest_efer = regs->ax & 0XFFFFFFFF;
		guest_efer |= ((regs->dx & 0XFFFFFFFF) << 32);
		regs->efer = guest_efer;

		goto done;
	}
	case MSR_IA32_BIOS_SIGN_ID:
	{
		/* Microcode has been retrived in the kernel, thus don't need to process here */
		goto done;
	}
	case MSR_IA32_XSS:
	{
		u64_t guest_xss;
		guest_xss = regs->ax & 0XFFFFFFFF;
		guest_xss |= ((regs->dx & 0XFFFFFFFF) << 32);
		if ((guest_xss & ~(MSR_IA32_XSS_PT | MSR_IA32_XSS_HDC)) != 0UL) {
				/* Assuming other features are not supported */
				VM_PANIC(vcpu);
		} else {
			/* TODO: only enable the xss pt and hdx, but currently just ignore them */
		}
		goto done;
	}		
	case MSR_IA32_MTRR_CAP:
	case MSR_IA32_MTRR_DEF_TYPE:
	case MSR_IA32_MTRR_PHYSBASE_0:
	case MSR_IA32_MTRR_PHYSMASK_0:
	case MSR_IA32_MTRR_PHYSBASE_1:
	case MSR_IA32_MTRR_PHYSMASK_1:
	case MSR_IA32_MTRR_PHYSBASE_2:
	case MSR_IA32_MTRR_PHYSMASK_2:
	case MSR_IA32_MTRR_PHYSBASE_3:
	case MSR_IA32_MTRR_PHYSMASK_3:
	case MSR_IA32_MTRR_PHYSBASE_4:
	case MSR_IA32_MTRR_PHYSMASK_4:
	case MSR_IA32_MTRR_PHYSBASE_5:
	case MSR_IA32_MTRR_PHYSMASK_5:
	case MSR_IA32_MTRR_PHYSBASE_6:
	case MSR_IA32_MTRR_PHYSMASK_6:
	case MSR_IA32_MTRR_PHYSBASE_7:
	case MSR_IA32_MTRR_PHYSMASK_7:
	case MSR_IA32_MTRR_PHYSBASE_8:
	case MSR_IA32_MTRR_PHYSMASK_8:
	case MSR_IA32_MTRR_PHYSBASE_9:
	case MSR_IA32_MTRR_PHYSMASK_9:
	case MSR_IA32_MTRR_FIX64K_00000:
	case MSR_IA32_MTRR_FIX16K_80000:
	case MSR_IA32_MTRR_FIX16K_A0000:
	case MSR_IA32_MTRR_FIX4K_C0000:
	case MSR_IA32_MTRR_FIX4K_C8000:
	case MSR_IA32_MTRR_FIX4K_D0000:
	case MSR_IA32_MTRR_FIX4K_D8000:
	case MSR_IA32_MTRR_FIX4K_E0000:
	case MSR_IA32_MTRR_FIX4K_E8000:
	case MSR_IA32_MTRR_FIX4K_F0000:
	case MSR_IA32_MTRR_FIX4K_F8000:
	case MSR_IA32_PAT:
	{
		/* MTRRs can be ingored in Linux and Linux knows it is a virtual environment */
		goto done;
	}	
	case MSR_IA32_TSC_DEADLINE: {
		u64_t tsc_future, curr_tsc;
		rdtscll(curr_tsc);
		tsc_future = regs->ax & 0xffffffff;
		tsc_future |= ((regs->dx & 0xffffffff) << 32);
		vcpu->next_timer = tsc_future;

		goto done;
	}
	case MSR_MISC_FEATURE_ENABLES:
	{
		/* Write to this MSR will be all 0 since we ignored this, doesn't matter */
		goto done;
	}
	case MSR_IA32_SYSENTER_CS:
	case MSR_IA32_SYSENTER_ESP:
	case MSR_IA32_SYSENTER_EIP:
	{
		/* 64-bit system doesn't require these MSRs, its fine to ignore them */
		goto done;
	}
	case MSR_IA32_SPEC_CTRL:
	{
		/* This MSR has a value of 0 after reset, thus just keep it ad default, don't modify */
		goto done;
	}
	case MSR_IA32_APIC_BASE:
	{
		VM_PANIC(vcpu);
		goto done;
	}
	default:
		VM_PANIC(vcpu);;
	}

done:
	GOTO_NEXT_INST(regs);
	return;
}
