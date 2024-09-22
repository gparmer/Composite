## VMRT runtime library

A simple VM lib for Composite VMM managing virtual machines. Currently, it includes interfaces of VM creation, VCPU execution and simple exception handler mechanisms.


## VM abstraction data structure

```c
struct vmrt_vm_vcpu {
	struct vm_vcpu_shared_region *shared_region;
	u64_t next_timer;
	void *lapic_page;

	/*
	 * A opaque pointer points to VMM's specific implementation of lapic.
	 * A VMM is responsible to have its own apic implementation.
	 */
	void *vlapic;

	thdid_t tid;
	thdcap_t cap;

	u8_t cpuid;
	u8_t coreid;
	struct vmrt_vm_comp *vm;
	u64_t pending_req;

	u16_t vpid;
	vm_vmcscap_t vmcs_cap;
	vm_msrbitmapcap_t msr_bitmap_cap;
	vm_lapiccap_t lapic_cap;
	vm_shared_mem_t shared_mem_cap; 
	vm_lapicaccesscap_t lapic_access_cap;
	vm_vmcb_t vmcb_cap;
	thdid_t handler_tid;
};

struct vmrt_vm_comp {
	compid_t comp_id;
	void *guest_addr;
	word_t guest_mem_sz;

	vm_lapicaccesscap_t lapic_access_page;

	char name[VMRT_VM_NAME_SIZE];

	u8_t num_vcpu;
	struct vmrt_vm_vcpu vcpus[VMRT_VM_MAX_VCPU];
};
```

## Interfaces

### VM creation

```c
void
vmrt_vm_create(struct vmrt_vm_comp *vm, char *name, u8_t num_vcpu, u64_t vm_mem_sz)
{
	/* 1. VM component creation */
	vm_id = capmgr_vm_comp_create(vm_mem_sz);

	/* 2. Initialize vm members */
	assert(num_vcpu < VMRT_VM_MAX_VCPU);
	vm->num_vcpu = num_vcpu;
	vm->guest_mem_sz = vm_mem_sz;  

	strcpy((char *)&vm->name, name);
}

```

### VCPU initialization

```c
void
vmrt_vm_vcpu_init(struct vmrt_vm_comp *vm, u32_t vcpu_nr)
{
	/* 1. VCPU exception handler thread creation */
	handler_tid = sched_thd_create(vmrt_vm_exception_handler, vcpu);

	/* 2. vmcb cap creation */
	vmrt_vmcs_page_create(vcpu);
	vmrt_msr_bitmap_page_create(vcpu);
	vmrt_lapic_page_create(vcpu);
	vmrt_shared_page_create(vcpu);
	vmrt_lapic_access_page_create(vcpu);
	vmrt_vmcb_create(vcpu);

	/* 3. Bind the vmcb to the VCPU thread */
	cap = capmgr_vm_vcpu_create(vcpu->vm->comp_id, vcpu->vmcb_cap, &tid);

	/* TODO: create new capabilities for shared resources such as lapic page and combine them into a single api */
	vcpu->next_timer = ~0ULL;

	vcpu->vm = vm;
}
```

### Loading data into/from VM
```c
void
vmrt_vm_data_copy_to(struct vmrt_vm_comp *vm, char *data, u64_t size, paddr_t gpa)
{
	char *host_va = GPA2HVA(gpa, vm);
	memcpy(host_va, data, size);
}

void
vmrt_vm_data_copy_from(struct vmrt_vm_comp *vm, char *data, u64_t size, paddr_t gpa)
{
	char *host_va = GPA2HVA(gpa, vm);
	memcpy(data, host_va, size);
}
```

### Exception handler

```c
void
vmrt_vm_exception_handler(struct vmrt_vm_vcpu *vcpu)
{
	shared_region = vcpu->shared_region;
	while (1)
	{
		vmrt_vm_vcpu_resume(vcpu);

		/* 1. Get exit reason */
		u64_t reason = shared_region->reason;

		/* 2. handle the reason */
		vmrt_handle_reason(vcpu, reason);

		/* 3. inject necessary interrupt such as timer */
		rdtscll(curr_tsc);
		if (curr_tsc >= vcpu->next_timer) {
			lapic_intr_inject(vcpu, vector, 0);
		}
	}
}
```

### VM-exit reasons

- VM_EXIT_REASON_EXTERNAL_INTERRUPT

	When there were an interrupt from host hardware like timer, this will be triggered with the interrupt number.

- VM_EXIT_REASON_INTERRUPT_WINDOW

	When the guest enables interrupt(sti instruction) and if vmcs enables this VM-exit, this will be triggered. Currently, this is a legacy VM-exit reason and is not used.

- VM_EXIT_REASON_RDTSC

	When guest use rdtsc and if vmcs enables this exit bit, it will be triggerred. Currently the vmm just pass-through it.

- VM_EXIT_REASON_VMCALL

	When guest uses vmcall, it will be triggered.

- VM_EXIT_REASON_CONTROL_REGISTER_ACCESS

	When guest accesses control registers, it will be triggered.

- VM_EXIT_REASON_IO_INSTRUCTION

	When guest uses in/out, it will be triggered.

- VM_EXIT_REASON_PAUSE

	When guest uses pause and if vmcs enables this exit bit, it will be triggered.

- VM_EXIT_REASON_EPT_MISCONFIG

	When hardware finds EPT is incorrect, it will be triggered.

- VM_EXIT_REASON_APIC_ACCESS

	When guest accesses lapic address and if vmcs doesn't enable virtual lapic, this will be triggered. This is not used because the system enables virtual lapic feature.

- VM_EXIT_REASON_PREEMPTION_TIMER

	Vmcs can set a time-out value for guest to preempt it. But this is not used. This is not related to lapic timer at all.

- VM_EXIT_REASON_APIC_WRITE
	When vmcs enables virtual lapic feature, guest access to lapic registers will trigger VM-exit.

- VM_EXIT_REASON_XSETBV

	When guest uses xsetbv, this will be triggered.