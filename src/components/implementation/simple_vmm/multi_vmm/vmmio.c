#include <vmrt.h>
#include <instr_emul.h>
#include <acrn_common.h>
#include <vioapic.h>

void 
ept_violation_handler(struct vmrt_vm_vcpu *vcpu)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;
	u64_t qualification = regs->qualification;
	u64_t gpa;
	struct acrn_mmio_request *mmio_req = vcpu->mmio_request;

	gpa = regs->gpa;

	/* Specify if read or write operation */
	if ((qualification & 0x2UL) != 0UL) {
		/* Write operation */
		mmio_req->direction = ACRN_IOREQ_DIR_WRITE;
		mmio_req->value = 0UL;
	} else {
		/* Read operation */
		mmio_req->direction = ACRN_IOREQ_DIR_READ;
	}

	mmio_req->address = gpa;

	if (gpa >= IOAPIC_BASE_ADDR && gpa < IOAPIC_BASE_ADDR + PAGE_SIZE_4K) {
		int ret = decode_instruction(vcpu);

		if (ret > 0) {
			mmio_req->size = (uint64_t)ret;
		} else {
			VM_PANIC(vcpu);
		}

		if (mmio_req->direction == ACRN_IOREQ_DIR_WRITE) {
			if (emulate_instruction(vcpu) != 0) {
				VM_PANIC(vcpu);
			}
		}

		vioapic_mmio_access_handler(vcpu);

		if (mmio_req->direction == ACRN_IOREQ_DIR_READ) {
			/* Emulate instruction and update vcpu register set */
			(void)emulate_instruction(vcpu);
		}
		GOTO_NEXT_INST(regs);
	} else {
		VM_PANIC(vcpu);
	}
}
