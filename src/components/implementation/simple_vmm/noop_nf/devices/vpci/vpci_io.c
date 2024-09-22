#include <cos_types.h>
#include <cos_debug.h>
#include <vmrt.h>
#include "vpci.h"

static u32_t curr_bdf = 0;

extern u32_t get_vpci_reg(u32_t bdf);
extern void set_vpci_reg(u32_t bdf, u32_t val, u8_t idx, u8_t sz);

static void
vpci_outb(u32_t port_id, struct vmrt_vm_vcpu *vcpu)
{
	u8_t val = vcpu->shared_region->ax;

	switch (port_id)
	{
	case VPCI_MECHANISM_CONTROL_REG:
		/* This is the register to configure the PCI access mecanism, we only support type 1 which is commonly used */
		assert(val == 0x1);
		break;
	case VPCI_CONFIG_DATA0:
		set_vpci_reg(curr_bdf, val, 0, 1);
		break;
	case VPCI_CONFIG_DATA1:
		set_vpci_reg(curr_bdf, val, 1, 1);
		break;
	case VPCI_CONFIG_DATA2:
		set_vpci_reg(curr_bdf, val, 2, 1);
		break;
	case VPCI_CONFIG_DATA3:
		set_vpci_reg(curr_bdf, val, 3, 1);
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}
	return;
}

static void
vpci_inb(u32_t port_id, struct vmrt_vm_vcpu *vcpu)
{
	u32_t bdf = 0;

	switch (port_id)
	{
	case VPCI_MECHANISM_CONTROL_REG:
		vcpu->shared_region->ax = 1;
		break;
	case VPCI_CONFIG_DATA0:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u8_t)bdf;
		break;
	case VPCI_CONFIG_DATA1:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u8_t)(bdf >> 8);
		break;
	case VPCI_CONFIG_DATA2:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u8_t)(bdf >> 16);
		break;
	case VPCI_CONFIG_DATA3:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u8_t)(bdf >> 24);
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}

	return;
}

static void
vpci_inw(u32_t port_id, struct vmrt_vm_vcpu *vcpu)
{
	u32_t bdf = 0;

	switch (port_id)
	{
	case VPCI_CONFIG_DATA0:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u16_t)bdf;
		break;
	case VPCI_CONFIG_DATA2:
		bdf = get_vpci_reg(curr_bdf);
		vcpu->shared_region->ax = (u16_t)(bdf>>16);
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}

	return;
}

static void
vpci_outw(u32_t port_id,  struct vmrt_vm_vcpu *vcpu)
{
	u16_t val = vcpu->shared_region->ax;

	switch (port_id)
	{
	case VPCI_CONFIG_DATA0:
		set_vpci_reg(curr_bdf, val, 0, 2);
		break;
	case VPCI_CONFIG_DATA2:
		set_vpci_reg(curr_bdf, val, 2, 2);
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}

	return;
}

static void
vpci_outl(u32_t port_id, struct vmrt_vm_vcpu *vcpu)
{
	u32_t val = vcpu->shared_region->ax;

	switch (port_id)
	{
	case VPCI_CONFIG_ADDRESS:
		curr_bdf = val;
		break;
	case VPCI_CONFIG_DATA0:
		set_vpci_reg(curr_bdf, val, 0, 3);
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}
	return;
}

static u32_t
vpci_inl(u32_t port_id, struct vmrt_vm_vcpu *vcpu)
{
	switch (port_id)
	{
	case VPCI_CONFIG_DATA0:
		vcpu->shared_region->ax = get_vpci_reg(curr_bdf);
		break;
	case VPCI_CONFIG_ADDRESS:
		vcpu->shared_region->ax = curr_bdf;
		break;
	default:
		VM_PANIC(vcpu);
		break;
	}
	return 0;
}

void
vpci_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu)
{
	if (dir == IO_IN) {
		switch (sz)
		{
		case IO_BYTE:
			vpci_inb(port, vcpu);
			break;
		case IO_WORD:
			vpci_inw(port, vcpu);
			break;
		case IO_LONG:
			vpci_inl(port, vcpu);
			break;
		default:
			VM_PANIC(vcpu);
		}
	} else {
		switch (sz)
		{
		case IO_BYTE:
			vpci_outb(port, vcpu);
			break;
		case IO_WORD:
			vpci_outw(port, vcpu);
			break;
		case IO_LONG:
			vpci_outl(port, vcpu);
			break;
		default:
			VM_PANIC(vcpu);
		}
	}
}
