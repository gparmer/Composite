#include <cos_types.h>
#include <cos_debug.h>
#include <vmrt.h>
#include "vps2.h"

static u8_t ps2_porta_data[0x0F];
static u8_t ps2_portb_data[0x0F];

void
ps2_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu)
{
	assert(port == PS2_CONTROL_PORT_A || port == PS2_CONTROL_PORT_B);
	assert(sz == IO_BYTE);

	if (dir == IO_IN) {
		switch (port)
		{
		case PS2_CONTROL_PORT_A:
			vcpu->shared_region->ax = ps2_porta_data[port - 0x90];
			break;
		default:
			VM_PANIC(vcpu);
			break;
		}
	} else if (dir == IO_OUT) {
		switch (port)
		{
		case PS2_CONTROL_PORT_A:
			ps2_porta_data[port - 0x90] = (u8_t)vcpu->shared_region->ax;
			break;
		default:
			VM_PANIC(vcpu);
			break;
		}
	} else {
		VM_PANIC(vcpu);
	}

	return;
}

static void __attribute__((constructor))
init(void)
{
	memset(&ps2_porta_data, 0, sizeof(ps2_porta_data));
	memset(&ps2_portb_data, 0, sizeof(ps2_portb_data));
}
