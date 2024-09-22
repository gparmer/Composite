#include "serial.h"

static u8_t serial_data[0x08];
static u8_t send_intr_enable = 0;

void
serial_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu)
{
	assert(port <= SERIAL_PORT_MAX && port >= SERIAL_PORT_MIN);
	assert(sz == IO_BYTE);

	if (dir == IO_IN) {
		vcpu->shared_region->ax = serial_data[port - SERIAL_PORT_MIN];
	} else if (dir == IO_OUT) {
		serial_data[port - SERIAL_PORT_MIN] = (u8_t)vcpu->shared_region->ax;
		switch (port)
		{

		case SERIAL_PORT1:
			printc("%c", (u8_t)vcpu->shared_region->ax);
			if (send_intr_enable) {
				/*
				 * TODO: correctly handle serial output(eg: multiple vcpu case) and inject serial interrupt,
				 * with io apic, 34 is serial8250_interrupt vector.
				 */
#if VMX_SUPPORT_POSTED_INTR
				vlapic_set_intr(vcpu, 34, 0);
#else
				lapic_intr_inject(vcpu, 34, 1);
#endif
				serial_data[SERIAL_IIR - SERIAL_PORT_MIN] = 0x2;
				serial_data[MODEM_STATUS_REGISTER - SERIAL_PORT_MIN] = 0x20;
				serial_data[SERIAL_LSR - SERIAL_PORT_MIN] = 0x60;
			}
			break;
		case SERIAL_IER:			
			if (0x2 & (u8_t)vcpu->shared_region->ax) {
				send_intr_enable = 1;
			} else {
				send_intr_enable = 0;
			}
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
	memset(&serial_data, 0, sizeof(serial_data));
	serial_data[SERIAL_LSR - SERIAL_PORT_MIN] = 0x60;
}
