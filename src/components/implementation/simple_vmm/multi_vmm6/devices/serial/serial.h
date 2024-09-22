#pragma once
#include <cos_types.h>
#include <vmrt.h>

/* Reference: https://www.lammertbies.nl/comm/info/serial-uart */
#define SERIAL_PORT1		0x3F8
#define SERIAL_IER		0x3F9
#define SERIAL_IIR		0x3FA
#define SERIAL_LCR		0x3FB
#define SERIAL_MCR		0x3FC
#define SERIAL_LSR		0x3FD
#define MODEM_STATUS_REGISTER 	0x3FE

#define SERIAL_PORT_MIN SERIAL_PORT1
#define SERIAL_PORT_MAX MODEM_STATUS_REGISTER

void serial_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
