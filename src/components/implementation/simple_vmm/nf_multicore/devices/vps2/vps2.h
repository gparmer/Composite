#pragma once

/* PS/2 system control port A  (port B is at 0061) */
#define PS2_CONTROL_PORT_A 0x92
#define PS2_CONTROL_PORT_B 0x61
void ps2_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
