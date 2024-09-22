#pragma once

#define CMOS_CMD_PORT	0x70
#define CMOS_DATA_PORT	0x71

void
vrtc_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
