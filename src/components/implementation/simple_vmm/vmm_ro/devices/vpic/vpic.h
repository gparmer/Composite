#pragma once

#define PIC_MASTER_CMD_PORT			0x20
#define PIC_MASTER_DATA_PORT			0x21
#define PIC_SLAVE_CMD_PORT			0XA0
#define PIC_SLAVE_DATA_PORT			0XA1

#define ICW1_ICW4				0x01
#define ICW1_SINGLE				0x02
#define ICW1_INTERVAL4				0x04
#define ICW1_LEVEL				0x08
#define ICW1_INIT				0x10
 
#define ICW4_8086				0x01
#define ICW4_AUTO				0x02
#define ICW4_BUF_SLAVE				0x08
#define ICW4_BUF_MASTER				0x0C
#define ICW4_SFNM				0x10

#define PIC_EOI					0x20
#define PIC_ELCR1				0x4d0
#define PIC_ELCR2				0x4d1

void vpic_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
