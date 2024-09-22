#include <vmrt.h>
#include "devices/serial/serial.h"
#include "devices/vpci/vpci.h"
#include "devices/vpic/vpic.h"
#include "devices/vrtc/vrtc.h"
#include "devices/vps2/vps2.h"
#include "devices/vpci/virtio_net_io.h"

void 
io_handler(struct vmrt_vm_vcpu *vcpu)
{
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;
	u64_t qualification = regs->qualification;

	u16_t port_id = (qualification >> 16) & 0XFFFF;
	u8_t access_sz = qualification & 7;
	u8_t access_dir = (qualification >> 3) & 1;

	assert(!((qualification >> 4) & 1));
	assert(!((qualification >> 5) & 1));

	switch (access_sz)
	{
	case 0:
		access_sz = IO_BYTE;
		break;
	case 1:
		access_sz = IO_WORD;
		break;
	case 3:
		access_sz = IO_LONG;
		break;
	default:
		VM_PANIC(vcpu);
		
	}
	if (port_id == 0x3ff || port_id == 0x2f9 || port_id == 0x2fc || port_id == 0x2fb || port_id == 0x2fa || port_id == 0x2ff || port_id == 0x2f8 || port_id == 0x3e9 || port_id == 0x3ec || port_id == 0x3eb || port_id == 0x3ea || port_id == 0x3ef || port_id == 0x3e8
		 || port_id == 0x2e9 || port_id == 0x2ec || port_id == 0x2eb || port_id == 0x2ee) {
			/* TODO: fix these io ports emulcation */
			goto done;
	}
	if (port_id <= SERIAL_PORT_MAX && port_id >= SERIAL_PORT_MIN) {
		serial_handler(port_id, access_dir, access_sz, vcpu);
		goto done;
	}

	/* Fast path for virtio-net processing */
	switch (port_id)
	{
	case VIRTIO_NET_DEV_FEATURES:
	case VIRTIO_NET_GUEST_FEATURES:
	case VIRTIO_NET_QUEUE_ADDR:
	case VIRTIO_NET_QUEUE_SIZE:
	case VIRTIO_NET_QUEUE_SELECT:
	case VIRTIO_NET_QUEUE_NOTIFY:
	case VIRTIO_NET_DEV_STATUS:
	case VIRTIO_NET_ISR:
	case VIRTIO_NET_MAC:
	case VIRTIO_NET_MAC1:
	case VIRTIO_NET_MAC2:
	case VIRTIO_NET_MAC3:
	case VIRTIO_NET_MAC4:
	case VIRTIO_NET_MAC5:
	case VIRTIO_NET_STATUS:
	case VIRTIO_NET_STATUS_H:	
		virtio_net_handler(port_id, access_dir, access_sz, vcpu);
		goto done;	
	default:
		break;
	}

	switch (port_id)
	{
	case CMOS_CMD_PORT:
	case CMOS_DATA_PORT:
		vrtc_handler(port_id, access_dir, access_sz, vcpu);
		goto done;
	case PIC_MASTER_CMD_PORT:
	case PIC_MASTER_DATA_PORT:
	case PIC_SLAVE_CMD_PORT:
	case PIC_SLAVE_DATA_PORT:
	case PIC_ELCR1:
	case PIC_ELCR2:
		vpic_handler(port_id, access_dir, access_sz, vcpu);
		goto done;
	case PS2_CONTROL_PORT_A:
	case PS2_CONTROL_PORT_B:
		ps2_handler(port_id, access_dir, access_sz, vcpu);
		goto done;
	case VPCI_CONFIG_ADDRESS:
	case VPCI_CONFIG_DATA0:
	case VPCI_CONFIG_DATA1:
	case VPCI_CONFIG_DATA2:
	case VPCI_CONFIG_DATA3:
	case VPCI_MECHANISM_CONTROL_REG:
		vpci_handler(port_id, access_dir, access_sz, vcpu);
		goto done;
	}

	printc("port id:%x, sz:%d, dir:%d\n", port_id, access_sz, access_dir);
	VM_PANIC(vcpu);
done:
	GOTO_NEXT_INST(regs);
	
	return;
}