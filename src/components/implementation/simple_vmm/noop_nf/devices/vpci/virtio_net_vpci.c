#include "vpci.h"

#define VIRTIO_VENDOR_ID	0x1AF4
#define VIRTIO_NETWORK_DEV_ID	0x1000
#define	VIRTIO_CLASS_NETWORK	0x02
#define	VIRTIO_TYPE_NET		1

struct vpci_config_type0 virtio_net_dev = {
	.header.vendor_id = VIRTIO_VENDOR_ID,
	.header.device_id = VIRTIO_NETWORK_DEV_ID,
	.header.command = 0,
	.header.status = 0,
	.header.revision_id = 0,
	.header.prog_if = 0,
	.header.subclass = 0,
	.header.class_code = VIRTIO_CLASS_NETWORK,
	.header.cache_line_sz = 0,
	.header.latency_timer = 0,
	.header.header_type = PCI_HDR_TYPE_DEV,
	.header.BIST = 0,

	/* Legacy virtio-net only uses bar 0, and it should be a IO bar, no capability is supported */
	.bars[0].io_bar.fixed_bit = 1,
	.bars[0].io_bar.reserved = 0,
	.bars[0].io_bar.base_addr = 0x1000,


	.bars[1].raw_data = 0,
	.bars[2].raw_data = 0,
	.bars[3].raw_data = 0,
	.bars[4].raw_data = 0,
	.bars[5].raw_data = 0,

	.cardbus_cis_pointer = 0,
	.subsystem_vendor_id = VIRTIO_VENDOR_ID,
	.subsystem_id = VIRTIO_TYPE_NET,
	.exp_rom_base = 0,
	.cap_pointer = 0,
	.reserved = 0,
	.interrupt_line = 0,
	.interrupt_pin = 0,
	.min_grant = 0,
	.max_lentency = 0
};

void
virtio_net_dev_init(void){
	vpci_regist((struct vpci_config_space *)&virtio_net_dev, sizeof(virtio_net_dev));
	extern void virtio_net_io_init(void);
	virtio_net_io_init();
}
