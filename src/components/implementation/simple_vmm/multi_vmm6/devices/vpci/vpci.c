#include <cos_types.h>
#include <cos_debug.h>
#include "vpci.h"

/* Only two are supported: one bridge pci and one virtio-net pci */
#define MAX_VPCI_NUM 2

#define PCI_HOST_BRIDGE_VENDOR		0x8086
#define PCI_HOST_BRIDGE_DEV		0x29C0
#define	PCI_CLASS_BRIDGE		0x06
#define PCI_SUBCLASS_BRIDGE_HOST	0x00

struct vpci_config_space vpci_devs[MAX_VPCI_NUM];
static u8_t free_dev = 0;

struct vpci_config_type1 vpci_host_bridge = {
	.header.vendor_id = PCI_HOST_BRIDGE_VENDOR,
	.header.device_id = PCI_HOST_BRIDGE_DEV,
	.header.command = 0,
	.header.status = 0,
	.header.revision_id = 0,
	.header.prog_if = 0,
	.header.subclass = PCI_SUBCLASS_BRIDGE_HOST,
	.header.class_code = PCI_CLASS_BRIDGE,
	.header.cache_line_sz = 0,
	.header.latency_timer = 0,
	.header.header_type = PCI_HDR_TYPE_BRIDGE,
	.header.BIST = 0,

	.bars[0].raw_data = 0,
	.bars[1].raw_data = 0,

	.primary_bus_number = 0,
	.secondary_bus_number = 0,
	.subordinate_bus_number = 0, 
	.secondary_latency_timer = 0,
	.io_base = 0,
	.io_limit = 0,
	.secondary_status = 0,
	.memory_base = 0,
	.memory_limit = 0,
	.prefetchable_memory_base = 0,
	.prefetchable_memory_limit = 0,
	.prefetchable_base_upper_32_bits = 0,
	.prefetchable_limit_upper_32_bits = 0,
	.io_base_upper_16_bits = 0,
	.io_limit_upper_16_bits = 0,
	.capability_pointer = 0,
	.reserved = 0,
	.expansion_rom_base_address = 0,
	.interrupt_line = 0,
	.interrupt_pin = 0,
	.bridge_control = 0
};

void
vpci_regist(struct vpci_config_space *vpci, u32_t sz)
{
	memcpy(&vpci_devs[free_dev++], vpci, sz);
}

void
set_vpci_comm_hdr(u8_t* raw_data, u8_t reg, u32_t val)
{
	switch (reg)
	{
	/* TODO: implement necessary pci write emulations */
	case OFFSET_COMMAND:
		break;
	case OFFSET_CACHE_LINE_SZ:
		break;
	case OFFSET_LATENCY_TIMER:
		break;
	case OFFSET_STATUS:
		/* Linux writes 0xFFFF to clear errors, thus ignore it */
		break;
	default:
		printc("trying to write RO reg:0x%x, val:0x%x", reg, val);
		assert(0);
	}
}

void
set_vpci_bar(u8_t* raw_data, u8_t reg, u32_t val)
{
	u32_t bar0;

	switch (reg)
	{
	case OFFSET_BAR0:
		bar0 = *(u32_t *)raw_data;
		if (bar0 & 0x1) { /* IO bar */
			/* mask all bits that should not be writable */
			val = val & 0xFFFFC000; 
			val |= 0x1;
			*(u32_t *)raw_data = val;
		} else { /* Mem bar */
			/* Currently don't support IO bar */
			printc("no vpci bar\n");
			assert(0);
		}

		break;
	/* Currently only support one bar, other bars are ignored */
	case OFFSET_BAR1:
		break;
	case OFFSET_BAR2:
		break;
	case OFFSET_BAR3:
		break;
	case OFFSET_BAR4:
		break;
	case OFFSET_BAR5:
		break;
	default:
		printc("trying to write RO reg:0x%x, val:0x%x", reg, val);
		assert(0);
	}
}

void
set_vpci_host_bridge_reg(u8_t *raw_data, u8_t reg, u32_t val, u8_t sz)
{
	if (reg < OFFSET_BAR0) {
		set_vpci_comm_hdr(raw_data, reg, val);
		return;
	}

	if (reg < OFFSET_PRIMARY_BUS_NUM) {
		/* transparent bridge, ignore the write */
		return;
	}

	switch (reg)
	{
	case OFFSET_PRIMARY_BUS_NUM:
		*raw_data = (u8_t) val;
		break;
	case OFFSET_SECONDARY_BUS_NUMBER:
		*raw_data = (u8_t) val;
		break;
	case OFFSET_SUBORDINATE_BUS_NUMBER:
		*raw_data = (u8_t) val;
		break;
	case OFFSET_SECONDARY_LATENCY_TIMER:
		/* Currently ignore this */
		break;
	case OFFSET_IO_BASE:
		/* this bridge won't support IO base */
		break;
	case OFFSET_IO_LIMIT:
		/* this bridge won't support IO base */
		assert(0);
		break;
	case OFFSET_SECONDARY_STATUS:
		assert(0);
		break;
	case OFFSET_MEMORY_BASE:
		/* Currently ignore this */
		break;
	case OFFSET_MEMORY_LIMIT:
		assert(0);
		break;
	case OFFSET_PREFETCHABLE_MEMORY_BASE:
		/* Currently ignore this */
		break;
	case OFFSET_PREFETCHABLE_MEMORY_LIMIT:
		printc("trying to write RO reg:0x%x, val:0x%x", reg, val);
		assert(0);
		break;
	case OFFSET_PREFETCHABLE_BASE_UPPER_32_BITS:
		/* Currently ignore this */
		break;
	case OFFSET_PREFETCHABLE_LIMIT_UPPER_32_BITS:
		/* Currently ignore this */
		break;
	case  OFFSET_IO_BASE_UPPER_16_BITS:
		/* Currently ignore this */
		break;
	case OFFSET_IO_LIMIT_UPPER_16_BITS:
		assert(0);
		break;
	case OFFSET_CAPABILITY_POINTER:
		assert(0);
		break;
	case OFFSET_EXPANSION_ROM_BASE_ADDRESS:
		/* Ingore this, we don't support EXP ROM */
		break;
	case OFFSET_INTERRUPT_LINE:
		assert(0);
		break;
	case OFFSET_INTERRUPT_PIN:
		assert(0);
		break;
	case OFFSET_BRIDGE_CONTROL:
		/* Currently ignore this */
		break;
	default:
		assert(0);
	}
}

void
set_vpci_dev_reg(u8_t* raw_data, u8_t reg, u32_t val, u8_t sz)
{
	if (reg < OFFSET_BAR0) {
		set_vpci_comm_hdr(raw_data, reg, val);
		return;
	}

	if (reg < OFFSET_CARDBUS_CIS_POINTER) {
		set_vpci_bar(raw_data, reg, val);
		return;
	}
	switch (reg)
	{
	case OFFSET_CARDBUS_CIS_POINTER:
		assert(0);
		break;
	case OFFSET_SUBSYSTEM_VENDOR_ID:
		assert(0);
		break;
	case OFFSET_SUBSYSTEM_ID:
		assert(0);
		break;
	case OFFSET_EXP_ROM_BASE:
		/* Currently ignore this */
		break;
	case OFFSET_CAP_POINTER:
		assert(0);
		break;
	case OFFSET_RESERVED:
		assert(0);
		break;
	case OFFSET_INTERRUPT_LINE:
		assert(0);
		break;
	case OFFSET_INTERRUPT_PIN:
		assert(0);
		break;
	case OFFSET_MIN_GRANT:
		assert(0);
		break;
	case OFFSET_MAX_LENTENCY:
		assert(0);
		break;
	default:
		assert(0);
	}
}

void
set_vpci_reg(u32_t bdf, u32_t val, u8_t idx, u8_t sz)
{
	struct vpci_bdf vbdf;
	u8_t index;
	struct vpci_config_space *vpci;
	u8_t *raw_data;
	u8_t reg;

	assert(idx < 4 && sz > 0 && sz < 4);

	memcpy(&vbdf, &bdf, sizeof(vbdf));

	index = vbdf.bus_num + vbdf.dev_num;
	if (vbdf.bus_num > 0 || vbdf.dev_num > 1) return;

	vpci = &vpci_devs[index];

	raw_data = (u8_t *)(vpci) + vbdf.reg_offset;

	raw_data += idx;
	reg = vbdf.reg_offset + idx;

	switch (index)
	{
	case 0:
		/* Process host bridge */
		set_vpci_host_bridge_reg(raw_data, reg, val, sz);
		break;

	case 1:
		/* Process with device */
		set_vpci_dev_reg(raw_data, reg, val, sz);
		break;
	default:
		assert(0);
	}
}

u32_t
get_vpci_reg(u32_t bdf)
{
	struct vpci_bdf vbdf;
	struct vpci_config_space *vpci;
	u8_t index;

	memcpy(&vbdf, &bdf, sizeof(vbdf));
	index = vbdf.bus_num + vbdf.dev_num;

	if (vbdf.bus_num > 0 || vbdf.dev_num > 1) return 0XFFFFFFFF;

	vpci = &vpci_devs[index];

	return *(u32_t *)((char *)(vpci) + vbdf.reg_offset);
}

extern void virtio_net_dev_init(void);

static void __attribute__((constructor))
init(void)
{
	memset(&vpci_devs, 0, sizeof(vpci_devs));
	vpci_regist((struct vpci_config_space *)&vpci_host_bridge, sizeof(vpci_host_bridge));
	virtio_net_dev_init();
}
