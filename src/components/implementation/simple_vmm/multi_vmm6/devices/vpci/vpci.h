#pragma once

#include <cos_types.h>
#include <vmrt.h>

#define VPCI_CONFIG_ADDRESS				0xCF8
#define VPCI_CONFIG_DATA0				0xCFC
#define VPCI_CONFIG_DATA1				0xCFD
#define VPCI_CONFIG_DATA2				0xCFE
#define VPCI_CONFIG_DATA3				0xCFF
#define VPCI_MECHANISM_CONTROL_REG			0xCFB

#define VPCI_MAX_CONFIG_SPACE_SZ			256

#define OFFSET_VENDOR_ID				0x00
#define OFFSET_DEVICE_ID				0x02
#define OFFSET_COMMAND					0x04
#define OFFSET_STATUS					0x06
#define OFFSET_REVISION_ID				0x08
#define OFFSET_PROG_IF					0x09
#define OFFSET_SUBCLASS					0x0A
#define OFFSET_CLASS_CODE				0x0B
#define OFFSET_CACHE_LINE_SZ				0x0C
#define OFFSET_LATENCY_TIMER				0x0D
#define OFFSET_HEADER					0x0E
#define OFFSET_BIST					0x0F

#define OFFSET_BAR0					0x10
#define OFFSET_BAR1					0x14
#define OFFSET_BAR2					0x18
#define OFFSET_BAR3					0x1C
#define OFFSET_BAR4					0x20
#define OFFSET_BAR5					0x24

#define OFFSET_PRIMARY_BUS_NUM				0x18
#define OFFSET_SECONDARY_BUS_NUMBER			0x19
#define OFFSET_SUBORDINATE_BUS_NUMBER			0x1A
#define OFFSET_SECONDARY_LATENCY_TIMER			0x1B
#define OFFSET_IO_BASE					0x1C
#define OFFSET_IO_LIMIT					0x1D
#define OFFSET_SECONDARY_STATUS 			0x1E
#define OFFSET_MEMORY_BASE				0x20
#define OFFSET_MEMORY_LIMIT				0x22
#define OFFSET_PREFETCHABLE_MEMORY_BASE			0x24
#define OFFSET_PREFETCHABLE_MEMORY_LIMIT		0x26
#define OFFSET_PREFETCHABLE_BASE_UPPER_32_BITS		0x28
#define OFFSET_PREFETCHABLE_LIMIT_UPPER_32_BITS		0x2C
#define OFFSET_IO_BASE_UPPER_16_BITS			0x30
#define OFFSET_IO_LIMIT_UPPER_16_BITS			0x32
#define OFFSET_CAPABILITY_POINTER			0x34
#define OFFSET_EXPANSION_ROM_BASE_ADDRESS		0x38
#define OFFSET_INTERRUPT_LINE				0x3C
#define OFFSET_INTERRUPT_PIN				0x3D
#define OFFSET_BRIDGE_CONTROL				0x3E

#define OFFSET_CARDBUS_CIS_POINTER			0x28
#define OFFSET_SUBSYSTEM_VENDOR_ID			0x2C
#define OFFSET_SUBSYSTEM_ID				0x2E
#define OFFSET_EXP_ROM_BASE				0x30
#define OFFSET_CAP_POINTER				0x34
#define OFFSET_RESERVED					0x38
#define OFFSET_MIN_GRANT				0x3E
#define OFFSET_MAX_LENTENCY				0x3F

#define PCI_HDR_TYPE_BRIDGE				0x01
#define PCI_HDR_TYPE_DEV				0x00

struct vpci_common_header {
	u16_t	vendor_id;
	u16_t	device_id;
	u16_t	command;
	u16_t	status;
	u8_t	revision_id;
	u8_t	prog_if;
	u8_t	subclass;
	u8_t	class_code;
	u8_t	cache_line_sz;
	u8_t	latency_timer;

	union
	{
		u8_t	header_type:7;
		u8_t	MF:1;
		u8_t	header;
	};
	
	union 
	{
		u8_t completion_code:4;
		u8_t reserved:2;
		u8_t Start_BIST:1;
		u8_t BIST_capable:1;
		u8_t BIST;
	};
} __attribute__((packed));

struct mem_bar {
	u32_t fixed_bit:1;
	u32_t type:2;
	u32_t prefetchable:1;
	/* Needs to be 16-byte aligned */
	u32_t base_addr:28;
} __attribute__((packed));

struct io_bar {
	u32_t fixed_bit:1;
	u32_t reserved:1;
	/* Needs to be 4-byte aligned */
	u32_t base_addr:30;
} __attribute__((packed));

struct vpci_bar {
	union
	{
		u32_t raw_data;
		struct mem_bar mem_bar;
		struct io_bar io_bar;
	};
} __attribute__((packed));

#define PCI_TYPE0_BAR_NUM 6
#define PCI_TYPE1_BAR_NUM 2

struct vpci_config_type0 {
	struct vpci_common_header header;
	struct vpci_bar bars[PCI_TYPE0_BAR_NUM];
	u32_t cardbus_cis_pointer;
	u16_t subsystem_vendor_id;
	u16_t subsystem_id;
	u32_t exp_rom_base;
	u32_t cap_pointer;
	u32_t reserved;
	u8_t interrupt_line;
	u8_t interrupt_pin;
	u8_t min_grant;
	u8_t max_lentency;
} __attribute__((packed));

struct vpci_config_type1 {
	struct vpci_common_header header;
	struct vpci_bar bars[PCI_TYPE1_BAR_NUM];
	u8_t primary_bus_number;
	u8_t secondary_bus_number;
	u8_t subordinate_bus_number;
	u8_t secondary_latency_timer;
	u8_t io_base;
	u8_t io_limit;
	u16_t secondary_status;
	u16_t memory_base;
	u16_t memory_limit;
	u16_t prefetchable_memory_base;
	u16_t prefetchable_memory_limit;
	u32_t prefetchable_base_upper_32_bits;
	u32_t prefetchable_limit_upper_32_bits;
	u16_t io_base_upper_16_bits;
	u16_t io_limit_upper_16_bits;
	u32_t capability_pointer:8; 
	u32_t reserved:24;
	u32_t expansion_rom_base_address;
	u8_t interrupt_line;
	u8_t interrupt_pin;
	u16_t bridge_control;
} __attribute__((packed));

struct vpci_config_space {
	struct vpci_common_header header;
	char data[VPCI_MAX_CONFIG_SPACE_SZ - sizeof(struct vpci_common_header)]; 
} __attribute__((packed));

struct vpci_bdf {
	u8_t reg_offset;
	u8_t func_num:3;
	u8_t dev_num:5;
	u8_t bus_num;
	u8_t resverd:7;
	u8_t enable_bit:1;
};

void vpci_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
void vpci_regist(struct vpci_config_space *vpci, u32_t sz);
