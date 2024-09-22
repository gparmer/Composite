#pragma once
#include <shared/cos_config.h>
#include <chal_config.h>

#include <vmx_utils.h>
#include <vmx_logging.h>
#include <vmx_msr.h>

/* Host encodings */
#define HOST_ES 				0x00000C00
#define HOST_CS 				0x00000C02
#define HOST_SS 				0x00000C04
#define HOST_DS 				0x00000C06
#define HOST_FS					0x00000C08
#define HOST_GS					0x00000C0A
#define HOST_TR					0x00000C0C
#define HOST_IA32_PAT				0x00002C00
#define HOST_IA32_SYSENTER_CS			0x00004C00
#define HOST_CR0				0x00006C00
#define HOST_CR3				0x00006C02
#define HOST_CR4				0x00006C04
#define HOST_FS_BASE				0x00006C06
#define HOST_GS_BASE				0x00006C08
#define HOST_TR_BASE				0x00006C0A
#define HOST_GDTR_BASE				0x00006C0C
#define HOST_IDTR_BASE				0x00006C0E
#define HOST_IA32_SYSENTER_ESP			0x00006C10
#define HOST_IA32_SYSENTER_EIP			0x00006C12
#define HOST_RSP				0x00006C14
#define HOST_RIP				0x00006C16
#define HOST_IA32_EFER				0x00002C02

/* Gguest encodings */
#define GUEST_ES				0x00000800
#define GUEST_CS				0x00000802
#define GUEST_SS				0x00000804
#define GUEST_DS				0x00000806
#define GUEST_FS				0x00000808
#define GUEST_GS				0x0000080A
#define GUEST_LDTR				0x0000080C
#define GUEST_TR				0x0000080E

#define GUEST_ES_LIMIT				0x00004800
#define GUEST_CS_LIMIT				0x00004802
#define GUEST_SS_LIMIT				0x00004804
#define GUEST_DS_LIMIT				0x00004806
#define GUEST_FS_LIMIT				0x00004808
#define GUEST_GS_LIMIT				0x0000480A
#define GUEST_LDTR_LIMIT			0x0000480C
#define GUEST_TR_LIMIT				0x0000480E
#define GUEST_GDTR_LIMIT			0x00004810
#define GUEST_IDTR_LIMIT			0x00004812

#define GUEST_ES_ACCESS_RIGHTS			0x00004814
#define GUEST_CS_ACCESS_RIGHTS			0x00004816
#define GUEST_SS_ACCESS_RIGHTS			0x00004818
#define GUEST_DS_ACCESS_RIGHTS			0x0000481A
#define GUEST_FS_ACCESS_RIGHTS			0x0000481C
#define GUEST_GS_ACCESS_RIGHTS			0x0000481E
#define GUEST_LDTR_ACCESS_RIGHTS		0x00004820
#define GUEST_TR_ACCESS_RIGHTS			0x00004822

#define GUEST_ES_BASE				0x00006806
#define GUEST_CS_BASE				0x00006808
#define GUEST_SS_BASE				0x0000680A
#define GUEST_DS_BASE				0x0000680C
#define GUEST_FS_BASE				0x0000680E
#define GUEST_GS_BASE				0x00006810
#define GUEST_LDTR_BASE				0x00006812
#define GUEST_TR_BASE				0x00006814
#define GUEST_GDTR_BASE				0x00006816
#define GUEST_IDTR_BASE				0x00006818

#define GUEST_INTERRUPTIBILITY_STATE		0x00004824
#define GUEST_ACTIVITY_STATE			0x00004826

#define GUEST_CR0				0x00006800
#define GUEST_CR3				0x00006802
#define GUEST_CR4				0x00006804

#define CR0_MASK				0x00006000U
#define CR4_MASK				0x00006002U
#define CR0_READ_SHADOW    			0x00006004U
#define CR4_READ_SHADOW    			0x00006006U

#define GUEST_DR7				0x0000681A
#define GUEST_RSP				0x0000681C
#define GUEST_RIP				0x0000681E
#define GUEST_RFLAG				0x00006820

#define GUEST_IA32_PAT				0x00002804
#define GUEST_IA32_EFER				0x00002806

#define GUEST_IA32_SYSENTER_CS			0x0000482A
#define GUEST_IA32_SYSENTER_ESP			0x00006824
#define GUEST_IA32_SYSENTER_EIP			0x00006826

#define GUEST_VMCS_LINK_POINTER_FULL		0x00002800
#define GUEST_VMCS_LINK_POINTER_HIGH		0x00002801
#define GUEST_INTERRUPT_STATUS			0x00000810

#define EPTP					0x0000201A
#define VPID					0x00000000

#define VM_INSTRUCTION_ERROR			0x00004400

#define PIN_BASED_VM_EXECUTION_CONTROLS		0x00004000
#define PRI_PROC_BASED_VM_EXECUTION_CONTROLS	0x00004002
#define SEC_PROC_BASED_VM_EXECUTION_CONTROLS	0x0000401E
#define PRIMARY_VM_EXIT_CONTROLS		0x0000400C
#define VM_ENTRY_CONTROLS			0x00004012
#define VM_ENTRY_INTERRUPTION_INFORMATION_FIELD	0x00004016

#define EXIT_REASON				0x00004402
#define EXIT_INSTRUCTION_LENGTH			0x0000440C
#define EXIT_INSTRUCTION_INFORMATION		0x0000440E
#define EXIT_QUALIFICATION			0x00006400
#define EXIT_GUEST_PHYSICAL_ADDRESS		0x00002400
#define EXIT_GUEST_LINEAR_ADDRESS		0x0000640A

#define MSR_BITMAPS_ADDRESS			0x00002004
#define LAPIC_ACCESS_ADDRESS			0x00002014
#define VAPIC_ACCESS_ADDRESS			0x00002012

#define POSTED_INTERRUPT_NOTIFICATION_VECTOR	0x00000002
#define POSTED_INTERRUPT_DESCRIPTOR		0x00002016

#define EXTERNAL_INTERRUPT_EXITING		BIT(0)
#define PROCESS_POSTED_INTERRUPTS		BIT(7)

#define HLT_EXITING				BIT(7)
#define INVLPG_EXITING				BIT(9)
#define MWAIT_EXITING				BIT(10)
#define RDPMC_EXITING				BIT(11)
#define RDTSC_EXITING				BIT(12)
#define ACTIVATE_TERTIARY_CONTROLS		BIT(17)
#define UNCONDITIONAL_IO_EXITING		BIT(24)
#define USE_MSR_BITMAPS				BIT(28)
#define USE_TPR_SHADOW				BIT(21)
#define PAUSE_EXITING				BIT(30)
#define ACTIVATE_SECONDARY_CONTROLS		BIT(31)

#define VIRTUALIZE_APIC_ACCESSES		BIT(0)
#define ENABLE_EPT				BIT(1)
#define ENABLE_RDTSCP				BIT(3)
#define VIRTUALIZE_x2APIC_MODE			BIT(4)
#define ENABLE_VPID				BIT(5)
#define UNRESTRICTED_GUEST			BIT(7)
#define APIC_REGISTER_VIRTUALIZATION		BIT(8)
#define VIRTUAL_INTERRUPT_DELIVERY		BIT(9)
#define PAUSE_LOOP_EXITING			BIT(10)
#define ENABLE_INVPCID				BIT(12)
#define ENABLE_XSAVES_XRSTORS			BIT(20)
#define ENABLE_USER_WAIT_AND_PAUSE		BIT(26)

#define HOST_ADDRESS_SPACE_SIZE			BIT(9)
#define ACKNOWLEDGE_INTERRUPT_ON_EXIT		BIT(15)
#define EXIT_SAVE_IA32_PAT			BIT(18)
#define EXIT_LOAD_IA32_PAT			BIT(19)
#define EXIT_SAVE_IA32_EFER			BIT(20)
#define EXIT_LOAD_IA32_EFER			BIT(21)

#define ENTRY_LOAD_IA32_PAT			BIT(14)
#define ENTRY_LOAD_IA32_EFER			BIT(15)

static inline void
load_vmcs(u8_t *vmcs)
{
	u64_t pa = chal_va2pa(vmcs);
	__asm__ volatile ("vmptrld (%%rax)": : "a"(&pa) : "memory", "cc");
}

static inline u64_t
vmread(u32_t encoding)
{
	u64_t value;
	__asm__ volatile ("vmread %%rdx, %%rax" :"=a" (value) :"d"(encoding) :"cc");
	return value;
}

static inline void
vmwrite(u32_t encoding, u64_t value)
{
	__asm__ volatile ("vmwrite %%rax, %%rdx ": :"a" (value), "d"(encoding): "cc");
}

static inline u32_t
vmx_get_revision_id(void)
{
	u64_t tmp64;
	u32_t low, high, mem_type;

	tmp64 = msr_get(IA32_VMX_BASIC);

	/* Bit-31 is always 0 */
	vmx_assert(((u32_t)tmp64 & 0x80000000) == 0);

	return (u32_t)tmp64;
}

static void
vmx_on(void *vmxon_region)
{
	/* The ncecssary routine to enable vmx feature on cpu */
	u64_t vmxon_region_pa;
	u64_t tmp;
	u32_t low, high, mem_type;
	u16_t ret = 0;

	void *vmxon_region_va = vmxon_region;

	tmp = msr_get(IA32_VMX_BASIC);
	low = (u32_t)tmp;
	high = (u32_t)(tmp >> 32);

	/* Bit-31 is always 0 */
	vmx_assert((low & 0x80000000) == 0);

	VMX_DEBUG("IA32_VMX_BASIC: 0x%p\n", tmp);

	VMX_DEBUG("VMX revision identifier: 0x%x\n", low & 0x7FFFFFFF);
	VMX_DEBUG("VMCS size is 0x%x(%d) bytes\n", high & ((1 << 13) - 1), high & ((1 << 13) - 1));

	mem_type = (tmp >> 50) & 0xF;

	/* TODO: need to put this somewhere else */
	enum mem_type {
		UNCACHEABLE = 0,
		WRITE_BACK = 6,
	};

	/* Modern cpu should be WB, if not, panic */
	vmx_assert(mem_type == WRITE_BACK);

	/* Assume processor supports INS and OUTS information report on VM-exit */
	vmx_assert(high & 0x400000);

	/* Assume processor supports true execution control bits */
	vmx_assert(high & 0x800000);

	memcpy(vmxon_region_va, (void *)&low, 4U);

	vmxon_region_pa = chal_va2pa(vmxon_region_va);
	vmx_assert((vmxon_region_pa % PAGE_SIZE_4K) == 0);

	VMX_DEBUG("VMXON page:0x%p\n", vmxon_region_pa);

	CR_GET(cr0, &tmp);
	tmp |= (1UL << 5);
	VMX_DEBUG("CR0: 0x%p\n", tmp);
	CR_SET(cr0, tmp);

	CR_GET(cr4, &tmp);
	tmp |= (1UL << 13);
	VMX_DEBUG("CR4: 0x%p\n", tmp);
	CR_SET(cr4, tmp);

	__asm__ volatile("xorw %%dx, %%dx; clc; mov $0x1, %%cx; vmxon %1; cmovnc %%cx, %%dx;" :"=d"(ret) :"m"(vmxon_region_pa) :"memory", "cc", "rcx");

	/* TODO: handle error case */
	if (!ret) {
		VMX_ERROR("VMXON failed\n");
	}

	VMX_INFO("VMXON initialization OK!\n");
}
