#include <cos_types.h>
#include <cos_debug.h>
#include <stddef.h>
#include <string.h>
#include <vmrt.h>
#include <vmx_msr.h>
#include "cpu.h"
#include "cpuid.h"
#include "vcpuid.h"
#include "cpu_caps.h"
#include "apicreg.h"

/*
 * Copyright (C) 2018-2022 Intel Corporation.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

static struct cpuinfo_x86 boot_cpu_data;
static struct vcpuid_entry vcpuid_entries[MAX_VM_VCPUID_ENTRIES];
static u32_t g_entry_nr = 0, g_vcpuid_level, g_vcpuid_xlevel;
void memcpy_erms(void *d, const void *s, size_t slen)
{
	asm volatile ("rep; movsb"
		: "=&D"(d), "=&S"(s)
		: "c"(slen), "0" (d), "1" (s)
		: "memory");
}

static uint64_t get_address_mask(uint8_t limit)
{
	return ((1UL << limit) - 1UL) & PAGE_MASK;
}

/*
 * @brief  Copies at most slen bytes from src address to dest address, up to dmax.
 *
 *   INPUTS
 *
 * @param[in] d        pointer to Destination address
 * @param[in] dmax     maximum  length of dest
 * @param[in] s        pointer to Source address
 * @param[in] slen     maximum number of bytes of src to copy
 *
 * @return 0 for success and -1 for runtime-constraint violation.
 */
int32_t memcpy_s(void *d, size_t dmax, const void *s, size_t slen)
{
	int32_t ret = -1;

	if ((d != NULL) && (s != NULL) && (dmax >= slen) && ((d > (s + slen)) || (s > (d + dmax)))) {
		if (slen != 0U) {
			memcpy_erms(d, s, slen);
		}
		ret = 0;
	} else {
		(void)memset(d, 0U, dmax);
	}

	return ret;
}

uint32_t get_tsc_khz(void)
{
	//3100.000 MHz 
	return 3100000;
}

struct cpuinfo_x86 *get_pcpu_info(void)
{
	return &boot_cpu_data;
}

/**
 * initialization of virtual CPUID leaf
 */
static void init_vcpuid_entry(uint32_t leaf, uint32_t subleaf,
			uint32_t flags, struct vcpuid_entry *entry)
{
	struct cpuinfo_x86 *cpu_info;

	entry->leaf = leaf;
	entry->subleaf = subleaf;
	entry->flags = flags;

	switch (leaf) {

	case 0x06U:
		cpuid_subleaf(leaf, subleaf, &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);
		entry->eax &= ~(CPUID_EAX_DTHERM | CPUID_EAX_HWP | CPUID_EAX_HWP_N | CPUID_EAX_HWP_AW | CPUID_EAX_HWP_EPP | CPUID_EAX_HWP_PLR);
		entry->ecx &= ~CPUID_ECX_HCFC;
		break;

	case 0x07U:
		if (subleaf == 0U) {
			cpuid_subleaf(leaf, subleaf, &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);

			entry->ebx &= ~(CPUID_EBX_PQM | CPUID_EBX_PQE);

			entry->eax &= ~CPUID_EAX_XCR0_BNDREGS;
			entry->eax &= ~CPUID_EAX_XCR0_BNDCSR;
			entry->ebx &= ~CPUID_EBX_AVX512;

			/* mask LA57 */
			entry->ecx &= ~CPUID_ECX_LA57;

			/* mask CPUID_EDX_IBRS_IBPB */
			entry->edx &= ~CPUID_EDX_IBRS_IBPB;

			/* mask SGX and SGX_LC */
			entry->ebx &= ~CPUID_EBX_SGX;
			entry->ecx &= ~CPUID_ECX_SGX_LC;

			/* mask MPX */
			entry->ebx &= ~CPUID_EBX_MPX;

			/* mask Intel Processor Trace, since 14h is disabled */
			entry->ebx &= ~CPUID_EBX_PROC_TRC;

			/* mask CET shadow stack and indirect branch tracking */
			entry->ecx &= ~CPUID_ECX_CET_SS;
			entry->edx &= ~CPUID_EDX_CET_IBT;

			// entry->ebx &= ~CPUID_EBX_FSGSBASE;

			entry->ebx &= ~CPUID_EBX_SMEP;

			entry->ebx &= ~CPUID_EBX_SMAP;

			entry->ecx &= ~CPUID_ECX_UMIP;

			entry->ecx &= ~CPUID_ECX_PKE;

			entry->ecx &= ~CPUID_ECX_LA57;

			entry->ecx &= ~CPUID_ECX_PKS;
		} else {
			entry->eax = 0U;
			entry->ebx = 0U;
			entry->ecx = 0U;
			entry->edx = 0U;
		}
		break;

	case 0x16U:
		cpu_info = get_pcpu_info();
		if (cpu_info->cpuid_level >= 0x16U) {
			/*
			 * call the cpuid when 0x16 is supported,
			 * but nested vmx will not return correct values,
			 * thus use the second way here. If you are using
			 * the real hardware, can test if this will work.
			 */
			// cpuid_subleaf(leaf, subleaf, &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);

			/* Use the tsc to derive the emulated 0x16U cpuid. */
			entry->eax = (uint32_t) (get_tsc_khz() / 1000U);
			entry->ebx = entry->eax;
			/* Bus frequency: hard coded to 100M */
			entry->ecx = 100U;
			entry->edx = 0U;

		} else {
			/* Use the tsc to derive the emulated 0x16U cpuid. */
			entry->eax = (uint32_t) (get_tsc_khz() / 1000U);
			entry->ebx = entry->eax;
			/* Bus frequency: hard coded to 100M */
			entry->ecx = 100U;
			entry->edx = 0U;
		}
		break;

	/*
	 * Leaf 0x40000000
	 * This leaf returns the CPUID leaf range supported by the
	 * hypervisor and the hypervisor vendor signature.
	 *
	 * EAX: The maximum input value for CPUID supported by the
	 *	hypervisor.
	 * EBX, ECX, EDX: Hypervisor vendor ID signature.
	 */
	case 0x40000000U:
	{
		static const char sig[12] = "ACRNACRNACRN";
		const uint32_t *sigptr = (const uint32_t *)sig;

		entry->eax = 0x40000010U;
		entry->ebx = sigptr[0];
		entry->ecx = sigptr[1];
		entry->edx = sigptr[2];
		break;
	}

	/*
	 * Leaf 0x40000001 - ACRN extended information.
	 * This leaf returns the extended information of ACRN hypervisor.
	 *
	 * EAX: Guest capability flags
	 * EBX, ECX, EDX: RESERVED (reserved fields are set to zero).
	 */
	case 0x40000001U:
		entry->eax = 0U;
		entry->ebx = 0U;
		entry->ecx = 0U;
		entry->edx = 0U;
		break;

	/*
	 * Leaf 0x40000010 - Timing Information.
	 * This leaf returns the current TSC frequency and
	 * current Bus frequency in kHz.
	 *
	 * EAX: (Virtual) TSC frequency in kHz.
	 *      TSC frequency is calculated from PIT in ACRN
	 * EBX, ECX, EDX: RESERVED (reserved fields are set to zero).
	 */
	case 0x40000010U:
		entry->eax = get_tsc_khz();
		entry->ebx = 0U;
		entry->ecx = 0U;
		entry->edx = 0U;
		break;

	default:
		cpuid_subleaf(leaf, subleaf, &entry->eax, &entry->ebx, &entry->ecx, &entry->edx);
		break;
	}
}

static inline int32_t set_vcpuid_entry(struct vcpuid_entry vcpuid_entries[],
				const struct vcpuid_entry *entry)
{
	struct vcpuid_entry *tmp;
	size_t entry_size = sizeof(struct vcpuid_entry);
	int32_t ret;

	if (g_entry_nr == MAX_VM_VCPUID_ENTRIES) {
		printc("%s, vcpuid entry over MAX_VM_VCPUID_ENTRIES(%u)\n", __func__, MAX_VM_VCPUID_ENTRIES);
		ret = -ENOMEM;
	} else {
		tmp = &vcpuid_entries[g_entry_nr];
		g_entry_nr++;
		(void)memcpy_s(tmp, entry_size, entry, entry_size);
		ret = 0;
	}
	return ret;
}

static inline bool is_percpu_related(uint32_t leaf)
{
	return ((leaf == 0x1U) || (leaf == 0xbU) || (leaf == 0xdU) || (leaf == 0x19U) || (leaf == 0x80000001U) || (leaf == 0x2U) || (leaf == 0x1aU));
}

static int32_t set_vcpuid_extended_function(void)
{
	uint32_t i, limit;
	struct vcpuid_entry entry;
	int32_t result;

	init_vcpuid_entry(0x40000000U, 0U, 0U, &entry);
	result = set_vcpuid_entry(vcpuid_entries, &entry);
	if (result == 0) {
		init_vcpuid_entry(0x40000001U, 0U, 0U, &entry);

		result = set_vcpuid_entry(vcpuid_entries, &entry);
	}

	if (result == 0) {
		init_vcpuid_entry(0x40000010U, 0U, 0U, &entry);
		result = set_vcpuid_entry(vcpuid_entries, &entry);
	}

	if (result == 0) {
		init_vcpuid_entry(0x80000000U, 0U, 0U, &entry);
		result = set_vcpuid_entry(vcpuid_entries, &entry);
	}

	if (result == 0) {
		limit = entry.eax;
		g_vcpuid_xlevel = limit;
		for (i = 0x80000002U; i <= limit; i++) {
			init_vcpuid_entry(i, 0U, 0U, &entry);
			result = set_vcpuid_entry(vcpuid_entries, &entry);
			if (result != 0) {
				break;
			}
		}
	}

	return result;
}

void init_pcpu_capabilities(void)
{
	uint32_t eax, unused;
	uint32_t family_id, model_id, displayfamily, displaymodel;

	cpuid_subleaf(CPUID_VENDORSTRING, 0x0U,
		&boot_cpu_data.cpuid_level,
		&unused, &unused, &unused);

	cpuid_subleaf(CPUID_FEATURES, 0x0U, &eax, &unused,
		&boot_cpu_data.cpuid_leaves[FEAT_1_ECX],
		&boot_cpu_data.cpuid_leaves[FEAT_1_EDX]);

	/* SDM Vol.2A 3-211 states the algorithm to calculate DisplayFamily and DisplayModel */
	family_id = (eax >> 8U) & 0xfU;
	displayfamily = family_id;
	if (family_id == 0xFU) {
		displayfamily += ((eax >> 20U) & 0xffU);
	}
	boot_cpu_data.displayfamily = (uint8_t)displayfamily;

	model_id = (eax >> 4U) & 0xfU;
	displaymodel = model_id;
	if ((family_id == 0x06U) || (family_id == 0xFU)) {
		displaymodel += ((eax >> 16U) & 0xfU) << 4U;
	}
	boot_cpu_data.displaymodel = (uint8_t)displaymodel;


	cpuid_subleaf(CPUID_EXTEND_FEATURE, 0x0U, &unused,
		&boot_cpu_data.cpuid_leaves[FEAT_7_0_EBX],
		&boot_cpu_data.cpuid_leaves[FEAT_7_0_ECX],
		&boot_cpu_data.cpuid_leaves[FEAT_7_0_EDX]);

	cpuid_subleaf(CPUID_EXTEND_FEATURE, 0x2U, &unused, &unused, &unused,
		&boot_cpu_data.cpuid_leaves[FEAT_7_2_EDX]);

	cpuid_subleaf(CPUID_MAX_EXTENDED_FUNCTION, 0x0U,
		&boot_cpu_data.extended_cpuid_level,
		&unused, &unused, &unused);

	if (boot_cpu_data.extended_cpuid_level >= CPUID_EXTEND_FUNCTION_1) {
		cpuid_subleaf(CPUID_EXTEND_FUNCTION_1, 0x0U, &unused, &unused,
			&boot_cpu_data.cpuid_leaves[FEAT_8000_0001_ECX],
			&boot_cpu_data.cpuid_leaves[FEAT_8000_0001_EDX]);
	}

	if (boot_cpu_data.extended_cpuid_level >= CPUID_EXTEND_INVA_TSC) {
		cpuid_subleaf(CPUID_EXTEND_INVA_TSC, 0x0U, &eax, &unused, &unused,
			&boot_cpu_data.cpuid_leaves[FEAT_8000_0007_EDX]);
	}

	if (boot_cpu_data.extended_cpuid_level >= CPUID_EXTEND_ADDRESS_SIZE) {
		cpuid_subleaf(CPUID_EXTEND_ADDRESS_SIZE, 0x0U, &eax,
			&boot_cpu_data.cpuid_leaves[FEAT_8000_0008_EBX],
			&unused, &unused);

			/* EAX bits 07-00: #Physical Address Bits
			 *     bits 15-08: #Linear Address Bits
			 */
			boot_cpu_data.virt_bits = (uint8_t)((eax >> 8U) & 0xffU);
			boot_cpu_data.phys_bits = (uint8_t)(eax & 0xffU);
			boot_cpu_data.physical_address_mask =
				get_address_mask(boot_cpu_data.phys_bits);
	}

	// detect_pcpu_cap();
}

int32_t
set_vcpuid_entries(void)
{
	int32_t result;
	struct vcpuid_entry entry;
	uint32_t limit;
	uint32_t i, j;
	struct cpuinfo_x86 *cpu_info = get_pcpu_info();

	init_vcpuid_entry(0U, 0U, 0U, &entry);

	if (cpu_info->cpuid_level < 0x16U) {
		/* The cpuid with zero leaf returns the max level. Emulate that the 0x16U is supported */
		entry.eax = 0x16U;
	}
	result = set_vcpuid_entry(vcpuid_entries, &entry);
	if (result == 0) {
		limit = entry.eax;
		g_vcpuid_level = limit;

		for (i = 1U; i <= limit; i++) {
			if (is_percpu_related(i)) {
				continue;
			}

			switch (i) {
			case 0x04U:
				for (j = 0U; ; j++) {
					init_vcpuid_entry(i, j, CPUID_CHECK_SUBLEAF, &entry);
					if (entry.eax == 0U) {
						break;
					}

					result = set_vcpuid_entry(vcpuid_entries, &entry);
					if (result != 0) {
						/* wants to break out of switch */
						break;
					}
				}
				break;
			/* MONITOR/MWAIT */
			case 0x05U:
				break;
			case 0x07U:
				init_vcpuid_entry(i, 0U, CPUID_CHECK_SUBLEAF, &entry);
				if (entry.eax != 0U) {
					printc("vcpuid: only support subleaf 0 for cpu leaf 07h\n");
					entry.eax = 0U;
				}
				/* mask CPUID_EDX_IBRS_IBPB */
				entry.edx &= ~CPUID_EDX_IBRS_IBPB;
				
				entry.ecx &= ~CPUID_ECX_WAITPKG;

				result = set_vcpuid_entry(vcpuid_entries, &entry);
				break;
			case 0x12U:
				break;
			/* These features are disabled */
			/* PMU is not supported except for core partition VM, like RTVM */
			case 0x0aU:
				break;

			/* Intel RDT */
			case 0x0fU:
				break;
			/* Intel RDT */
			case 0x10U:
				break;

			/* Intel Processor Trace */
			case 0x14U:
			/* PCONFIG */
			case 0x1bU:
			/* V2 Extended Topology Enumeration Leaf */
			case 0x1fU:
				break;
			default:
				init_vcpuid_entry(i, 0U, 0U, &entry);
				result = set_vcpuid_entry(vcpuid_entries, &entry);
				break;
			}

			/* WARNING: do nothing between break out of switch and before this check */
			if (result != 0) {
				/* break out of for */
				break;
			}
		}

		if (result == 0) {
			result = set_vcpuid_extended_function();
		}
	}

	return result;
}

static inline const struct vcpuid_entry *local_find_vcpuid_entry(uint32_t leaf, uint32_t subleaf)
{
	uint32_t i = 0U, nr, half;
	const struct vcpuid_entry *found_entry = NULL;

	nr = g_entry_nr;
	half = nr >> 1U;
	if (vcpuid_entries[half].leaf < leaf) {
		i = half;
	}

	for (; i < nr; i++) {
		const struct vcpuid_entry *tmp = (const struct vcpuid_entry *)(&vcpuid_entries[i]);

		if (tmp->leaf < leaf) {
			continue;
		} else if (tmp->leaf == leaf) {
			if (((tmp->flags & CPUID_CHECK_SUBLEAF) != 0U) && (tmp->subleaf != subleaf)) {
				continue;
			}
			found_entry = tmp;
			break;
		} else {
			/* tmp->leaf > leaf */
			break;
		}
	}

	return found_entry;
}

static inline const struct vcpuid_entry *find_vcpuid_entry(uint32_t leaf_arg, uint32_t subleaf)
{
	const struct vcpuid_entry *entry;
	uint32_t leaf = leaf_arg;

	entry = local_find_vcpuid_entry(leaf, subleaf);
	if (entry == NULL) {
		uint32_t limit;

		if ((leaf & 0x80000000U) != 0U) {
			limit = g_vcpuid_xlevel;
		} else {
			limit = g_vcpuid_level;
		}

		if (leaf > limit) {
			/* Intel documentation states that invalid EAX input
			 * will return the same information as EAX=cpuid_level
			 * (Intel SDM Vol. 2A - Instruction Set Reference -
			 * CPUID)
			 */
			leaf = g_vcpuid_level;
			entry = local_find_vcpuid_entry(leaf, subleaf);
		}

	}

	return entry;
}

static void guest_cpuid_01h(struct vmrt_vm_vcpu *vcpu, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	uint32_t apicid = 1;

	cpuid_subleaf(0x1U, 0x0U, eax, ebx, ecx, edx);
	/* Patching initial APIC ID */
	*ebx &= ~APIC_ID_MASK;
	*ebx |= (apicid <<  APIC_ID_SHIFT);

	*edx &= ~CPUID_EDX_MTRR;

	/* mask Safer Mode Extension */
	*ecx &= ~CPUID_ECX_SMX;

	*ecx &= ~CPUID_ECX_EST;

	/* mask SDBG for silicon debug */
	*ecx &= ~CPUID_ECX_SDBG;

	/* mask VMX to guest OS */
	*ecx &= ~CPUID_ECX_VMX;

	/* set Hypervisor Present Bit */
	*ecx |= CPUID_ECX_HV;

	/* Warning: should we support pcid in VM? Let's begin with not setting it first */
	*ecx &= ~CPUID_ECX_PCID;

	/*
	 * Hide MONITOR/MWAIT.
	 */
	// *ecx &= ~CPUID_ECX_MONITOR;

	/* Warning: should we support CPUID_ECX_OSXSAVE in VM? Let's begin with not setting it first */
	*ecx &= ~CPUID_ECX_OSXSAVE;
	if ((*ecx & CPUID_ECX_XSAVE) != 0U) {
		uint64_t cr4;
		/*read guest CR4*/
		cr4 = vcpu->shared_region->cr4;
		if ((cr4 & CR4_OSXSAVE) != 0UL) {
			*ecx |= CPUID_ECX_OSXSAVE;
		}
	}

	/* disable thermal ctrl*/
	*edx &= ~CPUID_EDX_TM1;

	*edx &= ~CPUID_EDX_VME;

	*edx &= ~CPUID_EDX_DE;

	*edx &= ~CPUID_EDX_PSE;

	/* Warning: it seems that PAE, PGE, FXSR should be supported */
	// *edx &= ~CPUID_EDX_PAE;

	// *edx &= ~CPUID_EDX_PGE;

	// *edx &= ~CPUID_EDX_FXSR;

	/* Don't support complex apic */
	*ecx &= ~CPUID_ECX_x2APIC;

	/* DS/PEBS is not supported except for core partition VM, like RTVM */
	/* mask Debug Store feature */
	*ecx &= ~(CPUID_ECX_DTES64 | CPUID_ECX_DS_CPL);

	/* mask PDCM: Perfmon and Debug Capability */
	*ecx &= ~CPUID_ECX_PDCM;

	/* mask Debug Store feature */
	*edx &= ~CPUID_EDX_DTES;
}

static void guest_cpuid_0bh(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	/* Forward host cpu topology to the guest, guest will know the native platform information such as host cpu topology here */
	cpuid_subleaf(0x0BU, *ecx, eax, ebx, ecx, edx);

	/* Patching X2APIC */
	*edx = 1;
}

static void guest_cpuid_0dh(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	uint32_t subleaf = *ecx;
	
	cpuid_subleaf(0x0dU, subleaf, eax, ebx, ecx, edx);
	switch (subleaf) {
	case 0U:
		/* SDM Vol.1 17-2, On processors that do not support Intel MPX,
			* CPUID.(EAX=0DH,ECX=0):EAX[3] and
			* CPUID.(EAX=0DH,ECX=0):EAX[4] will both be 0 */
		*eax &= ~(CPUID_EAX_XCR0_BNDREGS | CPUID_EAX_XCR0_BNDCSR);
		break;
	case 1U:
		*ecx &= ~(CPUID_ECX_CET_U_STATE | CPUID_ECX_CET_S_STATE);
		break;
	case 11U:
	case 12U:
		*eax = 0U;
		*ebx = 0U;
		*ecx = 0U;
		*edx = 0U;
		break;
	default:
		/* No emulation for other leaves */
		break;
	}
}

static void guest_cpuid_19h(uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	*eax = 0U;
	*ebx = 0U;
	*ecx = 0U;
	*edx = 0U;
}

static void guest_cpuid_80000001h(const struct vmrt_vm_vcpu *vcpu,
	uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	const struct vcpuid_entry *entry_check = find_vcpuid_entry(0x80000000U, 0);
	uint64_t guest_ia32_misc_enable = 0x800001;
	uint32_t leaf = 0x80000001U;

	if ((entry_check != NULL) && (entry_check->eax >= leaf)) {
		cpuid_subleaf(leaf, 0x0U, eax, ebx, ecx, edx);
		/* SDM Vol4 2.1, XD Bit Disable of MSR_IA32_MISC_ENABLE
		 * When set to 1, the Execute Disable Bit feature (XD Bit) is disabled and the XD Bit
		 * extended feature flag will be clear (CPUID.80000001H: EDX[20]=0)
		 */
		if ((guest_ia32_misc_enable & MSR_IA32_MISC_ENABLE_XD_DISABLE) != 0UL) {
			*edx = *edx & ~CPUID_EDX_XD_BIT_AVIL;
		}
	} else {
		*eax = 0U;
		*ebx = 0U;
		*ecx = 0U;
		*edx = 0U;
	}
}

static void guest_limit_cpuid(const struct vmrt_vm_vcpu *vcpu, uint32_t leaf,
	uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	uint64_t guest_ia32_misc_enable = 0x800001;

	if ((guest_ia32_misc_enable & MSR_IA32_MISC_ENABLE_LIMIT_CPUID) != 0UL) {
		/* limit the leaf number to 2 */
		if (leaf == 0U) {
			*eax = 2U;
		} else if (leaf > 2U) {
			*eax = 0U;
			*ebx = 0U;
			*ecx = 0U;
			*edx = 0U;
		} else {
			/* In this case, leaf is 1U, return the cpuid value get above */
		}
	}
}

void guest_cpuid(struct vmrt_vm_vcpu *vcpu, uint32_t *eax, uint32_t *ebx, uint32_t *ecx, uint32_t *edx)
{
	uint32_t leaf = *eax;
	uint32_t subleaf = *ecx;

	/* vm related */
	if (!is_percpu_related(leaf)) {
		const struct vcpuid_entry *entry = find_vcpuid_entry(leaf, subleaf);

		if (entry != NULL) {
			*eax = entry->eax;
			*ebx = entry->ebx;
			*ecx = entry->ecx;
			*edx = entry->edx;
		} else {
			*eax = 0U;
			*ebx = 0U;
			*ecx = 0U;
			*edx = 0U;
		}
	} else {
		/* percpu related */
		switch (leaf) {
		case 0x01U:
			guest_cpuid_01h(vcpu, eax, ebx, ecx, edx);
			break;

		case 0x0bU:
			guest_cpuid_0bh(eax, ebx, ecx, edx);
			break;

		case 0x0dU:
			guest_cpuid_0dh(eax, ebx, ecx, edx);
			break;

		case 0x19U:
			guest_cpuid_19h(eax, ebx, ecx, edx);
			break;

		case 0x80000001U:
			guest_cpuid_80000001h(vcpu, eax, ebx, ecx, edx);
			break;

		default:
			/*
			 * In this switch statement, leaf 0x01/0x0b/0x0d/0x19/0x80000001
			 * shall be handled specifically. All the other cases
			 * just return physical value.
			 */
			cpuid_subleaf(leaf, *ecx, eax, ebx, ecx, edx);
			break;
		}
	}

	guest_limit_cpuid(vcpu, leaf, eax, ebx, ecx, edx);
}

void 
cpuid_handler(struct vmrt_vm_vcpu *vcpu)
{
	uint64_t rax, rbx, rcx, rdx;
	volatile struct vm_vcpu_shared_region *regs = vcpu->shared_region;
	int test = 0;

	rax = regs->ax;
	rbx = regs->bx;
	rcx = regs->cx;
	rdx = regs->dx;

	guest_cpuid(vcpu, (uint32_t *)&rax, (uint32_t *)&rbx, (uint32_t *)&rcx, (uint32_t *)&rdx);
	
	regs->ax = rax;
	regs->bx = rbx;
	regs->cx = rcx;
	regs->dx = rdx;

	GOTO_NEXT_INST(regs);

	return;
}

static void __attribute__((constructor))
init(void)
{
	init_pcpu_capabilities();
	set_vcpuid_entries();
}
