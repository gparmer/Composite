/*-
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2017-2022 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#define pr_prefix		"vlapic: "

#include <cos_types.h>
#include <cos_debug.h>
#include <vmrt.h>
#include <cpu.h>
#include <vlapic.h>
#include <vlapic_priv.h>
#include "vpic.h"
#include "bits.h"
#include "atomic.h"

#include <errno.h>

#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#define VLAPIC_VERBOS 0

#define VLAPIC_VERSION		(16U)
#define	APICBASE_BSP		0x00000100UL
#define	APICBASE_X2APIC		0x00000400UL
#define APICBASE_XAPIC		0x00000800UL
#define APICBASE_LAPIC_MODE	(APICBASE_XAPIC | APICBASE_X2APIC)
#define	APICBASE_ENABLED	0x00000800UL
#define LOGICAL_ID_MASK		0xFU
#define CLUSTER_ID_MASK		0xFFFF0U

#define DBG_LEVEL_VLAPIC	6U

int g_vlapi_enabled = 0;

static inline struct vmrt_vm_vcpu *vlapic2vcpu(const struct acrn_vlapic *vlapic)
{
	return vlapic->vcpu;
}
static inline struct acrn_vlapic *vcpu_vlapic(struct vmrt_vm_vcpu *vcpu)
{
	return vcpu->vlapic;
}
static inline bool is_lapic_pt_configured(void)
{
	return false;
}

static inline void vlapic_dump_irr(__unused const struct acrn_vlapic *vlapic, __unused const char *msg) {}
static inline void vlapic_dump_isr(__unused const struct acrn_vlapic *vlapic, __unused const char *msg) {}

const struct acrn_apicv_ops *apicv_ops;

static bool apicv_set_intr_ready(struct acrn_vlapic *vlapic, uint32_t vector);

static void apicv_trigger_pi_anv(uint16_t dest_pcpu_id, uint32_t anv);

static void vlapic_x2apic_self_ipi_handler(struct acrn_vlapic *vlapic);

/*
 * Post an interrupt to the vcpu running on 'hostcpu'. This will use a
 * hardware assist if available (e.g. Posted Interrupt) or fall back to
 * sending an 'ipinum' to interrupt the 'hostcpu'.
 */
static void vlapic_set_error(struct acrn_vlapic *vlapic, uint32_t mask);

void vlapic_timer_expired(struct vmrt_vm_vcpu *vcpu);
static struct pi_desc *get_pi_desc(struct vmrt_vm_vcpu *vcpu);

static inline bool vlapic_enabled(const struct acrn_vlapic *vlapic)
{
	const struct lapic_regs *lapic = vlapic->apic_page;

	return (((vlapic->msr_apicbase & APICBASE_ENABLED) != 0UL) &&
			((lapic->svr.v & APIC_SVR_ENABLE) != 0U));
}

static inline void vlapic_build_x2apic_id(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;
	uint32_t logical_id, cluster_id;

	lapic = vlapic->apic_page;
	lapic->id.v = vlapic->vapic_id;
	logical_id = lapic->id.v & LOGICAL_ID_MASK;
	cluster_id = (lapic->id.v & CLUSTER_ID_MASK) >> 4U;
	lapic->ldr.v = (cluster_id << 16U) | (1U << logical_id);
}

static inline uint32_t vlapic_find_isrv(const struct acrn_vlapic *vlapic)
{
	const struct lapic_regs *lapic = vlapic->apic_page;
	uint32_t i, val, bitpos, isrv = 0U;
	const struct lapic_reg *isrptr;

	isrptr = &lapic->isr[0];

	/* i ranges effectively from 7 to 1 */
	for (i = 7U; i > 0U; i--) {
		val = isrptr[i].v;
		if (val != 0U) {
			bitpos = (uint32_t)fls32(val);
			isrv = (i << 5U) | bitpos;
			break;
		}
	}

	return isrv;
}

static void
vlapic_write_dfr(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;

	lapic = vlapic->apic_page;
	lapic->dfr.v &= APIC_DFR_MODEL_MASK;
	lapic->dfr.v |= APIC_DFR_RESERVED;

	if ((lapic->dfr.v & APIC_DFR_MODEL_MASK) == APIC_DFR_MODEL_FLAT) {
		printc("vlapic DFR in Flat Model\n");
	} else if ((lapic->dfr.v & APIC_DFR_MODEL_MASK)
			== APIC_DFR_MODEL_CLUSTER) {
		printc("vlapic DFR in Cluster Model\n");
	} else {
		assert(0);
	}
}

static void
vlapic_write_ldr(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;

	lapic = vlapic->apic_page;
	lapic->ldr.v &= ~APIC_LDR_RESERVED;
}

static inline uint32_t
vlapic_timer_divisor_shift(uint32_t dcr)
{
	uint32_t val;

	val = ((dcr & 0x3U) | ((dcr & 0x8U) >> 1U));
	return ((val + 1U) & 0x7U);
}

__unused static inline bool
vlapic_lvtt_oneshot(const struct acrn_vlapic *vlapic)
{
	return (((vlapic->apic_page->lvt[APIC_LVT_TIMER].v) & APIC_LVTT_TM)
				== APIC_LVTT_TM_ONE_SHOT);
}

static inline bool
vlapic_lvtt_period(const struct acrn_vlapic *vlapic)
{
	return (((vlapic->apic_page->lvt[APIC_LVT_TIMER].v) & APIC_LVTT_TM)
				==  APIC_LVTT_TM_PERIODIC);
}

static inline bool
vlapic_lvtt_tsc_deadline(const struct acrn_vlapic *vlapic)
{
	return (((vlapic->apic_page->lvt[APIC_LVT_TIMER].v) & APIC_LVTT_TM)
				==  APIC_LVTT_TM_TSCDLT);
}

static inline bool
vlapic_lvtt_masked(const struct acrn_vlapic *vlapic)
{
	return (((vlapic->apic_page->lvt[APIC_LVT_TIMER].v) & APIC_LVTT_M) != 0U);
}

static bool
set_expiration(struct acrn_vlapic *vlapic)
{
	struct vlapic_timer *vtimer;
	uint32_t tmicr, divisor_shift;
	bool ret;

	vtimer = &vlapic->vtimer;
	tmicr = vtimer->tmicr;
	divisor_shift = vtimer->divisor_shift;

	if ((tmicr == 0U) || (divisor_shift > 8U)) {
		ret = false;
	} else {
		uint64_t delta = (uint64_t)tmicr << divisor_shift;
		assert(0);

		ret = true;
	}
	return ret;
}

static void vlapic_update_lvtt(struct acrn_vlapic *vlapic,
			uint32_t val)
{
	uint32_t timer_mode = val & APIC_LVTT_TM;
	struct vlapic_timer *vtimer = &vlapic->vtimer;

	if (vtimer->mode != timer_mode) {
		struct hv_timer *timer = &vtimer->timer;

		/*
		 * A write to the LVT Timer Register that changes
		 * the timer mode disarms the local APIC timer.
		 */
		/* TODO: reset timer */
		vtimer->mode = timer_mode;
	}
}

static uint32_t vlapic_get_ccr(const struct acrn_vlapic *vlapic)
{
	uint32_t remain_count = 0U;
	const struct vlapic_timer *vtimer = &vlapic->vtimer;

	if ((vtimer->tmicr != 0U) && (!vlapic_lvtt_tsc_deadline(vlapic))) {
		uint64_t remains;
		assert(0);
	}

	return remain_count;
}

static void vlapic_write_dcr(struct acrn_vlapic *vlapic)
{
	uint32_t divisor_shift;
	struct vlapic_timer *vtimer;
	struct lapic_regs *lapic = vlapic->apic_page;

	vtimer = &vlapic->vtimer;
	divisor_shift = vlapic_timer_divisor_shift(lapic->dcr_timer.v);

	vtimer->divisor_shift = divisor_shift;
}

static void vlapic_write_icrtmr(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;
	struct vlapic_timer *vtimer;

	if (!vlapic_lvtt_tsc_deadline(vlapic)) {
		lapic = vlapic->apic_page;
		vtimer = &vlapic->vtimer;
		vtimer->tmicr = lapic->icr_timer.v;
	}
}

static void
vlapic_write_esr(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;

	lapic = vlapic->apic_page;
	lapic->esr.v = vlapic->esr_pending;
	vlapic->esr_pending = 0U;
}

static void
vlapic_set_tmr(struct acrn_vlapic *vlapic, uint32_t vector, bool level)
{
	struct lapic_reg *tmrptr = &(vlapic->apic_page->tmr[0]);
	if (level) {
		if (!bitmap32_test_and_set_lock((uint16_t)(vector & 0x1fU), &tmrptr[(vector & 0xffU) >> 5U].v)) {
			assert(0);
		}
	} else {
		if (bitmap32_test_and_clear_lock((uint16_t)(vector & 0x1fU), &tmrptr[(vector & 0xffU) >> 5U].v)) {
			assert(0);
		}
	}
}

static void apicv_basic_accept_intr(struct acrn_vlapic *vlapic, uint32_t vector, bool level)
{
	struct lapic_regs *lapic;
	struct lapic_reg *irrptr;
	uint32_t idx;

	lapic = vlapic->apic_page;
	idx = vector >> 5U;
	irrptr = &lapic->irr[0];

	/* If the interrupt is set, don't try to do it again */
	if (!bitmap32_test_and_set_lock((uint16_t)(vector & 0x1fU), &irrptr[idx].v)) {
		/* update TMR if interrupt trigger mode has changed */
		vlapic_set_tmr(vlapic, vector, level);
		assert(0);
	}
}

static void apicv_advanced_accept_intr(struct acrn_vlapic *vlapic, uint32_t vector, bool level)
{
	/* update TMR if interrupt trigger mode has changed */
	vlapic_set_tmr(vlapic, vector, level);

	if (apicv_set_intr_ready(vlapic, vector)) {
		/*
		 * Send interrupt to vCPU via posted interrupt way:
		 * 1. If target vCPU is in root mode(isn't running),
		 *    record this request as ACRN_REQUEST_EVENT,then
		 *    will pick up the interrupt from PIR and inject
		 *    it to vCPU in next vmentry.
		 * 2. If target vCPU is in non-root mode(running),
		 *    send PI notification to vCPU and hardware will
		 *    sync PIR to vIRR automatically.
		 */

		/* TODO: handle cross-core virtual interrupt notification */
	}
}

/*
 * @pre vector >= 16
 */
static void vlapic_accept_intr(struct acrn_vlapic *vlapic, uint32_t vector, bool level)
{
	struct lapic_regs *lapic;
	assert(vector <= 255);

	lapic = vlapic->apic_page;
	if ((lapic->svr.v & APIC_SVR_ENABLE) == 0U) {
		printc("vlapic is software disabled, ignoring interrupt %u", vector);
		assert(0);
	} else {
		apicv_advanced_accept_intr(vlapic, vector, level);
	}
}

/**
 * @brief Send notification vector to target pCPU.
 *
 * If APICv Posted-Interrupt is enabled and target pCPU is in non-root mode,
 * pCPU will sync pending virtual interrupts from PIR to vIRR automatically,
 * without VM exit.
 * If pCPU in root-mode, virtual interrupt will be injected in next VM entry.
 *
 * @param[in] dest_pcpu_id Target CPU ID.
 * @param[in] anv Activation Notification Vectors (ANV)
 *
 * @return None
 */
static void apicv_trigger_pi_anv(uint16_t dest_pcpu_id, uint32_t anv)
{
	/* TODO: support pi in the future */
	assert(0);
}

/**
 * @pre offset value shall be one of the folllowing values:
 *	APIC_OFFSET_CMCI_LVT
 *	APIC_OFFSET_TIMER_LVT
 *	APIC_OFFSET_THERM_LVT
 *	APIC_OFFSET_PERF_LVT
 *	APIC_OFFSET_LINT0_LVT
 *	APIC_OFFSET_LINT1_LVT
 *	APIC_OFFSET_ERROR_LVT
 */
static inline uint32_t
lvt_off_to_idx(uint32_t offset)
{
	uint32_t index;

	switch (offset) {
	case APIC_OFFSET_CMCI_LVT:
		index = APIC_LVT_CMCI;
		break;
	case APIC_OFFSET_TIMER_LVT:
		index = APIC_LVT_TIMER;
		break;
	case APIC_OFFSET_THERM_LVT:
		index = APIC_LVT_THERMAL;
		break;
	case APIC_OFFSET_PERF_LVT:
		index = APIC_LVT_PMC;
		break;
	case APIC_OFFSET_LINT0_LVT:
		index = APIC_LVT_LINT0;
		break;
	case APIC_OFFSET_LINT1_LVT:
		index = APIC_LVT_LINT1;
		break;
	case APIC_OFFSET_ERROR_LVT:
	default:
		/*
		 * The function caller could guarantee the pre condition.
		 * So, all of the possible 'offset' other than
		 * APIC_OFFSET_ERROR_LVT has been handled in prior cases.
		 */
		index = APIC_LVT_ERROR;
		break;
	}

	return index;
}

/**
 * @pre offset value shall be one of the folllowing values:
 *	APIC_OFFSET_CMCI_LVT
 *	APIC_OFFSET_TIMER_LVT
 *	APIC_OFFSET_THERM_LVT
 *	APIC_OFFSET_PERF_LVT
 *	APIC_OFFSET_LINT0_LVT
 *	APIC_OFFSET_LINT1_LVT
 *	APIC_OFFSET_ERROR_LVT
 */
static inline uint32_t *
vlapic_get_lvtptr(struct acrn_vlapic *vlapic, uint32_t offset)
{
	struct lapic_regs *lapic = vlapic->apic_page;
	uint32_t i;
	uint32_t *lvt_ptr;

	switch (offset) {
	case APIC_OFFSET_CMCI_LVT:
		lvt_ptr = &lapic->lvt_cmci.v;
		break;
	default:
		/*
		 * The function caller could guarantee the pre condition.
		 * All the possible 'offset' other than APIC_OFFSET_CMCI_LVT
		 * could be handled here.
		 */
		i = lvt_off_to_idx(offset);
		lvt_ptr = &(lapic->lvt[i].v);
		break;
	}
	return lvt_ptr;
}

static inline uint32_t
vlapic_get_lvt(const struct acrn_vlapic *vlapic, uint32_t offset)
{
	uint32_t idx;

	idx = lvt_off_to_idx(offset);
	return vlapic->lvt_last[idx];
}

static void
vlapic_write_lvt(struct acrn_vlapic *vlapic, uint32_t offset)
{
	uint32_t *lvtptr, mask, val, idx;
	struct lapic_regs *lapic;
	bool error = false;

	lapic = vlapic->apic_page;
	lvtptr = vlapic_get_lvtptr(vlapic, offset);
	val = *lvtptr;

	if ((lapic->svr.v & APIC_SVR_ENABLE) == 0U) {
		val |= APIC_LVT_M;
	}
	mask = APIC_LVT_M | APIC_LVT_DS | APIC_LVT_VECTOR;
	switch (offset) {
	case APIC_OFFSET_TIMER_LVT:
		mask |= APIC_LVTT_TM;
		break;
	case APIC_OFFSET_ERROR_LVT:
		break;
	case APIC_OFFSET_LINT0_LVT:
	case APIC_OFFSET_LINT1_LVT:
		mask |= APIC_LVT_TM | APIC_LVT_RIRR | APIC_LVT_IIPP;
		/* FALLTHROUGH */
	default:
		mask |= APIC_LVT_DM;
		break;
	}
	val &= mask;

	/* vlapic mask/unmask LINT0 for ExtINT? */
	if ((offset == APIC_OFFSET_LINT0_LVT) &&
		((val & APIC_LVT_DM) == APIC_LVT_DM_EXTINT)) {
		uint32_t last = vlapic_get_lvt(vlapic, offset);
		struct vmrt_vm_comp *vm = vlapic2vcpu(vlapic)->vm;

		/* mask -> unmask: may from every vlapic in the vm */
		if (((last & APIC_LVT_M) != 0U) && ((val & APIC_LVT_M) == 0U)) {
			if ((vm->wire_mode == VPIC_WIRE_INTR) ||
				(vm->wire_mode == VPIC_WIRE_NULL)) {
				vm->wire_mode = VPIC_WIRE_LAPIC;
				printc("vpic wire mode -> LAPIC\n");
			} else {
				printc("WARNING:invalid vpic wire mode change\n");
				assert(0);
			}
		/* unmask -> mask: only from the vlapic LINT0-ExtINT enabled */
		} else if (((last & APIC_LVT_M) == 0U) && ((val & APIC_LVT_M) != 0U)) {
			if (vm->wire_mode == VPIC_WIRE_LAPIC) {
				vm->wire_mode = VPIC_WIRE_NULL;
				printc("vpic wire mode -> NULL\n");
			}
		} else {
			/* APIC_LVT_M unchanged. No action required. */
		}
	} else if (offset == APIC_OFFSET_TIMER_LVT) {
		vlapic_update_lvtt(vlapic, val);
	} else {
		/* No action required. */
	}

	if (!error) {
		*lvtptr = val;
		idx = lvt_off_to_idx(offset);
		vlapic->lvt_last[idx] = val;
	}
}

static void
vlapic_mask_lvts(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic = vlapic->apic_page;

	lapic->lvt_cmci.v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_CMCI_LVT);

	lapic->lvt[APIC_LVT_TIMER].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_TIMER_LVT);

	lapic->lvt[APIC_LVT_THERMAL].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_THERM_LVT);

	lapic->lvt[APIC_LVT_PMC].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_PERF_LVT);

	lapic->lvt[APIC_LVT_LINT0].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_LINT0_LVT);

	lapic->lvt[APIC_LVT_LINT1].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_LINT1_LVT);

	lapic->lvt[APIC_LVT_ERROR].v |= APIC_LVT_M;
	vlapic_write_lvt(vlapic, APIC_OFFSET_ERROR_LVT);
}

/*
 * Algorithm adopted from section "Interrupt, Task and Processor Priority"
 * in Intel Architecture Manual Vol 3a.
 */
static void
vlapic_update_ppr(struct acrn_vlapic *vlapic)
{
	uint32_t isrv, tpr, ppr;

	isrv = vlapic->isrv;
	tpr = vlapic->apic_page->tpr.v;

	if (prio(tpr) >= prio(isrv)) {
		ppr = tpr;
	} else {
		ppr = isrv & 0xf0U;
	}

	vlapic->apic_page->ppr.v = ppr;
}

static void
vlapic_process_eoi(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic = vlapic->apic_page;
	struct lapic_reg *isrptr, *tmrptr;
	uint32_t i, vector, bitpos;

	isrptr = &lapic->isr[0];
	tmrptr = &lapic->tmr[0];

	if (vlapic->isrv != 0U) {
		vector = vlapic->isrv;
		i = (vector >> 5U);
		bitpos = (vector & 0x1fU);
		bitmap32_clear_nolock((uint16_t)bitpos, &isrptr[i].v);

		vlapic_dump_isr(vlapic, "vlapic_process_eoi");

		vlapic->isrv = vlapic_find_isrv(vlapic);
		vlapic_update_ppr(vlapic);
	}
}

static void
vlapic_set_error(struct acrn_vlapic *vlapic, uint32_t mask)
{
	uint32_t lvt, vec;

	vlapic->esr_pending |= mask;
	if (vlapic->esr_firing == 0) {
		vlapic->esr_firing = 1;

		/* The error LVT always uses the fixed delivery mode. */
		lvt = vlapic_get_lvt(vlapic, APIC_OFFSET_ERROR_LVT);
		if ((lvt & APIC_LVT_M) == 0U) {
			vec = lvt & APIC_LVT_VECTOR;
			if (vec >= 16U) {
				vlapic_accept_intr(vlapic, vec, LAPIC_TRIG_EDGE);
			}
		}
		vlapic->esr_firing = 0;
	}
}

static void vlapic_write_icrlo(struct acrn_vlapic *vlapic)
{
	uint16_t vcpu_id;
	bool phys = false, is_broadcast = false;
	uint64_t dmask;
	uint32_t icr_low, icr_high, dest;
	uint32_t vec, mode, shorthand;
	struct lapic_regs *lapic;
	struct vmrt_vm_vcpu *target_vcpu;

	lapic = vlapic->apic_page;
	lapic->icr_lo.v &= ~APIC_DELSTAT_PEND;

	icr_low = lapic->icr_lo.v;
	icr_high = lapic->icr_hi.v;
	if (is_x2apic_enabled(vlapic)) {
		dest = icr_high;
		is_broadcast = (dest == 0xffffffffU);
	} else {
		dest = icr_high >> APIC_ID_SHIFT;
		is_broadcast = (dest == 0xffU);
	}
	vec = icr_low & APIC_VECTOR_MASK;
	mode = icr_low & APIC_DELMODE_MASK;
	phys = ((icr_low & APIC_DESTMODE_LOG) == 0UL);
	shorthand = icr_low & APIC_DEST_MASK;

	if ((mode == APIC_DELMODE_FIXED) && (vec < 16U)) {
		vlapic_set_error(vlapic, APIC_ESR_SEND_ILLEGAL_VECTOR);
		printc("Ignoring invalid IPI %u", vec);
		assert(0);
	} else if (((shorthand == APIC_DEST_SELF) || (shorthand == APIC_DEST_ALLISELF))
			&& ((mode == APIC_DELMODE_NMI) || (mode == APIC_DELMODE_INIT)
			|| (mode == APIC_DELMODE_STARTUP))) {
		printc("unsupported ICR command, ignore it\n");
	} else {
		struct vmrt_vm_vcpu *vcpu = vlapic2vcpu(vlapic);

		printc(
			"icrlo 0x%08x icrhi 0x%08x triggered ipi %u",
				icr_low, icr_high, vec);

		assert(0);
	}
}

static inline uint32_t vlapic_find_highest_irr(const struct acrn_vlapic *vlapic)
{
	const struct lapic_regs *lapic = vlapic->apic_page;
	uint32_t i, val, bitpos, vec = 0U;
	const struct lapic_reg *irrptr;

	irrptr = &lapic->irr[0];

	/* i ranges effectively from 7 to 1 */
	for (i = 7U; i > 0U; i--) {
		val = irrptr[i].v;
		if (val != 0U) {
			bitpos = (uint32_t)fls32(val);
			vec = (i * 32U) + bitpos;
			break;
		}
	}

	return vec;
}

/**
 * @brief Find a deliverable virtual interrupts for vLAPIC in irr.
 *
 * @param[in]    vlapic Pointer to target vLAPIC data structure
 * @param[inout] vecptr Pointer to vector buffer and will be filled
 *               with eligible vector if any.
 *
 * @retval false There is no deliverable pending vector.
 * @retval true There is deliverable vector.
 *
 * @remark The vector does not automatically transition to the ISR as a
 *	   result of calling this function.
 *	   This function is only for case that APICv/VID is NOT supported.
 */
static bool vlapic_find_deliverable_intr(const struct acrn_vlapic *vlapic, uint32_t *vecptr)
{
	const struct lapic_regs *lapic = vlapic->apic_page;
	uint32_t vec;
	bool ret = false;

	vec = vlapic_find_highest_irr(vlapic);
	if (prio(vec) > prio(lapic->ppr.v)) {
		ret = true;
		if (vecptr != NULL) {
			*vecptr = vec;
		}
	}

	return ret;
}

/**
 * @brief Get a deliverable virtual interrupt from irr to isr.
 *
 * Transition 'vector' from IRR to ISR. This function is called with the
 * vector returned by 'vlapic_find_deliverable_intr()' when the guest is able to
 * accept this interrupt (i.e. RFLAGS.IF = 1 and no conditions exist that
 * block interrupt delivery).
 *
 * @param[in] vlapic Pointer to target vLAPIC data structure
 * @param[in] vector Target virtual interrupt vector
 *
 * @return None
 *
 * @pre vlapic != NULL
 */
static void vlapic_get_deliverable_intr(struct acrn_vlapic *vlapic, uint32_t vector)
{
	struct lapic_regs *lapic = vlapic->apic_page;
	struct lapic_reg *irrptr, *isrptr;
	uint32_t idx;

	/*
	 * clear the ready bit for vector being accepted in irr
	 * and set the vector as in service in isr.
	 */
	idx = vector >> 5U;

	irrptr = &lapic->irr[0];
	bitmap32_clear_lock((uint16_t)(vector & 0x1fU), &irrptr[idx].v);

	vlapic_dump_irr(vlapic, "vlapic_get_deliverable_intr");

	isrptr = &lapic->isr[0];
	bitmap32_set_nolock((uint16_t)(vector & 0x1fU), &isrptr[idx].v);
	vlapic_dump_isr(vlapic, "vlapic_get_deliverable_intr");

	vlapic->isrv = vector;

	/*
	 * Update the PPR
	 */
	vlapic_update_ppr(vlapic);
}

static void
vlapic_write_svr(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;
	uint32_t old, new, changed;

	lapic = vlapic->apic_page;

	new = lapic->svr.v;
	old = vlapic->svr_last;
	vlapic->svr_last = new;

	changed = old ^ new;

	if ((changed & APIC_SVR_ENABLE) != 0U) {
		if ((new & APIC_SVR_ENABLE) == 0U) {
			struct vmrt_vm_comp *vm = vlapic2vcpu(vlapic)->vm;
			/*
			 * The apic is now disabled so stop the apic timer
			 * and mask all the LVT entries.
			 */
			printc("vlapic is software-disabled\n");

			vlapic_mask_lvts(vlapic);
			/* the only one enabled LINT0-ExtINT vlapic disabled */
			if (vm->wire_mode == VPIC_WIRE_NULL) {
				vm->wire_mode = VPIC_WIRE_INTR;
				printc("vpic wire mode -> INTR\n");
			}
		} else {
			/*
			 * The apic is now enabled so restart the apic timer
			 * if it is configured in periodic mode.
			 */
			printc("vlapic is software-enabled\n");
			g_vlapi_enabled = 1;
			if (vlapic_lvtt_period(vlapic)) {
				/* TODO: set timer logic */
				assert(0);
			}
		}
	}
}

static int32_t vlapic_read(struct acrn_vlapic *vlapic, uint32_t offset_arg, uint64_t *data)
{
	int32_t ret = 0;
	struct lapic_regs *lapic = vlapic->apic_page;
	uint32_t i;
	uint32_t offset = offset_arg;
	*data = 0UL;

	if (offset > sizeof(*lapic)) {
		ret = -EACCES;
	} else {

		offset &= ~0x3UL;
		switch (offset) {
		case APIC_OFFSET_ID:
			*data = lapic->id.v;
			break;
		case APIC_OFFSET_VER:
			*data = lapic->version.v;
			break;
		case APIC_OFFSET_PPR:
			*data = lapic->ppr.v;
			break;
		case APIC_OFFSET_EOI:
			*data = lapic->eoi.v;
			break;
		case APIC_OFFSET_LDR:
			*data = lapic->ldr.v;
			break;
		case APIC_OFFSET_DFR:
			*data = lapic->dfr.v;
			break;
		case APIC_OFFSET_SVR:
			*data = lapic->svr.v;
			break;
		case APIC_OFFSET_ISR0:
		case APIC_OFFSET_ISR1:
		case APIC_OFFSET_ISR2:
		case APIC_OFFSET_ISR3:
		case APIC_OFFSET_ISR4:
		case APIC_OFFSET_ISR5:
		case APIC_OFFSET_ISR6:
		case APIC_OFFSET_ISR7:
			i = (offset - APIC_OFFSET_ISR0) >> 4U;
			*data = lapic->isr[i].v;
			break;
		case APIC_OFFSET_TMR0:
		case APIC_OFFSET_TMR1:
		case APIC_OFFSET_TMR2:
		case APIC_OFFSET_TMR3:
		case APIC_OFFSET_TMR4:
		case APIC_OFFSET_TMR5:
		case APIC_OFFSET_TMR6:
		case APIC_OFFSET_TMR7:
			i = (offset - APIC_OFFSET_TMR0) >> 4U;
			*data = lapic->tmr[i].v;
			break;
		case APIC_OFFSET_IRR0:
		case APIC_OFFSET_IRR1:
		case APIC_OFFSET_IRR2:
		case APIC_OFFSET_IRR3:
		case APIC_OFFSET_IRR4:
		case APIC_OFFSET_IRR5:
		case APIC_OFFSET_IRR6:
		case APIC_OFFSET_IRR7:
			i = (offset - APIC_OFFSET_IRR0) >> 4U;
			*data = lapic->irr[i].v;
			break;
		case APIC_OFFSET_ESR:
			*data = lapic->esr.v;
			break;
		case APIC_OFFSET_ICR_LOW:
			*data = lapic->icr_lo.v;
			if (is_x2apic_enabled(vlapic)) {
				*data |= ((uint64_t)lapic->icr_hi.v) << 32U;
			}
			break;
		case APIC_OFFSET_ICR_HI:
			*data = lapic->icr_hi.v;
			break;
		case APIC_OFFSET_CMCI_LVT:
		case APIC_OFFSET_TIMER_LVT:
		case APIC_OFFSET_THERM_LVT:
		case APIC_OFFSET_PERF_LVT:
		case APIC_OFFSET_LINT0_LVT:
		case APIC_OFFSET_LINT1_LVT:
		case APIC_OFFSET_ERROR_LVT:
			*data = vlapic_get_lvt(vlapic, offset);
#ifdef INVARIANTS
			reg = vlapic_get_lvtptr(vlapic, offset);
			assert(*data == *reg, "inconsistent lvt value at offset %#x: %#lx/%#x", offset, *data, *reg);
#endif
			break;
		case APIC_OFFSET_TIMER_ICR:
			/* if TSCDEADLINE mode always return 0*/
			if (vlapic_lvtt_tsc_deadline(vlapic)) {
				*data = 0UL;
			} else {
				*data = lapic->icr_timer.v;
			}
			break;
		case APIC_OFFSET_TIMER_CCR:
			*data = vlapic_get_ccr(vlapic);
			break;
		case APIC_OFFSET_TIMER_DCR:
			*data = lapic->dcr_timer.v;
			break;
		default:
			ret = -EACCES;
			break;
		}
	}

	return ret;
}



/*
 *  @pre vcpu != NULL
 *  @pre vector <= 255U
 */
void
vlapic_set_intr(struct vmrt_vm_vcpu *vcpu, uint32_t vector, bool level)
{
	struct acrn_vlapic *vlapic;

	vlapic = vcpu_vlapic(vcpu);
	if (vector < 16U) {
		vlapic_set_error(vlapic, APIC_ESR_RECEIVE_ILLEGAL_VECTOR);
		assert(0);
	} else {
		vlapic_accept_intr(vlapic, vector, level);
	}
}

void vlapic_timer_expired(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic;
	struct lapic_regs *lapic;

	vlapic = vcpu_vlapic(vcpu);
	lapic = vlapic->apic_page;

	/* inject vcpu timer interrupt if not masked */
	if (!vlapic_lvtt_masked(vlapic)) {
		vlapic_set_intr(vcpu, lapic->lvt[APIC_LVT_TIMER].v & APIC_LVTT_VECTOR, LAPIC_TRIG_EDGE);
	}
}

/*
 * @pre vm != NULL
 */
bool is_x2apic_enabled(const struct acrn_vlapic *vlapic)
{
	bool ret = false;

	return ret;
}

bool is_xapic_enabled(const struct acrn_vlapic *vlapic)
{
	bool ret = true;

	return ret;
}


static bool apicv_basic_x2apic_read_msr_may_valid(uint32_t offset)
{
	return (offset != APIC_OFFSET_DFR) && (offset != APIC_OFFSET_ICR_HI);
}

static bool apicv_advanced_x2apic_read_msr_may_valid(uint32_t offset)
{
	return (offset == APIC_OFFSET_TIMER_CCR);
}

static bool apicv_basic_x2apic_write_msr_may_valid(uint32_t offset)
{
	return (offset != APIC_OFFSET_DFR) && (offset != APIC_OFFSET_ICR_HI);
}

static bool apicv_advanced_x2apic_write_msr_may_valid(uint32_t offset)
{
	return (offset != APIC_OFFSET_DFR) && (offset != APIC_OFFSET_ICR_HI) &&
		(offset != APIC_OFFSET_EOI) && (offset != APIC_OFFSET_SELF_IPI);
}


/**
 * APIC-v functions
 * @pre get_pi_desc(vlapic2vcpu(vlapic)) != NULL
 */
static bool
apicv_set_intr_ready(struct acrn_vlapic *vlapic, uint32_t vector)
{
	struct pi_desc *pid;
	uint32_t idx;
	bool notify = false;

	pid = get_pi_desc(vlapic2vcpu(vlapic));
	idx = vector >> 6U;
	if (!bitmap_test_and_set_lock((uint16_t)(vector & 0x3fU), &pid->pir[idx])) {
		notify = !bitmap_test_and_set_lock(POSTED_INTR_ON, &pid->control.value);
	}
	return notify;
}


static void apicv_basic_inject_intr(struct acrn_vlapic *vlapic,
		bool guest_irq_enabled, bool injected)
{
	uint32_t vector = 0U;

	if (guest_irq_enabled && (!injected)) {
		vlapic_update_ppr(vlapic);
		if (vlapic_find_deliverable_intr(vlapic, &vector)) {
			assert(0);
			vlapic_get_deliverable_intr(vlapic, vector);
		}
	}

	vlapic_update_tpr_threshold(vlapic);
}

/*
 * @brief Send a Posted Interrupt to itself.
 *
 * Interrupts are disabled on pCPU at this point of time.
 * Upon the next VMEnter the self-IPI is serviced by the logical processor.
 * Since the IPI vector is Posted Interrupt vector, logical processor syncs
 * PIR to vIRR and updates RVI.
 *
 * @pre get_pi_desc(vlapic->vcpu) != NULL
 */
static inline struct pi_desc *get_pi_desc(struct vmrt_vm_vcpu *vcpu)
{
	return (struct pi_desc *)&(vcpu->shared_region->pi_desc);
}

static void apicv_advanced_inject_intr(struct acrn_vlapic *vlapic,
		__unused bool guest_irq_enabled, __unused bool injected)
{
	struct vmrt_vm_vcpu *vcpu = vlapic2vcpu(vlapic);
	struct pi_desc *pid = get_pi_desc(vcpu);
	
	if (bitmap_test(POSTED_INTR_ON, &(pid->control.value))) {
		vcpu->shared_region->inject_evt = 1;
	}
}

void vlapic_inject_intr(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	apicv_advanced_inject_intr(vlapic, 0, 0);
}

static bool apicv_basic_has_pending_delivery_intr(struct vmrt_vm_vcpu *vcpu)
{
	uint32_t vector;
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);

	vlapic_update_ppr(vlapic);

	/* check and raise request if we have a deliverable irq in LAPIC IRR */
	if (vlapic_find_deliverable_intr(vlapic, &vector)) {
		/* we have pending IRR */
		assert(0);
	}

	return vcpu->pending_req != 0UL;
}

static bool apicv_advanced_has_pending_delivery_intr(__unused struct vmrt_vm_vcpu *vcpu)
{
	return false;
}

bool vlapic_has_pending_delivery_intr(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	return vlapic->ops->has_pending_delivery_intr(vcpu);
}

uint32_t vlapic_get_next_pending_intr(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	uint32_t vector;

	vector = vlapic_find_highest_irr(vlapic);

	return vector;
}

static bool apicv_basic_has_pending_intr(struct vmrt_vm_vcpu *vcpu)
{
	return vlapic_get_next_pending_intr(vcpu) != 0UL;
}

static bool apicv_advanced_has_pending_intr(struct vmrt_vm_vcpu *vcpu)
{
	return apicv_basic_has_pending_intr(vcpu);
}

bool vlapic_clear_pending_intr(struct vmrt_vm_vcpu *vcpu, uint32_t vector)
{
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	struct lapic_reg *irrptr = &(vlapic->apic_page->irr[0]);
	uint32_t idx = vector >> 5U;
	return bitmap32_test_and_clear_lock((uint16_t)(vector & 0x1fU), &irrptr[idx].v);
}

bool vlapic_has_pending_intr(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	return vlapic->ops->has_pending_intr(vcpu);
}

static bool apicv_basic_apic_read_access_may_valid(__unused uint32_t offset)
{
	return true;
}

static bool apicv_advanced_apic_read_access_may_valid(uint32_t offset)
{
	return ((offset == APIC_OFFSET_CMCI_LVT) || (offset == APIC_OFFSET_TIMER_CCR));
}

static bool apicv_basic_apic_write_access_may_valid(uint32_t offset)
{
	return (offset != APIC_OFFSET_SELF_IPI);
}

static bool apicv_advanced_apic_write_access_may_valid(uint32_t offset)
{
	return (offset == APIC_OFFSET_CMCI_LVT);
}

int32_t veoi_vmexit_handler(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_vlapic *vlapic = NULL;

	uint32_t vector;
	struct lapic_regs *lapic;
	struct lapic_reg *tmrptr;
	uint32_t idx;

	/* TODO: fix veoi if necessary */
	assert(0);

	return 0;
}

static void vlapic_x2apic_self_ipi_handler(struct acrn_vlapic *vlapic)
{
	/* TODO: fix x2apic virtualization if necessary */
	struct lapic_regs *lapic;
	uint32_t vector;

	lapic = vlapic->apic_page;
	vector = lapic->self_ipi.v & APIC_VECTOR_MASK;
	assert(0);
}


/*
 * TPR threshold (32 bits). Bits 3:0 of this field determine the threshold
 * below which bits 7:4 of VTPR (see Section 29.1.1) cannot fall.
 */
void vlapic_update_tpr_threshold(const struct acrn_vlapic *vlapic)
{
	/* TODO: fix trp virtualization if necessary */
	uint32_t irr, tpr, threshold;
	assert(0);
}

int32_t tpr_below_threshold_vmexit_handler(struct vmrt_vm_vcpu *vcpu)
{
	/* TODO: fix trp virtualization if necessary */
	assert(0);

	return 0;
}

static const struct acrn_apicv_ops apicv_basic_ops = {
	.accept_intr = apicv_basic_accept_intr,
	.inject_intr = apicv_basic_inject_intr,
	.has_pending_delivery_intr = apicv_basic_has_pending_delivery_intr,
	.has_pending_intr = apicv_basic_has_pending_intr,
	.apic_read_access_may_valid = apicv_basic_apic_read_access_may_valid,
	.apic_write_access_may_valid = apicv_basic_apic_write_access_may_valid,
	.x2apic_read_msr_may_valid = apicv_basic_x2apic_read_msr_may_valid,
	.x2apic_write_msr_may_valid = apicv_basic_x2apic_write_msr_may_valid,
};

static const struct acrn_apicv_ops apicv_advanced_ops = {
	.accept_intr = apicv_advanced_accept_intr,
	.inject_intr = apicv_advanced_inject_intr,
	.has_pending_delivery_intr = apicv_advanced_has_pending_delivery_intr,
	.has_pending_intr = apicv_advanced_has_pending_intr,
	.apic_read_access_may_valid  = apicv_advanced_apic_read_access_may_valid,
	.apic_write_access_may_valid  = apicv_advanced_apic_write_access_may_valid,
	.x2apic_read_msr_may_valid  = apicv_advanced_x2apic_read_msr_may_valid,
	.x2apic_write_msr_may_valid  = apicv_advanced_x2apic_write_msr_may_valid,
};

/*
 * set apicv ops for apicv basic mode or apicv advenced mode.
 */
void vlapic_set_apicv_ops(void)
{
	if (is_apicv_advanced_feature_supported()) {
		apicv_ops = &apicv_advanced_ops;
	} else {
		apicv_ops = &apicv_basic_ops;
	}
}

static uint16_t vm_apicid2vcpu_id(struct vmrt_vm_comp *vm, uint32_t lapicid)
{
	uint16_t i;
	struct vmrt_vm_vcpu *vcpu = NULL;
	uint16_t cpu_id = INVALID_CPU_ID;

	for (int i = 0; i < vm->num_vcpu; i++) {
		vcpu = &vm->vcpus[i];
		if (vcpu_vlapic(vcpu)->vapic_id == lapicid) {
			cpu_id = vcpu->cpuid;
			break;
		}
	}

	if (cpu_id == INVALID_CPU_ID) {
		printc("%s: bad lapicid %u", __func__, lapicid);
		assert(0);
	}

	return cpu_id;

}

static inline void set_dest_mask_phys(struct vmrt_vm_comp *vm, uint64_t *dmask, uint32_t dest)
{
	uint16_t vcpu_id;

	vcpu_id = vm_apicid2vcpu_id(vm, dest);
	if (vcpu_id < vm->num_vcpu) {
		bitmap_set_nolock(vcpu_id, dmask);
	}
}

/*
 * This function tells if a vlapic belongs to the destination.
 * If yes, return true, else reture false.
 *
 * @pre vlapic != NULL
 */
static inline bool is_dest_field_matched(const struct acrn_vlapic *vlapic, uint32_t dest)
{
	uint32_t logical_id, cluster_id, dest_logical_id, dest_cluster_id;
	uint32_t ldr = vlapic->apic_page->ldr.v;
	bool ret = false;

	if (is_x2apic_enabled(vlapic)) {
		logical_id = ldr & 0xFFFFU;
		cluster_id = (ldr >> 16U) & 0xFFFFU;
		dest_logical_id = dest & 0xFFFFU;
		dest_cluster_id = (dest >> 16U) & 0xFFFFU;
		if ((cluster_id == dest_cluster_id) && ((logical_id & dest_logical_id) != 0U)) {
			ret = true;
		}
	} else {
		uint32_t dfr = vlapic->apic_page->dfr.v;
		if ((dfr & APIC_DFR_MODEL_MASK) == APIC_DFR_MODEL_FLAT) {
			/*
			 * In the "Flat Model" the MDA is interpreted as an 8-bit wide
			 * bitmask. This model is available in the xAPIC mode only.
			 */
			logical_id = ldr >> 24U;
			dest_logical_id = dest & 0xffU;
			if ((logical_id & dest_logical_id) != 0U) {
				ret = true;
			}
		} else if ((dfr & APIC_DFR_MODEL_MASK) == APIC_DFR_MODEL_CLUSTER) {
			/*
			 * In the "Cluster Model" the MDA is used to identify a
			 * specific cluster and a set of APICs in that cluster.
			 */
			logical_id = (ldr >> 24U) & 0xfU;
			cluster_id = ldr >> 28U;
			dest_logical_id = dest & 0xfU;
			dest_cluster_id = (dest >> 4U) & 0xfU;
			if ((cluster_id == dest_cluster_id) && ((logical_id & dest_logical_id) != 0U)) {
				ret = true;
			}
		} else {
			/* Guest has configured a bad logical model for this vcpu. */
			printc("vlapic has bad logical model %x", dfr);
			assert(0);
		}
	}

	return ret;
}

/*
 * This function populates 'dmask' with the set of vcpus that match the
 * addressing specified by the (dest, phys, lowprio) tuple.
 */
uint64_t
vlapic_calc_dest_noshort(struct vmrt_vm_comp *vm, bool is_broadcast,
		uint32_t dest, bool phys, bool lowprio)
{
	uint64_t dmask = 0UL;
	struct acrn_vlapic *vlapic, *lowprio_dest = NULL;
	struct vmrt_vm_vcpu *vcpu;
	uint16_t vcpu_id;

	if (is_broadcast) {
		/* Broadcast in both logical and physical modes. */
		printc("Broadcast is not supported now\n");
		assert(0);
	} else if (phys) {
		/* Physical mode: "dest" is local APIC ID. */
		printc("vlapic phy dst mode to find cpu\n");
		set_dest_mask_phys(vm, &dmask, dest);
	} else {
		/*
		 * Logical mode: "dest" is message destination addr
		 * to be compared with the logical APIC ID in LDR.
		 */
		for (int i = 0; i < vm->num_vcpu; i++) {
			vcpu = &vm->vcpus[i];
			vcpu_id = i;
			vlapic = vcpu_vlapic(vcpu);
			if (!is_dest_field_matched(vlapic, dest)) {
				continue;
			}

			if (lowprio) {
				/*
				 * for lowprio delivery mode, the lowest-priority one
				 * among all "dest" matched processors accepts the intr.
				 */
				if (lowprio_dest == NULL) {
					lowprio_dest = vlapic;
				} else if (lowprio_dest->apic_page->ppr.v > vlapic->apic_page->ppr.v) {
					lowprio_dest = vlapic;
				} else {
					/* No other state currently, do nothing */
				}
			} else {
				bitmap_set_nolock(vcpu_id, &dmask);
			}
		}

		if (lowprio && (lowprio_dest != NULL)) {
			bitmap_set_nolock(vlapic2vcpu(lowprio_dest)->cpuid, &dmask);
		}
	}

	return dmask;
}

void
vlapic_receive_intr(struct vmrt_vm_comp *vm, bool level, uint32_t dest, bool phys,
		uint32_t delmode, uint32_t vec, bool rh)
{
	bool lowprio;
	uint16_t vcpu_id;
	uint64_t dmask;
	struct vmrt_vm_vcpu *target_vcpu;

	if ((delmode != IOAPIC_RTE_DELMODE_FIXED) &&
			(delmode != IOAPIC_RTE_DELMODE_LOPRI) &&
			(delmode != IOAPIC_RTE_DELMODE_EXINT)) {
		printc("vlapic intr invalid delmode %#x", delmode);
		assert(0);
	} else {
		lowprio = (delmode == IOAPIC_RTE_DELMODE_LOPRI) || rh;

		/*
		 * We don't provide any virtual interrupt redirection hardware so
		 * all interrupts originating from the ioapic or MSI specify the
		 * 'dest' in the legacy xAPIC format.
		 */
		dmask = vlapic_calc_dest_noshort(vm, false, dest, phys, lowprio);

		for (vcpu_id = 0U; vcpu_id < vm->num_vcpu; vcpu_id++) {
			struct acrn_vlapic *vlapic;
			if ((dmask & (1UL << vcpu_id)) != 0UL) {
				target_vcpu = vmrt_get_vcpu(vm, vcpu_id);

				/* only make request when vlapic enabled */
				vlapic = vcpu_vlapic(target_vcpu);
				if (vlapic_enabled(vlapic)) {
					if (delmode == IOAPIC_RTE_DELMODE_EXINT) {
						assert(0);
					} else {
						vlapic_set_intr(target_vcpu, vec, level);
					}
				} else {assert(0);}
			}
		}
	}
}

void
vlapic_reset(struct acrn_vlapic *vlapic)
{
	struct lapic_regs *lapic;

	vlapic->msr_apicbase = DEFAULT_APIC_BASE;

	if (vlapic2vcpu(vlapic)->cpuid == BSP_CPU_ID) {
		vlapic->msr_apicbase |= APICBASE_BSP;
	}
	vlapic->vapic_id = vlapic2vcpu(vlapic)->cpuid;
	
	/* Upon reset, vlapic is set to xAPIC mode. */
	vlapic->msr_apicbase |= APICBASE_XAPIC;

	lapic = vlapic->apic_page;
	(void)memset((void *)lapic, 0U, sizeof(struct lapic_regs));

	lapic->id.v = vlapic->vapic_id;
	if (!is_x2apic_enabled(vlapic)) {
		lapic->id.v <<= APIC_ID_SHIFT;
	}

	lapic->version.v = VLAPIC_VERSION;
	lapic->version.v |= (VLAPIC_MAXLVT_INDEX << MAXLVTSHIFT);
	lapic->dfr.v = 0xffffffffU;
	lapic->svr.v = APIC_SVR_VECTOR;
	vlapic_mask_lvts(vlapic);

	lapic->icr_timer.v = 0U;
	lapic->dcr_timer.v = 0U;
	vlapic_write_dcr(vlapic);

	vlapic->svr_last = lapic->svr.v;

	vlapic->isrv = 0U;
}


int32_t apic_write_vmexit_handler(struct vmrt_vm_vcpu *vcpu)
{
	uint64_t qual;
	int32_t err = 0;
	uint32_t offset;
	struct acrn_vlapic *vlapic = NULL;

	qual = vcpu->shared_region->qualification;
	offset = (uint32_t)(qual & 0xFFFUL);

	vlapic = vcpu->vlapic;

	switch (offset) {
	case APIC_OFFSET_ID:
		/* Force APIC ID as read only */
		break;
	case APIC_OFFSET_LDR:
		vlapic_write_ldr(vlapic);
		break;
	case APIC_OFFSET_DFR:
		vlapic_write_dfr(vlapic);
		break;
	case APIC_OFFSET_SVR:
		vlapic_write_svr(vlapic);
		break;
	case APIC_OFFSET_ESR:
		vlapic_write_esr(vlapic);
		break;
	case APIC_OFFSET_ICR_LOW:
		vlapic_write_icrlo(vlapic);
		break;
	case APIC_OFFSET_CMCI_LVT:
	case APIC_OFFSET_TIMER_LVT:
	case APIC_OFFSET_THERM_LVT:
	case APIC_OFFSET_PERF_LVT:
	case APIC_OFFSET_LINT0_LVT:
	case APIC_OFFSET_LINT1_LVT:
	case APIC_OFFSET_ERROR_LVT:
		vlapic_write_lvt(vlapic, offset);
		break;
	case APIC_OFFSET_TIMER_ICR:
		vlapic_write_icrtmr(vlapic);
		break;
	case APIC_OFFSET_TIMER_DCR:
		vlapic_write_dcr(vlapic);
		break;
	case APIC_OFFSET_SELF_IPI:
		if (is_x2apic_enabled(vlapic)) {
			/* Don't support x2apic */
			assert(0);
			break;
		}
		/* falls through */
	default:
		err = -EACCES;
		printc("Unhandled APIC-Write, offset:0x%x", offset);
		VM_PANIC(vcpu);
		break;
	}

	return err;
}

void
lapic_write_handler(struct vmrt_vm_vcpu *vcpu)
{
	apic_write_vmexit_handler(vcpu);
}

void
lapic_intr_inject(struct vmrt_vm_vcpu *vcpu, u8_t vector, int autoeoi)
{
	struct vm_vcpu_shared_region *shared_region = vcpu->shared_region;
	struct acrn_vlapic *vlapic = vcpu_vlapic(vcpu);
	struct lapic_regs *lapic = vlapic->apic_page;
	u8_t offset = vector / 32;
	u8_t bit = vector % 32;

	u8_t svi = (u8_t)(shared_region->interrupt_status >> 8);
	u8_t rvi = (u8_t)shared_region->interrupt_status;

	if (svi == vector && autoeoi) {
		/* TODO: svi should be the second highest priority bit in isr */
		svi = 0;
		lapic->isr[offset].v &= ~(1U << bit);
	}
	if (rvi < vector) {
		rvi = vector;
	}

	/* Accept the interrupt */
	lapic->irr[offset].v |= (1U << bit);

	shared_region->interrupt_status = svi << 8 | rvi;
}
