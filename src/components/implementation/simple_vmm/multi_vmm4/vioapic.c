/*-
 * Copyright (c) 2013 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
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

#define pr_prefix	"vioapic: "

#include <errno.h>
#include <acrn_common.h>
#include <irq.h>
#include <bits.h>
#include <ioapic.h>
#include <vioapic.h>
#include <vpic.h>
#include <vlapic.h>


#define	RTBL_RO_BITS	((uint32_t)0x00004000U | (uint32_t)0x00001000U) /*Remote IRR and Delivery Status bits*/

#define DBG_LEVEL_VIOAPIC	6U
#define ACRN_IOAPIC_VERSION	0x11U

#define MASK_ALL_INTERRUPTS   0x0001000000010000UL

static inline struct acrn_vioapics *vm_ioapics(const struct vmrt_vm_comp *vm)
{
	return (struct acrn_vioapics *)(vm->ioapic);
}

/**
 * @pre pin < vioapic->chipinfo.nr_pins
 */
static void
vioapic_generate_intr(struct acrn_single_vioapic *vioapic, uint32_t pin)
{
	uint32_t vector, dest, delmode;
	union ioapic_rte rte;
	bool level, phys;

	rte = vioapic->rtbl[pin];

	if (rte.bits.intr_mask == IOAPIC_RTE_MASK_SET) {
		printc("ioapic pin%hhu: masked\n", pin);
	} else {
		phys = (rte.bits.dest_mode == IOAPIC_RTE_DESTMODE_PHY);
		delmode = rte.bits.delivery_mode;
		level = (rte.bits.trigger_mode == IOAPIC_RTE_TRGRMODE_LEVEL);

		/* For level trigger irq, avoid send intr if
		 * previous one hasn't received EOI
		 */
		if (!level || (vioapic->rtbl[pin].bits.remote_irr == 0UL)) {
			if (level) {
				vioapic->rtbl[pin].bits.remote_irr = IOAPIC_RTE_REM_IRR;
			}
			vector = rte.bits.vector;
			dest = rte.bits.dest_field;
			vlapic_receive_intr(vioapic->vm, level, dest, phys, delmode, vector, false);
		}
	}
}

/**
 * @pre pin < vioapic->chipinfo.nr_pins
 */
static void
vioapic_set_pinstate(struct acrn_single_vioapic *vioapic, uint32_t pin, uint32_t level)
{
	uint32_t old_lvl;
	union ioapic_rte rte;

	if (pin < vioapic->chipinfo.nr_pins) {
		rte = vioapic->rtbl[pin];
		old_lvl = (uint32_t)bitmap_test((uint16_t)(pin & 0x3FU), &vioapic->pin_state[pin >> 6U]);
		if (level == 0U) {
			/* clear pin_state and deliver interrupt according to polarity */
			bitmap_clear_nolock((uint16_t)(pin & 0x3FU), &vioapic->pin_state[pin >> 6U]);
			if ((rte.bits.intr_polarity == IOAPIC_RTE_INTPOL_ALO)
				&& (old_lvl != level)) {
				vioapic_generate_intr(vioapic, pin);
			}
		} else {
			/* set pin_state and deliver intrrupt according to polarity */
			bitmap_set_nolock((uint16_t)(pin & 0x3FU), &vioapic->pin_state[pin >> 6U]);
			if ((rte.bits.intr_polarity == IOAPIC_RTE_INTPOL_AHI)
				&& (old_lvl != level)) {
				vioapic_generate_intr(vioapic, pin);
			}
		}
	}
}


struct acrn_single_vioapic *
vgsi_to_vioapic_and_vpin(const struct vmrt_vm_comp *vm, uint32_t vgsi, uint32_t *vpin)
{
	struct acrn_single_vioapic *vioapic;
	uint8_t vioapic_index = 0U;

	if (vpin != NULL) {
		*vpin = vgsi;
	}

	vioapic = (struct acrn_single_vioapic *)&(vm_ioapics(vm)->vioapic_array[vioapic_index]);

	return vioapic;
}

/**
 * @brief Set vIOAPIC IRQ line status.
 *
 * Similar with vioapic_set_irqline_lock(),but would not make sure
 * operation be done with ioapic lock.
 *
 * @param[in] vm        Pointer to target VM
 * @param[in] vgsi   	Target GSI number
 * @param[in] operation Action options: GSI_SET_HIGH/GSI_SET_LOW/
 *			GSI_RAISING_PULSE/GSI_FALLING_PULSE
 *
 * @pre vgsi < get_vm_gsicount(vm)
 * @pre vm != NULL
 * @return None
 */
void
vioapic_set_irqline_nolock(const struct vmrt_vm_comp *vm, uint32_t vgsi, uint32_t operation)
{
	struct acrn_single_vioapic *vioapic;
	uint32_t pin;

	vioapic = vgsi_to_vioapic_and_vpin(vm, vgsi, &pin);

	switch (operation) {
	case GSI_SET_HIGH:
		vioapic_set_pinstate(vioapic, pin, 1U);
		break;
	case GSI_SET_LOW:
		vioapic_set_pinstate(vioapic, pin, 0U);
		break;
	case GSI_RAISING_PULSE:
		vioapic_set_pinstate(vioapic, pin, 1U);
		vioapic_set_pinstate(vioapic, pin, 0U);
		break;
	case GSI_FALLING_PULSE:
		vioapic_set_pinstate(vioapic, pin, 0U);
		vioapic_set_pinstate(vioapic, pin, 1U);
		break;
	default:
		/*
		 * The function caller could guarantee the pre condition.
		 */
		break;
	}
}

/**
 * @brief Set vIOAPIC IRQ line status.
 *
 * @param[in] vm        Pointer to target VM
 * @param[in] vgsi  	Target GSI number
 * @param[in] operation Action options: GSI_SET_HIGH/GSI_SET_LOW/
 *			GSI_RAISING_PULSE/GSI_FALLING_PULSE
 *
 * @pre vgsi < get_vm_gsicount(vm)
 * @pre vm != NULL
 *
 * @return None
 */
void
vioapic_set_irqline_lock(const struct vmrt_vm_comp *vm, uint32_t vgsi, uint32_t operation)
{
	uint64_t rflags;

	vioapic_set_irqline_nolock(vm, vgsi, operation);
}

static uint32_t
vioapic_indirect_read(struct acrn_single_vioapic *vioapic, uint32_t addr)
{
	uint32_t regnum, ret = 0U;
	uint32_t pin, pincount = vioapic->chipinfo.nr_pins;

	regnum = addr & 0xffU;
	switch (regnum) {
	case IOAPIC_ID:
		ret = (uint32_t)vioapic->chipinfo.id << IOAPIC_ID_SHIFT;
		break;
	case IOAPIC_VER:
		ret = ((pincount - 1U) << MAX_RTE_SHIFT) | ACRN_IOAPIC_VERSION;
		break;
	case IOAPIC_ARB:
		ret = (uint32_t)vioapic->chipinfo.id << IOAPIC_ID_SHIFT;
		break;
	default:
		/*
		 * In this switch statement, regnum shall either be IOAPIC_ID or
		 * IOAPIC_VER or IOAPIC_ARB.
		 * All the other cases will be handled properly later after this
		 * switch statement.
		 */
		break;
	}

	/* redirection table entries */
	if ((regnum >= IOAPIC_REDTBL) &&
	    (regnum < (IOAPIC_REDTBL + (pincount * 2U)))) {
		uint32_t addr_offset = regnum - IOAPIC_REDTBL;
		uint32_t rte_offset = addr_offset >> 1U;
		pin = rte_offset;
		if ((addr_offset & 0x1U) != 0U) {
			ret = vioapic->rtbl[pin].u.hi_32;
		} else {
			ret = vioapic->rtbl[pin].u.lo_32;
		}
	}

	return ret;
}

static inline bool vioapic_need_intr(const struct acrn_single_vioapic *vioapic, uint16_t pin)
{
	uint32_t lvl;
	union ioapic_rte rte;
	bool ret = false;

	if ((uint32_t)pin < vioapic->chipinfo.nr_pins) {
		rte = vioapic->rtbl[pin];
		lvl = (uint32_t)bitmap_test(pin & 0x3FU, &vioapic->pin_state[pin >> 6U]);
		ret = !!(((rte.bits.intr_polarity == IOAPIC_RTE_INTPOL_ALO) && (lvl == 0U)) ||
			((rte.bits.intr_polarity == IOAPIC_RTE_INTPOL_AHI) && (lvl != 0U)));
	}

	return ret;
}

/*
 * Due to the race between vcpus and vioapic->lock could be accessed from softirq, ensure to do
 * spinlock_irqsave_obtain(&(vioapic->lock), &rflags) & spinlock_irqrestore_release(&(vioapic->lock), rflags)
 * by caller.
 */
static void vioapic_indirect_write(struct acrn_single_vioapic *vioapic, uint32_t addr, uint32_t data)
{
	union ioapic_rte last, new, changed;
	uint32_t regnum;
	uint32_t pin, pincount = vioapic->chipinfo.nr_pins;

	regnum = addr & 0xffUL;
	switch (regnum) {
	case IOAPIC_ID:
		vioapic->chipinfo.id = (uint8_t)((data & IOAPIC_ID_MASK) >> IOAPIC_ID_SHIFT);
		break;
	case IOAPIC_VER:
	case IOAPIC_ARB:
		/* readonly */
		break;
	default:
		/*
		 * In this switch statement, regnum shall either be IOAPIC_ID or
		 * IOAPIC_VER or IOAPIC_ARB.
		 * All the other cases will be handled properly later after this
		 * switch statement.
		 */
		break;
	}

	/* redirection table entries */
	if ((regnum >= IOAPIC_REDTBL) && (regnum < (IOAPIC_REDTBL + (pincount * 2U)))) {
		bool wire_mode_valid = true;
		uint32_t addr_offset = regnum - IOAPIC_REDTBL;
		uint32_t rte_offset = addr_offset >> 1U;
		pin = rte_offset;

		last = vioapic->rtbl[pin];
		new = last;
		if ((addr_offset & 1U) != 0U) {
			new.u.hi_32 = data;
		} else {
			new.u.lo_32 &= RTBL_RO_BITS;
			new.u.lo_32 |= (data & ~RTBL_RO_BITS);
		}

		/* In some special scenarios, the LAPIC somehow hasn't send
		 * EOI to IOAPIC which cause the Remote IRR bit can't be clear.
		 * To clear it, some OSes will use EOI Register to clear it for
		 * 0x20 version IOAPIC, otherwise use switch Trigger Mode to
		 * Edge Sensitive to clear it.
		 */
		if (new.bits.trigger_mode == IOAPIC_RTE_TRGRMODE_EDGE) {
			new.bits.remote_irr = 0U;
		}

		changed.full = last.full ^ new.full;
		/* pin0 from vpic mask/unmask */
		if ((pin == 0U) && (changed.bits.intr_mask != 0UL)) {
			/* mask -> umask */
			if (last.bits.intr_mask == IOAPIC_RTE_MASK_SET) {
				if ((vioapic->vm->wire_mode == VPIC_WIRE_NULL) ||
						(vioapic->vm->wire_mode == VPIC_WIRE_INTR)) {
					vioapic->vm->wire_mode = VPIC_WIRE_IOAPIC;
					printc("vpic wire mode -> IOAPIC\n");
				} else {
					printc("WARNING: invalid vpic wire mode change\n");
					wire_mode_valid = false;
				}
			/* unmask -> mask */
			} else {
				if (vioapic->vm->wire_mode == VPIC_WIRE_IOAPIC) {
					vioapic->vm->wire_mode = VPIC_WIRE_INTR;
					printc("vpic wire mode -> INTR\n");
				}
			}
		}

		if (wire_mode_valid) {
			vioapic->rtbl[pin] = new;

			/* remap for ptdev */
			if ((new.bits.intr_mask == IOAPIC_RTE_MASK_CLR) || (last.bits.intr_mask  == IOAPIC_RTE_MASK_CLR)) {
				/* TODO: set pin remap*/	
			}

			/*
			 * Generate an interrupt if the following conditions are met:
			 * - pin is not masked
			 * - previous interrupt has been EOIed
			 * - pin level is asserted
			 */
			if ((vioapic->rtbl[pin].bits.intr_mask == IOAPIC_RTE_MASK_CLR) &&
				(vioapic->rtbl[pin].bits.remote_irr == 0UL) &&
				vioapic_need_intr(vioapic, (uint16_t)pin)) {
				vioapic_generate_intr(vioapic, pin);
			}
		}
	}
}

static void
vioapic_mmio_rw(struct acrn_single_vioapic *vioapic, uint64_t gpa,
		uint32_t *data, bool do_read)
{
	uint32_t offset;
	uint64_t rflags;

	offset = (uint32_t)(gpa - vioapic->chipinfo.addr);

	/* The IOAPIC specification allows 32-bit wide accesses to the
	 * IOAPIC_REGSEL (offset 0) and IOAPIC_WINDOW (offset 16) registers.
	 */
	switch (offset) {
	case IOAPIC_REGSEL:
		if (do_read) {
			*data = vioapic->ioregsel;
		} else {
			vioapic->ioregsel = *data & 0xFFU;
		}
		break;
	case IOAPIC_WINDOW:
		if (do_read) {
			*data = vioapic_indirect_read(vioapic,
							vioapic->ioregsel);
		} else {
			vioapic_indirect_write(vioapic,
						 vioapic->ioregsel, *data);
		}
		break;
	default:
		assert(0);
		if (do_read) {
			*data = 0xFFFFFFFFU;
		}
		break;
	}
}

/*
 * @pre vm != NULL
 */
static void
vioapic_process_eoi(struct acrn_single_vioapic *vioapic, uint32_t vector)
{
	uint32_t pin, pincount = vioapic->chipinfo.nr_pins;
	union ioapic_rte rte;
	uint64_t rflags;

	if ((vector < VECTOR_DYNAMIC_START) || (vector > NR_MAX_VECTOR)) {
		printc("vioapic_process_eoi: invalid vector %u", vector);
	}

	printc("ioapic processing eoi for vector %u\n", vector);

	/* notify device to ack if assigned pin */
	for (pin = 0U; pin < pincount; pin++) {
		rte = vioapic->rtbl[pin];
		if ((rte.bits.vector != vector) ||
			(rte.bits.remote_irr == 0U)) {
			continue;
		}
	}

	/*
	 * XXX keep track of the pins associated with this vector instead
	 * of iterating on every single pin each time.
	 */
	for (pin = 0U; pin < pincount; pin++) {
		rte = vioapic->rtbl[pin];
		if ((rte.bits.vector != vector) ||
			(rte.bits.remote_irr == 0U)) {
			continue;
		}

		vioapic->rtbl[pin].bits.remote_irr = 0U;
		if (vioapic_need_intr(vioapic, (uint16_t)pin)) {
			printc("ioapic pin%hhu: asserted at eoi\n", pin);
			vioapic_generate_intr(vioapic, pin);
		}
	}
}

void vioapic_broadcast_eoi(const struct vmrt_vm_comp *vm, uint32_t vector)
{
	struct acrn_single_vioapic *vioapic;
	uint8_t vioapic_index;

	/*
	 * For platforms with multiple IO-APICs, EOI message from LAPIC is
	 * broadcast to all IO-APICs. Emulating the same behavior here.
	 */

	for (vioapic_index = 0U; vioapic_index < vm_ioapics(vm)->ioapic_num; vioapic_index++) {
		vioapic = &(vm_ioapics(vm)->vioapic_array[vioapic_index]);
		vioapic_process_eoi(vioapic, vector);
	}
}

static void reset_one_vioapic(struct acrn_single_vioapic *vioapic)
{
	uint32_t pin, pincount;

	/* Initialize all redirection entries to mask all interrupts */
	pincount = vioapic->chipinfo.nr_pins;
	for (pin = 0U; pin < pincount; pin++) {
		vioapic->rtbl[pin].full = MASK_ALL_INTERRUPTS;
	}
	vioapic->chipinfo.id = 0U;
	vioapic->ioregsel = 0U;
}

void reset_vioapics(const struct vmrt_vm_comp *vm)
{
	struct acrn_vioapics *vioapics = vm_ioapics(vm);
	uint8_t vioapic_index;

	for (vioapic_index = 0U; vioapic_index < vioapics->ioapic_num; vioapic_index++) {
		reset_one_vioapic(&vioapics->vioapic_array[vioapic_index]);
	}
}

void
vioapic_init(struct vmrt_vm_comp *vm)
{
	static struct ioapic_info virt_ioapic_info = {
		.nr_pins = VIOAPIC_RTE_NUM,
		.addr = VIOAPIC_BASE
	};

	struct ioapic_info *vioapic_info;
	uint8_t vioapic_index;
	struct acrn_single_vioapic *vioapic = NULL;
	struct acrn_vioapics *vioapics = vm_ioapics(vm);

	/* only set one io apic */
	vioapics->ioapic_num = 1U;
	vioapic_info = &virt_ioapic_info;

	for (vioapic_index = 0U; vioapic_index < vioapics->ioapic_num; vioapic_index++) {
		vioapic = &vioapics->vioapic_array[vioapic_index];
		vioapic->chipinfo = vioapic_info[vioapic_index];

		vioapic->vm = vm;
		reset_one_vioapic(vioapic);
	}

	/*
	 * Maximum number of GSI is computed as GSI base of the IOAPIC i.e. enumerated last in ACPI MADT
	 * plus the number of interrupt pins of that IOAPIC.
	 */
	if (vioapic != NULL) {
		vioapics->nr_gsi = vioapic->chipinfo.gsi_base + vioapic->chipinfo.nr_pins;
	}
}

uint32_t
get_vm_gsicount(const struct vmrt_vm_comp *vm)
{
	struct acrn_vioapics *vioapics = vm_ioapics(vm);
	return vioapics->nr_gsi;
}

/*
 * @pre handler_private_data != NULL
 */
int32_t vioapic_mmio_access_handler(struct vmrt_vm_vcpu *vcpu)
{
	struct acrn_mmio_request *mmio = vcpu->mmio_request;
	struct acrn_single_vioapic *vioapic = &vm_ioapics(vcpu->vm)->vioapic_array[0];
	uint64_t gpa = mmio->address;
	int32_t ret = 0;

	/* Note all RW to IOAPIC are 32-Bit in size */
	if (mmio->size == 4UL) {
		uint32_t data = (uint32_t)mmio->value;

		if (mmio->direction == ACRN_IOREQ_DIR_READ) {
			vioapic_mmio_rw(vioapic, gpa, &data, true);
			mmio->value = (uint64_t)data;
		} else if (mmio->direction == ACRN_IOREQ_DIR_WRITE) {
			vioapic_mmio_rw(vioapic, gpa, &data, false);
		} else {
			ret = -EINVAL;
		}
	} else {
		printc("All RW to IOAPIC must be 32-bits in size\n");
		assert(0);
	}

	return ret;
}

/**
 * @pre vm->arch_vm.vioapics != NULL
 * @pre vgsi < get_vm_gsicount(vm)
 * @pre rte != NULL
 */
void vioapic_get_rte(const struct vmrt_vm_comp *vm, uint32_t vgsi, union ioapic_rte *rte)
{
	struct acrn_single_vioapic *vioapic;
	uint32_t pin;
	vioapic = vgsi_to_vioapic_and_vpin(vm, vgsi, &pin);

	*rte = vioapic->rtbl[pin];
}
