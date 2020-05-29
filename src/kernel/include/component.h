/**
 * Copyright 2014 by Gabriel Parmer, gparmer@gwu.edu
 *
 * Redistribution of this file is permitted under the GNU General
 * Public License v2.
 */

#ifndef COMPONENT_H
#define COMPONENT_H

#include "liveness_tbl.h"
#include "captbl.h"
#include "pgtbl.h"
#include "cap_ops.h"
#include "shared/cos_sched.h"

struct comp_info {
	struct liveness_data        liveness;
	pgtbl_t                     pgtbl;
	struct captbl              *captbl;
	struct cos_scb_info        *scb_data;
} __attribute__((packed));

struct cap_comp {
	struct cap_header  h;
	vaddr_t            entry_addr;
	struct cap_pgtbl  *pgd;
	struct cap_captbl *ct_top;
	struct comp_info   info;
} __attribute__((packed));

#include "scb.h"

static int
comp_activate(struct captbl *t, capid_t cap, capid_t capin, capid_t captbl_cap, capid_t pgtbl_cap, capid_t scbcap,
	      livenessid_t lid, vaddr_t entry_addr, vaddr_t scb_uaddr)
{
	struct cap_comp   *compc;
	struct cap_pgtbl  *ptc;
	struct cap_captbl *ctc;
	u32_t              v, flags;
	int                ret = 0;
	struct cap_scb    *scbc = NULL;

	ctc = (struct cap_captbl *)captbl_lkup(t, captbl_cap);
	if (unlikely(!ctc || ctc->h.type != CAP_CAPTBL || ctc->lvl > 0)) return -EINVAL;
	ptc = (struct cap_pgtbl *)captbl_lkup(t, pgtbl_cap);
	if (unlikely(!ptc || ptc->h.type != CAP_PGTBL || ptc->lvl > 0)) return -EINVAL;
	if (likely(scbcap)) {
		scbc = (struct cap_scb *)captbl_lkup(t, scbcap);
		if (unlikely(!scbc || scbc->h.type != CAP_SCB)) return -EINVAL;
	}

	v = ptc->refcnt_flags;
	if (v & CAP_MEM_FROZEN_FLAG) return -EINVAL;
	if (cos_cas((unsigned long *)&ptc->refcnt_flags, v, v + 1) != CAS_SUCCESS) return -ECASFAIL;

	v = ctc->refcnt_flags;
	if (v & CAP_MEM_FROZEN_FLAG) cos_throw(undo_ptc, -EINVAL);
	if (cos_cas((unsigned long *)&ctc->refcnt_flags, v, v + 1) != CAS_SUCCESS) {
		/* undo before return */
		cos_throw(undo_ptc, -ECASFAIL);
	}
	compc = (struct cap_comp *)__cap_capactivate_pre(t, cap, capin, CAP_COMP, &ret);
	if (!compc) cos_throw(undo_ctc, ret);

	if (likely(scbc)) {
		ret = scb_comp_update(t, scbc, compc, ptc, scb_uaddr);
		if (ret) cos_throw(undo_capact, ret);
	}
	compc->entry_addr    = entry_addr;
	compc->info.pgtbl    = ptc->pgtbl;
	compc->info.captbl   = ctc->captbl;
	compc->pgd           = ptc;
	compc->ct_top        = ctc;
	ltbl_get(lid, &compc->info.liveness);
	__cap_capactivate_post(&compc->h, CAP_COMP);

	return 0;

/*undo_scb:
	scb_comp_remove(t, scbc, pgtbl_cap, scb_uaddr);*/
undo_capact:
undo_ctc:
	cos_faa((int *)&ctc->refcnt_flags, -1);
undo_ptc:
	cos_faa((int *)&ptc->refcnt_flags, -1);
	return ret;
}

static int
comp_deactivate(struct cap_captbl *ct, capid_t capin, livenessid_t lid)
{
	int                ret;
	struct cap_comp   *compc;
	struct cap_pgtbl  *pgd;
	struct cap_captbl *ct_top;

	compc = (struct cap_comp *)captbl_lkup(ct->captbl, capin);
	if (compc->h.type != CAP_COMP) return -EINVAL;

	ltbl_expire(&compc->info.liveness);
	pgd    = compc->pgd;
	ct_top = compc->ct_top;
	/* TODO: right way to remove scb info */
	if (likely(compc->info.scb_data)) scb_comp_remove(ct, 0, 0, 0);

	ret = cap_capdeactivate(ct, capin, CAP_COMP, lid);
	if (ret) return ret;

	/* decrement the refcnt of the pgd, and top level of
	 * captbl. */
	cos_faa((int *)&pgd->refcnt_flags, -1);
	cos_faa((int *)&ct_top->refcnt_flags, -1);

	return 0;
}

static void
comp_init(void)
{
	assert(sizeof(struct cap_comp) <= __captbl_cap2bytes(CAP_COMP));
}

static inline int
comp_introspect(struct cap_comp *t, unsigned long op, unsigned long *retval)
{
	switch (op) {
	case COMP_GET_SCB_CURTHD:
		*retval = t->info.scb_data->curr_thd;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

#endif /* COMPONENT_H */
