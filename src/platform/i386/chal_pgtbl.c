/**
 * Copyright 2018 by Runyu Pan, panrunyu@gwu.edu
 *
 * Redistribution of this file is permitted under the GNU General
 * Public License v2.
 */
#include "shared/cos_types.h"
#include "captbl.h"
#include "pgtbl.h"
#include "cap_ops.h"
#include "liveness_tbl.h"
#include "retype_tbl.h"
#include "chal/chal_proto.h"
#include "chal_pgtbl.h"

/* These functions do flag operations */
unsigned long
chal_pgtbl_flag_add(unsigned long input, pgtbl_flags_t flags)
{
	return input | flags;
}

unsigned long
chal_pgtbl_flag_clr(unsigned long input, pgtbl_flags_t flags)
{
	return input & (~flags);
}

unsigned long
chal_pgtbl_flag_exist(unsigned long input, pgtbl_flags_t flags)
{
	return input & flags;
}

unsigned long
chal_pgtbl_flag_all(unsigned long input, pgtbl_flags_t flags)
{
	return chal_pgtbl_flag_exist(input, flags) == flags;
}

unsigned long 
chal_pgtbl_frame(unsigned long input)
{
	return PGTBL_FRAME_MASK & input;
}

unsigned long 
chal_pgtbl_flag(unsigned long input)
{
	return PGTBL_FLAG_MASK & input;
}

unsigned long
chal_pgtbl_flag_update(unsigned long orig, pgtbl_flags_x86_t new)
{
	unsigned long updated;
	/* 
	 * This is kind of hacky but we only want the user to be able  
	 * to change a subset of the original flags when we delegate 
	 * a pte to another component. Obviously user-level components
	 * should not change certain bits in the pagetable, but we also
	 * don't want a component to have upgraded rights to a page that
	 * they are delegated (e.i. making a RO page RW).
	 */

	/* first, user-level components can't change most flags*/
	updated = new | (orig & ~X86_PGTBL_USER_MODIFIABLE);

	/* second, they should not be able to upgrade a page's rights */
	if (orig & X86_PGTBL_WRITABLE) {
		updated |= new & PGTBL_WRITABLE;
	}
#if defined(__x86_64__)
	if (!(orig & X86_PGTBL_XDISABLE)) {
		updated |= new & X86_PGTBL_XDISABLE;
	}
#endif
	return updated; 
}

unsigned long
chal_vm_pgtbl_def_flag(void)
{
	return x86_EPT_VM_DEF;
}

int
chal_pgtbl_kmem_act(pgtbl_t pt, vaddr_t addr, unsigned long *kern_addr, unsigned long **pte_ret)
{
	struct ert_intern *pte;
	unsigned long              orig_v, new_v, accum = 0;

	assert(pt);
	assert((PGTBL_FLAG_MASK & addr) == 0);

#if defined(__x86_64__)
	word_t flags;
	pte = pgtbl_lkup_lvl(pt, addr, &flags, 0, 1);
#elif defined(__i386__)	
	/* Is this place really a pte? If there is a super page, reject the operation now */
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
	                                          1, &accum);
#endif
	if (unlikely(!pte)) return -ENOENT;
	orig_v = (unsigned long)(pte->next);
	if (orig_v & X86_PGTBL_SUPER) return -EINVAL;

	/* Get the pte */
#if defined(__x86_64__)
	pte = pgtbl_lkup_lvl(pt, addr, &flags, 0, PGTBL_DEPTH);
#elif defined(__i386__)	
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
	                                          PGTBL_DEPTH, &accum);
#endif
	if (unlikely(!pte)) return -ENOENT;
	if (unlikely(__pgtbl_isnull(pte, 0, 0))) return -ENOENT;

	orig_v = (unsigned long)(pte->next);
	if (unlikely(!(orig_v & X86_PGTBL_COSFRAME))) return -EINVAL; /* can't activate non-frames */
	if (unlikely(orig_v & X86_PGTBL_COSKMEM)) return -EEXIST;     /* can't re-activate kmem frames */
	assert(!(orig_v & X86_PGTBL_QUIESCENCE));

	*kern_addr = (unsigned long)chal_pa2va((paddr_t)(orig_v & PGTBL_FRAME_MASK));
	new_v      = orig_v | X86_PGTBL_COSKMEM;

	/* pa2va (value in *kern_addr) will return NULL if the page is not kernel accessible */
	if (unlikely(!*kern_addr)) return -EINVAL; /* cannot retype a non-kernel accessible page */
	/* Now we can only activate 4k pages */
	if (unlikely(retypetbl_kern_ref((void *)(new_v & PGTBL_FRAME_MASK), PAGE_ORDER))) return -EFAULT;

	/*
	 * We keep the cos_frame entry, but mark it as COSKMEM so that
	 * we won't use it for other kernel objects.
	 */
	if (unlikely(cos_cas((unsigned long *)pte, orig_v, new_v) != CAS_SUCCESS)) {
		/* restore the ref cnt. */
		retypetbl_kern_deref((void *)(orig_v & PGTBL_FRAME_MASK), PAGE_ORDER);
		return -ECASFAIL;
	}
	/*
	 * Return the pte ptr, so that we can release the page if the
	 * kobj activation failed later.
	 */
	*pte_ret = (unsigned long *)pte;

	return 0;
}

int
chal_tlb_quiescence_check(u64_t timestamp)
{
	int i, quiescent = 1;

	/*
	 * Did timer interrupt (which does tlb flush
	 * periodically) happen after unmap? The periodic
	 * flush happens on all cpus, thus only need to check
	 * the time stamp of the current core for that case
	 * (assuming consistent time stamp counters).
	 */
	if (timestamp > tlb_quiescence[get_cpuid()].last_periodic_flush) {
		/*
		 * If no periodic flush done yet, did the
		 * mandatory flush happen on all cores?
		 */
		for (i = 0; i < NUM_CPU_COS; i++) {
			if (timestamp > tlb_quiescence[i].last_mandatory_flush) {
				/* no go */
				quiescent = 0;
				break;
			}
		}
	}
	if (quiescent == 0) {
		printk("from cpu %d, t %llu: cpu %d last mandatory flush: %llu\n", get_cpuid(), timestamp, i,
		       tlb_quiescence[i].last_mandatory_flush);
		for (i = 0; i < NUM_CPU_COS; i++) {
			printk("cpu %d: flush %llu\n", i, tlb_quiescence[i].last_mandatory_flush);
		}
	}

	return quiescent;
}

int
chal_cap_memactivate(struct captbl *ct, struct cap_pgtbl *pt, capid_t frame_cap, capid_t dest_pt, vaddr_t vaddr, vaddr_t order)
{
	unsigned long *    pte, cosframe, orig_v;
	struct cap_header *dest_pt_h;
	word_t             flags;
	int                ret;

	if (unlikely(pt->lvl || (pt->refcnt_flags & CAP_MEM_FROZEN_FLAG))) return -EINVAL;

	dest_pt_h = captbl_lkup(ct, dest_pt);
	if (dest_pt_h->type != CAP_PGTBL) return -EINVAL;
	if (((struct cap_pgtbl *)dest_pt_h)->lvl) return -EINVAL;

	/* What is the order needed for this? */
	/* We will probably activate a part of a superpage */
#if defined(__x86_64__)
	pte = pgtbl_lkup_lvl(pt->pgtbl, frame_cap, &flags, 0, 1);
#elif defined(__i386__)	
	pte = pgtbl_lkup_pgd(pt->pgtbl, frame_cap, &flags);
#endif
	if (!pte) return -EINVAL;
	orig_v = *pte;

	/* We don't allow activating non-frames or kernel entry */
	if (orig_v & X86_PGTBL_SUPER) {
		if (order != SUPER_PAGE_ORDER) {
			/* We need to pick a subpage */
			orig_v += EXTRACT_SUB_PAGE(frame_cap);
		}
	} else {
		if (order != PAGE_ORDER) return -EPERM;
	#if defined(__x86_64__)
		pte = pgtbl_lkup_lvl(pt->pgtbl, frame_cap, &flags, 0, PGTBL_DEPTH);
	#elif defined(__i386__)	
		pte = pgtbl_lkup_pte(pt->pgtbl, frame_cap, &flags);
	#endif
		if (!pte) return -EINVAL;
		orig_v = *pte;
	}

	if (!(orig_v & X86_PGTBL_COSFRAME) || (orig_v & X86_PGTBL_COSKMEM)) return -EPERM;

	assert(!(orig_v & X86_PGTBL_QUIESCENCE));
	cosframe = orig_v & PGTBL_FRAME_MASK;
	flags = X86_PGTBL_USER_DEF;
	ret = pgtbl_mapping_add(((struct cap_pgtbl *)dest_pt_h)->pgtbl, vaddr, cosframe, flags, order);

	return ret;
}

int
chal_pgtbl_activate(struct captbl *t, unsigned long cap, unsigned long capin, pgtbl_t pgtbl, u32_t lvl)
{
	struct cap_pgtbl *pt;
	int               ret;

	pt = (struct cap_pgtbl *)__cap_capactivate_pre(t, cap, capin, CAP_PGTBL, &ret);
	if (unlikely(!pt)) return ret;
	pt->pgtbl = pgtbl;

	pt->refcnt_flags = 1;
	pt->parent       = NULL; /* new cap has no parent. only copied cap has. */
	pt->lvl          = lvl & PGTBL_FLAG_EPT_MASK;

	if (unlikely(lvl & PGTBL_FLAG_EPT)) {
		pt->type = PGTBL_TYPE_EPT;
	} else {
		pt->type = PGTBL_TYPE_DEF;
	}
	__cap_capactivate_post(&pt->h, CAP_PGTBL);

	return 0;
}

int
chal_pgtbl_deactivate(struct captbl *t, struct cap_captbl *dest_ct_cap, unsigned long capin,
                      livenessid_t lid, capid_t pgtbl_cap, capid_t cosframe_addr, const int root)
{
	struct cap_header *deact_header;
	struct cap_pgtbl * deact_cap, *parent;

	unsigned long l, old_v = 0, *pte = NULL;
	int           ret;

	deact_header = captbl_lkup(dest_ct_cap->captbl, capin);
	if (!deact_header || deact_header->type != CAP_PGTBL) cos_throw(err, -EINVAL);
	deact_cap = (struct cap_pgtbl *)deact_header;
	parent    = deact_cap->parent;

	l = deact_cap->refcnt_flags;
	assert(l & CAP_REFCNT_MAX);

	if ((l & CAP_REFCNT_MAX) != 1) {
		/* We need to deact children first! */
		cos_throw(err, -EINVAL);
	}

	if (parent == NULL) {
		if (!root) cos_throw(err, -EINVAL);
		/*
		 * Last reference to the captbl page. Require pgtbl
		 * and cos_frame cap to release the kmem page.
		 */
		ret = kmem_deact_pre(deact_header, t, pgtbl_cap, cosframe_addr, &pte, &old_v);
		if (ret) cos_throw(err, ret);
	} else {
		/* more reference exists. */
		if (root) cos_throw(err, -EINVAL);
		assert(!pgtbl_cap && !cosframe_addr);
	}

	if (cos_cas_32((u32_t *)&deact_cap->refcnt_flags, l, CAP_MEM_FROZEN_FLAG) != CAS_SUCCESS) cos_throw(err, -ECASFAIL);

	/*
	 * deactivation success. We should either release the
	 * page, or decrement parent cnt.
	 */
	if (parent == NULL) {
		/* move the kmem to COSFRAME */
		ret = kmem_deact_post(pte, old_v);
		if (ret) {
			cos_faa((int *)&deact_cap->refcnt_flags, 1);
			cos_throw(err, ret);
		}
	} else {
		cos_faa((int *)&parent->refcnt_flags, -1);
	}

	/* FIXME: this should be before the kmem_deact_post */
	ret = cap_capdeactivate(dest_ct_cap, capin, CAP_PGTBL, lid);
	if (ret) cos_throw(err, ret);

	return 0;
err:
	return ret;
}

void *
chal_pgtbl_lkup_lvl(pgtbl_t pt, vaddr_t addr, word_t *flags, u32_t start_lvl, u32_t end_lvl)
{
#if defined(__x86_64__)
	u32_t i;
	unsigned long *intern = chal_pa2va((unsigned long)pt & PGTBL_ENTRY_ADDR_MASK);
	unsigned long *page   = chal_pa2va((unsigned long)pt & PGTBL_ENTRY_ADDR_MASK);

	assert(addr <= COS_MEM_USER_MAX_VA || addr >= COS_MEM_KERN_START_VA);
	assert(start_lvl == 0);

	for (i = start_lvl; i < end_lvl; i++) {
		/* high 16 bits doesn't involve indexing, so we mask them */
		addr = addr & (0xffffffffffff >> (PGTBL_ENTRY_ORDER * i));
		intern = page + (addr >> (PAGE_ORDER + PGTBL_ENTRY_ORDER * (PGTBL_DEPTH - 1 - i))); 
		page = chal_pa2va((*intern) & PGTBL_ENTRY_ADDR_MASK);
	}

	*flags = (*intern) & PGTBL_FLAG_MASK;
	return intern;
#elif defined(__i386__)
	return __pgtbl_lkupani((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT, start_lvl,
							end_lvl, flags);
#endif
}

int
chal_pgtbl_mapping_add(pgtbl_t pt, vaddr_t addr, paddr_t page, word_t flags, u32_t order)
{
	int                ret = 0;
	struct ert_intern *pte = 0;
	unsigned long      orig_v;
	u32_t              accum = 0;
	/* this temp_flag should not be used */
	word_t             temp_flag = 0;

	assert(pt);
	assert((PGTBL_FLAG_MASK & page) == 0);
	assert((PGTBL_FRAME_MASK & flags) == 0);
	/* 
	 * FIXME:the current ertrie implementation cannot stop upon detection of superpage.
	 * We have to do this manually, get the PGD first, to make sure that we will not
	 * dereference the super page as a second-level pointer. Performance bummer.
	 */
	assert(order == PAGE_ORDER);

#if defined(__x86_64__)
	pte = (struct ert_intern *)chal_pgtbl_lkup_lvl((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr, &temp_flag, 0, PGTBL_DEPTH);
#elif defined(__i386__)
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((u32_t)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
						PGTBL_DEPTH, &accum);
#endif

	if (!pte) return -ENOENT;
	orig_v = (unsigned long)(pte->next);
	if (orig_v & X86_PGTBL_PRESENT) return -EEXIST;
	if (orig_v & X86_PGTBL_COSFRAME) return -EPERM;

	/* Quiescence check */
	ret = pgtbl_quie_check(orig_v);
	if (ret) return ret;

	/* ref cnt on the frame - always user frame. */
	ret = retypetbl_ref((void *)page, order);
	if (ret) return ret;

	ret = __pgtbl_update_leaf(pte, (void *)(page | flags), orig_v);
	/* restore the refcnt if necessary */
	if (ret) retypetbl_deref((void *)page, order);

	return ret;
}

int
chal_pgtbl_cosframe_add(pgtbl_t pt, vaddr_t addr, paddr_t page, word_t flags, u32_t order)
{
	struct ert_intern *pte;
	unsigned long      orig_v = 0;
	u32_t              accum = 0;
	word_t             temp_flags = 0;

	assert(pt);
	assert((PGTBL_FLAG_MASK & page) == 0);
	assert((PGTBL_FRAME_MASK & flags) == 0);

	/* 
	 * FIXME:the current ertrie implementation cannot stop upon detection of superpage.
	 * We have to do this manually, get the PGD first, to make sure that we will not
	 * dereference the super page as a second-level pointer. Performance bummer.
	 */
#if defined(__x86_64__)
	pte = (struct ert_intern *)chal_pgtbl_lkup_lvl((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr, &temp_flags, 0, PGTBL_DEPTH);
#elif defined(__i386__)
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((u32_t)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
						PGTBL_DEPTH, &accum);
#endif

	if (!pte) return -ENOENT;
	orig_v = (unsigned long)(pte->next);
	assert(orig_v == 0);

	return __pgtbl_update_leaf(pte, (void *)(page | flags), 0);
}

/* This function updates flags of an existing mapping. */
int
chal_pgtbl_mapping_mod(pgtbl_t pt, vaddr_t addr, u32_t flags, u32_t *prevflags)
{
	/* Not used for now. TODO: add retypetbl_ref / _deref */

	struct ert_intern *pte;
	u32_t              orig_v, accum = 0;

	assert(pt && prevflags);
	assert((PGTBL_FLAG_MASK & addr) == 0);
	assert((PGTBL_FRAME_MASK & flags) == 0);

	/* get the pte */
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
	                                          PGTBL_DEPTH, &accum);
	if (__pgtbl_isnull(pte, 0, 0)) return -ENOENT;

	orig_v = (unsigned long)(pte->next);
	/**
	 * accum contains flags from pgd as well, so don't use it to
	 * get prevflags.
	 */
	*prevflags = orig_v & PGTBL_FLAG_MASK;

	/* and update the flags. */
	return __pgtbl_update_leaf(pte, (void *)(unsigned long)((orig_v & PGTBL_FRAME_MASK) | ((u32_t)flags & PGTBL_FLAG_MASK)),
	                           orig_v);
}

/**
 * When we remove a mapping, we need to link the vas to a liv_id,
 * which tracks quiescence for us.
 */
int
chal_pgtbl_mapping_del(pgtbl_t pt, vaddr_t addr, u32_t liv_id)
{
	int                ret;
	struct ert_intern *pte;
	unsigned long      orig_v, accum = 0;
	vaddr_t            order;

	assert(pt);
	assert((PGTBL_FLAG_MASK & addr) == 0);

	/* In pgtbl, we have only 20bits for liv id. */
	if (unlikely(liv_id >= (1 << (32 - PGTBL_PAGEIDX_SHIFT)))) return -EINVAL;

	/* Liveness tracking of the unmapping VAS. */
	ret = ltbl_timestamp_update(liv_id);
	if (unlikely(ret)) goto done;

	/* Get the PGD to see if we are deleting a superpage */
	pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
                                                  1, &accum);
	orig_v = (unsigned long)(pte->next);
	if (!(orig_v & X86_PGTBL_PRESENT)) return -EEXIST;
	if (orig_v & X86_PGTBL_COSFRAME) return -EPERM;
	if (!(orig_v & X86_PGTBL_SUPER)) {
		/* There is a pgd here. We are going to delete ptes in it */
		pte = (struct ert_intern *)__pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT,
		                                          PGTBL_DEPTH, &accum);
		orig_v = (unsigned long)(pte->next);
		if (!(orig_v & X86_PGTBL_PRESENT)) return -EEXIST;
		if (orig_v & X86_PGTBL_COSFRAME) return -EPERM;
		order = PAGE_ORDER;
	} else order = SUPER_PAGE_ORDER;

	ret = __pgtbl_update_leaf(pte, (void *)(unsigned long)((liv_id << PGTBL_PAGEIDX_SHIFT) | X86_PGTBL_QUIESCENCE), orig_v);
	if (ret) cos_throw(done, ret);

	/* decrement ref cnt on the frame. */
	ret = retypetbl_deref((void *)(orig_v & PGTBL_FRAME_MASK), order);
	if (ret) cos_throw(done, ret);

done:
	return ret;
}

/**
 * NOTE: This just removes the mapping. NO liveness tracking! TLB
 * flush should be taken care of separately (and carefully).
 */
int
chal_pgtbl_mapping_del_direct(pgtbl_t pt, u32_t addr)
{
	unsigned long accum = 0, *pte = NULL;

	assert(pt);
	assert((PGTBL_FLAG_MASK & addr) == 0);

	return __pgtbl_expandn(pt, addr >> PGTBL_PAGEIDX_SHIFT, PGTBL_DEPTH + 1, &accum, &pte, NULL);
}

int
chal_pgtbl_mapping_scan(struct cap_pgtbl *pt)
{
	unsigned int i, pte, *page;
	livenessid_t lid;
	u64_t        past_ts;

	/**
         * This scans the leaf level of the pgtbl and verifies
	 * quiescence.
         */
	if (pt->lvl != PGTBL_DEPTH - 1) return -EINVAL;

	page = (unsigned int *)(pt->pgtbl);
	assert(page);

	for (i = 0; i < PAGE_SIZE / sizeof(int *); i++) {
		pte = *(page + i);
		if (pte & X86_PGTBL_PRESENT || pte & X86_PGTBL_COSFRAME) return -EINVAL;

		if (pte & X86_PGTBL_QUIESCENCE) {
			lid = pte >> PGTBL_PAGEIDX_SHIFT;

			if (ltbl_get_timestamp(lid, &past_ts)) return -EFAULT;
			if (!tlb_quiescence_check(past_ts)) return -EQUIESCENCE;
		}
	}

	return 0;
}


int
chal_pgtbl_ispresent(word_t flags)
{
	return flags & (X86_PGTBL_PRESENT | X86_PGTBL_COSFRAME);
}

unsigned long *
chal_pgtbl_lkup(pgtbl_t pt, vaddr_t addr, word_t *flags)
{
	void *ret;

	ret = __pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT, PGTBL_DEPTH + 1,
	                     flags);
	if (!pgtbl_ispresent(*flags)) return NULL;
	return ret;
}

unsigned long *
chal_pgtbl_lkup_pte(pgtbl_t pt, vaddr_t addr, word_t *flags)
{
	return __pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT, PGTBL_DEPTH,
	                      flags);
}

unsigned long *
chal_pgtbl_lkup_pgd(pgtbl_t pt, vaddr_t addr, word_t *flags)
{
	return __pgtbl_lkupan((pgtbl_t)((unsigned long)pt | X86_PGTBL_PRESENT), addr >> PGTBL_PAGEIDX_SHIFT, 1,
			      flags);
}

int
chal_pgtbl_get_cosframe(pgtbl_t pt, vaddr_t frame_addr, paddr_t *cosframe, vaddr_t *order)
{
	word_t         flags;
	unsigned long *pte;
	paddr_t        v;
#if defined(__x86_64__)
	pte = pgtbl_lkup_lvl(pt, frame_addr, &flags, 0, PGTBL_DEPTH);
	if (!pte) return -EINVAL;
	v = *pte;
	*order = PAGE_ORDER;
#elif defined(__i386__)
	/* What is the order of this cosframe? */
	pte = pgtbl_lkup_pgd(pt, frame_addr, &flags);
	if (!pte) return -EINVAL;
	v = *pte;
	if (chal_pgtbl_flag_exist(v, X86_PGTBL_SUPER)) {
		*order = SUPER_PAGE_ORDER;
	} else {
		pte = pgtbl_lkup_pte(pt, frame_addr, &flags);
		if (!pte) return -EINVAL;
		v = *pte;
		*order = PAGE_ORDER;
	}
	
#endif
	if (!(v & X86_PGTBL_COSFRAME)) return -EINVAL;

	*cosframe = v & PGTBL_FRAME_MASK;

	return 0;
}

pgtbl_t
chal_pgtbl_create(void *page, void *curr_pgtbl)
{
	pgtbl_t ret = pgtbl_alloc(page);

	/* Copying the kernel part of the pgd. */
	memcpy(page + KERNEL_PGD_REGION_OFFSET, (void *)chal_pa2va((paddr_t)curr_pgtbl) + KERNEL_PGD_REGION_OFFSET,
	       KERNEL_PGD_REGION_SIZE);

	return ret;
}

int
chal_pgtbl_quie_check(u32_t orig_v)
{
	livenessid_t lid;
	u64_t        ts;

	if (orig_v & X86_PGTBL_QUIESCENCE) {
		lid = orig_v >> PGTBL_PAGEIDX_SHIFT;
		/*
		 * An unmap happened at this vaddr before. We need to
		 * make sure that all cores have done tlb flush before
		 * creating new mapping.
		 */
		assert(lid < LTBL_ENTS);

		if (ltbl_get_timestamp(lid, &ts)) return -EFAULT;
		if (!tlb_quiescence_check(ts)) {
			printk("kern tsc %llu, lid %d, last flush %llu\n", ts, lid,
			       tlb_quiescence[get_cpuid()].last_periodic_flush);
			return -EQUIESCENCE;
		}
	}

	return 0;
}

void
chal_pgtbl_init_pte(void *pte)
{
	int            i;
	unsigned long *vals = pte;

	for (i = 0; i < (1 << PGTBL_ENTRY_ORDER); i++) vals[i] = 0;
}

int
chal_pgtbl_pgtblactivate(struct captbl *ct, capid_t cap, capid_t pt_entry, capid_t pgtbl_cap, vaddr_t kmem_cap, capid_t pgtbl_lvl)
{
	pgtbl_t        new_pt, curr_pt;
	vaddr_t        kmem_addr = 0;
	unsigned long *pte       = NULL;
	int            ret;
	capid_t        lvl       = pgtbl_lvl; 

	pgtbl_lvl &= PGTBL_FLAG_EPT_MASK;
	ret = cap_kmem_activate(ct, pgtbl_cap, kmem_cap, (unsigned long *)&kmem_addr, &pte);
	if (unlikely(ret)) return ret;
	assert(kmem_addr && pte);
 
	if (pgtbl_lvl == 0) {
		/* PGD */
		struct cap_pgtbl *cap_pt = (struct cap_pgtbl *)captbl_lkup(ct, pgtbl_cap);
		if (!CAP_TYPECHK(cap_pt, CAP_PGTBL)) return -EINVAL;

		curr_pt = cap_pt->pgtbl;
		assert(curr_pt);

		if (!(lvl & PGTBL_FLAG_EPT)) {
			new_pt = pgtbl_create((void *)kmem_addr, curr_pt);
		} else {
			pgtbl_init_pte((void *)kmem_addr);
			new_pt = (pgtbl_t)chal_va2pa((void *)kmem_addr);
		}
		
		ret    = pgtbl_activate(ct, cap, pt_entry, new_pt, lvl);
	} else if (pgtbl_lvl < 0 || pgtbl_lvl > 3 ) {
		/* Not supported yet. */
		printk("cos: warning - PGTBL level greater than 4 not supported yet. \n");
		ret = -1;
	} else {
		pgtbl_init_pte((void *)kmem_addr);
		ret = pgtbl_activate(ct, cap, pt_entry, (pgtbl_t)kmem_addr, lvl);
	}

	if (ret) kmem_unalloc(pte);
	return ret;
}

int
chal_pgtbl_cpy(struct captbl *t, capid_t cap_to, capid_t capin_to, struct cap_pgtbl *ctfrom, capid_t capin_from, cap_t cap_type, word_t flags_in)
{
	struct cap_header	*ctto;
	unsigned long		*f, old_v;
	word_t			     flags;

	ctto = captbl_lkup(t, cap_to);
	if (unlikely(!ctto)) return -ENOENT;
	if (unlikely(ctto->type != cap_type)) return -EINVAL;
	if (unlikely(((struct cap_pgtbl *)ctto)->refcnt_flags & CAP_MEM_FROZEN_FLAG)) return -EINVAL;

#if defined(__x86_64__)
	f = pgtbl_lkup_lvl(((struct cap_pgtbl *)ctfrom)->pgtbl, capin_from, &flags, 0, PGTBL_DEPTH);
#elif defined(__i386__)	
	f = pgtbl_lkup_pte(((struct cap_pgtbl *)ctfrom)->pgtbl, capin_from, &flags);
#endif
	if (!f) return -ENOENT;
	old_v = *f;

	/* Cannot copy frame, or kernel entry. */
	if (chal_pgtbl_flag_exist(old_v, PGTBL_COSFRAME) || !chal_pgtbl_flag_exist(old_v, PGTBL_USER)) return -EPERM;

	if (unlikely((((struct cap_pgtbl *)ctto)->type) == PGTBL_TYPE_EPT)) {
		flags = chal_vm_pgtbl_def_flag();
	} else {
		/* sanitize the input flags */
		flags = chal_pgtbl_flag_update(flags, flags_in);
	}
	return pgtbl_mapping_add(((struct cap_pgtbl *)ctto)->pgtbl, capin_to, old_v & PGTBL_FRAME_MASK, flags, PAGE_ORDER);
}

/* 
 * FIXME: we need to ensure TLB quiescence for pgtbl cons/decons!
 * ct - main table capability
 * ctsub - sub table capability
 * expandid - address to place the subtable
 * depth - the depth level of the subtable
 */
int
chal_pgtbl_cons(struct cap_captbl *ct, struct cap_captbl *ctsub, capid_t expandid, unsigned long depth)
{
	word_t flags = 0; 
	u32_t  refcnt_flags, old_v;
	u8_t type;
	unsigned long old_pte, new_pte;
	unsigned long *    intern;
	int                ret = 0;

	intern = pgtbl_lkup_lvl(((struct cap_pgtbl *)ct)->pgtbl, expandid, &flags, ct->lvl, depth);
	if (!intern) return -ENOENT;
	old_pte = *intern;
	if (pgtbl_ispresent(old_pte)) return -EPERM;
	old_v = refcnt_flags = ((struct cap_pgtbl *)ctsub)->refcnt_flags;
	if (refcnt_flags & CAP_MEM_FROZEN_FLAG) return -EINVAL;
	if ((refcnt_flags & CAP_REFCNT_MAX) == CAP_REFCNT_MAX) return -EOVERFLOW;

	refcnt_flags++;
	ret = cos_cas_32((u32_t *)&(((struct cap_pgtbl *)ctsub)->refcnt_flags), old_v, refcnt_flags);
	if (ret != CAS_SUCCESS) return -ECASFAIL;

	new_pte = (u64_t)((chal_va2pa((void *)((struct cap_pgtbl *)ctsub)->pgtbl) & PGTBL_FRAME_MASK));

	type = ((struct cap_pgtbl *)ctsub)->type;
	if (type == PGTBL_TYPE_DEF) {
		new_pte |= X86_PGTBL_INTERN_DEF;
	} else if (type == PGTBL_TYPE_EPT) {
		new_pte |= x86_EPT_INTERN_DEF;

	} else {
		/* Some error has occured in this cap! */
		assert(0);
	}

	ret = cos_cas(intern, old_pte, new_pte);
	if (ret != CAS_SUCCESS) {
		/* decrement to restore the refcnt on failure. */
		cos_faa((int *)&(((struct cap_pgtbl *)ctsub)->refcnt_flags), -1);
		return -ECASFAIL;
	} else {
		ret = 0;
	}

	return ret;
}

int 
chal_pgtbl_decons(struct cap_header *head, struct cap_header *sub, capid_t pruneid, unsigned long lvl)
{
	unsigned long *    intern, old_v;

	struct cap_pgtbl *pt = (struct cap_pgtbl *)head;
	word_t            flags;
	if (lvl <= pt->lvl) return -EINVAL;
	intern = pgtbl_lkup_lvl(pt->pgtbl, pruneid, &flags, pt->lvl, lvl);

	if (!intern) return -ENOENT;
	old_v = *intern;

	/* Is this really a pte or we are trying to decons on superpages - prohibited? */
	if (old_v & X86_PGTBL_SUPER) return -EINVAL;
	if (old_v == 0) return 0; /* FIXME: old comment - return an error here? */
	/* commit; note that 0 is "no entry" in both pgtbl and captbl */
	if (cos_cas(intern, old_v, 0) != CAS_SUCCESS) return -ECASFAIL;

	/* decrement the refcnt */
	pt = (struct cap_pgtbl *)sub;
	u32_t l;
	l = pt->refcnt_flags;
	if (l & CAP_MEM_FROZEN_FLAG) return -EINVAL;
	cos_faa((int *)&(pt->refcnt_flags), -1);

	return 0;
}

word_t
chal_pgtbl_introspect(struct cap_header *ch, vaddr_t addr)
{
	unsigned long *pte;
	word_t         flags;
	word_t         ret = 0;
#if defined(__x86_64__)
	unsigned long		*f, old_v;

	f = pgtbl_lkup_lvl(((struct cap_pgtbl *)ch)->pgtbl, addr, &flags, 0, PGTBL_DEPTH);
	old_v = *f;
	return old_v;
#endif
	/* Is this a pte or a pgd? */
	pte = pgtbl_lkup_pgd(((struct cap_pgtbl *)ch)->pgtbl, addr, &flags);
	if (pte) {
		if (chal_pgtbl_flag_exist(*pte, PGTBL_SUPER)) {
			ret = *pte;
		} else {
			pte = pgtbl_lkup_pte(((struct cap_pgtbl *)ch)->pgtbl, addr, &flags);
			if (pte) ret = *pte;
		}
	}

	return ret;
}

int 
chal_pgtbl_deact_pre(struct cap_header *ch, u32_t pa)
{
	struct cap_pgtbl *deact_cap = (struct cap_pgtbl *)ch;
	void *            page      = deact_cap->pgtbl;
	u32_t             l         = deact_cap->refcnt_flags;
	u64_t             curr;
	int               ret;

	if (chal_pa2va((paddr_t)pa) != page) return -EINVAL;

	/* Require freeze memory and wait for quiescence
	 * first! */
	if (!(l & CAP_MEM_FROZEN_FLAG)) return -EQUIESCENCE;

	/* Quiescence check! */
	if (deact_cap->lvl == 0) {
		/* top level has tlb quiescence period. */
		if (!tlb_quiescence_check(deact_cap->frozen_ts)) return -EQUIESCENCE;
	} else {
		/* other levels have kernel quiescence
		 * period. (but the mapping scan will ensure
		 * tlb quiescence implicitly). */
		rdtscll(curr);
		if (!QUIESCENCE_CHECK(curr, deact_cap->frozen_ts, KERN_QUIESCENCE_CYCLES)) return -EQUIESCENCE;
	}

	/* set the scan flag to avoid concurrent scanning. */
	if (cos_cas_32((u32_t *)&deact_cap->refcnt_flags, l, l | CAP_MEM_SCAN_FLAG) != CAS_SUCCESS)
		return -ECASFAIL;

	if (deact_cap->lvl == 0) {
		/* PGD: only scan user mapping. */
		ret = kmem_page_scan(page, PAGE_SIZE - KERNEL_PGD_REGION_SIZE);
	} else if (deact_cap->lvl == PGTBL_DEPTH - 1) {
		/* Leaf level, scan mapping. */
		ret = pgtbl_mapping_scan(deact_cap);
	} else {
		/* don't have this with 2-level pgtbl. */
		ret = kmem_page_scan(page, PAGE_SIZE);
	}

	if (ret) {
		/* unset scan and frozen bits. */
		cos_cas_32((u32_t *)&deact_cap->refcnt_flags, l | CAP_MEM_SCAN_FLAG,
		        l & ~(CAP_MEM_FROZEN_FLAG | CAP_MEM_SCAN_FLAG));
		return ret;
	}
	cos_cas((unsigned long *)&deact_cap->refcnt_flags, l | CAP_MEM_SCAN_FLAG, l);

	return 0;
}

