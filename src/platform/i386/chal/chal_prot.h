/******************************************************************************
Filename    : chal_prot.h
Author      : Runyu Pan
Date        : ?/?/2018
Licence     : GPL v2; see COPYING for details.
Description : The Composite chal general prototype interface.
******************************************************************************/

/* Begin Function Prototypes *************************************************/
#ifndef CHAL_PROT
#define CHAL_PROT

/* Page table platform-dependent definitions */
#define PGTBL_PAGEIDX_SHIFT (12)
#define PGTBL_FRAME_BITS (32 - PGTBL_PAGEIDX_SHIFT)
#define PGTBL_FLAG_MASK ((1 << PGTBL_PAGEIDX_SHIFT) - 1)
#define PGTBL_FRAME_MASK (~PGTBL_FLAG_MASK)
#define PGTBL_DEPTH 2
#define PGTBL_ORD 10

/* Page table related prototypes & structs */
/* make it an opaque type...not to be touched */
typedef struct pgtbl *pgtbl_t;

/* identical to the capability structure */
struct cap_pgtbl {
	struct cap_header h;
	u32_t             refcnt_flags; /* includes refcnt and flags */
	pgtbl_t           pgtbl;
	u32_t             lvl;       /* what level are the pgtbl nodes at? */
	struct cap_pgtbl *parent;    /* if !null, points to parent cap */
	u64_t             frozen_ts; /* timestamp when frozen is set. */
} __attribute__((packed));

/* Do flag transformations */
/* These functions do flag operations */
/* PRESENT flag */
u32_t           chal_pgtbl_set_present(u32_t input);
u32_t           chal_pgtbl_clr_present(u32_t input);
u32_t           chal_pgtbl_is_present(u32_t input);
/* WRITABLE flag */
u32_t           chal_pgtbl_set_writable(u32_t input);
u32_t           chal_pgtbl_clr_writable(u32_t input);
u32_t           chal_pgtbl_is_writable(u32_t input);
/* USER flag */
u32_t           chal_pgtbl_set_user(u32_t input);
u32_t           chal_pgtbl_clr_user(u32_t input);
u32_t           chal_pgtbl_is_user(u32_t input);
/* WT flag */
u32_t           chal_pgtbl_set_wt(u32_t input);
u32_t           chal_pgtbl_clr_wt(u32_t input);
u32_t           chal_pgtbl_is_wt(u32_t input);
/* NOCACHE flag */
u32_t           chal_pgtbl_set_nocache(u32_t input);
u32_t           chal_pgtbl_clr_nocache(u32_t input);
u32_t           chal_pgtbl_is_nocache(u32_t input);
/* ACCESSED flag */
u32_t           chal_pgtbl_set_accessed(u32_t input);
u32_t           chal_pgtbl_clr_accessed(u32_t input);
u32_t           chal_pgtbl_is_accessed(u32_t input);
/* MODIFIED flag */
u32_t           chal_pgtbl_set_modified(u32_t input);
u32_t           chal_pgtbl_clr_modified(u32_t input);
u32_t           chal_pgtbl_is_modified(u32_t input);
/* SUPER flag */
u32_t           chal_pgtbl_set_super(u32_t input);
u32_t           chal_pgtbl_clr_super(u32_t input);
u32_t           chal_pgtbl_is_super(u32_t input);
/* GLOBAL flag */
u32_t           chal_pgtbl_set_global(u32_t input);
u32_t           chal_pgtbl_clr_global(u32_t input);
u32_t           chal_pgtbl_is_global(u32_t input);
/* COSFRAME flag */
u32_t           chal_pgtbl_set_cosframe(u32_t input);
u32_t           chal_pgtbl_clr_cosframe(u32_t input);
u32_t           chal_pgtbl_is_cosframe(u32_t input);
/* COSKMEM flag */
u32_t           chal_pgtbl_set_coskmem(u32_t input);
u32_t           chal_pgtbl_clr_coskmem(u32_t input);
u32_t           chal_pgtbl_is_coskmem(u32_t input);
/* QUIESCENCE flag */
u32_t          chal_pgtbl_set_quiescence(u32_t input);
u32_t          chal_pgtbl_clr_quiescence(u32_t input);
u32_t          chal_pgtbl_is_quiescence(u32_t input);
/* USER_DEF flag group */
u32_t          chal_pgtbl_set_user_def(u32_t input);
u32_t          chal_pgtbl_clr_user_def(u32_t input);
u32_t          chal_pgtbl_is_user_def(u32_t input);
/* INTERN_DEF flag group */
u32_t          chal_pgtbl_set_intern_def(u32_t input);
u32_t          chal_pgtbl_clr_intern_def(u32_t input);
u32_t          chal_pgtbl_is_intern_def(u32_t input);

int            chal_pgtbl_kmem_act(pgtbl_t pt, u32_t addr, unsigned long *kern_addr, unsigned long **pte_ret);
int            chal_tlb_quiescence_check(u64_t timestamp);
int            chal_cap_memactivate(struct captbl *ct, struct cap_pgtbl *pt, capid_t frame_cap, capid_t dest_pt, vaddr_t vaddr);
int            chal_pgtbl_activate(struct captbl *t, unsigned long cap, unsigned long capin, pgtbl_t pgtbl, u32_t lvl);
int            chal_pgtbl_deactivate(struct captbl *t, struct cap_captbl *dest_ct_cap, unsigned long capin,
                                     livenessid_t lid, capid_t pgtbl_cap, capid_t cosframe_addr, const int root);


int            chal_pgtbl_mapping_add(pgtbl_t pt, u32_t addr, u32_t page, u32_t flags);
int            chal_pgtbl_cosframe_add(pgtbl_t pt, u32_t addr, u32_t page, u32_t flags);
/* This function updates flags of an existing mapping. */
int            chal_pgtbl_mapping_mod(pgtbl_t pt, u32_t addr, u32_t flags, u32_t *prevflags);
int            chal_pgtbl_mapping_del(pgtbl_t pt, u32_t addr, u32_t liv_id);
int            chal_pgtbl_mapping_del_direct(pgtbl_t pt, u32_t addr);
int            chal_pgtbl_mapping_scan(struct cap_pgtbl *pt);
void          *chal_pgtbl_lkup_lvl(pgtbl_t pt, u32_t addr, u32_t *flags, u32_t start_lvl, u32_t end_lvl);
int            chal_pgtbl_ispresent(u32_t flags);
unsigned long *chal_pgtbl_lkup(pgtbl_t pt, u32_t addr, u32_t *flags);
unsigned long *chal_pgtbl_lkup_pte(pgtbl_t pt, u32_t addr, u32_t *flags);
int            chal_pgtbl_get_cosframe(pgtbl_t pt, vaddr_t frame_addr, paddr_t *cosframe);
pgtbl_t        chal_pgtbl_create(void *page, void *curr_pgtbl);
int            chal_pgtbl_quie_check(u32_t orig_v);
void           chal_pgtbl_init_pte(void *pte);

/* Cons & decons functions */
int            chal_pgtbl_cons(struct cap_captbl *ct, struct cap_captbl *ctsub, capid_t expandid, unsigned long depth);
#endif
/* End Function Prototypes ***************************************************/

/* End Of File ***************************************************************/

/* Copyright (C) GWU Systems & Security Lab. All rights reserved *************/

