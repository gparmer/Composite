/* These code below are for x86 specifically */
typedef enum {
	X86_PRESENT  = 1,
	X86_WRITABLE = 1 << 1,
	X86_USER     = 1 << 2,
	X86_WT       = 1 << 3, /* write-through caching */
	X86_NOCACHE  = 1 << 4, /* caching disabled */
	X86_ACCESSED = 1 << 5,
	X86_MODIFIED = 1 << 6,
	X86_SUPER    = 1 << 7, /* super-page (4MB on x86-32) */
	X86_GLOBAL   = 1 << 8,
	/* Composite defined bits next*/
	X86_COSFRAME   = 1 << 9,
	X86_COSKMEM    = 1 << 10, /* page activated as kernel object */
	X86_QUIESCENCE = 1 << 11,
	/* Flag bits done. */

	X86_USER_DEF   = X86_PRESENT | X86_USER | X86_ACCESSED | X86_MODIFIED | X86_WRITABLE,
	X86_INTERN_DEF = X86_USER_DEF,
} pgtbl_flags_x86_t;

/*
 * Use the passed in page, but make sure that we only use the passed
 * in page once.
 */
static inline void *
__pgtbl_a(void *d, int sz, int leaf)
{
	void **i = d, *p;

	(void)leaf;
	assert(sz == PAGE_SIZE);
	if (unlikely(!*i)) return NULL;
	p  = *i;
	*i = NULL;
	return p;
}
static struct ert_intern *
__pgtbl_get(struct ert_intern *a, void *accum, int isleaf)
{
	(void)isleaf;
	/* don't use | here as we only want the pte flags */
	*(u32_t *)accum = (((u32_t)a->next) & PGTBL_FLAG_MASK);
	return chal_pa2va((paddr_t)((((u32_t)a->next) & PGTBL_FRAME_MASK)));
}
static int
__pgtbl_isnull(struct ert_intern *a, void *accum, int isleaf)
{
	(void)isleaf;
	(void)accum;
	return !(((u32_t)(a->next)) & (X86_PRESENT | X86_COSFRAME));
}
static void
__pgtbl_init(struct ert_intern *a, int isleaf)
{
	(void)isleaf;
	//	if (isleaf) return;
	a->next = NULL;
}

/* We only need to do mapping_add at boot time to add all physical
 * memory to the pgtbl of llboot. After that, we only need to do copy
 * from llboot pgtbl to other pgtbls. Thus, when adding to pgtbl, we
 * use physical addresses; when doing copy, we don't need to worry
 * about PA. */

/* v should include the desired flags */
static inline int
__pgtbl_setleaf(struct ert_intern *a, void *v)
{
	u32_t new, old;

	old = (u32_t)(a->next);
	new = (u32_t)(v);

	if (!cos_cas((unsigned long *)a, old, new)) return -ECASFAIL;

	return 0;
}

/* This takes an input parameter as the old value of the mapping. Only
 * update when the existing value matches. */
static inline int
__pgtbl_update_leaf(struct ert_intern *a, void *v, u32_t old)
{
	u32_t new;

	new = (u32_t)(v);
	if (!cos_cas((unsigned long *)a, old, new)) return -ECASFAIL;

	return 0;
}

/* Note:  We're just using pre-defined default flags for internal (pgd) entries */
static int
__pgtbl_set(struct ert_intern *a, void *v, void *accum, int isleaf)
{
	u32_t old, new;
	(void)accum;
	assert(!isleaf);

	old = (u32_t)a->next;
	new = (u32_t)chal_va2pa((void *)((u32_t)v & PGTBL_FRAME_MASK)) | X86_INTERN_DEF;

	if (!cos_cas((unsigned long *)&a->next, old, new)) return -ECASFAIL;

	return 0;
}

static inline void *
__pgtbl_getleaf(struct ert_intern *a, void *accum)
{
	if (unlikely(!a)) return NULL;
	return __pgtbl_get(a, accum, 1);
}

ERT_CREATE(__pgtbl, pgtbl, PGTBL_DEPTH, PGTBL_ORD, sizeof(int *), PGTBL_ORD, sizeof(int *), NULL, __pgtbl_init,
           __pgtbl_get, __pgtbl_isnull, __pgtbl_set, __pgtbl_a, __pgtbl_setleaf, __pgtbl_getleaf, ert_defresolve);

static pgtbl_t
pgtbl_alloc(void *page)
{
	return (pgtbl_t)((unsigned long)__pgtbl_alloc(&page) & PGTBL_FRAME_MASK);
}

static int
pgtbl_intern_expand(pgtbl_t pt, u32_t addr, void *pte, u32_t flags)
{
	unsigned long accum = (unsigned long)flags;
	int           ret;

	/* NOTE: flags currently ignored. */

	assert(pt);
	assert((PGTBL_FLAG_MASK & (u32_t)pte) == 0);
	assert((PGTBL_FRAME_MASK & flags) == 0);

	if (!pte) return -EINVAL;
	ret = __pgtbl_expandn(pt, (unsigned long)(addr >> PGTBL_PAGEIDX_SHIFT), PGTBL_DEPTH, &accum, &pte, NULL);
	if (!ret && pte) return -EEXIST; /* no need to expand */
	assert(!(ret && !pte));          /* error and used memory??? */

	return ret;
}

/*
 * FIXME: If these need to return a physical address, we should do a
 * va2pa before returning
 */
static void *
pgtbl_intern_prune(pgtbl_t pt, u32_t addr)
{
	unsigned long accum = 0, *pgd;
	void *        page;

	assert(pt);
	assert((PGTBL_FLAG_MASK & (u32_t)addr) == 0);

	pgd = __pgtbl_lkupan((pgtbl_t)((u32_t)pt | X86_PRESENT), (u32_t)addr >> PGTBL_PAGEIDX_SHIFT, 1, &accum);
	if (!pgd) return NULL;
	page  = __pgtbl_get((struct ert_intern *)pgd, &accum, 0);
	accum = 0;

	if (__pgtbl_set((struct ert_intern *)pgd, NULL, &accum, 0)) return NULL;

	return page;
}

/* FIXME:  these pgd functions should be replaced with lookup_lvl functions (see below) */
static void *
pgtbl_get_pgd(pgtbl_t pt, u32_t addr)
{
	unsigned long accum = 0;

	assert(pt);
	return __pgtbl_lkupan((pgtbl_t)((u32_t)pt | X86_PRESENT), (u32_t)addr >> PGTBL_PAGEIDX_SHIFT, 1, &accum);
}

static int
pgtbl_check_pgd_absent(pgtbl_t pt, u32_t addr)
{
	return __pgtbl_isnull(pgtbl_get_pgd(pt, (u32_t)addr), 0, 0);
}

