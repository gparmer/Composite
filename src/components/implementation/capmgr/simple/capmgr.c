/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2020, The George Washington University
 * Author: Gabe Parmer, gparmer@gwu.edu
 */

#include <cos_debug.h>
#include <consts.h>
#include <static_slab.h>
#include <crt.h>

#include <cos_component.h>
#include <cos_kernel_api.h>
#include <cos_defkernel_api.h>
#include <initargs.h>
#include <addr.h>
#include <contigmem.h>

struct cm_rcv {
	struct crt_rcv  rcv;
	struct cm_comp *sched;
	arcvcap_t       aliased_cap;
};

struct cm_comp {
	struct crt_comp comp;
	struct cm_rcv *sched_rcv[NUM_CPU];    /* rcv cap for this scheduler or NULL if not a scheduler */
	struct cm_rcv *sched_parent; /* rcv cap for this scheduler's scheduler, or NULL */
};

struct cm_thd {
	struct crt_thd  thd;

	struct cm_comp *client; /* component thread begins execution in */
	struct cm_comp *sched;	/* The scheduler that has the alias */
	thdcap_t aliased_cap;	/* location thread is aliased into the scheduler. */
};

struct cm_asnd {
	struct crt_asnd asnd;
	asndcap_t       aliased_cap;
};

/*
 * Shared memory should be manager -> client, and between
 * point-to-point channel recipients
 */
#define MM_MAPPINGS_MAX 5

struct mm_mapping {
	SS_STATE_T(struct cm_comp *) comp;
	vaddr_t     addr;
};

typedef unsigned int cbuf_t;
struct mm_page {
	void *page;
	struct mm_mapping mappings[MM_MAPPINGS_MAX];
};

/* Span of pages, indexed by cbuf_t */
struct mm_span {
	unsigned int page_off;
	unsigned int n_pages;
};

SS_STATIC_SLAB(comp, struct cm_comp, MAX_NUM_COMPS);
SS_STATIC_SLAB(thd, struct cm_thd, MAX_NUM_THREADS);
/* These size values are somewhat arbitrarily chosen */
SS_STATIC_SLAB(rcv, struct cm_rcv, MAX_NUM_THREADS);
SS_STATIC_SLAB(asnd, struct cm_asnd, MAX_NUM_THREADS);

/* 64 MiB */
#define MB2PAGES(mb) (round_up_to_page(mb * 1024 * 1024) / PAGE_SIZE)
#define MM_NPAGES (MB2PAGES(9000))
SS_STATIC_SLAB(page, struct mm_page, MM_NPAGES);
SS_STATIC_SLAB(span, struct mm_span, MM_NPAGES);

#define CONTIG_PHY_PAGES 300000
static u8_t *contig_phy_pages = 0;
static u8_t *max_contig_phy_pages = 0;

static struct cm_comp *
cm_self(void)
{
	struct cm_comp *c = ss_comp_get(cos_compid());

	assert(c);

	return c;
}

static struct cm_comp *
cm_comp_self_alloc(char *name)
{
	struct cm_comp *c = ss_comp_alloc_at_id(cos_compid());

	assert(c);
	if (crt_booter_create(&c->comp, name, cos_compid(), 0)) BUG();
	ss_comp_activate(c);

	return c;
}

static struct cm_comp *
cm_comp_alloc_with(char *name, compid_t id, struct crt_comp_resources *resources)
{
	struct cm_comp *c = ss_comp_alloc_at_id(id);

	if (!c) return NULL;
	if (crt_comp_create_with(&c->comp, name, id, resources)) {
		ss_comp_free(c);
		return NULL;
	}
	ss_comp_activate(c);

	return c;
}

struct cm_rcv *
cm_rcv_alloc_in(struct crt_comp *c, struct crt_rcv *sched, thdclosure_index_t closure_id, crt_rcv_flags_t flags, thdcap_t *thdcap, thdid_t *tid)
{
	struct cm_rcv *r = ss_rcv_alloc();
	struct cm_thd *t = ss_thd_alloc();
	struct crt_rcv_resources res = (struct crt_rcv_resources) { 0 };
	struct cos_compinfo *target_ci = cos_compinfo_get(c->comp_res);
	struct cos_aep_info *sched_aep = cos_sched_aep_get(c->comp_res);

	if (!r) return NULL;
	if (crt_rcv_create_in(&r->rcv, c, sched, closure_id, flags)) {
		ss_rcv_free(r);
		return NULL;
	}
	ss_rcv_activate(r);

	if (crt_rcv_alias_in(&r->rcv, c, &res, CRT_RCV_ALIAS_THD | CRT_RCV_ALIAS_RCV | CRT_RCV_ALIAS_TCAP)) {
		ss_rcv_free(r);
		assert(0);
		return NULL;
	}
	r->aliased_cap = res.rcv;

	*tid = cos_introspect(target_ci, res.thd, THD_GET_TID);
	*thdcap = res.thd;

	return r;
}

struct cm_asnd *
cm_asnd_alloc_in(struct crt_comp *c, struct crt_rcv *rcv)
{
	struct cm_asnd *s = ss_asnd_alloc();
	struct crt_asnd_resources res = { 0 };

	if (!s) return NULL;
	if (crt_asnd_create(&s->asnd, rcv)) {
		ss_asnd_free(s);
		return NULL;
	}

	if (crt_asnd_alias_in(&s->asnd, c, &res)) {
		ss_asnd_free(s);
		return NULL;
	}
	s->aliased_cap = res.asnd;
	ss_asnd_activate(s);

	return s;
}

struct cm_thd *
cm_thd_alloc_in(struct cm_comp *c, struct cm_comp *sched, thdclosure_index_t closure_id)
{
	struct cm_thd *t = ss_thd_alloc();
	struct crt_thd_resources res = { 0 };

	if (!t) return NULL;
	if (crt_thd_create_in(&t->thd, &c->comp, closure_id)) {
		ss_thd_free(t);
		printc("capmgr: couldn't create new thread correctly.\n");
		return NULL;
	}
	ss_thd_activate(t);
	if (crt_thd_alias_in(&t->thd, &sched->comp, &res)) {
		printc("capmgr: couldn't alias correctly.\n");
		/* FIXME: reclaim the thread */
		return NULL;
	}

	t->sched       = sched;
	t->aliased_cap = res.cap;
	t->client      = c;
	/* FIXME: should take a reference to the scheduler */

	return t;
}

/**
 * Allocate a page from the pool of physical memory into a component.
 *
 * - @c - The component to allocate into.
 * - @return - the allocated and initialized page, or `NULL` if no
 *   page is available.
 */
static struct mm_page *
mm_page_alloc(struct cm_comp *c, unsigned long align)
{
	struct mm_mapping *m;
	struct mm_page    *ret = NULL, *p;
	int    i;

	p = ss_page_alloc();
	if (!p) return NULL;

	m = &p->mappings[0];
	if (ss_state_alloc(&m->comp)) BUG();

	/* Allocate page, map page */
	p->page = crt_page_allocn(&cm_self()->comp, 1);
	if (!p->page) ERR_THROW(NULL, free_p);
	if (crt_page_aliasn_aligned_in(p->page, align, 1, &cm_self()->comp, &c->comp, &m->addr)) BUG();

	ss_state_activate_with(&m->comp, (word_t)c);
	ss_page_activate(p);
	ret = p;
done:
	return ret;
free_p:
	ss_page_free(p);
	goto done;
}

static struct mm_page *
mm_page_allocn(struct cm_comp *c, unsigned long num_pages, unsigned long align)
{
	struct mm_page *p, *prev, *initial;
	unsigned long i;

	initial = prev = p = mm_page_alloc(c, align);
	if (!p) return 0;
	for (i = 1; i < num_pages; i++) {
		p = mm_page_alloc(c, PAGE_SIZE);
		if (!p) return NULL;
		if ((prev->page + 4096) != p->page) {
			BUG(); /* FIXME: handle concurrency */
		}
		prev = p;
	}

	return initial;
}

static vaddr_t
__memmgr_virt_to_phys(compid_t id, vaddr_t vaddr)
{
	struct cm_comp *c;

	c = ss_comp_get(id);
	if (!c) return 0;

	return call_cap_op(c->comp.comp_res->ci.pgtbl_cap, CAPTBL_OP_INTROSPECT, (vaddr_t)vaddr, 0, 0, 0);
}

vaddr_t
memmgr_virt_to_phys(vaddr_t vaddr)
{
	return __memmgr_virt_to_phys(cos_inv_token(), vaddr);
}

static void
contigmem_check(compid_t id, vaddr_t vaddr, int npages)
{
	vaddr_t paddr_pre = 0, paddr_next = 0;

	paddr_pre = __memmgr_virt_to_phys(id, vaddr);

	for (int i = 1; i < npages; i++) {
		paddr_next = __memmgr_virt_to_phys(id, vaddr + i * PAGE_SIZE);
		assert(paddr_next - paddr_pre == PAGE_SIZE);

		paddr_pre = paddr_next;
	}
}

vaddr_t
contigmem_alloc(unsigned long npages)
{
	struct cm_comp *c;
	struct mm_page *p;

	struct mm_mapping *m;

	vaddr_t vaddr;
	unsigned long i;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;

	void *page = contig_phy_pages;

	if (crt_page_aliasn_aligned_in(page, PAGE_SIZE, npages, &cm_self()->comp, &c->comp, &vaddr)) BUG();

	for (i = 0; i < npages; i++) {
		p = ss_page_alloc();
		assert(p);

		m = &p->mappings[0];
		if (ss_state_alloc(&m->comp)) BUG();

		p->page = page + i * PAGE_SIZE;
		m->addr = vaddr + i * PAGE_SIZE;

		ss_state_activate_with(&m->comp, (word_t)c);
		ss_page_activate(p);
	}

	contigmem_check(cos_inv_token(), (vaddr_t)vaddr, npages);
	contig_phy_pages += npages * PAGE_SIZE;
	assert((word_t)contig_phy_pages < max_contig_phy_pages + CONTIG_PHY_PAGES * PAGE_SIZE);
	return vaddr;
}

cbuf_t
contigmem_ro_shared_alloc_aligned(unsigned long npages, unsigned long align, vaddr_t *pgaddr)
{
	struct cm_comp *c;
	struct mm_page *p, *initial = NULL;
	struct mm_span *s;

	struct mm_mapping *m;

	vaddr_t vaddr;

	unsigned long i;
	int ret;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;

	void * page = contig_phy_pages;

	if (crt_ro_page_aliasn_aligned_in(page, align, npages, &cm_self()->comp, &c->comp, &vaddr)) BUG();

	s = ss_span_alloc();
	if (!s) return 0;
	for (i = 0; i < npages; i++) {
		p = ss_page_alloc();
		assert(p);

		if (unlikely(i == 0)) {
			initial = p;
		}

		m = &p->mappings[0];
		if (ss_state_alloc(&m->comp)) BUG();

		p->page = page + i * PAGE_SIZE;
		m->addr = vaddr + i * PAGE_SIZE;

		ss_state_activate_with(&m->comp, (word_t)c);
		ss_page_activate(p);
	}

	/**
	 * FIXME: Need to reslove concurrent issue here,
	 * this is not multi-thread safe
	 */
	s->page_off = ss_page_id(initial);
	s->n_pages  = npages;
	ss_span_activate(s);

	ret = ss_span_id(s);

	*pgaddr = initial->mappings[0].addr;

	contigmem_check(cos_inv_token(), (vaddr_t)vaddr, npages);
	contig_phy_pages += npages * PAGE_SIZE;
	assert((word_t)contig_phy_pages < max_contig_phy_pages + CONTIG_PHY_PAGES * PAGE_SIZE);
	return ret;
}

cbuf_t
contigmem_shared_alloc_aligned(unsigned long npages, unsigned long align, vaddr_t *pgaddr)
{
	struct cm_comp *c;
	struct mm_page *p, *initial = NULL;
	struct mm_span *s;

	struct mm_mapping *m;

	vaddr_t vaddr;

	unsigned long i;
	int ret;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;

	void * page = contig_phy_pages;

	if (crt_page_aliasn_aligned_in(page, align, npages, &cm_self()->comp, &c->comp, &vaddr)) BUG();

	s = ss_span_alloc();
	if (!s) return 0;
	for (i = 0; i < npages; i++) {
		p = ss_page_alloc();
		assert(p);

		if (unlikely(i == 0)) {
			initial = p;
		}

		m = &p->mappings[0];
		if (ss_state_alloc(&m->comp)) BUG();

		p->page = page + i * PAGE_SIZE;
		m->addr = vaddr + i * PAGE_SIZE;

		ss_state_activate_with(&m->comp, (word_t)c);
		ss_page_activate(p);
	}

	/**
	 * FIXME: Need to reslove concurrent issue here,
	 * this is not multi-thread safe
	 */
	s->page_off = ss_page_id(initial);
	s->n_pages  = npages;
	ss_span_activate(s);

	ret = ss_span_id(s);

	*pgaddr = initial->mappings[0].addr;

	contigmem_check(cos_inv_token(), (vaddr_t)vaddr, npages);
	contig_phy_pages += npages * PAGE_SIZE;
	assert((word_t)contig_phy_pages < max_contig_phy_pages + CONTIG_PHY_PAGES * PAGE_SIZE);
	return ret;
}

vaddr_t
memmgr_heap_page_allocn_aligned(unsigned long num_pages, unsigned long align)
{
	struct cm_comp *c;
	struct mm_page *p;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;
	p = mm_page_allocn(c, num_pages, align);
	if (!p) return 0;

	return (vaddr_t)p->mappings[0].addr;
}

vaddr_t
memmgr_map_phys_to_virt(paddr_t paddr, size_t size)
{
	struct cm_comp *c;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;

	return (vaddr_t)cos_hw_map(&c->comp.comp_res->ci, BOOT_CAPTBL_SELF_INITHW_BASE, paddr, size);
}

vaddr_t
memmgr_heap_page_allocn(unsigned long num_pages)
{
	return memmgr_heap_page_allocn_aligned(num_pages, PAGE_SIZE);
}

cbuf_t
memmgr_shared_page_allocn_aligned(unsigned long num_pages, unsigned long align, vaddr_t *pgaddr)
{
	struct cm_comp *c;
	struct mm_page *p;
	struct mm_span *s;
	cbuf_t ret = 0;

	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;
	s = ss_span_alloc();
	if (!s) return 0;
	p = mm_page_allocn(c, num_pages, align);
	if (!p) ERR_THROW(0, cleanup);

	s->page_off = ss_page_id(p);
	s->n_pages  = num_pages;
	ss_span_activate(s);

	ret = ss_span_id(s);

	*pgaddr = p->mappings[0].addr;
done:
	return ret;
cleanup:
	ss_span_free(s);
	goto done;
}

cbuf_t
memmgr_shared_page_allocn(unsigned long num_pages, vaddr_t *pgaddr)
{
	return memmgr_shared_page_allocn_aligned(num_pages, PAGE_SIZE, pgaddr);
}


/**
 * Alias a page of memory into another component (i.e., create shared
 * memory). The number of mappings are limited by `MM_MAPPINGS_MAX`.
 *
 * @p - the page we're going to alias
 * @c - the component to alias into
 * @addr - returns the virtual address mapped into
 * @return - `0` = success, `<0` = error
 */
static int
mm_page_alias(struct mm_page *p, struct cm_comp *c, vaddr_t *addr, unsigned long align)
{
	struct mm_mapping *m;
	int i;

	*addr = 0;
	for (i = 1; i < MM_MAPPINGS_MAX; i++) {
		m = &p->mappings[i];

		if (ss_state_alloc(&m->comp)) continue;
		if (crt_page_aliasn_aligned_in(p->page, align, 1, &cm_self()->comp, &c->comp, &m->addr)) BUG();
		assert(m->addr);
		*addr = m->addr;
		ss_state_activate_with(&m->comp, (word_t)c);

		return 0;
	}
	assert(i == MM_MAPPINGS_MAX);

	return -ENOMEM;
}

unsigned long
memmgr_shared_page_map_aligned_in_vm(cbuf_t id, unsigned long align, vaddr_t *pgaddr, compid_t cid)
{
	struct cm_comp *c;
	struct mm_span *s;
	struct mm_page *p;
	unsigned int i;
	vaddr_t addr;
	compid_t vmm = (compid_t)cos_inv_token();

	*pgaddr = 0;
	s = ss_span_get(id);
	if (!s) return 0;
	c = ss_comp_get(cid);
	if (!c) return 0;

	/* Only the vmm of this VM is allowed to call this interface */
	assert(vmm == c->comp.vm_comp_info.vmm_comp_id);

	for (i = 0; i < s->n_pages; i++) {
		struct mm_page *p;

		p = ss_page_get(s->page_off + i);
		if (!p) return 0;

		if (mm_page_alias(p, c, &addr, align)) BUG();
		if (*pgaddr == 0) *pgaddr = addr;
		align = PAGE_SIZE_4K;
	}

	return s->n_pages;
}

struct ps_lock map_lock = {.o = 0};

unsigned long
memmgr_shared_page_map_aligned(cbuf_t id, unsigned long align, vaddr_t *pgaddr)
{
	struct cm_comp *c;
	struct mm_span *s;
	struct mm_page *p;
	unsigned int i;
	vaddr_t addr;
	ps_lock_take(&map_lock);

	*pgaddr = 0;
	s = ss_span_get(id);
	if (!s) return 0;
	c = ss_comp_get(cos_inv_token());
	if (!c) return 0;

	for (i = 0; i < s->n_pages; i++) {
		struct mm_page *p;

		p = ss_page_get(s->page_off + i);
		if (!p) return 0;

		if (mm_page_alias(p, c, &addr, align)) BUG();
		if (*pgaddr == 0) *pgaddr = addr;
		align = PAGE_SIZE; // only the first page can have special alignment
	}
	ps_lock_release(&map_lock);

	return s->n_pages;
}

unsigned long
memmgr_shared_page_map(cbuf_t id, vaddr_t *pgaddr)
{
	return memmgr_shared_page_map_aligned(id, PAGE_SIZE, pgaddr);
}

static compid_t
capmgr_comp_sched_hier_get(compid_t cid)
{
#define SCHED_STR_SZ 36 /* base-10 32 bit int + "sched_hierarchy/" */
	char *sched;
	char serialized[SCHED_STR_SZ];

	snprintf(serialized, SCHED_STR_SZ, "scheduler_hierarchy/%ld", cid);
	sched = args_get(serialized);
	if (!sched) return 0;

	return atoi(sched);
}

static compid_t
capmgr_comp_sched_get(compid_t cid)
{
#define INIT_STR_SZ 35 /* base-10 32 bit int + "init_hierarchy/" */
	char *sched;
	char serialized[SCHED_STR_SZ];

	snprintf(serialized, SCHED_STR_SZ, "init_hierarchy/%ld", cid);
	sched = args_get(serialized);
	if (!sched) return 0;

	return atoi(sched);
}

static void
capmgr_execution_init(int is_init_core)
{
	struct initargs cap_entries, exec_entries, curr;
	struct initargs_iter i;
	vaddr_t vasfr = 0;
	capid_t capfr = 0;
	int ret, cont;

	/* Create execution in the relevant components */
	ret = args_get_entry("execute", &exec_entries);
	assert(!ret);
	if (is_init_core) printc("Capmgr: %d components that need execution\n", args_len(&exec_entries));
	for (cont = args_iter(&exec_entries, &i, &curr) ; cont ; cont = args_iter_next(&i, &curr)) {
		struct cm_comp    *cmc;
		struct crt_comp   *comp;
		int      keylen;
		compid_t id        = atoi(args_key(&curr, &keylen));
		char    *exec_type = args_value(&curr);
		struct crt_comp_exec_context ctxt = { 0 };

		assert(exec_type);
		assert(id != cos_compid());
		cmc  = ss_comp_get(id);
		assert(cmc);
		comp = &cmc->comp;

		if (!strcmp(exec_type, "sched")) {
			struct cm_rcv *r = ss_rcv_alloc();

			assert(r);
			if (crt_comp_exec(comp, crt_comp_exec_sched_init(&ctxt, &r->rcv))) BUG();
			ss_rcv_activate(r);
			cmc->sched_rcv[cos_cpuid()] = r;
			if (is_init_core) printc("\tCreated scheduling execution for %ld\n", id);
		} else if (!strcmp(exec_type, "init")) {
			struct cm_thd *t = ss_thd_alloc();

			assert(t);
			if (crt_comp_exec(comp, crt_comp_exec_thd_init(&ctxt, &t->thd))) BUG();
			ss_thd_activate(t);
			if (is_init_core) printc("\tCreated thread for %ld\n", id);
		} else {
			printc("Error: Found unknown execution schedule type %s.\n", exec_type);
			BUG();
		}
	}

	return;
}

static void
capmgr_comp_init(void)
{
	struct initargs cap_entries, exec_entries, shared_comps, curr;
	struct initargs_iter i;
	vaddr_t vasfr = 0;
	capid_t capfr = 0;
	int ret, cont;
	struct cm_comp *comp;

	int remaining = 0;
	int num_comps = 0;

	/* ...then those that we're responsible for... */
	ret = args_get_entry("captbl", &cap_entries);
	assert(!ret);
	printc("Capmgr: processing %d capabilities for components that have already been booted\n", args_len(&cap_entries));

	for (cont = args_iter(&cap_entries, &i, &curr) ; cont ; ) {
		compid_t sched_id;
		compid_t id = 0;
		struct crt_comp_resources comp_res = { 0 };
		int keylen;
		int j;
		char id_serialized[16]; 	/* serialization of the id number */
		char *name;

		for (j = 0 ; j < 3 ; j++, cont = args_iter_next(&i, &curr)) {
			capid_t capid = atoi(args_key(&curr, &keylen));
			char   *type  = args_get_from("type", &curr);

			assert(capid && type);

			if (j == 0) id = atoi(args_get_from("target", &curr));
			else        assert((compid_t)atoi(args_get_from("target", &curr)) == id);

			if (!strcmp(type, "comp")) {
				comp_res.compc = capid;
			} else if (!strcmp(type, "captbl")) {
				comp_res.ctc = capid;
			} else if (!strcmp(type, "pgtbl")) {
				comp_res.ptc = capid;
			} else {
				BUG();
			}
		}
		assert(id);

		assert(comp_res.compc && comp_res.ctc && comp_res.ptc);
		sched_id = capmgr_comp_sched_get(id);
		if (sched_id == 0) {
			sched_id = capmgr_comp_sched_hier_get(id);
		}
		comp_res.heap_ptr        = addr_get(id, ADDR_HEAP_FRONTIER);
		comp_res.captbl_frontier = addr_get(id, ADDR_CAPTBL_FRONTIER);

		snprintf(id_serialized, 20, "names/%ld", id);
		name = args_get(id_serialized);
		assert(name);
		printc("\tCreating component %s: id %ld\n", name, id);
		printc("\t\tcaptbl:%ld, pgtbl:%ld, comp:%ld, captbl/pgtbl frontiers %d & %lx, sched %ld\n",
		       comp_res.ctc, comp_res.ptc, comp_res.compc, comp_res.captbl_frontier, comp_res.heap_ptr, sched_id);
		comp = cm_comp_alloc_with(name, id, &comp_res);
		assert(comp);
	}

	/* Create ULK memory region for UL sinvs and map it into comps that need it */
	ret = crt_ulk_init();
	assert(!ret);
	ret = args_get_entry("addrspc_shared", &shared_comps);
	assert(!ret);
	for (cont = args_iter(&shared_comps, &i, &curr) ; cont ; cont = args_iter_next(&i, &curr)) {
		compid_t        id  = atoi(args_value(&curr));
		struct cm_comp *cmc = ss_comp_get(id);

		/* if this fails, we already aliased the ICB memory into this shared pt */
		crt_ulk_map_in(&cmc->comp);
	}

	return;
}

static inline struct crt_comp *
crtcomp_get(compid_t id)
{
	struct cm_comp *c = ss_comp_get(id);

	assert(c);

	return &c->comp;
}

void
capmgr_set_tls(thdcap_t cap, void* tls_addr)
{
	compid_t cid = (compid_t)cos_inv_token();
	struct crt_comp* c = crtcomp_get(cid);

	cos_thd_mod(&c->comp_res->ci, cap, tls_addr);
}

void
init_done(int parallel_init, init_main_t main_type)
{
	compid_t client = (compid_t)cos_inv_token();
	struct crt_comp *c;

	assert(client > 0 && client <= MAX_NUM_COMPS);
	c = crtcomp_get(client);

	crt_compinit_done(c, parallel_init, main_type);

	return;
}


void
init_exit(int retval)
{
	compid_t client = (compid_t)cos_inv_token();
	struct crt_comp *c;

	assert(client > 0 && client <= MAX_NUM_COMPS);
	c = crtcomp_get(client);
	assert(c);

	crt_compinit_exit(c, retval);

	while (1) ;
}

thdcap_t
capmgr_thd_create_ext(spdid_t client, thdclosure_index_t idx, thdid_t *tid)
{
	compid_t schedid = (compid_t)cos_inv_token();
	struct cm_thd *t;
	struct cm_comp *s, *c;

	c = ss_comp_get(client);

	if (schedid != capmgr_comp_sched_get(client)) {
		if (c->comp.flags & CRT_COMP_VM) {
			schedid = c->comp.vm_comp_info.vmm_comp_id;
		} else {
			/* don't have permission to create execution in that component. */
			printc("capmgr: Component asking to create thread from %ld in %ld -- no permission.\n",
			schedid, (compid_t)client);
			return 0;
		}
	}

	s = ss_comp_get(schedid);
	if (!c || !s) return 0;
	t = cm_thd_alloc_in(c, s, idx);
	if (!t) {
		/* TODO: release resources */
		return 0;
	}
	*tid = t->thd.tid;

	return t->aliased_cap;
}

thdcap_t
capmgr_initthd_create(spdid_t client, thdid_t *tid)
{
	return capmgr_thd_create_ext(client, 0, tid);
}

thdcap_t  capmgr_initaep_create(spdid_t child, struct cos_aep_info *aep, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, asndcap_t *sndret) { BUG(); return 0; }

thdcap_t
capmgr_thd_create_thunk(thdclosure_index_t idx, thdid_t *tid)
{
	compid_t client = (compid_t)cos_inv_token();
	struct cm_thd *t;
	struct cm_comp *c;

	assert(client > 0 && client <= MAX_NUM_COMPS);
	c = ss_comp_get(client);
	t = cm_thd_alloc_in(c, c, idx);
	if (!t) {
		/* TODO: release resources */
		return 0;
	}

	*tid = t->thd.tid;

	return t->aliased_cap;
}

arcvcap_t
capmgr_rcv_create(thdclosure_index_t idx, crt_rcv_flags_t flags, asndcap_t *asnd, thdcap_t *thdcap, thdid_t *tid)
{
	compid_t sched = (compid_t)cos_inv_token();
	struct cm_comp   *c;
	struct cm_rcv    *r;
	struct cm_asnd   *s;
	arcvcap_t  child_rcv;

	/* TODO: Should replace this static check with one that uses the initargs to validate that the call is coming from the scheduler. */
	c = ss_comp_get(sched);

	r = cm_rcv_alloc_in(&c->comp, &c->sched_rcv[cos_cpuid()]->rcv, idx, flags, thdcap, tid);

	s = cm_asnd_alloc_in(&c->comp, &r->rcv);
	*asnd = s->aliased_cap;

	return r->aliased_cap;
}

static struct cm_thd *
capmgr_get_thd(thdid_t tid)
{
	/* This can only be used on the slow path */
	struct cm_thd *thd;
	for (int i = 1; i < MAX_NUM_THREADS; i++) {
		thd = ss_thd_get(i);
		if (thd == NULL) continue;
		if (thd->thd.tid == tid) return thd;
	}
	
	return NULL;
}

compid_t
capmgr_vm_comp_create(u64_t mem_sz)
{
	/* TODO: allocate name rather than make it static */
	char *name = "vmlinux";
	prot_domain_t protdom = 0;
	compid_t id = crt_comp_id_new();

	/* Allocate a new comp */
	struct cm_comp *c = ss_comp_alloc_at_id(id);
	assert(c);

	crt_comp_vm_create(&c->comp, name, id, protdom);

	ss_comp_activate(c);

	return id;
}

vaddr_t
capmgr_vm_shared_kernel_page_create_at(compid_t comp_id, vaddr_t addr)
{
	struct cm_comp *vmm = ss_comp_get(cos_inv_token());
	struct cm_comp *vm = ss_comp_get(comp_id);

	assert(vmm && vm);
	assert(vm->comp.vm_comp_info.vmm_comp_id == vmm->comp.id);

	return crt_comp_shared_kernel_page_alloc_at(&vm->comp, addr);
}

vaddr_t
capmgr_shared_kernel_page_create(vaddr_t *resource)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_comp_shared_kernel_page_alloc(&c->comp, resource);
}

capid_t
capmgr_vm_vmcs_create(void)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_vm_vmcs_create(&c->comp);
}

capid_t
capmgr_vm_msr_bitmap_create(void)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_vm_msr_bitmap_create(&c->comp);
}

capid_t
capmgr_vm_lapic_create(vaddr_t *page)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_vm_lapic_create(&c->comp, page);
}

capid_t
capmgr_vm_shared_region_create(vaddr_t *page)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_vm_shared_region_create(&c->comp, page);
}

/* lapic access page is very special: all vcpu needs to set the same mem page */
capid_t
capmgr_vm_lapic_access_create(vaddr_t mem)
{
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	return crt_vm_lapic_access_create(&c->comp, mem);
}

capid_t
capmgr_vm_vmcb_create(vm_vmcscap_t vmcs_cap, vm_msrbitmapcap_t msr_bitmap_cap, vm_lapicaccesscap_t lapic_access_cap, vm_lapiccap_t lapic_cap, vm_shared_mem_t shared_mem_cap, thdid_t handler_thd_id, word_t vpid)
{
	struct cm_thd *handler_thd;
	struct cm_comp *c = ss_comp_get(cos_inv_token());
	assert(c);

	handler_thd = capmgr_get_thd(handler_thd_id);

	return crt_vm_vmcb_create(&c->comp, vmcs_cap, msr_bitmap_cap, lapic_access_cap, lapic_cap, shared_mem_cap, handler_thd->thd.cap, vpid);
}

thdcap_t
capmgr_vm_vcpu_create(compid_t vm_comp, vm_vmcb_t vmcb_cap, thdid_t *tid)
{
	/*
	 * Set vmcb_cap as the closure_id to pass this cap into kernel,
	 * this is OK since vm thread doesn't need closure_id, and the 
	 * existing thead creation api has used all arguments(thus it's
	 * not easy to modify it).
	 */
	return capmgr_thd_create_ext(vm_comp, vmcb_cap, tid);
}

thdcap_t  capmgr_aep_create_thunk(struct cos_aep_info *a, thdclosure_index_t idx, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax) { BUG(); return 0; }
thdcap_t  capmgr_aep_create_ext(spdid_t child, struct cos_aep_info *a, thdclosure_index_t idx, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, arcvcap_t *extrcv) { BUG(); return 0; }
asndcap_t capmgr_asnd_create(spdid_t child, thdid_t t) { BUG(); return 0; }
asndcap_t capmgr_asnd_rcv_create(arcvcap_t rcv) { BUG(); return 0; }
asndcap_t capmgr_asnd_key_create(cos_channelkey_t key) { BUG(); return 0; }

void capmgr_create_noop(void) { return; }

void
cos_init(void)
{
	struct cos_defcompinfo *defci = cos_defcompinfo_curr_get();
	struct cos_compinfo    *ci    = cos_compinfo_get(defci);
	struct initargs curr, comps;
	struct initargs_iter i;
	int cont, found_shared = 0;
	int ret;

	/* 
	 * FIXME: This is a hack since the booter's __thdid_alloc is
	 *        initialized the same as ours. Need a better solution.
	 */
	extern unsigned long __thdid_alloc;
	__thdid_alloc = NUM_CPU * 4;

	printc("Starting the capability manager.\n");
	assert(atol(args_get("captbl_end")) >= BOOT_CAPTBL_FREE);

	/* Example code to walk through the components in shared address spaces */
	printc("Components in shared address spaces: ");
	ret = args_get_entry("addrspc_shared", &comps);
	assert(!ret);
	for (cont = args_iter(&comps, &i, &curr) ; cont ; cont = args_iter_next(&i, &curr)) {
		compid_t id = atoi(args_value(&curr));

		found_shared = 1;
		printc("%ld ", id);
	}
	if (!found_shared) {
		printc("none");
	}
	printc("\n");

	/* Get our house in order. Initialize ourself and our data-structures */
	cos_meminfo_init(&(ci->mi), BOOT_MEM_KM_BASE, COS_MEM_KERN_PA_SZ, BOOT_CAPTBL_SELF_UNTYPED_PT);
	cos_defcompinfo_init();

	/*
	 * FIXME: this is a hack. The captbl_end variable does *not*
	 * take into account the synchronous invocations yet. That is
	 * because we don't want to modify the image to include it
	 * after we've sealed in all initargs and sinvs. Regardless,
	 * that is the *correct* approach.
	 */
	cos_comp_capfrontier_update(ci, addr_get(cos_compid(), ADDR_CAPTBL_FRONTIER), 0);
	if (!cm_comp_self_alloc("capmgr")) BUG();
	/* Initialize the other component's for which we're responsible */
	capmgr_comp_init();

	/* Reserve some continuous pages */
	contig_phy_pages = crt_page_allocn(&cm_self()->comp, CONTIG_PHY_PAGES);
	max_contig_phy_pages = contig_phy_pages;
	contigmem_check(cos_compid(), (vaddr_t)contig_phy_pages, CONTIG_PHY_PAGES);

	return;
}

void
cos_parallel_init(coreid_t cid, int init_core, int ncores)
{
	cos_defcompinfo_sched_init();
	capmgr_execution_init(init_core);
}

void
parallel_main(coreid_t cid)
{
	crt_compinit_execute(crtcomp_get);
}
