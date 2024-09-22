#ifndef CRT_H
#define CRT_H

#include <cos_kernel_api.h>
#include <cos_defkernel_api.h>
#include <cos_component.h>
#include <cos_types.h>
#include <init.h>
#include <barrier.h>
#include <protdom.h>

typedef unsigned long crt_refcnt_t;

#define CRT_COMP_SINVS_LEN 16

struct crt_comp;

struct crt_asnd {
	struct crt_rcv *rcv;
	asndcap_t asnd;
};

struct crt_asnd_resources {
	asndcap_t asnd;
};

typedef enum {
	CRT_COMP_NONE        = 0,
	CRT_COMP_SCHED       = 1, 	/* is this a scheduler? */
	CRT_COMP_CAPMGR      = 2,	/* does this component require delegating management capabilities to it? */
	CRT_COMP_INITIALIZE  = 4,	/* The current component should initialize this component... */
	CRT_COMP_BOOTER      = 8,	/* Is this the current component (i.e. the booter)? */
	CRT_COMP_VM          = 16,	/* VM component */
} crt_comp_flags_t;

struct crt_comp_exec_context {
	crt_comp_flags_t flags;
	union {
		struct crt_thd *thd;
		struct crt_sched {
			struct crt_rcv *sched_rcv;
			struct crt_asnd sched_asnd;
		} sched;
	} exec[NUM_CPU];
	size_t memsz;
};

typedef enum {
	CRT_COMP_INIT_PREINIT,
	CRT_COMP_INIT_COS_INIT,
	CRT_COMP_INIT_PAR_INIT,
	CRT_COMP_INIT_MAIN, /* type of main is determined by main_type */
	CRT_COMP_INIT_PASSIVE,
	CRT_COMP_INIT_TERM
} crt_comp_init_state_t;

struct crt_sinv {
	char *name;
	struct crt_comp *server, *client;
	vaddr_t c_fn_addr, c_ucap_addr;
	vaddr_t s_fn_addr;
	sinvcap_t sinv_cap;
};

struct crt_vm_comp_info {
	compid_t vmm_comp_id;
};

struct crt_comp {
	crt_comp_flags_t flags;
	char *name;
	compid_t id;
	vaddr_t entry_addr, ro_addr, rw_addr, info;

	char *mem;		/* image memory */
	pgtblcap_t capmgr_untyped_mem;
	struct elf_hdr *elf_hdr;
	struct cos_defcompinfo *comp_res;
	struct cos_defcompinfo comp_res_mem;

	/* Flags hold tagged variant indicating the execution type */
	struct crt_comp_exec_context exec_ctxt;

	/* Initialization state and coordination information */
	volatile crt_comp_init_state_t init_state;
	init_main_t main_type; /* does this component have post-initialization execution? */
	struct simple_barrier barrier;
	coreid_t init_core;

	crt_refcnt_t refcnt;

	size_t tot_sz_mem;
	size_t ro_sz;
	struct crt_sinv sinvs[CRT_COMP_SINVS_LEN];
	u32_t  n_sinvs;

	prot_domain_t protdom;
	capid_t second_lvl_pgtbl_cap;
	struct protdom_ns_vas *ns_vas;

	struct crt_vm_comp_info vm_comp_info;
};

struct crt_comp_resources {
	pgtblcap_t  ptc;
	captblcap_t ctc;
	compcap_t   compc;
	cap_t       captbl_frontier;
	vaddr_t     heap_ptr;
	vaddr_t     info;
};

struct crt_chkpt {
	struct crt_comp *c;
	char            *mem;
	size_t           tot_sz_mem;
};

typedef enum {
	CRT_COMP_ALIAS_NONE   = 0,
	CRT_COMP_ALIAS_PGTBL  = 1,
	CRT_COMP_ALIAS_CAPTBL = 1 << 1,
	CRT_COMP_ALIAS_COMP   = 1 << 2,
	CRT_COMP_ALIAS_ALL    = CRT_COMP_ALIAS_PGTBL | CRT_COMP_ALIAS_CAPTBL | CRT_COMP_ALIAS_COMP
} crt_comp_alias_t;

struct crt_thd {
	thdcap_t cap;
	thdid_t  tid;
	struct crt_comp *c;
};

struct crt_thd_resources {
	thdcap_t cap;
};

typedef enum {
	CRT_RCV_TCAP_INHERIT = 1 /* should the rcv inherit/use the tcap from its scheduler? */
} crt_rcv_flags_t;

struct crt_rcv {
	crt_comp_flags_t flags;
	/* The thread/component the aep is attached to */
	struct crt_thd thd;
	/* Local information in this component */
	struct cos_aep_info *aep; /* either points to local_aep, or a component's aep */
	struct cos_aep_info local_aep;
	arcvcap_t child_rcv;	/* set by alias when mapped into child */

	struct crt_comp *c;
	crt_refcnt_t refcnt; 	/* senders create references */
};

struct crt_rcv_resources {
	tcap_t          tc;
	thdcap_t        thd;
	arcvcap_t       rcv;
	thdid_t         tid;
};

typedef enum {
	CRT_RCV_ALIAS_NONE = 0,
	CRT_RCV_ALIAS_THD  = 1,
	CRT_RCV_ALIAS_TCAP = 2,
	CRT_RCV_ALIAS_RCV  = 4,
	CRT_RCV_ALIAS_ALL  = CRT_RCV_ALIAS_THD | CRT_RCV_ALIAS_TCAP | CRT_RCV_ALIAS_RCV,
} crt_rcv_alias_t;

struct crt_sinv_resources {
	sinvcap_t sinv_cap;
};

int crt_comp_create(struct crt_comp *c, char *name, compid_t id, void *elf_hdr, vaddr_t info, prot_domain_t protdom);
int crt_comp_create_with(struct crt_comp *c, char *name, compid_t id, struct crt_comp_resources *resources);
int crt_comp_vm_create(struct crt_comp *c, char *name, compid_t id, prot_domain_t protdom);
int crt_vm_comp_init(struct crt_comp *c, char *name, compid_t id, vaddr_t info);

int crt_comp_create_from(struct crt_comp *c, char *name, compid_t id, struct crt_chkpt *chkpt);
unsigned long crt_ncomp();
unsigned long crt_nchkpt();
unsigned long crt_comp_id_new(void);

int crt_comp_alias_in(struct crt_comp *c, struct crt_comp *c_in, struct crt_comp_resources *res, crt_comp_alias_t flags);
void crt_comp_captbl_frontier_update(struct crt_comp *c, capid_t capid);
vaddr_t crt_comp_shared_kernel_page_alloc_at(struct crt_comp *c, vaddr_t mem_ptr);
vaddr_t crt_comp_shared_kernel_page_alloc(struct crt_comp *c, vaddr_t *resource);
int crt_booter_create(struct crt_comp *c, char *name, compid_t id, vaddr_t info);
thdcap_t crt_comp_thdcap_get(struct crt_comp *c);
int crt_comp_sched_delegate(struct crt_comp *child, struct crt_comp *self, tcap_prio_t prio, tcap_res_t res);

struct crt_comp_exec_context *crt_comp_exec_sched_init(struct crt_comp_exec_context *ctxt, struct crt_rcv *r);
struct crt_comp_exec_context *crt_comp_exec_thd_init(struct crt_comp_exec_context *ctxt, struct crt_thd *t);
struct crt_comp_exec_context *crt_comp_exec_capmgr_init(struct crt_comp_exec_context *ctxt, size_t untyped_memsz);
int crt_comp_exec(struct crt_comp *c, struct crt_comp_exec_context *ctxt);
struct crt_rcv *crt_comp_exec_rcv(struct crt_comp *comp);
struct crt_thd *crt_comp_exec_thd(struct crt_comp *comp);

capid_t crt_vm_vmcs_create(struct crt_comp *comp);
capid_t crt_vm_msr_bitmap_create(struct crt_comp *comp);
capid_t crt_vm_lapic_create(struct crt_comp *comp, vaddr_t *page);
capid_t crt_vm_lapic_access_create(struct crt_comp *comp, vaddr_t mem);
capid_t crt_vm_shared_region_create(struct crt_comp *comp, vaddr_t *page);
capid_t crt_vm_vmcb_create(struct crt_comp *comp, vm_vmcscap_t vmcs_cap, vm_msrbitmapcap_t msr_bitmap_cap, vm_lapicaccesscap_t lapic_access_cap, vm_lapiccap_t lapic_cap, vm_shared_mem_t shared_mem_cap, thdcap_t handler_thd_cap, u16_t vpid);

int crt_sinv_create(struct crt_sinv *sinv, char *name, struct crt_comp *server, struct crt_comp *client, vaddr_t c_fn_addr, vaddr_t c_fast_callgate_addr, vaddr_t c_ucap_addr, vaddr_t s_fn_addr, vaddr_t s_altfn_addr);
int crt_sinv_create_shared(struct crt_sinv *sinv, char *name, struct crt_comp *server, struct crt_comp *client, vaddr_t c_fn_addr, vaddr_t c_ucap_addr, vaddr_t s_fn_addr);

int crt_sinv_alias_in(struct crt_sinv *s, struct crt_comp *c, struct crt_sinv_resources *res);

int crt_asnd_create(struct crt_asnd *s, struct crt_rcv *r);
int crt_asnd_alias_in(struct crt_asnd *s, struct crt_comp *c, struct crt_asnd_resources *res);

typedef cos_thd_fn_t crt_thd_fn_t;
int crt_rcv_create(struct crt_rcv *r, struct crt_comp *self, crt_thd_fn_t fn, void *data);
int crt_rcv_create_in(struct crt_rcv *r, struct crt_comp *c, struct crt_rcv *sched, thdclosure_index_t closure_id, crt_rcv_flags_t flags);
int crt_rcv_create_with(struct crt_rcv *r, struct crt_comp *c, struct crt_rcv_resources *rs);
int crt_rcv_alias_in(struct crt_rcv *r, struct crt_comp *c, struct crt_rcv_resources *res, crt_rcv_alias_t flags);

int crt_thd_create(struct crt_thd *t, struct crt_comp *self, crt_thd_fn_t fn, void *data);
int crt_thd_create_in(struct crt_thd *t, struct crt_comp *c, thdclosure_index_t closure_id);
int crt_thd_create_with(struct crt_thd *t, struct crt_comp *c, struct crt_thd_resources *rs);
int crt_thd_alias_in(struct crt_thd *t, struct crt_comp *c, struct crt_thd_resources *res);

void *crt_page_allocn(struct crt_comp *c, u32_t n_pages);
int crt_page_aliasn_in(void *pages, u32_t n_pages, struct crt_comp *self, struct crt_comp *c_in, vaddr_t *map_addr);
int crt_page_aliasn_aligned_in(void *pages, unsigned long align, u32_t n_pages, struct crt_comp *self, struct crt_comp *c_in, vaddr_t *map_addr);
int crt_ro_page_aliasn_aligned_in(void *pages, unsigned long align, u32_t n_pages, struct crt_comp *self, struct crt_comp *c_in, vaddr_t *map_addr);

/**
 * Initialization API to automate the coordination necessary for
 * component initialization, both in this component, and in components
 * that this component is responsible for.
 */
typedef struct crt_comp *(*comp_get_fn_t)(compid_t id);
void crt_compinit_execute(comp_get_fn_t comp_get);
void crt_compinit_done(struct crt_comp *c, int parallel_init, init_main_t main_type);
void crt_compinit_exit(struct crt_comp *c, int retval);

int crt_chkpt_create(struct crt_chkpt *chkpt, struct crt_comp *c);
int crt_chkpt_restore(struct crt_chkpt *chkpt, struct crt_comp *c);

int crt_ulk_init(void);
int crt_ulk_map_in(struct crt_comp *c);


/*
 * A `crt_comp_create` replacement if you want to create a component
 * in a vas directly. Note that, the
 * `crt_comp_create` likely needs to take the asid namespace as well.
 */
int crt_comp_create_in_vas(struct crt_comp *c, char *name, compid_t id, void *elf_hdr, vaddr_t info, struct protdom_ns_vas *vas);


/**
 * `crt_delay` is a simple function to delay for a number of cycles.
 */
static inline void
crt_delay(cycles_t spin)
{
	cycles_t start, now;

	rdtscll(start);
	now = start;

	/* Unintuitive logic here to consider wrap-around */
	while (now - start < spin) {
		rdtscll(now);
	}

	return;
}

#endif /* CRT_H */
