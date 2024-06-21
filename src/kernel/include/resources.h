#pragma once

#include <chal.h>
#include <cos_error.h>
#include <cos_consts.h>
#include <types.h>
#include <compiler.h>
//#include <component.h>

struct page_type {
	page_type_t     type;  	   /* page type */
	page_kerntype_t kerntype;  /* page's kernel type, assuming type == kernel */
	coreid_t        coreid;	   /* resources that are bound to a core (e.g. thread) */
	epoch_t         epoch;	   /* increment to invalidate pointers to the page */
	liveness_t      liveness;  /* tracking if there are potential parallel references */
	refcnt_t        refcnt;	   /* reference count */
};

struct page {
	uword_t words[COS_PAGE_SIZE / sizeof(uword_t)];
} COS_PAGE_ALIGNED;

int          page_bounds_check(pageref_t ref);
void         page_zero(struct page *p);

cos_retval_t resource_comp_create(captbl_ref_t captbl_ref, pgtbl_ref_t pgtbl_ref, prot_domain_tag_t pd,
                                  vaddr_t entry_ip, pageref_t untyped_src_ref);
cos_retval_t resource_comp_destroy(pageref_t compref);
cos_retval_t resource_thd_create(pageref_t sched_thd_ref, pageref_t comp_ref, thdid_t id, coreid_t coreid,
                                 id_token_t sched_token, pageref_t untyped_src_ref);
cos_retval_t resource_thd_destroy(pageref_t thdref);
cos_retval_t resource_restbl_create(page_kerntype_t kt, pageref_t untyped_src_ref);
cos_retval_t resource_restbl_destroy(pageref_t restblref);

cos_retval_t resource_vm_create(pageref_t vmref);
cos_retval_t resource_vm_destroy(pageref_t vmref);

/*
 * Faster paths for type checking, and resource dereferencing that
 * likely want to be inlined (to remove quite a bit of the code based
 * on arguments).
 */

extern struct page_type page_types[COS_NUM_RETYPEABLE_PAGES] COS_PAGE_ALIGNED;
extern struct page      pages[COS_NUM_RETYPEABLE_PAGES];

/**
 * `page2ref` is a simple utility function to return the opaque
 * (integer) reference to a page.
 *
 * Assumes: `p` is a `struct page *`.
 *
 * - `@p` - page to retrieve reference
 * - `@return` - the opaque reference to the page
 */
static inline pageref_t
page2ref(void *p)
{ return (struct page *)p - pages; }

/**
 * `ref2page` finds a pointer to a page from its reference. Returns
 * the generic type to enable call-site typing.
 *
 * Assumes: `ref` is a in-bound reference to a page. No bounds
 * checking is done here. This is only reasonable given verification
 * that can assert that all refs are in-bounds. Additionally, return
 * the type and metadata information for the page.
 *
 * - `@ref` - the resource reference
 * - `@p` - the returned page structure
 * - `@t` - the returned page_type structure
 */
COS_FORCE_INLINE static inline void
ref2page(pageref_t ref, struct page **p, struct page_type **t)
{
	/*
	 * Page references should be implementation-internal. Use
	 * verification invariants to guarantee they are valid
	 * values (i.e. ref is within bounds).
	 */
	if (t) *t = &page_types[ref];
	if (p) *p = &pages[ref];

	return;
}

/**
 * `ref2page_ptr` returns the page corresponding to the ref. As with
 * `ref2page`, it assumes that `ref` is in-bounds, as this is not
 * bounds-checked. See `ref2page` documentation.
 *
 * - `@ref` - page reference, and the...
 * - `@return` - corresponding page
 */
static inline struct page *
ref2page_ptr(pageref_t ref)
{
	struct page *p;

	ref2page(ref, &p, NULL);

	return p;
}

/*
 * `page_resolve` finds the page corresponding to `offset`, validate
 * that it has the expected type, and that it is live. Returns either
 * `COS_ERR_WRONG_INPUT_TYPE` or `COS_ERR_WRONG_NOT_LIVE` in either
 * event, and `COS_RET_SUCCESS` on success. On success, the `page` and
 * `page_type` structures are returned in the corresponding
 * parameters.
 *
 * Assumes: the `offset` is a valid offset. This means that either it
 * is derived from a kernel-internal reference. As user-level only has
 * access capability namespaces that are component-local, user-level
 * should never use or know about these references.
 *
 * - `@offset` - which of the retypable pages; must be in bounds
 * - `@type` - expected type of the page
 * - `@kerntype` - expected kernel type of the page
 * - `@version` - `NULL`, or the expected version of the page
 * - `@page` - the returned page on success
 * - `@ptype` - the returned page type on success
 * - `@return` - the error or `COS_RET_SUCCESS`
 */
COS_FORCE_INLINE static inline cos_retval_t
page_resolve(pageref_t offset, page_type_t type, page_kerntype_t kerntype, epoch_t *version, struct page **page, struct page_type **ptype)
{
	struct page_type *pt;
	struct page      *p;

	ref2page(offset, &p, &pt);

	if (unlikely(pt->type != type || pt->kerntype != kerntype)) return -COS_ERR_WRONG_INPUT_TYPE;
	if (unlikely(version != NULL && *version != pt->epoch))     return -COS_ERR_NOT_LIVE;

	if (page)  *page  = p;
	if (ptype) *ptype = pt;

	return COS_RET_SUCCESS;
}

/*
 * Weak reference motivation, implementation, and usage are documented
 * in the "Weak References" documentation section in `resources.c`.
 */

cos_retval_t resource_weakref_create(pageref_t resource_ref, page_kerntype_t expected_kerntype, struct weak_ref *wr);

/**
 * `resource_weakref_deref` takes a weak reference, and dereferences
 * it, returning the resource in `resource` only if that resource is
 * live (i.e. if the `epoch`, or "version" matches that in the
 * reference).
 *
 * - `@wr` - the weak reference we're attempt to dereference
 * - `@resource` - the *returned* resource if `COS_RET_SUCCESS`
 * - `@return` - `COS_RET_SUCCESS` or `-COS_ERR_NOT_LIVE`
 */
COS_FORCE_INLINE static inline cos_retval_t
resource_weakref_deref(struct weak_ref *wr, pageref_t *resource)
{
	struct page_type *pt;

	ref2page(wr->ref, NULL, &pt);
	if (unlikely(wr->epoch != pt->epoch)) return -COS_ERR_NOT_LIVE;

	*resource = wr->ref;

	return COS_RET_SUCCESS;
}

/**
 * `resource_weakref_force_deref` is *not* safe, as it dereferences a
 * resource *without checking if it is live*.
 *
 * - `@wr` - The weak reference to dereference
 * - `@return` - the resource reference
 */
static inline pageref_t
resource_weakref_force_deref(struct weak_ref *wr)
{
	return wr->ref;
}

/**
 * `resource_weakref_copy` simply copies a weak reference (i.e. not
 * the referenced resource). Note that the reference being copied does
 * *not* have to be live. If it is not, the copy will also not be
 * live.
 *
 * - `@to` - empty structure to copy the reference into
 * - `@from` - active weak reference to copy
 */
COS_FORCE_INLINE static inline void
resource_weakref_copy(struct weak_ref *to, struct weak_ref *from)
{
	*to = *from;
}

/**
 * `struct component_ref` is a specialized form of a weak reference
 * that not only references a component, but also caches that
 * component's information in the reference, thus avoiding another
 * cache-line access, and pointer-chasing.
 *
 * See the description in the "Weak References" section of the
 * documentation in `resources.c`.
 */
struct component_ref {
	pgtbl_t                    pgtbl;
	captbl_t                   captbl;
	/*
	 * This is a `struct weakref`, but we have to guarantee that
	 * the pageref_t and the prot_domain_tag_t share the same 64
	 * bit word to make sure the sinv capability fits into a
	 * cache-line.
	 */
	epoch_t                    epoch;
	pageref_t                  component;
	prot_domain_tag_t          pd_tag;
};

/* Required so that the sinv capability fits into a cache-line */
COS_STATIC_ASSERT(sizeof(struct component_ref) <= 4 * sizeof(word_t),
		  "Component reference is larger than expected.");

/**
 * `resource_compref_copy` copys a component reference. If the source
 * reference references a component that is not live, the copy will
 * proceed, but the destination reference will also not be live. It is
 * on the fastpath as it is used to copy a reference from a
 * synchronous invocation capability reference, into the thread's
 * invocation stack to track the invocation.
 *
 * - `@to` - uninitialized reference to populate
 * - `@from` - the component reference to copy
 */
COS_FASTPATH static inline void
resource_compref_copy(struct component_ref *to, struct component_ref *from)
{
	*to = *from;
}

/**
 * `resource_compref_deref` dereferences the reference, returning the
 * component reference if it is alive (see the "Weak References"
 * documentation section in `resources.c`). Return values are similar
 * to those in `resource_weakref_deref`.
 *
 * Importantly, if this returns `COS_RET_SUCCESS`, the rest of the
 * cached contents in the `component_ref` is accessible.
 *
 * - `@comp` - the component reference to be dereferenced
 * - `@ref` - the returned component reference.
 * - `@return` - normal returns (same as `resource_weakref_deref`)
 */
COS_FASTPATH static inline cos_retval_t
resource_compref_deref(struct component_ref *comp, pageref_t *ref)
{
	struct page_type *t;

	ref2page(comp->component, NULL, &t);
	if (unlikely(t->epoch != comp->epoch)) return -COS_ERR_NOT_LIVE;
	*ref = comp->component;

	return COS_RET_SUCCESS;
}

cos_retval_t resource_compref_create(pageref_t compref, struct component_ref *r);