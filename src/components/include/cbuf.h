/**
 * Copyright 2010 by The George Washington University.  All rights reserved.
 *
 * Redistribution of this file is permitted under the GNU General
 * Public License v2.
 *
 * Author: Gabriel Parmer, gparmer@gwu.edu, 2010
 */

#ifndef  CBUF_H
#define  CBUF_H

#include <cos_component.h>
#include <cos_debug.h>
#include <cbuf_c.h>
#include <cbuf_vect.h>
#include <cos_vect.h>
#include <cos_list.h>
#include <bitmap.h>
#include <cos_synchronization.h>

#include <tmem_conf.h>

cos_lock_t l;
#define CBUF_TAKE()    do { if (unlikely(l.lock_id == 0)) lock_static_init(&l); if (lock_take(&l) != 0) BUG(); } while(0)
#define CBUF_RELEASE() do { if (lock_release(&l) != 0) BUG(); } while(0)

extern cbuf_vect_t meta_cbuf;
extern cos_vect_t slab_descs; 

/* static init_flag = 0; */

/* 
 * Shared buffer management for Composite.
 *
 * A delicate dance between cbuf structures.  There are a number of
 * design goals: 1) cbuf_t must be passed between components without
 * shared memory (i.e. it must fit in a register).  2) each component
 * should be able to efficiently allocate memory for a given principal
 * (i.e. thd) that can be accessed by that principal in other
 * components (but not necessarily written).  3) Each component should
 * be able to efficiently and predictably find a buffer referenced by
 * a cbuf_t.  These are brought in to the component on-demand, i.e. if
 * a component has already accessed the page that holds the cbuf, then
 * it will be able to find it only from its own "cache"; however, if
 * it hasn't, it will need to bring in that buffer from another
 * component using shared memory.  Locality of access will ensure that
 * this is the uncommon case.  4) A component given a cbuf_t should
 * not have a chance of crashing when accessing the buffer.  This
 * implies that the cbuf_t does not contain any information that can't
 * be verified as correct from the component's own data-structures.
 *
 * A large assumption I'm making is that buffers can be fragmented and
 * spread around memory.  This relies on a programming model that is
 * scatter-gather.  This assumption enables all buffers to be less
 * than or equal to the size of a page.  Larger "buffers" are a
 * collection of multiple smaller buffers.
 *
 * Given these constraints, the solution we take follows:
 *
 * 1) cbuf_t is 32 bits, and includes a) the id associated with the
 * page containing the buffer.  This id is assigned by a trusted
 * component, and the namespace is shared between components (i.e. the
 * id is meaningful and is the identify mapping between components),
 * and b) the offset into the page for the desired object.  This
 * latter offset is not the byte-offset.  Instead each page is "typed"
 * in that it holds objects only of a certain size, and more
 * specifically, and array of objects of a specific size.  The offset,
 * is the index into this array.
 *
 * 2) cbuf_meta is a data-structure that is stored per-component, thus
 * it is trusted by the component to which it belongs.  A combination
 * of the (principal_id, cbuf page id) is used to lookup the
 * appropriate referenced cbuf_meta structure, and it also fits in 32
 * bits so that it can be held directly in the index structure (it's
 * lookup structure).  It holds a) a pointer to the page in this
 * component, and b) the size of objects held in this page.
 *
 * 3) Any references to buffers via interface invocations pass both
 * the cbuf_t, and the length of the allocation, if it is less than
 * the size associated with the page.  
 *
 * With these three pieces of data we satisfy the constraints because
 * 1) cbuf_t is 32 bits and is passed in a register between
 * components, 2) a component can allocate its own buffers, and share
 * their cid_t with others, 3) cbuf_meta can be found efficiently
 * using cbuf_t, and we get the buffer pointer from the cbuf_meta's
 * data, and the length of the buffer from the argument to the
 * interface function, 4) cbuf_meta information is trusted and not
 * corruptible by other components, and though it is found using
 * information in the untrusted cbuf_t, that data is verified in the
 * cbuf_meta lookup process (i.e. does the page id exist, does the it
 * belong to the principal, etc...).
 */

/* 
 * log2(max slab size) - log2(min slab size) = 
 * log2(PAGE_SIZE) - log2(CACHELINE_SIZE) = 
 * 12 - 6 = 6 thus
 * max obj size = 2^6 = 64
 */
#define N_CBUF_SMALL_SLABS 6 	/* <= PAGE_SIZE */
#define N_CBUF_LARGE_SLABS 10
#define N_CBUF_SLABS (N_CBUF_LARGE_SLABS + N_CBUF_SMALL_SLABS)

#define CBUF_MIN_SLAB_ORDER 6 	/* minimum slab size = 2^6 = 64 */
#define CBUF_MIN_SLAB (1<<CBUF_MIN_SLAB_ORDER)
#define SLAB_MAX_OBJS (PAGE_SIZE/CBUF_MIN_SLAB)

/* #define CBUF_ID_ORDER 26 //(32-CBUF_MIN_SLAB_ORDER) */

#define CBUF_OBJ_SZ_SHIFT 7

typedef u32_t cbuf_t; /* Requirement: gcc will return this in a register */
typedef union {
	cbuf_t v;
	struct {
		/* u32_t id:20, idx:12; */
		u32_t id:32, idx:6;  /*Jiguo: Since min_slab_order is 6, set idx to be 6? */
	} __attribute__((packed)) c;
} cbuf_unpacked_t;

static inline void 
cbuf_unpack(cbuf_t cb, u32_t *cbid, u32_t *idx) 
{
	cbuf_unpacked_t cu = {0};
	
	cu.v  = cb;
	*cbid = cu.c.id;
	*idx  = cu.c.idx;
	return;
}

static inline cbuf_t 
cbuf_cons(u32_t cbid, u32_t idx) 
{
	cbuf_unpacked_t cu;
	assert(idx <= CBUF_MIN_SLAB);
	cu.c.id  = cbid;
	cu.c.idx = idx;
	return cu.v; 
}

static inline cbuf_t cbuf_null(void)      { return 0; }
static inline int cbuf_is_null(cbuf_t cb) { return cb == 0; }


extern int cbuf_cache_miss(int cbid, int idx, int len);
/* 
 * Common case.  This is the most optimized path.  Every component
 * that wishes to access a cbuf created by another component must use
 * this function to map the cbuf_t to the actual buffer.
 */
static inline void * 
cbuf2buf(cbuf_t cb, int len)
{
	int obj_sz, off;
	u32_t id, idx;
	union cbuf_meta cm;
	void *ret;

	CBUF_TAKE();
	assert(len);
	/* len = len == 1 ? 1 : len-1; */
	/* len = nlpow2(len); */
	len = nlpow2(len - 1);
	cbuf_unpack(cb, &id, &idx);

	long cbidx;
	cbidx = cbid_to_meta_idx(id);

	DOUT("buf2buf:: id %x, idx %x  cbidx is %ld\n", id, idx, cbidx);

	/* DOUT("cbuf2buf before cache_miss::\n"); */

	/* int i; */
	/* for(i=0;i<20;i++) */
	/* 	DOUT("i:%d %p\n",i,cbuf_vect_lookup(&meta_cbuf, i)); */

again:				/* avoid convoluted conditions */
	cm.c_0.v = (u32_t)cbuf_vect_lookup(&meta_cbuf, cbidx);
	if (unlikely(cm.c_0.v == 0)) {
		/* slow path */
		// If there is no 2nd level vector exists, create here!!
		if (cbuf_cache_miss(id, idx, len)) goto err;
		goto again;
	}

	if (likely(!(cm.c.flags & CBUFM_LARGE))) {
		obj_sz = cm.c.obj_sz << CBUF_OBJ_SZ_SHIFT;
		off    = obj_sz * idx; /* multiplication...ouch */
		/* DOUT("len %d obj_sz %d off %d \n",len, obj_sz ,off); */
		if (unlikely(len > obj_sz || off + len > PAGE_SIZE )) goto err;
		/* DOUT("<<<Not CBUF_LARGE>>> idx: %d off: %d\n", idx, off); */
	} else {
		BUG();
		obj_sz = PAGE_SIZE * (1 << cm.c.obj_sz);
		off    = 0;
		if (unlikely(len > obj_sz)) goto err;
	}

	/* DOUT("After Cache missing here::\n"); */
	DOUT("%p\n",((char*)(cm.c.ptr << PAGE_ORDER)) + off);
	ret = ((char*)(cm.c.ptr << PAGE_ORDER)) + off;

done:	
	CBUF_RELEASE();
	return ret;
err:
	ret = NULL;
	goto done;
}

#define SLAB_BITMAP_SIZE (SLAB_MAX_OBJS/32)

/* 
 * This is really the slab cache, and ->mem points to the slab, but
 * calling this cbuf_cache would not make its association with a slab
 * allocator clear.
 */
struct cbuf_slab_freelist;	/* forward decl */
struct cbuf_slab {
	int cbid;
	char *mem;
	u32_t obj_sz;
	u16_t nfree, max_objs;
	u32_t bitmap[SLAB_BITMAP_SIZE];
	struct cbuf_slab *next, *prev; /* freelist next */
	struct cbuf_slab_freelist *flh; /* freelist head */
};
struct cbuf_slab_freelist {
	struct cbuf_slab *list;
	int npages;
};
extern struct cbuf_slab_freelist slab_freelists[N_CBUF_SLABS];

static inline void printfl(struct cbuf_slab_freelist *fl, char *c){
	struct cbuf_slab *p;
	int a=0;
	p = fl->list;
	printc("thd %d\n", cos_get_thd_id());
	while (p) {
		printc("[%s p->cbid %d @ %p]\n", c, p->cbid, p->mem);
		a++;
		assert(a < 50);
		if (p==fl->list) break;
		p = FIRST_LIST(p, next, prev);
	}
	DOUT("done print fl\n");
}

static inline void
slab_rem_freelist(struct cbuf_slab *s, struct cbuf_slab_freelist *fl)
{
	assert(s && fl);

	if (fl->list == s) {
		if (EMPTY_LIST(s, next, prev)) fl->list = NULL;
		else fl->list = FIRST_LIST(s, next, prev);
	}
	REM_LIST(s, next, prev);
	fl->npages--;

	assert(fl->npages >= 0);
	DOUT("thd %d REM:fl->npages %d cbid is %d\n",cos_get_thd_id(),fl->npages, s->cbid);
	/* printfl(fl,"REM"); */

	return;
}

static inline void
slab_add_freelist(struct cbuf_slab *s, struct cbuf_slab_freelist *fl)
{
	assert(s && fl);
	assert(EMPTY_LIST(s, next, prev));
	assert(s != fl->list);
	if (fl->list) {
		if (fl->npages <= 0) {
			DOUT("s cbid %d @%p; fl cbid %d @%p\n", s->cbid,s->mem, fl->list->cbid,fl->list->mem);
		}
		assert(fl->npages > 0);
		ADD_END_LIST(fl->list, s, next, prev);
	}
	fl->list = s;
	fl->npages++;
	DOUT("thd %d ADD:fl->npages %d cbid is %d\n",cos_get_thd_id(),fl->npages, s->cbid);
	/* printfl(fl,"ADD"); */

	return;
}

static void
slab_deallocate(struct cbuf_slab *s, struct cbuf_slab_freelist *fl)
{
	slab_rem_freelist(s, fl);
	cos_vect_del(&slab_descs, (u32_t)s->mem >> PAGE_ORDER);
	free(s);

	return;
}


extern struct cbuf_slab *cbuf_slab_alloc(int size, struct cbuf_slab_freelist *freelist);
extern void cbuf_slab_free(struct cbuf_slab *s);

static inline void 
__cbuf_free(void *buf)
{
	u32_t p = ((u32_t)buf & PAGE_MASK) >> PAGE_ORDER; /* page id */
	/* DOUT("page id is %d\n",p); */
	struct cbuf_slab *s = cos_vect_lookup(&slab_descs, p);
	u32_t b   = (u32_t)buf;
	u32_t off = b - (b & PAGE_MASK);
	int idx;
	union cbuf_meta cm;
	long cbidx;

	assert(s);
	/* Argh, division!  Maybe transform into loop? Maybe assume pow2? */
	idx = off/s->obj_sz;
	assert(!bitmap_check(&s->bitmap[0], idx));
	bitmap_set(&s->bitmap[0], idx);
	s->nfree++;
	assert(s->flh);
	DOUT(">>>  free: nfree is now : %d cbid is %d\n",s->nfree,s->cbid);
	DOUT("thd %d spd %ld in __cbuf_free\n", cos_get_thd_id(),cos_spd_id());
	if (s->nfree == 1) {
		DOUT("Add slab_add_freelist cbid is %d\n", s->cbid);
		assert(EMPTY_LIST(s, next, prev));
		cbidx = cbid_to_meta_idx(s->cbid);
		cm.c_0.v = (u32_t)cbuf_vect_lookup(&meta_cbuf, cbidx);
		cm.c.flags &= ~CBUFM_ALL_ALLOCATED;
		/* if (!(void*)cm.c_0.v) */
		/* 	printc("thd %d spd %ld in __cbuf_free\n", cos_get_thd_id(),cos_spd_id()); */
		assert((void*)cm.c_0.v);
 		cbuf_vect_add_id(&meta_cbuf, (void*)cm.c_0.v, cbidx);
		slab_add_freelist(s, s->flh);
	}

	if (s->nfree == s->max_objs) {
		DOUT("slab_free(s) is called\n");
		cbuf_slab_free(s);
	} 
	
	/* int i; */
	/* for(i=0;i<20;i++) */
	/* 	DOUT("i:%d %p\n",i,cbuf_vect_lookup(&meta_cbuf, i)); */

	return;
}

static inline void *
__cbuf_alloc(struct cbuf_slab_freelist *slab_freelist, int size, cbuf_t *cb)
{
	struct cbuf_slab *s;
	union cbuf_meta cm;
	int idx;
	u32_t *bm;

	DOUT("\n***** thd %d spd :: %ld __cbuf_alloc:******\n", cos_get_thd_id(), cos_spd_id());
	DOUT("<<<__cbuf_alloc size %d>>>\n",size);
again:					/* avoid convoluted conditions */
	if (unlikely(!slab_freelist->list)) {
		DOUT("..not on free list..\n");
		if (unlikely(!cbuf_slab_alloc(size, slab_freelist))) return NULL;
		if (unlikely(!slab_freelist->list)) return NULL;
	}
	s = slab_freelist->list;
	/* 
	 * This is complicated.
	 *
	 * See cbuf_slab_free for the rest of the story.  
	 *
	 * Assumptions:
	 * 1) The cbuf manager shared the cbuf meta (in the meta_cbuf
	 * vector) information with this component.  It can remove
	 * asynchronously a cbuf from this structure at any time IFF
	 * that cbuf is marked as ~CBUF_IN_USE.  
	 *
	 * 2) The slab descriptors, and the slab_desc vector are _not_
	 * shared with the cbuf manager for complexity reasons.
	 *
	 * Question: How do we reconcile the fact that the cbuf mgr
	 * might remove at any point a cbuf from this component, but
	 * we still have a slab descriptor lying around for it?  How
	 * will we know that the cbuf has been removed, and not to use
	 * the slab data-structure anymore?
	 *
	 * Answer: The slabs are deallocated lazily.  When a slab is
	 * pulled off of the freelist (see the following code), we
	 * check to make sure that the cbuf meta information matches
	 * up with the slab's information (i.e. the cbuf id and the
	 * address in memory of the cbuf.  If they do not, then we
	 * know that the slab is outdated and that the cbuf backing it
	 * has been taken from this component.  In that case (shown in
	 * the following code), we delete the slab descriptor.  Again,
	 * see cbuf_slab_free to see the surprising fact that we do
	 * _not_ deallocate the slab descriptor there to reinforce
	 * that point.
	 */
	long cbidx;
	cbidx = cbid_to_meta_idx(s->cbid);

	cm.c_0.v = (u32_t)cbuf_vect_lookup(&meta_cbuf, cbidx);

	if (unlikely(!cm.c_0.v || (cm.c.flags & CBUFM_ALL_ALLOCATED) || 
		     (cm.c.ptr != ((u32_t)s->mem >> PAGE_ORDER)))) {
		slab_deallocate(s, slab_freelist);
		DOUT("goto again\n");
		goto again;
	}

	DOUT("alloc get slab. s-> cbid %d @ %p\n", s->cbid, s->mem);

	assert(s->nfree);

	if (s->obj_sz <= PAGE_SIZE) {
		bm  = &s->bitmap[0];
		idx = bitmap_one(bm, SLAB_BITMAP_SIZE);
		assert(idx > -1 && idx < SLAB_MAX_OBJS);
		bitmap_unset(bm, idx);
	}
	if (s->nfree == s->max_objs) {
		/* set IN_USE bit and thread info */
		cm.c_0.v = (u32_t)cbuf_vect_lookup(&meta_cbuf, cbidx);
		cm.c.flags |= CBUFM_IN_USE;
		cm.c.flags |= CBUFM_TOUCHED; /* this bit is used for policy to estimate concurrency */
		assert((void*)cm.c_0.v);
		cbuf_vect_add_id(&meta_cbuf, (void*)cm.c_0.v, cbidx);
		cm.c_0.th_id = cos_get_thd_id();
		cbuf_vect_add_id(&meta_cbuf, (void*)cm.c_0.th_id, cbidx+1);
	}

	s->nfree--;

	/* remove from the freelist */
	/* printc("after alloc and  nfree %d\n",s->nfree); */
	if (!s->nfree) {
		cm.c.flags |= CBUFM_ALL_ALLOCATED;
		assert((void*)cm.c_0.v);
		cbuf_vect_add_id(&meta_cbuf, (void*)cm.c_0.v, cbidx);
		slab_rem_freelist(s, slab_freelist);
	}

	*cb = cbuf_cons(s->cbid, idx);
	return s->mem + (idx * s->obj_sz);  // return correct position of cbuf in this slab
}

/* 
 * Create a slab of a specific size (smaller than or equal to the size
 * of a page).  This relies on the compiler to do proper inlining and
 * consequentially partial evaluation to get the slab allocation
 * benefits in terms of avoiding touching many memory locations.
 */
/*
#define SLAB_BOUND_CHK(sz)					\
	#ifdef sz > PAGE_SIZE					\
	#error "Cannot create slabs larger than a page"		\
	#endif							
*/

#define CBUF_CREATE_SLAB(name, size)				\
	/*SLAB_BOUND_CHK(size)*/				\
struct cbuf_slab *slab_##name##_freelist;			\
								\
static inline void *						\
cbuf_alloc_##name(cbuf_t *cb)					\
{								\
	return __cbuf_alloc(&slab_##name##_freelist, size, cb);	\
}								\
								\
cbuf_free_##name(void *buf)					\
{								\
	return __cbuf_free(&slab_##name##_freelist, buf);	\
}

/* Allocate something of a power of two (order = log(size)) */
static inline void *
cbuf_alloc_pow2(unsigned int order, cbuf_t *cb)
{
	struct cbuf_slab_freelist *sf;
	unsigned int dorder = order - CBUF_MIN_SLAB_ORDER;
	assert(dorder <= N_CBUF_SLABS);
	sf = &slab_freelists[dorder];
	return __cbuf_alloc(sf, 1<<order, cb);
}

/* 
 * Allocate/free memory of a dynamic size (not known statically), up
 * to the size of a page.
 */
static inline void *
cbuf_alloc(unsigned int sz, cbuf_t *cb)
{
	void *ret;
	int o;

	CBUF_TAKE();
	sz = sz < 65 ? 63 : sz; /* FIXME: do without branch */
	/* FIXME: find way to avoid making the wrong decision on pow2 values */
	sz = ones(sz) == 1 ? sz-1 : sz;
	o = log32_floor(sz) + 1;

	ret = cbuf_alloc_pow2(o, cb);
	CBUF_RELEASE();
	return ret;
}

static inline void
cbuf_free(void *buf)
{
	CBUF_TAKE();
	__cbuf_free(buf);
	CBUF_RELEASE();
}

#endif /* CBUF_H */
