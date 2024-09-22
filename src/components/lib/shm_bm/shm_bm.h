#ifndef SHM_BM_H
#define SHM_BM_H

#include <cos_types.h>
#include <memmgr.h>
#include <limits.h>
#include <consts.h>
#include <string.h>

/**
 * This library provides a slab-like memory allocator interface to allocate fixed-size
 * blocks of memory from a region of memory shared between a server component and a 
 * number of client components.
 * 
 * Reference ./doc.md for interface documentation. Most of this interface is generated
 * at compile-time for using the preprocessor. This is required for the performance of
 * this library by giving more information to the compiler that allows it to significantly
 * optimize most operations, particularily allocating, freeing, and translating between
 * address spaces, by knowing at compile time the size of allocations and the size of the 
 * shared memory region.
 */

#define SHM_BM_BITMAP_BLOCK (sizeof (word_t) * CHAR_BIT)
#define SHM_BM_ALIGN (1 << 24)
#define SHM_BM_BITS_TO_WORDS(bits) (round_up_to_pow2(bits, SHM_BM_BITMAP_BLOCK) / SHM_BM_BITMAP_BLOCK)

typedef void *        shm_bm_t;
typedef unsigned int  shm_bm_objid_t;

#define SHM_BM_REFC(shm, nobj) ((unsigned char *)((unsigned char *)shm + SHM_BM_BITS_TO_WORDS(nobj) * sizeof (word_t)))
#define SHM_BM_DATA(shm, nobj) ((unsigned char *)(SHM_BM_REFC(shm, nobj) + (unsigned int)nobj))

enum {
	BYWAY_RO,
	BYWAY_RO_BIFURCATE,
	BYWAY_RW
};

#define BIFURCATE_ARR_SZ 32
struct bifurcate_shmem {
	shm_bm_t shm;
	cbuf_t shm_id;
};

struct bifurcate_shmem_tuple {
	cbuf_t shm_id;
	shm_bm_objid_t first_objid;
};

struct bifurcate_shmem_header {
	u16_t len;
	struct bifurcate_shmem_tuple nf_arr[BIFURCATE_ARR_SZ];
};

static inline void
__shm_bm_set_contig(word_t *bm, int offset)
{
	int i, n, ind;

	ind = offset / SHM_BM_BITMAP_BLOCK;
	offset %= SHM_BM_BITMAP_BLOCK;

	for (i = 0; i < ind; i++) {
		bm[i] = ~0x0ul;
	}

	n = SHM_BM_BITMAP_BLOCK - offset;
	bm[ind] = ~((1ul << n) - 1); // set most sig n bits of bm[ind]
}

/* Find the first nonzero word in the inputted bitmap */
static inline int
__shm_bm_next_free_word(word_t *bm, unsigned long nwords)
{
	/* the index of the word in the bitmap where the first set bit is found */
	int idx;

	for (idx = 0; idx < (int) nwords; idx++) {
		if (*bm != 0) return idx;
		bm++;
	}

	/* all bits set to zero */
	return -1;
}

static inline size_t
__shm_bm_size(size_t objsz, unsigned int nobj)
{
	size_t bitmap_sz, refcnt_sz, data_sz;

	bitmap_sz = SHM_BM_BITS_TO_WORDS(nobj) * sizeof(word_t);
	refcnt_sz = nobj;
	data_sz   = nobj * objsz;

	return bitmap_sz + refcnt_sz + data_sz;
}

static inline shm_bm_t 
__shm_bm_create(void *mem, size_t memsz, size_t objsz, unsigned int nobj)
{
	if ((word_t)mem % SHM_BM_ALIGN != 0) return 0;
	if (memsz < __shm_bm_size(objsz, nobj)) return 0;
	return (shm_bm_t)mem;
}

static inline void
__shm_bm_init(shm_bm_t shm, size_t objsz, unsigned int nobj)
{
	memset(shm, 0, __shm_bm_size(objsz, nobj));
	/* set nobj bits to free in the bitmap */
	__shm_bm_set_contig((word_t *)shm, nobj);
}

static inline void * 
__shm_bm_alloc(shm_bm_t shm, shm_bm_objid_t *objid, size_t objsz, unsigned int nobj)
{
	int     freebit, idx , offset, lz;
	word_t  word; 
	word_t *bm;

	/* 
	 * Find a free space; could be preempted. Find the next word in
	 * the bitmap with a free bit and get its index in the bitmap, and 
	 * the offset of the free bit in that word. Then try to atomically 
	 * xchg the bitmap with the freebit set to 0
	 */
	bm = (word_t *)shm;
	do {
		idx = __shm_bm_next_free_word(bm, SHM_BM_BITS_TO_WORDS(nobj));
		if (unlikely(idx == -1)) return NULL;
		word   = bm[idx];
		lz     = __builtin_clzl(word); 
		offset = SHM_BM_BITMAP_BLOCK - lz - 1;
	} while (!cos_cas(bm + idx, word, word & ~(1ul << offset)));

	freebit = lz + (idx * SHM_BM_BITMAP_BLOCK);

	cos_faab(SHM_BM_REFC(shm, nobj) + freebit, 1);

	*objid = (shm_bm_objid_t)freebit;
	return SHM_BM_DATA(shm, nobj) + (freebit * objsz);
}

static inline void *   
__shm_bm_take(shm_bm_t shm, shm_bm_objid_t objid, size_t objsz, unsigned int nobj)
{
	if (unlikely(objid >= nobj)) return NULL;

	/* obj has not been allocated */
	if (unlikely(*(SHM_BM_REFC(shm, nobj) + objid) == 0)) return NULL;

	cos_faab(SHM_BM_REFC(shm, nobj) + objid, 1);

	return SHM_BM_DATA(shm, nobj) + (objid * objsz);
}

static inline void *   
__shm_bm_take_norefcnt(shm_bm_t shm, shm_bm_objid_t objid, size_t objsz, unsigned int nobj)
{
	if (unlikely(objid >= nobj)) return NULL;

	/* obj has not been allocated */
	if (unlikely(*(SHM_BM_REFC(shm, nobj) + objid) == 0)) return NULL;

	return SHM_BM_DATA(shm, nobj) + (objid * objsz);
}

static void
__shm_bm_ptr_free(void *ptr, size_t objsz, unsigned int nobj)
{
	void        *shm;
	unsigned int obj_idx, bm_idx, bm_offset;
	word_t      *bm;

	/* Mask out bits less significant than the alignment to get pointer to head of shm */
	shm = (void *)((word_t)ptr & ~(SHM_BM_ALIGN - 1));
	obj_idx = ((unsigned char *)ptr - SHM_BM_DATA(shm, nobj)) / objsz;
	if (obj_idx >= nobj) return;
	
	if (cos_faab(SHM_BM_REFC(shm, nobj) + obj_idx, -1) > 1) { 
		return;
	}
	/* droping the last reference, must set obj to free in bitmap */
	bm         = (word_t *)shm;
	bm_idx     = obj_idx / SHM_BM_BITMAP_BLOCK;
	bm_offset  = SHM_BM_BITMAP_BLOCK - obj_idx % SHM_BM_BITMAP_BLOCK - 1;
	bm[bm_idx] = bm[bm_idx] | (1ul << bm_offset);
}

static shm_bm_objid_t
__shm_bm_get_objid(void *ptr, size_t objsz, unsigned int nobj)
{
	void        *shm;
	unsigned int obj_idx, bm_idx, bm_offset;
	word_t      *bm;

	/* Mask out bits less significant than the alignment to get pointer to head of shm */
	shm = (void *)((word_t)ptr & ~(SHM_BM_ALIGN - 1));
	obj_idx = ((unsigned char *)ptr - SHM_BM_DATA(shm, nobj)) / objsz;
	assert (obj_idx <= nobj);

	return obj_idx;
}


#define __SHM_BM_DEFINE_FCNS(name)                                                          \
    static inline size_t   shm_bm_size_##name(void);                                        \
    static inline shm_bm_t shm_bm_create_##name(void *mem, size_t memsz);                   \
    static inline void     shm_bm_init_##name(shm_bm_t shm);                                \
    static inline void *   shm_bm_alloc_##name(shm_bm_t shm, shm_bm_objid_t *objid);        \
    static inline void *   shm_bm_take_##name(shm_bm_t shm, shm_bm_objid_t objid);          \
    static inline void *   shm_bm_borrow_##name(shm_bm_t shm, shm_bm_objid_t objid);        \
    static inline void *   shm_bm_transfer_##name(shm_bm_t shm, shm_bm_objid_t objid);      \
    static inline void     shm_bm_free_##name(void *ptr);                                                                                         

#define __SHM_BM_CREATE_FCNS(name, objsz, nobjs)                                            \
    static inline size_t                                                                    \
    shm_bm_size_##name(void)                                                                \
    {                                                                                       \
        return __shm_bm_size(objsz, nobjs);                                                 \
    }                                                                                       \
    static inline shm_bm_t                                                                  \
    shm_bm_create_##name(void *mem, size_t memsz)                                           \
    {                                                                                       \
        return __shm_bm_create(mem, memsz, objsz, nobjs);                                   \
    }                                                                                       \
    static inline void                                                                      \
    shm_bm_init_##name(shm_bm_t shm)                                                        \
    {                                                                                       \
        __shm_bm_init(shm, objsz, nobjs);                                                   \
    }                                                                                       \
    static inline void *                                                                    \
    shm_bm_alloc_##name(shm_bm_t shm, shm_bm_objid_t *objid)                                \
    {                                                                                       \
        return __shm_bm_alloc(shm, objid, objsz, nobjs);                                    \
    }                                                                                       \
    static inline void *                                                                    \
    shm_bm_take_##name(shm_bm_t shm, shm_bm_objid_t objid)                                  \
    {                                                                                       \
        return __shm_bm_take(shm, objid, objsz, nobjs);                                     \
    }                                                                                       \
    static inline void *                                                                    \
    shm_bm_borrow_##name(shm_bm_t shm, shm_bm_objid_t objid)                                \
    {                                                                                       \
        return __shm_bm_take_norefcnt(shm, objid, objsz, nobjs);                            \
    }                                                                                       \
    static inline void *                                                                    \
    shm_bm_transfer_##name(shm_bm_t shm, shm_bm_objid_t objid)                              \
    {                                                                                       \
        return __shm_bm_take_norefcnt(shm, objid, objsz, nobjs);                            \
    }                                                                                       \
    static inline void                                                                      \
    shm_bm_free_##name(void *ptr)                                                           \
    {                                                                                       \
        __shm_bm_ptr_free(ptr, objsz, nobjs);                                               \
    }                                                                                       \
    static inline shm_bm_objid_t                                                            \
    shm_bm_get_objid_##name(void *ptr)                                                      \
    {                                                                                       \
        return __shm_bm_get_objid(ptr, objsz, nobjs);                                              \
    }

#define SHM_BM_INTERFACE_CREATE(name, objsz, nobjs)                                         \
    __SHM_BM_DEFINE_FCNS(name)                                                              \
    __SHM_BM_CREATE_FCNS(name, objsz, nobjs) 

#endif