/**
 * Copyright 2007 by Gabriel Parmer, gabep1@cs.bu.edu
 *
 * Redistribution of this file is permitted under the GNU General
 * Public License v2.
 */

#ifndef COS_COMPONENT_X86_64_H
#define COS_COMPONENT_X86_64_H

#include <consts.h>
#include <cos_types.h>
#include <util.h>
#include <string.h>
#include <bitmap.h>
#include <ps_plat.h>
#include <cos_stubs.h>

/*
 * dewarn: strtok_r()
 * reference: feature_test_macro() requirement: _SVID_SOURCE || _BSD_SOURCE || _POSIX_C_SOURCE >= 1 || _XOPEN_SOURCE || _POSIX_SOURCE
 */
extern char *strtok_r(char *str, const char *delim, char **saveptr);
void libc_init();
char *cos_initargs_tar();

/* temporary */
static inline sword_t
call_cap_asm(u32_t cap_no, u32_t op, word_t arg1, word_t arg2, word_t arg3, word_t arg4)
{
	long fault = 0;
	sword_t  ret;

	/*
	 * We use this frame ctx to save bp(frame pointer) and sp(stack pointer)
	 * before it goes into the kernel through syscall.
	 * 
	 * We cannot use a push %rbp/%rsp because the compiler doesn't know
	 * the inline assembly code changes the stack pointer. Thus, in some
	 * cases the compiler might do some optimizations which could conflict
	 * with the push %rbp/%rsp. That means, the push might corrupt some
	 * stack local variables. Thus, instead of using push instruction, we
	 * use mov instruction to first save them to a stack local position(frame_ctx)
	 * and then pass the address of the frame_ctx to the kernel rather than the sp.
	 * When the syscall returns, the kernel will restore the sp to the address of
	 * frame_ctx, thus we can simply use two pops to restore the original bp and sp.
	 */
	struct frame_ctx {
		word_t bp;
		word_t sp;
	} frame_ctx;

	cap_no = (cap_no + 1) << COS_CAPABILITY_OFFSET;
	cap_no += op;

	__asm__ __volatile__(
	                     "movq %%rbp, (%%rcx)\n\t"	\
	                     "movq %%rsp, 8(%%rcx)\n\t"	\
	                     "movq %%rcx, %%rbp\n\t"	\
	                     "movabs $1f, %%r8\n\t"	\
	                     "syscall\n\t"		\
	                     ".align 8\n\t"		\
	                     "jmp 2f\n\t"		\
	                     ".align 8\n\t"		\
	                     "1:\n\t"			\
	                     "movl $0, %%ecx\n\t"	\
	                     "jmp 3f\n\t"		\
	                     "2:\n\t"			\
	                     "movl $1, %%ecx\n\t"	\
	                     "3:\n\t"			\
	                     "popq %%rbp\n\t"		\
	                     "popq %%rsp\n\t"		\
	                     : "=a"(ret), "=c"(fault)
	                     : "a"(cap_no), "b"(arg1), "S"(arg2), "D"(arg3), "d"(arg4), "c"(&frame_ctx)
	                     : "memory", "cc", "r8", "r9", "r11","r12");

	return ret;
}

static inline sword_t
call_cap_retvals_asm(u32_t cap_no, u32_t op, word_t arg1, word_t arg2, word_t arg3, word_t arg4, word_t *r1, word_t *r2, word_t *r3)
{
	long fault = 0;
	sword_t  ret;
	/*
	 * We use this frame ctx to save bp(frame pointer) and sp(stack pointer)
	 * before it goes into the kernel through syscall.
	 * 
	 * We cannot use a push %rbp/%rsp because the compiler doesn't know
	 * the inline assembly code changes the stack pointer. Thus, in some
	 * cases the compiler might do some optimizations which could conflict
	 * with the push %rbp/%rsp. That means, the push might corrupt some
	 * stack local variables. Thus, instead of using push instruction, we
	 * use mov instruction to first save them to a stack local position(frame_ctx)
	 * and then pass the address of the frame_ctx to the kernel rather than the sp.
	 * When the syscall returns, the kernel will restore the sp to the address of
	 * frame_ctx, thus we can simply use two pops to restore the original bp and sp.
	 */
	struct frame_ctx {
		word_t bp;
		word_t sp;
	} frame_ctx;

	cap_no = (cap_no + 1) << COS_CAPABILITY_OFFSET;
	cap_no += op;

	__asm__ __volatile__(
	                     "movq %%rbp, (%%rcx)\n\t"	\
	                     "movq %%rsp, 8(%%rcx)\n\t"	\
	                     "movq %%rcx, %%rbp\n\t"	\
	                     "movabs $1f, %%r8\n\t"	\
	                     "syscall\n\t"		\
	                     ".align 8\n\t"		\
	                     "jmp 2f\n\t"		\
	                     ".align 8\n\t"		\
	                     "1:\n\t"			\
	                     "mov $0, %%rcx\n\t"	\
	                     "jmp 3f\n\t"		\
	                     "2:\n\t"			\
	                     "mov $1, %%rcx\n\t"	\
	                     "3:\n\t"			\
	                     "popq %%rbp\n\t"		\
	                     "popq %%rsp\n\t"		\
	                     : "=a"(ret), "=c"(fault), "=S"(*r1), "=D"(*r2), "=b" (*r3)
	                     : "a"(cap_no), "b"(arg1), "S"(arg2), "D"(arg3), "d"(arg4), "c"(&frame_ctx)
	                     : "memory", "cc", "r8", "r9", "r11", "r12");

	return ret;
}

static inline word_t
call_cap_2retvals_asm(u32_t cap_no, u32_t op, word_t arg1, word_t arg2, word_t arg3, word_t arg4, word_t *r1, word_t *r2)
{
	long   fault = 0;
	word_t ret;
	/*
	 * We use this frame ctx to save bp(frame pointer) and sp(stack pointer)
	 * before it goes into the kernel through syscall.
	 * 
	 * We cannot use a push %rbp/%rsp because the compiler doesn't know
	 * the inline assembly code changes the stack pointer. Thus, in some
	 * cases the compiler might do some optimizations which could conflict
	 * with the push %rbp/%rsp. That means, the push might corrupt some
	 * stack local variables. Thus, instead of using push instruction, we
	 * use mov instruction to first save them to a stack local position(frame_ctx)
	 * and then pass the address of the frame_ctx to the kernel rather than the sp.
	 * When the syscall returns, the kernel will restore the sp to the address of
	 * frame_ctx, thus we can simply use two pops to restore the original bp and sp.
	 */
	struct frame_ctx {
		word_t bp;
		word_t sp;
	} frame_ctx;


	cap_no = (cap_no + 1) << COS_CAPABILITY_OFFSET;
	cap_no += op;

	__asm__ __volatile__(
	                     "movq %%rbp, (%%rcx)\n\t"	\
	                     "movq %%rsp, 8(%%rcx)\n\t"	\
	                     "movq %%rcx, %%rbp\n\t"	\
	                     "movabs $1f, %%r8\n\t"	\
	                     "syscall\n\t"		\
	                     ".align 8\n\t"		\
	                     "jmp 2f\n\t"		\
	                     ".align 8\n\t"		\
	                     "1:\n\t"			\
	                     "mov $0, %%rcx\n\t"	\
	                     "jmp 3f\n\t"		\
	                     "2:\n\t"			\
	                     "mov $1, %%rcx\n\t"	\
	                     "3:\n\t"			\
	                     "popq %%rbp\n\t"		\
	                     "popq %%rsp\n\t"		\
	                     : "=a"(ret), "=c"(fault), "=S"(*r1), "=D"(*r2)
	                     : "a"(cap_no), "b"(arg1), "S"(arg2), "D"(arg3), "d"(arg4), "c"(&frame_ctx)
	                     : "memory", "cc", "r8","r9","r10", "r11", "r12");

	return ret;
}

static inline sword_t
cap_switch_thd(u32_t cap_no)
{
	return call_cap_asm(cap_no, 0, 0, 0, 0, 0);
}

static inline sword_t
call_cap(u32_t cap_no, word_t arg1, word_t arg2, word_t arg3, word_t arg4)
{
	return call_cap_asm(cap_no, 0, arg1, arg2, arg3, arg4);
}

static inline sword_t
call_cap_op(u32_t cap_no, u32_t op_code, word_t arg1, word_t arg2, word_t arg3, word_t arg4)
{
	return call_cap_asm(cap_no, op_code, arg1, arg2, arg3, arg4);
}

static sword_t
cos_print(char *s, int len)
{
	u32_t *s_ints = (u32_t *)s;
	return call_cap(PRINT_CAP_TEMP, s_ints[0], s_ints[1], s_ints[2], len);
}

static inline sword_t
cos_sinv(struct usr_inv_cap *uc, word_t arg1, word_t arg2, word_t arg3, word_t arg4)
{
	word_t r1, r2;

	if (likely(uc->alt_fn)) return (uc->alt_fn)(arg1, arg2, arg3, arg4, &r1, &r2);

	return call_cap_op(uc->cap_no, 0, arg1, arg2, arg3, arg4);
}

static inline sword_t
cos_sinv_2rets(struct usr_inv_cap *uc, word_t arg1, word_t arg2, word_t arg3, word_t arg4, word_t *ret1, word_t *ret2)
{
	if (likely(uc->alt_fn)) return (uc->alt_fn)(arg1, arg2, arg3, arg4, ret1, ret2);

	return call_cap_2retvals_asm(uc->cap_no, 0, arg1, arg2, arg3, arg4, ret1, ret2);
}

static inline sword_t
cos_sinv_rets(u32_t sinv, word_t arg1, word_t arg2, word_t arg3, word_t arg4, word_t *ret1, word_t *ret2, word_t *ret3)
{
	return call_cap_retvals_asm(sinv, 0, arg1, arg2, arg3, arg4, ret1, ret2, ret3);
}

/**
 * FIXME: Please remove this since it is no longer needed
 */

extern long stkmgr_stack_space[ALL_TMP_STACKS_SZ];
extern struct cos_component_information __cosrt_comp_info;

static inline long
get_stk_data(int offset)
{
	unsigned long curr_stk_pointer;

	__asm__("mov %%rsp, %0;" : "=r"(curr_stk_pointer));
	/*
	 * We save the CPU_ID and thread id in the stack for fast
	 * access.  We want to find the struct cos_stk (see the stkmgr
	 * interface) so that we can then offset into it and get the
	 * cpu_id.  This struct is at the _top_ of the current stack,
	 * and cpu_id is at the top of the struct (it is a u32_t).
	 */
	return *(long *)((curr_stk_pointer & ~(COS_STACK_SZ - 1)) + COS_STACK_SZ - offset * sizeof(unsigned long));
}

#define GET_CURR_CPU cos_cpuid()

static inline u64_t
cos_rdtscp(coreid_t *coreid, u16_t *numaid)
{
	unsigned long a, d, c;

	__asm__ __volatile__("rdtscp" : "=a"(a), "=d"(d), "=c"(c) : : );

	*coreid = c & 0xFFF;
	*numaid = c >> 12;

	return ((u64_t)d << 32) | (u64_t)a;
}

static inline long
cos_cpuid(void)
{
#if NUM_CPU == 1
	return 0;
#endif
	coreid_t coreid;
	u16_t    numaid;
	cos_rdtscp(&coreid, &numaid);

	return (long)coreid;
}

static inline coreid_t
cos_coreid(void)
{
	return (coreid_t)cos_cpuid();
}

static inline unsigned short int
cos_get_thd_id(void)
{
	/*
	 * see comments in the get_stk_data above.
	 */
	return get_stk_data(THDID_OFFSET);
}

static inline invtoken_t
cos_inv_token(void)
{
	return get_stk_data(INVTOKEN_OFFSET);
}

typedef u16_t cos_thdid_t;

static thdid_t
cos_thdid(void)
{
	return cos_get_thd_id();
}

#define ERR_THROW(errval, label) \
	do {                     \
		ret = errval;    \
		goto label;      \
	} while (0)

static inline long
cos_spd_id(void)
{
	return __cosrt_comp_info.cos_this_spd_id;
}

static inline compid_t
cos_compid(void)
{
	return cos_spd_id();
}

static inline int
cos_compid_uninitialized(void)
{
	return cos_compid() == 0;
}

static inline void
cos_compid_set(compid_t cid)
{
	__cosrt_comp_info.cos_this_spd_id = cid;
}

static inline void *
cos_get_heap_ptr(void)
{
	return (void *)__cosrt_comp_info.cos_heap_ptr;
}

static inline void
cos_set_heap_ptr(void *addr)
{
	__cosrt_comp_info.cos_heap_ptr = (vaddr_t)addr;
}

static inline char *
cos_init_args(void)
{
	return __cosrt_comp_info.init_string;
}

#define COS_CPUBITMAP_STARTTOK 'c'
#define COS_CPUBITMAP_ENDTOK   ","
#define COS_CPUBITMAP_LEN      (NUM_CPU)

static inline int
cos_args_cpubmp(u32_t *cpubmp, char *arg)
{
	char *tok1 = NULL, *tok2 = NULL;
	char res[COMP_INFO_INIT_STR_LEN] = { '\0' }, *rs = res;
	int i, len = 0;

	if (!arg || !cpubmp) return -EINVAL;
	strncpy(rs, arg, COMP_INFO_INIT_STR_LEN);
	if (!strlen(arg)) goto allset;
	while ((tok1 = strtok_r(rs, COS_CPUBITMAP_ENDTOK, &rs)) != NULL) {
		if (tok1[0] == COS_CPUBITMAP_STARTTOK) break;
	}
	/* if "c" tag is not present.. set the component to be runnable on all cores */
	if (!tok1) goto allset;
	if (strlen(tok1) != (COS_CPUBITMAP_LEN + 1)) return -EINVAL;

	tok2 = tok1 + 1;
	len = strlen(tok2);
	for (i = 0; i < len; i++) {
		if (tok2[i] == '1') bitmap_set(cpubmp, (len - 1 - i));
	}

	return 0;

allset:
	bitmap_set_contig(cpubmp, 0, NUM_CPU, 1);

	return 0;
}

static inline int
cos_init_args_cpubmp(u32_t *cpubmp)
{
	return cos_args_cpubmp(cpubmp, cos_init_args());
}

static inline long
cos_cmpxchg(volatile void *memory, long anticipated, long result)
{
	long ret;

	__asm__ __volatile__("call cos_atomic_cmpxchg"
	                     : "=d"(ret)
	                     : "a"(anticipated), "b"(memory), "c"(result)
	                     : "cc", "memory");

	return ret;
}

/* A uni-processor variant with less overhead but that doesn't
 * guarantee atomicity across cores. */
static inline int
cos_cas_up(unsigned long *target, unsigned long cmp, unsigned long updated)
{
	char z;
	__asm__ __volatile__("cmpxchgl %2, %0; setz %1"
	                     : "+m"(*target), "=a"(z)
	                     : "q"(updated), "a"(cmp)
	                     : "memory", "cc");
	return (int)z;
}

static inline void *
cos_get_prealloc_page(void)
{
	char *h;
	long  r;
	do {
		h = (char *)__cosrt_comp_info.cos_heap_alloc_extent;
		if (!h || (char *)__cosrt_comp_info.cos_heap_allocated >= h) return NULL;
		r = (long)h + PAGE_SIZE;
	} while (cos_cmpxchg(&__cosrt_comp_info.cos_heap_allocated, (long)h, r) != r);

	return h;
}

/* allocate and release a page in the vas */
extern void *cos_get_vas_page(void);
extern void  cos_release_vas_page(void *p);

/* only if the heap pointer is pre_addr, set it to post_addr */
static inline void
cos_set_heap_ptr_conditional(void *pre_addr, void *post_addr)
{
	cos_cmpxchg(&__cosrt_comp_info.cos_heap_ptr, (long)pre_addr, (long)post_addr);
}

/* from linux source in string.h */
static inline void *
cos_memcpy(void *to, const void *from, int n)
{
	int d0, d1, d2;

	__asm__ __volatile__("rep ; movsl\n\t"
	                     "movl %4,%%ecx\n\t"
	                     "andl $3,%%ecx\n\t"
#if 1 /* want to pay 2 byte penalty for a chance to skip microcoded rep? */
	                     "jz 1f\n\t"
#endif
	                     "rep ; movsb\n\t"
	                     "1:"
	                     : "=&c"(d0), "=&D"(d1), "=&S"(d2)
	                     : "0"(n / 4), "g"(n), "1"((long)to), "2"((long)from)
	                     : "memory");

	return (to);
}

static inline void *
cos_memset(void *s, char c, int count)
{
	int d0, d1;
	__asm__ __volatile__("rep\n\t"
	                     "stosb"
	                     : "=&c"(d0), "=&D"(d1)
	                     : "a"(c), "1"(s), "0"(count)
	                     : "memory");
	return s;
}

/* compiler branch prediction hints */
#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define CREGPARM(r) __attribute__((regparm(r)))
#define CFORCEINLINE __attribute__((always_inline))
#define CWEAKSYMB __attribute__((weak))
/*
 * Create a weak function alias called "aliasn" which aliases the
 * existing function "name".  Example: COS_FN_WEAKALIAS(read,
 * __my_read) will take your "__my_read" function and create "read" as
 * an a weak alias to it.
 */
#define COS_FN_WEAKALIAS(weak_alias, name)					\
	__typeof__(name) weak_alias __attribute__((weak, alias(STR(name))))

/*
 * A composite constructor (deconstructor): will be executed before
 * other component execution (after component execution).  CRECOV is a
 * function that should be called if one of the depended-on components
 * has failed (e.g. the function serves as a callback notification).
 */
#define CCTOR __attribute__((constructor))
#define CDTOR __attribute__((destructor)) /* currently unused! */
#define CRECOV(fnname) long crecov_##fnname##_ptr __attribute__((section(".crecov"))) = (long)fnname

static inline void
section_fnptrs_execute(long *list)
{
	int i;

	for (i = 0; i < list[0]; i++) {
		typedef void (*ctors_t)(void);
		ctors_t ctors = (ctors_t)list[i + 1];
		ctors();
	}
}

static void
constructors_execute(void)
{
	extern void * __CTOR_LIST__;
	extern void * __INIT_ARRAY_LIST__;
	section_fnptrs_execute((long *)&__CTOR_LIST__);
	section_fnptrs_execute((long *)&__INIT_ARRAY_LIST__);
}
static void
destructors_execute(void)
{
	extern long __DTOR_LIST__;
	extern long __FINI_ARRAY_LIST__;
	section_fnptrs_execute(&__DTOR_LIST__);
	section_fnptrs_execute(&__FINI_ARRAY_LIST__);
}
static void
recoveryfns_execute(void)
{
	extern long __CRECOV_LIST__;
	section_fnptrs_execute(&__CRECOV_LIST__);
}

#define FAIL() *(int *)NULL = 0

struct cos_array {
	char *mem;
	int   sz;
}; /* TODO: remove */
#define prevent_tail_call(ret) __asm__("" : "=r"(ret) : "m"(ret))

#if defined(__x86_64__)
		#define rdtscll(val) __asm__ __volatile__("rdtsc; shl $32, %%rdx; or %%rdx, %0" : "=a"(val)::"rdx")
#elif defined(__i386__)
		#define rdtscll(val) __asm__ __volatile__("rdtsc" : "=A"(val))
#endif


#ifndef STR
#define STRX(x) #x
#define STR(x) STRX(x)
#endif

struct __thd_init_data {
	void *fn;
	void *data;
};

typedef u32_t cbuf_t; /* TODO: remove when we have cbuf.h */

#define perfcntr(v) rdtscll(v)
static inline void pmccntr_init(void) {}

#define perfcntr_init pmccntr_init

#endif
