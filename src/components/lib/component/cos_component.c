/**
 * Copyright 2007 by Gabriel Parmer, gabep1@cs.bu.edu
 *
 * Redistribution of this file is permitted under the GNU General
 * Public License v2.
 */

#include <cos_regs.h>
#include <stdio.h>
#include <sys/auxv.h>

#include <cos_regs.h>
#include <cos_system.h>
#include <cos_error.h>
#include <cos_types.h>
#include <cos_compiler.h>
#include <capop.h>

#include <cos_component.h>
#include <cos_debug.h>
#include <cos_kernel_api.h>
#include <consts.h>

#include <init.h>

#include <ps.h>

/*
 * __crt_main is just used to identify if the user has defined their
 * own main (thus overriding the weak place-holder below)
 */
static int
__crt_main(void)
{
	return 0;
}
COS_FN_WEAKALIAS(main, __crt_main);

COS_WEAK void
cos_init()
{
	return;
}

static void
__crt_parallel_main(coreid_t cid, int init_core, int ncores)
{
	return;
}
COS_FN_WEAKALIAS(parallel_main, __crt_parallel_main);

void
__crt_cos_parallel_init(coreid_t cid, int init_core, int ncores)
{
	return;
}
COS_FN_WEAKALIAS(cos_parallel_init, __crt_cos_parallel_init);

int
cos_main_defined(void)
{
	return __crt_main != main;
}

/*
 * Invoke the user's main. Only makes sense to call this if there is
 * an actual main function defined. TODO: handle passing arguments
 * properly.
 */
int
cos_main(void)
{
	assert(cos_main_defined());

	return main();
}

/* Intended to be implement by libraries */
COS_WEAK void
pre_syscall_default_setup()
{
}

/* Intended to be overriden by components */
COS_WEAK void
pre_syscall_setup()
{
	pre_syscall_default_setup();
}

COS_WEAK void
syscall_emulation_setup()
{
}

COS_WEAK long
cos_syscall_handler(int syscall_num, long a, long b, long c, long d, long e, long f, long g)
{
	printc("Default syscall handler called (syscall: %d, first arg: %ld), faulting!", syscall_num, a);
	assert(0);
	return 0;
}

CREGPARM(1) long
__cos_syscall(int syscall_num, long a, long b, long c, long d, long e, long f, long g)
{
	return cos_syscall_handler(syscall_num, a, b, c, d, e, f, g);
}

COS_WEAK void
libc_initialization_handler()
{
}

COS_WEAK void
libc_posixcap_initialization_handler()
{
}

COS_WEAK void
libc_posixsched_initialization_handler()
{
}

/* TODO: Make this a weak symbol (currently doing so makes this fail) */
void __init_libc(char **envp, char *pn);

void
libc_init()
{
	/* The construction of this is:
	 * evn1, env2, ..., NULL, auxv_n1, auxv_1, auxv_n2, auxv_2 ..., NULL
	 * TODO: Figure out a way to set AT_HWCAP / AT_SYSINFO
	 */
	static char *envp[] = {
                               "USER=composite_user",
                               "LANG=en_US.UTF-8",
                               "HOME=/home/composite_user",
                               "LOGNAME=composite_user",
                               NULL,
                               (char *)AT_PAGESZ,
                               (char *)PAGE_SIZE, /* Page size */
                               (char *)AT_UID,
                               (char *)1000, /* User id */
                               (char *)AT_EUID,
                               (char *)1000, /* Effective user id */
                               (char *)AT_GID,
                               (char *)1000, /* Group id */
                               (char *)AT_EGID,
                               (char *)1000, /* Effective group id */
                               (char *)AT_SECURE,
                               (char *)0, /* Whether the program is being run under sudo */
                               NULL
	};
	char *program_name = "composite component";
	__init_libc(envp, program_name);
}

COS_WEAK void
cos_upcall_exec(void *arg)
{
}

COS_WEAK int
cos_async_inv(struct usr_inv_cap *ucap, int *params)
{
	return 0;
}

COS_WEAK int
cos_thd_entry_static(u32_t idx)
{
	assert(0);
	return 0;
}

/*
 * Print a string of a given length to the debugging (i.e. serial)
 * output. Will return the number of bytes written (which must be less
 * than or equal to `len`). This will often make many system calls,
 * many of which polling serial availability.
 */
COS_WEAK int
cos_print_str(char *s, uword_t len)
{
	uword_t written = 0;

	while (written < len) {
		cos_retval_t ret;
		uword_t max_amnt = (REGS_MAX_NUM_ARGS - 1) * sizeof(uword_t);
		uword_t left = len - written;
		uword_t as[REGS_MAX_NUM_ARGS - 1];
		uword_t amnt, amnt_ret, na;
		int i;
		uword_t rets[REGS_MAX_NUM_ARGS];

		if (left > max_amnt) {
			amnt = max_amnt;
		} else {
			amnt = left;
		}

		memcpy(as, s + written, amnt);

		cos_syscall_9_4(COS_CAPTBL_DEFAULT_HW, COS_OP_HW_PRINT,
				amnt, as[0], as[1], as[2], as[3], as[4], as[5], as[6], as[7],
				(uword_t *)&ret, &amnt_ret, &na, &na);
		written += amnt_ret;

		if (cos_retval_error(ret)) break;
	}

	return written;
}

/*
 * Cos thread creation data structures.
 */
struct __thd_init_data __thd_init_data[COS_THD_INIT_REGION_SIZE] CACHE_ALIGNED;

static void
cos_thd_entry_exec(u32_t idx)
{
	void (*fn)(void *);
	void *data;

	fn   = __thd_init_data[idx].fn;
	data = __thd_init_data[idx].data;
	/* and release the entry... might need a barrier here. */
	__thd_init_data[idx].data = NULL;
	__thd_init_data[idx].fn   = NULL;

	(fn)(data);
}

static void
start_execution(coreid_t cid, int init_core, int ncores)
{
	init_main_t main_type = INIT_MAIN_NONE;
	/* is there a user-defined parallel init? */
	const int parallel_init = cos_parallel_init != __crt_cos_parallel_init;
	int ret = 0;
	int main_time = 0;
	static volatile int initialization_completed = 0;

	/* are parallel/regular main user-defined? */
	if (parallel_main != __crt_parallel_main) {
		main_type = INIT_MAIN_PARALLEL;
	} else if (cos_main_defined()) {
		/* only execute main if parallel_main doesn't exist */
		main_type = INIT_MAIN_SINGLE;
	}

	/* single-core initialization */
	if (initialization_completed == 0) {
		if (init_core) {
			cos_init();
			/* continue only if there is no user-defined main, or parallel exec */
			COS_EXTERN_INV(init_done)(parallel_init, main_type);
			/* Shouldn't return if we don't want to run parallel init or main */
			assert(parallel_init || main_type != INIT_MAIN_NONE);
		}

		/* Parallel initialization awaits `cos_init` completion */
		COS_EXTERN_INV(init_parallel_await_init)();
		if (parallel_init) {
			cos_parallel_init(cid, init_core, init_parallelism());
		}
		/* All initialization completed here, go onto main execution */
		COS_EXTERN_INV(init_done)(0, main_type);
		initialization_completed = 1;
	}
	/* No main? we shouldn't have continued here... */
	assert(main_type != INIT_MAIN_NONE);
	/* Either parallel main, or a single main with only the initial core executing here. */
	assert(main_type == INIT_MAIN_PARALLEL || (main_type == INIT_MAIN_SINGLE && init_core));

	/* Execute the main: either parallel or normal */
	if (main_type == INIT_MAIN_PARALLEL) {
		parallel_main(cid, init_core, init_parallelism());
	} else {
		/* Only the initial core should execute main */
		assert(init_core && main_type == INIT_MAIN_SINGLE);
		ret = cos_main();
	}
	COS_EXTERN_INV(init_exit)(ret);

	/* with the previous exits, we should never get here */
	BUG();
}

#if defined(__arm__)
COS_WEAK vaddr_t
cos_inv_cap_set(struct usr_inv_cap *uc)
{
	set_stk_data(INVCAP_OFFSET, (long)uc);

	return uc->invocation_fn;
}
#endif

COS_WEAK void
cos_upcall_fn(upcall_type_t t, void *arg1, void *arg2, void *arg3)
{
	static int first = 1;
	static struct ps_lock _lock = {0};

	printc("hello world: core %d, thread %ld\n", cos_coreid(), cos_thdid());

	/*
	 * There should be no concurrency at initialization (the init
	 * interface ensures this), so atomic operations aren't
	 * required here to update first.
	 */
	ps_lock_take(&_lock);
	if (first) {
		first = 0;

		/*
		 * Use the heap pointer as calculated from the linker
		 * script *if* the loader doesn't pass in its own
		 * value.
		 */
		if (__cosrt_comp_info.cos_heap_ptr == 0) {
			extern const vaddr_t __crt_static_heap_ptr;

			__cosrt_comp_info.cos_heap_ptr = round_up_to_page((vaddr_t)&__crt_static_heap_ptr);
		}

		/* The syscall enumlator might need something to be setup before it can work */
		pre_syscall_setup();
		/* libc needs syscall emulation to work */
		syscall_emulation_setup();
		/* With all that setup, we can invoke the libc_initialization_handler */
		libc_initialization_handler();
		/* init lib posix variants */
		libc_posixcap_initialization_handler();
		libc_posixsched_initialization_handler();


		constructors_execute();
	}
	ps_lock_release(&_lock);
	/*
	 * if it's the first component.. wait for timer calibration.
	 * NOTE: for "fork"ing components and not updating "spdid"s, this call will just fail and should be fine.
	 */
	if (cos_compid_uninitialized()) { /* we must be in the initial booter! */
		cos_hw_cycles_per_usec(BOOT_CAPTBL_SELF_INITHW_BASE);
		perfcntr_init();
	}

	/* A new thread is created in this comp. */
	/* arg1 is the thread init data. 0 means bootstrap. */
	if (arg1 == 0) {
		static unsigned long first_core = 1;
		/* FIXME: assume that core 0 is the initial core for now */
		start_execution(cos_coreid(), ps_cas(&first_core, 1, 0), init_parallelism());
	} else {
		word_t idx = (word_t)arg1 - 1;
		if (idx >= COS_THD_INIT_REGION_SIZE) {
			/* This means static defined entry */
			cos_thd_entry_static(idx - COS_THD_INIT_REGION_SIZE);
		} else {
			/* Execute dynamic allocated entry. */
			cos_thd_entry_exec(idx);
		}
	}
	assert(0); 		/* should *not* return from threads */

	return;
}

COS_WEAK void *
cos_get_vas_page(void)
{
	char *h;
	long  r;
	do {
		h = cos_get_heap_ptr();
		r = (long)h + PAGE_SIZE;
	} while (cos_cmpxchg(&__cosrt_comp_info.cos_heap_ptr, (long)h, r) != r);
	return h;
}

COS_WEAK void
cos_release_vas_page(void *p)
{
	cos_set_heap_ptr_conditional(p + PAGE_SIZE, p);
}

extern const vaddr_t __cosrt_upcall_entry;

extern const vaddr_t cos_ainv_entry;

COS_WEAK vaddr_t ST_user_caps;

/*
 * Much of this is either initialized at load time, or passed to the
 * loader though this structure.
 */
struct cos_component_information __cosrt_comp_info =
        { .cos_this_spd_id         = 0,
	  .cos_heap_ptr            = 0,
	  .cos_heap_limit          = 0,
	  .cos_stacks.freelists[0] = {.freelist = 0, .thd_id = 0},
	  .cos_upcall_entry        = (vaddr_t)&__cosrt_upcall_entry,
	  .cos_async_inv_entry     = (vaddr_t)&cos_ainv_entry,
	  .cos_user_caps           = (vaddr_t)&ST_user_caps,
	  .cos_poly = {0,}
	};

COS_WEAK long _binary_tar_binary_start = 0;
COS_WEAK long _binary_tar_binary_end = 0;

char *
cos_initargs_tar(void)
{
	/* Tar files are at least one record, which is 512 bytes */
	if (_binary_tar_binary_end - _binary_tar_binary_start < 512) return NULL;
	return (char *)_binary_tar_binary_start;
}

#if COS_STATIC_DIRECT_MAPPED_STACKS
struct cos_stack_layout __first_stack __attribute__((aligned(COS_STACK_SIZE)));
struct cos_stack_layout cos_static_stack[COS_MAX_NUM_THREADS - 1] __attribute__((aligned(COS_STACK_SIZE)));
#endif	/* COS_STATIC_DIRECT_MAPPED_STACKS */
