/**
 * Redistribution of this file is permitted under the BSD two clause license.
 *
 * Copyright 2017, The George Washington University
 * Author: Gabriel Parmer, gparmer@gwu.edu
 */

#include <ps.h>
#include <sl.h>
#include <sl_xcore.h>
#include <sl_child.h>
#include <sl_mod_policy.h>
#include <cos_debug.h>
#include <cos_kernel_api.h>
#include <bitmap.h>
#include <cos_dcb.h>
#include <cos_ulsched_rcv.h>

struct sl_global sl_global_data;
struct sl_global_core sl_global_core_data[NUM_CPU] CACHE_ALIGNED;
static void sl_sched_loop_intern(int non_block) __attribute__((noreturn));
extern struct sl_thd *sl_thd_alloc_init(struct cos_aep_info *aep, asndcap_t sndcap, sl_thd_property_t prps, struct cos_dcb_info *dcb);
extern int sl_xcore_process_no_cs(void);
extern void sl_xcore_asnd_alloc(void);

/*
 * These functions are removed from the inlined fast-paths of the
 * critical section (cs) code to save on code size/locality
 */
int
sl_cs_enter_contention(union sl_cs_intern *csi, union sl_cs_intern *cached, struct sl_global_core *gcore, struct sl_thd *curr, sched_tok_t tok)
{
#ifdef SL_CS
	int ret;

	/* recursive locks are not allowed */
	assert(csi->s.owner != sl_thd_thdcap(curr));
	if (!csi->s.contention) {
		csi->s.contention = 1;
		if (!ps_upcas(&gcore->lock.u.v, cached->v, csi->v)) return 1;
	}
	/* Switch to the owner of the critical section, with inheritance using our tcap/priority */
	if ((ret = cos_defswitch(csi->s.owner, curr->prio, csi->s.owner == sl_thd_thdcap(gcore->sched_thd) ?
				 TCAP_TIME_NIL : gcore->timeout_next, tok))) return ret;
	/* if we have an outdated token, then we want to use the same repeat loop, so return to that */
#endif

	return 1;
}

/* Return 1 if we need a retry, 0 otherwise */
int
sl_cs_exit_contention(union sl_cs_intern *csi, union sl_cs_intern *cached, struct sl_global_core *gcore, sched_tok_t tok)
{
#ifdef SL_CS
	if (!ps_upcas(&gcore->lock.u.v, cached->v, 0)) return 1;
	/* let the scheduler thread decide which thread to run next, inheriting our budget/priority */
	cos_defswitch(gcore->sched_thdcap, sl_thd_curr()->prio, TCAP_TIME_NIL, tok);
#endif

	return 0;
}

/* Timeout and wakeup functionality */
/*
 * TODO:
 * (comments from Gabe)
 * We likely want to replace all of this with rb-tree with nodes internal to the threads.
 * This heap is fast, but the static memory allocation is not great.
 */
struct timeout_heap {
	struct heap  h;
	void        *data[SL_MAX_NUM_THDS];
};

static struct timeout_heap timeout_heap[NUM_CPU] CACHE_ALIGNED;

struct heap *
sl_timeout_heap(void)
{ return &timeout_heap[cos_cpuid()].h; }

static inline void
sl_timeout_block(struct sl_thd *t, cycles_t timeout)
{
	assert(t && t->timeout_idx == -1);
	assert(heap_size(sl_timeout_heap()) < SL_MAX_NUM_THDS);

	if (!timeout) {
		cycles_t tmp = t->periodic_cycs;

		assert(t->period);
		t->periodic_cycs += t->period; /* implicit timeout = task period */
		assert(tmp < t->periodic_cycs); /* wraparound check */
		t->timeout_cycs   = t->periodic_cycs;
	} else {
		t->timeout_cycs   = timeout;
	}

	t->wakeup_cycs = 0;
	heap_add(sl_timeout_heap(), t);
}

static inline void
sl_timeout_remove(struct sl_thd *t)
{
	assert(t && t->timeout_idx > 0);
	assert(heap_size(sl_timeout_heap()));

	heap_remove(sl_timeout_heap(), t->timeout_idx);
	t->timeout_idx = -1;
}

static int
__sl_timeout_compare_min(void *a, void *b)
{
	/* FIXME: logic for wraparound in either timeout_cycs */
	return ((struct sl_thd *)a)->timeout_cycs <= ((struct sl_thd *)b)->timeout_cycs;
}

static void
__sl_timeout_update_idx(void *e, int pos)
{ ((struct sl_thd *)e)->timeout_idx = pos; }

static void
sl_timeout_init(microsec_t period)
{
	assert(period >= SL_MIN_PERIOD_US);

	sl_timeout_period(period);
	memset(&timeout_heap[cos_cpuid()], 0, sizeof(struct timeout_heap));
	heap_init(sl_timeout_heap(), SL_MAX_NUM_THDS, __sl_timeout_compare_min, __sl_timeout_update_idx);
}

void
sl_thd_free_no_cs(struct sl_thd *t)
{
        struct sl_thd *ct = sl_thd_curr();

        assert(t);
        assert(t->state != SL_THD_FREE);
        if (t->state == SL_THD_BLOCKED_TIMEOUT) sl_timeout_remove(t);
        sl_thd_index_rem_backend(sl_mod_thd_policy_get(t));
        sl_mod_thd_delete(sl_mod_thd_policy_get(t));
	ps_faa(&(sl__globals()->nthds_running[cos_cpuid()]), -1);
        t->state = SL_THD_FREE;
        /* TODO: add logic for the graveyard to delay this deallocation if t == current */
        sl_thd_free_backend(sl_mod_thd_policy_get(t));

        /* thread should not continue to run if it deletes itself. */
        if (unlikely(t == ct)) {
                while (1) {
			sl_cs_exit_schedule();
		}
                /* FIXME: should never get here, but tcap mechanism can let a child scheduler run! */
        }
}
/*
 * This API is only used by the scheduling thread to block an AEP thread.
 * AEP thread scheduling events could be redundant.
 *
 * @return: 0 if it successfully blocked in this call.
 */
int
sl_thd_sched_block_no_cs(struct sl_thd *t, sl_thd_state_t block_type, cycles_t timeout)
{
	assert(t);
	assert(t != sl__globals_core()->idle_thd && t != sl__globals_core()->sched_thd);
	assert(block_type == SL_THD_BLOCKED_TIMEOUT || block_type == SL_THD_BLOCKED);

	if (t->schedthd) return 0;
	/*
	 * If an AEP/a child COMP was blocked and an interrupt caused it to wakeup and run
	 * but blocks itself before the scheduler could see the wakeup event.. Scheduler
	 * will only see a BLOCKED event from the kernel.
	 * Only update the timeout if it already exists in the TIMEOUT QUEUE.
	 */
	if (unlikely(t->state == SL_THD_BLOCKED_TIMEOUT || t->state == SL_THD_BLOCKED)) {
		if (t->state == SL_THD_BLOCKED_TIMEOUT) sl_timeout_remove(t);
		goto update;
	}

	assert(sl_thd_is_runnable(t));
	sl_mod_block(sl_mod_thd_policy_get(t));
	ps_faa(&(sl__globals()->nthds_running[cos_cpuid()]), -1);

update:
	t->state = block_type;
	if (block_type == SL_THD_BLOCKED_TIMEOUT) sl_timeout_block(t, timeout);
	t->rcv_suspended = 1;

	return 0;
}

/*
 * Wake "t" up if it was previously blocked on cos_rcv and got
 * to run before the scheduler (tcap-activated)!
 */
static inline int
sl_thd_sched_unblock_no_cs(struct sl_thd *t)
{
	if (unlikely(!t->rcv_suspended)) return 0;
	t->rcv_suspended = 0;
	if (unlikely(t->state != SL_THD_BLOCKED && t->state != SL_THD_BLOCKED_TIMEOUT)) return 0;

	if (likely(t->state == SL_THD_BLOCKED_TIMEOUT)) sl_timeout_remove(t);
	/* make it RUNNABLE */
	sl_thd_wakeup_no_cs_rm(t);

	return 1;
}

/*
 * @return: 1 if it's already WOKEN.
 *	    0 if it successfully blocked in this call.
 */
int
sl_thd_block_no_cs(struct sl_thd *t, sl_thd_state_t block_type, cycles_t timeout)
{
	assert(t && sl_thd_curr() == t); /* only current thread is allowed to block itself */
	assert(t != sl__globals_core()->idle_thd && t != sl__globals_core()->sched_thd);
	/* interrupt thread could run and block itself before scheduler sees any of that! */
	sl_thd_sched_unblock_no_cs(t);
	assert(sl_thd_is_runnable(t));
	assert(block_type == SL_THD_BLOCKED_TIMEOUT || block_type == SL_THD_BLOCKED);

	if (t->schedthd) {
		sl_parent_notif_block_no_cs(t->schedthd, t);

		return 0;
	}

	if (unlikely(t->state == SL_THD_WOKEN)) {
		assert(!t->rcv_suspended);
		t->state = SL_THD_RUNNABLE;
		return 1;
	}

	/* reset rcv_suspended if the scheduler thinks "curr" was suspended on cos_rcv previously */
	assert(t->state == SL_THD_RUNNABLE);
	sl_mod_block(sl_mod_thd_policy_get(t));
	ps_faa(&(sl__globals()->nthds_running[cos_cpuid()]), -1);
	t->state = block_type;
	if (block_type == SL_THD_BLOCKED_TIMEOUT) sl_timeout_block(t, timeout);

	return 0;
}

void
sl_thd_block(thdid_t tid)
{
	struct sl_thd *t;

	/* TODO: dependencies not yet supported */
	assert(!tid);

	sl_cs_enter();
	t = sl_thd_curr();
	if (sl_thd_block_no_cs(t, SL_THD_BLOCKED, 0)) {
		sl_cs_exit();
		return;
	}
	sl_cs_exit_schedule();
	assert(sl_thd_is_runnable(t));

	return;
}

/*
 * if timeout == 0, blocks on timeout = last periodic wakeup + task period
 * @return: 0 if blocked in this call. 1 if already WOKEN!
 */
static inline int
sl_thd_block_timeout_intern(thdid_t tid, cycles_t timeout)
{
	struct sl_thd *t;

	sl_cs_enter();
	t = sl_thd_curr();
	if (sl_thd_block_no_cs(t, SL_THD_BLOCKED_TIMEOUT, timeout)) {
		sl_cs_exit();
		return 1;
	}
	sl_cs_exit_schedule();

	return 0;
}

cycles_t
sl_thd_block_timeout(thdid_t tid, cycles_t abs_timeout)
{
	cycles_t jitter  = 0, wcycs, tcycs;
	struct sl_thd *t = sl_thd_curr();

	/* TODO: dependencies not yet supported */
	assert(!tid);

	if (unlikely(!abs_timeout)) {
		sl_thd_block(tid);
		goto done;
	}

	if (sl_thd_block_timeout_intern(tid, abs_timeout)) goto done;
	wcycs = t->wakeup_cycs;
	tcycs = t->timeout_cycs;
	if (wcycs > tcycs) jitter = wcycs - tcycs;

done:
	return jitter;
}

unsigned int
sl_thd_block_periodic(thdid_t tid)
{
	cycles_t wcycs, pcycs;
	unsigned int jitter = 0;
	struct sl_thd *t    = sl_thd_curr();

	/* TODO: dependencies not yet supported */
	assert(!tid);

	assert(t->period);
	if (sl_thd_block_timeout_intern(tid, 0)) goto done;
	wcycs = t->wakeup_cycs;
	pcycs = t->periodic_cycs;
	if (wcycs > pcycs) jitter = ((unsigned int)((wcycs - pcycs) / t->period)) + 1;

done:
	return jitter;
}

void
sl_thd_block_expiry(struct sl_thd *t)
{
	cycles_t abs_timeout = 0;

	assert(t != sl__globals_core()->idle_thd && t != sl__globals_core()->sched_thd);
	sl_cs_enter();
	if (!(t->properties & SL_THD_PROPERTY_OWN_TCAP)) {
		assert(!t->rcv_suspended);
		abs_timeout = sl__globals_core()->timeout_next;
	} else {
		assert(t->period);
		abs_timeout = t->last_replenish + t->period;
	}

	/* reset rcv_suspended if the scheduler thinks "t" was suspended on cos_rcv previously */
	sl_thd_sched_unblock_no_cs(t);
	sl_thd_sched_block_no_cs(t, SL_THD_BLOCKED_TIMEOUT, abs_timeout);

	sl_cs_exit();
}

/*
 * This API is only used by the scheduling thread to wakeup an AEP thread.
 * AEP thread scheduling events could be redundant.
 *
 * @return: 1 if it's already WOKEN or RUNNABLE.
 *	    0 if it successfully blocked in this call.
 */
int
sl_thd_sched_wakeup_no_cs(struct sl_thd *t)
{
	assert(t);

	if (unlikely(!t->rcv_suspended)) return 1; /* not blocked on cos_rcv, so don't mess with user-level thread states */
	t->rcv_suspended = 0;
	/*
	 * If a thread was preempted and scheduler updated it to RUNNABLE status and if that AEP
	 * was activated again (perhaps by tcap preemption logic) and expired it's budget, it could
	 * result in the scheduler having a redundant WAKEUP event.
	 *
	 * Thread could be in WOKEN state:
	 * Perhaps the thread was blocked waiting for a lock and was woken up by another thread and
	 * and then scheduler sees some redundant wakeup event through "asnd" or "tcap budget expiry".
	 */
	if (unlikely(t->state == SL_THD_RUNNABLE || t->state == SL_THD_WOKEN)) return 1;

	assert(t->state == SL_THD_BLOCKED || t->state == SL_THD_BLOCKED_TIMEOUT);
	if (t->state == SL_THD_BLOCKED_TIMEOUT) sl_timeout_remove(t);
	t->state = SL_THD_RUNNABLE;
	sl_mod_wakeup(sl_mod_thd_policy_get(t));
	ps_faa(&(sl__globals()->nthds_running[cos_cpuid()]), 1);

	return 0;
}

/*
 * @return: 1 if it's already RUNNABLE.
 *          0 if it was woken up in this call
 */
int
sl_thd_wakeup_no_cs_rm(struct sl_thd *t)
{
	assert(t);
	assert(t != sl__globals_core()->idle_thd && t != sl__globals_core()->sched_thd);

	assert(t->state == SL_THD_BLOCKED || t->state == SL_THD_BLOCKED_TIMEOUT);
	t->state = SL_THD_RUNNABLE;
	sl_mod_wakeup(sl_mod_thd_policy_get(t));
	ps_faa(&(sl__globals()->nthds_running[cos_cpuid()]), 1);
	t->rcv_suspended = 0;

	return 0;
}

int
sl_thd_wakeup_no_cs(struct sl_thd *t)
{
	assert(t);
	assert(sl_thd_curr() != t); /* current thread is not allowed to wake itself up */

	if (t->schedthd) {
		sl_parent_notif_wakeup_no_cs(t->schedthd, t);

		return 0;
	}

//	if (unlikely(sl_thd_is_runnable(t))) {
//		/* t->state == SL_THD_WOKEN? multiple wakeups? */
//		t->state = SL_THD_WOKEN;
//		return 1;
//	}
	/*
	 * TODO: with blockpoints, multiple wakeup problem might go away.
	 * will try that next!
	 *
	 * For now, if a thread creates N tasks and if at least two of them
	 * complete before master goes to block, which can happen on multi-core
	 * execution of tasks, then that results in multiple wakeups!
	 */
	if (unlikely(t->state == SL_THD_WOKEN)) {
		t->state = SL_THD_RUNNABLE;
		return 1;
	} else if (unlikely(t->state == SL_THD_RUNNABLE)) {
		t->state = SL_THD_WOKEN;
		return 1;
	}

	assert(t->state == SL_THD_BLOCKED || t->state == SL_THD_BLOCKED_TIMEOUT);
	if (t->state == SL_THD_BLOCKED_TIMEOUT) sl_timeout_remove(t);
	return sl_thd_wakeup_no_cs_rm(t);
}

void
sl_thd_wakeup(thdid_t tid)
{
	struct sl_thd *t;

	sl_cs_enter();
	t = sl_thd_lkup(tid);
	if (unlikely(!t)) goto done;

	if (sl_thd_wakeup_no_cs(t)) goto done;
	sl_cs_exit_schedule();

	return;
done:
	sl_cs_exit();
	return;
}

static inline void
sl_thd_yield_cs_exit_intern(thdid_t tid)
{
	struct sl_thd *t = sl_thd_curr();

	/* reset rcv_suspended if the scheduler thinks "curr" was suspended on cos_rcv previously */
	sl_thd_sched_unblock_no_cs(t);
	if (likely(tid)) {
		struct sl_thd *to = sl_thd_lkup(tid);

		sl_cs_exit_switchto(to);
	} else {
		if (likely(t != sl__globals_core()->sched_thd && t != sl__globals_core()->idle_thd)) sl_mod_yield(sl_mod_thd_policy_get(t), NULL);
		sl_cs_exit_schedule();
	}
}


void
sl_thd_yield_cs_exit(thdid_t tid)
{
	sl_thd_yield_cs_exit_intern(tid);
}

void
sl_thd_yield_intern(thdid_t tid)
{
	sl_cs_enter();
	sl_thd_yield_cs_exit_intern(tid);
}

void
sl_thd_yield_intern_timeout(cycles_t abs_timeout)
{
	struct sl_thd *t = sl_thd_curr();

	sl_cs_enter();
	/* reset rcv_suspended if the scheduler thinks "curr" was suspended on cos_rcv previously */
	sl_thd_sched_unblock_no_cs(t);
	if (likely(t != sl__globals_core()->sched_thd && t != sl__globals_core()->idle_thd)) sl_mod_yield(sl_mod_thd_policy_get(t), NULL);
	sl_cs_exit_schedule_timeout(abs_timeout);
}

void
sl_thd_exit()
{
	sl_thd_free(sl_thd_curr());
}

void
sl_thd_param_set_no_cs(struct sl_thd *t, sched_param_t sp)
{
	sched_param_type_t type;
	unsigned int       value;

	assert(t);

	sched_param_get(sp, &type, &value);

	switch (type) {
	case SCHEDP_WINDOW:
	{
		t->period = sl_usec2cyc(value);
		t->periodic_cycs = sl_now(); /* TODO: synchronize for all tasks */
		break;
	}
	case SCHEDP_BUDGET:
	{
		t->budget = sl_usec2cyc(value);
		break;
	}
	default: break;
	}

	sl_mod_thd_param_set(sl_mod_thd_policy_get(t), type, value);
}

void
sl_thd_param_set(struct sl_thd *t, sched_param_t sp)
{
	assert(t);

	sl_cs_enter();

	sl_thd_param_set_no_cs(t, sp);
	sl_cs_exit();
}

void
sl_timeout_period(microsec_t period)
{
	cycles_t p = sl_usec2cyc(period);

	sl__globals_core()->period = p;
}

/* engage space heater mode */
void
sl_idle(void *d)
{ while (1) ; }

/* call from the user? */
static void
sl_global_init(u32_t *core_bmp)
{
	struct sl_global *g = sl__globals();
	unsigned int i = 0;

	memset(g, 0, sizeof(struct sl_global));
	assert(sizeof(struct cos_scb_info) * NUM_CPU <= COS_SCB_SIZE && COS_SCB_SIZE == PAGE_SIZE);
	g->scb_area = (struct cos_scb_info *)cos_scb_info_get();

	for (i = 0; i < NUM_CPU; i++) {
		if (!bitmap_check(core_bmp, i)) continue;

		bitmap_set(g->core_bmp, i);
		ck_ring_init(sl__ring(i), SL_XCORE_RING_SIZE);
	}
}

void
sl_init_corebmp(microsec_t period, u32_t *corebmp)
{
	int i;
	static volatile unsigned long  first = NUM_CPU + 1, init_done = 0;
	struct cos_defcompinfo        *dci   = cos_defcompinfo_curr_get();
	struct cos_compinfo           *ci    = cos_compinfo_get(dci);
	struct sl_global_core         *g     = sl__globals_core();
	struct cos_aep_info           *ga    = cos_sched_aep_get(dci);

	if (ps_cas((unsigned long *)&first, NUM_CPU + 1, cos_cpuid())) {
		sl_global_init(corebmp);
		ps_faa((unsigned long *)&init_done, 1);
	} else {
		/* wait until global ring buffers are initialized correctly! */
		while (!ps_load((unsigned long *)&init_done)) ;
		/* make sure this scheduler is active on this cpu/core */
		assert(sl_core_active());
	}

	/* must fit in a word */
	assert(sizeof(struct sl_cs) <= sizeof(unsigned long));
	memset(g, 0, sizeof(struct sl_global_core));

	g->cyc_per_usec = cos_hw_cycles_per_usec(BOOT_CAPTBL_SELF_INITHW_BASE);
	g->lock.u.v     = 0;
	g->scb_info     = ((sl__globals()->scb_area) + cos_cpuid());

	sl_thd_init_backend();
	sl_mod_init();
	sl_timeout_init(period);

	/* Create the scheduler thread for us. */
	g->sched_thd       = sl_thd_alloc_init(ga, 0, 0, (struct cos_dcb_info *)cos_init_dcb_get());
	assert(g->sched_thd);
	g->sched_thdcap    = ga->thd;
	g->sched_tcap      = ga->tc;
	g->sched_rcv       = ga->rcv;
	assert(g->sched_rcv);
	g->sched_thd->prio = TCAP_PRIO_MAX;
	ps_list_head_init(&g->event_head);
	assert(cos_thdid() == sl_thd_thdid(g->sched_thd));
	g->scb_info->curr_thd = 0;

	g->idle_thd        = sl_thd_alloc(sl_idle, NULL);
	assert(g->idle_thd);

	/* all cores that this sched runs on, must be initialized by now so "asnd"s can be created! */
	sl_xcore_asnd_alloc();

	return;
}


void
sl_init(microsec_t period)
{
	u32_t corebmp[NUM_CPU_BMP_WORDS] = { 0 };

	/* runs on all cores.. */
	bitmap_set_contig(corebmp, 0, NUM_CPU, 1);
	sl_init_corebmp(period, corebmp);
}

static inline int
__sl_sched_events_present(void)
{
	struct cos_scb_info *scb = sl_scb_info_core();
	struct cos_sched_ring *ring = &scb->sched_events;

	return __cos_sched_events_present(ring);
}

static inline int
__sl_sched_event_consume(struct cos_sched_event *e)
{
	struct cos_scb_info *scb = sl_scb_info_core();
	struct cos_sched_ring *ring = &scb->sched_events;

	return __cos_sched_event_consume(ring, e);
}

static inline int
__sl_sched_rcv(rcv_flags_t rf, struct cos_sched_event *e)
{
	struct sl_global_core *g = sl__globals_core();
#if 0
	struct sl_thd *curr = sl_thd_curr();
	struct cos_dcb_info *cd = sl_thd_dcbinfo(curr);
	int ret = 0;
//	if (cos_spd_id() != 4) printc("D");

	assert(curr == g->sched_thd);
	if (!cd) return cos_ul_sched_rcv(g->sched_rcv, rf, g->timeout_next, e);

	rf |= RCV_ULSCHED_RCV;
	
	__asm__ __volatile__ (			\
		"pushl %%ebp\n\t"		\
		"movl %%esp, %%ebp\n\t"		\
		"movl $1f, (%%eax)\n\t"		\
		"movl %%esp, 4(%%eax)\n\t"	\
		"movl $2f, %%ecx\n\t"		\
		"movl %%edx, %%eax\n\t"		\
		"inc %%eax\n\t"			\
		"shl $16, %%eax\n\t"		\
		"movl $0, %%edx\n\t"		\
		"movl $0, %%edi\n\t"		\
		"sysenter\n\t"			\
		"jmp 2f\n\t"			\
		".align 4\n\t"			\
		"1:\n\t"			\
		"movl $1, %%eax\n\t"		\
		".align 4\n\t"			\
		"2:\n\t"			\
		"popl %%ebp\n\t"		\
		: "=a" (ret)
		: "a" (cd), "b" (rf), "S" (g->timeout_next), "d" (g->sched_rcv)
		: "memory", "cc", "ecx", "edi");

//	if (cos_spd_id() != 4) printc("E");
//	if (cos_thdid() == 7) PRINTC("%s:%d %d\n", __func__, __LINE__, ret);
	cd = sl_thd_dcbinfo(sl_thd_curr());
	cd->sp = 0;

	rf |= RCV_ULONLY;
#endif
	return cos_ul_sched_rcv(g->sched_rcv, rf, g->timeout_next, e);
}

static void
sl_sched_loop_intern(int non_block)
{
	struct sl_global_core *g   = sl__globals_core();
	rcv_flags_t            rfl = (non_block ? RCV_NON_BLOCKING : 0);

	assert(sl_thd_curr() == g->sched_thd);
	assert(sl_core_active());

	while (1) {
		int pending;

		do {
			struct sl_thd *t = NULL, *tn = NULL;
			struct sl_child_notification notif;
			struct cos_sched_event e = { .tid = 0 };

			
	struct sl_thd *curr = sl_thd_curr();
	struct cos_dcb_info *cd = sl_thd_dcbinfo(curr);
			assert(cd->sp == 0);
			/*
			 * a child scheduler may receive both scheduling notifications (block/unblock
			 * states of it's child threads) and normal notifications (mainly activations from
			 * it's parent scheduler).
			 */
			//pending = cos_ul_sched_rcv(g->sched_rcv, rfl, g->timeout_next, &e);
//			if (cos_spd_id() != 4) printc("L");
			//else                   printc("l");
			pending = __sl_sched_rcv(rfl, &e);
			assert(cd->sp == 0);
//			if (cos_spd_id() != 4) printc("M");

			//else                   printc("m");

			if (pending < 0 || !e.tid) goto pending_events;

			t = sl_thd_lkup(e.tid);
			assert(t);
			/* don't report the idle thread or a freed thread */
			if (unlikely(t == g->idle_thd || t->state == SL_THD_FREE)) goto pending_events;

			/*
			 * Failure to take the CS because another thread is holding it and switching to
			 * that thread cannot succeed because scheduler has pending events causes the event
			 * just received to be dropped.
			 * To avoid dropping events, add the events to the scheduler event list and processing all
			 * the pending events after the scheduler can successfully take the lock.
			 */
			sl_thd_event_enqueue(t, &e.evt);

pending_events:
			if (ps_list_head_empty(&g->event_head) &&
			    ck_ring_size(sl__ring_curr()) == 0 &&
			    sl_child_notif_empty()) continue;

			/*
			 * receiving scheduler notifications is not in critical section mainly for
			 * 1. scheduler thread can often be blocked in rcv, which can add to
			 *    interrupt execution or even AEP thread execution overheads.
			 * 2. scheduler events are not acting on the sl_thd or the policy structures, so
			 *    having finer grained locks around the code that modifies sl_thd states is better.
			 */
			if (sl_cs_enter_sched()) continue;

			ps_list_foreach_del(&g->event_head, t, tn, SL_THD_EVENT_LIST) {
				/* remove the event from the list and get event info */
				sl_thd_event_dequeue(t, &e.evt);

				/* outdated event for a freed thread */
				if (t->state == SL_THD_FREE) continue;

				sl_mod_execution(sl_mod_thd_policy_get(t), e.evt.elapsed_cycs);

				if (e.evt.blocked) {
					sl_thd_state_t state = SL_THD_BLOCKED;
					cycles_t abs_timeout = 0;

					if (likely(e.evt.elapsed_cycs)) {
						if (e.evt.next_timeout) {
							state       = SL_THD_BLOCKED_TIMEOUT;
							abs_timeout = tcap_time2cyc(e.evt.next_timeout, sl_now());
						}
						sl_thd_sched_block_no_cs(t, state, abs_timeout);
					}
				} else {
					sl_thd_sched_wakeup_no_cs(t);
				}
			}

			/* process notifications from the parent of my threads */
			while (sl_child_notif_dequeue(&notif)) {
				struct sl_thd *t = sl_thd_lkup(notif.tid);

				if (notif.type == SL_CHILD_THD_BLOCK) sl_thd_block_no_cs(t, SL_THD_BLOCKED, 0);
				else                                  sl_thd_wakeup_no_cs(t);
			}

			/* process cross-core requests */
			sl_xcore_process_no_cs();

			sl_cs_exit();
		} while (pending > 0);

		if (sl_cs_enter_sched()) continue;
		/* If switch returns an inconsistency, we retry anyway */
		sl_cs_exit_schedule_nospin_timeout(0);
	}
}

void
sl_sched_loop(void)
{
	sl_sched_loop_intern(0);
}

void
sl_sched_loop_nonblock(void)
{
	sl_sched_loop_intern(1);
}

int
sl_thd_kern_dispatch(thdcap_t t)
{
	//return cos_switch(t, sl__globals_core()->sched_tcap, 0, sl__globals_core()->timeout_next, sl__globals_core()->sched_rcv, cos_sched_sync());
	return cos_thd_switch(t);
}

void
sl_thd_replenish_no_cs(struct sl_thd *t, cycles_t now)
{
#ifdef SL_REPLENISH
	struct cos_compinfo *ci = cos_compinfo_get(cos_defcompinfo_curr_get());
	tcap_res_t currbudget = 0;
	cycles_t replenish;
	int ret;

	if (!(t->properties & SL_THD_PROPERTY_OWN_TCAP && t->budget)) return;
	assert(t->period);
	assert(sl_thd_tcap(t) != sl__globals_core()->sched_tcap);

	if (!(t->last_replenish == 0 || t->last_replenish + t->period <= now)) return;

	replenish = now - ((now - t->last_replenish) % t->period);

	ret = 0;
	currbudget = (tcap_res_t)cos_introspect(ci, sl_thd_tcap(t), TCAP_GET_BUDGET);

	if (!cycles_same(currbudget, t->budget, SL_CYCS_DIFF) && currbudget < t->budget) {
		tcap_res_t transfer = t->budget - currbudget;

		/* tcap_transfer will assign sched_tcap's prio to t's tcap if t->prio == 0, which we don't want. */
		assert(t->prio >= TCAP_PRIO_MAX && t->prio <= TCAP_PRIO_MIN);
		ret = cos_tcap_transfer(sl_thd_rcvcap(t), sl__globals_core()->sched_tcap, transfer, t->prio);
	}

	if (likely(ret == 0)) t->last_replenish = replenish;
#endif
}
