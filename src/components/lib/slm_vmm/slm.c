#include <slm.h>
#include <slm_api.h>
#include <ps_list.h>

struct slm_global __slm_global[NUM_CPU];
struct slm_ipi_percore slm_ipi_percore_data[NUM_CPU];

CK_RING_PROTOTYPE(slm_ipi_ringbuf, slm_ipi_event);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
/* GCC has bug of processing a warning(-Warray-bounds) and it does not get fixed, thus currently just close the warning in this function */
inline int
slm_ipi_event_enqueue(struct slm_ipi_event *event, cpuid_t id)
{
    struct slm_ipi_percore *ipi_data = &slm_ipi_percore_data[id];
	assert(&ipi_data->ring && ipi_data->ringbuf);

    return CK_RING_ENQUEUE_MPSC(slm_ipi_ringbuf, &ipi_data->ring, ipi_data->ringbuf, event);
}

inline int
slm_ipi_event_dequeue(struct slm_ipi_event *event, cpuid_t id)
{
    struct slm_ipi_percore *ipi_data = &slm_ipi_percore_data[id];
    assert(&ipi_data->ring && ipi_data->ringbuf);

    return CK_RING_DEQUEUE_MPSC(slm_ipi_ringbuf, &ipi_data->ring, ipi_data->ringbuf, event);
}

inline int
slm_ipi_event_empty(cpuid_t id)
{
    struct slm_ipi_percore *ipi_data = &slm_ipi_percore_data[id];
    assert(&ipi_data->ring);
    return (!ck_ring_size(&ipi_data->ring));
}

inline struct slm_ipi_percore *
slm_ipi_percore_get(cpuid_t id)
{
    return &slm_ipi_percore_data[id];
}
#pragma GCC diagnostic pop

struct slm_thd *
slm_thd_special(void)
{
	thdid_t me = cos_thdid();
	struct slm_global *g = slm_global();

	if (me == g->sched_thd.tid)     return &g->sched_thd;
	else if (me == g->idle_thd.tid) return &g->idle_thd;
	else                            return NULL;
}

static int
slm_thd_init_internal(struct slm_thd *t, thdcap_t thd, thdid_t tid)
{
	struct cos_defcompinfo *defci     = cos_defcompinfo_curr_get();
	struct cos_aep_info    *sched_aep = cos_sched_aep_get(defci);
	int ret;

	memset(t, 0, sizeof(struct slm_thd));
	*t = (struct slm_thd) {
		.tc = sched_aep->tc,
		.thd = thd,
		.tid = tid,
		.state = SLM_THD_RUNNABLE,
		.priority = TCAP_PRIO_MIN,
		.cpuid = cos_cpuid(),
		.block_count = 0,
		.last_yield = 1,
		.properties = 0
	};
	ps_list_init(t, thd_list);
	ps_list_init(t, graveyard_list);

	return 0;
}

static int
slm_thd_deinit_internal(struct slm_thd *t)
{
	ps_list_head_append(&slm_global()->graveyard_head, t, graveyard_list);

	return 0;
}

int
slm_thd_init(struct slm_thd *t, thdcap_t thd, thdid_t tid)
{
	int ret;

	if ((ret = slm_thd_init_internal(t, thd, tid))) return ret;
	if ((ret = slm_timer_thd_init(t))) return ret;
	if ((ret = slm_sched_thd_init(t))) return ret;

	return 0;
}

void
slm_thd_deinit(struct slm_thd *t)
{
	slm_sched_thd_deinit(t);
	slm_timer_thd_deinit(t);
	t->state = SLM_THD_DYING;
}

/*
 * If there is contention of the critical section, this is called.
 * This is pulled out of the inlined fastpath.
 *
 * - @cs - critical section
 * - @cached - the cached value of the cs
 * - @curr - current thread
 * - @owner - the thread that owns the cs
 * - @contended - {0, 1} previously contended or not
 * - @tok - scheduler synchronization token for cos_defswitch
 *
 * @ret:
 *     (Caller of this function should retry for a non-zero return value.)
 *     1 for cas failure or after successful thread switch to thread that owns the lock.
 *     -ve from cos_defswitch failure, allowing caller for ex: the scheduler thread to
 *     check if it was -EBUSY to first recieve pending notifications before retrying lock.
 */
int
slm_cs_enter_contention(struct slm_cs *cs, slm_cs_cached_t cached, struct slm_thd *curr, struct slm_thd *owner, int contended, sched_tok_t tok)
{
	struct slm_global *g = slm_global();
	int ret;

	/* Set contention if it isn't yet set */
	if (!contended) {
		if (__slm_cs_cas(cs, cached, owner, 1)) return 1;
	}

	/* 
	 * FIXME: if there is a owner holding the lock, the owner should also be in the scheduler component.
	 * If we use g->timeout_next as the argument of cos_defswitch's timeout parameter when the owner is 
	 * not a scheduler thread, deadlock could happen. The reason is: because the non-scheduler thread is 
	 * in the critical section while the scheduler thread is trying to enter this critical section, each
	 * time when the scheduler tries to switch to the owner thread, it uses g->timeout_next to switch to
	 * the owner. However, since the scheduler cannot update g->timeout_next because it does not gain the
	 * lock at this point of time, the timeout value g->timeout_next is a old value. Then, when the kernel
	 * tries to switch to the owner, it will set the timer interrupt with current actual time plus a small
	 * latency compensate. The problem here is because the timer interrupt is set to be a very near future,
	 * it could happen that before the kernel really switches into the owner, the timer interrrupt has been
	 * fired. Thus, when it comes into the first instruction of owner code, it will immediately be interrupted
	 * and then switch back to the scheduler thread here. Becuase the scheduler thread again doesn't gain the
	 * lock, it will use the same old g->timeout_next value to have the same switch request, which causes a deadlock. 
	 * 
	 * As a result, we use TCAP_TIME_NIL here, which tells the kernel to disable the timer interrupt for the
	 * owner thread. Because we know the owner thread at this point of time is in the scheduler componet, thus
	 * it is trusted to disable the timer interrupt. After the owner thread properly exits the critical section,
	 * it will have chance to do scheduling decisions which will enable timer interrupt again for other non-trusted
	 * components' thread.
	 * 
	 * However, this could cause problems when we have other types of interrupt like nic interrupt because that type
	 * of interrupt could directly switch to the user level component (like a nic component). If this happens while
	 * the timer interrupt is disabled, it will casue problem. Thue, we currently assume there is no other type of
	 * interrupt except the timer interrupt.
	 */

	/* Switch to the owner of the critical section, with inheritance using our tcap/priority */
	ret = cos_defswitch(owner->thd, curr->priority, TCAP_TIME_NIL, tok);
	if (ret) return ret;
	/* if we have an outdated token, then we want to use the same repeat loop, so return to that */

	return 1;
}

/*
 * If another thread contended the critical section we're giving up,
 * this is the slowpath.
 *
 * - @cs - the critical section
 * - @curr - the current thread (releasing the cs)
 * - @cached - cached copy the critical section value
 * - @tok: scheduler synchronization token
 *
 * @ret: returns 1 if we need a retry, 0 otherwise
 */
int
slm_cs_exit_contention(struct slm_cs *cs, struct slm_thd *curr, slm_cs_cached_t cached, sched_tok_t tok)
{
	struct slm_thd *s = &slm_global()->sched_thd;
	int ret;

	if (__slm_cs_cas(cs, cached, NULL, 0)) return 1;
	/*
	 * We simplify here by simply switching to the scheduler
	 * thread to let it resolve the situation. Use our priority
	 * for its execution to avoid inversion.
	 */
	ret = cos_defswitch(s->thd, curr->priority, TCAP_TIME_NIL, tok);
	assert(ret != -EINVAL);

	return 0;
}

/***
 * Thread blocking and waking.
 */

/**
 * `slm_thd_wakeup_blked` assumes that `t` is in the `BLOCKED` state,
 * and wakes it up, telling the policy to insert it into the
 * runqueues.
 *
 * - @t - The thread to wakeup
 * - @return - `1` if it's already `RUNNABLE`.
 *             `0` if it was woken up in this call
 */
static inline int
slm_thd_wakeup_blked(struct slm_thd *t)
{
	assert(t);
	assert(slm_thd_normal(t));

	assert(t->state == SLM_THD_BLOCKED);
	t->state = SLM_THD_RUNNABLE;
	slm_sched_wakeup(t);
	t->properties &= ~SLM_THD_PROPERTY_SUSPENDED;

	return 0;
}

/*
 * - @t must be the current thread.
 * - @return: 1 if it's already WOKEN.
 *	    0 if it successfully blocked in this call.
 */
int
slm_thd_block(struct slm_thd *t)
{
	assert(t);
	assert(slm_thd_normal(t));

	if (unlikely(t->state == SLM_THD_WOKEN)) {
		assert(!(t->properties & SLM_THD_PROPERTY_SUSPENDED));
		t->state = SLM_THD_RUNNABLE;

		return 1;
	}
	assert(t->state == SLM_THD_RUNNABLE);

	/*
	 * reset SLM_THD_PROPERTY_SUSPENDED if the scheduler thinks
	 * "curr" was suspended on cos_rcv previously
	 */
	if (t->properties & SLM_THD_PROPERTY_SUSPENDED) {
		t->properties &= ~SLM_THD_PROPERTY_SUSPENDED;
		if (t->state == SLM_THD_BLOCKED) {
			slm_thd_wakeup_blked(t);
		}
	}

	assert(t->state == SLM_THD_RUNNABLE);
	t->state = SLM_THD_BLOCKED;
	slm_sched_block(t);

	return 0;
}

void
slm_thd_block_cs(struct slm_thd *current)
{
	slm_cs_enter(current, SLM_CS_NONE);
	if (slm_thd_block(current)) {
		slm_cs_exit(current, SLM_CS_NONE);
	} else {
		slm_cs_exit_reschedule(current, SLM_CS_NONE);
	}

	return;
}

/*
 * This API is only used by the scheduling thread to block an AEP thread.
 * AEP thread scheduling events could be redundant.
 *
 * @return: 0 if it successfully blocked in this call.
 */
static inline int
slm_thd_sched_block(struct slm_thd *t)
{
	assert(t);
	assert(slm_state_is_runnable(t->state) || t->state == SLM_THD_BLOCKED);
	assert(slm_thd_normal(t));

	/*
	 * It is oddly possible that the thread is already blocked. It
	 * was previously blocked, yet woke due to an asynchronous
	 * activation. This code can execute *before* the scheduler
	 * thread sees the notification that it had been woken.
	 */
	if (likely(slm_state_is_runnable(t->state))) {
		slm_sched_block(t);
	}
	t->state       = SLM_THD_BLOCKED;
	t->properties |= SLM_THD_PROPERTY_SUSPENDED;

	return 0;
}


/*
 * This API is only used by the scheduling thread to wakeup an AEP thread.
 * AEP thread scheduling events could be redundant.
 *
 * @return: 1 if it's already WOKEN or RUNNABLE.
 *	    0 if it successfully blocked in this call.
 */
int
slm_thd_sched_wakeup(struct slm_thd *t)
{
	assert(t);

	/* not blocked on cos_rcv, so don't mess with user-level thread states */
	if (unlikely(!(t->properties & SLM_THD_PROPERTY_SUSPENDED))) return 1;
	t->properties &= ~SLM_THD_PROPERTY_SUSPENDED;
	/*
	 * If a thread was preempted and scheduler updated it to
	 * RUNNABLE status and if that AEP was activated again
	 * (perhaps by tcap preemption logic) and expired it's budget,
	 * it could result in the scheduler having a redundant WAKEUP
	 * event.
	 *
	 * Thread could be in WOKEN state: Perhaps the thread was
	 * blocked waiting for a lock and was woken up by another
	 * thread and and then scheduler sees some redundant wakeup
	 * event through "asnd" or "tcap budget expiry".
	 */
	if (unlikely(slm_state_is_runnable(t->state))) {
		t->state = SLM_THD_RUNNABLE;

		return 1;
	}

	assert(t->state == SLM_THD_BLOCKED);
	t->state = SLM_THD_RUNNABLE;
	slm_sched_wakeup(t);

	return 0;
}

/**
 * - @redundant - can we have redundant wakeups? Likely this only
 *   makes sense for redundant periodic wakeups.
 */
int
slm_thd_wakeup(struct slm_thd *t, int redundant)
{
	assert(t);
	if (unlikely(t->cpuid != cos_cpuid())) {
		struct slm_ipi_percore *ipi_data = slm_ipi_percore_get(t->cpuid);
		struct slm_ipi_event    event    = { 0 };
		event.tid = t->tid;
		int ret = slm_ipi_event_enqueue(&event, t->cpuid);
		/* Check if the enqueuing of the event is successful. */
		assert(ret);
		cos_asnd(ipi_data->ipi_thd.asnd, 1);
		return 0;
	}

	if (t->state == SLM_THD_WOKEN) return 1;
	if (unlikely(t->state == SLM_THD_RUNNABLE || (redundant && t->state == SLM_THD_WOKEN))) {
		/*
		 * We have an odd case. We have a thread that is
		 * runnable (and running!), but is being asked to wake
		 * up. How can this happen? There can be a race
		 * between a thread blocking itself, and another
		 * thread waking it up. If the thread is preempted
		 * before it blocks itself, it can be runnable, but
		 * the other thread can get activated and tries to
		 * wake it.
		 *
		 * t->state == SLM_THD_WOKEN? multiple wakeups?
		 */
		t->state = SLM_THD_WOKEN;

		return 1;
	}
	assert(t->state == SLM_THD_BLOCKED);

	return slm_thd_wakeup_blked(t);
}

void
slm_thd_wakeup_cs(struct slm_thd *curr, struct slm_thd *t)
{
	assert(t);

	slm_cs_enter(curr, SLM_CS_NONE);
	/* Only reschedule if we wake up a thread */
	if (slm_thd_wakeup(t, 0)) {
		slm_cs_exit(curr, SLM_CS_NONE);
	} else {
		slm_cs_exit_reschedule(curr, SLM_CS_NONE);
	}

	return;
}

void
slm_thd_event_reset(struct slm_thd *t)
{
	memset(&t->event_info, 0, sizeof(struct event_info));
}

static inline void
slm_thd_event_enqueue(struct slm_thd *t, int blocked, cycles_t cycles, tcap_time_t timeout)
{
	struct slm_global *g = slm_global();

	if (ps_list_singleton(t, thd_list)) ps_list_head_append(&g->event_head, t, thd_list);

	t->event_info.blocked = blocked;
	t->event_info.cycles += cycles;
	t->event_info.timeout = timeout;
}

static inline void
slm_thd_event_dequeue(struct slm_thd *t, int *blocked, cycles_t *cycles, tcap_time_t *timeout)
{
	ps_list_rem(t, thd_list);

	*blocked = t->event_info.blocked;
	*cycles  = t->event_info.cycles;
	*timeout = t->event_info.timeout;
	slm_thd_event_reset(t);
}

/*
 * `slm_cs_enter_sched` enter into scheduler cs from the scheduler
 * thread context, and if we cannot take the critical section because
 * there are pending scheduler events (for this thread to get from the
 * kernel), then return as such.
 *
 * - @ret: returns -EBUSY if sched thread has events to process and
 *     cannot switch threads, 0 otherwise.
 */
static inline int
slm_cs_enter_sched(void)
{
	int ret;

	while ((ret = slm_cs_enter(&slm_global()->sched_thd, SLM_CS_SCHEDEVT))) {
		/* We don't want to retry if we have pending events to handle */
		if (ret == -EBUSY) break;
	}

	return ret;
}

unsigned long
slm_get_cycs_per_usec(void)
{
	struct slm_global *g = slm_global();

	return (unsigned long)g->cyc_per_usec;
}

static void
slm_sched_loop_intern(int non_block)
{
	struct slm_global *g = slm_global();
	rcv_flags_t      rfl = (non_block ? RCV_NON_BLOCKING : 0) | RCV_ALL_PENDING;
	struct slm_thd   *us = &g->sched_thd;
	struct slm_thd *t = NULL, *tn = NULL;

	/* Only the scheduler thread should call this function. */
	assert(cos_thdid() == us->tid);

	while (1) {
		int pending, ret;

		do {
			thdid_t        tid;
			int            blocked, rcvd;
			cycles_t       cycles;
			tcap_time_t    thd_timeout;

			/*
			 * Here we retrieve the kernel scheduler
			 * events. These include threads being asnded
			 * (thus activating), rcving (thus
			 * suspending), and generally executing (thus
			 * consuming cycles of computation). This is a
			 * rcv, so it may suspend the calling thread
			 * if `non_block` is `0`.
			 *
			 * Important that this is *not* in the CS due
			 * to the potential blocking.
			 */
			pending = cos_sched_rcv(us->rcv, rfl, g->timeout_next, &rcvd, &tid, &blocked, &cycles, &thd_timeout);
			if (!tid) goto pending_events;
			/*
			 * FIXME: kernel should pass an untyped
			 * pointer back here that we can use instead
			 * of the tid. This is the only place where
			 * slm requires the thread id -> thread
			 * mapping ;-(
			 */
			t = slm_thd_lookup(tid);
			assert(t);
			/* don't report the idle thread or a freed thread */
			if (unlikely(t == &g->idle_thd || slm_state_is_dead(t->state))) goto pending_events;

			/*
			 * Failure to take the CS because 1. another
			 * thread is holding it and 2. switching to
			 * that thread cannot succeed because
			 * scheduler has pending events which will
			 * prevent the switch to the CS holder. This
			 * can cause the event just received to be
			 * dropped. Thus, to avoid dropping events,
			 * add the events to the scheduler event list
			 * and processing all the pending events after
			 * the scheduler can successfully take the
			 * lock.
			 *
			 * TODO: Better would be to update the kernel
			 * to enable a flag that ignores pending
			 * events on a dispatch request. This would
			 * allow the scheduler thread to switch to the
			 * CS holder, and switch back when the CS
			 * holder releases the CS (thus allowing the
			 * events to be processed at that point.
			 */
			slm_thd_event_enqueue(t, blocked, cycles, thd_timeout);

pending_events:
			/* No events? make a scheduling decision */
			if (ps_list_head_empty(&g->event_head)) break;

			/*
			 * Receiving scheduler notifications is not in critical section mainly for
			 * 1. scheduler thread can often be blocked in rcv, which can add to
			 *    interrupt execution or even AEP thread execution overheads.
			 * 2. scheduler events are not acting on the slm_thd or the policy structures, so
			 *    having finer grained locks around the code that modifies slm_thd states is better.
			 *
			 * Thus we process the events now, with the CS taken.
			 */
			if (slm_cs_enter(us, SLM_CS_SCHEDEVT)) continue;

			ps_list_foreach_del(&g->event_head, t, tn, thd_list) {
				/* remove the event from the list and get event info */
				slm_thd_event_dequeue(t, &blocked, &cycles, &thd_timeout);

				/* outdated event for a freed thread */
				if (unlikely(slm_state_is_dead(t->state))) continue;

				/* Notify the policy that some execution has happened. */
				slm_sched_execution(t, cycles);

				if (blocked) {
					assert(cycles);
					slm_thd_sched_block(t);
				} else {
					slm_thd_sched_wakeup(t);
				}
			}

			slm_cs_exit(us, SLM_CS_NONE);
		} while (pending > 0);

		if (slm_cs_enter_sched()) continue;
		/* If switch returns an inconsistency, we retry anyway */
		ret = slm_cs_exit_reschedule(us, SLM_CS_CHECK_TIMEOUT);
		if (ret && ret != -EAGAIN && ret != -EBUSY) BUG();
	}
}

void
slm_sched_loop(void)
{
	slm_sched_loop_intern(0);
}

void
slm_sched_loop_nonblock(void)
{
	slm_sched_loop_intern(1);
}

void
slm_init(thdcap_t thd, thdid_t tid)
{
	struct slm_global *g = slm_global();
	struct slm_thd *s    = &g->sched_thd;
	struct slm_thd *i    = &g->idle_thd;
	struct cos_defcompinfo *defci;
	struct cos_aep_info    *sched_aep;

	defci = cos_defcompinfo_curr_get();
	sched_aep = cos_sched_aep_get(defci);

	*s = (struct slm_thd) {
		.properties = SLM_THD_PROPERTY_SPECIAL,
		.state = SLM_THD_RUNNABLE,
		.tc  = sched_aep->tc,
		.thd = sched_aep->thd,
		.tid = sched_aep->tid,
		.rcv = sched_aep->rcv,
		.cpuid = cos_cpuid(),
		.priority = TCAP_PRIO_MAX
	};
	ps_list_init(s, thd_list);
	ps_list_init(s, graveyard_list);
	assert(s->tid == cos_thdid());

	*i = (struct slm_thd) {
		.properties = SLM_THD_PROPERTY_SPECIAL,
		.state = SLM_THD_RUNNABLE,
		.tc = sched_aep->tc,
		.thd = thd,
		.tid = tid,
		.rcv = 0,
		.cpuid = cos_cpuid(),
		.priority = TCAP_PRIO_MIN
	};
	ps_list_init(i, thd_list);
	ps_list_init(i, graveyard_list);

	ps_list_head_init(&g->event_head);
	ps_list_head_init(&g->graveyard_head);

	g->cyc_per_usec = cos_hw_cycles_per_usec(BOOT_CAPTBL_SELF_INITHW_BASE);
	g->lock.owner_contention = 0;

	slm_sched_init();
	slm_timer_init();
}
