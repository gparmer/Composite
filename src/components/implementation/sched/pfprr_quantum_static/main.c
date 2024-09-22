#include <cos_component.h>
#include <llprint.h>
#include <capmgr.h>
#include <static_slab.h>
#include <ps_list.h>
#include <ps.h>
#include <crt.h>

/***
 * A version of scheduling using a simple periodic timeout,
 * preemptive, fixed priority, round-robin scheduling, and uses the
 * capability manager to allocate threads, with local thread memory
 * tracked in static (allocate-only, finite) memory.
 */

#include <slm.h>
#include <quantum.h>
#include <fprr.h>
#include <slm_blkpt.c>
#include <slm_modules.h>

#include <syncipc.h>

struct slm_resources_thd {
	thdcap_t cap;
	thdid_t  tid;
	compid_t comp;
};

struct slm_thd *slm_thd_static_cm_lookup(thdid_t id);

SLM_MODULES_COMPOSE_DATA();
SLM_MODULES_COMPOSE_FNS(quantum, fprr, static_cm);

struct crt_comp self;

SS_STATIC_SLAB(thd, struct slm_thd_container, MAX_NUM_THREADS);

/* Implementation for use by the other parts of the slm */
struct slm_thd *
slm_thd_static_cm_lookup(thdid_t id)
{
	return &ss_thd_get(id)->thd;
}

static inline struct slm_thd *
slm_thd_current(void)
{
	return &ss_thd_get(cos_thdid())->thd;
}

struct slm_thd *
slm_thd_current_extern(void)
{
	return slm_thd_current();
}

struct slm_thd *
slm_thd_from_container(struct slm_thd_container *c) {
	return &c->thd;
}

struct slm_thd_container *
slm_thd_mem_alloc(thdcap_t _cap, thdid_t _tid, thdcap_t *thd, thdid_t *tid)
{
	struct slm_thd_container *t   = NULL;
	struct slm_thd_container *ret = NULL;

	ret = t = ss_thd_alloc_at_id(_tid);
	if (!t) assert(0);

	assert(_cap != 0 && _tid != 0);
	t->resources = (struct slm_resources_thd) {
		.cap  = _cap,
		.tid  = _tid,
		.comp = cos_compid()
	};

	*thd = _cap;
	*tid = _tid;

	return ret;
}

void slm_thd_mem_activate(struct slm_thd_container *t) { ss_thd_activate(t); }
/* TODO */
void slm_thd_mem_free(struct slm_thd_container *t) { return; }

thdid_t
sched_thd_create_closure(thdclosure_index_t idx)
{
	sched_param_t p = 0;
	struct slm_thd *t = thd_alloc_in(cos_inv_token(), idx, &p, 0);

	if (!t) return 0;

	return t->tid;
}

int
sched_thd_param_set(thdid_t tid, sched_param_t p)
{
	struct slm_thd *t = slm_thd_lookup(tid);
	sched_param_type_t type;
	unsigned int value;

	sched_param_get(p, &type, &value);

	if (!t) return -1;

	return slm_sched_thd_update(t, type, value);
}

int
sched_thd_delete(thdid_t tid)
{
	return 0;
}

int
sched_thd_exit(void)
{
	struct slm_thd *current = slm_thd_current();
	int i;

	slm_cs_enter(current, SLM_CS_NONE);
	slm_thd_deinit(current);
	for (i = 0; slm_cs_exit_reschedule(current, SLM_CS_NONE) && i < 16; i++) ;

	/* If we got here, something went wrong */
	BUG();

	return 0;
}

int
sched_thd_yield_to(thdid_t t)
{
	struct slm_thd *current = slm_thd_current();
	struct slm_thd *to = slm_thd_lookup(t);
	int ret;

	assert(to);
	if (!to) return -1;

	slm_cs_enter(current, SLM_CS_NONE);
        slm_sched_yield(current, to);
	ret = slm_cs_exit_reschedule(current, SLM_CS_NONE);

	return ret;
}

int
sched_thd_yield(void)
{
	struct slm_thd *current = slm_thd_current();
	int ret;

	slm_cs_enter(current, SLM_CS_NONE);
	slm_sched_yield(current, 0);
	ret = slm_cs_exit_reschedule(current, SLM_CS_NONE);

	return ret;
}

void
sched_set_tls(void* tls_addr)
{
	struct slm_thd *current = slm_thd_current();
	thdcap_t thdcap = current->thd;

	capmgr_set_tls(thdcap, tls_addr);
}

int
thd_block(void)
{
	struct slm_thd *current = slm_thd_current();
	int ret;

	slm_cs_enter(current, SLM_CS_NONE);
        ret = slm_thd_block(current);
	if (!ret) ret = slm_cs_exit_reschedule(current, SLM_CS_NONE);
	else      slm_cs_exit(NULL, SLM_CS_NONE);

	return ret;
}

int
sched_thd_block(thdid_t dep_id)
{
	if (dep_id) return -1;

	return thd_block();
}

int
thd_wakeup(struct slm_thd *t)
{
	int ret;
	struct slm_thd *current = slm_thd_current();

	slm_cs_enter(current, SLM_CS_NONE);
	ret = slm_thd_wakeup(t, 0);
	if (ret < 0) {
		slm_cs_exit(NULL, SLM_CS_NONE);
		return ret;
	}

	return slm_cs_exit_reschedule(current, SLM_CS_NONE);
}

int
sched_thd_wakeup(thdid_t tid)
{
	struct slm_thd *t = slm_thd_lookup(tid);

	if (!t) return -1;

	return thd_wakeup(t);
}

int
sched_debug_thd_state(thdid_t tid)
{
	struct slm_thd *t = slm_thd_lookup(tid);
	return t->state;
}

static int
thd_block_until(cycles_t timeout)
{
	struct slm_thd *current = slm_thd_current();
	int ret = 0;

	while (cycles_greater_than(timeout, slm_now())) {
		slm_cs_enter(current, SLM_CS_NONE);
		if (slm_timer_add(current, timeout)) goto done;
		if (slm_thd_block(current)) {
			slm_timer_cancel(current);
		}
done:
		ret = slm_cs_exit_reschedule(current, SLM_CS_NONE);
		/* cleanup stale timeouts (e.g. if we were woken outside of the timer) */
		slm_timer_cancel(current);
	}

	return ret;
}

cycles_t
sched_thd_block_timeout(thdid_t dep_id, cycles_t abs_timeout)
{
	cycles_t now;

	if (dep_id) return 0;
	if (thd_block_until(abs_timeout)) return 0;

	now = slm_now();
	assert(cycles_greater_than(now, abs_timeout));

	return now;
}

int
thd_sleep(cycles_t c)
{
	cycles_t timeout = c + slm_now();

	return thd_block_until(timeout);
}

sched_blkpt_id_t
sched_blkpt_alloc(void)
{
	struct slm_thd *current = slm_thd_current();

	return slm_blkpt_alloc(current);
}

int
sched_blkpt_free(sched_blkpt_id_t id)
{
	return slm_blkpt_free(id);
}

int
sched_blkpt_trigger(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, int single)
{
	struct slm_thd *current = slm_thd_current();

	return slm_blkpt_trigger(blkpt, current, epoch, single);
}

int
sched_blkpt_block(sched_blkpt_id_t blkpt, sched_blkpt_epoch_t epoch, thdid_t dependency)
{
	struct slm_thd *current = slm_thd_current();

	return slm_blkpt_block(blkpt, current, epoch, dependency);
}

struct ipc_retvals {
	int ready;
	word_t r0, r1;
};

struct ipc_ep {
	struct slm_thd     *client, *server;
	word_t              a0, a1;
	struct ipc_retvals *retvals;
};

/* For now, mainly a testing feature, thus only one */
#define IPC_EP_NUM 1 /* MAX_NUM_THREADS */

struct ipc_ep eps[IPC_EP_NUM];

enum {
	CNT_C_CALL,
	CNT_C_LOOP,
	CNT_C_RET,
	CNT_S_REPLY,
	CNT_S_LOOP,
	CNT_S_WAIT,
	CNT_S_RET,
	CNT_MAX
};
unsigned long counts[CNT_MAX];
static void
count_inc(int type)
{
	counts[type]++;
}

cycles_t readings[4];
struct total {
	int cnt;
	int prev_stage_cnt[4];
	cycles_t tot;
} totals[4];

static void
trace_add(int reading)
{
	struct total *t = &totals[reading];
	cycles_t prev_tsc;
	cycles_t now = ps_tsc();
	cycles_t max = 0;
	int i, max_idx;

	/* Avoid this overhead for now! */
	return;

	for (i = 0; i < 4; i++) {
		if (readings[i] > max) {
			max = readings[i];
			max_idx = i;
		}
	}
	prev_tsc = max;
	t->prev_stage_cnt[max_idx]++;

	t->cnt++;
	t->tot += now - prev_tsc;

	if (t->cnt % 128 == 128 - 1) {
		int i;

		for (i = 0; i < 4; i++)	{
			int cnt = totals[i].cnt;
			int j;

			if (cnt == 0) cnt = 1;
			printc("%d:%llu (", i, totals[i].tot / cnt);
			for (j = 0; j < 4; j++) {
				printc("%d:%d%s", j, totals[i].prev_stage_cnt[j], j == 3 ? "" :  ", ");
			}
			printc(")\n");
		}
		printc("Counts: ");
		for (i = 0; i < CNT_MAX; i++) {
			printc("%ld%s", counts[i], i == CNT_MAX - 1 ? "\n\n" : ", ");
		}

		readings[reading] = ps_tsc();
	} else {
		readings[reading] = now;
	}
}

int
syncipc_call(int ipc_ep, word_t arg0, word_t arg1, word_t *ret0, word_t *ret1)
{
	struct slm_thd *t = slm_thd_current(), *switchto, *client;
	/* avoid the conditional for bounds checking, ala Nova */
	struct ipc_ep *ep = &eps[ipc_ep % IPC_EP_NUM];
	sched_tok_t   tok;
	int           ret;
	struct ipc_retvals retvals = { .ready = 0 };

	count_inc(CNT_C_CALL);
	/* No server thread yet? Nothing to do here. */
	if (ep->server == NULL) return -EAGAIN;
	while (1) {
		tok      = cos_sched_sync();
		switchto = ps_load(&ep->server);


		/* Lets try and set ourself as the client communicating with the server! */
		if (likely(ps_cas((unsigned long *)&ep->client, 0, (unsigned long)t))) {
			/* We are the serviced client, pass arguments! */
			ep->a0      = arg0;
			ep->a1      = arg1;
			ep->retvals = &retvals;
			assert(ps_load(&ep->client) == t);
		}
		/*
		 * If another client is already communicating with the
		 * server, and they haven't yet populated the
		 * arguments and retvals, let them finish setting up
		 * their communication.
		 */
		client = ps_load(&ep->client);
		if (unlikely(ep->client != t && ep->retvals == NULL)) switchto = client;

		/*
		 * If we are the client, then we're activating the
		 * server here. If another client exists, we're
		 * generally just performing priority inheritance
		 * here.
		 */
		trace_add(0);
		ret = slm_switch_to(t, switchto, tok, 1);
		trace_add(3);
		count_inc(CNT_C_LOOP);
		/*
		 * Iterate while we are not the serviced client, we
		 * have a stale scheduling token...
		 */
		if (unlikely(ret)) {
			if (ret != -EAGAIN) return ret;
			if (ret == EAGAIN) continue;
		}

		/* ...or the server hasn't provided a response. */
		if (likely(ps_load(&retvals.ready))) break;
	}

	count_inc(CNT_C_RET);
	*ret0 = ps_load(&retvals.r0);
	*ret1 = ps_load(&retvals.r1);

	return 0;
}

int
syncipc_reply_wait(int ipc_ep, word_t arg0, word_t arg1, word_t *ret0, word_t *ret1)
{
	struct slm_thd *t = slm_thd_current(), *client;
	/* avoid the conditional for bounds checking, ala Nova */
	struct ipc_ep *ep = &eps[ipc_ep % IPC_EP_NUM];
	sched_tok_t   tok;
	int           ret;

	/*
	 * Phase 1: An EP is associated with a specific server. This
	 * conditional is formulated to move the cas and awaiting the
	 * first client off the fast-path.
	 */
	if (unlikely(ep->server != t)) {
		/* Another server claimed the endpoint */
		if (ep->server != NULL)         return -1;
		if (!ps_cas((unsigned long *)&ep->server, 0, (unsigned long)t)) return -1;
		ret = slm_sched_thd_update(t, SCHEDP_INIT, 0);
		assert(ret == 0);
		assert(ep->server == t);

		/* Now await the first client spinning at idle prio! */
		while (ps_load(&ep->client) == NULL) ;
		*ret0 = ep->a0;
		*ret1 = ep->a1;

		return 0;
	}

	count_inc(CNT_S_REPLY);

	/*
	 * Phase 2: Reply to the client we are currently servicing!
	 */
	client             = ps_load(&ep->client);
	ep->retvals->r0    = arg0;
	ep->retvals->r1    = arg1;
	/* Make sure to set this *last*. */
	ep->retvals->ready = 1;
	/*
	 * Reset the endpoint, so that the next client can make a
	 * request. As the client variable is the sync point, we have
	 * to write it last.
	 */
	ep->retvals       = NULL;
	ep->client        = NULL;

	do {
		/*
		 * Switch back to the client!
		 *
		 * TODO: We should add a bit that designates if there
		 * is *contention* on the server thread, and if it is
		 * set, instead call `slm_exit_reschedule` here to
		 * instead run the highest-priority client.
		 */
		trace_add(2);
		ret = slm_switch_to(t, client, cos_sched_sync(), 1);
		trace_add(1);
		if (unlikely(ret) && ret != -EAGAIN) return ret;
		count_inc(CNT_S_LOOP);
	} while (ret == -EAGAIN);

	count_inc(CNT_S_WAIT);
	/*
	 * Phase 3: Now await the next call! We spin as we're idle
	 * priority.
	 */
	while (ps_load(&ep->client) == NULL) ;
	/*
	 * FIXME: If we are repriorized at higher than the client, we
	 * might preempt it after it sets ->client, but before it sets
	 * the arguments. The *correct* design is to create a PASSIVE
	 * priority in which threads only execute using explicit
	 * switches from other, properly prioritized threads. Such
	 * threads could *not* reprioritize.
	 */
	*ret0 = ep->a0;
	*ret1 = ep->a1;

	count_inc(CNT_S_RET);

	return 0;
}

thdid_t
sched_aep_create_closure(thdclosure_index_t id, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax, arcvcap_t *rcv)
{
	return -1;
}

unsigned long
sched_get_cpu_freq(void)
{
	return slm_get_cycs_per_usec();
}

struct slm_thd *
slm_ipithd_create(thd_fn_t fn, void * data, crt_rcv_flags_t flags, thdcap_t *thdcap, thdid_t *tid)
{
	struct slm_ipi_percore   *ipi_data = slm_ipi_percore_get(cos_cpuid());
	struct slm_ipi_thd       *r        = &ipi_data->ipi_thd;
	struct slm_thd_container *t;
	struct slm_global        *g = slm_global();
	struct slm_thd           *current = &g->sched_thd;
	struct slm_thd           *thd;
	struct slm_thd           *ret;
	thdcap_t                  _thd;
	thdid_t                   _tid;
	
	r->rcv = capmgr_rcv_alloc(fn, data, flags, &r->asnd, &_thd, &_tid);
	r->cpuid = cos_cpuid();
	r->tid = _tid;

	t = slm_thd_mem_alloc(_thd, _tid, thdcap, tid);
	if (!t) ERR_THROW(NULL, done);
	thd = slm_thd_from_container(t);

	slm_cs_enter(current, SLM_CS_NONE);
	if (slm_thd_init(thd, _thd, _tid)) ERR_THROW(NULL, free);

	slm_thd_mem_activate(t);

	slm_cs_exit(NULL, SLM_CS_NONE);

	ret = thd;
done:
	return ret;
free:
	slm_thd_mem_free(t);
	ret = NULL;
	goto done;
}

void
slm_ipi_process(void *d)
{
	int rcvd, ret;
	struct slm_ipi_percore *ipi_data = slm_ipi_percore_get(cos_cpuid());
	struct slm_ipi_thd     *r        = &ipi_data->ipi_thd;
	struct slm_ipi_event    event    = { 0 };
	struct slm_thd         *current  = slm_thd_current();
	struct slm_thd         *thd;

	/* block the IPI thd for test purpose */
	sched_thd_block(0);

	while (1) {
		cos_rcv(r->rcv, RCV_ALL_PENDING, &rcvd);

		while (!slm_ipi_event_empty(cos_cpuid())) {
			slm_ipi_event_dequeue(&event, cos_cpuid());

			thd = slm_thd_static_cm_lookup(event.tid);
			slm_cs_enter(current, SLM_CS_NONE);
			ret = slm_thd_wakeup(thd, 0);
			/*
			 * Return "0" means the thread is woken up in this call.
			 * Return "1" means the thread is already `RUNNABLE`.
			 */
			assert(ret == 0 || ret == 1);
			slm_cs_exit(current, SLM_CS_NONE);
		}
	}
	return;
}

static coreid_t _init_core_id = 0;

void
parallel_main(coreid_t cid)
{
	if (cid == _init_core_id) printc("Starting scheduler loop...\n");
	slm_sched_loop_nonblock();
}

void
cos_parallel_init(coreid_t cid, int init_core, int ncores)
{
	struct slm_thd_container *t;
	struct slm_thd *r;
	thdcap_t thdcap, ipithdcap;
	arcvcap_t rcvcap;
	thdid_t tid, ipitid;
	if (init_core) {
		_init_core_id = cid;
	} 
	struct slm_ipi_percore *ipi_data = slm_ipi_percore_get(cos_cpuid());

	cos_defcompinfo_sched_init();

	t = slm_thd_alloc(slm_idle, NULL, &thdcap, &tid);
	if (!t) BUG();

	slm_init(thdcap, tid);

	r = slm_ipithd_create(slm_ipi_process, NULL, 0, &ipithdcap, &ipitid);
	if (!r) BUG();
	sched_thd_param_set(ipitid, sched_param_pack(SCHEDP_PRIO, SLM_IPI_THD_PRIO));
	ck_ring_init(&ipi_data->ring, PAGE_SIZE / sizeof(struct slm_ipi_event));
}

void
cos_init(void)
{
	struct cos_compinfo *boot_info = cos_compinfo_get(cos_defcompinfo_curr_get());

	cos_meminfo_init(&(boot_info->mi), BOOT_MEM_KM_BASE, COS_MEM_KERN_PA_SZ, BOOT_CAPTBL_SELF_UNTYPED_PT);
	extern void calculate_initialization_schedule(void);
	calculate_initialization_schedule();
	cos_defcompinfo_init();
}
