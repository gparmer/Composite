#include <slm.h>
#include <fprr.h>
#include <slm_api.h>
#include <cos_types.h>
#include <cos_component.h>

#define ENABLE_DEBUG_INFO 0

#define SLM_FPRR_NPRIOS         32
#define SLM_FPRR_PRIO_HIGHEST   TCAP_PRIO_MAX
#define SLM_FPRR_PRIO_LOWEST    (SLM_FPRR_NPRIOS - 1)

#define SLM_FPRR_PERIOD_US_MIN  10000

struct runqueue {
	struct ps_list_head prio[SLM_FPRR_NPRIOS];
} CACHE_ALIGNED;
struct runqueue threads[NUM_CPU];

/* No RR based on execution, yet */
void
slm_sched_fprr_execution(struct slm_thd *t, cycles_t cycles)
{ return; }

/* simply dump a core's task queue for debug usage */
static void
debug_dump_info(void)
{
	#define LIMIT 10000
	#define CORE_ID 0
	static u64_t counter = 0;
	struct slm_sched_thd *t;
	struct ps_list_head *prios = threads[CORE_ID].prio;

	if (cos_cpuid() == CORE_ID) {
		counter++;
		if (counter > LIMIT) {
			/* iterate thread queue */
			printc("---thread queue dump begin---\n");
			for (int i = 0 ; i < SLM_FPRR_NPRIOS ; i++) {
				if (ps_list_head_empty(&prios[i])) continue;
				ps_list_foreach(&prios[i], t, list) {
					struct slm_thd *cur = slm_thd_from_sched(t);
					printc("thd id:%lu, stage:%d\n", cur->tid, cur->state);
				}
			}
			printc("---thread queue dump end---\n");
			counter = 0;
		} 
	}
}

struct slm_thd *
slm_sched_fprr_schedule(void)
{
	int i;
	struct slm_sched_thd *t;
	struct ps_list_head *prios = threads[cos_cpuid()].prio;

#if ENABLE_DEBUG_INFO
	debug_dump_info();
#endif

	for (i = 0 ; i < SLM_FPRR_NPRIOS ; i++) {
		if (ps_list_head_empty(&prios[i])) continue;
		t = ps_list_head_first_d(&prios[i], struct slm_sched_thd);

		/*
		 * We want to move the selected thread to the back of the list.
		 * Otherwise fprr won't be truly round robin
		 */
		ps_list_rem_d(t);
		ps_list_head_append_d(&prios[i], t);

//		printc("Schedule -> %ld\n", slm_thd_from_sched(t)->tid);
		return slm_thd_from_sched(t);
	}
//	printc("Schedule -> idle\n");

	return NULL;
}

int
slm_sched_fprr_block(struct slm_thd *t)
{
	struct slm_sched_thd *p = slm_thd_sched_policy(t);

	ps_list_rem_d(p);

	return 0;
}

int
slm_sched_fprr_wakeup(struct slm_thd *t)
{
	struct slm_sched_thd *p = slm_thd_sched_policy(t);

	assert(ps_list_singleton_d(p));

	ps_list_head_append_d(&threads[cos_cpuid()].prio[t->priority - 1], p);

	return 0;
}

void
slm_sched_fprr_yield(struct slm_thd *t, struct slm_thd *yield_to)
{
	struct slm_sched_thd *p = slm_thd_sched_policy(t);

	ps_list_rem_d(p);
	ps_list_head_append_d(&threads[cos_cpuid()].prio[t->priority], p);
}

int
slm_sched_fprr_thd_init(struct slm_thd *t)
{
	t->priority = SLM_FPRR_PRIO_LOWEST;
	ps_list_init_d(slm_thd_sched_policy(t));

	return 0;
}

void
slm_sched_fprr_thd_deinit(struct slm_thd *t)
{
	ps_list_rem_d(slm_thd_sched_policy(t));
}

static void
update_queue(struct slm_thd *t, tcap_prio_t prio)
{
	struct slm_sched_thd *p = slm_thd_sched_policy(t);

	t->priority = prio;
	ps_list_rem_d(p); /* if we're already on a list, and we're updating priority */
	ps_list_head_append_d(&threads[cos_cpuid()].prio[prio], p);

	return;
}

int
slm_sched_fprr_thd_update(struct slm_thd *t, sched_param_type_t type, unsigned int v)
{
	switch (type) {
	case SCHEDP_INIT_PROTO:
	{
		update_queue(t, 0);

		return 0;
	}
	case SCHEDP_INIT:
	{
		update_queue(t, SLM_FPRR_PRIO_LOWEST);

		return 0;
	}
	case SCHEDP_PRIO:
	{
		assert(v >= SLM_FPRR_PRIO_HIGHEST && v <= SLM_FPRR_PRIO_LOWEST);
		update_queue(t, v);

		return 0;
	}
	/* Only support priority, for now */
	default:
		return -1;
	}
}

void
slm_sched_fprr_init(void)
{
	int i;

	for (i = 0 ; i < SLM_FPRR_NPRIOS ; i++) {
		ps_list_head_init(&threads[cos_cpuid()].prio[i]);
	}
}
