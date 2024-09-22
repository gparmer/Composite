#include <slm.h>
#include <slm_modules.h>
#include <capmgr.h>

struct slm_thd_container *
slm_thd_alloc(thd_fn_t fn, void *data, thdcap_t *thd, thdid_t *tid)
{
	thdid_t _tid;
	thdcap_t _cap;
	struct slm_thd_container *ret = NULL;

	_cap = capmgr_thd_create(fn, data, &_tid);
	if (_cap <= 0) return NULL;

	return slm_thd_mem_alloc(_cap, _tid, thd, tid);
}

struct slm_thd_container *
slm_thd_alloc_in(compid_t cid, thdclosure_index_t idx, thdcap_t *thd, thdid_t *tid)
{
	struct slm_thd_container *ret = NULL;
	thdid_t _tid;
	thdcap_t _cap;

	_cap = capmgr_thd_create_ext(cid, idx, &_tid);
	if (_cap <= 0) return NULL;

	return slm_thd_mem_alloc(_cap, _tid, thd, tid);
}

extern struct slm_thd *slm_thd_current_extern(void);
extern struct slm_thd *slm_thd_from_container(struct slm_thd_container *c);

struct slm_thd *
thd_alloc(thd_fn_t fn, void *data, sched_param_t *parameters, int reschedule)
{
	struct slm_thd_container *t;
	struct slm_thd *thd;
	struct slm_thd *ret     = NULL;
	struct slm_thd *current = slm_thd_current_extern();
	thdcap_t thdcap;
	thdid_t tid;
	int i;

	/*
	 * If this condition is true, we are likely in the
	 * initialization sequence in the idle or scheduler threads...
	 */
	if (!current) {
		current = slm_thd_special();
		assert(current);
	}

	t = slm_thd_alloc(fn, data, &thdcap, &tid);
	if (!t) ERR_THROW(NULL, done);
	thd = slm_thd_from_container(t);

	slm_cs_enter(current, SLM_CS_NONE);
	if (slm_thd_init(thd, thdcap, tid)) ERR_THROW(NULL, free);

	for (i = 0; parameters[i] != 0; i++) {
		sched_param_type_t type;
		unsigned int value;

		sched_param_get(parameters[i], &type, &value);
		if (slm_sched_thd_update(thd, type, value)) ERR_THROW(NULL, free);
	}
	slm_thd_mem_activate(t);

	if (reschedule) {
		if (slm_cs_exit_reschedule(current, SLM_CS_NONE)) ERR_THROW(NULL, free);
	} else {
		slm_cs_exit(NULL, SLM_CS_NONE);
	}

	ret = thd;
done:
	return ret;
free:
	slm_thd_mem_free(t);
	ret = NULL;
	goto done;
}

struct slm_thd *
thd_alloc_in(compid_t id, thdclosure_index_t idx, sched_param_t *parameters, int reschedule)
{
	struct slm_thd_container *t;
	struct slm_thd *ret     = NULL, *thd;
	struct slm_thd *current = slm_thd_current_extern();
	thdcap_t thdcap;
	thdid_t tid;
	int i;

	/*
	 * If this condition is true, we are likely in the
	 * initialization sequence in the idle or scheduler threads...
	 */
	if (!current) {
		current = slm_thd_special();
		assert(current);
	}

	t = slm_thd_alloc_in(id, idx, &thdcap, &tid);
	if (!t) ERR_THROW(NULL, done);
	thd = slm_thd_from_container(t);

	slm_cs_enter(current, SLM_CS_NONE);
	if (slm_thd_init(thd, thdcap, tid)) ERR_THROW(NULL, free);

	for (i = 0; parameters[i] != 0; i++) {
		sched_param_type_t type;
		unsigned int value;

		sched_param_get(parameters[i], &type, &value);
		if (slm_sched_thd_update(thd, type, value)) ERR_THROW(NULL, free);
	}
	slm_thd_mem_activate(t);

	if (reschedule) {
		if (slm_cs_exit_reschedule(current, SLM_CS_NONE)) ERR_THROW(NULL, done);
	} else {
		slm_cs_exit(NULL, SLM_CS_NONE);
	}

	ret = thd;
done:
	return ret;
free:
	slm_thd_mem_free(t);
	ret = NULL;
	goto done;
}
