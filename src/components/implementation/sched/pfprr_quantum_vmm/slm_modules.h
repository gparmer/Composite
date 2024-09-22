#ifndef SLM_MODULES_H
#define SLM_MODULES_H

#include <slm.h>

struct slm_thd_container;

/* Thread memory allocation functions */
struct slm_thd_container *slm_thd_mem_alloc(thdcap_t _cap, thdid_t _tid, thdcap_t *thd, thdid_t *tid);
void slm_thd_mem_activate(struct slm_thd_container *t);
void slm_thd_mem_free(struct slm_thd_container *t);

/* Thread allocation functions */
struct slm_thd_container *slm_thd_alloc(thd_fn_t fn, void *data, thdcap_t *thd, thdid_t *tid);
struct slm_thd_container *slm_thd_alloc_in(compid_t cid, thdclosure_index_t idx, thdcap_t *thd, thdid_t *tid);
struct slm_thd *thd_alloc(thd_fn_t fn, void *data, sched_param_t *parameters, int reschedule);
struct slm_thd *thd_alloc_in(compid_t id, thdclosure_index_t idx, sched_param_t *parameters, int reschedule);


#endif	/* SLM_MODULES_H */
