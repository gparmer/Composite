#ifndef FPRR_H
#define FPRR_H

#include <ps_list.h>

struct slm_sched_thd {
	struct ps_list list;
};

#include <slm.h>

SLM_MODULES_POLICY_PROTOTYPES(fprr)

#endif	/* FPRR_H */
