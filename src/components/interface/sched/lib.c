#include <sched.h>
#include <cos_thd_init.h>

thdid_t
sched_thd_create(cos_thd_fn_t fn, void *data)
{
	thdclosure_index_t idx = cos_thd_init_alloc(fn, data);

	if (idx < 1) return 0;

	return sched_thd_create_closure(idx);
}

thdid_t
sched_thd_create_nf_rx(cos_thd_fn_t fn, void *data)
{
	thdclosure_index_t idx = cos_thd_init_alloc(fn, data);

	if (idx < 1) return 0;

	return sched_thd_create_closure_nf_rx(idx);
}

thdid_t
sched_aep_create(struct cos_aep_info *aep, cos_aepthd_fn_t fn, void *data, int owntc, cos_channelkey_t key, microsec_t ipiwin, u32_t ipimax)
{
	thdclosure_index_t idx = cos_thd_init_alloc(fn, data);
	thdid_t ret;
	arcvcap_t rcv;

	if (idx < 1) return 0;

	memset(aep, 0, sizeof(struct cos_aep_info));
	ret = sched_aep_create_closure(idx, owntc, key, ipiwin, ipimax, &rcv);
	if (ret == 0) return 0;

	*aep = (struct cos_aep_info) {
		.fn   = fn,
		.data = data,
		.rcv  = rcv,
		.tid  = ret,
	};

	return ret;
}
