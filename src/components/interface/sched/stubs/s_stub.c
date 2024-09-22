#include <cos_stubs.h>
#include <sched.h>

COS_SERVER_3RET_STUB(int, sched_thd_block_timeout)
{
	cycles_t elapsed = 0, abs_timeout;

	/* works on armv7a too, as we control where hi and lo are passed for timeout */
	COS_ARG_WORDS_TO_DWORD(p1, p2, abs_timeout);
	elapsed = sched_thd_block_timeout((thdid_t)p0, abs_timeout);
	*r1 = (elapsed >> 32);
	*r2 = (elapsed << 32) >> 32;

	return 0;
}

COS_SERVER_3RET_STUB(thdid_t, sched_aep_create_closure)
{
	struct cos_defcompinfo *dci;
	int                 owntc  = (p0 << 16) >> 16;
	thdclosure_index_t  idx    = (p0 >> 16);
	microsec_t          ipiwin = (microsec_t)p2;
	u32_t               ipimax = (p1 << 16) >> 16;
	cos_channelkey_t    key    = (p1 >> 16);
	arcvcap_t rcv;
	thdid_t ret;

	ret = sched_aep_create_closure(idx, owntc, key, ipiwin, ipimax, &rcv);

	*r1 = rcv;
	*r2 = 0;

	return ret;
}

CWEAKSYMB thdid_t sched_thd_create_closure_nf_rx(thdclosure_index_t idx) { return 0; }