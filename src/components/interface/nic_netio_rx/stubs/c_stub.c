#include <cos_component.h>
#include <cos_stubs.h>
#include <nic_netio_rx.h>


COS_CLIENT_STUB(shm_bm_objid_t, nic_netio_rx_packet, u16_t *pkt_len)
{
	COS_CLIENT_INVCAP;
	word_t r1, r2;
	int ret;

	ret = cos_sinv_2rets(uc, 0, 0, 0, 0, &r1, &r2);
	*pkt_len = (u16_t)r1;

	return ret;
}
