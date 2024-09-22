#include <cos_stubs.h>
#include <vmm_netio_rx.h>

COS_SERVER_3RET_STUB(shm_bm_objid_t, vmm_netio_rx_packet)
{
	return vmm_netio_rx_packet((u16_t *)r1);
}
