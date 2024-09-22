#include <cos_stubs.h>
#include <netio.h>

COS_SERVER_3RET_STUB(shm_bm_objid_t, netio_get_a_packet)
{
	return netio_get_a_packet((u16_t *)r1);
}
