#ifndef VMM_NETIO_RX_H
#define VMM_NETIO_RX_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>
#include <shm_bm.h>

shm_bm_objid_t vmm_netio_rx_packet(u16_t *pkt_len);
shm_bm_objid_t vmm_netio_rx_packet_batch(u8_t batch_limit);

#endif
