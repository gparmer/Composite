#ifndef VMM_NETIO_TX_H
#define VMM_NETIO_TX_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>
#include <shm_bm.h>

int vmm_netio_tx_packet(shm_bm_objid_t pktid, u16_t pkt_len);
int vmm_netio_tx_packet_batch(shm_bm_objid_t pktid);
#endif
