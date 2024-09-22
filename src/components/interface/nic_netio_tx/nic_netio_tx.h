#ifndef NIC_NETIO_TX_H
#define NIC_NETIO_TX_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>
#include <shm_bm.h>

int nic_netio_tx_packet(shm_bm_objid_t pktid, u16_t pkt_offset, u16_t pkt_len);
int nic_netio_tx_packet_batch(shm_bm_objid_t pktid);
#endif
