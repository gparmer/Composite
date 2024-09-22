#ifndef NIC_H
#define NIC_H

#include <cos_types.h>
#include <cos_component.h>
#include <cos_stubs.h>
#include <shm_bm.h>

void nic_shmem_map(cbuf_t shm_id);

int nic_send_packet(shm_bm_objid_t pktid, u16_t pkt_offset, u16_t pkt_len);
int nic_send_packet_batch(shm_bm_objid_t pktid);
int nic_bind_port(u32_t ip_addr, u16_t port);
u64_t nic_get_port_mac_address(u16_t port);

/*
 * caller will be suspended until there is a packet for this thread,
 * dpdk will then copy the packet to this shmem region specified by the shmid
 * and return its shmem objectid.
 */
shm_bm_objid_t nic_get_a_packet(u16_t *pkt_len);
shm_bm_objid_t nic_get_a_packet_batch(u8_t batch_limit);
#endif /* NIC_H */
