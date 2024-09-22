#ifndef NICMGR_H
#define NICMGR_H

#include <cos_types.h>
#include <cos_component.h>
#include <shm_bm.h>
#include <ck_ring.h>
#include <sync_sem.h>

#define NIC_MAX_SESSION 2000
#define NIC_MAX_SHEMEM_REGION 3

#define NIC_SHMEM_RX 0
#define NIC_SHMEM_TX 1

/* Client can use this port to send debug commands */
#define NIC_DEBUG_PORT 36000

struct shemem_info {
	cbuf_t   shmid;
	shm_bm_t shm;
	paddr_t  paddr;
};

struct pkt_buf {
	char   *obj;
	char   *pkt;
	u64_t   paddr;
	int     pkt_len;
};

struct pkt_ring_buf {
	struct ck_ring *ring;
	struct pkt_buf *ringbuf;
};

/* per thread session */
struct client_session {
	struct shemem_info shemem_info;

	thdid_t thd;

	u32_t ip_addr; 
	u16_t port;
	int thd_state;

	struct pkt_ring_buf pkt_ring_buf;
	struct pkt_ring_buf pkt_tx_ring;

	int tx_init_done;
	struct sync_sem sem;

	/* number of blocked loops of the tenant, this is counted each time when the thread is blocked */
	int blocked_loops_begin;
	/* number of bloocked loops exit of the tenant, this is counted each time when the thread exits its blocked state */
	int blocked_loops_end;
};

extern struct pkt_ring_buf g_tx_ring;
extern struct pkt_ring_buf g_free_ring;

extern struct client_session client_sessions[NIC_MAX_SESSION];

#define RX_PKT_RBUF_NUM 4096
#define RX_PKT_RBUF_SZ (RX_PKT_RBUF_NUM * sizeof(struct pkt_buf))
#define RX_PKT_RING_SZ   (sizeof(struct ck_ring) + RX_PKT_RBUF_SZ)
#define RX_PKT_RING_PAGES (round_up_to_page(RX_PKT_RING_SZ)/PAGE_SIZE)

#define TX_PKT_RBUF_NUM 4096
#define TX_PKT_RBUF_SZ (TX_PKT_RBUF_NUM * sizeof(struct pkt_buf))
#define TX_PKT_RING_SZ   (sizeof(struct ck_ring) + TX_PKT_RBUF_SZ)
#define TX_PKT_RING_PAGES (round_up_to_page(TX_PKT_RING_SZ)/PAGE_SIZE)

#define FREE_PKT_RBUF_NUM 4096
#define FREE_PKT_RBUF_SZ (FREE_PKT_RBUF_NUM * sizeof(struct pkt_buf))
#define FREE_PKT_RING_SZ   (sizeof(struct ck_ring) + FREE_PKT_RBUF_SZ)
#define FREE_PKT_RING_PAGES (round_up_to_page(FREE_PKT_RING_SZ)/PAGE_SIZE)

void pkt_ring_buf_init(struct pkt_ring_buf *pkt_ring_buf, size_t ringbuf_num, size_t ringbuf_sz);

int pkt_ring_buf_enqueue(struct pkt_ring_buf *pkt_ring_buf, struct pkt_buf *buf);
int pkt_ring_buf_dequeue(struct pkt_ring_buf *pkt_ring_buf, struct pkt_buf *buf);
int pkt_ring_buf_empty(struct pkt_ring_buf *pkt_ring_buf);

void cos_hash_add(uint16_t tenant_id, struct client_session *session);
struct client_session *cos_hash_lookup(uint16_t tenant_id);

#define USE_CK_RING_FREE_MBUF 0
#endif /* NICMGR_H */
