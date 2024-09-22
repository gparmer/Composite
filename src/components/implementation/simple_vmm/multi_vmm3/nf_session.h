#include <ck_ring.h>
#include <netshmem.h>
#include <vmrt.h>
#include <sync_sem.h>

struct nf_pkt_meta_data {
	void          *obj;
	shm_bm_objid_t objid;
	u16_t          pkt_len;
};

struct nf_tx_ring_buf {
	struct ck_ring *ring;
	struct nf_pkt_meta_data *ringbuf;
};

struct nf_session {
	shm_bm_t rx_shmemd;
	shm_bm_t tx_shmemd;

	thdid_t rx_thd;
	thdid_t tx_thd;

	struct sync_sem tx_sem;

	struct nf_tx_ring_buf nf_tx_ring_buf;
};

#define NF_TX_PKT_RBUF_NUM 512
#define NF_TX_PKT_RBUF_SZ (NF_TX_PKT_RBUF_NUM * sizeof(struct nf_tx_ring_buf))
#define NF_TX_PKT_RING_SZ   (sizeof(struct ck_ring) + NF_TX_PKT_RBUF_SZ)
#define NF_TX_PKT_RING_PAGES (round_up_to_page(NF_TX_PKT_RING_SZ)/PAGE_SIZE)

#define NF_TX_MAX_RING_NUM 1000

#define MAX_NF_SESSION 10

#define MAX_SVC_NUM (20000)

struct nf_session *get_nf_session(int svc_id);
void nf_session_tx_update(struct nf_session *session, shm_bm_t tx_shmemd, thdid_t tx_thd);
void nf_tx_ring_buf_init(struct nf_tx_ring_buf *pkt_ring_buf, size_t ringbuf_num, size_t ringbuf_sz);
int nf_tx_ring_buf_enqueue(struct nf_tx_ring_buf *pkt_ring_buf, struct nf_pkt_meta_data *buf);
int nf_tx_ring_buf_dequeue(struct nf_tx_ring_buf *pkt_ring_buf, struct nf_pkt_meta_data *buf);
int nf_tx_ring_buf_empty(struct nf_tx_ring_buf *pkt_ring_buf);

void nf_svc_update(compid_t nf_id, int thd_id, int svc_id, struct vmrt_vm_comp *vm);
void nf_svc_init(void);
void nf_sessions_init(void);
