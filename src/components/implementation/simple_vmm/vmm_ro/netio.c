#include <vmm_netio_rx.h>
#include <vmm_netio_tx.h>
#include <vmm_netio_shmem.h>
#include <string.h>
#include <netshmem.h>
#include <nic_netio_rx.h>
#include <nic_netio_tx.h>
#include <nic_netio_shmem.h>
#include <sched.h>
#include <devices/vpci/virtio_net_io.h>
#include <nf_session.h>
#include <sync_sem.h>

shm_bm_objid_t
vmm_netio_rx_packet(u16_t *pkt_len)
{
	struct netshmem_pkt_buf *tx_obj;
	shm_bm_t tx_shmemd = 0;
	shm_bm_objid_t tx_pktid;
	u16_t _pkt_len = 0;
	
	tx_shmemd = netshmem_get_shm();
	tx_obj = shm_bm_alloc_net_pkt_buf(tx_shmemd, &tx_pktid);
	assert(tx_obj);

	virtio_net_send_one_pkt(tx_obj->data, &_pkt_len);
	*pkt_len = _pkt_len;

	return tx_pktid;
}

void pkt_hex_dump(void *_data, u16_t len)
{
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    u8_t *data, ch; 

    data = _data;

    printc("Packet hex dump, len:%d\n", len);
    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printc("%06d\t", li);

        linelen = remaining < rowsize ? remaining : rowsize;
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printc( "%02X ", (u32_t) ch);
        }

        data += linelen;
        li += 10; 

        printc( "dump done\n");
    }
}

#if 0
shm_bm_objid_t
vmm_netio_rx_packet_batch(u8_t batch_limit)
{
	struct netshmem_pkt_buf *tx_obj;
	shm_bm_t tx_shmemd = 0;
	shm_bm_objid_t tx_pktid;
	u16_t _pkt_len = 0;
	shm_bm_objid_t             first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u8_t batch_ct = 0;
	
	tx_shmemd = netshmem_get_shm();
	tx_obj = first_obj = shm_bm_alloc_net_pkt_buf(tx_shmemd, &tx_pktid);
	assert(tx_obj);
	first_objid = tx_pktid;
	first_obj_pri = netshmem_get_pri(tx_obj);
	pkt_arr = (struct netshmem_meta_tuple *)&first_obj_pri->pkt_arr;
	first_obj_pri->batch_len = 0;

	while (batch_ct < batch_limit) {
		assert(tx_obj);
		if (likely(batch_ct > 0)) {
			tx_obj = shm_bm_alloc_net_pkt_buf(tx_shmemd, &tx_pktid);
			assert(tx_obj);
		}

		virtio_net_send_one_pkt(netshmem_get_data_buf(tx_obj), &_pkt_len);

		// pkt_hex_dump(netshmem_get_data_buf(tx_obj), _pkt_len);
		if (likely(_pkt_len != 0)) {
			pkt_arr[batch_ct].obj_id = tx_pktid;
			pkt_arr[batch_ct].pkt_len = _pkt_len;
			batch_ct++;
		} else {
			if (batch_ct == 0) {
				sched_thd_yield();
			} else {
				shm_bm_free_net_pkt_buf(tx_obj);
				break;
			}
		}
	}
	first_obj_pri->batch_len = batch_ct;
	return first_objid;
}
#endif

struct nf_svc {
	int svc_id;
	struct vmrt_vm_comp  *vm;
};

#define MAX_NFS 200
#define MAX_THD_PER_NF 1000

static struct nf_svc nf_svc_tbl[MAX_NFS][MAX_THD_PER_NF];

void
nf_svc_update(compid_t nf_id, int thd, int svc_id, struct vmrt_vm_comp *vm)
{
	// printc("svc update:%d, %d, %d\n", nf_id, thd, nf_svc_tbl[nf_id][thd].svc_id);
	if (nf_svc_tbl[nf_id][thd].svc_id < 0) {
		nf_svc_tbl[nf_id][thd].svc_id = svc_id;
		nf_svc_tbl[nf_id][thd].vm = vm;
	} else {
		return;
	}
}

void
nf_svc_init(void)
{
	for (int i = 0; i < MAX_NFS; i++) {
		for (int j = 0; j < MAX_THD_PER_NF; j++) {
			nf_svc_tbl[i][j].svc_id = -1;
			nf_svc_tbl[i][j].vm = NULL;
		}
	}
}

shm_bm_objid_t
vmm_netio_rx_packet_batch(u8_t batch_limit)
{
	shm_bm_objid_t             first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_pkt_buf *tx_obj;
	shm_bm_objid_t tx_pktid;
	struct netshmem_meta_tuple *pkt_arr;

	struct nf_session *session;
	struct nf_pkt_meta_data buf;
	u8_t batch_ct = 0;
	compid_t vmm_id = cos_compid();
	compid_t nf_id = (compid_t)cos_inv_token();
	if (nf_id == 0) nf_id = vmm_id;
	thdid_t nf_thd = cos_thdid();

	int svc_id = nf_svc_tbl[nf_id][nf_thd].svc_id;

	if (svc_id < 0) {
		printc("no svc available for this nf:%d, thd:%d\n", nf_id, nf_thd);
		assert(0);
	}

	session = get_nf_session(svc_id);

	while (nf_tx_ring_buf_empty(&session->nf_tx_ring_buf)) {
		sched_thd_yield();
	}

	assert(nf_tx_ring_buf_dequeue(&session->nf_tx_ring_buf, &buf));
	tx_obj = first_obj = buf.obj;
	assert(tx_obj);
	tx_pktid = first_objid = buf.objid;
	first_obj_pri = netshmem_get_pri(tx_obj);
	pkt_arr = (struct netshmem_meta_tuple *)&first_obj_pri->pkt_arr;
	first_obj_pri->batch_len = 0;

	pkt_arr[batch_ct].obj_id = tx_pktid;
	pkt_arr[batch_ct].pkt_len = buf.pkt_len;
	batch_ct++;

	while (batch_ct < batch_limit && nf_tx_ring_buf_dequeue(&session->nf_tx_ring_buf, &buf)) {
		// printc("netio out a pkt, batch_ct:%d\n", batch_ct);
		pkt_arr[batch_ct].obj_id = buf.objid;
		pkt_arr[batch_ct].pkt_len = buf.pkt_len;
		batch_ct++;
	}

	first_obj_pri->batch_len = batch_ct;
	return first_objid;
}

int
vmm_netio_tx_packet(shm_bm_objid_t pktid, u16_t pkt_len)
{
	struct netshmem_pkt_buf *rx_obj;
	shm_bm_t rx_shmemd = 0;

	rx_shmemd = netshmem_get_shm();

	rx_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, pktid);
	virtio_net_rcv_one_pkt(rx_obj->data, pkt_len);
	shm_bm_free_net_pkt_buf(rx_obj);

	return 0;
}


int
vmm_netio_tx_packet_batch(shm_bm_objid_t pktid)
{
	struct netshmem_pkt_buf *rx_obj;
	shm_bm_objid_t first_objid;
	struct netshmem_pkt_buf *first_obj;
	struct netshmem_pkt_pri *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u16_t pkt_len;
	u8_t batch_tc = 0;
	shm_bm_t rx_shmemd = 0;

	rx_shmemd = netshmem_get_shm();
	first_objid = pktid;


	first_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, first_objid);

	first_obj_pri = netshmem_get_pri(first_obj);
	pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
	batch_tc = first_obj_pri->batch_len;

	pkt_len = pkt_arr[0].pkt_len;
	// pkt_hex_dump(netshmem_get_data_buf(first_obj), pkt_len);
	virtio_net_rcv_one_pkt(netshmem_get_data_buf(first_obj), pkt_len);

	for (u8_t i = 1; i < batch_tc; i++) {
		pkt_len = pkt_arr[i].pkt_len;
		pktid = pkt_arr[i].obj_id;
		rx_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, pktid);
		virtio_net_rcv_one_pkt(netshmem_get_data_buf(rx_obj), pkt_len);
		shm_bm_free_net_pkt_buf(rx_obj);
	}

	shm_bm_free_net_pkt_buf(first_obj);

	return 0;
}

int
vmm_netio_tx_packet_batch_bifurcate(shm_bm_t rx_shmemd, shm_bm_objid_t pktid)
{
	struct netshmem_pkt_buf *rx_obj;
	shm_bm_objid_t first_objid;
	struct netshmem_pkt_buf *first_obj;
	struct netshmem_pkt_pri *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u16_t pkt_len;
	u8_t batch_tc = 0;

	first_objid = pktid;

	first_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, first_objid);

	first_obj_pri = netshmem_get_pri(first_obj);
	pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
	batch_tc = first_obj_pri->batch_len;

	pkt_len = pkt_arr[0].pkt_len;
	// pkt_hex_dump(netshmem_get_data_buf(first_obj), pkt_len);
	virtio_net_rcv_one_pkt(netshmem_get_data_buf(first_obj), pkt_len);

	for (u8_t i = 1; i < batch_tc; i++) {
		pkt_len = pkt_arr[i].pkt_len;
		pktid = pkt_arr[i].obj_id;
		rx_obj = shm_bm_transfer_net_pkt_buf(rx_shmemd, pktid);
		virtio_net_rcv_one_pkt(netshmem_get_data_buf(rx_obj), pkt_len);
		shm_bm_free_net_pkt_buf(rx_obj);
	}

	shm_bm_free_net_pkt_buf(first_obj);

	return 0;
}

extern shm_bm_t bifurcate_hash_tbl[2000];
extern struct netshmem netshmems[NETSHMEM_REGION_SZ];
void
vmm_netio_shmem_map(cbuf_t shm_id)
{
	netshmem_map_shmem(shm_id);
	thdid_t thd = cos_thdid();

	bifurcate_hash_tbl[shm_id] = netshmems[thd].shm;
}

extern struct vmrt_vm_comp *vm_list[2];

void
vmm_netio_shmem_svc_update(int svc_id, u32_t vm)
{
	compid_t nf_id = cos_inv_token();
	thdid_t thd = cos_thdid(); 
	assert(vm < 2);
	shm_bm_t tx_shm = netshmem_get_shm();
	assert(tx_shm);
	
	nf_svc_update(nf_id, thd, svc_id, vm_list[vm]);

	struct nf_session *session;
	session = get_nf_session(svc_id);
	nf_session_tx_update(session, tx_shm, thd);
	sync_sem_init(&session->tx_sem, 0);

	nf_tx_ring_buf_init(&session->nf_tx_ring_buf, NF_TX_PKT_RBUF_NUM, NF_TX_PKT_RING_SZ);
}
