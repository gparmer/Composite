#include <cos_types.h>
#include <memmgr.h>
#include <netshmem.h>
#include <shm_bm.h>
#include <string.h>
#include <sched.h>
#include <nic_netio_rx.h>
#include <nic_netio_tx.h>
#include <nic_netio_shmem.h>
#include <cos_dpdk.h>
#include <ck_ring.h>
#include <rte_atomic.h>
#include <rte_memcpy.h>
#include <sync_sem.h>
#include <sync_lock.h>
#include <arpa/inet.h>
#include "nicmgr.h"
#include "fast_memcpy.h"
#include "simple_hash.h"

extern volatile int debug_flag;

typedef unsigned long cos_paddr_t; /* physical address */
typedef unsigned long cos_vaddr_t; /* virtual address */

extern cos_paddr_t cos_map_virt_to_phys(cos_vaddr_t addr);
extern char *g_tx_mp[NIC_TX_QUEUE_NUM];

/* indexed by thread id */
struct client_session client_sessions[NIC_MAX_SESSION];

CK_RING_PROTOTYPE(pkt_ring_buf, pkt_buf);

struct pkt_ring_buf g_tx_ring;
struct pkt_ring_buf g_free_ring;

rte_atomic64_t tx_enqueued_miss = {0};

static char ring_buffers[NIC_MAX_SESSION][RX_PKT_RING_SZ];
static char ring_buffers_bifurcate[NIC_MAX_SESSION][RX_PKT_RING_SZ];

void
pkt_ring_buf_init_bifurcate(struct pkt_ring_buf *pkt_ring_buf, size_t ringbuf_num, size_t ringbuf_sz)
{
	struct ck_ring *buf_addr;

	/* prevent multiple thread from contending memory */
	assert(cos_thdid() < NIC_MAX_SESSION);
	buf_addr = (struct ck_ring *)&ring_buffers_bifurcate[cos_thdid()];

	ck_ring_init(buf_addr, ringbuf_num);

	pkt_ring_buf->ring    = buf_addr;
	pkt_ring_buf->ringbuf = (struct pkt_buf *)((char *)buf_addr + sizeof(struct ck_ring));
}

void
pkt_ring_buf_init(struct pkt_ring_buf *pkt_ring_buf, size_t ringbuf_num, size_t ringbuf_sz)
{
	struct ck_ring *buf_addr;

	/* prevent multiple thread from contending memory */
	assert(cos_thdid() < NIC_MAX_SESSION);
	buf_addr = (struct ck_ring *)&ring_buffers[cos_thdid()];

	ck_ring_init(buf_addr, ringbuf_num);

	pkt_ring_buf->ring    = buf_addr;
	pkt_ring_buf->ringbuf = (struct pkt_buf *)((char *)buf_addr + sizeof(struct ck_ring));
}

inline int
pkt_ring_buf_enqueue(struct pkt_ring_buf *pkt_ring_buf, struct pkt_buf *buf)
{
	assert(pkt_ring_buf->ring && pkt_ring_buf->ringbuf);

	return CK_RING_ENQUEUE_SPSC(pkt_ring_buf, pkt_ring_buf->ring, pkt_ring_buf->ringbuf, buf);
}

inline int
pkt_ring_buf_dequeue(struct pkt_ring_buf *pkt_ring_buf, struct pkt_buf *buf)
{
	assert(pkt_ring_buf->ring && pkt_ring_buf->ringbuf);

	return CK_RING_DEQUEUE_SPSC(pkt_ring_buf, pkt_ring_buf->ring, pkt_ring_buf->ringbuf, buf);
}

inline int
pkt_ring_buf_empty(struct pkt_ring_buf *pkt_ring_buf)
{
	assert(pkt_ring_buf->ring);

	return (!ck_ring_size(pkt_ring_buf->ring));
}

shm_bm_objid_t
nic_netio_rx_packet(u16_t *pkt_len)
{
	thdid_t                    thd;	
	struct pkt_buf             buf;
	shm_bm_objid_t             objid;
	struct client_session     *session;
	struct netshmem_pkt_buf   *obj;
	int len;

	thd = cos_thdid();
	assert(thd < NIC_MAX_SESSION);

	session = &client_sessions[thd];	

	session->blocked_loops_begin++;
	sync_sem_take(&session->sem);
	session->blocked_loops_end++;

	assert(!pkt_ring_buf_empty(&session->pkt_ring_buf));

	while (!pkt_ring_buf_dequeue(&session->pkt_ring_buf, &buf))
	assert(buf.pkt);

	char *pkt = cos_get_packet(buf.pkt, &len);
	assert(len < PKT_BUF_SIZE);

	obj = shm_bm_alloc_net_pkt_buf(session->shemem_info.shm, &objid);
	assert(obj);

	memcpy(obj->data, pkt, len);

#if USE_CK_RING_FREE_MBUF
	while (!pkt_ring_buf_enqueue(&g_free_ring, &buf));
#else
	cos_free_packet(buf.pkt);
#endif

	*pkt_len = len;

	return objid;
}

static shm_bm_objid_t
__batch_packets(shm_bm_t shm, struct pkt_ring_buf *pkt_ring_buf, u8_t batch_limit)
{
	struct netshmem_pkt_buf   *obj;
	struct pkt_buf             buf;
	shm_bm_objid_t             objid;
	shm_bm_objid_t             first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	char *data_buf;
	char *pkt;
	int len;
	u8_t batch_ct = 0;

	obj = first_obj = shm_bm_alloc_net_pkt_buf(shm, &objid);
	assert(obj);
	first_objid = objid;
	first_obj_pri = netshmem_get_pri(obj);
	pkt_arr = (struct netshmem_meta_tuple *)&first_obj_pri->pkt_arr;
	first_obj_pri->batch_len = 0;

	while (batch_ct < batch_limit && pkt_ring_buf_dequeue(pkt_ring_buf, &buf)) {
		assert(buf.pkt);
		if (likely(batch_ct > 0)) {
			obj = shm_bm_alloc_net_pkt_buf(shm, &objid);
			// sync_sem_take(&session->sem);
			assert(obj);
		}

		pkt = cos_get_packet(buf.pkt, &len);
		assert(len < netshmem_get_max_data_buf_sz());
		
		data_buf = netshmem_get_data_buf(obj);
		// memcpy_fast(data_buf, pkt, len);
		// memcpy(data_buf, pkt, len);
		rte_memcpy(data_buf, pkt , len);
		pkt_arr[batch_ct].obj_id = objid;
		pkt_arr[batch_ct].pkt_len = len;
		batch_ct++;

		cos_free_packet(buf.pkt);
	}
	first_obj_pri->batch_len = batch_ct;

	return first_objid;
}

shm_bm_objid_t
nic_netio_rx_packet_batch_ro(u8_t batch_limit)
{
	thdid_t                    thd;	
	struct pkt_buf             buf;
	shm_bm_objid_t             objid;
	struct client_session     *session;
	struct netshmem_pkt_buf   *obj;
	shm_bm_objid_t             first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	char *data_buf;
	char *pkt;
	int len;
	u8_t batch_ct = 0;

	thd = cos_thdid();

	session = &client_sessions[thd];
	shm_bm_t rx_shmemd = netshmem_get_shm();
	assert(rx_shmemd);

	first_objid = session->last_objid;
	if (likely(first_objid != 0xF0000000)) {
		first_obj = shm_bm_borrow_net_pkt_buf(rx_shmemd, first_objid);
		first_obj_pri = netshmem_get_pri(first_obj);
		pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
		batch_ct = first_obj_pri->batch_len;
		// printc("[nf]:ro batch read:%p, ct:%d\n", &session->pkt_ring_buf_bifurcate, batch_ct);

		for (int i = batch_ct - 1; i >= 0; i--) {
			objid = pkt_arr[i].obj_id;
			obj = shm_bm_borrow_net_pkt_buf(rx_shmemd, objid);
			shm_bm_free_net_pkt_buf(obj);
		}
	}

	while(pkt_ring_buf_empty(&session->pkt_ring_buf_bifurcate)) {
		sched_thd_yield();
	}
	shm_bm_objid_t ret = session->first_objid;
	session->last_objid = ret;
	pkt_ring_buf_dequeue(&client_sessions[thd].pkt_ring_buf_bifurcate, &buf);

	return ret;
}

shm_bm_objid_t
nic_netio_rx_packet_batch(u8_t batch_limit)
{
	thdid_t                    thd;	
	struct pkt_buf             buf;
	shm_bm_objid_t             objid;
	struct client_session     *session;
	struct netshmem_pkt_buf   *obj;
	shm_bm_objid_t             first_objid;
	struct netshmem_pkt_buf   *first_obj;
	struct netshmem_pkt_pri   *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	char *data_buf;
	char *pkt;
	int len;
	u8_t batch_ct = 0;

	thd = cos_thdid();

	session = &client_sessions[thd];	

	// sync_sem_take(&session->sem);

	// assert(!pkt_ring_buf_empty(&session->pkt_ring_buf));
	while (pkt_ring_buf_empty(&session->pkt_ring_buf) && pkt_ring_buf_empty(&session->pkt_ring_buf_bifurcate)) {
		sched_thd_yield();
	}

	if (pkt_ring_buf_dequeue(&session->pkt_ring_buf_bifurcate, &buf)) {
		assert(buf.pkt);
		thd = buf.bifurcate_thd;
		obj = first_obj = shm_bm_alloc_net_pkt_buf(client_sessions[thd].shemem_info.shm, &objid);
		assert(obj);

		first_objid = objid;
		first_obj_pri = netshmem_get_pri(obj);
		pkt_arr = (struct netshmem_meta_tuple *)&first_obj_pri->pkt_arr;

		data_buf = netshmem_get_data_buf(obj);
		pkt = cos_get_packet(buf.pkt, &len);
		assert(len < netshmem_get_max_data_buf_sz());
		rte_memcpy(data_buf, pkt , len);
		pkt_arr[batch_ct].obj_id = objid;
		pkt_arr[batch_ct].pkt_len = len;
		batch_ct++;

		cos_free_packet(buf.pkt);

		int bifurcate_flag = 0;
		if (pkt_ring_buf_empty(&client_sessions[thd].pkt_ring_buf_bifurcate)) {
			bifurcate_flag = 1;
		}

		if (bifurcate_flag) {
			// add ref count
			shm_bm_take_net_pkt_buf(client_sessions[thd].shemem_info.shm, objid);
		}

		while (batch_ct < batch_limit - 1 && pkt_ring_buf_dequeue(&session->pkt_ring_buf_bifurcate, &buf)) {
			assert(buf.pkt);
			if (likely(batch_ct > 0)) {
				obj = shm_bm_alloc_net_pkt_buf(client_sessions[thd].shemem_info.shm, &objid);
				// sync_sem_take(&session->sem);
				assert(obj);
			}

			pkt = cos_get_packet(buf.pkt, &len);
			assert(len < netshmem_get_max_data_buf_sz());
			
			data_buf = netshmem_get_data_buf(obj);
			// memcpy_fast(data_buf, pkt, len);
			// memcpy(data_buf, pkt, len);
			rte_memcpy(data_buf, pkt , len);
			pkt_arr[batch_ct].obj_id = objid;
			pkt_arr[batch_ct].pkt_len = len;
			batch_ct++;

			cos_free_packet(buf.pkt);
			if (bifurcate_flag) {
				// add ref count
				shm_bm_take_net_pkt_buf(client_sessions[thd].shemem_info.shm, objid);
			}
		}
		first_obj_pri->batch_len = batch_ct;

		struct bifurcate_shmem_header *hdr = session->bifurcate_rx.shm;
		hdr->len = 1;
		hdr->nf_arr[0].first_objid = first_objid;
		hdr->nf_arr[0].shm_id = client_sessions[thd].shemem_info.shmid;
		if (bifurcate_flag) {
			client_sessions[thd].first_objid = first_objid;
			pkt_ring_buf_enqueue(&client_sessions[thd].pkt_ring_buf_bifurcate, &buf);
		}
	}

	if (!pkt_ring_buf_empty(&session->pkt_ring_buf)) {
		return __batch_packets(session->shemem_info.shm, &session->pkt_ring_buf, batch_limit);
	} else {
		return 0xF0000000;
	}

;
}

static void
ext_buf_free_callback_fn(void *addr, void *opaque)
{
	/* Shared mem uses borrow api, thus do not need to free it here */
	if (addr != NULL) {
		shm_bm_free_net_pkt_buf(addr);
	} else {
		printc("External buffer address is invalid\n");
		assert(0);
	}
}

extern struct sync_lock tx_lock[NUM_CPU];

int
nic_netio_tx_packet(shm_bm_objid_t pktid, u16_t pkt_offset, u16_t pkt_len)
{
	thdid_t                  thd;
	shm_bm_objid_t           objid;
	struct pkt_buf           buf;
	struct netshmem_pkt_buf *obj;

	thd   = cos_thdid();
	objid = pktid;

	obj = (struct netshmem_pkt_buf *)shm_bm_transfer_net_pkt_buf(client_sessions[thd].shemem_info.shm, objid);

	buf.obj = (char *)obj;
	buf.pkt = pkt_offset + obj->data;

	u64_t data_paddr = client_sessions[thd].shemem_info.paddr 
		+ (u64_t)buf.obj - (u64_t)client_sessions[thd].shemem_info.shm;
	
	buf.paddr   = data_paddr;
	buf.pkt_len = pkt_len;
#if 0
	if (!pkt_ring_buf_enqueue(&client_sessions[thd].pkt_tx_ring, &buf)) {
		/* tx queue is full, drop the packet */
		rte_atomic64_add(&tx_enqueued_miss, 1);
		shm_bm_free_net_pkt_buf(obj);
	}
#else 
	char *mbuf;
	void *ext_shinfo;
	char *tx_packets[256];

	coreid_t core_id = cos_cpuid();
#if E810_NIC == 0
	core_id = 1;
#endif
	mbuf = cos_allocate_mbuf(g_tx_mp[core_id - 1]);
	assert(mbuf);
	ext_shinfo = netshmem_get_tailroom((struct netshmem_pkt_buf *)buf.obj);
	cos_attach_external_mbuf(mbuf, buf.obj, buf.paddr, PKT_BUF_SIZE, ext_buf_free_callback_fn, ext_shinfo);
	cos_set_external_packet(mbuf, (buf.pkt - buf.obj), buf.pkt_len, 1);
	tx_packets[0] = mbuf;

	sync_lock_take(&tx_lock[core_id - 1]);
	cos_dev_port_tx_burst(0, core_id - 1, tx_packets, 1);
	sync_lock_release(&tx_lock[core_id - 1]);
#endif

	return 0;
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

int
nic_netio_tx_packet_batch(shm_bm_objid_t pktid)
{
	thdid_t                  thd;
	shm_bm_objid_t           objid;
	struct pkt_buf           buf;
	struct netshmem_pkt_buf *obj;
	shm_bm_objid_t first_objid;
	struct netshmem_pkt_buf *first_obj;
	struct netshmem_pkt_pri *first_obj_pri;
	struct netshmem_meta_tuple *pkt_arr;
	u16_t pkt_len;
	u8_t batch_tc = 0;
	shm_bm_t shm;
	u64_t   paddr, data_paddr;

	thd   = cos_thdid();
	objid = pktid;

	paddr = client_sessions[thd].shemem_info.paddr;
	shm = client_sessions[thd].shemem_info.shm;

	obj = first_obj = shm_bm_transfer_net_pkt_buf(shm, objid);

	first_obj_pri = netshmem_get_pri(first_obj);
	pkt_arr = (struct netshmem_meta_tuple *)&(first_obj_pri->pkt_arr);
	batch_tc = first_obj_pri->batch_len;

	pkt_len = pkt_arr[0].pkt_len;

	data_paddr = paddr + (u64_t)obj - (u64_t)shm;
	
	char *mbuf;
	void *ext_shinfo;
	char *tx_packets[256];

	coreid_t core_id = cos_cpuid();
#if E810_NIC == 0
	core_id = 1;
#endif

	mbuf = cos_allocate_mbuf(g_tx_mp[core_id]);
	assert(mbuf);
	ext_shinfo = netshmem_get_tailroom((struct netshmem_pkt_buf *)obj);
	cos_attach_external_mbuf(mbuf, obj, data_paddr, PKT_BUF_SIZE, ext_buf_free_callback_fn, ext_shinfo);
	cos_set_external_packet(mbuf, netshmem_get_data_offset(), pkt_len, 1);
	tx_packets[0] = mbuf;
	// pkt_hex_dump(netshmem_get_data_buf(obj), pkt_len);

	for (u8_t i = 1; i < batch_tc; i++) {
		pkt_len = pkt_arr[i].pkt_len;
		pktid = pkt_arr[i].obj_id;
		obj = shm_bm_transfer_net_pkt_buf(shm, pktid);
		data_paddr = paddr + (u64_t)obj - (u64_t)shm;

		mbuf = cos_allocate_mbuf(g_tx_mp[core_id]);
		assert(mbuf);
		ext_shinfo = netshmem_get_tailroom((struct netshmem_pkt_buf *)obj);
		cos_attach_external_mbuf(mbuf, obj, data_paddr, PKT_BUF_SIZE, ext_buf_free_callback_fn, ext_shinfo);
		cos_set_external_packet(mbuf, netshmem_get_data_offset(), pkt_len, 0);
		tx_packets[i] = mbuf;
	}

	sync_lock_take(&tx_lock[core_id]);
	cos_dev_port_tx_burst(0, core_id, tx_packets, batch_tc);
	sync_lock_release(&tx_lock[core_id]);

	return 0;
}

void
nic_netio_shmem_map(cbuf_t shm_id)
{
	netshmem_map_shmem(shm_id);
}

int
nic_netio_shmem_bind_port(u32_t ip_addr, u16_t port)
{
	unsigned long npages;
	void         *mem;

	shm_bm_t    shm;
	cbuf_t      shmid;
	cos_paddr_t paddr = 0;
	thdid_t     thd;

	thd = cos_thdid();
	assert(thd < NIC_MAX_SESSION);

	client_sessions[thd].ip_addr = ip_addr;
	client_sessions[thd].port    = port;
	client_sessions[thd].thd     = thd;

	shm   = netshmem_get_shm();
	assert(shm);
	shmid = netshmem_get_shm_id();
	paddr = cos_map_virt_to_phys((cos_vaddr_t)shm);
	assert(paddr);

	client_sessions[thd].shemem_info.shmid = shmid;
	client_sessions[thd].shemem_info.shm   = shm;
	client_sessions[thd].shemem_info.paddr = paddr;
	client_sessions[thd].first_objid = 0xF0000000;
	client_sessions[thd].last_objid = 0xF0000000;
	simple_hash_add(client_sessions[thd].ip_addr, client_sessions[thd].port, &client_sessions[thd]);

	sync_sem_init(&client_sessions[thd].sem, 0);

	pkt_ring_buf_init(&client_sessions[thd].pkt_ring_buf, RX_PKT_RBUF_NUM, RX_PKT_RING_SZ);
	pkt_ring_buf_init_bifurcate(&client_sessions[thd].pkt_ring_buf_bifurcate, RX_PKT_RBUF_NUM, RX_PKT_RING_SZ);

	client_sessions[thd].blocked_loops_begin = 0;
	client_sessions[thd].blocked_loops_end = 0;
	client_sessions[thd].tx_init_done = 1;

	return 0;
}

int
nic_netio_shmem_bind_port_right(u32_t ip_addr, u16_t port, u8_t right)
{
	unsigned long npages;
	void         *mem;

	shm_bm_t    shm;
	cbuf_t      shmid;
	cos_paddr_t paddr = 0;
	thdid_t     thd;

	thd = cos_thdid();
	assert(thd < NIC_MAX_SESSION);

	client_sessions[thd].ip_addr = ip_addr;
	client_sessions[thd].port    = port;
	client_sessions[thd].thd     = thd;

	shm   = netshmem_get_shm();
	assert(shm);
	shmid = netshmem_get_shm_id();
	paddr = cos_map_virt_to_phys((cos_vaddr_t)shm);
	assert(paddr);

	client_sessions[thd].shemem_info.shmid = shmid;
	client_sessions[thd].shemem_info.shm   = shm;
	client_sessions[thd].shemem_info.paddr = paddr;
	client_sessions[thd].right = right;
	client_sessions[thd].first_objid = 0xF0000000;
	client_sessions[thd].last_objid = 0xF0000000;
	simple_hash_add(client_sessions[thd].ip_addr, client_sessions[thd].port, &client_sessions[thd]);

	sync_sem_init(&client_sessions[thd].sem, 0);

	pkt_ring_buf_init(&client_sessions[thd].pkt_ring_buf, RX_PKT_RBUF_NUM, RX_PKT_RING_SZ);
	pkt_ring_buf_init_bifurcate(&client_sessions[thd].pkt_ring_buf_bifurcate, 2, sizeof(struct ck_ring) + 2 * sizeof(struct pkt_buf));

	client_sessions[thd].blocked_loops_begin = 0;
	client_sessions[thd].blocked_loops_end = 0;
	client_sessions[thd].tx_init_done = 1;

	return 0;
}

void
nic_netio_shmem_map_bifurcate(u8_t dir, cbuf_t shm_id)
{
	thdid_t     thd;
	void        *mem;
	thd = cos_thdid();

	memmgr_shared_page_map_aligned(shm_id, PAGE_SIZE, (vaddr_t *)&mem);

	client_sessions[thd].bifurcate_rx.shm_id = shm_id;
	client_sessions[thd].bifurcate_rx.shm = mem;
}

u64_t
nic_netio_shmem_get_port_mac_address(u16_t port)
{
	return cos_get_port_mac_address(port);
}
