#ifndef NETSHMEM_H
#define NETSHMEM_H

#include <cos_component.h>
#include <shm_bm.h>

#define PKT_BUF_NUM 1024
#define PKT_BUF_SIZE 2048

struct netshmem {
	size_t shmsz;
	shm_bm_t shm;
	cbuf_t shm_id;
};

/*
 * Assumption 1: a thread will only bind to a single shmem region.
 * Thus, within a component's code, it can use thread id to find 
 * which shared memory region it should use.
 * Assumption 2: thread will not be destroyed and then its id is 
 * assigned to another new thread.
 */
#define NETSHMEM_REGION_SZ 1024

/*
 * This is the offset size of netshmem_pkt_buf.data for application to write data.
 * HEADROOM is used for lwip to set ether & ip & tcp/udp headers
 */
#define NETSHMEM_HEADROOM 256

/* This tailroom is the last few bytes in the shmem, used to store user specific data */
#define NETSHMEM_TAILROOM 64
#define NETSHMEM_MAX_BATCH_LEN 60

struct netshmem_meta_tuple
{
	u16_t pkt_len;
	u16_t obj_id;
};


struct netshmem_pkt_pri {
	u16_t batch_len;
	struct netshmem_meta_tuple pkt_arr[NETSHMEM_MAX_BATCH_LEN];
};

struct netshmem_pkt_buf {
	char data[PKT_BUF_SIZE];
};

/*
 * One component can have PKT_BUF_NUM pkt buffers.
 * This Macro doesn't actually create the buffers, 
 * it just declares some helper functions for the buffer.
 * It is the components' duty to actually create the buffers/shmem.
 */
SHM_BM_INTERFACE_CREATE(net_pkt_buf, sizeof (struct netshmem_pkt_buf), PKT_BUF_NUM);

/* This will create a shmem for the current component*/
void netshmem_create(thdid_t tid);

cbuf_t netshmem_get_shm_id();
shm_bm_t netshmem_get_shm();
void netshemem_move(thdid_t old, thdid_t new);

/* map a shmem for a client component */
void netshmem_map_shmem(cbuf_t shm_id);

static inline struct netshmem_pkt_pri *netshmem_get_pri(struct netshmem_pkt_buf *pkt_buf)
{
	return (struct netshmem_pkt_pri *)pkt_buf;
}

static inline void * netshmem_get_data_buf(struct netshmem_pkt_buf *pkt_buf)
{
	return (char *)pkt_buf + NETSHMEM_HEADROOM;
}

static inline u16_t netshmem_get_data_offset(void)
{
	return NETSHMEM_HEADROOM;
}

static inline u16_t netshmem_get_max_data_buf_sz(void)
{
	return (PKT_BUF_SIZE - NETSHMEM_HEADROOM);
}

static inline void * netshmem_get_tailroom(struct netshmem_pkt_buf *pkt_buf)
{
	return (char *)pkt_buf + (PKT_BUF_SIZE - NETSHMEM_TAILROOM);
}
#endif
