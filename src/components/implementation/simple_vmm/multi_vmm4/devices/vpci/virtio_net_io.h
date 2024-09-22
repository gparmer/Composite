#pragma once

#include <cos_types.h>
#include <vmrt.h>

#define VIRTIO_NET_IO_ADDR 0x4000

#define VIRTIO_NET_DEV_FEATURES (VIRTIO_NET_IO_ADDR + 0)
#define VIRTIO_NET_GUEST_FEATURES (VIRTIO_NET_IO_ADDR + 4)
#define VIRTIO_NET_QUEUE_ADDR (VIRTIO_NET_IO_ADDR + 8)
#define VIRTIO_NET_QUEUE_SIZE (VIRTIO_NET_IO_ADDR + 12)
#define VIRTIO_NET_QUEUE_SELECT (VIRTIO_NET_IO_ADDR + 14)
#define VIRTIO_NET_QUEUE_NOTIFY (VIRTIO_NET_IO_ADDR + 16)
#define VIRTIO_NET_DEV_STATUS (VIRTIO_NET_IO_ADDR + 18)
#define VIRTIO_NET_ISR (VIRTIO_NET_IO_ADDR + 19)

#define VIRTIO_NET_MAC (VIRTIO_NET_IO_ADDR + 20)
#define VIRTIO_NET_MAC1 (VIRTIO_NET_IO_ADDR + 21)
#define VIRTIO_NET_MAC2 (VIRTIO_NET_IO_ADDR + 22)
#define VIRTIO_NET_MAC3 (VIRTIO_NET_IO_ADDR + 23)
#define VIRTIO_NET_MAC4 (VIRTIO_NET_IO_ADDR + 24)
#define VIRTIO_NET_MAC5 (VIRTIO_NET_IO_ADDR + 25)

#define VIRTIO_NET_STATUS (VIRTIO_NET_IO_ADDR + 26)
#define VIRTIO_NET_STATUS_H (VIRTIO_NET_IO_ADDR + 27)

#define VIRTIO_NET_F_CSUM (0)
#define VIRTIO_NET_F_GUEST_CSUM (1)
#define VIRTIO_NET_F_MAC (5)
#define VIRTIO_NET_F_GSO (6)
#define VIRTIO_NET_F_GUEST_TSO4 (7)
#define VIRTIO_NET_F_GUEST_TSO6 (8)
#define VIRTIO_NET_F_GUEST_ECN (9)
#define VIRTIO_NET_F_GUEST_UFO (10)
#define VIRTIO_NET_F_HOST_TSO4 (11)
#define VIRTIO_NET_F_HOST_TSO6 (12)
#define VIRTIO_NET_F_HOST_ECN (13)
#define VIRTIO_NET_F_HOST_UFO (14)
#define VIRTIO_NET_F_MRG_RXBUF (15)
#define VIRTIO_NET_F_STATUS (16)
#define VIRTIO_NET_F_CTRL_VQ (17)
#define VIRTIO_NET_F_CTRL_RX (18)
#define VIRTIO_NET_F_CTRL_VLAN (19)
#define VIRTIO_NET_F_GUEST_ANNOUNCE (21)

#define VIRTIO_NET_RINGSZ	512
#define VIRTIO_NET_MAXSEGS	32
#define	VQ_MAX_DESCRIPTORS	512

struct virtio_header {
	u32_t dev_features;
	u32_t guest_features;
	u32_t queue_addr;
	u16_t queue_size;
	u16_t queue_select;
	u16_t queue_notify;
	u8_t dev_status;
	u8_t ISR;
} __attribute__((packed));

struct virtio_queue {
	u16_t queue_sz;
	void *queue;
};

#define VIRTIO_NET_S_LINK_UP 1
#define VIRTIO_NET_S_ANNOUNCE 2

#define VIRTIO_NET_RX 0
#define VIRTIO_NET_TX 1

#define VIRTIO_NET_RXQ	0
#define VIRTIO_NET_TXQ	1
#define VIRTIO_NET_CTLQ	2

#define VIRTIO_NET_MAXQ	3

#define VRING_PAGE_BITS		12
#define VIRTIO_PCI_VRING_ALIGN	4096

#define	VQ_ALLOC	0x01	/* set once we have a pfn */
#define	VQ_BROKED	0x02

struct virtio_net_config {
	u8_t mac[6];
	u16_t status;
} __attribute__((packed));

struct virtio_net_io_reg {
	struct virtio_header header;
	struct virtio_net_config config_reg;
} __attribute__((packed));

// struct iovec
// {
//     void *iov_base;	/* Pointer to data.  */
//     size_t iov_len;	/* Length of data.  */
// };

struct virtio_vq_info {
	u16_t qsize;		/* size of this queue (a power of 2) */
	void (*notify)(void *, struct virtio_vq_info *);
				/* called instead of notify, if not NULL */

	u16_t num;		/* the num'th queue in the virtio_base */

	u16_t flags;		/* flags (see above) */
	u16_t last_avail;	/* a recent value of avail->idx */
	u16_t save_used;	/* saved used->idx; see vq_endchains */
	u16_t msix_idx;		/* MSI-X index, or VIRTIO_MSI_NO_VECTOR */

	u32_t pfn;		/* PFN of virt queue (not shifted!) */

	volatile struct vring_desc *desc;
				/* descriptor array */
	volatile struct vring_avail *avail;
				/* the "avail" ring */
	volatile struct vring_used *used;
				/* the "used" ring */

	u32_t gpa_desc[2];	/* gpa of descriptors */
	u32_t gpa_avail[2];	/* gpa of avail_ring */
	u32_t gpa_used[2];	/* gpa of used_ring */
	int enabled;		/* whether the virtqueue is enabled */

	/* each vq is bounded to a vcpu */
	struct vmrt_vm_vcpu *vcpu;
};

/*
 * Fixed network header size
 */
struct virtio_net_rxhdr {
	u8_t	vrh_flags;
	u8_t	vrh_gso_type;
	u16_t	vrh_hdr_len;
	u16_t	vrh_gso_size;
	u16_t	vrh_csum_start;
	u16_t	vrh_csum_offset;
} __attribute__((packed));

void virtio_net_handler(u16_t port, int dir, int sz, struct vmrt_vm_vcpu *vcpu);
void virtio_net_rcv_one_pkt(void *data, int pkt_len);
void virtio_net_send_one_pkt(void *data, u16_t *pkt_len);
