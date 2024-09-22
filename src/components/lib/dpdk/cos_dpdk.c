
#include <rte_eal.h>
#include "adapter/cos_dpdk_adapter.h"
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_config.h>
#include <rte_mbuf.h>

#include <arpa/inet.h>
#include <net_stack_types.h>

#include "cos_dpdk.h"
extern struct rte_pci_bus rte_pci_bus;

struct rte_port *ports;

static int cos_dpdk_log_type;
#define COS_DPDK_APP_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, cos_dpdk_log_type, "COD_DPDK_APP: " fmt, ## args)

static cos_portid_t ports_ids[RTE_MAX_ETHPORTS];
static uint16_t nb_ports = 0;

#define IP_PROTOCOL_TCP 6
#define IP_PROTOCOL_UDP 17

static void
cos_eth_info_print(cos_portid_t port_id)
{
	int ret;
	char dev_name[COS_ETH_NAME_SZ];
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	struct rte_eth_dev_info dev_info;
	struct rte_ether_addr mac_addr;
	struct rte_eth_link link;

	memset(dev_name, 0, COS_ETH_NAME_SZ);
	rte_eth_dev_get_name_by_port(port_id, dev_name);
	rte_eth_dev_info_get(port_id, &dev_info);
	rte_eth_macaddr_get(port_id, &mac_addr);

	ret = rte_eth_link_get(port_id, &link);
	if (ret < 0) {
			cos_printf("Link get failed (port %u): %s\n",
			port_id, rte_strerror(-ret));
	} else {
			rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text),
					&link);
	}

	COS_DPDK_APP_LOG(NOTICE,
			"\n\tDEV_INFO:\n"
			"\t\tport_id: %d\n"
			"\t\tdev_name:%s\n"
			"\t\tdev_mac_addr: "NMACHEX_FMT"\n"
			"\t\tdev_min_mtu: %d\n"
			"\t\tdev_max_mtu: %d\n"
			"\t\tdev_min_rx_bufsize: %d\n"
			"\t\tdev_max_rx_pktlen: %d\n"
			"\t\tdev_max_rx_quques: %d\n"
			"\t\tdev_max_tx_queues: %d\n"
			"\t\tdev_min_rx_desc: %d\n"
			"\t\tdev_max_rx_desc: %d\n"
			"\t\tdev_min_tx_desc: %d\n"
			"\t\tdev_min_tx_desc: %d\n"
			"\t\tlink_status: %s\n",
			port_id,
			dev_name, 
			NMACHEX(mac_addr),
			dev_info.min_mtu,
			dev_info.max_mtu,
			dev_info.min_rx_bufsize,
			dev_info.max_rx_pktlen,
			dev_info.max_rx_queues,
			dev_info.max_tx_queues,
			dev_info.rx_desc_lim.nb_min,
			dev_info.rx_desc_lim.nb_max,
			dev_info.tx_desc_lim.nb_min,
			dev_info.tx_desc_lim.nb_max,
			link_status_text
			);

	return;
}

/*
 * cos_eth_ports_init: find and init all ether ports that are available
 *
 * @return: nb_ports: 0 no port found
 * 
 * note: each port repesents an Ether NIC, and ports whose link status is down will be ignored
 */
uint16_t
cos_eth_ports_init(void)
{
	cos_portid_t port_id;
	uint16_t i;

	memset(ports_ids, 0, sizeof(ports_ids));

	RTE_ETH_FOREACH_DEV(port_id) {
		ports_ids[nb_ports] = port_id;
		nb_ports++;
	}

	COS_DPDK_APP_LOG(NOTICE, "cos_eth_ports_init success, find %d ports\n", nb_ports);

	for (i = 0; i < nb_ports; i++) {
		cos_eth_info_print(ports_ids[i]);
	}

	if (nb_ports != 1) {
		ports_ids[0] = 1;
		nb_ports = 1;
	}

	return nb_ports;
}

static struct rte_mempool * cos_dpdk_pktmbuf_pool = NULL;
static struct rte_eth_conf default_port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

/*
 * cos_create_pkt_mbuf: wrapper function for rte_pktmbuf_pool_create
 *
 * @name: pkt pool name
 * @nb_mbufs: number of mbufs within this pool, thus the maximum packets
 *            that can be stored in this single mem pool.
 * 
 * @return: NULL on allocate failure, others on success
 * 
 * note: this function assumes that the size of each mbuf is COS_MBUF_DEFAULT_BUF_SIZE.
 *       this setting should be enough for most use cases and thus is intended to simplify
 *       users' programming overhead.
 */
char*
cos_create_pkt_mbuf_pool(const char *name, size_t nb_mbufs)
{
	#define MEMPOOL_CACHE_SIZE 0
	return (char *)rte_pktmbuf_pool_create(name, nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, COS_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
}

/*
 * cos_free_packet: wrapper function for rte_pktmbuf_free
 *
 * @packet: mbuf packet
 * 
 * @return: 0 on success, others on failure
 * 
 * note: this function will free the mbuf used by this packet
 */
int
cos_free_packet(char* packet)
{
	/* TODO: add free logic */
	rte_pktmbuf_free((struct rte_mbuf *)packet);
	return 0;
}

/*
 * cos_config_dev_port_queue: wrapper function for rte_eth_dev_configure
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @nb_rx_q: number of rx queues used with this port
 * @nb_tx_q: number of tx queues used with this port
 * 
 * return: 0 on success, others will cause panic
 * 
 * note: this function gives users ability to config a port's rx/tx queues
 */
int
cos_config_dev_port_queue(cos_portid_t port_id, uint16_t nb_rx_q, uint16_t nb_tx_q)
{
	int ret;
	struct rte_eth_conf local_port_conf = default_port_conf;

	ret = rte_eth_dev_configure(ports_ids[port_id], nb_rx_q, nb_tx_q, &local_port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}
	
	COS_DPDK_APP_LOG(NOTICE, "cos_config_dev_port_queue success, with "
			"%d rx_queue, %d tx_queues\n", nb_tx_q, nb_tx_q);

	return ret;
}

/*
 * cos_dev_port_adjust_rx_tx_desc: wrapper function for rte_eth_dev_adjust_nb_rx_tx_desc
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @nb_rx_desc: number of rx descriptors used by this port
 * @nb_tx_desc: number of tx descriptors used with this port
 * 
 * @return: 0 on success, others will cause panic
 * 
 * note: this function will check if nb_rx_desc/nb_tx_desc set by user is valid, if not, 
 *       system default values will be set to them
 */
int
cos_dev_port_adjust_rx_tx_desc(cos_portid_t port_id, uint16_t *nb_rx_desc, uint16_t *nb_tx_desc)
{
	int ret;

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(ports_ids[port_id], nb_rx_desc, nb_tx_desc);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"Cannot adjust number of descriptors: err=%d, port=%u\n",
				ret, port_id);
	}
	
	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_adjust_rx_tx_desc success, with "
			"%d rx_desc, %d tx_desc\n", *nb_rx_desc, *nb_tx_desc);

	return ret;
}

/*
 * cos_dev_port_rx_queue_setup: wrapper function for rte_eth_rx_queue_setup
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @rx_queue_id: queue idx setup by user
 * @nb_rx_desc: number of rx descriptors used with this queue
 * 
 * @return: 0 on success, others will cause panic
 * 
 * note: this function gives users ability to config a rx queue
 */
int
cos_dev_port_rx_queue_setup(cos_portid_t port_id, uint16_t rx_queue_id, 
			uint16_t nb_rx_desc, char* mp)
{
	int ret;
	cos_portid_t real_port_id = ports_ids[port_id];
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rxconf rxq_conf;

	ret = rte_eth_dev_info_get(real_port_id, &dev_info);
	rxq_conf = dev_info.default_rxconf;

	ret = rte_eth_rx_queue_setup(real_port_id, rx_queue_id, nb_rx_desc,
					rte_eth_dev_socket_id(real_port_id),
					&rxq_conf,
					(struct rte_mempool *)mp);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				ret, port_id);
	}

	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_rx_queue_setup success, with "
			"%d rx_desc in rx_queue_%d\n", nb_rx_desc, rx_queue_id);

	return ret;
}

/*
 * cos_dev_port_tx_queue_setup: wrapper function for rte_eth_tx_queue_setup
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @tx_queue_id: queue idx setup by user
 * @nb_tx_desc: number of tx descriptors used with this queue
 * 
 * @return: 0 on success, others will cause panic
 * 
 * note: this function gives users ability to config a tx queue
 */
int
cos_dev_port_tx_queue_setup(cos_portid_t port_id, uint16_t tx_queue_id, 
			uint16_t nb_tx_desc)
{
	int ret;
	cos_portid_t real_port_id = ports_ids[port_id];

	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txq_conf;

	ret = rte_eth_dev_info_get(real_port_id, &dev_info);
	txq_conf = dev_info.default_txconf;

#if 0
	/* We assume the NIC provides both IP & UDP offload capability */
	assert(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM);
	assert(dev_info.tx_offload_capa & DEV_TX_OFFLOAD_UDP_CKSUM);
#endif

	txq_conf.tx_free_thresh = nb_tx_desc - 32;
	/* set the txq to enable IP and UDP offload */
	if (ENABLE_OFFLOAD) {
		txq_conf.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM;
		txq_conf.offloads |= DEV_TX_OFFLOAD_UDP_CKSUM;
	}

	ret = rte_eth_tx_queue_setup(real_port_id, tx_queue_id, nb_tx_desc,
				rte_eth_dev_socket_id(real_port_id),
				&txq_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
			ret, port_id);
	}

	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_tx_queue_setup success, with "
			"%d tx_desc in tx_queue_%d\n", nb_tx_desc, tx_queue_id);

	return ret;
}

/*
 * cos_dev_port_start: wrapper function for rte_eth_dev_start
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @return: 0 on success, others will cause panic
 * 
 * note: this function will let the NIC begin to rx/tx packets
 */
int
cos_dev_port_start(cos_portid_t port_id)
{
	int ret;

	ret = rte_eth_dev_start(ports_ids[port_id]);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);
	}
	
	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_start success, with port %d\n", port_id);

	return ret;
}

/*
 * cos_dev_port_stop: wrapper function for rte_eth_dev_stop
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @return: 0 on success, others will cause panic
 * 
 * note: this function will stop the NIC
 */
int
cos_dev_port_stop(cos_portid_t port_id)
{
	int ret;
	ret = rte_eth_dev_stop(ports_ids[port_id]);
	if (ret != 0)
		printf("rte_eth_dev_stop: err=%d, port=%d\n",
			ret, port_id);

	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_stop success, with port %d\n", port_id);

	return ret;
}

/*
 * cos_dev_port_set_promiscuous_mode: wrapper function for rte_eth_promiscuous_enable
 * and rte_eth_promiscuous_disable
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @mode: ON will enable promiscuous mode, OFF will disable it
 * 
 * @return: 0 on success, others will cause panic
 */
int
cos_dev_port_set_promiscuous_mode(cos_portid_t port_id, bool mode)
{
	int ret;
	cos_portid_t real_port_id = ports_ids[port_id];
	if (mode == COS_DPDK_SWITCH_ON) {
		ret = rte_eth_promiscuous_enable(real_port_id);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_enable:err=%s, port=%u\n",
				rte_strerror(-ret), port_id);
		}
	} else if (mode == COS_DPDK_SWITCH_OFF){
		ret = rte_eth_promiscuous_disable(real_port_id);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
				"rte_eth_promiscuous_disable:err=%s, port=%u\n",
				rte_strerror(-ret), port_id);
		}
	} else {
		rte_exit(EXIT_FAILURE, "invalid mode\n");
	}

	COS_DPDK_APP_LOG(NOTICE, "cos_dev_port_set_promiscuous_mode success, "
			"with port %d, mode: %s\n", port_id,
			(mode == COS_DPDK_SWITCH_ON) ? "COS_DPDK_SWITCH_ON":"COS_DPDK_SWITCH_OFF");

	return ret;
}

/*
 * cos_dev_port_rx_burst: wrapper function for rte_eth_rx_burst
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @queue_id: queue idx setup by user
 * @rx_pkts: pointer array, this will be filled with packets received
 * @nb_pkts: maximum packets bursted at this time
 * 
 * @return: number of packets received at this burst
 */
uint16_t
cos_dev_port_rx_burst(cos_portid_t port_id, uint16_t queue_id,
		 char**rx_pkts, const uint16_t nb_pkts)
{
	return rte_eth_rx_burst(ports_ids[port_id], queue_id, (struct rte_mbuf **)rx_pkts, nb_pkts);
}

/*
 * cos_dev_port_tx_burst: wrapper function for rte_eth_tx_burst
 *
 * @port_id: eth port id, from user's perspective, the maximum id is get
 *           from cos_eth_ports_init
 * @queue_id: queue idx setup by user
 * @tx_pkts: pointer array, this will be filled with packets to be sent
 * @nb_pkts: maximum packets bursted at this time
 * 
 * @return: number of acutal packets sent at this burst
 */
uint16_t
cos_dev_port_tx_burst(cos_portid_t port_id, uint16_t queue_id,
		 char**tx_pkts, const uint16_t nb_pkts)
{
	return rte_eth_tx_burst(ports_ids[port_id], queue_id, (struct rte_mbuf **)tx_pkts, nb_pkts);
}

/*
 * cos_parse_pkts: return data pointer of this packet
 */
char*
cos_get_packet(char* mbuf, int *len)
{
	rte_prefetch0((char *)rte_pktmbuf_mtod((struct rte_mbuf*)mbuf, void *) + 16);
	*len = ((struct rte_mbuf*)mbuf)->pkt_len;
	return (char *)rte_pktmbuf_mtod((struct rte_mbuf*)mbuf, struct rte_ether_hdr *);
}

/*
 * cos_get_port_stats: get a port's NIC stats
 *
 * @return: null
 * 
 */
void
cos_get_port_stats(cos_portid_t port_id)
{
	struct rte_eth_stats stats;

	rte_eth_stats_get(ports_ids[port_id], &stats);

	COS_DPDK_APP_LOG(NOTICE, 
		"PORT STATS(%d):\n"
		"\t\t rx bytes: %lu\n"
		"\t\t rx packets: %lu\n"
		"\t\t tx bytes: %lu\n"
		"\t\t tx packets: %lu\n"
		"\t\t imssied: %lu\n"
		"\t\t ierrors: %lu\n"
		"\t\t oerrors: %lu\n"
		"\t\t no_buf: %lu\n",
		ports_ids[port_id],
		stats.ibytes,
		stats.ipackets,
		stats.obytes,
		stats.opackets,
		stats.imissed,
		stats.ierrors,
		stats.oerrors,
		stats.rx_nombuf);
}

/*
 * On success: return the number of parsed arguments (can be zero)
 * On failure: return -1
 */
int
cos_dpdk_init(int argc, char **argv)
{	
	int ret;

	/* override the dpdk's default pci scan function */
	rte_pci_bus.bus.scan = cos_pci_scan;

	/* register a log type for cos dpdk application */
	cos_dpdk_log_type = rte_log_register("cos_dpdk_app");
	if (cos_dpdk_log_type < 0) {
		rte_exit(EXIT_FAILURE, "Cannot register log type");
	}

	rte_log_set_level(cos_dpdk_log_type, RTE_LOG_INFO);

	ret = rte_eal_init(argc, argv);

	if (ret >= 0) {
		COS_DPDK_APP_LOG(NOTICE, "cos_dpdk_init success.\n");
	}

	return ret;
}

/* A simple transmiting test function */
void
cos_test_send(int queue, char* mp) {
	struct rte_mbuf * mbuf;
	struct rte_ether_hdr *eth_hdr;
#if E810_NIC
	struct rte_ether_addr s_addr = {{0x6c,0xfe,0x54,0x40,0x41,0x01}};
	struct rte_ether_addr d_addr = {{0x6c,0xfe,0x54,0x40,0x46,0x09}};
#else 
	struct rte_ether_addr s_addr = {{0x66,0x66,0x66,0x66,0x66,0x66}};
	struct rte_ether_addr d_addr = {{0x10,0x10,0x10,0x10,0x10,0x11}};
#endif
	char *tx_packets[4096];
	#define BURST_NB 1024 
	#define PKT_SZ 100
	struct rte_ipv4_hdr *ip_hdr;
	struct rte_udp_hdr *udp_hdr;

	while (1)
	{
		/* code */
		for (int i = 0;i < BURST_NB; i++) {
			mbuf = rte_pktmbuf_alloc((struct rte_mempool *)mp);
			assert(mbuf);
			tx_packets[i] = (char *)mbuf;
			mbuf->data_off = 128;

			mbuf->data_len = PKT_SZ;
			mbuf->pkt_len = PKT_SZ;

			mbuf->buf_len = 1500;
			mbuf->tx_offload = 0;

			eth_hdr = mbuf->buf_addr + mbuf->data_off;
			eth_hdr->dst_addr = d_addr;
			eth_hdr->src_addr = s_addr;
			eth_hdr->ether_type = 0x0008;

			ip_hdr = mbuf->buf_addr + mbuf->data_off + 14;
			udp_hdr =  mbuf->buf_addr + mbuf->data_off + 14 + 20;

			udp_hdr->src_port = 10000;
			udp_hdr->dst_port = 20000;
			udp_hdr->dgram_len = htons(200 + 8);
			udp_hdr->dgram_cksum = 0;

			ip_hdr->ihl =  5;
			ip_hdr->version = 4;
			ip_hdr->type_of_service = 0;
			ip_hdr->total_length = htons(20 + 200);
			ip_hdr->packet_id = 0;
			ip_hdr->fragment_offset = 0;
			ip_hdr->time_to_live = 64;
			ip_hdr->next_proto_id = 17;
			ip_hdr->src_addr =0x01010101;
			ip_hdr->dst_addr = 0x02020202;
			ip_hdr->hdr_checksum = 0;
		}

		uint16_t ret = 0;
		while (ret < BURST_NB) {
			ret += cos_dev_port_tx_burst(0, queue, &tx_packets[ret], BURST_NB - ret);
		}
	}
}

uint16_t cos_send_a_packet(char * pkt, uint32_t pkt_size, char* mp)
{
	struct rte_mbuf * mbuf;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ether_addr s_addr = {{0x66,0x66,0x66,0x66,0x66,0x66}};
	struct rte_ether_addr d_addr = {{0x11,0x11,0x11,0x11,0x11,0x11}};

	mbuf = rte_pktmbuf_alloc((struct rte_mempool *)mp);
	eth_hdr = rte_pktmbuf_mtod(mbuf,struct rte_ether_hdr*);

	eth_hdr->dst_addr = d_addr;
	eth_hdr->src_addr = s_addr;
	eth_hdr->ether_type = 0x0008;

	char* ip_data = (char*)eth_hdr + sizeof(struct rte_ether_hdr);
	memcpy(ip_data, pkt, pkt_size);
	
	mbuf->data_len = pkt_size + sizeof(struct rte_ether_hdr);
	mbuf->pkt_len = pkt_size + sizeof(struct rte_ether_hdr);

	return cos_dev_port_tx_burst(0, 0, (char **)&mbuf, 1);
}

char*
cos_allocate_mbuf(char* mp) {
	return (char *)rte_pktmbuf_alloc((struct rte_mempool *)mp);
}

static inline void
cos_pktmbuf_ext_shinfo_init_helper(void *ext_shinfo_addr, rte_mbuf_extbuf_free_callback_t free_cb, void *fcb_opaque)
{
	struct rte_mbuf_ext_shared_info *shinfo = ext_shinfo_addr;

	shinfo->free_cb = free_cb;
	shinfo->fcb_opaque = fcb_opaque;
	rte_mbuf_ext_refcnt_set(shinfo, 1);
}

int
cos_attach_external_mbuf(char *mbuf, void *buf_vaddr,
			uint64_t buf_paddr, uint16_t buf_len,
			void (*ext_buf_free_cb)(void *addr, void *opaque),
			void *ext_shinfo)
{
	rte_iova_t buf_iova = buf_paddr ;

	struct rte_mbuf *_mbuf = (struct rte_mbuf *)mbuf;

	cos_pktmbuf_ext_shinfo_init_helper(ext_shinfo, ext_buf_free_cb, 0);
	rte_pktmbuf_attach_extbuf(_mbuf, buf_vaddr, buf_iova, buf_len, ext_shinfo);

	return 0;
}

void
cos_set_external_packet(char*mbuf, uint16_t data_offset, uint16_t pkt_len, int offload)
{
	struct rte_mbuf *_mbuf = (struct rte_mbuf *)mbuf;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;

	_mbuf->data_len = pkt_len;
	_mbuf->pkt_len = pkt_len;
	_mbuf->data_off = data_offset;

	if (offload) {
		ipv4_hdr = _mbuf->buf_addr + _mbuf->data_off + 14;
		udp_hdr =  _mbuf->buf_addr + _mbuf->data_off + 14 + 20;

		/* Eth header should always be the stardand length */
		_mbuf->l2_len = ETH_STD_LEN;

		/* IP header length is (ihl * 4) */
		_mbuf->l3_len = ipv4_hdr->ihl * 4;

		/* if the original csum field is set, don't do the offload */
		if (unlikely(ipv4_hdr->hdr_checksum != 0 || udp_hdr->dgram_cksum != 0)) return;

		_mbuf->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM| RTE_MBUF_F_TX_UDP_CKSUM;

		/* NIC needs a pseudo-header L4 checksum before offload */
		udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr, RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM| RTE_MBUF_F_TX_UDP_CKSUM);
	}
}

int
cos_mempool_full(const char *mp)
{
	return rte_mempool_full((struct rte_mempool *)mp);
}

unsigned int
cos_mempool_in_use_count(const char *mp)
{
	return rte_mempool_in_use_count((struct rte_mempool *)mp);
}

int
cos_eth_tx_done_cleanup(uint16_t port_id, uint16_t queue_id, uint32_t free_cnt)
{
	return rte_eth_tx_done_cleanup(port_id, queue_id, free_cnt);
}

/*
 * cos_create_pkt_mbuf: wrapper function of rte_pktmbuf_pool_create_by_ops 
 *
 * @name: pkt pool name
 * @nb_mbufs: number of mbufs within this pool, thus the maximum packets
 *            that can be stored in this single mem pool.
 * @ops_name: the name of the operations mode of mempool ring
 * 
 * @return: NULL on allocate failure, others on success
 * 
 * note: this function assumes that the size of each mbuf is COS_MBUF_DEFAULT_BUF_SIZE.
 *       this setting should be enough for most use cases and thus is intended to simplify
 *       users' programming overhead.
 */
char*
cos_create_pkt_mbuf_pool_by_ops(const char *name, size_t nb_mbufs, char* ops_name)
{
	return (char *)rte_pktmbuf_pool_create_by_ops(name, nb_mbufs, 0, 0,
		COS_MBUF_DEFAULT_BUF_SIZE, rte_socket_id(), ops_name);
}

uint64_t
cos_get_port_mac_address(uint16_t port_id)
{
	uint64_t mac_addr_ret = 0;
	struct rte_ether_addr mac_addr;

	rte_eth_macaddr_get(ports_ids[port_id], &mac_addr);
	rte_ether_addr_copy(&mac_addr, (struct rte_ether_addr *)&mac_addr_ret);

	return mac_addr_ret;
}

void cos_rte_flow(void)
{
	#define MAX_PATTERN_NUM		3
	#define MAX_ACTION_NUM		2

	struct rte_flow_attr attr;
	struct rte_flow_item pattern[MAX_PATTERN_NUM];
	struct rte_flow_action action[MAX_ACTION_NUM];
	struct rte_flow *flow = NULL;
	struct rte_flow_action_queue queue = { .index = 0 };
	struct rte_flow_item_ipv4 ip_spec;
	struct rte_flow_item_ipv4 ip_mask;
	struct rte_flow_error *error = NULL;
	int res;

 	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	/* set the rule attribute. in this case only ingress packets will be checked. */
	memset(&attr, 0, sizeof(struct rte_flow_attr));
	attr.ingress = 1;
	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[0].conf = &queue;
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

	memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));

	ip_spec.hdr.dst_addr = htonl(0xA0A0101);
	ip_mask.hdr.dst_addr = 0xFFFFFFFF; //exact match

	ip_spec.hdr.src_addr = htonl(0);
	ip_mask.hdr.src_addr = 0; //any src

	pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[1].spec = &ip_spec;
	pattern[1].mask = &ip_mask;
 
	/* the final level must be always type end */
	pattern[2].type = RTE_FLOW_ITEM_TYPE_END;

	res = rte_flow_validate(0, &attr, pattern, action, error);
	if (!res)
		flow = rte_flow_create(0, &attr, pattern, action, error);
	/* >8 End of validation the rule and create it. */

	assert(flow);
	cos_printf("flow :%p\n", flow);
	// return flow;

}
