#include <llprint.h>
#include <cos_dpdk.h>

#define NB_RX_DESC_DEFAULT 1024
#define NB_TX_DESC_DEFAULT 1024
#define MAX_PKT_BURST 512

static u16_t nic_ports = 0;

static void
process_packets(cos_portid_t port_id, char** rx_pkts, uint16_t nb_pkts)
{
	/* sent this group of packets out */
	cos_dev_port_tx_burst(port_id, 0, rx_pkts, nb_pkts);
}

static void
cos_nic_start(){
	int i, loop = 1000000000;
	uint16_t nb_pkts = 0;

	char* rx_packets[MAX_PKT_BURST];

	/* only burst for a little time */
	while (--loop)
	{
		/* infinite loop to process packets */
		for (i = 0; i < nic_ports; i++) {
			/* process rx */
			nb_pkts = cos_dev_port_rx_burst(i, 0, rx_packets, MAX_PKT_BURST);
			if (nb_pkts != 0) {
				process_packets(i, rx_packets, nb_pkts);
			}
		}
	}
	/* print stats */
	cos_get_port_stats(0);
}

static void
cos_nic_init(void)
{
	int argc, ret, nb_pkts;

	#define MAX_PKT_BURST 512

	const char *mpool_name = "cos_app_pool";
	uint16_t i;
	uint16_t nb_rx_desc = NB_RX_DESC_DEFAULT;
	uint16_t nb_tx_desc = NB_TX_DESC_DEFAULT;

	/*
	 * set max_mbufs 2 times than nb_rx_desc, so that there is enough room
	 * to store packets, or this will fail if nb_rx_desc <= max_mbufs.
	 */
	const size_t max_mbufs = 8 * nb_rx_desc;

	char *argv[] =	{
			"COS_DPDK_BOOTER", /* single core, the first argument has to be the program name */
			"-l", 
			"0",
			"--no-shconf", 
			"--no-huge",
			"--iova-mode=pa",
			"--log-level",
			"*:info", /* log level can be changed to *debug* if needed, this will print lots of information */
			"-m",
			"64", /* total memory used by dpdk memory subsystem, such as mempool */
			};

	argc = ARRAY_SIZE(argv);

	/* 1. do initialization of dpdk */
	ret = cos_dpdk_init(argc, argv);

	assert(ret == argc - 1); /* program name is excluded */

	/* 2. init all Ether ports */
	nic_ports = cos_eth_ports_init();

	assert(nic_ports > 0);

	/* 3. create mbuf pool where packets will be stored, user can create multiple pools */
	char* mp = cos_create_pkt_mbuf_pool(mpool_name, max_mbufs);

	assert(mp != NULL);

	/* 4. config each port */
	for (i = 0; i < nic_ports; i++) {
		cos_config_dev_port_queue(i, 1, 1);
		cos_dev_port_adjust_rx_tx_desc(i, &nb_rx_desc, &nb_tx_desc);
		cos_dev_port_rx_queue_setup(i, 0, nb_rx_desc, mp);
		cos_dev_port_tx_queue_setup(i, 0, nb_tx_desc);
	}

	/* 5. start each port, this will enable rx/tx */
	for (i = 0; i < nic_ports; i++) {
		cos_dev_port_start(i);
		cos_dev_port_set_promiscuous_mode(i, COS_DPDK_SWITCH_ON);
	}
}

void
cos_init(void)
{
	printc("nicmgr init...\n");
	cos_nic_init();
}

int
main(void)
{
	printc("NIC started\n");

	cos_nic_start();

	return 0;
}
