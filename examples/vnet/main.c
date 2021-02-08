#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>

#include "doca_gw.h"
#include "doca_pcap.h"
#include "doca_log.h"
#include "gw.h"
#include "gw_ft.h"

DOCA_LOG_MODULE(main)

#define GW_PKT_L2(M) rte_pktmbuf_mtod(M,uint8_t *)
#define GW_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

#define GW_MAX_FLOWS (4096)
#define GW_ENTRY_BUFF_SIZE (128)
#define GW_RX_BURST_SIZE (32)

static volatile bool force_quit;

static uint16_t port_id;
static uint16_t nr_queues = 2;
struct rte_mempool *mbuf_pool;
static const char *pcap_file_name = "/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_pcap_hander *ph;

struct gw_ft *gw_ft;

struct gw_entry {
    int total_pkts;
    char readble_str[GW_ENTRY_BUFF_SIZE];
};

static inline uint64_t gw_get_time_usec(void)
{
    //TODO: this is very bad way to do it
    //need to set start time and use rte_
    struct timeval tv;
    gettimeofday(&tv,NULL);

    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static
void gw_handle_packet(struct gw_pkt_info *pinfo)
{
    struct gw_ft_user_ctx *ctx;
    struct gw_entry *entry;
    if(!gw_ft_find(gw_ft, pinfo, &ctx)){
        printf("failed to find entry- trying to allocate\n");
        if (!gw_ft_add_new(gw_ft, pinfo,&ctx)) {
            printf("failed create new entry\n");
            return;
        }
    }
    entry = (struct gw_entry *) &ctx->data[0];
    entry->total_pkts++;
    printf("total packets %d\n",entry->total_pkts);
    doca_pcap_write(ph,pinfo->outer.l2, pinfo->len, gw_get_time_usec(), 0); 

}


static void
gw_process_pkts(void)
{
	struct rte_mbuf *mbufs[GW_RX_BURST_SIZE];
	struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
        struct gw_pkt_info pinfo;

	while (!force_quit) {
            for (port_id = 0; port_id < 2; port_id++) { 
                for (i = 0; i < nr_queues; i++) {
                    nb_rx = rte_eth_rx_burst(port_id, i, mbufs, GW_RX_BURST_SIZE);
                    if (nb_rx) {
                        for (j = 0; j < nb_rx; j++) {
                            memset(&pinfo,0, sizeof(struct gw_pkt_info)); 
                            if(gw_parse_packet(GW_PKT_L2(mbufs[i]),GW_PKT_LEN(mbufs[i]), &pinfo)){
                                if (pinfo.outer.l3_type == 4) {
                                    gw_handle_packet(&pinfo);
                                    //gw_parse_pkt_str(&pinfo, strbuff,DEBUG_BUFF_SIZE);
                                    //printf("got mbuf on port == %d,\n %s", m->port,strbuff);
                                }
                            }
                            rte_eth_tx_burst((mbufs[i]->port == 0) ? 1 : 0, 0, &mbufs[i], 1);
                        }
                    }
                }
            }
	}

	/* closing and releasing resources */
	rte_flow_flush(port_id, &error);
	rte_eth_dev_stop(port_id);
	rte_eth_dev_close(port_id);
}

#define CHECK_INTERVAL 1000  /* 100ms */
#define MAX_REPEAT_TIMES 90  /* 9s (90 * 100ms) in total */

static void
assert_link_status(void)
{
	struct rte_eth_link link;
	uint8_t rep_cnt = MAX_REPEAT_TIMES;
	int link_get_err = -EINVAL;

	memset(&link, 0, sizeof(link));
	do {
		link_get_err = rte_eth_link_get(port_id, &link);
		if (link_get_err == 0 && link.link_status == ETH_LINK_UP)
			break;
		rte_delay_ms(CHECK_INTERVAL);
	} while (--rep_cnt);

	if (link_get_err < 0)
		rte_exit(EXIT_FAILURE, ":: error: link get is failing: %s\n",
			 rte_strerror(-link_get_err));
	if (link.link_status == ETH_LINK_DOWN)
		rte_exit(EXIT_FAILURE, ":: error: link is still down\n");
}

static void
init_port(void)
{
	int ret;
	uint16_t i;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_VLAN_INSERT |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
		},
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	DOCA_LOG_INFO(":: initializing port: %d\n", port_id);
	ret = rte_eth_dev_configure(port_id,
				nr_queues, nr_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			":: cannot configure device: err=%d, port=%u\n",
			ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
				     rte_eth_dev_socket_id(port_id),
				     &rxq_conf,
				     mbuf_pool);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Rx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < nr_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				":: Tx queue setup failed: err=%d, port=%u\n",
				ret, port_id);
		}
	}

	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			":: promiscuous mode enable failed: err=%s, port=%u\n",
			rte_strerror(-ret), port_id);

	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start:err=%d, port=%u\n",
			ret, port_id);
	}

	assert_link_status();

	DOCA_LOG_INFO(":: initializing port: %d done\n", port_id);
}

static void
signal_handler(int signum)
{
        if (ph != NULL) {
            doca_pcap_file_stop(ph);
            ph = NULL;
        }

	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

struct doca_gw_port port0 = {0};
struct doca_gw_port port1 = {0};

static int init_doca(void)
{
    int ret = 0;
    struct doca_gw_port_cfg cfg_port0 = { DOCA_GW_PORT_DPDK_BY_ID, "0" };
    struct doca_gw_port_cfg cfg_port1 = { DOCA_GW_PORT_DPDK_BY_ID, "1" };
    struct doca_gw_error err = {0};
    struct doca_gw_cfg cfg = {1000};
    if (doca_gw_init(&cfg,&err)) { 
        fprintf(stderr,"failed to init doca\n");
        return -1;
    }

    // adding ports
    ret+=doca_gw_port_start(&cfg_port0, &port0, &err);
    ret+=doca_gw_port_start(&cfg_port1, &port1, &err);

    if (!ret) {
        //TODO: print errors
        fprintf(stderr, "log:\n");
    }

    return ret;
}

static void
init_dpdk(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, ":: invalid EAL arguments\n");

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");
	port_id = 0;
	if (nr_ports != 1) {
		printf(":: warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", 4096, 128, 0,
					    RTE_MBUF_DEFAULT_BUF_SIZE,
					    rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
}


static int init_gw(void)
{
    if (init_doca()){
        return -1;
    }

    gw_ft = gw_ft_create(GW_MAX_FLOWS , sizeof(struct gw_entry));
    if(!gw_ft) {
        return -1;
    }

    return 0;
}

int
main(int argc, char **argv)
{
	init_dpdk(argc, argv);
	port_id = 0;
	init_port();
	port_id = 1;
	init_port();

        DOCA_LOG_INFO("starting doca\n");
        if (init_gw()){
            rte_exit(EXIT_FAILURE,"failed to init doca");
        }
        DOCA_LOG_INFO("GW initiated!\n");

        ph = doca_pcap_file_start(pcap_file_name);

	gw_process_pkts();

	return 0;
}
