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
#include "doca_ft.h"
#include "gw_port.h"
#include "doca_vnf.h"

DOCA_LOG_MODULE(main)

#define VNF_PKT_L2(M) rte_pktmbuf_mtod(M,uint8_t *)
#define VNF_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

#define VNF_ENTRY_BUFF_SIZE (128)
#define VNF_RX_BURST_SIZE (32)
#define VNF_NUM_OF_PORTS (2)

static volatile bool force_quit;

static uint16_t port_id;
static uint16_t nr_queues = 2;
static const char *pcap_file_name = "/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_pcap_hander *ph;

static struct doca_vnf *vnf;

static inline uint64_t gw_get_time_usec(void)
{
    //TODO: this is very bad way to do it
    //need to set start time and use rte_
    struct timeval tv;
    gettimeofday(&tv,NULL);

    return tv.tv_sec * 1000000 + tv.tv_usec;
}

static void vnf_adjust_mbuf(struct rte_mbuf *m, struct doca_pkt_info *pinfo)
{
    int diff = pinfo->outer.l2 - VNF_PKT_L2(m);
    if (diff > 0) {
        //rte_pktmbuf_adj(m,diff);
    }
    //rte_pktmbuf_adj(m,diff);
}

static void
gw_process_pkts(void)
{
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	struct rte_flow_error error;
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
        struct doca_pkt_info pinfo;

	while (!force_quit) {
            for (port_id = 0; port_id < 2; port_id++) { 
                for (i = 0; i < nr_queues; i++) {
                    nb_rx = rte_eth_rx_burst(port_id, i, mbufs, VNF_RX_BURST_SIZE);
                    if (nb_rx) {
                        for (j = 0; j < nb_rx; j++) {
                            memset(&pinfo,0, sizeof(struct doca_pkt_info));
                            if(!doca_parse_packet(VNF_PKT_L2(mbufs[j]),VNF_PKT_LEN(mbufs[j]), &pinfo)){
                                pinfo.orig_port_id = mbufs[j]->port;
                                if (pinfo.outer.l3_type == 4) {

                                    vnf->doca_vnf_process_pkt(&pinfo);
                                    if(ph) {
                                        doca_pcap_write(ph,pinfo.outer.l2, pinfo.len, gw_get_time_usec(), 0); 
                                    }
                                    vnf_adjust_mbuf(mbufs[j], &pinfo);
                                    //gw_handle_packet(&pinfo);
                                }
                            }
                            rte_eth_tx_burst((mbufs[j]->port == 0) ? 1 : 0, 0, &mbufs[j], 1);
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

/*
static int init_doca(void)
{
    int ret = 0;

    struct gw_port_cfg cfg_port0 = { .n_queues = 4, .port_id = 0 };
    struct gw_port_cfg cfg_port1 = { .n_queues = 4, .port_id = 1 };
    struct doca_gw_error err = {0};

    struct doca_gw_cfg cfg = {VNF_MAX_FLOWS};
    if (doca_gw_init(&cfg,&err)) { 
        DOCA_LOG_ERR("failed to init doca:%s",err.message);
        return -1;
    }

    gw_ins->port0 = gw_init_doca_port(&cfg_port0);
    gw_ins->port1 = gw_init_doca_port(&cfg_port1);

    if (gw_ins->port0 == NULL || gw_ins->port1 == NULL) {
        DOCA_LOG_ERR("failed to start port %s",err.message);
        return ret;
    }

    gw_ins->p1_over_under[0] = gw_init_ol_to_ul_pipeline(gw_ins->port0);
    gw_ins->p1_over_under[1] = gw_init_ol_to_ul_pipeline(gw_ins->port1);

    return ret;
}*/

static int
init_dpdk(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;

	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		DOCA_LOG_CRIT("invalid EAL arguments\n");
                return ret;
        }

        nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0) {
		DOCA_LOG_CRIT("no Ethernet ports found\n");
                return -1;
        }
	port_id = 0;
	if (nr_ports != 1) {
		DOCA_LOG_WARN("warn: %d ports detected, but we use only one: port %u\n",
			nr_ports, port_id);
	}
	
        force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

        return 0;
}

static bool capture_en = 0;

int
main(int argc, char **argv)
{
	if (init_dpdk(argc , argv)) {
            rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
            return -1;
        }

        DOCA_LOG_INFO("starting doca\n");

	gw_init_port(0, nr_queues);
	gw_init_port(1, nr_queues);

        vnf = gw_get_doca_vnf();
        vnf->doca_vnf_init();

        DOCA_LOG_INFO("VNF initiated!\n");

        if (capture_en) {
            ph = doca_pcap_file_start(pcap_file_name);
        }

	gw_process_pkts();

        vnf->doca_vnf_destroy();
	return 0;
}
