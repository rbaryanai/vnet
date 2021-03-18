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

uint16_t nr_queues = 2;
static const char *pcap_file_name = "/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_pcap_hander *ph;

static struct doca_vnf *vnf;

struct vnf_per_core_params {
    int ports[VNF_NUM_OF_PORTS];
    int queues[VNF_NUM_OF_PORTS];
    int core_id;
    bool used;
};

struct vnf_per_core_params core_params_arr[RTE_MAX_LCORE];

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

static int
gw_process_pkts(void *p)
{
	struct rte_mbuf *mbufs[VNF_RX_BURST_SIZE];
	uint16_t nb_rx;
	uint16_t i;
	uint16_t j;
        struct doca_pkt_info pinfo;
        struct vnf_per_core_params *params = (struct vnf_per_core_params *)p;
        int port_id;

	while (!force_quit) {
            for (port_id = 0; port_id < 2; port_id++) { 
                for (i = 0; i < 1/*nr_queues*/; i++) {
                    nb_rx = rte_eth_rx_burst(port_id, params->queues[port_id], mbufs, VNF_RX_BURST_SIZE);
                    if (nb_rx) {
                        for (j = 0; j < nb_rx; j++) {
                            memset(&pinfo,0, sizeof(struct doca_pkt_info));
                            doca_dump_rte_mbuff("recv mbuff:", mbufs[j]);
                            if(!doca_parse_packet(VNF_PKT_L2(mbufs[j]),VNF_PKT_LEN(mbufs[j]), &pinfo)){
                                pinfo.orig_port_id = mbufs[j]->port;
                                if (pinfo.outer.l3_type == 4) {
                                    vnf->doca_vnf_process_pkt(&pinfo);
                                    if(ph) {
                                        doca_pcap_write(ph,pinfo.outer.l2, pinfo.len, gw_get_time_usec(), 0); 
                                    }
                                    vnf_adjust_mbuf(mbufs[j], &pinfo);
                                }
                            }
                            rte_eth_tx_burst((mbufs[j]->port == 0) ? 1 : 0, params->queues[port_id], &mbufs[j], 1);
                        }
                    }
                }
            }
	}

        return 0;
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

static int 
count_lcores(void)
{
    int cores = 0;
    while (core_params_arr[cores].used)
        cores++;
    return cores;
}

static int
init_dpdk(int argc, char **argv)
{
	int ret;
	uint16_t nr_ports;
        int i;
        int total_cores = 0;

        memset(core_params_arr, 0, sizeof(core_params_arr));
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		DOCA_LOG_CRIT("invalid EAL arguments\n");
                return ret;
        }

        for ( i = 0 ; i < 32 ; i++) {
            if (rte_lcore_is_enabled(i)){
                core_params_arr[total_cores].ports[0]= 0;
                core_params_arr[total_cores].ports[1]= 1;
                core_params_arr[total_cores].queues[0]= total_cores;
                core_params_arr[total_cores].queues[1]= total_cores;
                core_params_arr[total_cores].core_id = i;
                core_params_arr[total_cores].used = true;
                total_cores++;
            }
        }

        nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0) {
		DOCA_LOG_CRIT("no Ethernet ports found\n");
                return -1;
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
        int total_cores;
        int i = 0;
	if (init_dpdk(argc , argv)) {
            rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
            return -1;
        }

        total_cores = count_lcores();
        DOCA_LOG_INFO("init ports: lcores = %d\n",total_cores);

	gw_init_port(0, total_cores);
	gw_init_port(1, total_cores);

        vnf = gw_get_doca_vnf();
        vnf->doca_vnf_init((void *)&total_cores);

        DOCA_LOG_INFO("VNF initiated!\n");

        if (capture_en) {
            ph = doca_pcap_file_start(pcap_file_name);
        }

        i = 1;
        while (core_params_arr[i].used) {
              rte_eal_remote_launch((lcore_function_t *)gw_process_pkts,
                        &core_params_arr[i], core_params_arr[i].core_id);
            i++;
        }

        // use main lcode as a thread.
        gw_process_pkts(&core_params_arr[i]);

        vnf->doca_vnf_destroy();

        gw_close_port(0);
        gw_close_port(1);

	return 0;
}
