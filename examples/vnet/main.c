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
#include "gw_port.h"

DOCA_LOG_MODULE(main)

#define GW_PKT_L2(M) rte_pktmbuf_mtod(M,uint8_t *)
#define GW_PKT_LEN(M) rte_pktmbuf_pkt_len(M)

#define GW_MAX_FLOWS (4096)
#define GW_ENTRY_BUFF_SIZE (128)
#define GW_RX_BURST_SIZE (32)
#define GW_NUM_OF_PORTS (2)

static volatile bool force_quit;

static uint16_t port_id;
static uint16_t nr_queues = 2;
static const char *pcap_file_name = "/var/opt/rbaryanai/vnet/build/examples/vnet/test.pcap";
static struct doca_pcap_hander *ph;

struct ex_gw {
    struct gw_ft *ft;

    struct doca_gw_port *port0; 
    struct doca_gw_port *port1; 

    // pipeline of overlay to underlay
    struct doca_gw_pipeline *p1_over_under[GW_NUM_OF_PORTS];

};

struct gw_entry {
    int total_pkts;
    int total_bytes;
    bool is_hw;
    struct doca_gw_pipelne_entry *hw_entry;
    char readble_str[GW_ENTRY_BUFF_SIZE];
};

struct ex_gw *gw_ins;

static inline uint64_t gw_get_time_usec(void)
{
    //TODO: this is very bad way to do it
    //need to set start time and use rte_
    struct timeval tv;
    gettimeofday(&tv,NULL);

    return tv.tv_sec * 1000000 + tv.tv_usec;
}

/**
 * @brief - called when flow is aged out in FT.
 *
 * @param ctx
 */
static 
void gw_aged_flow_cb(struct gw_ft_user_ctx *ctx)
{
    struct gw_entry *entry = (struct gw_entry *) &ctx->data[0];
    if (entry->is_hw) {
        gw_rm_pipeline_entry(entry->hw_entry);
    }
}

static
int gw_handle_new_flow(struct app_pkt_info *pinfo, struct gw_ft_user_ctx **ctx)
    
{
    struct gw_entry *entry;
    enum gw_classification cls = gw_classifiy_pkt(pinfo);
    
    switch(cls) {
        case GW_CLS_OL_TO_UL:
            if (!gw_ft_add_new(gw_ins->ft, pinfo,ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            entry = (struct gw_entry *) &(*ctx)->data[0];
            entry->hw_entry = gw_pipeline_add_ol_to_ul_entry(pinfo,gw_ins->p1_over_under[pinfo->orig_port_id]);
            if (entry->hw_entry == NULL) {
                DOCA_LOG_DBG("failed to offload");
                return -1;
            }
            entry->is_hw = true;
            break;
        case GW_CLS_OL_TO_OL:
            if (!gw_ft_add_new(gw_ins->ft, pinfo,ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            entry = (struct gw_entry *) &(*ctx)->data[0];
            entry->hw_entry = gw_pipeline_add_ol_to_ol_entry(pinfo,gw_ins->p1_over_under[pinfo->orig_port_id]);
            if (entry->hw_entry == NULL) {
                DOCA_LOG_DBG("failed to offload");
                return -1;
            }
            entry->is_hw = true;

            // add flow to pipeline
            break;
        case GW_BYPASS_L4:
            if (!gw_ft_add_new(gw_ins->ft, pinfo,ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            break; 
        default:
            DOCA_LOG_WARN("BYPASS");
            return -1;
    }
    return 0;
}

static
void gw_handle_packet(struct app_pkt_info *pinfo)
{
    struct gw_ft_user_ctx *ctx = NULL;
    struct gw_entry *entry;

    if(!gw_ft_find(gw_ins->ft, pinfo, &ctx)){
        if (gw_handle_new_flow(pinfo,&ctx)) {
            return;
        }
    }
    entry = (struct gw_entry *) &ctx->data[0];
    entry->total_pkts++;
    DOCA_LOG_DBG("total packets %d",entry->total_pkts);
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
        struct app_pkt_info pinfo;

	while (!force_quit) {
            for (port_id = 0; port_id < 2; port_id++) { 
                for (i = 0; i < nr_queues; i++) {
                    nb_rx = rte_eth_rx_burst(port_id, i, mbufs, GW_RX_BURST_SIZE);
                    if (nb_rx) {
                        for (j = 0; j < nb_rx; j++) {
                            memset(&pinfo,0, sizeof(struct app_pkt_info)); 
                            if(!gw_parse_packet(GW_PKT_L2(mbufs[j]),GW_PKT_LEN(mbufs[j]), &pinfo)){
                                pinfo.orig_port_id = mbufs[j]->port;
                                if (pinfo.outer.l3_type == 4) {
                                    gw_handle_packet(&pinfo);
                                    //gw_parse_pkt_str(&pinfo, strbuff,DEBUG_BUFF_SIZE);
                                    //printf("got mbuf on port == %d,\n %s", m->port,strbuff);
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

static int init_doca(void)
{
    int ret = 0;

    struct gw_port_cfg cfg_port0 = { .n_queues = 4, .port_id = 0 };
    struct gw_port_cfg cfg_port1 = { .n_queues = 4, .port_id = 1 };
    struct doca_gw_error err = {0};

    struct doca_gw_cfg cfg = {GW_MAX_FLOWS};
    if (doca_gw_init(&cfg,&err)) { 
        DOCA_LOG_ERR("failed to init doca:%s",err.message);
        return -1;
    }

    // adding ports
    gw_ins->port0 = gw_init_doca_port(&cfg_port0);
    gw_ins->port1 = gw_init_doca_port(&cfg_port1);

    if (gw_ins->port0 == NULL || gw_ins->port1 == NULL) {
        DOCA_LOG_ERR("failed to start port %s",err.message);
        return ret;
    }

    // overlay to unserlay pipeline
    gw_ins->p1_over_under[0] = gw_init_ol_to_ul_pipeline(gw_ins->port0);
    gw_ins->p1_over_under[1] = gw_init_ol_to_ul_pipeline(gw_ins->port1);

    return ret;
}

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


static int init_gw(void)
{
    

    gw_ins = (struct ex_gw *) malloc(sizeof(struct ex_gw));
    if ( gw_ins == NULL ) {
        DOCA_LOG_CRIT("failed to allocate GW");
        goto fail_init;
    }
    
    memset(gw_ins, 0, sizeof(struct ex_gw));
    gw_ins->ft = gw_ft_create(GW_MAX_FLOWS , sizeof(struct gw_entry), &gw_aged_flow_cb);
    if ( gw_ins->ft == NULL )
        goto fail_init;
    
    if (init_doca()){
        goto fail_init;
    }

    gw_init();
    return 0;
fail_init:
    if (gw_ins->ft != NULL)
        free(gw_ins->ft);
    if (gw_ins != NULL) 
        free(gw_ins);
    gw_ins = NULL;
    return -1;
}

int
main(int argc, char **argv)
{
	if (init_dpdk(argc , argv)) {
            rte_exit(EXIT_FAILURE, "Cannot init dpdk\n");
            return -1;
        }

	gw_init_port(0, nr_queues);
	gw_init_port(1, nr_queues);

        DOCA_LOG_INFO("starting doca\n");
        if (init_gw()){
            rte_exit(EXIT_FAILURE,"failed to init doca");
        }
        DOCA_LOG_INFO("GW initiated!\n");

        ph = doca_pcap_file_start(pcap_file_name);

	gw_process_pkts();

	return 0;
}
