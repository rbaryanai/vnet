#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw.h"
#include "doca_vnf.h"
#include "doca_gw.h"
#include "doca_utils.h"
#include "doca_log.h"
#include "doca_fib.h"
#include "doca_ft.h"

#include <arpa/inet.h>
#include "rte_ether.h"
#include "rte_mbuf.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_gre.h"
#include "rte_vxlan.h"

DOCA_LOG_MODULE(GW)

#define GW_MAC_STR_FMT "%x:%x:%x:%x:%x:%x"
#define GW_MAC_EXPAND(b) b[0],b[1],b[2],b[3],b[4],b[5]
#define GW_IPV4_STR_FMT "%d:%d:%d:%d"
#define GW_IPV4_EXPAND(b) b[0],b[1],b[2],b[3]
#define GW_MAX_PORT_ID  (2)
#define GW_NEXT_HOPS_NUM  (16)
#define GW_NUM_OF_PORTS (2)
#define GW_MAX_FLOWS (4096)

static void gw_aged_flow_cb(struct doca_ft_user_ctx *ctx);


struct gw_next_hop {
    uint32_t ip;
    uint32_t vni;
};

struct gw_slb {
    uint32_t round_robin_idx;
    int size;
    struct doca_fib_tbl *gw_fib_tbl;
    struct gw_next_hop nodes[GW_NEXT_HOPS_NUM];
};

struct ex_gw {
    struct doca_ft *ft;

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
};

struct ex_gw *gw_ins;




static struct gw_slb *gw_slb;
static void gw_slb_set_next_node(uint32_t *node_ip, uint32_t *node_vni) 
{
    gw_slb->round_robin_idx++;
    gw_slb->round_robin_idx %= gw_slb->size;
    *node_ip  = gw_slb->nodes[gw_slb->round_robin_idx].ip; 
    *node_vni = gw_slb->nodes[gw_slb->round_robin_idx].vni; 
}

static uint16_t gw_slb_peer_port(uint16_t port_id)
{
    return port_id == 0?1:0;
}


struct doca_fwd_tbl *sw_rss_fwd_tbl_port[GW_MAX_PORT_ID];
struct doca_fwd_tbl *fwd_tbl_port[GW_MAX_PORT_ID];

static
struct doca_fwd_tbl *gw_build_port_fwd(int port_id)
{
    struct doca_fwd_table_cfg cfg = { .type = DOCA_FWD_PORT};
    cfg.port.id = port_id;
    return doca_gw_create_fwd_tbl(&cfg);
}


static
struct doca_fwd_tbl *gw_build_rss_fwd(int n_queues)
{
    int i;
    struct doca_fwd_table_cfg cfg = {0};
    uint16_t *queues;

    queues = malloc(sizeof(uint16_t) * n_queues);

    for(i = 0 ; i < n_queues ; i++){
        queues[i] = i;
    }

    cfg.type = DOCA_FWD_RSS;
    cfg.rss.queues = queues;
    cfg.rss.num_queues = n_queues;
    return doca_gw_create_fwd_tbl(&cfg);
}

static void gw_build_underlay_overlay_match(struct doca_gw_match *match)
{
    match->out_dst_ip.a.ipv4_addr = 0xffffffff;
    match->out_dst_ip.type = DOCA_IPV4;
    match->out_l3_type = DOCA_IPV4;
    match->out_dst_port = rte_be_to_cpu_16(4789); // VXLAN (change to enum/define)


    match->tun.type = DOCA_TUN_VXLAN;
    match->tun.vxlan.tun_id = 0xffffffff;

    //inner
    match->in_dst_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.type = DOCA_IPV4;
    match->in_l3_type = 0xff;

    match->in_src_port = 0xffff;
    match->in_dst_port = 0xffff;
}

static void gw_build_decap_inner_modify_actions(struct doca_gw_actions *actions)
{
    // chaning destination ip of inner packet (after decap)
    actions->decap = true;
    actions->mod_dst_ip.a.ipv4_addr = 0xffffffff;
}

static void gw_build_encap_actions(struct doca_gw_actions *actions)
{
    actions->encap.in_src_ip.a.ipv4_addr = doca_inline_parse_ipv4("13.0.0.13");;
    actions->encap.in_dst_ip.a.ipv4_addr = 0xffffffff;
    actions->encap.tun.type = DOCA_TUN_VXLAN;
    memset(actions->encap.src_mac,0xff, sizeof(actions->encap.src_mac));
    memset(actions->encap.dst_mac,0xff, sizeof(actions->encap.src_mac));

    actions->encap.tun.vxlan.tun_id = 0xffffffff;
}

static void gw_fill_monior(struct doca_gw_monitor *monitor)
{
    monitor->count = true;
}

static struct doca_gw_pipeline *gw_build_underlay_overlay(struct doca_gw_port *port)
{
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pipe_cfg = {0};
    struct doca_gw_error err = {0};
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = {0};

    gw_build_underlay_overlay_match(&match);
    gw_build_decap_inner_modify_actions(&actions);
    gw_fill_monior(&monitor);

    pipe_cfg.name   = "overlay-to-underlay";
    pipe_cfg.port   = port;
    pipe_cfg.match  = &match;
    pipe_cfg.actions = &actions;
    pipe_cfg.monitor = &monitor;
    pipe_cfg.count  = false;

    return doca_gw_create_pipe(&pipe_cfg,&err);
}

static struct doca_gw_pipeline *gw_build_overlay_to_overlay(struct doca_gw_port *port)
{   
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pipe_cfg = {0};
    struct doca_gw_error err = {0};
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = {0};

    gw_build_underlay_overlay_match(&match);
    gw_build_decap_inner_modify_actions(&actions);
    gw_build_encap_actions(&actions);
    gw_fill_monior(&monitor);

    pipe_cfg.name   = "overlay-to-overlay";
    pipe_cfg.port   = port;
    pipe_cfg.match  = &match;
    pipe_cfg.actions = &actions;
    pipe_cfg.monitor = &monitor;
    pipe_cfg.count  = false;

    return doca_gw_create_pipe(&pipe_cfg,&err);
}

static int gw_print_eth(uint8_t *data,char *str, int len)
{
    int off = 0;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *) data;

    off += snprintf(str+off, len-off, "ETH DST:"GW_MAC_STR_FMT,GW_MAC_EXPAND(((uint8_t *)&eth->d_addr)));
    off += snprintf(str+off, len-off, ", SRC:"GW_MAC_STR_FMT"\n",GW_MAC_EXPAND(((uint8_t *)&eth->s_addr)));
    return off;
}

static int gw_print_ipv4(uint8_t *data,char *str, int len)
{
    int off = 0;
    struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *) data;
    off += snprintf(str+off, len-off, "IP SRC:"GW_IPV4_STR_FMT,GW_IPV4_EXPAND(((uint8_t *)&iphdr->dst_addr)));
    off += snprintf(str+off, len-off, ", IP DST:"GW_IPV4_STR_FMT"\n",GW_IPV4_EXPAND(((uint8_t *)&iphdr->src_addr)));
    return off;
}

int gw_parse_pkt_str(struct doca_pkt_info *pinfo, char *str, int len)
{
    int off = 0;
    if(!pinfo)
        return -1;

    off+=gw_print_eth(pinfo->outer.l2, str, len);
    if ( pinfo->outer.l3_type != 4){
        return off;
    }

    off+=gw_print_ipv4(pinfo->outer.l3, str + off, len - off);

    switch(pinfo->tun_type){
        case APP_TUN_VXLAN:
            off+=snprintf(str+off,len-off,"TUNNEL:VXLAN\n");
            break;
        default:
            break;

    }
    if ( pinfo->inner.l3_type != 4){
        return off;
    }

    off+=gw_print_ipv4(pinfo->inner.l3, str + off, len - off);

    return off;
}
/**
 * @brief - decides about the type of the packet.
 *  which pipeline should be exeuted
 *
 * @param pinfo
 *
 * @return 
 */
enum gw_classification gw_classifiy_pkt(struct doca_pkt_info *pinfo)
{
    struct rte_ipv4_hdr *ipv4hdr;
    if (pinfo->tun_type != APP_TUN_VXLAN) {
        switch(pinfo->outer.l4_type) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
            case IPPROTO_ICMP:
                return GW_BYPASS_L4;
        }
        return GW_BYPASS;
    }

    // ip prefix of 11.0.0.0/24 goes to underlay
    ipv4hdr = (struct rte_ipv4_hdr *) pinfo->outer.l3;
    if ((ipv4hdr->dst_addr & rte_cpu_to_be_32(0xff000000)) == rte_cpu_to_be_32(0x0b000000)){
        DOCA_LOG_DBG("classified as overlay to underlay");
        return GW_CLS_OL_TO_UL;
    }

    return GW_CLS_OL_TO_OL;
}

struct doca_gw_pipeline *gw_init_ol_to_ul_pipeline(struct doca_gw_port *p)
{
    struct doca_gw_pipeline *pl;

    pl = gw_build_underlay_overlay(p);

    if ( pl == NULL) {
        DOCA_LOG_ERR("failed to allocate pipeline\n");
        return pl;
    }

    return pl;
}

struct doca_gw_pipeline *gw_init_ol_to_ol_pipeline(struct doca_gw_port *p)
{
    struct doca_gw_pipeline *pl;

    pl = gw_build_overlay_to_overlay(p);

    if ( pl == NULL) {
        DOCA_LOG_ERR("failed to allocate pipeline\n");
        return pl;
    }

    return pl;
}


struct doca_gw_port *gw_init_doca_port(struct gw_port_cfg *port_cfg)
{
#define GW_MAX_PORT_STR (128)
    char port_id_str[GW_MAX_PORT_STR];
    struct doca_gw_port_cfg doca_cfg_port; 
    struct doca_gw_port *port;
    struct doca_gw_error err = {0};

    snprintf(port_id_str, GW_MAX_PORT_STR,"%d",port_cfg->port_id);

    doca_cfg_port.type = DOCA_GW_PORT_DPDK_BY_ID;
    doca_cfg_port.queues = port_cfg->n_queues;
    doca_cfg_port.devargs = port_id_str;
    doca_cfg_port.priv_data_size = sizeof(struct gw_port_cfg);

    if (port_cfg->port_id >= GW_MAX_PORT_ID) {
        DOCA_LOG_ERR("port id exceeds max ports id:%d",GW_MAX_PORT_ID);
        return NULL;
    }

    // adding ports
    port = doca_gw_port_start(&doca_cfg_port, &err);

    if (port == NULL) {
        DOCA_LOG_ERR("failed to start port %s",err.message);
        return NULL;
    }

    *((struct gw_port_cfg *)doca_gw_port_priv_data(port)) = *port_cfg;
    sw_rss_fwd_tbl_port[port_cfg->port_id] = gw_build_rss_fwd(port_cfg->n_queues);
    fwd_tbl_port[port_cfg->port_id] = gw_build_port_fwd(port_cfg->port_id);

    return port;
}

struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ul_entry(struct doca_pkt_info *pinfo,
                                                             struct doca_gw_pipeline *pipeline)
{
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = {0};
    struct doca_gw_error err = {0};

    if (pinfo->outer.l3_type != GW_IPV4) {
        DOCA_LOG_WARN("IPv6 not supported");
        return NULL;
    }

    /* exact match on dst ip and vni */
    match.out_dst_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_dst(pinfo);
    match.tun.vxlan.tun_id = pinfo->tun.vni;

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_src(pinfo);
    match.in_l3_type = pinfo->inner.l4_type;
    match.in_src_port = doca_pinfo_inner_src_port(pinfo);
    match.in_dst_port = doca_pinfo_inner_dst_port(pinfo);

    actions.mod_dst_ip.a.ipv4_addr = (doca_pinfo_inner_ipv4_dst(pinfo) & rte_cpu_to_be_32(0x00ffffff))
                                    | rte_cpu_to_be_32(0x25000000); // change dst ip


    //TODO: add context
    return doca_gw_pipeline_add_entry(0, pipeline, &match, &actions, &monitor,
                                      sw_rss_fwd_tbl_port[pinfo->orig_port_id], &err);
}


struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ol_entry(struct doca_pkt_info *pinfo, struct doca_gw_pipeline *pipeline)
{
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = {0};
    struct doca_gw_error err = {0};

    if (pinfo->outer.l3_type != GW_IPV4) {
        DOCA_LOG_WARN("IPv6 not supported");
        return NULL;
    }

    /* exact match on dst ip and vni */
    match.out_dst_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_dst(pinfo);
    match.tun.vxlan.tun_id = pinfo->tun.vni;

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_src(pinfo);
    match.in_l3_type = pinfo->inner.l4_type;
    match.in_src_port = doca_pinfo_inner_src_port(pinfo);
    match.in_dst_port = doca_pinfo_inner_dst_port(pinfo);

    actions.mod_dst_ip.a.ipv4_addr = (doca_pinfo_inner_ipv4_dst(pinfo) & rte_cpu_to_be_32(0x00ffffff))
                                    | rte_cpu_to_be_32(0x25000000); // change dst ip

    /* encap:
     * choose next node in round robin, ip and vni
     * */
    gw_slb_set_next_node(&actions.encap.in_dst_ip.a.ipv4_addr, &actions.encap.tun.vxlan.tun_id);
    actions.encap.tun.type = DOCA_TUN_VXLAN;

    /* set chosen node mac address using fib tbl */
    if (!doca_lookup_fib_tbl_entry(gw_slb->gw_fib_tbl,&actions.encap.in_dst_ip.a.ipv4_addr,
                                   actions.encap.dst_mac)) {
        DOCA_LOG_ERR("no mac address for ip ");
        return NULL;
    }
    //TODO: add src port mac
    memset(actions.encap.src_mac,0xff, sizeof(actions.encap.src_mac));

    return doca_gw_pipeline_add_entry(0, pipeline, &match, &actions, &monitor,
            fwd_tbl_port[gw_slb_peer_port(pinfo->orig_port_id)], &err);
}


void gw_rm_pipeline_entry(struct doca_gw_pipelne_entry *entry)
{
   doca_gw_rm_entry(0,entry);
}


static int gw_alloc_instance(void)
{
    gw_ins = (struct ex_gw *) malloc(sizeof(struct ex_gw));
    if ( gw_ins == NULL ) {
        DOCA_LOG_CRIT("failed to allocate GW");
        goto fail_init;
    }
    
    memset(gw_ins, 0, sizeof(struct ex_gw));
    gw_ins->ft = doca_ft_create(GW_MAX_FLOWS , sizeof(struct gw_entry), &gw_aged_flow_cb);
    if ( gw_ins->ft == NULL )
        goto fail_init;
    
    return 0;
fail_init:
    if (gw_ins->ft != NULL)
        free(gw_ins->ft);
    if (gw_ins != NULL) 
        free(gw_ins);
    gw_ins = NULL;
    return -1;
}

static int ex_gw_init(void)
{

    int ret = 0;

    struct gw_port_cfg cfg_port0 = { .n_queues = 4, .port_id = 0 };
    struct gw_port_cfg cfg_port1 = { .n_queues = 4, .port_id = 1 };
    struct doca_gw_error err = {0};

    struct doca_gw_cfg cfg = {GW_MAX_FLOWS};
    gw_alloc_instance();
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

int gw_init(void)
{
    int i;
    ex_gw_init();
    gw_slb = (struct gw_slb*) malloc(sizeof(struct gw_slb));
    if (gw_slb == NULL) {
        DOCA_LOG_ERR("failed to alloc slb");
        return -1;
    }
    memset(gw_slb,0,sizeof(struct gw_slb));
    gw_slb->size = GW_NEXT_HOPS_NUM; 
    gw_slb->gw_fib_tbl = doca_create_fib_tbl(1024);
    if (gw_slb->gw_fib_tbl == NULL) {
        DOCA_LOG_ERR("failed to alloc slb fib tbl");
        return -1;
    }
 
    for( i = 0; i < gw_slb->size ; i++){ 
#define SLB_IP_BUFF_SIZE 255
        uint32_t ip;
        char ip_str[SLB_IP_BUFF_SIZE];
        snprintf(ip_str,0,"13.0.0.%d",i);
        uint8_t mac[6] = {0x1,0x2,0x3,0x40,0x5,0x6};
        mac[5] = 0x6 + i;
        ip = doca_inline_parse_ipv4(ip_str);
        doca_add_fib_tbl_entry(gw_slb->gw_fib_tbl, &ip,mac);
        gw_slb->nodes[i].ip = ip;
    }
    return 0;
}

static int gw_destroy(void)
{
    return 0;
}

/**
 * @brief - called when flow is aged out in FT.
 *
 * @param ctx
 */
static 
void gw_aged_flow_cb(struct doca_ft_user_ctx *ctx)
{
    struct gw_entry *entry = (struct gw_entry *) &ctx->data[0];
    if (entry->is_hw) {
        gw_rm_pipeline_entry(entry->hw_entry);
    }
}

static
int gw_handle_new_flow(struct doca_pkt_info *pinfo, struct doca_ft_user_ctx **ctx)
    
{
    struct gw_entry *entry;
    enum gw_classification cls = gw_classifiy_pkt(pinfo);
    
    switch(cls) {
        case GW_CLS_OL_TO_UL:
            if (!doca_ft_add_new(gw_ins->ft, pinfo,ctx)) {
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
            if (!doca_ft_add_new(gw_ins->ft, pinfo,ctx)) {
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
            if (!doca_ft_add_new(gw_ins->ft, pinfo,ctx)) {
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
int gw_handle_packet(struct doca_pkt_info *pinfo)
{
    struct doca_ft_user_ctx *ctx = NULL;
    struct gw_entry *entry;

    if(!doca_ft_find(gw_ins->ft, pinfo, &ctx)){
        if (gw_handle_new_flow(pinfo,&ctx)) {
            return -1;
        }
    }
    entry = (struct gw_entry *) &ctx->data[0];
    entry->total_pkts++;
    return 0;
}

struct doca_vnf gw_vnf = {
    .doca_vnf_init = &gw_init,
    .doca_vnf_process_pkt = &gw_handle_packet,
    .doca_vnf_destroy = &gw_destroy
};


struct doca_vnf *gw_get_doca_vnf(void)
{
    return &gw_vnf;
}

