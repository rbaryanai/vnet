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

#define SLB_IP_BUFF_SIZE 255
#define GW_MAX_PORT_ID  (2)
#define GW_NEXT_HOPS_NUM  (16)
#define GW_NUM_OF_PORTS (2)
#define GW_MAX_FLOWS (4096)
#define GW_MAX_PIPE_CLS (16)

#define GW_MASK_24 rte_cpu_to_be_32(0xff000000)

#define GW_FILL_MATCH(ENTRY, IP, IPV, TUN, MASK, CLS) \
                                             ENTRY.ip = doca_inline_parse_ipv4(IP); \
                                             ENTRY.mask = MASK; \
                                             ENTRY.used = true; \
                                             ENTRY.cls = CLS; \
                                             ENTRY.ipv = IPV; \
                                             ENTRY.tun = TUN;

#define GW_MATCH_EQUAL(ENTRY, P)  ((P->dst_addr & ENTRY.mask) == ENTRY.ip)

#define GW_DEFAULT_CIR (100000000/8)
#define GW_DEFAULT_CBS (GW_DEFAULT_CIR << 4)

static enum doca_gw_tun_type gw_tun_type = DOCA_TUN_GRE;

static void gw_aged_flow_cb(struct doca_ft_user_ctx *ctx);
static void gw_hw_aging_cb(void);
static int gw_init_lb(int ret);

struct gw_next_hop {
    uint32_t ip;
    uint32_t vni;
};

struct gw_ipv4_match {
    bool     used;
    uint16_t tun;
    uint8_t  ipv;
    uint32_t ip;
    uint32_t mask;
    enum gw_classification cls;
};

struct gw_slb {
    uint32_t round_robin_idx;
    int size;
    struct gw_next_hop nodes[GW_NEXT_HOPS_NUM];
};

struct ex_gw {
    struct doca_ft *ft;

    struct doca_gw_port *port0; 
    struct doca_gw_port *port1; 
    struct gw_slb slb;                 /* Service Load Balancer */
    struct doca_fib_tbl *gw_fib_tbl;   /* GW fib table */

    /* for classificaiton purpose */
    struct gw_ipv4_match cls_match[GW_MAX_PIPE_CLS];
    /* pipelines */
    struct doca_gw_pipeline *p_over_under[GW_NUM_OF_PORTS];
    struct doca_gw_pipeline *p_ol_ol[GW_NUM_OF_PORTS];
};

struct gw_entry {
    int total_pkts;
    int total_bytes;
    enum gw_classification cls;
    bool is_hw;
    struct doca_gw_pipelne_entry *hw_entry;
};

struct ex_gw *gw_ins;

/**
 * @brief - load balancing between nodes.
 *          policy it round robin
 *
 * @param node_ip
 * @param node_vni
 */
static void gw_slb_set_next_node(uint32_t *node_ip, uint32_t *node_vni) 
{
    struct gw_slb *cslb = &gw_ins->slb;
    cslb->round_robin_idx++;
    cslb->round_robin_idx %= cslb->size;
    *node_ip  = cslb->nodes[cslb->round_robin_idx].ip; 
    *node_vni = cslb->nodes[cslb->round_robin_idx].vni; 
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


static struct doca_fwd_tbl *gw_build_rss_fwd(int n_queues)
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
	cfg.rss.rss_flags = DOCA_RSS_IP | DOCA_RSS_UDP | DOCA_RSS_IP;
    cfg.rss.num_queues = n_queues;
    return doca_gw_create_fwd_tbl(&cfg);
}

static
void gw_build_tun_match(struct doca_gw_match *match)
{
    switch (gw_tun_type) {
        case DOCA_TUN_VXLAN:
            match->out_l4_type = IPPROTO_UDP;
            match->out_dst_port = rte_cpu_to_be_16(DOCA_VXLAN_DEFAULT_PORT); // VXLAN (change to enum/define)
            match->tun.type = DOCA_TUN_VXLAN;
            match->tun.vxlan.tun_id = 0xffffffff;
            break;
        case DOCA_TUN_GRE:
            match->out_l4_type = IPPROTO_GRE;
            match->tun.type = DOCA_TUN_GRE;
            match->tun.vxlan.tun_id = 0xffffffff;
            break;
        default:
            DOCA_LOG_ERR("unsupported tun type");

    }
}

/**
 * @brief - define a template that match on the following:
 *     
 *     vxlan packet on default port (and ipv4)
 *     some fields are dont care, such as src port and src ip
 *     of the vxlan.
 *
 * @param match
 */
static void gw_build_match_tun_and_5tuple(struct doca_gw_match *match)
{
    match->out_dst_ip.a.ipv4_addr = 0xffffffff;
    match->out_dst_ip.type = DOCA_IPV4;
    gw_build_tun_match(match);

    //inner
    match->in_dst_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.type = DOCA_IPV4;
    match->in_l4_type = 0x6;

    match->in_src_port = 0xffff;
    match->in_dst_port = 0xffff;
}

static void gw_build_decap_inner_modify_actions(struct doca_gw_actions *actions)
{
    // chaning destination ip of inner packet (after decap)
    actions->decap = true;
	//test cover all fields.
    //actions->mod_src_ip.a.ipv4_addr = 0xffffffff;
    actions->mod_dst_ip.a.ipv4_addr = 0xffffffff;
    //actions->mod_src_port = 0xffff;
    //actions->mod_dst_port = 0xffff;
}

static void gw_build_encap_tun(struct doca_gw_actions *actions)
{
    switch(gw_tun_type) {
        case DOCA_TUN_VXLAN:
            actions->encap.tun.type = DOCA_TUN_VXLAN;
            actions->encap.tun.vxlan.tun_id = 0xffffffff;
            break;
        case DOCA_TUN_GRE:
            actions->encap.tun.type = DOCA_TUN_GRE;
            actions->encap.tun.gre.key = 0xffffffff;
            break;
        default:
            DOCA_LOG_ERR("unsupported tunnel type %d",gw_tun_type);

    }
}

static void gw_build_encap_actions(struct doca_gw_actions *actions)
{
    actions->encap.in_src_ip.a.ipv4_addr = doca_inline_parse_ipv4("13.0.0.13");
    actions->encap.in_dst_ip.a.ipv4_addr = 0xffffffff;

    memset(actions->encap.src_mac,0xff, sizeof(actions->encap.src_mac));
    memset(actions->encap.dst_mac,0xff, sizeof(actions->encap.src_mac));

    gw_build_encap_tun(actions);
}

static void gw_fill_monior(struct doca_gw_monitor *monitor)
{
    monitor->count = true;
}

/**
 * @brief - build the underlay to overlay pipeline  
 *          match: (ip,tun),(5 tuple)
 *          actions: - decap
 *                   - change dst ip
 *          monitor: - count
 *
 * @param port
 *
 * @return 
 */
static struct doca_gw_pipeline *gw_build_ul_ol(struct doca_gw_port *port)
{
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pipe_cfg = {0};
    struct doca_gw_error err = {0};
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = { .m.cbs = UINT64_MAX,.m.cir = UINT64_MAX};

    gw_build_match_tun_and_5tuple(&match);
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

/**
 * @brief match:   on tunnel dst + inner 5-tuple
 *        actions: decap
 *                 change destination ip
 *                 encap (according to serving node)
 *                 monitor count
 *
 * @param port
 *
 * @return 
 */
static struct doca_gw_pipeline *gw_build_ol_to_ol(struct doca_gw_port *port)
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

    gw_build_match_tun_and_5tuple(&match);
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

/**
 * @brief - decides about the type of the packet.
 *  which pipeline should be exeuted.
 *
 *  if port 0 to port 1 and dst ip = 13.0.0.0/24 overlay to overlay
 *
 * @param pinfo
 *
 * @return 
 */
enum gw_classification gw_classifiy_pkt(struct doca_pkt_info *pinfo)
{
    struct rte_ipv4_hdr *ipv4hdr;
    int i = 0;

    /* unexpected none tunneled packets are ignored */
    if (pinfo->tun_type == APP_TUN_NONE) {
        switch(pinfo->outer.l4_type) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
            case IPPROTO_ICMP:
                return GW_BYPASS_L4;
        }
        return GW_BYPASS;
    }
    
    ipv4hdr = (struct rte_ipv4_hdr *) pinfo->outer.l3;
    for ( i = 0 ; i < GW_MAX_PIPE_CLS && gw_ins->cls_match[i].used ; i++) {
        if (GW_MATCH_EQUAL(gw_ins->cls_match[i], ipv4hdr)) {
                return gw_ins->cls_match[i].cls;
        }
    }

    return GW_CLS_OL_TO_OL;
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

static void gw_pipeline_set_entry_tun(struct doca_gw_match *match, 
                                struct doca_pkt_info *pinfo)
{
    switch (gw_tun_type) {
        case DOCA_TUN_VXLAN:
            match->tun.type = DOCA_TUN_VXLAN; 
            match->tun.vxlan.tun_id = pinfo->tun.vni;
            break;
        case DOCA_TUN_GRE:
            match->tun.type = DOCA_TUN_GRE; 
            match->tun.gre.key = pinfo->tun.vni;
            break;
        default:
            DOCA_LOG_ERR("unexpected gw_tun_type %d",gw_tun_type);
    }
}

/**
 * @brief - create entry on overlay to underlay pipeline
 *
 * @param pinfo
 * @param pipeline
 *
 * @return 
 */
struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ul_entry(struct doca_pkt_info *pinfo,
                                                             struct doca_gw_pipeline *pipeline)
{
    struct doca_gw_match match = {0};
    struct doca_gw_actions actions = {0};
    struct doca_gw_monitor monitor = { .m.cbs = GW_DEFAULT_CBS, .m.cir = GW_DEFAULT_CIR};
    struct doca_gw_error err = {0};

    if (pinfo->outer.l3_type != GW_IPV4) {
        DOCA_LOG_WARN("IPv6 not supported");
        return NULL;
    }

    /* exact match on dst ip and vni */
    match.out_dst_ip.a.ipv4_addr = doca_pinfo_outer_ipv4_dst(pinfo);
    gw_pipeline_set_entry_tun(&match,pinfo);

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_src(pinfo);
    match.in_l4_type = pinfo->inner.l4_type;
    match.in_src_port = doca_pinfo_inner_src_port(pinfo);
    match.in_dst_port = doca_pinfo_inner_dst_port(pinfo);

    actions.mod_dst_ip.a.ipv4_addr = (doca_pinfo_inner_ipv4_dst(pinfo) & rte_cpu_to_be_32(0x00ffffff))
                                    | rte_cpu_to_be_32(0x25000000); // change dst ip
    //DELELTE
    //for test all field
    //actions.mod_src_ip.a.ipv4_addr = rte_cpu_to_be_32(((192<<24) + (168<<16) + (1<<8) + 1));
    //actions.mod_dst_port = rte_cpu_to_be_16(0x1234); 
    //actions.mod_src_port = rte_cpu_to_be_16(0x4321);
    //TODO: add context
    monitor.flags |= DOCA_GW_METER;
    monitor.m.cir = 100 * 1000 / 8;// 100k
    monitor.m.cbs = monitor.m.cir / 8;
    return doca_gw_pipeline_add_entry(0, pipeline, &match, &actions, &monitor,
                                      sw_rss_fwd_tbl_port[pinfo->orig_port_id], &err);
}


struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ol_entry(struct doca_pkt_info *pinfo,
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
    gw_pipeline_set_entry_tun(&match, pinfo);

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = doca_pinfo_inner_ipv4_src(pinfo);
    match.in_l4_type = pinfo->inner.l4_type;
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
    if (!doca_lookup_fib_tbl_entry(gw_ins->gw_fib_tbl,&actions.encap.in_dst_ip.a.ipv4_addr,
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

static int gw_create(void)
{
    gw_ins = (struct ex_gw *) malloc(sizeof(struct ex_gw));
    if ( gw_ins == NULL ) {
        DOCA_LOG_CRIT("failed to allocate GW");
        goto fail_init;
    }
    
    memset(gw_ins, 0, sizeof(struct ex_gw));
    gw_ins->ft = doca_ft_create(GW_MAX_FLOWS , sizeof(struct gw_entry), 
                                &gw_aged_flow_cb, &gw_hw_aging_cb);
    if ( gw_ins->ft == NULL ) {
        DOCA_LOG_CRIT("failed to allocate FT");
        goto fail_init;
    }
    
    return 0;
fail_init:
    if (gw_ins->ft != NULL)
        free(gw_ins->ft);
    if (gw_ins != NULL) 
        free(gw_ins);
    gw_ins = NULL;
    return -1;
}

static int gw_init_doca_ports_and_pipes(int ret, int nr_queues)
{
    struct gw_port_cfg cfg_port0 = { .n_queues = nr_queues, .port_id = 0 };
    struct gw_port_cfg cfg_port1 = { .n_queues = nr_queues, .port_id = 1 };

    struct doca_gw_error err = {0};
    struct doca_gw_cfg cfg = {GW_MAX_FLOWS};
    if (ret) {
        return ret;
    }
    /* init doca framework */
    if (doca_gw_init(&cfg,&err)) { 
        DOCA_LOG_ERR("failed to init doca:%s",err.message);
        return -1;
    }

    /* define doca ports */
    gw_ins->port0 = gw_init_doca_port(&cfg_port0);
    gw_ins->port1 = gw_init_doca_port(&cfg_port1);

    if (gw_ins->port0 == NULL || gw_ins->port1 == NULL) {
        DOCA_LOG_ERR("failed to start port %s",err.message);
        return -1;
    }

    /* TBD: this should be read from file */
    /* init classification */
    /* overlay to overlay match */
    GW_FILL_MATCH(gw_ins->cls_match[0],"13.0.0.0",4,APP_TUN_VXLAN,
                                       GW_MASK_24, GW_CLS_OL_TO_OL);
    GW_FILL_MATCH(gw_ins->cls_match[1],"14.0.0.0",4,APP_TUN_VXLAN,
                                       GW_MASK_24, GW_CLS_OL_TO_OL);
    GW_FILL_MATCH(gw_ins->cls_match[2],"15.0.0.0",4,APP_TUN_VXLAN,
                                       GW_MASK_24, GW_CLS_OL_TO_UL);
    GW_FILL_MATCH(gw_ins->cls_match[3],"0.0.0.0",4,APP_TUN_NONE,
                                       0, GW_BYPASS_L4);

    /* init pipelines */
    /* overlay to under lay pipeline */
    gw_ins->p_over_under[0] = gw_build_ul_ol(gw_ins->port0);
    gw_ins->p_over_under[1] = gw_build_ul_ol(gw_ins->port1);

    gw_ins->p_ol_ol[0] = gw_build_ol_to_ol(gw_ins->port0);
    gw_ins->p_ol_ol[1] = gw_build_ol_to_ol(gw_ins->port1);

    return 0;
}

static int gw_init_lb(int ret)
{
    int i;

    /* allready failed before stop init */
    if(ret) {
        return ret;
    } 

    gw_ins->slb.size = GW_NEXT_HOPS_NUM; 
    gw_ins->gw_fib_tbl = doca_create_fib_tbl(1024);
    if (gw_ins->gw_fib_tbl == NULL) {
        DOCA_LOG_ERR("failed to alloc slb fib tbl");
        return -1;
    }
 
    // TBD: Load Balance should be read from file
    // or have a CLI
    for( i = 0; i < gw_ins->slb.size ; i++){ 
        uint32_t ip;
        char ip_str[SLB_IP_BUFF_SIZE];
        snprintf(ip_str,0,"13.0.0.%d",i);
        uint8_t mac[6] = {0x1,0x2,0x3,0x40,0x5,0x6};
        mac[5] = 0x6 + i;
        ip = doca_inline_parse_ipv4(ip_str);
        doca_add_fib_tbl_entry(gw_ins->gw_fib_tbl, &ip,mac);
        gw_ins->slb.nodes[i].ip = ip;
    }
    return 0;
}

static int gw_init(void *p)
{
    int queues = *((int *)p);
    int ret = 0;

    ret |= gw_create();
    ret |= gw_init_lb(ret);
    ret |= gw_init_doca_ports_and_pipes(ret, queues);

    return ret;
}

//TBD: clean all
static int gw_destroy(void)
{

    doca_ft_destroy(gw_ins->ft);
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
        entry->hw_entry = NULL;
    }
}

/**
 * @brief - when called from FT,
 *  aging context can be used here to clean HW flows.
 */
static void gw_hw_aging_cb(void)
{

}

static
int gw_handle_new_flow(struct doca_pkt_info *pinfo, struct doca_ft_user_ctx **ctx)
    
{
    struct gw_entry *entry = NULL;
    enum gw_classification cls = gw_classifiy_pkt(pinfo);
    
    switch(cls) {
        case GW_CLS_OL_TO_UL:
            DOCA_LOG_INFO("adding entry ol to ul");
            if (!doca_ft_add_new(gw_ins->ft, pinfo, ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            entry = (struct gw_entry *) &(*ctx)->data[0];
            entry->hw_entry = gw_pipeline_add_ol_to_ul_entry(pinfo,gw_ins->p_over_under[pinfo->orig_port_id]);
            if (entry->hw_entry == NULL) {
                DOCA_LOG_DBG("failed to offload");
                return -1;
            }
            entry->is_hw = true;
            break;
        case GW_CLS_OL_TO_OL:
            DOCA_LOG_INFO("adding entry ol to ol");
            if (!doca_ft_add_new(gw_ins->ft, pinfo,ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            entry = (struct gw_entry *) &(*ctx)->data[0];
            entry->hw_entry = gw_pipeline_add_ol_to_ol_entry(pinfo,gw_ins->p_over_under[pinfo->orig_port_id]);
            if (entry->hw_entry == NULL) {
                DOCA_LOG_DBG("failed to offload");
                return -1;
            }
            entry->is_hw = true;

            // add flow to pipeline
            break;
        case GW_BYPASS_L4:
            DOCA_LOG_INFO("adding entry no pipeline");
            if (!doca_ft_add_new(gw_ins->ft, pinfo,ctx)) {
                DOCA_LOG_DBG("failed create new entry");
                return -1;
            }
            break; 
        default:
            DOCA_LOG_WARN("BYPASS");
            return -1;
    }
    if (entry != NULL) 
        entry->cls = cls;
    return 0;
}

static
int gw_handle_packet(struct doca_pkt_info *pinfo)
{
    struct doca_ft_user_ctx *ctx = NULL;
    struct gw_entry *entry = NULL;

    if(!doca_ft_find(gw_ins->ft, pinfo, &ctx)){
        if (gw_handle_new_flow(pinfo,&ctx)) {
            return -1;
        }
    }
    entry = (struct gw_entry *) &ctx->data[0];
    entry->total_pkts++;

    /* after session was offloaded it should not
     * get to here */
    switch (entry->cls) {
        case GW_CLS_OL_TO_OL:
            break;
        case GW_CLS_OL_TO_UL:
            break;
        case GW_BYPASS_L4:
            break;
        case GW_BYPASS:
            break;
    }

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
