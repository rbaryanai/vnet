#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw.h"
#include "doca_gw.h"
#include "doca_utils.h"
#include "doca_log.h"
#include "doca_fib.h"

#include <arpa/inet.h>
#include "rte_ether.h"
#include "rte_mbuf.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "rte_gre.h"
#include "rte_vxlan.h"

DOCA_LOG_MODULE(GW)

#define GW_VARIFY_LEN(pkt_len, off) if (off > pkt_len) { \
                                            return -1; \
                                            }
#define GW_MAC_STR_FMT "%x:%x:%x:%x:%x:%x"
#define GW_MAC_EXPAND(b) b[0],b[1],b[2],b[3],b[4],b[5]
#define GW_IPV4_STR_FMT "%d:%d:%d:%d"
#define GW_IPV4_EXPAND(b) b[0],b[1],b[2],b[3]
#define GW_MAX_PORT_ID  (2)
#define GW_NEXT_HOPS_NUM  (16)

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
    match->out_proto_type = DOCA_IPV4;
    match->out_dst_port = rte_be_to_cpu_16(4789); // VXLAN (change to enum/define)


    match->tun.type = DOCA_TUN_VXLAN;
    match->tun.vxlan.tun_id = 0xffffffff;

    //inner
    match->in_dst_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.a.ipv4_addr = 0xffffffff;
    match->in_src_ip.type = DOCA_IPV4;
    match->in_proto_type = 0xff;

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

    return doca_gw_create_pipe(&pipe_cfg);
}

static struct doca_gw_pipeline *gw_build_overlay_to_overlay(struct doca_gw_port *port)
{   
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pipe_cfg = {0};
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

    return doca_gw_create_pipe(&pipe_cfg);
}

static 
int gw_parse_pkt_format(uint8_t *data, int len, bool l2, struct app_pkt_format *fmt)
{
    // parse outer
    struct rte_ether_hdr *eth = NULL;
    struct rte_ipv4_hdr * iphdr;
    int l3_off = 0;
    int l4_off = 0;
    int l7_off = 0;
    
    if (l2) {
        eth = (struct rte_ether_hdr *) data;
        fmt->l2 = data;

        //TODO: add ipv6
        switch(rte_be_to_cpu_16(eth->ether_type)){
            case RTE_ETHER_TYPE_IPV4:
                l3_off = sizeof(struct rte_ether_hdr);        
            break;
            case RTE_ETHER_TYPE_IPV6:
                l3_off = sizeof(struct rte_ether_hdr);        
                fmt->l3_type = 6; //const
                return -1;
            case RTE_ETHER_TYPE_ARP:
                //TODO: arps might need special handling
                return -1; 
            default:
                //TODO: should be rate limited
                DOCA_LOG_WARN("unsupported type %x\n",eth->ether_type);
                return -1;
        }
    }

    iphdr = (struct rte_ipv4_hdr *) (data + l3_off);
    if(iphdr->src_addr == 0 || iphdr->dst_addr == 0) {
        return -1;
    }

    fmt->l3 = (data + l3_off);
    fmt->l3_type = GW_IPV4; 

    l4_off = l3_off +  rte_ipv4_hdr_len(iphdr); 
    fmt->l4 = data + l4_off;
    
    switch(iphdr->next_proto_id){
        case IPPROTO_TCP:
            {
                struct rte_tcp_hdr * tcphdr  = (struct rte_tcp_hdr *) (data + l4_off);
                l7_off = l4_off +  (( tcphdr->data_off & 0xf0) >> 2);
                GW_VARIFY_LEN(len, l7_off);

                fmt->l4_type = IPPROTO_TCP;
                fmt->l7 = (data + l7_off);
            }
            break;
        case IPPROTO_UDP:
            {
                struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *)(data + l4_off);
                l7_off = l4_off + sizeof(*udphdr);

                fmt->l4_type = IPPROTO_UDP;
                GW_VARIFY_LEN(len, l7_off);
                fmt->l7 = (data + l7_off);
            }
            break;
        case IPPROTO_GRE:
            fmt->l4_type = IPPROTO_GRE;
            break;
        case IPPROTO_ICMP:
                fmt->l4_type = IPPROTO_ICMP;
                break;
        default:
            DOCA_LOG_INFO("unsupported l4 %d\n",iphdr->next_proto_id);
            return -1;
    }

    return 0;
}

static int gw_parse_is_tun(struct app_pkt_info *pinfo)
{
    //TODO: support ipv6
    if (pinfo->outer.l3_type != GW_IPV4) {
        return 0;
    }

    if (pinfo->outer.l3_type == IPPROTO_GRE) {
        // need to parse jre
        struct rte_gre_hdr *gre_hdr = (struct rte_gre_hdr *) pinfo->outer.l4;
        // need to now how to parse
        if (gre_hdr->k) {
                return 0;
        }
        pinfo->tun_type = APP_TUN_GRE;
        return sizeof(struct rte_gre_hdr);
   }


   if ( pinfo->outer.l4_type == IPPROTO_UDP ) {
        struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *) pinfo->outer.l4;
        switch ( rte_cpu_to_be_16(udphdr->dst_port)){
            case GW_VXLAN_PORT:
                {
                    // this is vxlan
                    struct rte_vxlan_gpe_hdr *vxlanhdr = (struct rte_vxlan_gpe_hdr *) (pinfo->outer.l4 + sizeof(struct rte_udp_hdr));
                    if (vxlanhdr->vx_flags & 0x08) {
                        //TODO: need to check if this gpe
                        pinfo->tun_type = APP_TUN_VXLAN;
                        pinfo->tun.vni  = vxlanhdr->vx_vni;
                        pinfo->tun.l2   = true;
                    }
                    return sizeof(struct rte_vxlan_gpe_hdr) + sizeof(struct rte_udp_hdr);
                }
            break;
            default:
                return 0;
        }
    }
   
   return 0; 
}

/**
 * @brief - parse packet and extract outer/inner + tunnels and
 *  put in packet info
 *
 * @param data    - packet raw data (including eth)
 * @param len     - len of the packet
 * @param pinfo   - extracted info is set here
 *
 * @return 0 on success and error otherwise.
 */
int gw_parse_packet(uint8_t *data, int len, struct app_pkt_info *pinfo)
{
    int off = 0;
    int inner_off = 0;
    pinfo->len = len;
    // parse outer

    if (!pinfo) {
        fprintf(stderr,"pinfo =%p\n", pinfo);
        return -1;
    }


    if (gw_parse_pkt_format(data, len, true, &pinfo->outer)) {
        return -1;
    }

    off = gw_parse_is_tun(pinfo);
    // no tunnel parsing is done
    if (pinfo->tun_type == APP_TUN_NONE) {
        return 0;
    }

    switch(pinfo->tun_type){
        case APP_TUN_GRE:
            inner_off = (pinfo->outer.l4 - data) + off;
            if (gw_parse_pkt_format(data + inner_off , len - inner_off, false, &pinfo->inner)) 
                return -1;
            break;
        case APP_TUN_VXLAN:
            inner_off = (pinfo->outer.l4 - data) + off;
            if (gw_parse_pkt_format(data + inner_off , len - inner_off, pinfo->tun.l2, &pinfo->inner)) 
                return -1;
            break;

        default:
            break;
    }

    return 0;
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

int gw_parse_pkt_str(struct app_pkt_info *pinfo, char *str, int len)
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
enum gw_classification gw_classifiy_pkt(struct app_pkt_info *pinfo)
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

struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ul_entry(struct app_pkt_info *pinfo,
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
    match.out_dst_ip.a.ipv4_addr = app_pinfo_outer_ipv4_dst(pinfo);
    match.tun.vxlan.tun_id = pinfo->tun.vni;

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = app_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = app_pinfo_inner_ipv4_src(pinfo);
    match.in_proto_type = pinfo->inner.l4_type;
    match.in_src_port = app_pinfo_inner_src_port(pinfo);
    match.in_dst_port = app_pinfo_inner_dst_port(pinfo);

    actions.mod_dst_ip.a.ipv4_addr = (app_pinfo_inner_ipv4_dst(pinfo) & rte_cpu_to_be_32(0x00ffffff))
                                    | rte_cpu_to_be_32(0x25000000); // change dst ip


    //TODO: add context
    return doca_gw_pipeline_add_entry(0, pipeline, &match, &actions, &monitor,
                                      sw_rss_fwd_tbl_port[pinfo->orig_port_id], &err);
}


struct doca_gw_pipelne_entry *gw_pipeline_add_ol_to_ol_entry(struct app_pkt_info *pinfo, struct doca_gw_pipeline *pipeline)
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
    match.out_dst_ip.a.ipv4_addr = app_pinfo_outer_ipv4_dst(pinfo);
    match.tun.vxlan.tun_id = pinfo->tun.vni;

    /* exact inner 5-tuple */
    match.in_dst_ip.a.ipv4_addr = app_pinfo_inner_ipv4_dst(pinfo);
    match.in_src_ip.a.ipv4_addr = app_pinfo_inner_ipv4_src(pinfo);
    match.in_proto_type = pinfo->inner.l4_type;
    match.in_src_port = app_pinfo_inner_src_port(pinfo);
    match.in_dst_port = app_pinfo_inner_dst_port(pinfo);

    actions.mod_dst_ip.a.ipv4_addr = (app_pinfo_inner_ipv4_dst(pinfo) & rte_cpu_to_be_32(0x00ffffff))
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


int gw_init(void)
{
    int i;
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
