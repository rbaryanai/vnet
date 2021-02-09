#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "gw.h"
#include "doca_gw.h"
#include "doca_utils.h"
#include "doca_log.h"

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


static struct doca_fwd_tbl sw_fwd_tbl = {0};



static struct doca_gw_pipeline *gw_build_underlay_overlay(struct doca_gw_port *port)
{
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pcfg = {0};
    struct doca_gw_match match = {0};

    match.out_dst_ip.a.ipv4_addr = 0xffffffff;
    match.out_dst_ip.type = DOCA_IPV4;
    match.out_proto_type = DOCA_IPV4;
    match.out_dst_port = 4789; // VXLAN (change to enum/define)


    match.tun.type = DOCA_TUN_VXLAN;
    match.tun.tun_id = 0xffffffff;

    //inner
    match.in_dst_ip.a.ipv4_addr = 0xffffffff;
    match.in_src_ip.a.ipv4_addr = 0xffffffff;
    match.in_src_ip.type = DOCA_IPV4;
    match.in_proto_type = 0xff;

    match.in_src_port = 0xffff;
    match.in_dst_port = 0xffff;

    pcfg.name  = "overlay-to-underlay";
    pcfg.port = port;
    pcfg.match  = &match;
    pcfg.count  = false;
    pcfg.mirror =  false;;

    return doca_gw_create_pipe(&pcfg);
}




static int gw_build_default_fwd_to_sw(struct doca_fwd_tbl *tbl)
{
#define GW_MAX_QUEUES 16
    int i;
    struct doca_fwd_table_cfg cfg = {0};
    uint16_t queues[GW_MAX_QUEUES];

    for(i = 0 ; i < GW_MAX_QUEUES ; i++){
        queues[i] = i;
    }

    cfg.type = DOCA_SW_FWD;
    cfg.s.queues = (uint16_t *) &queues;
    cfg.s.num_queues = GW_MAX_QUEUES;

    return doca_gw_add_fwd(&cfg, tbl);
}

static 
int gw_parse_pkt_format(uint8_t *data, int len, bool l2, struct gw_pkt_format *fmt)
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
            default:
                fprintf(stderr, "unsupported type %x\n",eth->ether_type);
                return -1;
        }
    }

    iphdr = (struct rte_ipv4_hdr *) (data + l3_off);
    if(iphdr->src_addr == 0 || iphdr->dst_addr == 0) {
        return -1;
    }
    fmt->l3 = (data + l3_off);
    fmt->l3_type = 4; //const



    l4_off = l3_off + 20; // should be taken from iphdr
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
            }
            break;
        case IPPROTO_GRE:
            fmt->l4_type = IPPROTO_GRE;
            break;
        default:
            printf("unsupported l4 %d\n",iphdr->next_proto_id);
            return -1;
    }

    return 0;
}

static int gw_parse_is_tun(struct gw_pkt_info *pinfo)
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
                return -1;
        }
        pinfo->tun_type = GW_TUN_GRE;
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
                        pinfo->tun_type = GW_TUN_VXLAN;
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
int gw_parse_packet(uint8_t *data, int len, struct gw_pkt_info *pinfo)
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
    if (pinfo->tun_type == GW_TUN_NONE) {
        return 0;
    }


    switch(pinfo->tun_type){
        case GW_TUN_GRE:
            inner_off = (pinfo->outer.l4 - data) + off;
            if (!gw_parse_pkt_format(data + inner_off , len - inner_off, false, &pinfo->inner)) 
                return -1;
            break;
        case GW_TUN_VXLAN:
            inner_off = (pinfo->outer.l4 - data) + off;
            if (!gw_parse_pkt_format(data + inner_off , len - inner_off, pinfo->tun.l2, &pinfo->inner)) 
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

int gw_parse_pkt_str(struct gw_pkt_info *pinfo, char *str, int len)
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
        case GW_TUN_VXLAN:
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



