#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"
#include "doca_pkt.h"

uint32_t doca_pinfo_outer_ipv4_dst(struct doca_pkt_info *pinfo)
{
    return ((struct rte_ipv4_hdr *) pinfo->outer.l3)->dst_addr;
}

uint32_t doca_pinfo_outer_ipv4_src(struct doca_pkt_info *pinfo)
{
    return ((struct rte_ipv4_hdr *) pinfo->outer.l3)->src_addr;
}

uint32_t doca_pinfo_inner_ipv4_dst(struct doca_pkt_info *pinfo)
{
    return ((struct rte_ipv4_hdr *) pinfo->inner.l3)->dst_addr;
}

uint32_t doca_pinfo_inner_ipv4_src(struct doca_pkt_info *pinfo)
{
    return ((struct rte_ipv4_hdr *) pinfo->inner.l3)->src_addr;
}

static uint16_t doca_pinfo_src_port(struct doca_pkt_format *fmt)
{
    switch(fmt->l4_type) {
            case IPPROTO_TCP:
                return ((struct rte_tcp_hdr *) fmt->l4)->src_port;
            case IPPROTO_UDP:
                return ((struct rte_udp_hdr *) fmt->l4)->src_port;
            default:
                return 0;
    }
}

static uint16_t doca_pinfo_dst_port(struct doca_pkt_format *fmt)
{
    switch(fmt->l4_type) {
            case IPPROTO_TCP:
                return ((struct rte_tcp_hdr *) fmt->l4)->dst_port;
            case IPPROTO_UDP:
                return ((struct rte_udp_hdr *) fmt->l4)->dst_port;
            default:
                return 0;
    }
}

uint16_t doca_pinfo_inner_src_port(struct doca_pkt_info *pinfo) {
    return doca_pinfo_src_port(&pinfo->inner);
}

uint16_t doca_pinfo_inner_dst_port(struct doca_pkt_info *pinfo){
    return doca_pinfo_dst_port(&pinfo->inner);
}

uint16_t doca_pinfo_outer_src_port(struct doca_pkt_info *pinfo) {
    return doca_pinfo_src_port(&pinfo->outer);
}

uint16_t doca_pinfo_outer_dst_port(struct doca_pkt_info *pinfo){
    return doca_pinfo_dst_port(&pinfo->outer);
}


