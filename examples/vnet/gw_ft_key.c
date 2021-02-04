#include <stdio.h>
#include <arpa/inet.h>
#include "gw.h"
#include "gw_ft_key.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"

int gw_ft_key_fill(struct gw_pkt_info *pinfo, struct gw_ft_key *key)
{
    struct gw_pkt_format *pktf = NULL;
    struct rte_ipv4_hdr * iphdr;

    if ( pinfo->tun_type == GW_TUN_NONE ) {
        pktf = &pinfo->outer;
    } else {
        pktf = &pinfo->inner;
    }

    if (pktf->l3_type != GW_IPV4) {
        return -1;
    }

    iphdr = (struct rte_ipv4_hdr *) pktf->l3;
    key->protocol = iphdr->next_proto_id;
    key->ipv4_1 = iphdr->src_addr;
    key->ipv4_2 = iphdr->dst_addr;
    
    switch(pktf->l4_type){
        case IPPROTO_TCP:
            {
                struct rte_tcp_hdr * tcphdr = (struct rte_tcp_hdr *) pktf->l4;
                key->port_1 = tcphdr->src_port;
                key->port_2 = tcphdr->dst_port;
            }
            break;
        case IPPROTO_UDP:
            {
                struct rte_udp_hdr * udphdr = (struct rte_udp_hdr *) pktf->l4;
                key->port_1 = udphdr->src_port;
                key->port_2 = udphdr->dst_port;
            }
            break;
        default:
            printf("unsupported l4 %d\n",key->protocol);
            return -1;
    }
    return 0;
}



int gw_ft_key_equal(struct gw_ft_key *key1, struct gw_ft_key *key2)
{
    return key1->ipv4_1 == key2->ipv4_1 && key1->port_1 == key2->port_1 &&
           key1->ipv4_2 == key2->ipv4_2 && key1->port_2 == key2->port_2 &&
           key1->protocol == key2->protocol; 
}

