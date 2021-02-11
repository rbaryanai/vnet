#include <stdio.h>
#include <arpa/inet.h>
#include "gw.h"
#include "gw_ft_key.h"
#include "rte_ip.h"
#include "rte_tcp.h"
#include "rte_udp.h"

#define gw_ft_key_get_ipv4_src(inner,pinfo) inner?app_pinfo_inner_ipv4_src(pinfo): \
                                            app_pinfo_outer_ipv4_src(pinfo);

#define gw_ft_key_get_ipv4_dst(inner,pinfo) inner?app_pinfo_inner_ipv4_dst(pinfo): \
                                            app_pinfo_outer_ipv4_dst(pinfo);

#define gw_ft_key_get_src_port(inner,pinfo) inner?app_pinfo_inner_src_port(pinfo): \
                                            app_pinfo_outer_src_port(pinfo);

#define gw_ft_key_get_dst_port(inner,pinfo) inner?app_pinfo_inner_dst_port(pinfo): \
                                            app_pinfo_outer_dst_port(pinfo);

int gw_ft_key_fill(struct app_pkt_info *pinfo, struct gw_ft_key *key)
{
    bool inner = false;

    if ( pinfo->tun_type != APP_TUN_NONE )
        inner = true; 

    //TODO: support ipv6
    if ( pinfo->outer.l3_type != GW_IPV4) {
        return -1;
    }

    /* 5-tuple of inner if there is tunnel or outer if none */
    key->protocol = inner?pinfo->inner.l4_type:pinfo->outer.l4_type;
    key->ipv4_1 = gw_ft_key_get_ipv4_src(inner,pinfo);
    key->ipv4_2 = gw_ft_key_get_ipv4_dst(inner,pinfo);
    key->port_1 = gw_ft_key_get_src_port(inner,pinfo);
    key->port_2 = gw_ft_key_get_dst_port(inner,pinfo);

    /* in case of tunnel , use tun tyoe and vni */
    if ( pinfo->tun_type != APP_TUN_NONE ) {
        key->tun_type = pinfo->tun_type;
        key->vni = pinfo->tun.vni;
    }    
    return 0;
}

bool gw_ft_key_equal(struct gw_ft_key *key1, struct gw_ft_key *key2)
{
    return memcmp(key1, key2, sizeof(struct gw_ft_key)) == 0;
}
