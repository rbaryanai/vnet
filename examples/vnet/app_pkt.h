#ifndef _APP_PKT_H_
#define _APP_PKT_H_

#include <stdint.h>
#include <stdbool.h>

#define GW_IPV4 (4)
#define GW_IPV6 (6)
#define GW_VXLAN_PORT (4789)
#define GW_GTPU_PORT  (2152)

enum APP_TUN_TYPE {
    APP_TUN_NONE,
    APP_TUN_GRE,
    APP_TUN_GREL2,
    APP_TUN_VXLAN,
    APP_TUN_GTPU,
};

struct app_pkt_format {

    uint8_t * l2;
    uint8_t * l3;
    uint8_t * l4;

    uint8_t l3_type;
    uint8_t l4_type;

    // if tunnel it is the internal, if no tunnel then outer
    uint8_t *l7;
};

struct app_pkt_tun_format {
    uint32_t  vni;
    bool      l2;
};

/**
 * @brief - packet parsing result.
 *  points to relevant point in packet and 
 *  classify it.
 */
struct app_pkt_info {
    uint16_t orig_port_id;
    struct app_pkt_format   outer;
    enum APP_TUN_TYPE       tun_type;
    struct app_pkt_tun_format tun;
    struct app_pkt_format   inner;
    int     len;
};

uint32_t app_pinfo_outer_ipv4_dst(struct app_pkt_info *pinfo);
uint32_t app_pinfo_outer_ipv4_src(struct app_pkt_info *pinfo);
uint32_t app_pinfo_inner_ipv4_src(struct app_pkt_info *pinfo);
uint32_t app_pinfo_inner_ipv4_dst(struct app_pkt_info *pinfo);

uint16_t app_pinfo_inner_src_port(struct app_pkt_info *pinfo);
uint16_t app_pinfo_inner_dst_port(struct app_pkt_info *pinfo);
uint16_t app_pinfo_outer_src_port(struct app_pkt_info *pinfo);
uint16_t app_pinfo_outer_dst_port(struct app_pkt_info *pinfo);
#endif
