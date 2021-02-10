#ifndef _GW_H_
#define _GW_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_gw.h"


#define GW_IPV4 (4)
#define GW_IPV6 (6)
#define GW_VXLAN_PORT (4789)
#define GW_GTPU_PORT  (2152)

enum GW_TUN_TYPE {
    GW_TUN_NONE,
    GW_TUN_GRE,
    GW_TUN_GREL2,
    GW_TUN_VXLAN,
    GW_TUN_GTPU,
};

struct gw_port_cfg {
    uint16_t n_queues;
    uint16_t port_id;
};

struct gw_pkt_format {

    uint8_t * l2;
    uint8_t * l3;
    uint8_t * l4;

    uint8_t l3_type;
    uint8_t l4_type;

    // if tunnel it is the internal, if no tunnel then outer
    uint8_t *l7;
};

struct gw_tun_format {
    uint32_t  vni;
    bool      l2;
};

/**
 * @brief - packet parsing result.
 *  points to relevant point in packet and 
 *  classify it.
 */
struct gw_pkt_info {
    struct gw_pkt_format   outer;
    enum GW_TUN_TYPE       tun_type;
    struct gw_tun_format   tun;
    struct gw_pkt_format   inner;
    int     len;
};


int gw_parse_packet(uint8_t *data, int len, struct gw_pkt_info *pinfo);


/**
 * @brief - put packet format as readble string.
 *  for debug/log purpose
 *
 * @param pinfo
 * @param str    - pointer to preallocated string 
 * @param len    - len of the string
 *
 * @return -1 on fail or str len on success
 */
int gw_parse_pkt_str(struct gw_pkt_info *pinfo, char *str, int len);

/**
 * @brief - overlay to underlay pipeline.
 *  match on:
 *            outer dst_ip/vni
 *            inner 5-tuple
 *        
 *  modify:
 *            decap
 *            inner-dst ip
 *
 *            count
 *            meter
 *
 *  fwd:      RSS-table
 *
 * @param p
 *
 * @return 
 */
struct doca_gw_pipeline *gw_init_ol_to_ul_pipeline(struct doca_gw_port *p);



/**
 * @brief - init doca port matching the provided configiration.
 *
 * @param port_cfg
 *
 * @return 
 */
struct doca_gw_port *gw_init_doca_port(struct gw_port_cfg *port_cfg);

enum gw_classification {
    GW_CLS_OL_TO_UL,
    GW_CLS_OL_TO_OL,
    GW_BYPASS,
};

/**
 * @brief - decides about the type of the packet.
 *  which pipeline should be exeuted
 *
 * @param pinfo
 *
 * @return 
 */
enum gw_classification gw_classifiy_pkt(struct gw_pkt_info *pinfo);

#endif
