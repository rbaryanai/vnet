#ifndef _GW_FT_KEY_H_
#define _GW_FT_KEY_H_


#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

struct gw_pkt_info;

struct gw_ft_key {
    uint32_t ipv4_1;
    uint16_t port_1;
    uint32_t ipv4_2;
    uint16_t port_2;
    uint8_t protocol;

    uint32_t ipv4_dst;
    uint8_t  tun_type;
    uint32_t vni;
};

int gw_ft_key_fill(struct gw_pkt_info *m, struct gw_ft_key *key);


/**
 * @brief - compare keys
 *
 * @param key1
 * @param key2
 *
 * @return true if keys are equal.
 */
bool gw_ft_key_equal(struct gw_ft_key *key1, struct gw_ft_key *key2);

#endif
