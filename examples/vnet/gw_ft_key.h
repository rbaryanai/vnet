#ifndef _GW_FT_KEY_H_
#define _GW_FT_KEY_H_


#include <stdint.h>
#include <sys/types.h>

struct gw_pkt_info;

struct gw_ft_key {
    uint32_t ipv4_1;
    uint16_t port_1;
    uint32_t ipv4_2;
    uint16_t port_2;
    uint8_t protocol;
};

int gw_ft_key_fill(struct gw_pkt_info *m, struct gw_ft_key *key);


int gw_ft_key_equal(struct gw_ft_key *key1, struct gw_ft_key *key2);

#endif
