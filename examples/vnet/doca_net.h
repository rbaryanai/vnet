#ifndef _DOCA_NET_H_
#define _DOCA_NET_H_

#define DOCA_TCP  (0x6)
#define DOCA_ETHER_ADDR_LEN (6)

enum doca_gw_ip_type
{
    DOCA_IPV4 = 4,
    DOCA_IPV6 = 6,
};

enum doca_gw_tun_type {
    DOCA_TUN_NONE = 0,
    DOCA_TUN_VXLAN,
};

struct doca_gw_tun {
    enum doca_gw_tun_type type;
    union {
        struct vxlan {
            uint32_t tun_id;
        } vxlan;
    };
};

struct doca_ip_addr {
    uint8_t type;
    union {
        uint32_t ipv4_addr;
        uint32_t ipv6_addr[4]; 
    } a;
};

#endif
