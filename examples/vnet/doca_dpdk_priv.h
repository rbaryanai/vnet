#ifndef _DOCA_DPDK_PRIV_H_
#define _DOCA_DPDK_PRIV_H_

struct doca_gw_port
{
    uint32_t port_id;
    int      idx;
    uint8_t  user_data[0];
};


struct doca_gw_pipelne_entry {
    int id;
    void *pipe_entry;
    /* for deletion */
    int meter_id;
    int meter_profile_id;
};


#endif
