#ifndef _SIMPLE_FWD_H_
#define _SIMPLE_FWD_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_flow.h"
#include "doca_pkt.h"

struct sf_port_cfg {
	uint16_t nb_desc;
	uint16_t port_id;
    uint16_t nb_queues;
    uint16_t nb_hairpinq;
};

struct doca_vnf *simple_fwd_get_doca_vnf(void);
int sf_start_dpdk_port(struct sf_port_cfg *);
#endif
