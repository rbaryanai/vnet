#ifndef _DOCA_DPDK_OFFLOAD_H_
#define _DOCA_DPDK_OFFLOAD_H_

#include "doca_dpdk_priv.h"

int doca_dpdk_off_init(struct doca_flow_cfg *cfg);

struct rte_flow_template *
doca_dpdk_pipe_create(struct doca_flow_pipe *pipe,
                        struct doca_flow_error *err);


struct rte_flow *
doca_dpdk_off_pipe_add_entry(struct doca_dpdk_pipe *pipe,
                        uint16_t pipe_queue,
                        struct doca_flow_error *derr);

#endif
