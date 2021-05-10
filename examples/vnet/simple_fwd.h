/*
 * Copyright (C) 2021 Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software
 * product, including all associated intellectual property rights, are and
 * shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

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
