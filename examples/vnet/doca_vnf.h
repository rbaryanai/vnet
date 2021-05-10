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

#ifndef _DOCA_VNF_H_
#define _DOCA_VNF_H_

#include <stdint.h>

struct doca_pkt_info;

struct doca_vnf {
	int (*doca_vnf_init)(void *p);
	int (*doca_vnf_process_pkt)(struct doca_pkt_info *pinfo);
	int (*doca_vnf_destroy)(void);
};

#endif
