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

#ifndef _DOCA_FIB_H_
#define _DOCA_FIB_H_

#include <stdint.h>
#include <rte_ether.h>
#include "doca_net.h"
/**
 *
 * FIB table
 * ip to mac address.
 * Can be attached to offload, where mac by fib flag is used.
 */

struct doca_fib_tbl;

struct doca_fib_tbl *doca_create_fib_tbl(uint32_t _size);

void doca_destroy_fib_tbl(struct doca_fib_tbl *table);

int doca_add_fib_tbl_entry(struct doca_fib_tbl *table, const uint32_t *ip_addr,
			   uint8_t mac[DOCA_ETHER_ADDR_LEN]);

int doca_remove_fib_tbl_entry(struct doca_fib_tbl *table,
			      const uint32_t *ip_addr);

int doca_lookup_fib_tbl_entry(struct doca_fib_tbl *table, uint32_t *ip_addr,
			      uint8_t mac[DOCA_ETHER_ADDR_LEN]);

#endif
