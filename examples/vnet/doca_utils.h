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

#ifndef _DOCA_UTILS_H_
#define _DOCA_UTILS_H_

#include <stdint.h>
#include <arpa/inet.h>

static inline int doca_parse_ipv4(uint32_t *ip_addr, const char *ip_str)
{
	uint16_t ip[4];
	int argc =
	    sscanf(ip_str, "%hu.%hu.%hu.%hu", &ip[3], &ip[2], &ip[1], &ip[0]);
	if (argc != 4)
		return -1;
	*ip_addr = htonl((ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0]);

	return 0;
}

static inline uint32_t doca_inline_parse_ipv4(const char *ip_str)
{
	uint16_t ip[4];
	int argc =
	    sscanf(ip_str, "%hu.%hu.%hu.%hu", &ip[3], &ip[2], &ip[1], &ip[0]);
	if (argc != 4)
		return -1;
	return htonl((ip[3] << 24) | (ip[2] << 16) | (ip[1] << 8) | ip[0]);
}
#endif
