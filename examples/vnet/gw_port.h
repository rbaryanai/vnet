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

#ifndef _GW_PORT_H_
#define _GW_PORT_H_

int gw_init_port(int port_id, int nr_queues);
void gw_close_port(int port_id);
void gw_dump_port_stats(uint16_t port_id);
#endif
