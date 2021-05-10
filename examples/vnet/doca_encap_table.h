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

#ifndef _DOCA_ENCAP_TAN_H_
#define _DOCA_ENCAP_TAN_H_

#include "doca_flow.h"

/**
 * @brief 
 *
 * @param max_encaps
 *    trying to add more encaps will result in error
 *
 * @return 0 on success
 */
int doca_encap_table_init(int max_encaps);

/**
 * @brief - add encap action
 *      encap is identidied by its 3-tuple
 *      src ip, dst ip and tun id.
 *      in case it exists refcnt++.
 *
 * @param ea
 *
 * @return positive value which is the encap idx.
 *  negative value on failure.
 */
int doca_encap_table_add_id(struct doca_flow_encap_action *ea);

/**
 * @brief - save per id data.
 *  the data is any pointer. table will not alloc or del
 *  the data just ref it.
 *
 * @param id
 * @param data
 *
 * @return 0 on success and if id exits. note that data will
 *  be overidden.
 */
int doca_encap_table_udpate_data(int id, uint8_t *data);

/**
 * @brief find specific encap.
 *
 * @param ea
 *
 * @return table encap id, or negative value if no such
 *  encap exits.
 */
int doca_encap_table_get_id(struct doca_flow_encap_action *ea);

/**
 * @brief - if ea exits
 *
 * @param ea
 *
 * @return 
 */
uint8_t *doca_encap_table_get_data(struct doca_flow_encap_action *ea);

/**
 * @brief - remove from table. 
 *  if id exits with data, data is returned.
 *  del will casue ref--, and on ref == 0,
 *  id will be cleared.
 *
 * @param id
 *
 * @return refcnt value or negative value if doesn't
 *  exists.
 */
int doca_encap_table_remove_id(int id);

int doca_encap_table_destroy(int max_encaps);

#endif
