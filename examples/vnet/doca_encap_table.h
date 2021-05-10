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

int doca_encap_table_add_id(struct doca_flow_encap_action *ea);

/**
 * @brief - save per id data.
 *  the data is any pointer. table will not alloc or del
 *  the data. 
 *
 * @param id
 * @param data
 *
 * @return 0 on success and if id exits. note that data will
 *  be overidden.
 */
int doca_encap_table_udpate_data(int id, uint8_t *data);

int doca_encap_table_get_id(struct doca_flow_encap_action *ea);

/**
 * @brief - remove from table. 
 *  if id exits with data, data is returned.
 *
 * @param id
 *
 * @return 
 */
uint8_t *doca_encap_table_remove_id(int id);

int doca_encap_table_destroy(int max_encaps);

#endif
