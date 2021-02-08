#ifndef _GW_FT_H_
#define _GW_FT_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <rte_mbuf.h>
#include "gw_ft_key.h"

struct gw_ft;
struct gw_ft_key;

struct gw_ft_user_ctx {
    uint32_t fid;
    uint8_t  data[0];
};

/**
 * @brief - create new flow table
 *
 * @param size             - number of flows
 * @param user_data_size   - private data for user
 *
 * @return pointer to new allocated flow table or NULL
 */
struct gw_ft *gw_ft_create(int size, uint32_t user_data_size);

void gw_ft_destroy(struct gw_ft *ft);

bool gw_ft_add_new(struct gw_ft *ft, struct gw_pkt_info *pinfo,struct gw_ft_user_ctx **ctx);

bool gw_ft_find(struct gw_ft *ft, struct gw_pkt_info *pinfo, 
                                 struct gw_ft_user_ctx **ctx);

int gw_ft_destory_flow(struct gw_ft *ft, struct gw_ft_key *key);

#endif
