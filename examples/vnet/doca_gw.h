#ifndef _DOCA_GW_H_
#define _DOCA_GW_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_net.h"

struct doca_gw_port;
struct doca_gw_pipeline; 

/**
 * @brief - on doca api failure one of 
 *the error reasons should be returned.
 */
enum doca_gw_error_type {
    DOCA_ERROR_UNKNOWN,
    DOCA_ERROR_UNSUPPORTED,
    DOCA_ERROR_TABLE_IS_FULL,
    DOCA_ERROR_OOM,
};      

/**
 * @brief - each call to api can include error message
 *  struct.
 *  in case of an error and type and a description of the error
 *  will provided.
 */
struct doca_gw_error {
    enum doca_gw_error_type type;
    const char *message;
};


struct doca_gw_cfg {
    uint32_t total_sessions;
    uint16_t queues; // each offload thread should use a different queue id.
};

enum doca_gw_port_type {
    DOCA_GW_PORT_DPDK,
    DOCA_GW_PORT_DPDK_BY_ID,
};

struct doca_gw_port_cfg {
    enum doca_gw_port_type type;
    uint16_t queues;
    const char *devargs;
    uint16_t priv_data_size;  // user private data
};



struct doca_gw_match {

    // tunnel
    struct   doca_ip_addr out_src_ip;
    struct   doca_ip_addr out_dst_ip;
    uint8_t  out_proto_type;
    uint16_t out_src_port;
    uint16_t out_dst_port;

    struct doca_gw_tun tun;

    //inner
    struct doca_ip_addr in_src_ip;
    struct doca_ip_addr in_dst_ip;

    uint8_t  in_proto_type;
    uint16_t in_src_port;
    uint16_t in_dst_port;
};

struct doca_gw_encap_action {
  
    //TODO: do we need here an array?  
    uint8_t src_mac[DOCA_ETHER_ADDR_LEN];
    uint8_t dst_mac[DOCA_ETHER_ADDR_LEN];

    struct doca_ip_addr in_src_ip;
    struct doca_ip_addr in_dst_ip;
    struct doca_gw_tun tun;
};

struct doca_gw_actions {

    bool decap;
    // tunnel

    struct doca_ip_addr mod_src_ip;
    struct doca_ip_addr mod_dst_ip;

    uint16_t mod_src_port;
    uint16_t mod_dst_port;
    
    struct doca_gw_encap_action encap;
};

struct doca_gw_monitor {
    bool count;
    struct meter {
        uint64_t cir;
        uint64_t cbs;
        uint64_t ebs;
    } m;
    uint32_t aging;
};

/**
 * @brief - pipe identifier.
 *  user defines a pipe before using it
 */
struct doca_gw_pipeline_cfg {
    const char *name;
    struct doca_gw_port     *port;
    struct doca_gw_match    *match;
    struct doca_gw_actions  *actions;
    struct doca_gw_monitor  *monitor;
    bool                    count; // count for entire pipe
};


enum doca_fwd_tbl_type {
    DOCA_FWD_RSS,
    DOCA_FWD_FIB_TBL
};


struct doca_fwd_table_cfg {
    enum doca_fwd_tbl_type type;
    union {
        struct fwd_rss {
            uint32_t rss_flags;
            uint16_t * queues;
            int      num_queues;
        } rss;

        struct fib_tbl {
            int size;
        } f;
    };
};

/**
 * @brief 
 *
 * @param cfg
 *
 * @return 
 */
struct doca_fwd_tbl *doca_gw_create_fwd_tbl(struct doca_fwd_table_cfg *cfg);

/**
 * @brief 
 *
 * @param cgf
 *
 * @return 
 */
int doca_gw_init(struct doca_gw_cfg *cfg, struct doca_gw_error *err);


/**
 * @brief 
 *
 * @param cfg
 * @param err
 *
 * @return 
 */
struct doca_gw_port *doca_gw_port_start(struct doca_gw_port_cfg *cfg, struct doca_gw_error *err);

/**
 * @brief - close port
 *  release all resources used by port, including all HW rules.
 *
 * @param port
 *
 * @return 
 */
int doca_gw_port_stop(struct doca_gw_port *port);


/**
 * @brief - return pointer to user private data.
 *   user can manage specific data stucture.
 *   the size of the data structure is given on port cfg
 *
 * @param p
 *
 * @return 
 */
uint8_t *doca_gw_port_priv_data(struct doca_gw_port *p);


/**
 * @brief 
 *
 * @param 
 * @param match
 * @param mod
 * @param fwd_tbl
 *
 * @return 
 */
struct doca_gw_pipeline *doca_gw_create_pipe(struct doca_gw_pipeline_cfg *cfg);

int doca_gw_add_entry(struct doca_gw_pipeline *pipeline, struct doca_gw_match *match,
                      struct doca_gw_actions *actions,struct doca_gw_monitor *mon,
                      uint32_t fwd_tbl);

/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
int doca_gw_rm_entry(void * session);

#endif
