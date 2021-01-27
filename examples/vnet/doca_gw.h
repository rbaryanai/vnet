#ifndef _DOCA_GW_H_
#define _DOCA_GW_H_

#include <stdint.h>
#include <stdbool.h>
#include "doca_net.h"

/**
 * @brief - on doca api failure one of 
 *the error reasons should be returned.
 */
enum doca_gw_error_type {
    DOCA_ERROR_UNKNOWN,
    DOCA_ERROR_UNSUPPORTED,
    DOCA_ERROR_TABLE_IS_FULL,
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
    
    uint8_t src_mac[DOCA_ETHER_ADDR_LEN];
    uint8_t dst_mac[DOCA_ETHER_ADDR_LEN];

    struct doca_ip_addr in_src_ip;
    struct doca_ip_addr in_dst_ip;
    struct doca_gw_tun tun;
};

struct doca_gw_action {

    bool decap;
    // tunnel

    struct doca_ip_addr in_src_ip;
    struct doca_ip_addr in_dst_ip;

    uint8_t  in_proto_type;
    uint16_t in_src_port;
    uint16_t in_dst_port;
    
    struct doca_gw_encap_action encap;
};

struct doca_gw_modify {
    bool decap;
};

enum doca_gw_port_type {
    DOCA_GW_PORT_DPDK,
    DOCA_GW_PORT_DPDK_BY_ID,

};

struct doca_gw_port_cfg {
    enum doca_gw_port_type type;
    const char *devargs;
};

struct doca_gw_port {
    uint32_t port_id;
};


/**
 * @brief - pipe identifier.
 *  user defines a pipe before using it
 */
struct doca_gw_pipeline {
    void * handler;
    uint32_t id;
};

struct doca_mirror_cfg {
    uint32_t id;
};

/**
 * @brief - pipe identifier.
 *  user defines a pipe before using it
 */
struct doca_gw_pipeline_cfg {
    const char *name;
    struct doca_gw_port   *port;
    struct doca_gw_match  *match;
    struct doca_gw_action *action;
    bool  count; // count for entire pipe
    struct doca_mirror_cfg *mirror;
};


enum doca_fwd_tbl_type {
    DOCA_SW_FWD,
    DOCA_FIB_TBL
};

struct doca_fwd_tbl {
    const char * name;
    void * handler;
    uint32_t id;
};

struct doca_fwd_table_cfg {
    enum doca_fwd_tbl_type type;
    union {
        struct sw_fwd {
            uint32_t default_flags;
            uint16_t * queues;
            int      num_queues;
        } s;

        struct fib_tbl {
            int size;
        } f;
    };
};

/**
 * @brief 
 *
 * @param cfg
 * @param fwd
 *
 * @return 
 */
int doca_gw_add_fwd(struct doca_fwd_table_cfg *cfg, struct doca_fwd_tbl *fwd);

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
 * @param port
 *
 * @return 
 */
int doca_gw_port_start(struct doca_gw_port_cfg *cfg, struct doca_gw_port *port, struct doca_gw_error *err);

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
 * @brief 
 *
 * @param port
 * @param cfg
 * @param pipeline
 *
 * @return 
 */
int doca_gw_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_pipeline *pipeline);

/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
int doca_gw_create_session(struct doca_gw_pipeline *pipeline, struct doca_gw_match *match, 
                           struct doca_gw_modify *mod,uint32_t fwd_tbl);

/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
int doca_gw_delete_session(void * session);

#endif
