#ifndef _DOCA_FLOW_ACL_H_
#define _DOCA_FLOW_ACL_H_

#include "doca_flow.h"

struct doca_flow_acl;

/**
 * @brief hold single ip with mask
 *  1.1.1.0/24 for example.
 */
struct doca_flow_acl_ip_prefix {
	struct doca_ip_addr ip;
	uint8_t mask;
};

/**
 * @brief - a list of prefixes.
 *  len holds the number of prefixes
 */
struct doca_flow_acl_ip_prefix_list {
    struct doca_flow_acl_ip_prefix *prifx;
    int len;
}

/**
 * @brief - port definition can be specific
 *  port, or full mask.
 */
struct doca_flow_acl_port_match {
	uint16_t port;
	uint8_t  mask;
};

/**
 * @brief protocl to match.
 *  can be full mask and then any protocol.
 *  or can be specific protocl such as TCP/UDP...etc.
 */
struct doca_flow_acl_proto_match {
	uint8_t  proto;
	uint8_t  mask;
};

/**
 * @brief - terminating action means
 *  that action it taken immediately.
 *  none terminating acion is saved and taken
 *  only if following domains has no hit.
 */
enum doca_flow_acl_action {
    DOCA_ACL_ALLOW_TERMINATE,
    DOCA_ACL_BLOCK_TERMINATE,
    DOCA_ACL_ALLOW,
    DOCA_ACL_BLOCK,
};

struct doca_flow_acl_cfg {
    uint32_t max_row; /* rules are attached to row */
    uint8_t  domain;  /* 0-2 */
};

/**
 * @brief - init resources. should be called before 
 *  any rule added.
 *
 * @param cfg
 */
struct doca_flow_acl_create(struct doca_flow_acl_cfg *cfg);

/**
 * @brief - the acl is a table with X rows.
 *  each row has a list of prefixes for src ip
 *  and dst ip. 
 *
 *  the defintion holds for the metrics of all ips.
 *  for example
 *  src ip:
 *  10.10.10.0/24
 *  11.11.0.0./16
 *  dst ip:
 *  12.12.12.12/32
 *  src port:
 *  *
 *  dst ip:
 *  *
 *  proto
 *  TCP
 *
 *  will generate two rules
 *  10.10.10.0/24,12.12.12.12/32,*,*,TCP
 *  11.11.0.0/16 ,12.12.12.12/32,*,*,TCP
 *
 *  rules are not applied to HW.
 *  after all rules are configured apply should  
 *  be called.
 *
 * @param row
 * @param domain
 * @param src_prefix
 * @param dst_prefix
 * @param src_port
 * @param dst_port
 * @param proto
 * @param action
 * @param priority
 *
 * @return 0 on success and other value otherwise.
 */
int doca_flow_acl_add_row(uint16_t row, uint8_t domain,
            struct doca_flow_acl_ip_prefix_list *src_prefix,
            struct doca_flow_acl_ip_prefix_list *dst_prefix,
            struct doca_flow_acl_port_match     *src_port,
            struct doca_flow_acl_port_match     *dst_port,
            struct doca_flow_acl_proto_match    *proto,
            enum doca_flow_acl_action           action, 
            uint16_t priority);

/**
 * @brief - remove the row from the table.
 *  apply should be called in order to take affect.
 *
 * @param row
 * @param domain
 *
 * @return 0 if such row exits, and was deleted
 */
int doca_flow_acl_del_row(uint16_t row, int domain);

/**
 * @brief - clear all
 *
 * @return 
 */
int doca_flow_acl_destroy(void);

int doca_flow_acl_apply(void);

#endif
