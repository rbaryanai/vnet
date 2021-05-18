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

#include "doca_flow_chain.h"
#include "doca_dpdk_priv.h"

#define MAX_ISOLATE_RULES 128
static bool isolate_mode = false;

struct flow_isolate_rule {
    struct rte_flow *rte_flow;
    uint16_t port_id;
};

struct isolate_drop {
    struct flow_isolate_rule p_drop[MAX_ISOLATE_RULES];
    int idx;
};
struct isolate_pass {
    struct flow_isolate_rule p_pass[MAX_ISOLATE_RULES];
    int idx;
};

static struct isolate_drop isolate_drop;
static struct isolate_pass isolate_pass;

int doca_flow_chain_init(int flags)
{
    if (flags & DOCA_FLOW_CHAIN_ACL)
        doca_dpdk_enable_acl();
    if (flags & DOCA_FLOW_CHAIN_ISOLATE_MODE) {
        isolate_mode = true;
        isolate_pass.idx = 0;
        isolate_drop.idx = 0;
    }
    return 0;
}

static struct rte_flow *
build_flow_isolate(struct doca_flow_port *port,
                   struct doca_flow_match *m,
                   struct doca_flow_match *mask,
                   struct doca_flow_actions *action)
{
    struct doca_flow_pipe_cfg pipe_cfg;
    struct doca_flow_error err = {0};
    struct doca_dpdk_pipe flow;
    int ret, i;

    memset(&flow, 0, sizeof flow);
    memset(&pipe_cfg, 0, sizeof pipe_cfg);

    pipe_cfg.name = "FLOW_ISOLATE";
    pipe_cfg.port = port;
    pipe_cfg.match = m;
    pipe_cfg.match_mask = mask;
    pipe_cfg.actions = action;
    pipe_cfg.count = false;

    for (i = 0; i < MAX_ITEMS; i++) {
        flow.item_entry[i].item = &flow.items[i];
    }
    for (i = 0; i < MAX_ACTIONS; i++) {
        flow.action_entry[i].action = &flow.actions[i];
    }
    ret = doca_dpdk_build_item(m, mask, &flow, &err);
    if (ret) {
        return NULL;
    }
    if (!action){
        doca_dpdk_build_drop_action(&flow);
        flow.attr.priority = 0;
    } else {
        ret = doca_dpdk_build_modify_actions(&pipe_cfg, &flow);
        if (ret)
            return NULL;
        flow.attr.priority = 1;
    }

    flow.attr.group = 0;
    flow.attr.ingress = 1;

    return doca_dpdk_create_rte_flow(port->port_id, &flow.attr,
                                     flow.items, flow.actions);
}

int
doca_flow_isolate_drop(struct doca_flow_port *port,
                       struct doca_flow_match *m,
                       struct doca_flow_match *mask)
{
    struct rte_flow *ret;

    if (isolate_mode && (isolate_drop.idx < MAX_ISOLATE_RULES - 1)) {
        ret = build_flow_isolate(port, m, mask, NULL);
        if (!ret)
            return -1;
        isolate_drop.p_drop[isolate_drop.idx++].rte_flow = ret;
        isolate_drop.p_drop[isolate_drop.idx].port_id = port->port_id;
        return 0;
    }
    return -1;
}
