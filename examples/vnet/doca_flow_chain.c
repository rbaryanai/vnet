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
#include "doca_log.h"

#define MAX_ISOLATE_RULES 128

DOCA_LOG_MODULE(doca_flow_chain);

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
        doca_dpdk_set_isolate_mode();
        isolate_mode = true;
        isolate_pass.idx = 0;
        isolate_drop.idx = 0;
    }
    return 0;
}

static void
build_jump_action(struct doca_dpdk_pipe *flow)
{
    struct doca_dpdk_action_entry *entry =
        &flow->action_entry[flow->nb_actions_pipe++];
    struct rte_flow_action *action = entry->action;
    struct rte_flow_action_jump jump;

    /* TBD: need a way to get the root table to jump to
     * assuming it's 1 now
     */
    jump.group = 1;
    action->type = RTE_FLOW_ACTION_TYPE_JUMP;
    action->conf = &jump;
    doca_dpdk_build_end_action(flow);
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
        DOCA_LOG_ERR("Failed to build isolate items.\n");
        return NULL;
    }
    if (!action){
        doca_dpdk_build_drop_action(&flow);
        flow.attr.priority = 0;
    } else {
        ret = doca_dpdk_build_modify_actions(&pipe_cfg, &flow);
        if (ret) {
            DOCA_LOG_ERR("Failed to build isolate actions.\n");
            return NULL;
        }
        build_jump_action(&flow);
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
    DOCA_LOG_DBG("Doca flow chain isolate enabled %d, flow items %d.\n", isolate_mode, isolate_pass.idx);
    return -1;
}

int
doca_flow_isolate_pass(struct doca_flow_port *port,
                       struct doca_flow_match *m,
                       struct doca_flow_match *mask,
                       struct doca_flow_actions *action)
{
    struct rte_flow *ret;

    if (isolate_mode && (isolate_pass.idx < MAX_ISOLATE_RULES - 1)) {
        ret = build_flow_isolate(port, m, mask, action);
        if (!ret)
            return -1;
        isolate_pass.p_pass[isolate_pass.idx++].rte_flow = ret;
        isolate_pass.p_pass[isolate_pass.idx].port_id = port->port_id;
        return 0;
    }
    DOCA_LOG_DBG("Doca flow chain isolate enabled %d, flow items %d.\n", isolate_mode, isolate_pass.idx);
    return -1;
}

int
doca_flow_isolate_clean_all(void)
{
    struct rte_flow_error error;
    int i;

    for (i = isolate_drop.idx - 1; i >= 0; i--) {
        if (rte_flow_destroy(isolate_drop.p_drop[i].port_id,
                             isolate_drop.p_drop[i].rte_flow, &error)) {
            DOCA_LOG_ERR("Failed to flush flow isolate rule %d.\n", i);
            return -1;
        }
    }
    isolate_drop.idx = 0;

    for (i = isolate_pass.idx - 1; i >= 0; i--) {
        if (rte_flow_destroy(isolate_pass.p_pass[i].port_id,
                             isolate_pass.p_pass[i].rte_flow, &error)) {
            DOCA_LOG_ERR("Failed to flush flow isolate rule %d.\n", i);
            return -1;
        }
    }
    isolate_pass.idx = 0;

    DOCA_LOG_INFO("Succesfully removed all flow isolate rules");
    return 0;
}
