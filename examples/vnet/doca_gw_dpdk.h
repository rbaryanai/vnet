#ifndef _DOCA_GW_DPDK_H_
#define _DOCA_GW_DPDK_H_

#include <stdio.h>
#include <rte_flow.h>
#include "doca_gw.h"
#include "doca_utils.h"

#define INNER_MATCH		1
#define OUTER_MATCH		2
#define MAX_ITEMS		12
#define MAX_ACTIONS		8
#define MAX_PIP_FLOWS	20

struct doca_dpdk_item_eth_data {
	struct rte_flow_item_eth spec;
	struct rte_flow_item_eth last;
	struct rte_flow_item_eth mask;
};

struct doca_dpdk_item_vlan_data {
	struct rte_flow_item_vlan spec;
	struct rte_flow_item_vlan last;
	struct rte_flow_item_vlan mask;
};

struct doca_dpdk_item_ipv4_data {
	uint8_t match_layer;	// inner or outer 
	struct rte_flow_item_ipv4 spec;
	struct rte_flow_item_ipv4 last;
	struct rte_flow_item_ipv4 mask;
};

struct doca_dpdk_item_ipv6_data {
	uint8_t match_layer;
	struct rte_flow_item_ipv6 spec;
	struct rte_flow_item_ipv6 last;
	struct rte_flow_item_ipv6 mask;
};

struct doca_dpdk_item_vxlan_data {
	struct rte_flow_item_vxlan spec;
	struct rte_flow_item_vxlan last;
	struct rte_flow_item_vxlan mask;
};

struct doca_dpdk_item_udp_data {
	uint8_t match_layer;
	struct rte_flow_item_udp spec;
	struct rte_flow_item_udp last;
	struct rte_flow_item_udp mask;
};

struct doca_dpdk_item_tcp_data {
	uint8_t match_layer;
	struct rte_flow_item_tcp spec;
	struct rte_flow_item_tcp last;
	struct rte_flow_item_tcp mask;
};

struct doca_gw_item_data {
	union {
		struct doca_dpdk_item_eth_data eth;
		struct doca_dpdk_item_vlan_data vlan;
		struct doca_dpdk_item_ipv4_data ipv4;
		struct doca_dpdk_item_ipv6_data ipv6;
		struct doca_dpdk_item_vxlan_data vxlan;
		struct doca_dpdk_item_tcp_data tcp;
		struct doca_dpdk_item_udp_data udp;
	};
};

struct doca_dpdk_item_entry {
	uint8_t flags;
	struct rte_flow_item *item;
	struct doca_gw_item_data item_data;
	int (*modify_item)(struct doca_dpdk_item_entry*, struct doca_gw_match*);
};

struct doca_gw_pipe_dpdk_flow {
	uint8_t nb_items;
	uint8_t nb_actions;
	struct rte_flow_item items[MAX_ITEMS];
	struct doca_dpdk_item_entry item_entry[MAX_ITEMS];
	LIST_ENTRY(doca_gw_pipe_dpdk_flow) free_list;
};

struct doca_gw_pipe_dpdk_flow_list {
	struct doca_gw_pipe_dpdk_flow pipe_flows[MAX_PIP_FLOWS];
	LIST_HEAD(, doca_gw_pipe_dpdk_flow) free_head;
};

/*need move to util file ??*/
static inline bool doca_is_mac_zero(void *mac_addr)
{
	uint16_t *addr = mac_addr;
	return (addr[0] | addr[1] | addr[2]) == 0;
}

static inline void doca_set_mac_max(void *mac_addr)
{
	uint16_t *addr = mac_addr;
	
	addr[0] = UINT16_MAX;
	addr[1] = UINT16_MAX;
	addr[2] = UINT16_MAX;
}

static inline bool doca_is_mac_max(void *mac_addr)
{
	uint16_t *addr = mac_addr;
	return addr[0] == UINT16_MAX && addr[1] == UINT16_MAX && addr[2] == UINT16_MAX;
}

static inline bool 
doca_is_ip_zero(struct doca_ip_addr *ip_addr)
{
	uint64_t *addr = (uint64_t *)(&ip_addr->a);
	if (ip_addr->type == DOCA_IPV6)
		return addr[0] == 0 && addr[1] == 0;
	return ip_addr->a.ipv4_addr == 0;
}

static inline bool
doca_is_ip_max(struct doca_ip_addr *ip_addr)
{
	uint64_t *addr = (uint64_t *)(&ip_addr->a);
	if (ip_addr->type == DOCA_IPV6)
		return addr[0] == UINT64_MAX && addr[1] == UINT64_MAX;
	return ip_addr->a.ipv4_addr == UINT32_MAX;
}

static inline void
doca_set_item_ipv6_max(void *ip6_addr)
{
	uint64_t *addr = (uint64_t *)ip6_addr;
	addr[0] = UINT64_MAX;
	addr[1] = UINT64_MAX;
}

static inline void
doca_set_item_vni_max(void *vni)
{
	uint8_t *addr = (uint8_t *)vni;
	addr[0] = UINT8_MAX;
	addr[1] = UINT8_MAX;
	addr[2] = UINT8_MAX;
}

static inline bool 
doca_match_is_ipv4(struct doca_gw_match *match, uint8_t type)
{
	struct doca_ip_addr ip_addr;

	// need confim: must set src or dst;
	if (type == INNER_MATCH)
		ip_addr = match->in_src_ip.type != DOCA_NONE ? match->in_src_ip : match->in_dst_ip;
	else
		ip_addr = match->out_src_ip.type != DOCA_NONE ? match->out_src_ip : match->out_dst_ip;
	return (ip_addr.type == DOCA_IPV4);
}

static uint16_t
doca_gw_get_l3_protol(struct doca_gw_match *match, uint8_t type)
{
	return doca_match_is_ipv4(match, type)? RTE_ETHER_TYPE_IPV4 : RTE_ETHER_TYPE_IPV6;
}

static inline bool doca_match_is_tcp(struct doca_gw_match *match)
{
	if (match->tun.type == DOCA_TUN_NONE)
		return (match->out_l4_type == IPPROTO_TCP);
	return (match->in_l4_type == IPPROTO_TCP);
}

static inline bool doca_match_is_udp(struct doca_gw_match *match)
{
	if (match->tun.type == DOCA_TUN_NONE)
		return (match->out_l4_type == IPPROTO_UDP);
	return (match->in_l4_type == IPPROTO_UDP);
}

void doca_gw_init_dpdk(struct doca_gw_cfg *cfg);

struct doca_gw_pipe_dpdk_flow*
doca_gw_dpdk_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_error *err);


#endif
