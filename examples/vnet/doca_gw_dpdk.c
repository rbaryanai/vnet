#include <stdio.h>
#include "doca_gw_dpdk.h"
#include "doca_log.h"
#include <rte_vxlan.h>
#include <rte_ethdev.h>

DOCA_LOG_MODULE(doca_gw_dpdk);

#define DOCA_GET_SRC_IP(match, type) ((type == OUTER_MATCH) ? match->out_src_ip : match->in_src_ip) 
#define DOCA_GET_DST_IP(match, type) ((type == OUTER_MATCH) ? match->out_dst_ip : match->in_dst_ip)
#define DOCA_GET_SRC_PORT(match, type) ((type == OUTER_MATCH) ? match->out_src_port : match->in_src_port)
#define DOCA_GET_DST_PORT(match, type) ((type == OUTER_MATCH) ? match->out_dst_port : match->in_dst_port)

struct doca_gw_pipe_dpdk_flow_list pipe_flows;

void doca_gw_init_dpdk(__rte_unused struct doca_gw_cfg *cfg)
{
	uint8_t pip_idx;
	struct doca_gw_pipe_dpdk_flow *pipe_flow;

	LIST_INIT(&pipe_flows.free_head);
	for(pip_idx = 0 ; pip_idx < MAX_PIP_FLOWS; pip_idx++){
		pipe_flow = &pipe_flows.pipe_flows[pip_idx];
		memset(pipe_flow, 0x0, sizeof(struct doca_gw_pipe_dpdk_flow));
		LIST_INSERT_HEAD(&pipe_flows.free_head, pipe_flow, free_list);
	}
	//todo, need remove to init_port 
	doca_gw_dpdk_init_port(0);
	doca_gw_dpdk_init_port(1);
}

/**
 * @brief get free pipeline flow from arry by used flage, currently.
 *    
 * @entry match
 *
 * @return 
 */
static struct doca_gw_pipe_dpdk_flow*
doca_gw_dpdk_get_free_pipe(void)
{
	uint8_t idx;
	struct doca_gw_pipe_dpdk_flow *pipe_flow = NULL;

	if (LIST_EMPTY(&pipe_flows.free_head))
		return NULL;
	pipe_flow = LIST_FIRST(&pipe_flows.free_head);
	LIST_REMOVE(pipe_flow, free_list);
	memset(pipe_flow, 0x0, sizeof(struct doca_gw_pipe_dpdk_flow));
	for (idx = 0 ; idx < MAX_ITEMS; idx++)
		pipe_flow->item_entry[idx].item = &pipe_flow->items[idx];
	for (idx = 0 ; idx < MAX_ACTIONS; idx++)
		pipe_flow->action_entry[idx].action = &pipe_flow->actions[idx];
	return pipe_flow;
}

static void
doca_gw_dpdk_pipe_release(struct doca_gw_pipe_dpdk_flow *pipe_flow)
{
	//TODO: need lock and set status 
	LIST_INSERT_HEAD(&pipe_flows.free_head, pipe_flow, free_list);
}

static int
doca_gw_dpdk_modify_eth_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;

	if ((entry->flags & DOCA_MODIFY_SMAC) && !doca_is_mac_zero(match->out_src_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &spec->src);
	if ((entry->flags & DOCA_MODIFY_DMAC) && !doca_is_mac_zero(match->out_dst_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_dst_mac, &spec->dst);
	return 0;
}

static void
doca_gw_dpdk_build_eth_flow_item(struct doca_dpdk_item_entry *entry,
					struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;
	struct rte_flow_item_eth *mask = &entry->item_data.eth.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_ETH;
	if (!doca_is_mac_zero(match->out_src_mac)) {
		doca_set_mac_max(mask->src.addr_bytes);
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &spec->src);
		if (doca_is_mac_max(match->out_src_mac))
			entry->flags |= DOCA_MODIFY_SMAC;
	}
	if (!doca_is_mac_zero(match->out_dst_mac)) {
		doca_set_mac_max(mask->dst.addr_bytes);
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_dst_mac, &spec->dst);
		if (doca_is_mac_max(match->out_dst_mac))
			entry->flags |= DOCA_MODIFY_DMAC;
	}
	if (match->vlan_id)
		spec->has_vlan = 1;//will debug if this set is need.
	spec->type = rte_cpu_to_be_16(doca_gw_get_l3_protol(match, OUTER_MATCH));
	mask->type = UINT16_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_eth_item;
}

static int
doca_gw_dpdk_modify_vlan_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	struct rte_flow_item_vlan *spec = &entry->item_data.vlan.spec;

	if ((entry->flags & DOCA_MODIFY_VLAN_ID) && match->vlan_id)
		spec->tci = RTE_BE16(match->vlan_id);
	return 0;
}

static void
doca_gw_dpdk_build_vlan_item(__rte_unused struct doca_dpdk_item_entry *entry,
					__rte_unused struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_vlan *spec = &entry->item_data.vlan.spec;
	struct rte_flow_item_vlan *mask = &entry->item_data.vlan.mask;

	if (!match->vlan_id)
		return;
	flow_item->type = RTE_FLOW_ITEM_TYPE_VLAN;
	spec->tci = RTE_BE16(match->vlan_id);
	flow_item->spec = spec;
	flow_item->spec = mask;
	if (match->vlan_id == UINT16_MAX) {
		entry->flags |= DOCA_MODIFY_VLAN_ID;
		entry->modify_item = doca_gw_dpdk_modify_vlan_item;
	}
}

static int
doca_gw_dpdk_modify_ipv4_item(struct doca_dpdk_item_entry *entry,
									struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.ipv4.match_layer;
	struct rte_flow_item_ipv4 *spec = &entry->item_data.ipv4.spec;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, layer);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, layer);

	if ((entry->flags & DOCA_MODIFY_SIP) && src_ip.a.ipv4_addr)
		spec->hdr.src_addr = src_ip.a.ipv4_addr;
	if ((entry->flags & DOCA_MODIFY_DIP) && dst_ip.a.ipv4_addr)
		spec->hdr.dst_addr = dst_ip.a.ipv4_addr;
	return 0;
}

static void doca_gw_dpdk_build_ipv4_flow_item(struct doca_dpdk_item_entry *entry,
						struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *flow_item = entry->item;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, type);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, type);
	struct rte_flow_item_ipv4 *spec = &entry->item_data.ipv4.spec;
	struct rte_flow_item_ipv4 *mask = &entry->item_data.ipv4.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	entry->item_data.ipv4.match_layer = type;//inner or outer
	if (!doca_is_ip_zero(&src_ip)){
		spec->hdr.src_addr = rte_cpu_to_be_16(src_ip.a.ipv4_addr);
		mask->hdr.src_addr = UINT32_MAX;
		if (doca_is_ip_max(&src_ip))
			entry->flags |= DOCA_MODIFY_SIP;
	}

	if (!doca_is_ip_zero(&dst_ip)){
		spec->hdr.dst_addr = dst_ip.a.ipv4_addr;
		mask->hdr.dst_addr = UINT32_MAX;
		if (doca_is_ip_max(&dst_ip))
			entry->flags |= DOCA_MODIFY_DIP;
	}
	spec->hdr.next_proto_id = match->out_l4_type;//IPPROTO_UDP or IPPROTO_TCP
	mask->hdr.next_proto_id = UINT8_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_ipv4_item;
}

/**
 * @brief todo.
 *    
 * @entry match
 *
 * @return 
 */
static int doca_gw_dpdk_modify_ipv6_item(__rte_unused struct doca_dpdk_item_entry *entry, __rte_unused struct doca_gw_match *match)
{
	return 0;
}

static void doca_gw_dpdk_build_ipv6_flow_item(struct doca_dpdk_item_entry *entry, 
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	struct doca_ip_addr src_ip = DOCA_GET_SRC_IP(match, type);
	struct doca_ip_addr dst_ip = DOCA_GET_DST_IP(match, type);
	struct rte_flow_item_ipv6 *spec = &entry->item_data.ipv6.spec;
	struct rte_flow_item_ipv6 *mask = &entry->item_data.ipv6.mask;

	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	if (!doca_is_ip_zero(&src_ip)){
		doca_set_item_ipv6_max(mask->hdr.src_addr);
		memcpy(spec->hdr.src_addr, src_ip.a.ipv6_addr, sizeof(src_ip.a.ipv6_addr));
		if (doca_is_ip_max(&src_ip))
			entry->flags |= DOCA_MODIFY_SIP;
	}
	if (!doca_is_ip_zero(&dst_ip)){
		doca_set_item_ipv6_max(mask->hdr.dst_addr);
		memcpy(spec->hdr.dst_addr, dst_ip.a.ipv6_addr, sizeof(dst_ip.a.ipv6_addr));
		if (doca_is_ip_max(&dst_ip))
			entry->flags |= DOCA_MODIFY_DIP;
	}
	spec->hdr.proto = match->out_l4_type;
	mask->hdr.proto = UINT8_MAX;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_ipv6_item;
}

static int
doca_gw_dpdk_modify_vxlan_item(struct doca_dpdk_item_entry *entry,
						struct doca_gw_match *match)
{
	struct rte_flow_item_vxlan *spec = &entry->item_data.vxlan.spec;

	if (match->tun.vxlan.tun_id) 
		memcpy(spec->vni, (uint8_t*)(&match->tun.vxlan.tun_id), 3);
	return 0;
}

static void doca_gw_dpdk_build_vxlan_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_vxlan *spec = &entry->item_data.vxlan.spec;
	struct rte_flow_item_vxlan *mask = &entry->item_data.vxlan.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_VXLAN;
	if (!match->tun.vxlan.tun_id) 
		return;
	doca_set_item_vni_max(mask->vni);
	memcpy(spec->vni, (uint8_t*)(&match->tun.vxlan.tun_id), 3); //TODO
	flow_item->spec = spec;
	flow_item->mask = mask;
	if (match->tun.vxlan.tun_id == UINT32_MAX) {
		entry->flags |= DOCA_MODIFY_VLAN_ID;
		entry->modify_item = doca_gw_dpdk_modify_vxlan_item;
	}
}

static void doca_gw_dpdk_build_inner_eth_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	struct rte_flow_item *flow_item = entry->item;
	struct rte_flow_item_eth *spec = &entry->item_data.eth.spec;
	struct rte_flow_item_eth *mask = &entry->item_data.eth.mask;

	flow_item->type = RTE_FLOW_ITEM_TYPE_ETH;
	spec->type = rte_cpu_to_be_16(doca_gw_get_l3_protol(match, OUTER_MATCH));
	mask->type = UINT16_MAX;
	flow_item->spec = spec;
	flow_item->mask = mask;
}

static void doca_gw_dpdk_build_end_flow_item(struct doca_dpdk_item_entry *entry)
{
	struct rte_flow_item *flow_item = entry->item;
	flow_item->type = RTE_FLOW_ITEM_TYPE_END;
}

static int
doca_gw_dpdk_modify_tcp_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.tcp.match_layer;
	uint16_t src_port = DOCA_GET_SRC_PORT(match, layer);
	uint16_t dst_port = DOCA_GET_DST_PORT(match, layer);
	struct rte_flow_item_tcp *spec = &entry->item_data.tcp.spec;

	if ((entry->flags & DOCA_MODIFY_SPORT) && src_port)
		spec->hdr.src_port = rte_cpu_to_be_16(src_port);
	if ((entry->flags & DOCA_MODIFY_DPORT) && dst_port)
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
	return 0;
}

static void doca_gw_dpdk_build_tcp_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	uint16_t src_port = DOCA_GET_SRC_PORT(match, type);
	uint16_t dst_port = DOCA_GET_DST_PORT(match, type);
	struct rte_flow_item_tcp *spec = &entry->item_data.tcp.spec;
	struct rte_flow_item_tcp *mask = &entry->item_data.tcp.mask;

	entry->item_data.tcp.match_layer = type;
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	if (src_port) {
		spec->hdr.src_port = rte_cpu_to_be_16(src_port);
		mask->hdr.src_port = UINT16_MAX;
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
		mask->hdr.dst_port = UINT16_MAX;
		if (dst_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_DPORT;
	}
	if (src_port == 0 && dst_port == 0)
		return;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_tcp_flow_item;
}

static int
doca_gw_dpdk_modify_udp_flow_item(struct doca_dpdk_item_entry *entry,
	struct doca_gw_match *match)
{
	uint8_t layer = entry->item_data.udp.match_layer;
	uint16_t src_port = DOCA_GET_SRC_PORT(match, layer);
	uint16_t dst_port = DOCA_GET_DST_PORT(match, layer);
	struct rte_flow_item_udp *spec = (struct rte_flow_item_udp *)((uintptr_t)entry->item->spec);

	if ((entry->flags & DOCA_MODIFY_SPORT) && src_port)
		spec->hdr.src_port = rte_cpu_to_be_16(src_port);
	if ((entry->flags & DOCA_MODIFY_DPORT) && dst_port)
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
	return 0;
}

static void doca_gw_dpdk_build_udp_flow_item(struct doca_dpdk_item_entry *entry,
			struct doca_gw_match *match, uint8_t type)
{
	struct rte_flow_item *item = entry->item;
	uint16_t src_port = DOCA_GET_SRC_PORT(match, type);
	uint16_t dst_port = DOCA_GET_DST_PORT(match, type);
	struct rte_flow_item_udp *spec = &entry->item_data.udp.spec;
	struct rte_flow_item_udp *mask = &entry->item_data.udp.mask;

	entry->item_data.udp.match_layer = type;
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	if (src_port) {
		spec->hdr.src_port = rte_cpu_to_be_16(src_port);
		mask->hdr.src_port = UINT16_MAX;
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
		mask->hdr.dst_port = UINT16_MAX;
		if (dst_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_DPORT;
	}
	if (src_port == 0 && dst_port == 0)
		return;
	item->spec = spec;
	item->mask = mask;
	if (entry->flags)
		entry->modify_item = doca_gw_dpdk_modify_udp_flow_item;
	return;
}

static int doca_gw_dpdk_build_item(struct doca_gw_match *match,
					struct doca_gw_pipe_dpdk_flow *pipe_flow, struct doca_gw_error *err)
{
#define NEXT_ITEM (&pipe_flow->item_entry[idx++]) //reduce line length
	uint8_t idx = 0, type = OUTER_MATCH;

	doca_gw_dpdk_build_eth_flow_item(NEXT_ITEM, match);
	if (match->vlan_id)
		doca_gw_dpdk_build_vlan_item(NEXT_ITEM, match);
	if (doca_match_is_ipv4(match, type))
		doca_gw_dpdk_build_ipv4_flow_item(NEXT_ITEM, match, type);
	else
		doca_gw_dpdk_build_ipv6_flow_item(NEXT_ITEM, match, type);
	if((match->tun.type != DOCA_TUN_NONE)) {
		switch (match->tun.type) {
		case DOCA_TUN_VXLAN:
			if (!match->out_dst_port)
				match->out_dst_port = DOCA_VXLAN_DEFAULT_PORT;
			doca_gw_dpdk_build_udp_flow_item(NEXT_ITEM, match, type);
			doca_gw_dpdk_build_vxlan_flow_item(NEXT_ITEM, match);
			doca_gw_dpdk_build_inner_eth_flow_item(NEXT_ITEM, match);
			break;
		default:
			err->type = DOCA_ERROR_UNSUPPORTED;
			DOCA_LOG_INFO("not support type:%x\n", match->tun.type);
			return -1;
		}
		type = INNER_MATCH;
		if (doca_match_is_ipv4(match, type))
			doca_gw_dpdk_build_ipv4_flow_item(NEXT_ITEM, match, type);
		else
			doca_gw_dpdk_build_ipv6_flow_item(NEXT_ITEM, match, type);
	}
	if (doca_match_is_tcp(match))
		doca_gw_dpdk_build_tcp_flow_item(NEXT_ITEM, match, type);
	else if (doca_match_is_udp(match))
		doca_gw_dpdk_build_udp_flow_item(NEXT_ITEM, match, type);
	else {
		DOCA_LOG_INFO("not support l3 type.\n");
		return -1;
	}
	doca_gw_dpdk_build_end_flow_item(NEXT_ITEM);
	pipe_flow->nb_items = idx;
	return 0;
}

/*
  *currently, only for decap, only need the decap length
  *for encap, will check how to implement.
  	is encap buffer fixed or will be modifid by packet info?
*/
static void
doca_gw_dpdk_build_ether_header(uint8_t **header, struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_ether_hdr eth_hdr;
	struct doca_gw_match *match = cfg->match;

	memset(&eth_hdr, 0, sizeof(struct rte_ether_hdr));
	if (!doca_is_mac_zero(match->out_dst_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &eth_hdr.s_addr);
	if (!doca_is_mac_zero(match->out_src_mac))
		rte_ether_addr_copy((const struct rte_ether_addr*)match->out_src_mac, &eth_hdr.d_addr);
	eth_hdr.ether_type = rte_cpu_to_be_16(doca_gw_get_l3_protol(match, OUTER_MATCH));
	memcpy(*header, &eth_hdr, sizeof(eth_hdr));
	*header += sizeof(eth_hdr);
	if (match->vlan_id) {
		struct rte_vlan_hdr vlan;
		memset(&vlan, 0x0, sizeof(vlan));
		memcpy(*header, &vlan, sizeof(vlan));
		*header += sizeof(vlan);
	}
}

static void
doca_gw_dpdk_build_ipv4_header(uint8_t **header,
			__rte_unused struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_ipv4_hdr ipv4_hdr;

	memset(&ipv4_hdr, 0, sizeof(struct rte_ipv4_hdr));
	if (!doca_is_ip_zero(&cfg->match->out_src_ip))
		ipv4_hdr.src_addr = rte_cpu_to_be_16(cfg->match->out_src_ip.a.ipv4_addr);
	if (!doca_is_ip_zero(&cfg->match->out_dst_ip))
		ipv4_hdr.dst_addr = rte_cpu_to_be_16(cfg->match->out_dst_ip.a.ipv4_addr);
	if (!cfg->match->out_l4_type)
		ipv4_hdr.next_proto_id = cfg->match->out_l4_type;
	memcpy(*header, &ipv4_hdr, sizeof(ipv4_hdr));
	*header += sizeof(ipv4_hdr); //todo, need check if has optional fields in iphdr
}

static void
doca_gw_dpdk_build_udp_header(uint8_t **header, struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_udp_hdr udp_hdr;

	memset(&udp_hdr, 0, sizeof(struct rte_flow_item_udp));
	if (cfg->match->out_src_port)
		udp_hdr.src_port = rte_cpu_to_be_16(cfg->match->out_src_port);
	if (cfg->match->out_dst_port)
		udp_hdr.dst_port = rte_cpu_to_be_16(cfg->match->out_dst_port);
	memcpy(*header, &udp_hdr, sizeof(udp_hdr));
	*header += sizeof(udp_hdr);
}

static void
doca_gw_dpdk_build_vxlan_header(uint8_t **header,
		struct doca_gw_pipeline_cfg *cfg)
{
	struct rte_vxlan_hdr vxlan_hdr;

	memset(&vxlan_hdr, 0, sizeof(struct rte_vxlan_hdr));
	memcpy(&vxlan_hdr.vx_vni, (uint8_t*)(&cfg->match->tun.vxlan.tun_id), 3);
	memcpy(*header, &vxlan_hdr, sizeof(vxlan_hdr));
	*header += sizeof(vxlan_hdr);
}

struct endecap_layer doca_endecap_layers[] = {
	{FILL_ETH_HDR,		doca_gw_dpdk_build_ether_header},
	{FILL_IPV4_HDR,		doca_gw_dpdk_build_ipv4_header},
	{FILL_UDP_HDR,		doca_gw_dpdk_build_udp_header},
	{FILL_VXLAN_HDR,	doca_gw_dpdk_build_vxlan_header},
};

static void
doca_gw_dpdk_build_endecap_data(uint8_t **header,
			struct doca_gw_pipeline_cfg *cfg,
			uint16_t flags)
{
	uint8_t idx;
	struct endecap_layer *layer;
	
	for (idx = 0; idx < RTE_DIM(doca_endecap_layers); idx++) {
		layer = &doca_endecap_layers[idx];
		if (flags & layer->layer)
			layer->fill_data(header, cfg);
	}
}

static void doca_gw_dpdk_build_vxlandecap_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg)
{
	uint8_t *header, decap_layer;
	struct rte_flow_action *action = entry->action;
	struct doca_dpdk_action_rawdecap_data *vxlan_decap;

	decap_layer = FILL_ETH_HDR | FILL_IPV4_HDR | FILL_UDP_HDR | FILL_VXLAN_HDR;
	vxlan_decap = &entry->action_data.rawdecap;
	header = vxlan_decap->data;
	vxlan_decap->conf.data = vxlan_decap->data;
	doca_gw_dpdk_build_endecap_data(&header, cfg, decap_layer);
	vxlan_decap->conf.size = header - vxlan_decap->data;
	action->type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	action->conf = &vxlan_decap->conf;
}

static int doca_gw_dpdk_build_tunnel_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg)
{
	struct doca_gw_match *match = cfg->match;

	switch (match->tun.type) {
		case DOCA_TUN_VXLAN:
			doca_gw_dpdk_build_vxlandecap_action(entry, cfg);
			return 0;
		default:
			return -1;
	}
}

static int doca_gw_dpdk_modify_mac_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	uint8_t *mac_addr;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_mac *set_mac = &entry->action_data.mac.set_mac;

	mac_addr = action->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC?
		pkt_action->mod_src_mac : pkt_action->mod_dst_mac;
	if (!doca_is_mac_zero(mac_addr))
		memcpy(set_mac->mac_addr, mac_addr, DOCA_ETHER_ADDR_LEN);
	return 0;
}

static void doca_gw_dpdk_build_mac_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	struct rte_flow_action *action = entry->action;
	uint8_t *mac_addr;
	struct rte_flow_action_set_mac *set_mac = &entry->action_data.mac.set_mac;

	mac_addr = (type == DOCA_SRC? cfg->actions->mod_src_mac : cfg->actions->mod_dst_mac);
	memcpy(set_mac->mac_addr, mac_addr, DOCA_ETHER_ADDR_LEN);
	action->conf = set_mac;
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_MAC_SRC : RTE_FLOW_ACTION_TYPE_SET_MAC_DST);
	if (doca_is_mac_max(mac_addr))
		entry->modify_action = doca_gw_dpdk_modify_mac_action;
}

static int doca_gw_dpdk_modify_ipv4_addr_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	struct doca_ip_addr *ip_addr;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_ipv4 *ipv4 = &entry->action_data.ipv4.ipv4;

	ip_addr = action->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC?
		&pkt_action->mod_src_ip : &pkt_action->mod_dst_ip;
	if (!doca_is_ip_zero(ip_addr))
		ipv4->ipv4_addr = rte_cpu_to_be_32(ip_addr->a.ipv4_addr);
	return 0;
}

static void doca_gw_dpdk_build_ipv4_addr_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	struct rte_flow_action *action = entry->action;
	struct doca_ip_addr *ip_addr;
	struct rte_flow_action_set_ipv4 *ipv4 = &entry->action_data.ipv4.ipv4;

	ip_addr = (type == DOCA_SRC? &cfg->actions->mod_src_ip : &cfg->actions->mod_dst_ip);
	ipv4->ipv4_addr = rte_cpu_to_be_32(ip_addr->a.ipv4_addr);
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC : RTE_FLOW_ACTION_TYPE_SET_IPV4_DST);
	action->conf = ipv4;
	if (doca_is_ip_max(ip_addr))
		entry->modify_action = doca_gw_dpdk_modify_ipv4_addr_action;
}

static int doca_gw_dpdk_modify_l4_port_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_actions *pkt_action)
{
	uint16_t l4port;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_tp *set_tp = &entry->action_data.l4port.l4port;

	l4port = action->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC?
		pkt_action->mod_src_port : pkt_action->mod_dst_port;
	if (l4port)
		set_tp->port = rte_cpu_to_be_16(l4port);
	return 0;
}

static void doca_gw_dpdk_build_l4_port_action(struct doca_dpdk_action_entry *entry,
									struct doca_gw_pipeline_cfg *cfg, uint8_t type)
{
	uint16_t l4port;
	struct rte_flow_action *action = entry->action;
	struct rte_flow_action_set_tp *set_tp = &entry->action_data.l4port.l4port;

	l4port = (type == DOCA_SRC? cfg->actions->mod_src_port : cfg->actions->mod_dst_port);
	set_tp->port = rte_cpu_to_be_16(l4port);
	action->type = (type == DOCA_SRC? RTE_FLOW_ACTION_TYPE_SET_TP_SRC : RTE_FLOW_ACTION_TYPE_SET_TP_DST);
	action->conf = set_tp;
	if (l4port == UINT16_MAX)
		entry->modify_action = doca_gw_dpdk_modify_l4_port_action;
}

static void doca_gw_dpdk_build_dec_ttl_action(struct doca_dpdk_action_entry *entry)
{
	struct rte_flow_action *action = entry->action;

	action->type = RTE_FLOW_ACTION_TYPE_DEC_TTL;
	action->conf = NULL;
}

static int doca_gw_dpdk_build_action(struct doca_gw_pipeline_cfg *cfg,
					struct doca_gw_pipe_dpdk_flow *pipe_flow)
{
#define NEXT_ACTION (&pipe_flow->action_entry[idx++])
	int ret = 0;
	uint8_t idx = 0;
	struct doca_gw_match *match = cfg->match;
	struct doca_gw_actions *actions = cfg->actions;

	if (actions->decap && match->tun.type)
		ret = doca_gw_dpdk_build_tunnel_action(NEXT_ACTION, cfg);
	if (!doca_is_mac_zero(actions->mod_src_mac))
		doca_gw_dpdk_build_mac_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (!doca_is_mac_zero(actions->mod_dst_mac))
		doca_gw_dpdk_build_mac_action(NEXT_ACTION, cfg, DOCA_DST);
	if (!doca_is_ip_zero(&actions->mod_src_ip))
		doca_gw_dpdk_build_ipv4_addr_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (!doca_is_ip_zero(&actions->mod_dst_ip))
		doca_gw_dpdk_build_ipv4_addr_action(NEXT_ACTION, cfg, DOCA_DST);
	if (actions->mod_src_port)
		doca_gw_dpdk_build_l4_port_action(NEXT_ACTION, cfg, DOCA_SRC);
	if (actions->mod_dst_port)
		doca_gw_dpdk_build_l4_port_action(NEXT_ACTION, cfg, DOCA_DST);
	if (actions->dec_ttl)
		doca_gw_dpdk_build_dec_ttl_action(NEXT_ACTION);
	pipe_flow->nb_actions = idx;
	return ret;
}

static void doca_gw_dpdk_build_end_action(struct doca_gw_pipe_dpdk_flow *pipe)
{
	struct rte_flow_action *action = &pipe->actions[pipe->nb_actions++];
	action->type = RTE_FLOW_ACTION_TYPE_END;
}

static inline uint64_t
doca_gw_get_rss_type(uint32_t rss_type)
{
	uint64_t rss_flags = 0;
	if (rss_type && DOCA_RSS_IP)
		rss_flags |= ETH_RSS_IP;
	if (rss_type && DOCA_RSS_UDP)
		rss_flags |= ETH_RSS_UDP;
	if (rss_type && DOCA_RSS_TCP)
		rss_flags |= ETH_RSS_TCP;
	return rss_flags;
}

static int 
doca_gw_dpdk_build_rss_action(struct doca_dpdk_action_entry *entry,
									struct doca_fwd_table_cfg *fwd_cfg)
{
	int qidx;
	struct rte_flow_action *action = entry->action;
	struct doca_dpdk_action_rss_data *rss = &entry->action_data.rss;

	rss->conf.queue_num = fwd_cfg->rss.num_queues;
	for (qidx = 0; qidx < fwd_cfg->rss.num_queues; qidx++)
		rss->queue[qidx] = fwd_cfg->rss.queues[qidx];
	rss->conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
	rss->conf.types = doca_gw_get_rss_type(fwd_cfg->rss.rss_flags);
	rss->conf.queue = rss->queue;
	action->type = RTE_FLOW_ACTION_TYPE_RSS;
	action->conf = &rss->conf;
	return 0;
}

static int doca_gw_dpdk_build_fwd(struct doca_gw_pipe_dpdk_flow *pipe,
									struct doca_fwd_table_cfg *fwd_cfg)
{
	struct doca_dpdk_action_entry *action_entry;

	action_entry = &pipe->action_entry[pipe->nb_actions++];
	switch(fwd_cfg->type) {
		case DOCA_FWD_RSS:
			doca_gw_dpdk_build_rss_action(action_entry, fwd_cfg);
			break;
		default:
			return 1;
	}
	return 0;
}

static int
doca_gw_dpdk_modify_pipe_match(struct doca_gw_pipe_dpdk_flow *pipe,
	struct doca_gw_match *match)
{
	int idex, ret;
	struct doca_dpdk_item_entry *item_entry;

	for (idex = 0 ; idex < pipe->nb_items; idex++) {
		item_entry = &pipe->item_entry[idex];
		if (item_entry->modify_item == NULL)
			continue;
		ret = item_entry->modify_item(item_entry, match);
		if (ret)
			return ret;
	}
	return 0;
}

static int
doca_gw_dpdk_modify_pipe_actions(struct doca_gw_pipe_dpdk_flow *pipe,
	struct doca_gw_actions *actions)
{
	int idex, ret;
	struct doca_dpdk_action_entry *action_entry;
	
	for (idex = 0 ; idex < pipe->nb_actions; idex++) {
		action_entry = &pipe->action_entry[idex];
		if (action_entry->modify_action == NULL)
			continue;
		ret = action_entry->modify_action(action_entry, actions);
		if (ret)
			return ret;
	}
	return 0;
}

static struct rte_flow*
doca_gw_dpdk_create_flow(uint16_t port_id,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[])
{
	struct rte_flow *flow;
	struct rte_flow_error err;

	flow = rte_flow_create(port_id, attr, pattern, actions, &err);
	if (!flow) {
		DOCA_LOG_ERR("Port %u create flow fail, type %d message: %s\n",
			port_id, err.type,
			err.message ? err.message : "(no stated reason)");
	}
	return flow;
}

static int
doca_gw_dpdk_free_flow(uint16_t port_id, struct rte_flow *flow)
{
	int ret;
	struct rte_flow_error err;

	ret = rte_flow_destroy(port_id, flow, &err);
	if (ret) {
		DOCA_LOG_ERR("Port %u free flow fail, type %d message: %s\n",
			port_id, err.type,
			err.message ? err.message : "(no stated reason)");	
	}
	return ret;
}

//create flow gourp 0 match eth action jump group 1
static struct rte_flow*
doca_gw_dpdk_create_root_jump(uint16_t port_id)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS];
	struct rte_flow_action actions[MAX_ACTIONS];
	struct rte_flow_action_jump jump;

	memset(&attr, 0x0, sizeof(struct rte_flow_attr));
	memset(items, 0x0, sizeof(items));
	memset(actions, 0x0, sizeof(actions));
	attr.group = 0;
	attr.ingress = 1;
	items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[0].type = RTE_FLOW_ITEM_TYPE_END;
	jump.group = 1;
	actions[0].type = RTE_FLOW_ACTION_TYPE_JUMP;
	actions[0].conf = &jump;
	return doca_gw_dpdk_create_flow(port_id, &attr, items, actions);
}

/*default match, -> queue[0]*/
static struct rte_flow*
doca_gw_dpdk_create_def_queue(uint16_t port_id)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS];
	struct rte_flow_action actions[MAX_ACTIONS];
	struct rte_flow_action_queue queue;

	memset(&attr, 0x0, sizeof(struct rte_flow_attr));
	memset(items, 0x0, sizeof(items));
	memset(actions, 0x0, sizeof(actions));	
	attr.group = 1;
	attr.ingress = 1;
	attr.priority = MAX_FLOW_FRIO;
	items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[0].type = RTE_FLOW_ITEM_TYPE_END;
	queue.index = 0;
	actions[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	actions[0].conf = &queue;

	return doca_gw_dpdk_create_flow(port_id, &attr, items, actions);
}

struct rte_flow *
doca_gw_dpdk_pipe_create_flow(struct doca_gw_pipe_dpdk_flow *pipe,
					struct doca_gw_match *match, struct doca_gw_actions *actions,
					__rte_unused struct doca_gw_monitor *mon, struct doca_fwd_table_cfg *cfg,
					__rte_unused struct doca_gw_error *err)
{
	if(match == NULL && actions == NULL && cfg == NULL)
		return NULL;
	if (doca_gw_dpdk_modify_pipe_match(pipe, match)) {
		DOCA_LOG_ERR("modify pipe match item fail.\n");
		return NULL;
	}
	if (doca_gw_dpdk_modify_pipe_actions(pipe, actions)) {
		DOCA_LOG_ERR("modify pipe action fail.\n");
		return NULL;
	}
	/*if different fwd action, need over write this action[x] ??*/
	if (doca_gw_dpdk_build_fwd(pipe, cfg)) {
		DOCA_LOG_ERR("build pipe fwd action fail.\n");
		return NULL;
	}
	doca_gw_dpdk_build_end_action(pipe);
	return doca_gw_dpdk_create_flow(pipe->port_id, &pipe->attr, pipe->items, pipe->actions);
}

/*todo , how to manager root/queue flows for one port.*/
int
doca_gw_dpdk_init_port(uint16_t port_id)
{
	struct rte_flow *root,*queue;

	root = doca_gw_dpdk_create_root_jump(port_id);
	if(root == NULL)
		return -1;
	queue = doca_gw_dpdk_create_def_queue(port_id);
	if(queue == NULL)
		return -1;
	return 0;
}

/**
 * @brief: there is not create the pipeline flows templet?
 *    
 * @param match
 *
 * @return 
 */
struct doca_gw_pipe_dpdk_flow*
doca_gw_dpdk_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_error *err)
{
	int ret;
	struct doca_gw_pipe_dpdk_flow *pipe_flow;

	pipe_flow = doca_gw_dpdk_get_free_pipe();
	if (pipe_flow == NULL) {
		err->type = DOCA_ERROR_NOMORE_PIPE_RESOURCE;
		return NULL;
	}
	//pipe_flow->port_id = (uint16_t)cfg->port->port_id;  
	pipe_flow->attr.ingress = 1;
	pipe_flow->attr.group = 1; // group 0 jump group 1
	ret = doca_gw_dpdk_build_item(cfg->match, pipe_flow, err);
	if (ret) {
		err->type = DOCA_ERROR_PIPE_BUILD_IMTE_ERROR;
		goto free_pipe;
	}
	ret = doca_gw_dpdk_build_action(cfg, pipe_flow);
	if (ret) {
		err->type = DOCA_ERROR_PIPE_BUILD_ACTION_ERROR;
		goto free_pipe;
	}
	return pipe_flow;
free_pipe:
	doca_gw_dpdk_pipe_release(pipe_flow);
	return NULL;
}


