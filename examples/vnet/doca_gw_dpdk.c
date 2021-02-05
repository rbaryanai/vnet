#include <stdio.h>
#include "doca_gw_dpdk.h"
#include "doca_log.h"

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
	if (match->vlan_id) {
		spec->type = rte_cpu_to_be_16(DOCA_ETH_P_8021Q);
		spec->has_vlan = 1; //will debug if this set is need.
	} else
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
		mask->hdr.src_port = rte_cpu_to_be_16(UINT16_MAX);
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
		mask->hdr.dst_port = rte_cpu_to_be_16(UINT16_MAX);
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
		mask->hdr.src_port = rte_cpu_to_be_16(UINT16_MAX);
		if (src_port == UINT16_MAX)
			entry->flags |= DOCA_MODIFY_SPORT;
	}
	if (dst_port) {
		spec->hdr.dst_port = rte_cpu_to_be_16(dst_port);
		mask->hdr.dst_port = rte_cpu_to_be_16(UINT16_MAX);
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
	ret = doca_gw_dpdk_build_item(cfg->match, pipe_flow, err);
	if (ret) {
		err->type = DOCA_ERROR_PIPE_BUILD_IMTE_ERROR;
		goto free_pipe;
	}
	//doca_gw_build_action(cfg, pipe_flow);

	return pipe_flow;
free_pipe:
	doca_gw_dpdk_pipe_release(pipe_flow);
	return NULL;
}


