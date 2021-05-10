#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "doca_flow.h"
#include "gw.h"
#include "doca_log.h"
#include "doca_dpdk.h"
#include "doca_dpdk_priv.h"


DOCA_LOG_MODULE(doca_flow);


uint8_t *doca_flow_port_priv_data(struct doca_flow_port *p)
{
	return &p->user_data[0];
}

int doca_flow_init(struct doca_flow_cfg *cfg, struct doca_flow_error *err)
{
	DOCA_LOG_INFO("total sessions = %d\n", cfg->total_sessions);
	if (err)
		*err = *err;
	doca_dpdk_init(cfg);
	return 0;
}

/**
 * @brief
 *
 * @param match
 *
 * @return
 */
struct doca_flow_pipe_entry *doca_flow_pipe_add_entry(
	uint16_t pipe_queue, struct doca_flow_pipe *pipe,
	struct doca_flow_match *match, struct doca_flow_actions *actions,
	struct doca_flow_monitor *mon, struct doca_flow_fwd *fwd,
	struct doca_flow_error *err)
{
	if (pipe == NULL || match == NULL || actions == NULL)
		return NULL;
	pipe_queue = pipe_queue;
	return doca_dpdk_pipe_create_flow(pipe, pipe_queue, match, actions, mon,
	                                  fwd, err);
}

int doca_flow_rm_entry(uint16_t pipe_queue,
		       struct doca_flow_pipe_entry *entry)
{
	DOCA_LOG_INFO("(pipe %d) HW release id%d", pipe_queue, entry->id);
	/* doca_dpdk_free_flow(0, entry->pipe_entry); */
	free(entry);
	return 0;
}

/**
 * @brief
 *
 * @param cfg
 * @param port
 *
 * @return
 */
struct doca_flow_port *doca_flow_port_start(struct doca_flow_port_cfg *cfg,
					    struct doca_flow_error *err)
{
	struct doca_flow_port *port = NULL;

	if (cfg == NULL)
		return NULL;
	switch (cfg->type) {
	case DOCA_FLOW_PORT_DPDK:
		DOCA_LOG_INFO("port is dpdk, matching port id");
		/* init all required data sturcures for port. */
		break;
	case DOCA_FLOW_PORT_DPDK_BY_ID:
		DOCA_LOG_INFO("new doca port type:dpdk port id:%s",
			      cfg->devargs);
		cfg->port_id = atoi(cfg->devargs);
		port = doca_dpdk_port_start(cfg, err);
		break;
	default:
		DOCA_LOG_ERR("unsupported port type");
		err->message = "unsupported port type";
		return NULL;
	}
	return port;
}

/**
 * @brief - close port
 *  release all resources used by port, including all HW rules.
 *
 * @param port
 *
 * @return
 */
int doca_flow_port_stop(struct doca_flow_port *port)
{
	if (port != NULL)
		DOCA_LOG_INFO("port id = %d stopped\n", port->port_id);
	return 0;
}

struct doca_flow_pipe *
doca_flow_create_pipe(struct doca_flow_pipe_cfg *cfg,
                      struct doca_flow_fwd *fwd,
		      struct doca_flow_error *err)
{
	if (cfg == NULL)
		return NULL;
	return doca_dpdk_create_pipe(cfg, fwd, err);
}

void doca_flow_destroy(uint16_t port_id)
{
	doca_dpdk_destroy(port_id);
}

void doca_flow_dump_pipe(uint16_t port_id)
{
	doca_dpdk_dump_pipe(port_id);
}
