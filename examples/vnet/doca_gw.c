#include "doca_gw.h"
#include "gw.h"
#include "doca_log.h"
#include "doca_gw_dpdk.h"
#include "doca_dpdk_priv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DOCA_LOG_MODULE(doca_gw)
//TODO: get it from dpdk
#define DOCA_GW_MAX_PORTS (128)

struct doca_fwd_tbl {
    const char * name;
    void * handler;
    uint32_t id;
    struct doca_fwd_table_cfg cfg;
};

static struct doca_gw_port *doca_gw_used_ports[DOCA_GW_MAX_PORTS];

static struct doca_gw_port *doca_get_port_byid(uint8_t port_id)
{
	return doca_gw_used_ports[port_id];
}

static struct doca_gw_port *doca_alloc_port_byid(uint8_t port_id, struct doca_gw_port_cfg *cfg)
{
	struct doca_gw_port *port;

	port = (struct doca_gw_port *) malloc(sizeof(struct doca_gw_port) + cfg->priv_data_size);
	if (port == NULL)
		return NULL;
	memset(port, 0x0, sizeof(struct doca_gw_port));
	port->port_id = port_id;
	LIST_INIT(&port->pipe_list);
	doca_gw_used_ports[port_id] = port;
	return port;
}

static struct doca_gw_pipelne_entry* doca_gw_alloc_new_entry(void)
{
	struct doca_gw_pipelne_entry *entry;

	entry = (struct doca_gw_pipelne_entry *) malloc(sizeof(struct doca_gw_pipelne_entry));
	if (entry)
		memset(entry, 0x0, sizeof(struct doca_gw_pipelne_entry));
	return entry;
}

static bool doca_gw_save_port(struct doca_gw_port *port)
{
    int i = 0;
    for ( i = 0 ; i < DOCA_GW_MAX_PORTS ; i++) {
        if (doca_gw_used_ports[i] == NULL) {
            doca_gw_used_ports[i] = port;
            port->idx = i;
            return true;
        }
    }
    return false;
}

uint8_t *doca_gw_port_priv_data(struct doca_gw_port *p)
{
    return &p->user_data[0];
}

int doca_gw_init(struct doca_gw_cfg *cfg,struct doca_gw_error *err)
{
    DOCA_LOG_INFO("total sessions = %d\n",cfg->total_sessions);
    if (err) {
        *err = *err;
    }
    doca_gw_init_dpdk(cfg);
    memset(doca_gw_used_ports,0,sizeof(doca_gw_used_ports));
    return 0;
}


/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
struct doca_gw_pipelne_entry *doca_gw_pipeline_add_entry(uint16_t pipe_queue, 
                      struct doca_gw_pipeline *pipeline, struct doca_gw_match *match,
                      struct doca_gw_actions *actions,struct doca_gw_monitor *mon,
                      struct doca_fwd_tbl *fwd, struct doca_gw_error *err)
{

    struct doca_gw_pipelne_entry *entry;

    if(fwd == NULL) {
        DOCA_LOG_WARN("no forwading");
        return NULL;
    }
	//todo: mv all of bellowing to dpdk layer...
	entry = doca_gw_alloc_new_entry();
    if (entry == NULL)
            return NULL;
    entry->pipe_entry = doca_gw_dpdk_pipe_create_flow(entry, pipeline->handler,
		match, actions, mon, &fwd->cfg, err);
    if (entry->pipe_entry == NULL) {
            DOCA_LOG_INFO("create pip entry fail.\n");
            goto free_pipe_entry;
    }
    entry->id = pipeline->pipe_entry_id++;
	LIST_INSERT_HEAD(&pipeline->entry_list, entry, next);
    DOCA_LOG_INFO("offload[%d]: queue = %d port id=%p, match =%pi mod %p, fwd %d", entry->id, 
                  pipe_queue, pipeline, match, actions, fwd->id);
	return entry;
free_pipe_entry:
	free(entry);
	return NULL;
}

int doca_gw_rm_entry(uint16_t pipe_queue, struct doca_gw_pipelne_entry *entry)
{
    DOCA_LOG_INFO("(pipe %d) HW release id%d",pipe_queue, entry->id);
	// TODO: how to get the port id?
	//doca_gw_dpdk_free_flow(0, entry->pipe_entry);
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
struct doca_gw_port * doca_gw_port_start(struct doca_gw_port_cfg *cfg, struct doca_gw_error *err)
{
	struct doca_gw_port *port = doca_alloc_port_byid(cfg->port_id, cfg);

    if ( port == NULL ) {
        return NULL;
    }
    memset(port, 0, sizeof(struct doca_gw_port));
    if (!doca_gw_save_port(port)) 
        goto fail_port_start;

    if ( cfg != NULL ){
        switch(cfg->type) {
            case DOCA_GW_PORT_DPDK:
                DOCA_LOG_INFO("port is dpdk, matching port id");
                // init all required data sturcures for port.
                break;
            case DOCA_GW_PORT_DPDK_BY_ID:
                //TODO: need to parse devargs
                DOCA_LOG_INFO("new doca port type:dpdk port id:%s", cfg->devargs);
                port->port_id = atoi(cfg->devargs);
                break;
            default:
                DOCA_LOG_ERR("unsupported port type");
                err->message = "unsupported port type";
                goto fail_port_start;
        }
    }
    return port;
fail_port_start:
    free(port);
    return NULL;
}

/**
 * @brief - close port
 *  release all resources used by port, including all HW rules.
 *
 * @param port
 *
 * @return 
 */
int doca_gw_port_stop(struct doca_gw_port *port)
{
    if (port != NULL) {
       printf("port id = %d stopped\n", port->port_id); 
    }
    return 0;
}

struct doca_gw_pipeline *doca_gw_create_pipe(struct doca_gw_pipeline_cfg *cfg, struct doca_gw_error *err)
{
    static uint32_t pipe_id = 1;
    struct doca_gw_pipeline *pl;

	pl = malloc(sizeof(struct doca_gw_pipeline));
    if (cfg == NULL || pl == NULL)
		return NULL;
    memset(pl,0,sizeof(struct doca_gw_pipeline));
	LIST_INIT(&pl->entry_list);
	pl->id = pipe_id++;
    pl->handler = doca_gw_dpdk_create_pipe(cfg, err);
	LIST_INSERT_HEAD(&cfg->port->pipe_list, pl, next);
	printf("port:%u create pipe:%p\n", cfg->port->port_id, pl);
    return pl;
}

static void doca_gw_free_pipe(uint16_t portid, struct doca_gw_pipeline *pipe)
{
	struct doca_gw_pipelne_entry *entry;

	DOCA_LOG_INFO("portid:%u free pipeid:%u\n", portid,pipe->id);
	while((entry = LIST_FIRST(&pipe->entry_list))) {
		LIST_REMOVE(entry, next);
		DOCA_LOG_INFO("free pipe entry:%d\n", entry->id);
		doca_gw_dpdk_pipe_free_entry(portid, entry);
		free(entry);		
	}
	free(pipe);
}

void doca_gw_destroy(uint16_t port_id)
{
	struct doca_gw_port *port;
	struct doca_gw_pipeline *pipe;

	DOCA_LOG_INFO("destroy port_id:%u\n", port_id);
	port = doca_get_port_byid(port_id);
	while((pipe = LIST_FIRST(&port->pipe_list))) {
		LIST_REMOVE(pipe, next);
		doca_gw_free_pipe(port_id, pipe);
	}
	doca_gw_used_ports[port_id] = NULL;
	free(port);
}

struct doca_fwd_tbl *doca_gw_create_fwd_tbl(struct doca_fwd_table_cfg *cfg)
{
    static uint32_t fwd_id = 0;
    struct doca_fwd_tbl *tbl = malloc(sizeof(struct doca_fwd_tbl));
    memset(tbl, 0, sizeof(struct doca_fwd_tbl));
    tbl->cfg = *cfg;
    tbl->id = fwd_id++;
    DOCA_LOG_INFO("add fwd tbl");
    return tbl;
}
