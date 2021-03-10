#include "doca_gw.h"
#include "doca_log.h"
#include "doca_gw_dpdk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

DOCA_LOG_MODULE(doca_gw)

struct doca_fwd_tbl {
    const char * name;
    void * handler;
    uint32_t id;
    struct doca_fwd_table_cfg cfg;
};

struct doca_gw_pipeline {
    void * handler;
    uint32_t id;
};

struct doca_gw_port
{
    uint32_t port_id;
    uint8_t  user_data[0];
};

uint8_t *doca_gw_port_priv_data(struct doca_gw_port *p)
{
    return &p->user_data[0];
}

int doca_gw_init(struct doca_gw_cfg *cfg,struct doca_gw_error *err)
{
    DOCA_LOG_INFO("total sessions = %d\n",cfg->total_sessions);
    printf("total sessions = %d\n",cfg->total_sessions);
    if (err) {
        *err = *err;
    }
	doca_gw_init_dpdk(cfg);
    return 0;
}

struct doca_gw_pipelne_entry {
    int id;
	void *pipe_entry;
};

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
    static int  pipe_entry_id = 0;
    struct doca_gw_pipelne_entry *entry;

    if(fwd == NULL) {
        DOCA_LOG_WARN("no forwading");
        return NULL;
    }
    entry = (struct doca_gw_pipelne_entry *) malloc(sizeof(struct doca_gw_pipelne_entry));
    if (entry == NULL)
            return NULL;
    memset(entry,0,sizeof(struct doca_gw_pipelne_entry));
    entry->pipe_entry = doca_gw_dpdk_pipe_create_flow(pipeline->handler,
		match, actions, mon, &fwd->cfg, err);
    if (entry->pipe_entry == NULL) {
            DOCA_LOG_INFO("create pip entry fail.\n");
            goto free_pipe_entry;
    }
    entry->id = pipe_entry_id++;
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
    struct doca_gw_port *port = (struct doca_gw_port *) malloc(sizeof(struct doca_gw_port)+cfg->priv_data_size);

    if ( port == NULL ) {
        return NULL;
    }
    memset(port, 0, sizeof(struct doca_gw_port));

    if ( cfg != NULL ){
        switch(cfg->type) {
            case DOCA_GW_PORT_DPDK:
                DOCA_LOG_INFO("port is dpdk, matching port id");
                // init all required data sturcures for port.
                break;
            case DOCA_GW_PORT_DPDK_BY_ID:
                DOCA_LOG_INFO("new doca port type:dpdk port id:%s", cfg->devargs);
                break;
            default:
                DOCA_LOG_ERR("unsupported port type");
                err->message = "unsupported port type";
                free(port);
                port = NULL;
        }
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
    struct doca_gw_pipeline *pl = malloc(sizeof(struct doca_gw_pipeline));
    memset(pl,0,sizeof(struct doca_gw_pipeline));

    if (cfg != NULL && pl != NULL) {
        // allocate what is needed
        pl->id = pipe_id++;
    }
    pl->handler = doca_gw_dpdk_create_pipe(cfg, err);
    return pl;
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
