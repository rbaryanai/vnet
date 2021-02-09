#include "doca_gw.h"
#include "doca_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


DOCA_LOG_MODULE(doca_gw)

struct doca_gw_pipeline {
    void * handler;
    uint32_t id;
};



int doca_gw_init(struct doca_gw_cfg *cfg,struct doca_gw_error *err)
{
    DOCA_LOG_ERR("total sessions = %d\n",cfg->total_sessions);
    printf("total sessions = %d\n",cfg->total_sessions);
    if (err) {
        *err = *err;
    }
    return 0;
}


/**
 * @brief 
 *
 * @param match
 *
 * @return 
 */
int doca_gw_add_entry(struct doca_gw_pipeline *pipeline, struct doca_gw_match *match, 
                      struct doca_gw_modify *mod,uint32_t fwd_tbl)
{
    printf("port id=%p, match =%pi mod %p, fwd %d\n", pipeline, match, mod, fwd_tbl);
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
int doca_gw_port_start(struct doca_gw_port_cfg *cfg, struct doca_gw_port *port, struct doca_gw_error *err)
{
    if ( port == NULL ) {
        return -1;
    }

    if ( cfg != NULL ){
        switch(cfg->type) {
            case DOCA_GW_PORT_DPDK:
                printf("port is dpdk, matching port id\n");
                // init all required data sturcures for port.
                break;
            case DOCA_GW_PORT_DPDK_BY_ID:
                printf("port is dpdk, matching port id:%s\n", cfg->devargs);
                break;
            default:
                printf("unsupported port type\n");
                err->message = "unsupported port type\n";
                return -1;
        }
    }
    return 0;
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


struct doca_gw_pipeline *doca_gw_create_pipe(struct doca_gw_pipeline_cfg *cfg)
{
    static uint32_t pipe_id = 1;
    struct doca_gw_pipeline *pl = malloc(sizeof(struct doca_gw_pipeline));
    memset(pl,0,sizeof(struct doca_gw_pipeline));



    if (cfg != NULL && pl != NULL) {
        // allocate what is needed
        pl->id = pipe_id++;
        printf("pipeline: %s, id = %d was created successfully \n",cfg->name, pl->id);
    }
    return pl;
}



int doca_gw_add_fwd(struct doca_fwd_table_cfg *cfg, struct doca_fwd_tbl *fwd)
{
    static uint32_t fwd_id = 0;

    if(cfg != NULL && fwd != NULL) {
        fwd->id = fwd_id++;
        printf("added SW FWD table %d\n",fwd->id);
        return 0;
    }
    return -1;
}
