#include <stdio.h>
#include "doca_gw.h"
#include "doca_utils.h"

struct doca_gw_port port1 = {0};
struct doca_gw_port port2 = {0};
static struct doca_gw_pipeline pipeline1 = {0};
static struct doca_fwd_tbl sw_fwd_tbl = {0};

static void init_doca(void)
{
    struct doca_gw_error err = {0};
    struct doca_gw_cfg cfg = {1000};
    if (!doca_gw_init(&cfg,&err)) { 
        printf("success\n");
    }
}

static int gw_build_underlay_overlay(struct doca_gw_pipeline *pipeline, struct doca_gw_port *port)
{
    // configure a pipeline. values of 0 means the parameters
    // will not be used. mask means for each entry a value should be provided
    // a real value means a constant value and should not be added on any entry
    // added
    struct doca_gw_pipeline_cfg pcfg = {0};
    struct doca_gw_match match = {0};

    match.out_dst_ip.a.ipv4_addr = 0xffffffff;
    match.out_dst_ip.type = DOCA_IPV4;
    match.out_proto_type = DOCA_IPV4;
    match.out_dst_port = 4789; // VXLAN (change to enum/define)


    match.tun.type = DOCA_TUN_VXLAN;
    match.tun.tun_id = 0xffffffff;

    //inner
    match.in_dst_ip.a.ipv4_addr = 0xffffffff;
    match.in_src_ip.a.ipv4_addr = 0xffffffff;
    match.in_src_ip.type = DOCA_IPV4;
    match.in_proto_type = 0xff;

    match.in_src_port = 0xffff;
    match.in_dst_port = 0xffff;

    pcfg.name  = "overlay-to-underlay";
    pcfg.port = port;
    pcfg.match  = &match;
    pcfg.count  = false;
    pcfg.mirror =  false;;

    return doca_gw_create_pipe(&pcfg, pipeline);
}




static int gw_build_default_fwd_to_sw(struct doca_fwd_tbl *tbl)
{
#define GW_MAX_QUEUES 16
    int i;
    struct doca_fwd_table_cfg cfg = {0};
    uint16_t queues[GW_MAX_QUEUES];

    for(i = 0 ; i < GW_MAX_QUEUES ; i++){
        queues[i] = i;
    }

    cfg.type = DOCA_SW_FWD;
    cfg.s.queues = (uint16_t *) &queues;
    cfg.s.num_queues = GW_MAX_QUEUES;

    return doca_gw_add_fwd(&cfg, tbl);
}

void build_data_plain(void)
{
    struct doca_gw_port_cfg cfg_port1 = { DOCA_GW_PORT_DPDK_BY_ID, "0" };
    struct doca_gw_port_cfg cfg_port2 = { DOCA_GW_PORT_DPDK_BY_ID, "1" };
    struct doca_gw_error err = {0};

    printf("init GW application .\n");

    // init any resources needed for DOCA, this might include
    // specific cfg, or implementaiton type (we start with always DPDK)
    init_doca();

    // adding ports
    doca_gw_port_start(&cfg_port1, &port1, &err);
    doca_gw_port_start(&cfg_port2, &port2, &err);

    // create pipeline
    if (gw_build_underlay_overlay(&pipeline1, &port1)){
        printf("failed to allocate pipeline\n");
    }

    if (gw_build_default_fwd_to_sw(&sw_fwd_tbl)){
        printf("failed to add SW fwd table\n");
    }
}


int doca_tencet_init(void){
    build_data_plain();
    return 0;
}


