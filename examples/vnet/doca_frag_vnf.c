#include <stdio.h>
#include "doca_frag_vnf.h"
#include "doca_vnf.h"

static int frag_init(void *p)
{
    int queues = *((int *)p);
    int ret = 0;

//    ret |= gw_create();
//    ret |= gw_init_lb(ret);
//    ret |= gw_init_doca_ports_and_pipes(ret, queues);
    printf("Ok FRAG Init\n");
    return ret;
}
static int frag_destroy(void)
{
    return 0;
}

int frag_handle_packet(struct doca_pkt_info *pinfo)
{
    return 0;
}
struct doca_vnf frag_vnf = {
    .doca_vnf_init = &frag_init,
    .doca_vnf_process_pkt = &frag_handle_packet,
    .doca_vnf_destroy = &frag_destroy
};

struct doca_vnf *frag_get_doca_vnf(void)
{
    return &frag_vnf;
}
