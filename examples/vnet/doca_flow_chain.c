#include "doca_flow_chain.h"

int doca_flow_chain_init(int flags)
{
    if (flags & DOCA_FLOW_CHAIN_ACL)
        doca_dpdk_enable_acl();
}
