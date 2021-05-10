/*
 * Copyright (C) 2021 Mellanox Technologies, Ltd. ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of Mellanox Technologies Ltd.
 * (the "Company") and all right, title, and interest in and to the software
 * product, including all associated intellectual property rights, are and
 * shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include "doca_flow_chain.h"

int doca_flow_chain_init(int flags)
{
    if (flags & DOCA_FLOW_CHAIN_ACL)
        doca_dpdk_enable_acl();
}
