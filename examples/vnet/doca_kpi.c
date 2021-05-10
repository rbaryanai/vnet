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

#include "doca_log.h"
#include "doca_kpi.h"
#include "doca_flow.h"

void doca_pipeline_kpi_get(__doca_unused struct doca_flow_pipeline *pl,
			   __doca_unused struct doca_pipeline_kpi *kpi)
{
	*kpi = *kpi;
}
