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

#ifndef _DOCA_KPI_H_
#define _DOCA_KPI_H_

#include <stdint.h>
#include "doca_gauge.h"

struct doca_flow_pipeline;

struct doca_pipeline_kpi {
	uint64_t avg_cycles;
	uint64_t total_cycles;
	uint64_t load;
};

void doca_pipeline_kpi_get(struct doca_flow_pipeline *pl,
			   struct doca_pipeline_kpi *kpi);

#endif
