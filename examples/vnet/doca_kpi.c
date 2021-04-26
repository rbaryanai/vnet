#include "doca_log.h"
#include "doca_kpi.h"
#include "doca_flow.h"

void doca_pipeline_kpi_get(__doca_unused struct doca_flow_pipeline *pl,
			   __doca_unused struct doca_pipeline_kpi *kpi)
{
	*kpi = *kpi;
}
