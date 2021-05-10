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

#include <stdio.h>
#include <stdlib.h>
#include "string.h"
#include "doca_log.h"

static enum doca_log_level doca_log_default_level = DOCA_LOG_LEVEL_INFO;
static int doca_log_moudle_id;

/*need add a lock here*/
void register_doca_log(struct doca_log_module *module, const char *name)
{
	int len = strlen(name) + 1;

	memset(module, 0, sizeof(struct doca_log_module));
	module->name = malloc(len * sizeof(char));
	memcpy(module->name, name, len);
	module->level = doca_log_default_level;
	module->id = doca_log_moudle_id++;
}

void doca_log(__doca_unused struct doca_log_module *module,
		enum doca_log_level level, const char *format, ...)
{
	va_list args;

	/*tmp handle, set --log_level*/
	if (level > doca_log_default_level)
		return;
	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

/**
 * @brief - configure logger:
 *   can be syslog file
 *   can be anyother we chose to support
 *
 * @param type
 * @param cfg
 */
void doca_log_cfg(enum doca_log_type type, __doca_unused const char *cfg)
{
	switch (type) {
	case DOCA_LOG_TYPE_NONE:
	case DOCA_LOG_TYPE_STDERR:
		break;
	}
}

void doca_set_log_level(uint32_t log_level)
{
	doca_log_default_level = log_level;
}

uint32_t doca_is_debug_level(void)
{
	return doca_log_default_level >= DOCA_LOG_LEVEL_DEBUG;
}
