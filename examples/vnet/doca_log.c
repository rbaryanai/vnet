#include <stdio.h>
#include <stdlib.h>
#include "string.h"

#include "doca_log.h"

static enum doca_log_level doca_log_default_level = DOCA_LOG_LEVEL_INFO;  
static int  doca_log_moudle_id = 0;

void register_doca_log(struct doca_log_module *module, const char *name)
{
    //TODO: add a lock here
    int len = strlen(name)+1;
    memset(module,0,sizeof(struct doca_log_module));
    module->name = malloc(len*sizeof(char));
    memcpy(module->name, name, len);
    module->level = doca_log_default_level;
    module->id = doca_log_moudle_id++;
}

void doca_log(struct doca_log_module *module, enum doca_log_level level, const char *format,...)
{
    va_list args;
    if (level > module->level) {
        return;
    }

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}


void doca_log_cfg(enum doca_log_type type, const char *cfg)
{
    //TODO: real support
    switch(type) {
        case DOCA_LOG_TYPE_NONE:
        case DOCA_LOG_TYPE_STDERR:
            break;
    }

    if (cfg) {
    }
}

