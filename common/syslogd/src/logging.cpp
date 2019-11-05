/*************************************************************************
	> File Name: logging.c
	> Author:
	> Mail:
	> Created Time: 2018年06月18日 星期一 22时45分43秒
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <dirent.h>
#include <ctype.h>

#include "rt_common.h"
#include "rt_time.h"
#include "rt_string.h"
#include "logging.h"
#include "MESA_prof_load.h"
#include "MESA_handle_logger.h"

RTLogInit2Data logging_sc_lid;

void mesa_logging_print(int log_level, const char *module, const char *msg)
{
    MESA_handle_runtime_log(logging_sc_lid.run_log_handle, log_level, (const char *)module, msg);
    return;
}

void cert_syslog_init(const char *config)
{
    char run_log_path[256] = {0};

    MESA_load_profile_int_def(config, (const char *)"SYSTEM",(const char *)"DEBUG_SWITCH",
                              &logging_sc_lid.debug_switch, 1);
    MESA_load_profile_int_def(config, (const char *)"SYSTEM",(const char *)"RUN_LOG_LEVEL",
                              &logging_sc_lid.run_log_level, 10);
    MESA_load_profile_string_def(config, (const char *)"SYSTEM",(const char *)"RUN_LOG_PATH",
                                 logging_sc_lid.run_log_path, 128, NULL);

    snprintf(run_log_path, 255, "%s/%s", logging_sc_lid.run_log_path, "certstore.log");

    logging_sc_lid.run_log_handle = MESA_create_runtime_log_handle(run_log_path, logging_sc_lid.run_log_level);
    if(logging_sc_lid.run_log_handle == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Create log runtime_log_handle error, init failed!");
        goto finish;
    }else{
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Log module initialization");
    }
finish:
    return;
}


