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
#include <MESA/breakpad_mini.h>
#include <MESA/MESA_prof_load.h>
#include <MESA/MESA_handle_logger.h>

RTLogInit2Data logging_sc_lid;

void mesa_logging_print(int log_level, const char *module, const char *msg)
{
    MESA_handle_runtime_log(logging_sc_lid.run_log_handle, log_level, (const char *)module, msg);
    return;
}

void cert_syslog_init(const char *config)
{
	struct breakpad_instance *breakpad;

    MESA_load_profile_int_def(config, (const char *)"SYSTEM",(const char *)"DEBUG_SWITCH",
                              &logging_sc_lid.debug_switch, 1);
    MESA_load_profile_string_def(config, (const char *)"SYSTEM",(const char *)"RUN_LOG_PATH",
	 							logging_sc_lid.run_log_path, 128, "conf/zlog.conf");

	if (0 != MESA_handle_runtime_log_creation(logging_sc_lid.run_log_path))
	{
		fprintf(stderr, "Create log runtime_log_handle error, init failed\n");
		goto finish;
	}

    logging_sc_lid.run_log_handle = MESA_create_runtime_log_handle("./logs", RLOG_LV_DEBUG);
    if(logging_sc_lid.run_log_handle == NULL)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Create log runtime_log_handle error, init failed!");
        goto finish;
    }else
    {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Log module initialization");
    }

	breakpad = breakpad_init(config, "breakpad", logging_sc_lid.run_log_handle);
	if(breakpad == NULL)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed at starting breakpad.");
	}
finish:
    return;
}


