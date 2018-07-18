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

static void rt_get_pname_by_pid(pid_t pid, char *task_name)
{
#define BUF_SIZE 1024
    char proc_pid_path[BUF_SIZE];
    char buf[BUF_SIZE];
    sprintf(proc_pid_path, "/proc/%d/status", pid);
    FILE* fp = fopen(proc_pid_path, "r");
    if(NULL != fp){
        if( fgets(buf, BUF_SIZE-1, fp)== NULL ){
            fclose(fp);
        }
        fclose(fp);
        sscanf(buf, "%*s %s", task_name);
    }
}

void mesa_logging_print(int log_level, char *module, char *msg)
{
    MESA_handle_runtime_log(logging_sc_lid.run_log_handle, log_level, module, msg);
    return;
}

int mesa_logging_mkfile(char *file, size_t size)
{
    char tm[24] = {0};
    char pname[32]= {0};

    assert(file);

    if (size < 32)
        return -1;

    rt_curr_tms2str(EVAL_TM_STYLE, tm, 23);
    rt_get_pname_by_pid(getpid(), &pname[0]);
    snprintf(file, 63, "%s-%s-%d-%d-%s.log", pname, getpwuid(getuid())->pw_name, getpwuid(getuid())->pw_uid, getpwuid(getuid())->pw_gid, tm);

    return 0;
}

void cert_syslog_init(char *config)
{
    char run_log_path[256] = {0};

    MESA_load_profile_int_def(config, (const char *)"SYSTEM",(const char *)"DEBUG_SWITCH",
                              &logging_sc_lid.debug_switch, 1);
    MESA_load_profile_int_def(config, (const char *)"SYSTEM",(const char *)"RUN_LOG_LEVEL",
                              &logging_sc_lid.run_log_level, 10);
    MESA_load_profile_string_def(config, (const char *)"SYSTEM",(const char *)"RUN_LOG_PATH",
                                 logging_sc_lid.run_log_path, 128, NULL);

    char file[64] = {0};
    mesa_logging_mkfile(file, 63);
    //STRCAT(logging_sc_lid.run_log_path, file);
    snprintf(run_log_path, 255, "%s/%s", logging_sc_lid.run_log_path, file);

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


