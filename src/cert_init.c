/*************************************************************************
	> File Name: cert_init.c
	> Author: fengweihao
	> Mail:
	> Created Time: Fri 01 Jun 2018 12:06:01 AM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rt_string.h"
#include "rt_common.h"
#include "rt_util.h"
#include "rt_file.h"
#include "cert_init.h"
#include "logging.h"
#include "MESA_prof_load.h"

struct config_bucket_t certConfig = {
    .thread_nu = 1,
    .ca_path = "/usr/local/bin/",
    .e_port = 9995,
    .r_ip = "0.0.0.0",
	.r_port = 3366,
};

struct config_bucket_t *cert_default_config()
{
    return &certConfig;
}

static int load_system_config(char *config)
{
    int xret = -1;

    struct config_bucket_t *rte = cert_default_config();

    xret = MESA_load_profile_uint_nodef(config, "CONFIG", "thread-nu", &(rte->thread_nu));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the number of running threads failed");
    }

    xret = MESA_load_profile_string_nodef(config, "CONFIG", "ca-path", rte->ca_path, 128);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the CA path failure");
        goto finish;
    }

    if(!rt_dir_exsit(rte->ca_path)) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "The signature certificate(%s) does not exist", rte->ca_path);
        goto finish;
    }
finish:
    return xret;
}

static int load_module_config(char *config)
{
    int xret = -1;

    struct config_bucket_t *rte = cert_default_config();

    xret = MESA_load_profile_short_nodef(config, "LIBEVENT", "port", (short *)&(rte->e_port));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Libevent Port invalid\n");
        goto finish;
    }

    xret = MESA_load_profile_string_nodef(config, "REDIS", "ip", rte->r_ip, 16);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Ip invalid\n");
        goto finish;
    }

    xret = MESA_load_profile_short_nodef(config, "REDIS", "port", (short *)&(rte->r_port));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis Port invalid\n");
        goto finish;
    }
finish:
    return xret;
}

void cert_init_config(char *config)
{
    load_system_config(config);

    load_module_config(config);
}

