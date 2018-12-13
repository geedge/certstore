/*************************************************************************
	> File Name: cert_init.c
	> Author: fengweihao
	> Mail:
	> Created Time: Fri 01 Jun 2018 12:06:01 AM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rt_string.h"
#include "rt_common.h"
#include "rt_file.h"
#include "cert_conf.h"
#include "logging.h"

#include "MESA_prof_load.h"

struct config_bucket_t certConfig = {
    .thread_nu = 1,
    .expire_after = 30,
    .ca_path  = "./cert/mesalab-ca.pem",
    .uninsec_path = "./cert/mesalab-ca-untrust.pem",
    .addr_t = {9995, 6379, "0.0.0.0", 0, 6379, "0.0.0.0"},
    .keyring = {0, 0, NULL, NULL},
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

    xret = MESA_load_profile_uint_nodef(config, "CONFIG", "expire_after", &(rte->expire_after));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the number of valid time failed");
    }

    xret = MESA_load_profile_string_nodef(config, "CONFIG", "ca_path", rte->ca_path, 128);
    if (xret <0 && rt_file_exsit(rte->ca_path)){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the ca path failed or the (%s) does not exist",
                         rte->ca_path);
        goto finish;

    }
    xret = MESA_load_profile_string_nodef(config, "CONFIG", "untrusted_ca_path", rte->uninsec_path, 128);
    if (xret <0 && rt_file_exsit(rte->uninsec_path)){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the untrusted ca path failed or the (%s) does not exist",
                             rte->ca_path);
        goto finish;

    }
finish:
    return xret;
}

static int load_module_config(char *config)
{
    int xret = -1;

    struct config_bucket_t *rte = cert_default_config();

    xret = MESA_load_profile_short_nodef(config, "LIBEVENT", "port", (short *)&(rte->addr_t.e_port));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Libevent Port invalid");
        goto finish;
    }

    xret = MESA_load_profile_string_nodef(config, "MAAT_REDIS", "ip", rte->addr_t.maat_ip, 16);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Maat redis ip invalid");
        goto finish;
    }

    xret = MESA_load_profile_short_nodef(config, "MAAT_REDIS", "port", (short *)&(rte->addr_t.maat_port));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Maat redis port invalid");
        goto finish;
    }

    xret = MESA_load_profile_short_nodef(config, "MAAT_REDIS", "dbindex", (short *)&(rte->addr_t.dbindex));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Maat redis dbindex invalid");
        goto finish;
    }

    xret = MESA_load_profile_string_nodef(config, "CERTSTORE_REDIS", "ip", rte->addr_t.store_ip, 16);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Certsotre redis ip invalid");
        goto finish;
    }

    xret = MESA_load_profile_short_nodef(config, "CERTSTORE_REDIS", "port", (short *)&(rte->addr_t.store_port));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Certsotre redis port invalid");
        goto finish;
    }

finish:
    return xret;
}

static int load_maat_config(char *config)
{
    int xret = -1;

    struct ntc_maat_t *maat_t = &cert_default_config()->maat_t;

    xret = MESA_load_profile_uint_nodef(config, "NTC_MAAT", "maat_json_switch", &(maat_t->maat_json_switch));
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the number of running threads failed");
    }

    xret = MESA_load_profile_string_nodef(config, "NTC_MAAT", "table_info", maat_t->info_path, 128);
    if (xret < 0 && !rt_file_exsit( maat_t->info_path)){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the table info failed or the (%s) does not exist",
                          maat_t->info_path);
        goto finish;
    }

    if (maat_t->maat_json_switch == 1){
        xret = MESA_load_profile_string_nodef(config, "NTC_MAAT", "pxy_obj_keyring", maat_t->pxy_path, 128);
         if (xret < 0 && !rt_file_exsit(maat_t->pxy_path)){
             mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the pxy obj keyring failed or the (%s) does not exist",
                              maat_t->pxy_path);
             goto finish;
         }
    }

    if (maat_t->maat_json_switch == 0){
        xret = MESA_load_profile_uint_nodef(config, "NTC_MAAT", "effective_interval", &(maat_t->effective_interval_s));
        if (xret < 0){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Reading the interval of scan failed");
        }
        xret = MESA_load_profile_string_nodef(config, "NTC_MAAT", "inc_cfg_dir", maat_t->inc_cfg_dir, 128);
        if (xret < 0 && !rt_file_exsit( maat_t->inc_cfg_dir)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the table info failed or the (%s) does not exist",
                              maat_t->inc_cfg_dir);
            goto finish;
        }
        xret = MESA_load_profile_string_nodef(config, "NTC_MAAT", "full_cfg_dir", maat_t->full_cfg_dir, 128);
        if (xret < 0 && !rt_file_exsit( maat_t->full_cfg_dir)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the table info failed or the (%s) does not exist",
                              maat_t->full_cfg_dir);
            goto finish;
        }
    }
finish:
    return xret;
}

void cert_init_config(char *config)
{
    load_system_config(config);

    load_maat_config(config);

    load_module_config(config);
}

