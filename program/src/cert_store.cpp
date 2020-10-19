/*************************************************************************
	> File Name: cert_server.c
	> Author: fengweihao
	> Mail:
	> Created Time: Tue 29 May 2018 06:45:23 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "rt_string.h"
#include "rt_common.h"
#include <cert_conf.h>
#include <cert_session.h>
#include "logging.h"

#include <MESA/MESA_prof_load.h>

#define CERT_BASIC_CFG "./conf/cert_store.ini"

/* VERSION STRING */
#ifdef TARGET_GIT_VERSION
static __attribute__((__used__)) const char * git_ver = TARGET_GIT_VERSION;
#else
static __attribute__((__used__)) const char * git_ver = "1.1";
#endif

const char * version()
{
	return git_ver;
}

enum syslog_display_format{
    FORMAT_CONSOLE,
    FORMAT_FILE,
    FORMAT_SYSLOG
};

static
void cert_preview ()
{
    struct config_bucket_t *rte = cfg_instanec();

    printf("\r\nBasic Configuration of CertStore \n");
	printf("%30s:%45s\n", "Run Mode", (rte->mode == 1)?"async":"sync");
    printf("%30s:%45d\n", "The Threads", rte->thread_nu);
    printf("%30s:%45s\n", "Store Redis Ip", rte->addr_t.store_ip);
    printf("%30s:%45d\n", "Store Redis Port", rte->addr_t.store_port);
    printf("%30s:%45s\n", "Maat Redis Ip", rte->addr_t.maat_ip);
    printf("%30s:%45d\n", "Maat Redis Port", rte->addr_t.maat_port);
    printf("%30s:%45d\n", "Maat Redis index", rte->addr_t.dbindex);
    printf("%30s:%45d\n", "Libevent Port", rte->addr_t.e_port);
    printf("%30s:%45s\n", "Cert Path", rte->ca_path);
    printf("%30s:%45s\n", "Uninsec cert Path", rte->uninsec_path);
    printf("%30s:%45s\n", "Log Directory", logging_sc_lid.run_log_path);
    printf("%30s:%45s\n", "Table Info", rte->maat_t.info_path);
    if (rte->maat_t.maat_json_switch == 1){
        printf("%30s:%45s\n", "Pxy Obj Keyring", rte->maat_t.pxy_path);
    }
    if (rte->maat_t.maat_json_switch == 0){
        printf("%30s:%45d\n", "Scan Interval", rte->maat_t.effective_interval_s);
        printf("%30s:%45s\n", "Full Cfg Path", rte->maat_t.full_cfg_dir);
        printf("%30s:%45s\n", "Inc  Cfg Path", rte->maat_t.inc_cfg_dir);

    }
    printf("\r\n");
}

int main(int argc, char **argv)
{
	int opt = 0;
	while ((opt = getopt(argc, argv, "v")) != -1)
	{
		switch (opt)
		{
			case 'v':
				fprintf(stderr, "Welcome to certstore, Version: %s\n", version());
				return 0;
			default:
				break;
		}
	}
    cert_syslog_init(CERT_BASIC_CFG, version());

    cert_init_config(CERT_BASIC_CFG);

    cert_preview();

    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Cert server init success");

    cert_session_init();

    signal(SIGINT, sigproc);

    return 0;
}

