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

#include "rt_string.h"
#include "rt_common.h"
#include "cert_daemon.h"
#include "cert_conf.h"
#include "cert_session.h"
#include "logging.h"
#include "MESA_prof_load.h"

/* GIT Release */
#define CERT_GIT_RELEASE "1.1.0"

#define MODE_TYPE(x) run_mode & x

/* Configure Path */
#if 0
#define CERT_BASIC_CFG "/usr/local/etc/cert_store.yaml"
#else
#define CERT_BASIC_CFG "../conf/cert_store.ini"
#endif

static char* cert_revision() { return (CERT_GIT_RELEASE); }

enum syslog_display_format{
    FORMAT_CONSOLE,
    FORMAT_FILE,
    FORMAT_SYSLOG
};

static int run_mode;

static void help()
{
  printf("Welcome to CertStor %s\n", cert_revision());
  printf("cert_store <--normal|--daemon>\n"
         "Usage:\n"
         "  --normal     | Run the program in normal mode\n"
         "  --daemon     | Run the program in daemon mode\n");
}

static void
cert_argv_parser(int argc, char **argv)
{
    int i;

    if (argc != 2){
        help();
        exit(0);
    }

    for (i = 0; argv[i] != NULL; i++){
		/** run version parser */
        if (!STRCMP (argv[i], "--normal")){
            goto finish;
        }
        /** daemonize */
        if (!STRCMP(argv[i], "--daemon")){
            run_mode = 0x20;
            goto finish;
        }
    }
finish:
	return;
}

static
void cert_preview ()
{
    struct config_bucket_t *rte = cert_default_config();

    printf("\r\nBasic Configuration of CertStore \n");
    printf("%30s:%45d\n", "The Threads", rte->thread_nu);
    printf("%30s:%45s\n", "Redis Ip", rte->r_ip);
    printf("%30s:%45d\n", "Redis Port", rte->r_port);
    printf("%30s:%45d\n", "Libevent Port", rte->e_port);
    printf("%30s:%45s\n", "Table Info", rte->info_path);
    printf("%30s:%45s\n", "Pxy Obj Keyring", rte->pxy_path);
    printf("%30s:%45s\n", "Log Directory", logging_sc_lid.run_log_path);

    printf("\r\n");
}

int main(int argc, char **argv)
{
    cert_argv_parser(argc, argv);

    cert_syslog_init(CERT_BASIC_CFG);

    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Cert server init success\n");

    cert_init_config(CERT_BASIC_CFG);

    if (MODE_TYPE(0x20)){
        daemonize();
    }
    cert_preview();

    cert_session_init();

    signal(SIGINT, sigproc);

    return 0;
}

