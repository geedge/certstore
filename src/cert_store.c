/*************************************************************************
	> File Name: cert_server.c
	> Author: fengweihao
	> Mail: fengweihao158@163.com
	> Created Time: Tue 29 May 2018 06:45:23 PM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rt_string.h"
#include "rt_common.h"
#include "cert_daemon.h"
#include "cert_init.h"
#include "cert_session.h"
#include "logging.h"
#include "MESA_prof_load.h"

/* GIT Release */
#define CERT_GIT_RELEASE "1.1.0"

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

static void help()
{
  printf("Welcome to cert server %s\n", cert_revision());
  printf("cert_server <--debug|--release|--daemon>\n"
         "Usage:\n"
         "  --debug      | Run the program in debug mode and display\n"
         "               | the print message on the interface\n"
         "  --release    | Run the program in release mode, the interface\n"
         "               | will not display print message\n"
         "  --daemon     | Run in daemon mode\n");
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
        if (!STRCMP (argv[i], "--release")){
            run_mode = 0x00;
            goto finish;
        }

		/** decoder configuration parser */
        if (!STRCMP(argv[i], "--debug")){
            run_mode = 0x10;
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

int main(int argc, char **argv)
{
    cert_argv_parser(argc, argv);

    cert_syslog_init(CERT_BASIC_CFG);

    if (MODE_TYPE(0x20)){
        daemonize();
    }

    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Cert server init success\n");

    cert_init_config(CERT_BASIC_CFG);

    cert_session_init();

    return 0;
}

