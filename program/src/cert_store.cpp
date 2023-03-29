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
#include <cert_store.h>
#include <cert_session.h>
#include "logging.h"

#include <MESA/MESA_prof_load.h>

struct cert_store_rt * g_cert_store;

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

static void cert_store_preview ()
{
    printf("\r\nBasic Configuration of CertStore \n");
	printf("%30s:%45s\n", "Run Mode", (g_cert_store->mode == 1)?"async":"sync");
    printf("%30s:%45d\n", "The Threads", g_cert_store->thread_nu);
    printf("%30s:%45s\n", "Store Redis Ip", g_cert_store->local_redis_ip);
    printf("%30s:%45d\n", "Store Redis Port", g_cert_store->local_redis_port);
    printf("%30s:%45d\n", "Libevent Port", g_cert_store->listen_port);
    printf("%30s:%45s\n", "Cert Path", g_cert_store->ca_path);
    printf("%30s:%45s\n", "Uninsec cert Path", g_cert_store->uninsec_path);
    printf("%30s:%45s\n", "Log Directory", logging_sc_lid.run_log_path);
    printf("\r\n");
}

static int signals[] = {SIGHUP, SIGPIPE, SIGUSR1,SIGINT};

void __signal_handler_cb(int sig)
{
	switch (sig)
	{
		case SIGHUP:
			mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Recv signal sighup, reload log config!");
            cert_store_log_reconstruction();
            break;
		case SIGPIPE:
			break;
		case SIGUSR1:
		case SIGINT:
			sigproc(SIGINT);
			break;
		default:
			break;
	}
}

int rt_file_exsit(const char *realpath_file)
{
    return (!access(realpath_file, F_OK));
}

void load_system_config(const char *main_profile)
{
    MESA_load_profile_int_def(main_profile, "CONFIG", "thread-nu", &(g_cert_store->thread_nu), 1);
    MESA_load_profile_int_def(main_profile, "CONFIG", "mode", &(g_cert_store->mode), 0);
	MESA_load_profile_int_def(main_profile, "CONFIG","expire_after", &(g_cert_store->expire_after), 30);
	MESA_load_profile_int_def(main_profile, "CONFIG","local_debug", &(g_cert_store->local_debug), 1);
	MESA_load_profile_int_def(main_profile, "CERTSTORE_REDIS", "port", &(g_cert_store->local_redis_port), 6379);
	MESA_load_profile_string_def(main_profile, "CERTSTORE_REDIS", "ip", g_cert_store->local_redis_ip, sizeof(g_cert_store->local_redis_ip), "127.0.0.1");
	MESA_load_profile_int_def(main_profile, "LIBEVENT", "port", &(g_cert_store->listen_port), 9991);

    MESA_load_profile_string_def(main_profile, "CONFIG", "ca_path", g_cert_store->ca_path, sizeof(g_cert_store->ca_path), "");
    if (!rt_file_exsit(g_cert_store->ca_path))
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the ca path failed or the (%s) does not exist", g_cert_store->ca_path);
    }

    MESA_load_profile_string_def(main_profile, "CONFIG", "untrusted_ca_path", g_cert_store->uninsec_path, sizeof(g_cert_store->uninsec_path), "");
    if (!rt_file_exsit(g_cert_store->uninsec_path))
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Read the untrusted ca path failed or the (%s) does not exist",g_cert_store->uninsec_path);
    }
}

int main(int argc, char **argv)
{
	int opt = 0;
	const char * main_profile = "./conf/cert_store.ini";

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

	g_cert_store = (struct cert_store_rt *)calloc(1, sizeof(struct cert_store_rt));
	assert(g_cert_store);

    load_log_module(main_profile, version());

    load_system_config(main_profile);

    cert_store_preview();

    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Cert server init success");

	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++)
	{
		signal(signals[i], __signal_handler_cb);
	}

    cert_store_session_init(main_profile);

    return 0;
}

