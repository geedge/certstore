/*************************************************************************
	> File Name: cert_init.h
	> Author:
	> Mail:
	> Created Time: Fri 01 Jun 2018 12:06:26 AM PDT
 ************************************************************************/

#ifndef _CERT_INIT_H
#define _CERT_INIT_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <event.h>
#include <x509.h>
#include <evp.h>

enum rt_command_type{
    RT_COMMAND_UKNOWN,

	RT_COMMAND_INSERT,
	RT_COMMAND_DELETE,
	RT_COMMAND_CHANGE,
	RT_COMMAND_SELECT,
	RT_COMMAND_SET_TIME
};

struct redis_t{
    enum rt_command_type type;
    struct redisAsyncContext *cl_ctx;
};

struct request_t{
#define DATALEN 64
    char host[DATALEN];

    int flag;

    int valid;

    struct evhttp_request *evh_req;
};

struct cert_trapper_t{

    int thread_id;

    EVP_PKEY *key;
	X509 *root;

    char *cert;

    struct request_t *req;

    struct redis_t *redis;
};

struct config_bucket_t{
    unsigned int thread_nu;

    char ca_path[128];

    uint16_t e_port;    /* libevent prot*/

    char r_ip[16];      /* redis ip */

    uint16_t r_port;    /* redis port*/
};

extern struct config_bucket_t *cert_default_config();

extern void cert_init_config(char *config);

#endif
