/*************************************************************************
	> File Name: cert_conf.h
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

#include "MESA_htable.h"

struct request_t{
#define DATALEN 64
    int t_id;
    int flag;
    X509 *origin;
    int kering_id;
    char host[DATALEN];
    char *odata;
    struct evhttp_request *evh_req;
};

struct pxy_obj_keyring{
	int id;
	int service;
    EVP_PKEY *key;
    X509 *root;
	char name[128];
	char type[128];
	char ctl[256];
	char public_algo[256];
	uint64_t expire_after;
	int is_valid;
};

struct key_ring_list
{
	uint64_t sum_cnt;
	MESA_htable_handle htable;
};

struct config_bucket_t{
    unsigned int thread_nu;

    unsigned int days;

    char info_path[128];

    char pxy_path[128];

    uint16_t e_port;    /* libevent prot*/

    char r_ip[16];      /* redis ip */

    uint16_t r_port;    /* redis port*/

    struct key_ring_list keyring;
};

extern struct config_bucket_t *cert_default_config();

extern void cert_init_config(char *config);

#endif
