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
#define DATALEN 128
    int thread_id;
    char *odata;
    X509 *origin;
    int keyring_id;
    char sni[DATALEN];
    char rkey[DATALEN];
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
    MESA_htable_handle htable, oldhtable;
};

struct _initer_addr_t{
    uint16_t e_port;    /* libevent prot*/
    uint16_t r_port;    /* redis port*/
    char r_ip[16];      /* redis ip */
};

struct config_bucket_t{
    unsigned int thread_nu;
	unsigned int expire_after;
    char info_path[128];
    char pxy_path[128];
    char def_path[128];
    struct _initer_addr_t addr_t;
    struct key_ring_list keyring;
};

extern struct config_bucket_t *cert_default_config();

extern void cert_init_config(char *config);

#endif
