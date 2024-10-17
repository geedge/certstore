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
#include <openssl/x509.h>
#include <openssl/evp.h>

#define CT_PATH_MAX 256
#define CT_ARRARY_LEN (CT_PATH_MAX/2)
#define CT_STRING_MAX 1024

struct http_request
{
#define DATALEN 128
    int thread_id;
    int is_valid;
    char *odata;
    X509 *origin;
    char *keyring_uuid_str;
    char *sni;
    char rkey[DATALEN];
    struct timespec create_time;
    struct evhttp_request *evh_req;
};

struct pxy_obj_keyring
{
    char keyring_uuid[64];
    int use_hsm;
    int slot_id;
	uint64_t expire_time;
	EVP_PKEY *key;
    X509 *issuer;
    char keyring_type[CT_ARRARY_LEN];
	char public_algo[CT_STRING_MAX];
	char v3_ctl[CT_STRING_MAX];
	int is_send;
    time_t op_time;
	atomic64_t ref_cnt;
    STACK_OF(X509) *stack_ca;
};

struct cert_store_rt
{
    struct maat *instance;
	int mode;
    int local_debug;
    int thread_nu;
	int expire_after;
    int listen_port;
    int local_redis_port;
    char local_redis_ip[32];
    char ca_path[128];
    char uninsec_path[128];
};

extern struct cert_store_rt * g_cert_store;

#endif
