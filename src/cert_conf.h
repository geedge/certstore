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

#include "moodycamel_maat_rule.h"
#include "MESA_htable.h"

#define CT_PATH_MAX 256
#define CT_ARRARY_LEN (CT_PATH_MAX/2)
#define CT_STRING_MAX 1024

struct request_t{
#define DATALEN 128
    int thread_id;
    int is_valid;
    char *odata;
    X509 *origin;
    int keyring_id;
    char sni[DATALEN];
    char rkey[DATALEN];
    struct evhttp_request *evh_req;
};

struct pxy_obj_keyring{
	int keyring_id;
	int ref_cnt;
    char keyring_type[CT_ARRARY_LEN];
	uint64_t expire_after;
	char public_algo[CT_STRING_MAX];
	char v3_ctl[CT_STRING_MAX];
    char finger[EVP_MAX_MD_SIZE];
    EVP_PKEY *key;
    X509 *root;
	int is_valid;
    STACK_OF(X509) *stack_ca;
};

struct _initer_addr_t{
    uint16_t e_port;    /*libevent prot*/
    uint16_t maat_port;    /*maat redis port*/
    char maat_ip[16];      /*maat redis ip */
    int dbindex;           /*maat redis dbindex*/

    uint16_t store_port;   /*store redis port */
    char store_ip[16];     /*store redis ip*/
};

struct ntc_maat_t{
    unsigned int maat_json_switch;
    unsigned int effective_interval_s;
    char info_path[128];
    char pxy_path[128];
    char inc_cfg_dir[128];
    char full_cfg_dir[128];
};

struct config_bucket_t{
    Maat_feather_t feather;
    int table_id;
    unsigned int local_debug;
    unsigned int thread_nu;
	unsigned int expire_after;
    char ca_path[128];
    char uninsec_path[128];
    struct ntc_maat_t maat_t;
    struct _initer_addr_t addr_t;
};

extern struct config_bucket_t *cert_default_config();

extern void cert_init_config(char *config);

#endif
