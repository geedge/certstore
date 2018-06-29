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

struct request_t{
#define DATALEN 64
    char host[DATALEN];

    int thread_id;

    int flag;

    int valid;

    struct evhttp_request *evh_req;
};

struct config_bucket_t{
    unsigned int thread_nu;

    unsigned int days;

    char ca_path[128];

    uint16_t e_port;    /* libevent prot*/

    char r_ip[16];      /* redis ip */

    uint16_t r_port;    /* redis port*/
};

extern struct config_bucket_t *cert_default_config();

extern void cert_init_config(char *config);

#endif
