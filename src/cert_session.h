/*************************************************************************
	> File Name: cert_session.h
	> Author:
	> Mail:
	> Created Time: Fri 01 Jun 2018 02:01:08 AM PDT
 ************************************************************************/

#ifndef _CERT_SESSION_H
#define _CERT_SESSION_H

#include "event_struct.h"
#include "MESA_list_queue.h"
#include "rt_sync.h"

struct x509_object_ctx
{
    X509 *root;
    EVP_PKEY *key;

    X509 *insec_root;
    EVP_PKEY *insec_key;
};

typedef struct {
    int  id;

    rt_pthread pid;        /* unique ID of this thread */

    evutil_socket_t accept_fd;

    rt_pthread_attr *attr;

	struct event_base *base;

    struct x509_object_ctx def;

    struct redisAsyncContext *cl_ctx;

    struct redisContext *sync;

    void * (*routine)(void *);  /** Executive entry */

    int field_ids;    /* dispaly */

    int column_ids;

    uint64_t diffTime;

} cert_thread_ctx;

int cert_session_init();

void sigproc(int __attribute__((__unused__))sig);

#endif

