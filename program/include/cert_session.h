/*************************************************************************
	> File Name: cert_session.h
	> Author:
	> Mail:
	> Created Time: Fri 01 Jun 2018 02:01:08 AM PDT
 ************************************************************************/

#ifndef _CERT_SESSION_H
#define _CERT_SESSION_H

#include <event2/event_compat.h>
#include <MESA/MESA_list_queue.h>

#include "rt_sync.h"


#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/*
 * SHA0 was removed in OpenSSL 1.1.0, including OPENSSL_NO_SHA0.
 */
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined(OPENSSL_NO_SHA0)
#define OPENSSL_NO_SHA0
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define ASN1_STRING_get0_data(value) ASN1_STRING_data(value)
#define SSL_is_server(ssl) (ssl->type != SSL_ST_CONNECT)
#define X509_get_signature_nid(x509) (OBJ_obj2nid(x509->sig_alg->algorithm))
int DH_set0_pqg(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
#endif

/*
 * The constructors returning a SSL_METHOD * were changed to return
 * a const SSL_METHOD * between 0.9.8 and 1.0.0.
 */
#if (OPENSSL_VERSION_NUMBER < 0x1000000fL)
#define CONST_SSL_METHOD SSL_METHOD
#else /* >= OpenSSL 1.0.0 */
#define CONST_SSL_METHOD const SSL_METHOD
#endif /* >= OpensSL 1.0.0 */


/*
 * SSL_OP_NO_* is used as an indication that OpenSSL is sufficiently recent
 * to have the respective protocol implemented.
 *
 * OPENSSL_NO_SSL2 indicates the complete removal of SSL 2.0 support.
 *
 * OPENSSL_NO_SSL3 indicates that no SSL 3.0 connections will be made by
 * default, but support is still present, unless OPENSSL_NO_SSL3_METHOD is
 * also defined.
 */
#if defined(SSL_OP_NO_SSLv2) && !defined(OPENSSL_NO_SSL2) && \
    defined(WITH_SSLV2)
#define HAVE_SSLV2
#endif /* SSL_OP_NO_SSLv2 && !OPENSSL_NO_SSL2 && WITH_SSLV2 */
#if defined(SSL_OP_NO_SSLv3) && !defined(OPENSSL_NO_SSL3_METHOD)
#define HAVE_SSLV3
#endif /* SSL_OP_NO_SSLv2 && !OPENSSL_NO_SSL3_METHOD */
#ifdef SSL_OP_NO_TLSv1
#define HAVE_TLSV10
#endif /* SSL_OP_NO_TLSv1 */
#ifdef SSL_OP_NO_TLSv1_1
#define HAVE_TLSV11
#endif /* SSL_OP_NO_TLSv1_1 */
#ifdef SSL_OP_NO_TLSv1_2
#define HAVE_TLSV12
#endif /* SSL_OP_NO_TLSv1_2 */

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

} x509_forge_thread;

int cert_store_session_init();

void sigproc(int __attribute__((__unused__))sig);

#endif

