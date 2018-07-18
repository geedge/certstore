/*************************************************************************
	> File Name: cert_session.c
	> Author:
	> Mail:
	> Created Time: Fri 01 Jun 2018 02:00:56 AM PDT
 ************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

/* openssl**/
#include <opensslv.h>
#include <ssl.h>
#include <err.h>
#include <rand.h>
#include <x509.h>
#include <x509v3.h>
#include <crypto.h>
#include <engine.h>

#include "rt_string.h"
#include "rt_common.h"
#include "rt_stdlib.h"
#include "rt_file.h"
#include "rt_time.h"
#include "cert_init.h"
#include "async.h"
#include "read.h"
#include "bufferevent.h"
#include "listener.h"
#include "libevent.h"
#include "cert_session.h"
#include "event_compat.h"
#include "http.h"
#include "buffer.h"
#include "util-internal.h"
#include "moodycamel_field_stat2.h"
#include "logging.h"

#define	SG_DATA_SIZE    2048

#define DEFAULT_PRIVATEKEY_NAME  "private.key"
#define DEFAULT_CA_CERTIFICATE   "ca.cer"

static libevent_thread *threads;

struct fs_stats_t{
    int line_ids[4];
    screen_stat_handle_t handle;
};

static struct fs_stats_t SGstats = {
    .line_ids = {0},
    .handle = NULL,
};

#define sizeof_seconds(x)  (x * 24 * 60 * 60)

rt_mutex entries_mtx = PTHREAD_MUTEX_INITIALIZER;

#define RD_SYNC

void connectCallback(const struct redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis connect error : %s\n", c->errstr);
        return;
    }
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Redis server connected...\n");
}

void disconnectCallback(const struct redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis disconnect error: %s\n", c->errstr);
        return;
    }
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Redis server disconnected...\n");
}

int
ssl_rand(void *p, size_t sz)
{
	int rv;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rv = RAND_pseudo_bytes((unsigned char*)p, sz);
	if (rv == 1)
		return 0;
#endif /* OPENSSL_VERSION_NUMBER < 0x10100000L */
	rv = RAND_bytes((unsigned char*)p, sz);
	if (rv == 1)
		return 0;
	return -1;
}

int
ssl_x509_serial_copyrand(X509 *dstcrt, X509 *srccrt)
{
	ASN1_INTEGER *srcptr, *dstptr;
	BIGNUM *bnserial;
	unsigned int rand;
	int rv;

#ifndef PURIFY
	rv = ssl_rand(&rand, sizeof(rand));
#else /* PURIFY */
	rand = 0xF001;
	rv = 0;
#endif /* PURIFY */
	dstptr = X509_get_serialNumber(dstcrt);
	srcptr = X509_get_serialNumber(srccrt);
	if ((rv == -1) || !dstptr || !srcptr)
		return -1;
	bnserial = ASN1_INTEGER_to_BN(srcptr, NULL);
	if (!bnserial) {
		/* random 32-bit serial */
		ASN1_INTEGER_set(dstptr, rand);
	} else {
		/* original serial plus random 32-bit offset */
		BN_add_word(bnserial, rand);
		BN_to_ASN1_INTEGER(bnserial, dstptr);
		BN_free(bnserial);
	}
	return 0;
}

int
ssl_x509_v3ext_add(X509V3_CTX *ctx, X509 *crt, char *k, char *v)
{
	X509_EXTENSION *ext;

	if (!(ext = X509V3_EXT_conf(NULL, ctx, k, v))) {
		return -1;
	}
	if (X509_add_ext(crt, ext, -1) != 1) {
		X509_EXTENSION_free(ext);
		return -1;
	}
	X509_EXTENSION_free(ext);
	return 0;
}

int
ssl_x509_v3ext_copy_by_nid(X509 *crt, X509 *origcrt, int nid)
{
	X509_EXTENSION *ext;
	int pos;

	pos = X509_get_ext_by_NID(origcrt, nid, -1);
	if (pos == -1)
		return 0;
	ext = X509_get_ext(origcrt, pos);
	if (!ext)
		return -1;
	if (X509_add_ext(crt, ext, -1) != 1)
		return -1;
	return 1;
}

X509 *
x509_modify_by_cert(X509 *cacrt, EVP_PKEY *cakey, X509 *origcrt, EVP_PKEY *key,
                            int days, const char *extraname, const char *crlurl)
{
	X509_NAME *subject, *issuer;
	GENERAL_NAMES *names;
	GENERAL_NAME *gn;
	X509 *crt;
	int rv;
//subjectname,issuername
	subject = X509_get_subject_name(origcrt);
	issuer = X509_get_subject_name(cacrt);
	if (!subject || !issuer)
		return NULL;

	crt = X509_new();
	if (!crt)
		return NULL;
//version,subjectname,issuername,serialnum,time,pubkey
	if (!X509_set_version(crt, 0x02) ||
	    !X509_set_subject_name(crt, subject) ||
	    !X509_set_issuer_name(crt, issuer) ||
	    ssl_x509_serial_copyrand(crt, origcrt) == -1 ||
	    !X509_gmtime_adj(X509_get_notBefore(crt), 0) ||
	    !X509_time_adj_ex(X509_get_notAfter(crt), days, 0, NULL) ||
	    !X509_set_pubkey(crt, key))
		goto errout;

	/* add standard v3 extensions; cf. RFC 2459 */
//extensions
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, cacrt, crt, NULL, NULL, 0);

	if (ssl_x509_v3ext_add(&ctx, crt, "subjectKeyIdentifier",
	                                  "hash") == -1 ||
	    ssl_x509_v3ext_add(&ctx, crt, "authorityKeyIdentifier",
	                                  "keyid,issuer:always") == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt,
	                                NID_basic_constraints);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "basicConstraints",
		                                   "CA:FALSE");
	if (rv == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt,
	                                NID_key_usage);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "keyUsage",
		                                   "digitalSignature,"
		                                   "keyEncipherment");
	if (rv == -1)
		goto errout;

	rv = ssl_x509_v3ext_copy_by_nid(crt, origcrt,
	                                NID_ext_key_usage);
	if (rv == 0)
		rv = ssl_x509_v3ext_add(&ctx, crt, "extendedKeyUsage",
		                                   "serverAuth");
	if (rv == -1)
		goto errout;

    char *crlurlval;
	if (crlurl) {
        crlurlval = (char *)malloc(strlen(crlurl) + 1);
		if (sprintf(crlurlval, "URI:%s", crlurl) < 0)
			goto errout;
		if (ssl_x509_v3ext_add(&ctx, crt, "crlDistributionPoints",
		                       crlurlval) == -1) {
			free(crlurlval);
			goto errout;
		}
		free(crlurlval);
	}

    char *cfval;
	if (!extraname) {
		/* no extraname provided: copy original subjectAltName ext */
		if (ssl_x509_v3ext_copy_by_nid(crt, origcrt,
		                               NID_subject_alt_name) == -1)
			goto errout;
	} else {
		names = (GENERAL_NAMES *)X509_get_ext_d2i(origcrt, NID_subject_alt_name, 0, 0);
		if (!names) {
			/* no subjectAltName present: add new one */
            cfval = (char *)malloc(strlen(extraname) + 1);
			if (sprintf(cfval, "DNS:%s", extraname) < 0)
				goto errout;
			if (ssl_x509_v3ext_add(&ctx, crt, "subjectAltName",
			                       cfval) == -1) {
				free(cfval);
				goto errout;
			}
			free(cfval);
		} else {
			/* add extraname to original subjectAltName
			 * and add it to the new certificate */
			gn = GENERAL_NAME_new();
			if (!gn)
				goto errout2;
			gn->type = GEN_DNS;
			gn->d.dNSName = ASN1_IA5STRING_new();
			if (!gn->d.dNSName)
				goto errout3;
			ASN1_STRING_set(gn->d.dNSName,
			                (unsigned char *)extraname,
			                strlen(extraname));
			sk_GENERAL_NAME_push(names, gn);
			X509_EXTENSION *ext = X509V3_EXT_i2d(
			                      NID_subject_alt_name, 0, names);
			if (!X509_add_ext(crt, ext, -1)) {
				if (ext) {
					X509_EXTENSION_free(ext);
				}
				goto errout3;
			}
			X509_EXTENSION_free(ext);
			sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
		}
	}
#ifdef DEBUG_CERTIFICATE
	ssl_x509_v3ext_add(&ctx, crt, "nsComment", "Generated by " PKGLABEL);
#endif /* DEBUG_CERTIFICATE */

	const EVP_MD *md;
	switch (EVP_PKEY_type(EVP_PKEY_base_id(cakey))) {
#ifndef OPENSSL_NO_RSA
	case EVP_PKEY_RSA:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_md5WithRSAEncryption:
			md = EVP_md5();
			break;
		case NID_ripemd160WithRSA:
			md = EVP_ripemd160();
			break;
		case NID_sha1WithRSAEncryption:
			md = EVP_sha1();
			break;
		case NID_sha224WithRSAEncryption:
			md = EVP_sha224();
			break;
		case NID_sha256WithRSAEncryption:
			md = EVP_sha256();
			break;
		case NID_sha384WithRSAEncryption:
			md = EVP_sha384();
			break;
		case NID_sha512WithRSAEncryption:
			md = EVP_sha512();
			break;
#ifndef OPENSSL_NO_SHA0
		case NID_shaWithRSAEncryption:
			md = EVP_sha();
			break;
#endif /* !OPENSSL_NO_SHA0 */
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_RSA */
#ifndef OPENSSL_NO_DSA
	case EVP_PKEY_DSA:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_dsaWithSHA1:
		case NID_dsaWithSHA1_2:
			md = EVP_sha1();
			break;
		case NID_dsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_dsa_with_SHA256:
			md = EVP_sha256();
			break;
#ifndef OPENSSL_NO_SHA0
		case NID_dsaWithSHA:
			md = EVP_sha();
			break;
#endif /* !OPENSSL_NO_SHA0 */
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_DSA */
#ifndef OPENSSL_NO_ECDSA
	case EVP_PKEY_EC:
		switch (X509_get_signature_nid(origcrt)) {
		case NID_ecdsa_with_SHA1:
			md = EVP_sha1();
			break;
		case NID_ecdsa_with_SHA224:
			md = EVP_sha224();
			break;
		case NID_ecdsa_with_SHA256:
			md = EVP_sha256();
			break;
		case NID_ecdsa_with_SHA384:
			md = EVP_sha384();
			break;
		case NID_ecdsa_with_SHA512:
			md = EVP_sha512();
			break;
		default:
			md = EVP_sha256();
			break;
		}
		break;
#endif /* !OPENSSL_NO_ECDSA */
	default:
		goto errout;
	}
	if (!X509_sign(crt, cakey, md))
		goto errout;

	return crt;

errout3:
	GENERAL_NAME_free(gn);
errout2:
	sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
errout:
	X509_free(crt);
	return NULL;
}

void x509_get_msg_from_ca(X509 *x509, char *ca_s)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output\n");
        goto finish;
    }
    PEM_write_bio_X509(bp, x509);
    len = BIO_read(bp, ca_s, SG_DATA_SIZE * 2);
    if(len <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error reading signature file");
        goto err;
    }
    ca_s[len] ='\0';
err:
    BIO_free(bp);
finish:
	return;
}

void x509_get_pubkey_form_ca(X509 *crt, char *pubkey)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output\n");
        goto finish;
    }

    EVP_PKEY * pkey = X509_get_pubkey(crt);
    if (pkey == NULL) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error getting public key");
        goto free_err;
    }
    PEM_write_bio_PUBKEY(bp, pkey);
    len = BIO_read(bp, pubkey, SG_DATA_SIZE);
    if(len <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error reading signature file");
        goto free_key;
    }
    pubkey[len] = '\0';
free_key:
    EVP_PKEY_free(pkey);
free_err:
    BIO_free(bp);
finish:
	return;
}

static void callback(int __attribute__((__unused__))p, int __attribute__((__unused__))n,
                     void __attribute__((__unused__))*arg)
{
    return;
}

/*
 * Add extension using V3 code: we can set the config file as NULL because we
 * wont reference any other sections.
 */

int add_ext(X509 *cert, int nid, char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /*
     * Issuer and subject certs: both the target since it is self signed, no
     * request and no CRL
     */
    X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
}

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits,
           int serial, char *host, int days)
{
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name = NULL;

    if ((pkeyp == NULL) || (*pkeyp == NULL)) {
        if ((pk = EVP_PKEY_new()) == NULL) {
            abort();
            return (0);
        }
    } else
        pk = *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL)) {
        if ((x = X509_new()) == NULL)
            goto err;
    } else
        x = *x509p;

    rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
    if (!EVP_PKEY_assign_RSA(pk, rsa)) {
        abort();
        goto err;
    }
    rsa = NULL;

    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), (long)60 * 60 * 24 * days);
    X509_set_pubkey(x, pk);

    name = X509_get_subject_name(x);

    /*
     * This function creates and adds the entry, working out the correct
     * string type and performing checks on its length. Normally we'd check
     * the return value for errors...
     */
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN",
                               MBSTRING_ASC, (const unsigned char *)host, -1, -1, 0);

    /*
     * Its self signed so set the issuer name to be the same as the subject.
     */
    X509_set_issuer_name(x, name);

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
    add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

    add_ext(x, NID_subject_key_identifier, "hash");

    /* Some Netscape specific extensions */
    add_ext(x, NID_netscape_cert_type, "sslCA");

    add_ext(x, NID_netscape_comment, "example comment extension");

#ifdef CUSTOM_EXT
    /* Maybe even add our own extension based on existing */
    {
        int nid;
        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, "example comment alias");
    }
#endif

    if (!X509_sign(x, pk, EVP_sha1()))
        goto err;

    *x509p = x;
    *pkeyp = pk;
    return (1);
 err:
    return (0);
}

X509 *x509_create_cert(char *host, int days)
{
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;

    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    mkcert(&x509, &pkey, 1024, 0, host, days);

    EVP_PKEY_free(pkey);

    return x509;
}

#if 0
static int fs_internal_operate(int id, int id2, int column_id, int column_id2, long long diffTime)
{
    int ret = -1;
    screen_stat_handle_t handle = SGstats.handle;

    FS_internal_operate(handle, id, column_id, FS_OP_ADD, 1);

    if (id2 < 0)
        goto finish;

    FS_internal_operate(handle, id2, 0, FS_OP_ADD, 1);

    if (column_id2 < 0)
        goto finish;

	ret = FS_internal_operate(handle, id, column_id2, FS_OP_SET, diffTime);
finish:
    return ret;
}
#endif

int redis_rsync_init(struct event_base *base, struct redisAsyncContext **cl_ctx)
{
    int xret = -1;
    struct config_bucket_t *redis = cert_default_config();

    *cl_ctx = redisAsyncConnect(redis->r_ip, redis->r_port);
	if((*cl_ctx)->err )	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis Connect error : %s", (*cl_ctx)->errstr);
		goto finish;
	}
	redisLibeventAttach((*cl_ctx), base);
	redisAsyncSetConnectCallback((*cl_ctx), connectCallback);
	redisAsyncSetDisconnectCallback((*cl_ctx), disconnectCallback);

    xret = 0;

finish:
	return xret;
}

/* Callback used for the /dump URI, and for every non-GET request:
 * dumps all information to stdout and gives back a trivial 200 ok */
static int
evhttp_socket_send(struct evhttp_request *req, char *sendbuf)
{
    struct evbuffer *evb = NULL;

    /* This holds the content we're sending. */
	evb = evbuffer_new();

    if (sendbuf[0] == '\0' && req == NULL){
        goto err;
    }
    evhttp_add_header(evhttp_request_get_output_headers(req),
		              "Content-Type", "test");
    evbuffer_add_printf(evb, "%s", sendbuf);
    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    goto done;

err:
    evhttp_send_error(req, HTTP_NOTFOUND, "Document was not found");
done:
    evbuffer_free(evb);
    return 0;
}

static void
redis_reget_callback(redisAsyncContext __attribute__((__unused__))*cl_ctx,
                     void *r, void *privdata)
{
    redisReply *reply              = (redisReply*)r;

    struct request_t *request      = (struct request_t *)privdata;

    struct evhttp_request *evh_req = request->evh_req;

    evhttp_socket_send(evh_req, reply->str);

    kfree(request->sendbuf);
    kfree(request);
    return;
}

static void
redis_set_callback(redisAsyncContext *cl_ctx, void *r,
                   void *privdata)
{
    struct request_t *request      = (struct request_t *)privdata;
    struct evhttp_request *evh_req = request->evh_req;

    redisReply *reply   = (redisReply*)r;

    if(reply->type == REDIS_REPLY_ERROR){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Set redis data(key = %s) returns failed", request->host);
        goto finish;
    }
    /*
        Synchronous reader data is +OK
        Asynchronous redis data is $-1\r\n+OK
    */

    libevent_thread *thread  = threads + request->t_id;
    redisReader *reader      = cl_ctx->c.reader;

    switch (reader->buf[5]) {
        case '+' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(key = %s) to redis successfully", request->host);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[2], FS_OP_ADD, 1);

            evhttp_socket_send(evh_req, request->sendbuf);
            goto free;
        case '\0':
        case '$' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(key = %s) to redis failed", request->host);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

            redisAsyncCommand(cl_ctx, redis_reget_callback, request, "GET %s", request->host);
            goto finish;
        default  :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Read redis data(key = %s) return code failed", request->host);
            evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
            goto free;
    }

free:
    kfree(request->sendbuf);
    kfree(request);
finish:
    return;
}

int x509_online_append(char *host, EVP_PKEY *key, X509 *root, char *ca_s, char *pubkey)
{
    int xret = -1;
    struct config_bucket_t *rte = cert_default_config();

    X509* ca = x509_create_cert(host, rte->days);
    if (!ca){
        goto finish;
    }
    X509* x509 = x509_modify_by_cert(root, key, ca, X509_get_pubkey(root),
                                     rte->days, NULL, NULL);
    if (!x509){
        goto err;
    }
    x509_get_pubkey_form_ca(x509, pubkey);
    x509_get_msg_from_ca(x509, ca_s);

    X509_free(x509);
err:
    X509_free(ca);
finish:
    return xret;
}

static char readBytes(char *str)
{
    char c;

    if (str && STRCMP(str, "OK") == 0)
        c = '+';
    if (!str)
        c= '$';

    return c;
}

static int
rediSyncCommand(redisAsyncContext *cl_ctx, struct request_t *request, char *sendbuf)
{
    int xret = -1;
    redisReply *reply;

    libevent_thread *thread        = threads + request->t_id;
    struct evhttp_request *evh_req = request->evh_req;

    reply = (redisReply *)redisCommand(thread->sync, "set %s %s ex %d nx", request->host, sendbuf,
                                             sizeof_seconds(cert_default_config()->days));
    if (NULL == reply)
        goto free;

    switch (readBytes(reply->str)) {
        case '+' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(key = %s) to redis successfully", request->host);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[2], FS_OP_ADD, 1);

            evhttp_socket_send(evh_req, request->sendbuf);
            goto free;
        case '$' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(key = %s) to redis failed", request->host);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

            redisAsyncCommand(cl_ctx, redis_reget_callback, request, "GET %s", request->host);
            freeReplyObject(reply);
            goto finish;
        default  :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Read redis data(key = %s) return code failed", request->host);
            evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
            goto free;
    }
    xret = 0;

free:
    freeReplyObject(reply);
    kfree(request->sendbuf);
    kfree(request);

finish:
    return xret;
}

static int
redis_encode_sendbuf(struct request_t *request, redisAsyncContext *c)
{
    int xret = -1;
    uint64_t startTime = 0, endTime = 0;
    libevent_thread *thread        = threads + request->t_id;
    char cert[SG_DATA_SIZE]        = {0}, pubkey[SG_DATA_SIZE] = {0};

    char *sendbuf = (char *)kmalloc(SG_DATA_SIZE * 2, MPF_CLR, -1);

    startTime        = rt_time_ns();

    x509_online_append(request->host, thread->key, thread->root, cert, pubkey);
    if (cert[0] == '\0' && pubkey[0] == '\0'){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to issue certificate");
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }

    endTime           = rt_time_ns();
    thread->diffTime += (endTime - startTime);

    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "%lu - %lu = %lu\n", startTime, endTime, endTime - startTime);

    FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[3], FS_OP_SET, thread->diffTime);

    FS_internal_operate(SGstats.handle, thread->field_ids, 0, FS_OP_ADD, 1);

    snprintf(sendbuf, SG_DATA_SIZE * 2 - 1, "%s%s", pubkey, cert);

    request->sendbuf = sendbuf;
#ifdef RD_SYNC
    xret = rediSyncCommand(c, request, sendbuf);
#else
    xret = redisAsyncCommand(c, redis_set_callback, request, "set %s %s ex %d nx",
                             request->host, sendbuf, sizeof_seconds(cert_default_config()->days));
#endif
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to set information to redis server");
        goto finish;
    }
    xret = 0;

finish:
    return xret;
}

static int
redis_decode_sendbuf(struct request_t *request, redisReply *reply)
{
    int xret                       = -1;

    char sendbuf[SG_DATA_SIZE * 2] = {0};
    libevent_thread *thread        = threads + request->t_id;

    if (!reply && !reply->str){
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }

    FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

    FS_internal_operate(SGstats.handle, thread->field_ids, 0, FS_OP_ADD, 1);

    snprintf(sendbuf, SG_DATA_SIZE * 2, "%s", reply->str);

    evhttp_socket_send(request->evh_req, sendbuf);

finish:
    kfree(request);
    return xret;
}

void redis_get_callback(redisAsyncContext *c, void *r, void *privdata)
{
    int  __attribute__((__unused__))xret = -1;

	redisReply *reply              = (redisReply*)r;
    struct request_t *request      = (struct request_t *)privdata;

    switch(reply->type){
        case REDIS_REPLY_STRING:
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Sends the certificate information to the requestor");

            xret = redis_decode_sendbuf(request, reply);
            break;

        case REDIS_REPLY_NIL:
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Generating certificate information");

            xret = redis_encode_sendbuf(request, c);
            break;
        default:
            break;
    }

    return;
}

int x509_privatekey_init(EVP_PKEY **key, X509 **root)
{
    int xret = -1, len = 0;
	FILE *fp; RSA *rsa = NULL;
    char key_path[128] = {0}, cert_path[128] = {0};
    struct config_bucket_t *rte = cert_default_config();

    snprintf(key_path, sizeof(key_path), "%s/%s", rte->ca_path, DEFAULT_PRIVATEKEY_NAME);
    snprintf(cert_path, sizeof(cert_path), "%s/%s", rte->ca_path, DEFAULT_CA_CERTIFICATE);

	*key = EVP_PKEY_new();
    if (NULL == *key){
        goto finish;
    }

    rsa = RSA_new();
    if (NULL == rsa){
        goto pkey_free;
    }

	unsigned char buf[SG_DATA_SIZE],*p;
    fp = fopen(key_path, "r");
    if (NULL == fp){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", key_path);
        RSA_free(rsa);
        goto pkey_free;
    }
    if ( !PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) || !EVP_PKEY_assign_RSA(*key,rsa))
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Private key read failed");
        goto pkey_free;
	}
    fclose(fp);

	fp = fopen(cert_path, "rb");
	if (NULL == fp){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", cert_path);
        goto pkey_free;
    }
    len = fread(buf, 1, SG_DATA_SIZE, fp);
    fclose(fp);

    p = buf;
    *root = X509_new();
    if ( d2i_X509(root, (const unsigned char**)&p, len) == NULL )
    {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Application for x509 failed");
		goto pkey_free;
	}
    xret = 0;
    goto finish;

pkey_free:
    EVP_PKEY_free(*key);
finish:
    return xret;
}

static int
rt_decode_uri(const char *uri, char *host,
           int *flag, int *valid)
{
    const char *fg    = NULL, *vl = NULL, *ht = NULL;
    char *decoded_uri = NULL;
    struct evkeyvalq params;

    decoded_uri = evhttp_decode_uri(uri);
    if (!decoded_uri){
        goto finish;
    }

    evhttp_parse_query(decoded_uri, &params);

    ht = evhttp_find_header(&params, "host");
    if (ht[0] != '\0')
        memcpy(host, ht, strlen(ht));

    fg = evhttp_find_header(&params, "flag");
    if (fg)
        *flag = atoi(fg);

    vl = evhttp_find_header(&params, "valid");
    if (vl)
        *valid = atoi(vl);

    evhttp_clear_headers(&params);
    free(decoded_uri);

finish:
    return 0;
}

static void
evhttp_socket_close_cb(struct evhttp_connection *evcon,
                       void __attribute__((__unused__))*arg)
{
    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Evhttp connection is broken");
    if (NULL == evcon){
        goto finish;
    }
finish:
    return;
}

void
pthread_work_proc(struct evhttp_request *evh_req, void *arg)
{
    int xret                     = -1;
    const char *cmdtype          = NULL;
    struct request_t *request    = NULL;
	struct evhttp_uri *decoded   = NULL;
    libevent_thread *t = (libevent_thread *)arg;

   /* we want to know if this connection closes on us */
	evhttp_connection_set_closecb(evhttp_request_get_connection(evh_req), evhttp_socket_close_cb, NULL);

	const char *uri = evhttp_request_get_uri(evh_req);
     /* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "It's not a good URI. Sending BADREQUEST\n");
		goto error;
	}

	request = (struct request_t *) kmalloc (sizeof(struct request_t), MPF_CLR, -1);
    if (request != NULL){
        request->t_id = t->id;
        request->evh_req   = evh_req;
    }

	switch (evhttp_request_get_command(evh_req)) {
        case EVHTTP_REQ_GET: cmdtype = "GET";     break;
        default:             cmdtype = "unknown"; break;
	}

    FS_internal_operate(SGstats.handle, t->column_ids, SGstats.line_ids[0], FS_OP_ADD, 1);

    rt_decode_uri(uri, request->host, &request->flag, &request->valid);
    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[Thread %d]Received a %s request for %s, host:%s, flag:%d, valid:%d\nHeaders:",
	                 request->t_id,  cmdtype, uri, request->host,
                     request->flag, request->valid);

    if (request->host[0] == '\0' || !request->evh_req){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to resolve the request url");
        kfree(request);
        evhttp_uri_free(decoded);
        goto error;
    }

    xret = redisAsyncCommand(t->cl_ctx, redis_get_callback, request, "GET %s", request->host);
    if (xret < 0)
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to get information from redis server");

    evhttp_uri_free(decoded);
    goto finish;

error:
    evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
    return;
}

int redis_sync_int(struct redisContext **c)
{
    struct config_bucket_t *redis = cert_default_config();

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    *c = redisConnectWithTimeout(redis->r_ip, redis->r_port, timeout);

    return 0;
}

static int
task_int(struct event_base *base, libevent_thread *me)
{
    int xret = -1;

    /* Initialize the redis connection*/
    xret = redis_rsync_init(base, &me->cl_ctx);
    if (xret < 0 || !me->cl_ctx){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the redis connection is failure\n");
        goto finish;
    }

    xret = redis_sync_int(&me->sync);

    /* Initialize the X509 CA*/
    xret = x509_privatekey_init(&me->key, &me->root);
    if (xret < 0 || !me->key || !me->root){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to initialize the x509 certificate");
        goto finish;
    }
finish:
    return xret;
}

static void *pthread_worker_libevent(void *arg)
{
    int xret                          = -1;
	struct evhttp *http               = NULL;
	struct event_base *base           = NULL;
	struct evhttp_bound_socket *bound = NULL;

    libevent_thread *t                = (libevent_thread *)arg;

    base = event_base_new();
    if (! base) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Can't allocate event base\n");
        goto finish;
    }

    http = evhttp_new(base);
	if (!http) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "couldn't create evhttp. Exiting.\n");
		goto error;
	}

    /* Context initialization */
    xret = task_int(base, t);
    if (xret < 0){
        goto error;
    }
    evhttp_set_cb(http, "/ca", pthread_work_proc, t);

    bound = evhttp_accept_socket_with_handle(http, t->accept_fd);
    if (bound != NULL) {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Bound(%p) to port %d - Awaiting connections ... ", bound,
                        cert_default_config()->e_port);
	}

	event_base_dispatch(base);
error:
    event_base_free(base);
finish:
    return NULL;
}

static evutil_socket_t
evhttp_listen_socket_byuser(const struct sockaddr *sa, int socklen,
                            unsigned flags, int backlog)
{
	evutil_socket_t fd;
	int on = 1;
	int family = sa ? sa->sa_family : AF_UNSPEC;
	int socktype = SOCK_STREAM | EVUTIL_SOCK_NONBLOCK;

	if (flags & LEV_OPT_CLOSE_ON_EXEC)
		socktype |= EVUTIL_SOCK_CLOEXEC;

	fd = evutil_socket_(family, socktype, 0);
	if (fd == -1)
		return fd;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&on, sizeof(on))<0)
		goto err;

	if (flags & LEV_OPT_REUSEABLE) {
		if (evutil_make_listen_socket_reuseable(fd) < 0)
			goto err;
	}

	if (flags & LEV_OPT_REUSEABLE_PORT) {
		if (evutil_make_listen_socket_reuseable_port(fd) < 0){
			goto err;
        }
	}

	if (sa) {
		if (bind(fd, sa, socklen)<0)
			goto err;
	}

    if (listen(fd, backlog) == -1) {
        goto err;
    }
	return fd;
err:
	evutil_closesocket(fd);
	return fd;
}

static int
fs_screen_preview(libevent_thread *thread)
{
	char buff[128] = {0};

    snprintf(buff, sizeof(buff),"Thread_%02d", thread->id);
    thread->field_ids = FS_internal_register(SGstats.handle, FS_STYLE_FIELD, FS_CALC_CURRENT, buff);

    snprintf(buff, sizeof(buff),"Thread_%d", thread->id);
    thread->column_ids = FS_internal_register(SGstats.handle, FS_STYLE_LINE, FS_CALC_CURRENT, buff);

    return 0;
}

static int
libevent_socket_init()
{
    struct sockaddr_in sin;
    evutil_socket_t accept_fd = -1;
    int xret                  = -1;
    unsigned int tid          = 0;
    libevent_thread *thread   = NULL;

    unsigned int thread_nu    = cert_default_config()->thread_nu;

    /* Create a new evhttp object to handle requests. */
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port   = htons(cert_default_config()->e_port);
    accept_fd      = evhttp_listen_socket_byuser((struct sockaddr*)&sin, sizeof(struct sockaddr_in),
                                                 LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1);
    if (accept_fd < 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Could not create a listen!\n");
        goto finish;
    }

    threads = calloc(thread_nu, sizeof(libevent_thread));
    if (! threads) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Can't allocate thread descriptors");
        goto finish;
    }
    memset(threads, 0, thread_nu * sizeof(libevent_thread));

    /* Create threads after we've done all the libevent setup. */
    for (tid = 0; tid < thread_nu; tid++) {
        thread            = threads + tid;

        thread->id        = tid;
        thread->accept_fd = accept_fd;
        thread->routine   = pthread_worker_libevent;

        fs_screen_preview(thread);

        if (pthread_create(&thread->pid, thread->attr, thread->routine, &threads[tid])){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}

		if (pthread_detach(thread->pid)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}
    }

    FOREVER{
        sleep(1);
    }
finish:
    return xret;
}

static void
rt_get_pname_by_pid(pid_t pid, char *task_name)
{
#define BUF_SIZE 1024
    char proc_pid_path[BUF_SIZE];
    char buf[BUF_SIZE];
    sprintf(proc_pid_path, "/proc/%d/status", pid);
    FILE* fp = fopen(proc_pid_path, "r");
    if(NULL != fp){
        if( fgets(buf, BUF_SIZE-1, fp)== NULL ){
            fclose(fp);
        }
        fclose(fp);
        sscanf(buf, "%*s %s", task_name);
    }
}

void sigproc(int __attribute__((__unused__))sig)
{
    unsigned int tid            = 0;
    libevent_thread *thread     = NULL;

    struct config_bucket_t *rte = cert_default_config();

    for (tid = 0; tid <  rte->thread_nu; tid++) {
        thread = threads + tid;

        X509_free(thread->root);
        EVP_PKEY_free(thread->key);
        if (thread->cl_ctx)
            redisAsyncDisconnect(thread->cl_ctx);
        if (thread->sync)
            redisFree(thread->sync);
    }
    kfree(threads);

    exit(1);
}

static int cert_screen_init()
{
	int value=0;
	char stat_path[63] = {0};
    char pname[32]= {0}, buff[128] = {0};

	SGstats.handle = FS_internal_create_handle();

    rt_get_pname_by_pid(getpid(), &pname[0]);
	FS_internal_set_para(SGstats.handle, APP_NAME, pname, strlen(pname)+1);
	value=0;
	FS_internal_set_para(SGstats.handle, FLUSH_BY_DATE, &value, sizeof(value));

    snprintf(stat_path, 63, "%s/fs2_%s.status", logging_sc_lid.run_log_path, pname);
	FS_internal_set_para(SGstats.handle, OUTPUT_DEVICE, stat_path, strlen(stat_path)+1);
	value=1;
	FS_internal_set_para(SGstats.handle, PRINT_MODE, &value, sizeof(value));
	value=1;
	FS_internal_set_para(SGstats.handle, CREATE_THREAD, &value, sizeof(value));
	value=3;
	FS_internal_set_para(SGstats.handle, STAT_CYCLE, &value, sizeof(value));

    snprintf(buff,sizeof(buff),"%s", "Req");
    SGstats.line_ids[0] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"%s", "DB");
    SGstats.line_ids[1] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"%s", "Local");
    SGstats.line_ids[2] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    snprintf(buff,sizeof(buff),"%s", "take-time");
    SGstats.line_ids[3] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

    value=SGstats.line_ids[3];
	FS_internal_set_para(SGstats.handle, ID_INVISBLE, &value, sizeof(value));
    snprintf(buff,sizeof(buff),"Cert/Nsec");
    FS_internal_register_ratio(SGstats.handle, SGstats.line_ids[3],
                               SGstats.line_ids[2], 1,
                               FS_STYLE_COLUMN, FS_CALC_CURRENT,
                               buff);
	FS_internal_start(SGstats.handle);

    return 0;
}

int cert_session_init()
{
    int xret = 0;

    cert_screen_init();

    libevent_socket_init();

    return xret;
}

