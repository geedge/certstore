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
#include "logging.h"

#define	SG_DATA_SIZE    2048

#define DEFAULT_PRIVATEKEY_NAME  "private.key"
#define DEFAULT_CA_CERTIFICATE   "ca.cer"

static libevent_thread *threads;

#define sizeof_seconds(x)  (x * 24 * 60 * 60)

void connectCallback(const struct redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis connect error : %s\n", c->errstr);
        return;
    }
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Redis server connected...\n");
}

void disconnectCallback(const struct redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        printf("Redis disconnect error: %s\n", c->errstr);
        return;
    }
    printf("Redis server disconnected...\n");
}

static rt_mutex *mutex_buf = NULL;

static unsigned long pthreads_thread_id(void)
{
  return ((unsigned long)pthread_self());
}

static void pthreads_locking_callback(int mode, int n, const char __attribute__((__unused__))*file,
                                      int __attribute__((__unused__))line)
{
  if(mode & CRYPTO_LOCK)
    rt_mutex_lock(&(mutex_buf[n]));
  else
    rt_mutex_unlock(&(mutex_buf[n]));
}

int thread_setup(void)
{
    int i;

    mutex_buf = malloc(CRYPTO_num_locks() * sizeof(rt_mutex));
    if(!mutex_buf)
        return 0;

    for(i = 0;  i < CRYPTO_num_locks();  i++)
        rt_mutex_init(&(mutex_buf[i]), NULL);

    CRYPTO_set_id_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
    return 1;
}

int thread_cleanup(void)
{
    int i;

    if(!mutex_buf)
        return 0;

    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    for(i = 0;  i < CRYPTO_num_locks();  i++)
        rt_mutex_destroy(&(mutex_buf[i]));

    free(mutex_buf);
    mutex_buf = NULL;
    return 1;
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

int cert_redis_init(struct event_base *base, struct redisAsyncContext **cl_ctx)
{
    int xret = -1;
    struct config_bucket_t *redis = cert_default_config();

    *cl_ctx = redisAsyncConnect(redis->r_ip, redis->r_port);
	if((*cl_ctx)->err)	{
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

static void
setCallback(redisAsyncContext __attribute__((__unused__))*c, void *r,
                   void *privdata)
{
    redisReply *reply = (redisReply*)r;

    char *host = (char *)privdata;
    if(reply->type == REDIS_REPLY_ERROR){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Writing data(key = %s) to redis failed", host);
    }
    return;
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
    evhttp_send_reply(req, 200, "OK", evb);
    goto done;

err:
    evhttp_send_error(req, 404, "Document was not found");
done:
    evbuffer_free(evb);
    return 0;
}

#if 0
static void
release_resources(struct cert_trapper_t *certCtx, char *cert, char *pubkey, int type)
{
    struct request_t *req = certCtx->req;

    req->flag = -1;
    req->valid = 0;
    memset(req->host, 0, DATALEN);
    //req->evh_req = NULL;
}
#endif

int x509_mkcert(char *host, EVP_PKEY *key, X509 *root, char *ca_s, char *pubkey)
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

int create_x509(struct request_t *request, redisAsyncContext *c, char *sendbuf)
{
    int xret = -1;

    libevent_thread *thread = threads + request->thread_id;

    struct config_bucket_t *rte = cert_default_config();
    char cert[SG_DATA_SIZE] = {0}, pubkey[SG_DATA_SIZE] = {0};

    x509_mkcert(request->host, thread->key, thread->root, cert, pubkey);
    if (cert[0] == '\0' && pubkey[0] == '\0'){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to issue certificate");
        evhttp_send_error(request->evh_req, HTTP_BADREQUEST, 0);
        goto finish;
    }
    CA_SIGN_ADD(1);
    snprintf(sendbuf, SG_DATA_SIZE * 2, "%s%s", pubkey, cert);

    xret = redisAsyncCommand(c, setCallback, request->host, "SETEX %s %d %s",
                             request->host, sizeof_seconds(rte->days), sendbuf);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to set information to redis server");
        goto finish;
    }
     xret = 0;
finish:
    return xret;
}

void getCallback(redisAsyncContext *c, void *r, void *privdata)
{
    int xret = -1;
    char sendbuf[SG_DATA_SIZE * 2] = {0};

	redisReply *reply = (redisReply*)r;

    struct request_t *request = (struct request_t *)privdata;

    switch(reply->type){
        case REDIS_REPLY_STRING:
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Sends the certificate information to the requestor");
            CA_STORE_ADD(1);
            if (reply->str != NULL){
                snprintf(sendbuf, SG_DATA_SIZE * 2, "%s", reply->str);
                xret = 0;
            }else{
                evhttp_send_error(request->evh_req, HTTP_BADREQUEST, 0);
            }
            break;
        case REDIS_REPLY_NIL:
            /* Certificate information modification  and Strategy to judge**/
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Generating certificate information");
            xret = create_x509(request, c, sendbuf);
            break;
        default:
            break;
    }
    if (xret < 0)
        goto finish;

    evhttp_socket_send(request->evh_req, sendbuf);
finish:
    kfree(request);
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

#if 0
int cert_session_finish()
{
    struct cert_trapper_t *rte = cert_default_trapper();
    struct redis_t *redis = rte->redis;

    redisAsyncDisconnect(redis->cl_ctx);
    event_base_free(event->base);
    X509_free(rte->root);
    EVP_PKEY_free(rte->key);

    return 0;
}
#endif

static int
sample_decode_uri(const char *uri, char *host,
           int *flag, int *valid)
{
    const char *fg = NULL, *vl = NULL;
    char *decoded_uri = NULL;
    struct evkeyvalq params;

    decoded_uri = evhttp_decode_uri(uri);
    if (!decoded_uri){
        goto finish;
    }
    evhttp_parse_query(decoded_uri, &params);
    sprintf(host,  "%s", evhttp_find_header(&params, "host"));

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

void
pthread_work_proc(struct evhttp_request *evh_req, void *arg)
{
    int xret = -1;
    const char *cmdtype;
    struct request_t *request = NULL;
	struct evhttp_uri *decoded = NULL;

    libevent_thread *thread_info = (libevent_thread *)arg;

	const char *uri = evhttp_request_get_uri(evh_req);
     /* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "It's not a good URI. Sending BADREQUEST\n");
		goto error;
	}
	request = (struct request_t *) kmalloc (sizeof(struct request_t), MPF_CLR, -1);
    if (request != NULL){
        request->thread_id = thread_info->id;
        request->evh_req = evh_req;
    }

	switch (evhttp_request_get_command(evh_req)) {
        case EVHTTP_REQ_GET: cmdtype = "GET"; break;
        case EVHTTP_REQ_POST: cmdtype = "POST"; break;
        case EVHTTP_REQ_HEAD: cmdtype = "HEAD"; break;
        case EVHTTP_REQ_PUT: cmdtype = "PUT"; break;
        case EVHTTP_REQ_DELETE: cmdtype = "DELETE"; break;
        case EVHTTP_REQ_OPTIONS: cmdtype = "OPTIONS"; break;
        case EVHTTP_REQ_TRACE: cmdtype = "TRACE"; break;
        case EVHTTP_REQ_CONNECT: cmdtype = "CONNECT"; break;
        case EVHTTP_REQ_PATCH: cmdtype = "PATCH"; break;
        default: cmdtype = "unknown"; break;
	}

    WEB_REQUEST_ADD(1);
    sample_decode_uri(uri, request->host, &request->flag, &request->valid);
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "[Thread %d]Received a %s request for %s, host:%s, flag:%d, valid:%d\nHeaders:",
	                request->thread_id, cmdtype, uri, request->host,
                    request->flag, request->valid);

    if (request->host[0] != '\0' && request->evh_req != NULL){
        xret = redisAsyncCommand(thread_info->cl_ctx, getCallback, request, "GET %s", request->host);
        if (xret < 0){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to get information from redis server");
        }
    }else{
        kfree(request);
        evhttp_uri_free(decoded);
        goto error;
    }
    evhttp_uri_free(decoded);
    goto finish;

error:
    evhttp_send_error(evh_req, HTTP_BADREQUEST, 0);
finish:
    return;
}

static int
cert_trapper_task_int(struct event_base *base, libevent_thread *me)
{
    int xret = -1;

    /* Initialize the redis connection*/
    xret = cert_redis_init(base, &me->cl_ctx);
    if (xret < 0 || !me->cl_ctx){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the redis connection is failure\n");
        goto finish;
    }
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
    int xret = -1;
	struct evhttp *http = NULL;
	struct event_base *base = NULL;
	struct evhttp_bound_socket *bound = NULL;

    libevent_thread *thread_info = (libevent_thread *)arg;

    struct config_bucket_t *rte = cert_default_config();

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
    xret = cert_trapper_task_int(base, thread_info);
    if (xret < 0){
        goto error;
    }
    evhttp_set_cb(http, "/ca", pthread_work_proc, thread_info);

    bound = evhttp_accept_socket_with_handle(http, thread_info->accept_fd);
    if (bound != NULL) {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Bound(%p) to port %d - Awaiting connections ... ", bound, rte->e_port);
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

void * do_perform_monitor(void __attribute__((__unused__))*_thread_id)
{
#define EVAL_TM_STYLE_FULL "%Y-%m-%d %H:%M:%S"
    char tm[64] = {0};
    int64_t web_req;
    int64_t ca_store, ca_sign;

    do{
        web_req = WEB_REQUEST_ADD(0);
        ca_store = CA_STORE_ADD(0);
        ca_sign = CA_SIGN_ADD(0);

        rt_curr_tms2str(EVAL_TM_STYLE_FULL, tm, 63);
        printf("%s     Web Req=%ld, Ca Total=%ld\n", tm, web_req, ca_store + ca_sign);
        printf("\tCa store=%ld, sign=%ld\n",
               ca_store, ca_sign);

        sleep(5);
    }while(1);

    return NULL;
}

int libevent_socket_init()
{
    struct sockaddr_in sin;
    evutil_socket_t accept_fd = -1;
    int xret = -1;
    unsigned int tid = 0;
    libevent_thread *thread = NULL;

    struct config_bucket_t *rte = cert_default_config();
    unsigned int thread_nu = rte->thread_nu;

    /* Create a new evhttp object to handle requests. */
    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(rte->e_port);
    accept_fd = evhttp_listen_socket_byuser((struct sockaddr*)&sin, sizeof(struct sockaddr_in),
                                             LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1);
    if (accept_fd < 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Could not create a listen!\n");
        goto finish;
    }

    /*  one way to set the necessary OpenSSL locking callbacks if you want to do
        multi-threaded transfers with HTTPS/FTPS built to use OpenSSL **/
    thread_setup();

    threads = calloc(thread_nu, sizeof(libevent_thread));
    if (! threads) {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Can't allocate thread descriptors");
        goto finish;
    }

    /* Create threads after we've done all the libevent setup. */
    for (tid = 0; tid < thread_nu; tid++) {
        thread = threads + tid;

        thread->id = tid;
        thread->accept_fd = accept_fd;
        thread->routine = pthread_worker_libevent;

        if (pthread_create(&thread->pid, thread->attr, thread->routine, &threads[tid])){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}

		if (pthread_detach(thread->pid)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s", strerror(errno));
			goto finish;
		}
    }

    rt_pthread perform;
    long thread_id = 5;
    pthread_create(&perform, NULL, do_perform_monitor, (void *) thread_id);

    void * per_res;
    pthread_join(perform, &per_res);

    FOREVER{
        sleep(1);
    }

    thread_cleanup();
finish:
    return xret;
}

int cert_session_init()
{
    int xret = 0;

    libevent_socket_init();

    return xret;
}

