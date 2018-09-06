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
#include "json.h"

#include "cert_conf.h"
#include "async.h"
#include "read.h"
#include "bufferevent.h"
#include "listener.h"
#include "libevent.h"
#include "cert_session.h"
#include "event_compat.h"
#include "http.h"
#include "buffer.h"
#include "MESA_htable.h"
#include "util-internal.h"
#include "moodycamel_maat_rule.h"
#include "moodycamel_field_stat2.h"
#include "logging.h"

#define	WAIT_FOR_EFFECTIVE_US	1000*1000

#define	SG_DATA_SIZE    4096

#define DEFAULT_PRIVATEKEY_NAME  "mesalab-ca-cert.key"
#define DEFAULT_CA_CERTIFICATE   "mesalab-ca-cert.cer"

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

static int
MESA_internal_htable_set_opt(MESA_htable_handle table, enum MESA_htable_opt opt_type, unsigned value)
{
	int ret = MESA_htable_set_opt(table, opt_type, &value, (int)(sizeof(value)));
	return ret;
}

static int
key_ring_list_create(struct key_ring_list *keyring)
{
	int ret = 0;

    keyring->htable = MESA_htable_born();
	assert(keyring->htable != NULL);
    keyring->sum_cnt = 0;

	MESA_internal_htable_set_opt(keyring->htable, MHO_SCREEN_PRINT_CTRL, 0);
	MESA_internal_htable_set_opt(keyring->htable, MHO_THREAD_SAFE, 1);

    MESA_internal_htable_set_opt(keyring->htable, MHO_MUTEX_NUM, 16);
	MESA_internal_htable_set_opt(keyring->htable, MHO_HASH_SLOT_SIZE, 1024);
	MESA_internal_htable_set_opt(keyring->htable, MHO_HASH_MAX_ELEMENT_NUM, 2048);
	MESA_internal_htable_set_opt(keyring->htable, MHO_EXPIRE_TIME, 0);

	MESA_internal_htable_set_opt(keyring->htable, MHO_ELIMIMINATE_TYPE,
		                         HASH_ELIMINATE_ALGO_LRU);
	ret = MESA_htable_mature(keyring->htable);
    if(ret != 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "MESA_htable_mature error!\n");
        goto finish;
    }

finish:
    return ret;
}

void x509_get_private_key(EVP_PKEY *pkey, char *pubkey)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output\n");
        goto finish;
    }

    PEM_write_bio_PrivateKey(bp, pkey, NULL, NULL, 0, NULL, NULL);
    len = BIO_read(bp, pubkey, SG_DATA_SIZE);
    if(len <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error reading signature file");
        goto free_err;
    }
    pubkey[len] = '\0';

free_err:
    BIO_free(bp);
finish:
	return;
}

static
int create_client_key(EVP_PKEY** pkey, char *pubkey, int bits)
{
    RSA *rsa = NULL;
    EVP_PKEY *pk = NULL;

    if((pk = EVP_PKEY_new()) == NULL){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "create_client_key, gen new key failed!");
        goto err;
    }

    rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if(!EVP_PKEY_assign_RSA(pk, rsa)){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "create_client_key, assign key failed!");
        EVP_PKEY_free(pk);
        goto err;
    }
    x509_get_private_key(pk, pubkey);
    rsa = NULL;

    *pkey = pk;
    return 1;

err:
    return 0;
}

static void key_ring_free(void *data)
{
    struct pxy_obj_keyring *pxy_obj = NULL;
    pxy_obj = (struct pxy_obj_keyring *)data;

    X509_free(pxy_obj->root);
    EVP_PKEY_free(pxy_obj->key);
}

void key_ring_list_destroy(struct key_ring_list *keyring)
{
    keyring->sum_cnt = 0;
	MESA_htable_destroy(keyring->htable, key_ring_free);
	keyring->htable  = NULL;
	return;
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
	long rand;
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

int x509_get_cn_name(X509 *origcrt, char *cn_name)
{
    int len = 0;
    X509_NAME *subject = NULL;

	subject = X509_get_subject_name(origcrt);
    if (!subject){
        goto finish;
    }
    len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn_name, 256);
    if (len > 0){
        printf("cn_name = %s\n", cn_name);
    }
finish:
    return 0;
}

X509 *
x509_modify_by_cert_bak(X509 *cacrt, EVP_PKEY *cakey, X509 *origcrt, char *pkey,
                        int days, const char *extraname, const char *crlurl)
{
	int rv;
	X509 *crt = NULL;
    EVP_PKEY* key = NULL;
	GENERAL_NAME *gn = NULL;
	GENERAL_NAMES *names = NULL;
	X509_NAME *subject = NULL, *issuer = NULL;

    if(!create_client_key(&key, pkey, 2048)){
        goto err;
    }
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
err:
	return NULL;
}

void x509_get_msg_from_ca(X509 *x509, char *root)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output\n");
        goto finish;
    }
    PEM_write_bio_X509(bp, x509);
    len = BIO_read(bp, root, SG_DATA_SIZE * 2);
    if(len <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error reading signature file");
        goto err;
    }
    root[len] ='\0';
err:
    BIO_free(bp);
finish:
	return;
}

X509 *
x509_get_ca_from_msg(const char *cert, int len)
{
    BIO *bp;
    X509* x509 = NULL;
	char in[SG_DATA_SIZE] = {0};

	strncpy(in, cert, len);

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output\n");
        goto finish;
    }
	BIO_printf(bp, "%s", in);
	x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
	if(NULL == x509) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to read pem file\n");
        goto err;
    }
err:
	BIO_free(bp);
finish:
	return x509;
}

/*
 * Add extension using V3 code: we can set the config file as NULL because we
 * wont reference any other sections.
 */

int add_ext(X509 *cacrt, X509 *cert, int nid, char *value)
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
    X509V3_set_ctx(&ctx, cacrt, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 1;
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

static
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

    kfree(request->odata);
    kfree(request);
    return;
}

int add_cert_ctx(X509_NAME* name, char* ctx[], int num)
{
    int i = 0;
    int max = 0;

    int item[] = {NID_commonName, NID_countryName,
        NID_stateOrProvinceName, NID_localityName,
        NID_organizationName, NID_organizationalUnitName,
        NID_pkcs9_emailAddress};

    max = sizeof(item)/sizeof(item[0]);
    max = max > num ? num : max;

    for(i = 0; i< max; ++i){
        if(!X509_NAME_add_entry_by_NID(name, item[i], MBSTRING_UTF8, (unsigned char *)ctx[i], -1, -1, 0)){
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "add_cert_ctx, add entry:%d to %s failed!", item[i], ctx[i]);
            return 0;
        }
    }

    return 1;
}

int rand_serial(BIGNUM *b, ASN1_INTEGER *ai)
{
#define SERIAL_RAND_BITS  124
    BIGNUM *btmp;
    int ret = 0;
    if (b)
        btmp = b;
    else
        btmp = BN_new();
    if (!btmp)
        return 0;
    if (!BN_pseudo_rand(btmp, SERIAL_RAND_BITS, 0, 0))
        goto error;
    if (ai && !BN_to_ASN1_INTEGER(btmp, ai))
        goto error;
    ret = 1;

 error:
    if (!b)
        BN_free(btmp);
    return ret;
}

X509 *x509_modify_by_cert(X509 *cacrt, EVP_PKEY *cakey, const char* host,
                          char *pubkey, const int days)
{
    X509* x = NULL;
    EVP_PKEY* pk = NULL;

    char* ctx[] = {(char*)host, "CN", "mystate",
                             "mycity", "myorganization", "mygroup",
                             "sample@sample.com"};

    if(!create_client_key(&pk, pubkey, 1024)){
        goto err;
    }

    if((x = X509_new()) == NULL){
        goto err;
    }

    if (!X509_set_version(x, 0x02)){
        goto err;
    }

    if (!X509_set_version(x, 0x02) ||
        !X509_set_issuer_name(x, X509_get_subject_name(cacrt)) ||
        !rand_serial(NULL, X509_get_serialNumber(x)) ||
        !X509_gmtime_adj(X509_get_notBefore(x), 0L) ||
        !X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL) ||
        !X509_set_pubkey(x, pk) ||
        !add_cert_ctx(X509_get_subject_name(x), ctx, 7))
        goto err;
#if 1

    /* Add various extensions: standard extensions */
    add_ext(cacrt, x, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(cacrt, x, NID_subject_key_identifier, "hash");
    add_ext(cacrt, x, NID_key_usage, "Digital Signature, Key Encipherment, Data Encipherment");

    /**/

    add_ext(cacrt, x, NID_authority_key_identifier, "keyid:always");

    add_ext(cacrt, x, NID_ext_key_usage, "serverAuth,clientAuth");
    /*NID_certificate_policies*/
/*
    char dns[128] = {0}, domain[16] = {0};
    sscanf(host, "%*[^.].%[^.]", domain);
    snprintf(dns, 127, "DNS:%s.com, DNS:*.%s.com, DNS:www.%s.cn", domain, domain, domain);
    add_ext(cacrt, x, NID_subject_alt_name, dns);
*/
#endif
    if(!X509_sign(x, cakey, EVP_sha256())){
        goto err;
    }
    return x;

err:
    if(x)
        X509_free(x);
    if(pk)
        EVP_PKEY_free(pk);
    return NULL;
}

static uint64_t
x509_online_append(X509 *origin, int id, char *root, char *sign, char *pkey)
{
	void *res = NULL;
    uint64_t expire_after = 0;

    struct key_ring_list *keyring = &cert_default_config()->keyring;

    res = MESA_htable_search(keyring->htable, (const uchar *)&id, sizeof(int));
    if (!res){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "The table where keyringid = %d was not found", 1);
        goto finish;
    }

    struct pxy_obj_keyring *pxy_obj = (struct pxy_obj_keyring *)res;
    if (pxy_obj->is_valid != 1){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Table information is invalid");
        goto finish;
    }
    if (STRCMP(pxy_obj->type, "root") == 0 ||
        STRCMP(pxy_obj->type, "intermediate") == 0){
        //X509* x509 = x509_modify_by_cert(pxy_obj->root, pxy_obj->key, host, pkey, pxy_obj->expire_after);
        X509* x509 = x509_modify_by_cert_bak(pxy_obj->root, pxy_obj->key, origin, pkey,
                                             pxy_obj->expire_after, NULL, NULL);

        if (!x509){
            goto finish;
        }
        expire_after = pxy_obj->expire_after;
        x509_get_msg_from_ca(x509, sign);
        x509_get_msg_from_ca(pxy_obj->root, root);

        X509_free(x509);
    }
    if (STRCMP(pxy_obj->type, "end-entity")){
    }

finish:
    return expire_after;
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
rediSyncCommand(redisAsyncContext *cl_ctx, struct request_t *request,
                char *odata, uint64_t expire_after)
{
    int xret = -1;
    redisReply *reply;

    libevent_thread *thread        = threads + request->t_id;
    struct evhttp_request *evh_req = request->evh_req;

    reply = (redisReply *)redisCommand(thread->sync, "set %s %s ex %d nx", request->host, odata,
                                             sizeof_seconds(expire_after));
    if (NULL == reply)
        goto free;

    switch (readBytes(reply->str)) {
        case '+' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(key = %s) to redis successfully", request->host);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[2], FS_OP_ADD, 1);

            evhttp_socket_send(evh_req, request->odata);
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
    kfree(request->odata);
    kfree(request);

finish:
    return xret;
}

static inline json_object *
web_json_record_array_add_string(char **chain)
{
    int i;
    json_object *sample_array;

    sample_array = json_object_new_array();
    if (sample_array == NULL)
        goto finish;

    for(i = 0; chain[i] != '\0'; i++){
        json_object_array_add(sample_array, json_object_new_string(chain[i]));
    }
finish:
    return sample_array;
}

static inline int
json_data_rebuild(const char *data,
                 size_t size,
                 char **odata,
                 size_t *osize)
{
    size_t real_size = size + 1; /** 2, '\n' + '\0' */

    if (!data || !size)
        return -1;

    *odata = malloc (real_size);
    if (!*odata)
        return -1;
    memset (*odata, 0, real_size);
    snprintf(*odata, real_size, "%s", data);

    *osize = real_size;

    return 0;
}

static int
web_json_table_add(char *privatekey, char *sign,
                   char **chain, char **data)
{
    size_t osize = 0;
    const char *jstr = NULL;
    struct json_object *outline = json_object_new_object();

    json_object_object_add(outline, "CERTIFICATE_CHAIN", web_json_record_array_add_string(chain));
	json_object_object_add(outline, "PRIVATE_KEY", json_object_new_string(privatekey));
    json_object_object_add(outline, "CERTIFICATE", json_object_new_string(sign));

    jstr = json_object_to_json_string (outline);

    json_data_rebuild(jstr, strlen(jstr), data, &osize);

    json_object_put(outline);

    return 0;
}

static int
redis_clnt_pdu_send(struct request_t *request, redisAsyncContext *c)
{
    int xret = -1;
    uint64_t expire_after;
    uint64_t startTime = 0, endTime = 0;
    libevent_thread *thread         = threads + request->t_id;
    char sign[SG_DATA_SIZE]         = {0}, pkey[SG_DATA_SIZE] = {0};
    char root[SG_DATA_SIZE]         = {0};

    startTime        = rt_time_ns();
    expire_after = x509_online_append(request->origin, request->kering_id, root, sign, pkey);
    if (sign[0] == '\0' && pkey[0] == '\0'){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to issue certificate");
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }
    endTime           = rt_time_ns();
    thread->diffTime += (endTime - startTime);

    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "%lu - %lu = %lu\n", startTime, endTime, endTime - startTime);

    FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[3], FS_OP_SET, thread->diffTime);
    FS_internal_operate(SGstats.handle, thread->field_ids, 0, FS_OP_ADD, 1);

#if 0
    char *chain[6] ={0};
    chain[0] = root;
    chain[1] = sign;
    web_json_table_add(pkey, sign, chain, &request->odata);
#else
    request->odata = (char *)malloc(SG_DATA_SIZE * 2);
    snprintf(request->odata, SG_DATA_SIZE * 2 - 1, "%s%s%s", pkey, sign, root);
#endif
    xret = rediSyncCommand(c, request, request->odata, expire_after);
    if (xret < 0){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to set information to redis server");
        goto finish;
    }
    xret = 0;
finish:
    return xret;
}

static int
redis_clnt_send(struct request_t *request, redisReply *reply)
{
    int xret                       = -1;

    char odata[SG_DATA_SIZE * 2] = {0};
    libevent_thread *thread        = threads + request->t_id;

    if (!reply && !reply->str){
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }

    FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

    FS_internal_operate(SGstats.handle, thread->field_ids, 0, FS_OP_ADD, 1);

    snprintf(odata, SG_DATA_SIZE * 2, "%s", reply->str);

    evhttp_socket_send(request->evh_req, odata);

finish:
    kfree(request);
    return xret;
}

void redis_get_callback(redisAsyncContext *c, void *r, void *privdata)
{
    int __attribute__((__unused__))xret = -1;

	redisReply *reply              = (redisReply*)r;
    struct request_t *request      = (struct request_t *)privdata;

    switch(reply->type){
        case REDIS_REPLY_STRING:
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Sends the certificate information to the requestor");

            xret = redis_clnt_send(request, reply);
            break;

        case REDIS_REPLY_NIL:
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Generating certificate information");

            xret = redis_clnt_pdu_send(request, c);
            break;
        default:
            break;
    }

    return;
}

int x509_privatekey_init(char *private_file, char *public_file,
                         EVP_PKEY **key, X509 **root)
{
    int xret = -1;
	FILE *fp; RSA *rsa = NULL;

	*key = EVP_PKEY_new();
    if (NULL == *key){
        goto finish;
    }

    rsa = RSA_new();
    if (NULL == rsa){
        goto pkey_free;
    }

    fp = fopen(private_file, "r");
    if (NULL == fp){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", private_file);
        RSA_free(rsa);
        goto pkey_free;
    }
    if ( !PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL) || !EVP_PKEY_assign_RSA(*key,rsa))
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Private key read failed");
        goto pkey_free;
	}
    fclose(fp);

    BIO *in;
    in = BIO_new_file(public_file, "r");
    if (!in){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", public_file);
        goto pkey_free;
    }

    if ((*root = PEM_read_bio_X509(in, NULL, 0, NULL)) == NULL )
    {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Application for x509 failed");
		goto pkey_free;
	}
    BIO_free(in);

    xret = 0;
    goto finish;

pkey_free:
    EVP_PKEY_free(*key);
finish:
    return xret;
}

#define BURSIZE 4096

int hex2dec(char c)
{
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('a' <= c && c <= 'f') {
        return c - 'a' + 10;
    } else if ('A' <= c && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

void _urldecode(char url[])
{
    int i = 0;
    int len = strlen(url);
    int res_len = 0;
    char res[BURSIZE];

    if(!strchr(url, '%'))
        return;

    for (i = 0; i < len; ++i) {
        char c = url[i];
        if (c != '%') {
            res[res_len++] = c;
        } else {
            char c1 = url[++i];
            char c0 = url[++i];
            int num = 0;
            num = hex2dec(c1) * 16 + hex2dec(c0);
            res[res_len++] = num;
        }
    }
    res[res_len] = '\0';
    strcpy(url, res);
}

static char*
decode_capture(const char *uri, const char *key)
{
    int size = 0;
    char *origin_uri = NULL;

    char *urlecode = STRSTR(uri, key);
    if (!urlecode){
        size = 0;
    }else{
        size = strlen(urlecode);
    }
    int len = strlen(uri) - size;
    origin_uri = (char *)malloc(len + 1);
    memcpy(origin_uri, uri, len);

    return origin_uri;
}

static char*
decode_origin_cert(const char *uri, const char *key)
{
    char *origin = NULL;

    char *urlecode = STRSTR(uri, key);
    if (!urlecode){
        goto finish;
    }
    origin = urlecode + 12;
    _urldecode(origin);
finish:
    return origin;
}

static int
thread_decode_uri(const char *uri, char *host,
             int *flag, X509 **origin, int *keyring_id)
{
    const char *fg = NULL, *cert = NULL;
    const char *ht = NULL, *id = NULL;
    char *decoded_uri = NULL, *ecode_uri = NULL;
    struct evkeyvalq params;

    decoded_uri = evhttp_decode_uri(ecode_uri = decode_capture(uri, "origin_cert"));
    if (!decoded_uri){
        goto finish;
    }
    evhttp_parse_query(uri, &params);

    ht = evhttp_find_header(&params, "host");
    if (ht != NULL)
        memcpy(host, ht, strlen(ht));
    fg = evhttp_find_header(&params, "flag");
    if (fg)
        *flag = atoi(fg);
    id = evhttp_find_header(&params, "kering_id");
    if (id)
        *keyring_id = atoi(id);
    cert = decode_origin_cert(uri, "origin_cert");
    if (cert)
        *origin = x509_get_ca_from_msg(cert, STRLEN(cert));

    evhttp_clear_headers(&params);
    free(decoded_uri);

finish:
    free(ecode_uri);
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

    thread_decode_uri(uri, request->host, &request->flag, &request->origin, &request->kering_id);
    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[Thread %d]Received a %s request for %s, host:%s, flag:%d, valid:%p\nHeaders:",
	                 request->t_id,  cmdtype, uri, request->host,
                     request->flag, request->origin);

    if (request->host[0] == '\0' ||
        request->origin == NULL ||
        !request->evh_req){
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

int redis_sync_init(struct redisContext **c)
{
    int xret = -1;
    struct config_bucket_t *redis = cert_default_config();

    struct timeval timeout = { 1, 500000 }; // 1.5 seconds

    *c = redisConnectWithTimeout(redis->r_ip, redis->r_port, timeout);
    if (*c == NULL || (*c)->err) {
        if (*c) {
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Sync connection error: %s\n", (*c)->errstr);
            redisFree(*c);
            *c = NULL;
        } else {
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Connection error: can't allocate redis context\n");
        }
        goto finish;
    }
    xret = 0;
finish:
    return xret;
}

static int
cert_task_private_init(struct event_base *base, libevent_thread *me)
{
    int xret = -1;

    /* Initialize the redis connection*/
    xret = redis_rsync_init(base, &me->cl_ctx);
    if (xret < 0 || !me->cl_ctx){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the redis connection is failure\n");
        goto finish;
    }

    xret = redis_sync_init(&me->sync);
    if (xret < 0 || !me->sync){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the sync redis connection is failure\n");
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

    libevent_thread *thread           = (libevent_thread *)arg;

    base = event_base_new();
    if (! base) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Can'thread allocate event base\n");
        goto finish;
    }

    http = evhttp_new(base);
	if (!http) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "couldn'thread create evhttp. Exiting.\n");
		goto error;
	}

    /* Context initialization */
    xret = cert_task_private_init(base, thread);
    if (xret < 0){
        goto error;
    }
    evhttp_set_cb(http, "/ca", pthread_work_proc, thread);

    bound = evhttp_accept_socket_with_handle(http, thread->accept_fd);
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
        if (thread->sync){
            redisAsyncDisconnect(thread->cl_ctx);
            redisFree(thread->sync);
        }
        key_ring_list_destroy(rte->keyring.htable);
    }
    kfree(threads);

    exit(1);
}

static int
MESA_internal_set_para(screen_stat_handle_t handle, enum FS_option type, unsigned value)
{
	int ret = FS_internal_set_para(handle, type, &value, (int)(sizeof(value)));
    return ret;
}

static int mesa_fiel_stat_init()
{
	char stat_path[63] = {0};
    char pname[32]= {0}, buff[128] = {0};

	SGstats.handle = FS_internal_create_handle();

    rt_get_pname_by_pid(getpid(), &pname[0]);
	FS_internal_set_para(SGstats.handle, APP_NAME, pname, strlen(pname)+1);
    snprintf(stat_path, 63, "%s/fs2_%s.status", logging_sc_lid.run_log_path, pname);
	FS_internal_set_para(SGstats.handle, OUTPUT_DEVICE, stat_path, strlen(stat_path)+1);

	MESA_internal_set_para(SGstats.handle, FLUSH_BY_DATE, 0);
	MESA_internal_set_para(SGstats.handle, PRINT_MODE, 1);
	MESA_internal_set_para(SGstats.handle, CREATE_THREAD, 1);
	MESA_internal_set_para(SGstats.handle, STAT_CYCLE, 3);

    snprintf(buff,sizeof(buff),"%s", "Req");
    SGstats.line_ids[0] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);
    snprintf(buff,sizeof(buff),"%s", "DB");
    SGstats.line_ids[1] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);
    snprintf(buff,sizeof(buff),"%s", "Local");
    SGstats.line_ids[2] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);
    snprintf(buff,sizeof(buff),"%s", "take-time");
    SGstats.line_ids[3] = FS_internal_register(SGstats.handle, FS_STYLE_COLUMN, FS_CALC_CURRENT, buff);

	MESA_internal_set_para(SGstats.handle, ID_INVISBLE, SGstats.line_ids[3]);
    snprintf(buff,sizeof(buff),"Cert/Nsec");
    FS_internal_register_ratio(SGstats.handle, SGstats.line_ids[3],
                               SGstats.line_ids[2], 1,
                               FS_STYLE_COLUMN, FS_CALC_CURRENT,
                               buff);
	FS_internal_start(SGstats.handle);

    return 0;
}

void Maat_read_entry_start_cb(int update_type, void* u_para)
{
    int xret = 0;

    struct key_ring_list *keyring = (struct key_ring_list *)u_para;

    if (update_type != 1)
        goto finish;

    /** The current behavior is full, and the original keyring chain is deleted */
    if (keyring->htable){
        key_ring_list_destroy(keyring);
    }

    xret = key_ring_list_create(keyring);
    if (xret == 0){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "The initial keyring list was successful, addr is %p\n",
                         keyring->htable);
    }
finish:
	return;
}

static void
Maat_read_entry_cb(int __attribute__((__unused__))table_id, const char* table_line,
                   void *u_para)
{
    int xret = 0;
	struct pxy_obj_keyring *pxy_obj = NULL;
	char private_file[512] = {0}, public_file[512] = {0};

    struct key_ring_list *keyring = (struct key_ring_list *)u_para;

    pxy_obj = (struct pxy_obj_keyring *)malloc(sizeof(struct pxy_obj_keyring));
    if (!pxy_obj){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Can not alloc, %s\n", strerror(errno));
        goto finish;
    }
    memset(pxy_obj, 0, sizeof(struct pxy_obj_keyring));
	sscanf(table_line, "%d\t%d\t%s\t%s\t%s\t%s\t%lu\t%s\t%s\t%d", &pxy_obj->id, &pxy_obj->service, pxy_obj->name,
		   pxy_obj->type, private_file, public_file, &pxy_obj->expire_after, pxy_obj->public_algo,
		   pxy_obj->ctl, &pxy_obj->is_valid);
    xret = x509_privatekey_init(private_file, public_file, &pxy_obj->key, &pxy_obj->root);
    if (xret < 0 || !pxy_obj->key || !pxy_obj->root){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to initialize the x509 certificate, the keyring id is %d",
                         pxy_obj->id);
        goto finish;
    }

    MESA_htable_add(keyring->htable, (const uchar *)(&(pxy_obj->id)), sizeof(int), pxy_obj);
    keyring->sum_cnt++;

finish:
	return;
}

void Maat_read_entry_finish_cb(void* u_para)
{
	long long version=0;
	Maat_feather_t feather = u_para;
	int ret = 0, is_last_updating_table = 0;

	ret = Maat_inter_read_state(feather,MAAT_STATE_VERSION, &version, sizeof(version));
	assert(ret==0);

	ret = Maat_inter_read_state(feather,MAAT_STATE_LAST_UPDATING_TABLE, &is_last_updating_table, sizeof(is_last_updating_table));
	assert(ret==0);
	//printf("Maat Version %lld at plugin finish callback, is_last_update=%d.\n",version,is_last_updating_table);

	return;
}

int sample_plugin_table(Maat_feather_t feather,const char* table_name,
					    Maat_start_callback_t *start,Maat_update_callback_t *update,Maat_finish_callback_t *finish,
					    void *u_para,
					    void __attribute__((__unused__))*logger)
{
	int table_id = 0,ret = 0;
	table_id = Maat_inter_table_register(feather,table_name);
	if(table_id == -1){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Database table %s register failed.\n",table_name);
	}else{
		ret = Maat_inter_table_callback_register(feather, table_id, start,
								                update, finish, u_para);
		if(ret < 0){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Maat callback register table %s error.\n",table_name);
		}
	}

	return ret;
}

int maat_feather_init()
{
    Maat_feather_t feather = NULL;
	int scan_interval_ms = 1, effective_interval_ms = 0;

    struct config_bucket_t *rte = cert_default_config();

	feather = Maat_inter_feather(rte->thread_nu, rte->info_path, logging_sc_lid.run_log_handle);

	Maat_inter_set_feather_opt(feather, MAAT_OPT_INSTANCE_NAME, "certstore", strlen("certstore") + 1);


    Maat_inter_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, rte->pxy_path, strlen(rte->pxy_path)+1);
    Maat_inter_set_feather_opt(feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	Maat_inter_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));
	Maat_inter_initiate_feather(feather);

    /*Keyring list initialization **/
    key_ring_list_create(&rte->keyring);

	sample_plugin_table(feather, "PXY_OBJ_KEYRING",
					    Maat_read_entry_start_cb,
					    Maat_read_entry_cb,
					    Maat_read_entry_finish_cb,
					    &rte->keyring,
    				    NULL);
    return 0;
}

int cert_session_init()
{
    mesa_fiel_stat_init();

    maat_feather_init();

    libevent_socket_init();
    return 0;
}

