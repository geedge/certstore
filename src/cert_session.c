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
#include <assert.h>

/* openssl**/
#include <opensslv.h>
#include <ssl.h>
#include <err.h>
#include <rand.h>
#include <x509.h>
#include <x509v3.h>
#include <crypto.h>
#include <engine.h>
#include <pkcs12.h>

#include <uuid/uuid.h>

#include "rt_string.h"
#include "rt_common.h"
#include "rt_stdlib.h"
#include "rt_file.h"
#include "rt_time.h"
#include "rt_tmr.h"
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

#define	SG_DATA_SIZE    10240

#define LOCAL_USER_PEN     1
#define LOCAL_USER_DER     2
#define LOCAL_USER_P12     3

#define	CM_UPDATE_TYPE_FULL	1
#define	CM_UPDATE_TYPE_INC	2

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
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis connect error : %s", c->errstr);
        return;
    }
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Redis server connected...");
}

void disconnectCallback(const struct redisAsyncContext *c, int status) {
    if (status != REDIS_OK) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis disconnect error: %s", c->errstr);
        return;
    }
    mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Redis server disconnected...");
}

void x509_get_private_key(EVP_PKEY *pkey, char *pubkey)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output");
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

static X509* base_load_pkcs12(BIO *in, EVP_PKEY **pkey, X509 **x, STACK_OF(X509) **ca)
{
    PKCS12 *p12 = NULL;
    const char *pass = "";

    X509 *_x = NULL;
    EVP_PKEY *_pkey;
    STACK_OF(X509) *_ca = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    p12 = d2i_PKCS12_bio(in, NULL);
    if (p12 == NULL) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error loading PKCS12 file");
        goto finish;
    }
    if (!PKCS12_parse(p12, pass, &_pkey, &_x, &_ca)) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error parsing PKCS#12 file");
        goto finish;
    }

    if (x)
        *x = _x;
    if (pkey)
        *pkey = _pkey;
    if (ca)
        *ca = _ca;

 finish:
    if (p12)
        PKCS12_free(p12);
    return _x;
}

static void cert_base_load_stack_info(BIO * in_bio, STACK_OF(X509) **stack_ca)
{
    int x509_cnt = 0;
    X509_INFO *x509_info;
    STACK_OF(X509) *stack_x509 = NULL;
    STACK_OF(X509_INFO) *stack_x509_info = NULL;

    if ((stack_x509 = sk_X509_new_null()) == NULL)
    {
        X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
        goto finish;
    }

    stack_x509_info = PEM_X509_INFO_read_bio(in_bio, NULL, NULL, NULL);
    if (stack_x509_info == NULL)
    {
        X509err(X509_F_X509_LOAD_CERT_CRL_FILE, ERR_R_PEM_LIB);
        goto finish;
    }

    while (sk_X509_INFO_num(stack_x509_info)) {
        x509_info = sk_X509_INFO_shift(stack_x509_info);
        if (x509_info->x509 != NULL) {
            sk_X509_push(stack_x509, x509_info->x509);
            x509_info->x509 = NULL;
            x509_cnt++;
        }
        X509_INFO_free(x509_info);
    }
    if (x509_cnt >= 1)
        *stack_ca = stack_x509;

finish:
    if (stack_x509_info != NULL)
        sk_X509_INFO_free(stack_x509_info);
    return;
}

static X509 *
cert_base_load_x509 (BIO * in_bio)
{
    return PEM_read_bio_X509 (in_bio, NULL, NULL, NULL);
}

static X509 *
cert_load_x509(char *file, STACK_OF(X509) **stack_ca)
{
    BIO *in_bio = NULL;
    X509 *x509 = NULL;

    if(!file){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Input cert file is empty.");
        goto finish;
    }

    if ((in_bio = BIO_new(BIO_s_file())) == NULL) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Bio malloc failed.");
        goto finish;
    }
    if (BIO_read_filename(in_bio, file) <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error opening %s", file);
        goto finish;
    }

    if ((x509 = cert_base_load_x509(in_bio)) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error loading pem file, %s",file);
    }
    cert_base_load_stack_info(in_bio, stack_ca);

    BIO_free (in_bio);
    in_bio = NULL;
finish:
    return x509;
}

EVP_PKEY * cert_base_key_x509 (BIO * bio, int iFormat, char *strPwd)
{
    EVP_PKEY *pkey = NULL;

    switch (iFormat){
        case LOCAL_USER_PEN:
            pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, strPwd);
            break;
        case LOCAL_USER_P12:
            base_load_pkcs12(bio, &pkey, NULL, NULL);
            break;
        default:
            break;
    }

    return pkey;
}

EVP_PKEY * cert_load_key(char *keyfile)
{
    EVP_PKEY *pkey = NULL;
    BIO *in = NULL;

    if(!keyfile){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Input key file is empty.");
        goto finish;
    }
    if ((in = BIO_new(BIO_s_file())) == NULL) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Bio malloc failed.");
        goto finish;
    }
    if (BIO_read_filename(in, keyfile) <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error opening %s\n", keyfile);
        goto finish;
    }

    if ((pkey = cert_base_key_x509 (in, LOCAL_USER_PEN, "")) != NULL)
        goto finish;
    (void)BIO_reset (in);
    if ((pkey = cert_base_key_x509 (in, LOCAL_USER_P12, "")) != NULL)
           goto finish;
finish:
    if (in != NULL)
        BIO_free (in);
    return pkey;
}

static void key_ring_free(void *data)
{
    struct pxy_obj_keyring *pxy_obj = NULL;
    pxy_obj = (struct pxy_obj_keyring *)data;

    X509_free(pxy_obj->root);
    EVP_PKEY_free(pxy_obj->key);
}

void key_ring_list_destroy(MESA_htable_handle *htable)
{
    MESA_htable_destroy(*htable, key_ring_free);
    *htable = NULL;
    return;
}

void uuid_squeeze(char *s,int c)
{
    int i,j;
    for (i = 0, j = 0; s[i] != '\0'; i++)
    {
        if (s[i] != c)
        {
            s[j++] = s[i];
        }
    }
    s[j] = '\0';
}

int
ssl_x509_set_serial(ASN1_INTEGER *ai)
{
    int ret = -1;
    uuid_t uu;
    char buf[64] = {0};
    BIGNUM *bignum = NULL;

    uuid_generate(uu);
    uuid_unparse(uu, buf);
    uuid_squeeze(buf, '-');

    BN_hex2bn(&bignum, buf);

    if (ai && !BN_to_ASN1_INTEGER(bignum, ai))
        goto error;
    ret = 1;
error:
    if (bignum)
        BN_free(bignum);
    return ret;
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

/**todo Use rules to determine if an sni exists */
static int
x509_alt_name_cmp(unsigned char *name, char *extraname)
{
    return strcmp((char *)name, extraname);
}

static int
x509_get_alt_name(X509 *x509, char *extraname)
{
    int i, xret = 1;

    if (x509 == NULL || extraname[0] == '\0'){
        xret = 0;
        goto finish;
    }

    GENERAL_NAMES* subjectAltNames = (GENERAL_NAMES*)X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
    if (subjectAltNames){
        int cnt = sk_GENERAL_NAME_num(subjectAltNames);

        for (i = 0; i < cnt; i++) {
            GENERAL_NAME* generalName = sk_GENERAL_NAME_value(subjectAltNames, i);
            xret = x509_alt_name_cmp(ASN1_STRING_data(GENERAL_NAME_get0_value(generalName, NULL)), extraname);
            if (xret == 0)
            break;
        }
    }
    if (subjectAltNames)
        GENERAL_NAMES_free(subjectAltNames);
finish:
    return xret;
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

static __attribute__((__unused__)) char*
x509_get_CrlDistPoints(X509 *x509)
{
    int i = 0, crit = 0;
	char value[512] = {0}, *crlurl = NULL;
	CRL_DIST_POINTS *crlpoints = NULL;

    crlpoints = (CRL_DIST_POINTS*)X509_get_ext_d2i(x509, NID_crl_distribution_points, &crit, NULL);
    if (!crlpoints)
        goto finish;

    for (i = 0; i < sk_DIST_POINT_num(crlpoints); i++){
		int j, gtype;
		GENERAL_NAMES *gens;
		GENERAL_NAME *gen;
		ASN1_STRING *uri;
		DIST_POINT *dp = sk_DIST_POINT_value(crlpoints, i);
		if (!dp->distpoint || dp->distpoint->type != 0)
			continue;
		gens = dp->distpoint->name.fullname;
		for (j = 0; j < sk_GENERAL_NAME_num(gens); j++){
			gen = sk_GENERAL_NAME_value(gens, j);
			uri = (ASN1_STRING*)GENERAL_NAME_get0_value(gen, &gtype);
            if (gtype == GEN_URI && ASN1_STRING_length(uri) > 6) {
                char *uptr = (char *)ASN1_STRING_data(uri);
				if (STRLEN(value) > 0){
					STRCAT(value, " | ");
				}
				STRCAT(value, uptr);
			}
		}
	}
	CRL_DIST_POINTS_free(crlpoints);

    crlurl = (char *)malloc(strlen(value) + 5);
    assert(crlurl);
    sprintf(crlurl, "URI:%s", value);
finish:
    return crlurl;
}

X509 *
x509_modify_by_cert(X509 *cacrt, EVP_PKEY *cakey, X509 *origcrt, char *pkey,
                        int days, char *extraname, char *crl)
{
	int rv;
	X509 *crt = NULL;
    EVP_PKEY* key = NULL;
	GENERAL_NAME *gn = NULL;
	GENERAL_NAMES *names = NULL;
	X509_NAME *subject = NULL, *issuer = NULL;

    if(!create_client_key(&key, pkey, 1024)){
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
	    ssl_x509_set_serial(X509_get_serialNumber(crt)) == -1 ||
	    !X509_gmtime_adj(X509_get_notBefore(crt), (long)(sizeof_seconds(-1))) ||
	    !X509_time_adj_ex(X509_get_notAfter(crt), days, 0, NULL) ||
	    !X509_set_pubkey(crt, key))
		goto errout;

    EVP_PKEY_free(key);
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

    if (crl != NULL && STRCMP(crl, "null")){
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Sign certificate the CRL is %s", crl);
        /**Add URI:**/
        char _crl[516] = {0};
        snprintf(_crl, 516, "%s%s", "URI:", crl);
        if (ssl_x509_v3ext_add(&ctx, crt, "crlDistributionPoints",
		                       _crl) == -1) {
			goto errout;
		}
    }
    char *cfval;
	if (x509_get_alt_name(origcrt, extraname) == 0) {
		/* no extraname provided: copy original subjectAltName ext */
		if (ssl_x509_v3ext_copy_by_nid(crt, origcrt,
		                               NID_subject_alt_name) == -1)
			goto errout;
	} else {
		names = (GENERAL_NAMES *)X509_get_ext_d2i(origcrt, NID_subject_alt_name, 0, 0);
		if (!names) {
			/* no subjectAltName present: add new one */
            cfval = (char *)malloc(strlen(extraname) + 5);
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
    EVP_PKEY_free(key);
err:
	return NULL;
}

void x509_get_msg_from_ca(X509 *x509, char **root)
{
	BIO *bp = NULL;
    int len = 0;

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output");
        goto finish;
    }
    PEM_write_bio_X509(bp, x509);

    char *p = NULL;
    len = BIO_get_mem_data(bp, &p);
    *root = (char*)malloc(len + 1);
    memset(*root, 0, len + 1);

    len = BIO_read(bp, *root, len);
    if(len <= 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Error reading signature file");
        goto err;
    }
err:
    BIO_free(bp);
finish:
	return;
}

X509 *
x509_get_ca_from_msg(const char *cert, int len)
{
    BIO *bp;
    char *in = NULL;
    X509* x509 = NULL;

    in = (char *)kmalloc(len, MPF_CLR, -1);
    assert(in);

	strncpy(in, cert, len);

    if ( (bp=BIO_new(BIO_s_mem())) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "unable to create BIO for output");
        goto finish;
    }
	BIO_printf(bp, "%s", in);
	x509 = PEM_read_bio_X509(bp, NULL, NULL, NULL);
	if(NULL == x509) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to read pem file");
        goto err;
    }
err:
	BIO_free(bp);
finish:
    free(in);
	return x509;
}

static
int redis_rsync_init(struct event_base *base, struct redisAsyncContext **cl_ctx)
{
    int xret = -1;
    struct config_bucket_t *redis = cert_default_config();

    *cl_ctx = redisAsyncConnect(redis->addr_t.store_ip, redis->addr_t.store_port);
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

void keyring_table_free_cb(int __attribute__((__unused__))table_id, MAAT_PLUGIN_EX_DATA* ad,
long __attribute__((__unused__))argl, void __attribute__((__unused__))*argp)
{
    if (ad == NULL)
        return;
	struct pxy_obj_keyring* pxy_obj=(struct pxy_obj_keyring*)(*ad);
	atomic64_dec(&pxy_obj->ref_cnt);	
    if (atomic64_read(&pxy_obj->ref_cnt) == 0)
    {
        if (pxy_obj->root)
            X509_free(pxy_obj->root);
        if (pxy_obj->key)
            EVP_PKEY_free(pxy_obj->key);
        kfree(&pxy_obj);
        *ad=NULL;
    }
}

void keyring_table_free(struct pxy_obj_keyring* pxy_obj)
{
    keyring_table_free_cb(0, (void **)&pxy_obj, 0, NULL);
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

X509 *x509_modify_by_cert_bak(X509 *cacrt, EVP_PKEY *cakey, const char* host,
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

char *x509_get_sn(X509 *x509)
{
	ASN1_INTEGER *asn1_i = NULL;
	BIGNUM *bignum = NULL;
	char *serial = NULL;

	asn1_i = X509_get_serialNumber(x509);
	bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
	if (bignum == NULL)	{
		goto finish;
	}
	serial = BN_bn2hex(bignum);
    if (serial == NULL)	{
		goto finish;
	}
    BN_free(bignum);
finish:
	return serial;
}

static int check(X509_STORE *ctx, X509 *x,
                 STACK_OF(X509) *uchain, STACK_OF(X509) *tchain,
                 STACK_OF(X509_CRL) *crls, ENGINE __attribute__((__unused__))*e)
{
    int i = 0, ret = 0;
    X509_STORE_CTX *csc;

    csc = X509_STORE_CTX_new();
    if (csc == NULL) {
        goto end;
    }
    X509_STORE_set_flags(ctx, 0);
    if (!X509_STORE_CTX_init(csc, ctx, x, uchain)) {
        goto end;
    }
    if (tchain)
        X509_STORE_CTX_trusted_stack(csc, tchain);
    if (crls)
        X509_STORE_CTX_set0_crls(csc, crls);
    i = X509_verify_cert(csc);
    X509_STORE_CTX_free(csc);

    ret = 0;
 end:
    if (i > 0) {
        ret = 1;
    }
    return (ret);
}

static int
x509_check_chain(STACK_OF(X509) *stack_ca, X509 *ca, X509 *x)
{
    int i = 0, xret = 0;
    X509_LOOKUP *lookup = NULL;
    X509_STORE *cert_ctx = NULL;

    cert_ctx = X509_STORE_new();
    if (cert_ctx == NULL){
        goto end;
    }
    X509_STORE_set_verify_cb(cert_ctx, NULL);

    lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file());
    if (stack_ca != NULL){
        for (i = 0; i < sk_X509_num(stack_ca); i++){
            X509_STORE_add_cert(lookup->store_ctx, sk_X509_value(stack_ca, i));
        }
    }
    X509_STORE_add_cert(lookup->store_ctx, ca);
    xret = check(cert_ctx, x, NULL, NULL, NULL, NULL);
end:
    if (cert_ctx != NULL)
        X509_STORE_free(cert_ctx);

    return xret;
}

static struct pxy_obj_keyring* get_obj_for_id(int keyring_id)
{
	struct pxy_obj_keyring *pxy_obj=NULL;

    struct config_bucket_t *rte = cert_default_config();

	char cfg_id_str[16] = {0};
	snprintf(cfg_id_str, sizeof(cfg_id_str), "%d", keyring_id);

	int tables_id = rte->table_id;
	pxy_obj = (struct pxy_obj_keyring*)maat_plugin_get_EX_data(rte->feather, tables_id, (const char*)cfg_id_str);
	return pxy_obj;
}

static int x509_online_append(struct x509_object_ctx *def, struct request_t *request,
                              char **root, char **sign, char *pkey,
                              STACK_OF(X509) **stack_ca, int *verify)
{
    X509* x509 = NULL;
    int is_valid = request->is_valid;
    int keyring_id = request->keyring_id;
    int _expire = 0; char *_crl = NULL;
    char *serial = NULL;
    X509 *_root = NULL; EVP_PKEY *_key = NULL;

    struct config_bucket_t *rte = cert_default_config();

    if (is_valid == 0 && keyring_id != 0) keyring_id = 0;
    if (is_valid == 1 && keyring_id == 0) keyring_id = 1;

    struct pxy_obj_keyring *pxy_obj = get_obj_for_id(keyring_id);
    if (NULL == pxy_obj)
    {
        if (!rte->local_debug)
        {
            if (1==is_valid)
            {
                pxy_obj = get_obj_for_id(1);
            }
            if (0==is_valid)
            {
                pxy_obj = get_obj_for_id(0);
            }
            assert(pxy_obj!=NULL);
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Certificate issued by table id %d", keyring_id);
        }
        else
        {
            _root = (is_valid == 1) ? def->root : def->insec_root;
            _key  = (is_valid == 1) ? def->key  : def->insec_key;
            _expire = cert_default_config()->expire_after;
            mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Certificate issued by local cert");
            goto modify;
        }
    }
    if (!STRCMP(pxy_obj->keyring_type, "end-entity"))
    {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "The certificate(%d) type is an entity certificate",
                         keyring_id);
        *stack_ca = pxy_obj->stack_ca;
        x509_get_msg_from_ca(pxy_obj->root, sign);
        x509_get_private_key(pxy_obj->key, pkey);
        goto finish;
    }
    if (!STRCMP(pxy_obj->keyring_type, "intermediate"))
    {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "The certificate(%d) type is intermediate, chain address %p",
                         keyring_id, pxy_obj->stack_ca);
        *stack_ca = pxy_obj->stack_ca;
    }
    _root = pxy_obj->root;
    _key  = pxy_obj->key;
    _expire = pxy_obj->expire_after;
    _crl    = pxy_obj->v3_ctl;
modify:
    x509 = x509_modify_by_cert(_root, _key, request->origin, pkey,
                                     _expire, request->sni, _crl);
    if (!x509){
        goto finish;
    }

    serial = x509_get_sn(x509);
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "The certificate serial number is %s", serial);
    OPENSSL_free(serial);

    *verify = x509_check_chain(*stack_ca, _root, x509);
    if (*verify != 1)
    {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Certificate chain match failed");
    }
    x509_get_msg_from_ca(x509, sign);
    x509_get_msg_from_ca(_root, root);

    if (request->origin)
        X509_free(request->origin);
    X509_free(x509);
finish:
    if (pxy_obj)
        keyring_table_free(pxy_obj);
    return _expire;
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

    libevent_thread *thread        = threads + request->thread_id;
    struct evhttp_request *evh_req = request->evh_req;

    reply = (redisReply *)redisCommand(thread->sync, "set %s %s ex %d nx", request->rkey, odata,
                                             sizeof_seconds(expire_after));
    if (NULL == reply)
        goto free;

    switch (readBytes(reply->str)) {
        case '+' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(%s) to redis successfully", request->rkey);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[2], FS_OP_ADD, 1);

            evhttp_socket_send(evh_req, request->odata);
            goto free;
        case '$' :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Writing data(%s) to redis failed", request->rkey);
            FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

            redisAsyncCommand(cl_ctx, redis_reget_callback, request, "GET %s", request->rkey);
            freeReplyObject(reply);
            goto finish;
        default  :
            mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Read redis data(%s) return code failed", request->rkey);
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
    int i = 0;
    size_t osize = 0;
    const char *jstr = NULL;
    struct json_object *outline = json_object_new_object();

    json_object_object_add(outline, "CERTIFICATE_CHAIN", web_json_record_array_add_string(chain));
	json_object_object_add(outline, "PRIVATE_KEY", json_object_new_string(privatekey));
    json_object_object_add(outline, "CERTIFICATE", json_object_new_string(sign));

    jstr = json_object_to_json_string (outline);

    json_data_rebuild(jstr, strlen(jstr), data, &osize);

    json_object_put(outline);

    kfree(sign);
    for (i = 0; i < 6; i ++){
        if (chain[i] != NULL)
            kfree(chain[i]);
    }
    return 0;
}

static int
redis_clnt_pdu_send(struct request_t *request, redisAsyncContext *c)
{
#define MAX_CHAIN_LEN 6
    int xret = -1, i = 0;
    int expire_after, verify = 0;
    STACK_OF(X509) *stack_ca = NULL;
    uint64_t startTime = 0, endTime = 0;
    libevent_thread *info   = threads + request->thread_id;
    char *sign = NULL, pkey[SG_DATA_SIZE] = {0};
    char *root = NULL;

    startTime        = rt_time_ns();

    expire_after = x509_online_append(&info->def, request, &root, &sign, pkey, &stack_ca, &verify);
    if (sign == NULL && pkey[0] == '\0'){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to sign certificate");
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }
    endTime           = rt_time_ns();
    info->diffTime += (endTime - startTime);

    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "%lu - %lu = %lu", startTime, endTime, endTime - startTime);

    FS_internal_operate(SGstats.handle, info->column_ids, SGstats.line_ids[3], FS_OP_SET, info->diffTime);
    FS_internal_operate(SGstats.handle, info->field_ids, 0, FS_OP_ADD, 1);

    char *single = NULL;
    char *chain[MAX_CHAIN_LEN] = {0};
    if (stack_ca){
        for (i = 0; i < sk_X509_num(stack_ca); i++){
            x509_get_msg_from_ca(sk_X509_value(stack_ca, i), &single);
            chain[i] = single;
        }
        if (root != NULL){
            chain[i] = root;
            i++;
        }
    }else{
        chain[0] = root;
    }

    web_json_table_add(pkey, sign, chain, &request->odata);

    if ((NULL == c) || (verify == 0)){
        struct evhttp_request *evh_req = request->evh_req;
        FS_internal_operate(SGstats.handle, info->column_ids, SGstats.line_ids[2], FS_OP_ADD, 1);
        evhttp_socket_send(evh_req, request->odata);
        kfree(request->odata);
        kfree(request);
        xret = 0;
        goto finish;
    }

    xret = rediSyncCommand(c, request, request->odata, expire_after);
    if (xret < 0){
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

    libevent_thread *thread        = threads + request->thread_id;

    if (!reply && !reply->str){
        evhttp_send_error(request->evh_req, HTTP_NOTFOUND, 0);
        goto finish;
    }

    FS_internal_operate(SGstats.handle, thread->column_ids, SGstats.line_ids[1], FS_OP_ADD, 1);

    FS_internal_operate(SGstats.handle, thread->field_ids, 0, FS_OP_ADD, 1);

    evhttp_socket_send(request->evh_req, reply->str);

finish:
    if (request->origin)
        X509_free(request->origin);
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

int x509_key_pair_init(char *ca_file, EVP_PKEY **key, X509 **root)
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

    fp = fopen(ca_file, "r");
    if (NULL == fp){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", ca_file);
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
    in = BIO_new_file(ca_file, "r");
    if (!in){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to open file(%s)", ca_file);
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
    char *res = NULL;

    res = (char *)malloc(len + 1);
    if (!res){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Url alloc faild");
        return;
    }

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

    free(res);
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
thread_decode_uri(const char *uri, X509 **origin,
                  int *keyring_id, char *sni, int *is_valid)
{
    const char *_origin = NULL, *id = NULL;
    const char *_sni = NULL, *_valid = NULL;
    char *decoded_uri = NULL, *ecode_uri = NULL;
    struct evkeyvalq params;

    decoded_uri = evhttp_decode_uri(ecode_uri = decode_capture(uri, "origin_cert"));
    if (!decoded_uri){
        goto finish;
    }
    evhttp_parse_query(uri, &params);
    id   = evhttp_find_header(&params, "keyring_id");
    if (id)
        *keyring_id = atoi(id);
    _valid = evhttp_find_header(&params, "is_valid");
    if (_valid)
        *is_valid = atoi(_valid);
    _sni = evhttp_find_header(&params, "sni");
    if (_sni)
         memcpy(sni, _sni, strlen(_sni));

    _origin = decode_origin_cert(uri, "origin_cert");
    if (_origin)
        *origin = x509_get_ca_from_msg(_origin, STRLEN(_origin) + 1);

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

static int
x509_get_rkey(X509 *origin, int keyring_id, char *rkey, int is_valid)
{
    unsigned int len = 0, i = 0;
    char hex[EVP_MAX_MD_SIZE] = {0};
    unsigned char fdig[EVP_MAX_MD_SIZE] = {0};

    X509_digest(origin, EVP_sha1(), fdig, &len);
    for (i = 0; i < len ; ++i){
        sprintf(hex + i * sizeof(unsigned char) * 2, "%02x", fdig[i]);
    }
    /** keyrind_id is 0, sign x509 by default */
    /** 0 uninsec, 1 insec*/
    if (is_valid && keyring_id == 0) keyring_id = 1;

    struct pxy_obj_keyring *pxy_obj = get_obj_for_id(keyring_id);
    if (pxy_obj != NULL)
    {
        snprintf(rkey, DATALEN, "%d:%s:%s:%d", keyring_id, hex, pxy_obj->finger, is_valid);
        goto finish;
    }
    snprintf(rkey, DATALEN, "%d:%s:%d", keyring_id, hex, is_valid);
finish:
    return 0;
}

void
pthread_work_proc(struct evhttp_request *evh_req, void *arg)
{
    int xret                     = -1;
    const char *cmdtype          = NULL;
    struct request_t *request    = NULL;
	struct evhttp_uri *decoded   = NULL;
    libevent_thread *info = (libevent_thread *)arg;

   /* we want to know if this connection closes on us */
	evhttp_connection_set_closecb(evhttp_request_get_connection(evh_req), evhttp_socket_close_cb, NULL);

	const char *uri = evhttp_request_get_uri(evh_req);
     /* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "It's not a good URI. Sending BADREQUEST");
		goto error;
	}

	request = (struct request_t *) kmalloc (sizeof(struct request_t), MPF_CLR, -1);
    if (request != NULL){
        memset(request, 0, sizeof(struct request_t));
        request->keyring_id = 0;
        request->thread_id  = info->id;
        request->evh_req    = evh_req;
    }
	switch (evhttp_request_get_command(evh_req)) {
        case EVHTTP_REQ_GET: cmdtype = "GET";     break;
        default:             cmdtype = "unknown"; break;
	}
    FS_internal_operate(SGstats.handle, info->column_ids, SGstats.line_ids[0], FS_OP_ADD, 1);

    thread_decode_uri(uri, &request->origin, &request->keyring_id, request->sni,
                      &request->is_valid);

    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "[Thread %d]Received a %s request for uri, kering_id:%d, sni:%s origin:%p valid:%d",
                     request->thread_id, cmdtype, request->keyring_id, request->sni, request->origin, request->is_valid);

    if (request->origin == NULL || !request->evh_req){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to resolve the request url");
        kfree(request);
        evhttp_uri_free(decoded);
        goto error;
    }

    x509_get_rkey(request->origin, request->keyring_id, request->rkey, request->is_valid);
    if (request->rkey[0] == '\0'){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Get the redis key from the certificate failed");
        goto error;
    }
    mesa_runtime_log(RLOG_LV_DEBUG, MODULE_NAME, "Redis key is %s", request->rkey);

    if (info->cl_ctx->err != 0){
        xret = redis_clnt_pdu_send(request, NULL);
        if (xret < 0)
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Local sign certificate failed");
        goto free;
    }else{
        xret = redisAsyncCommand(info->cl_ctx, redis_get_callback, request, "GET %s", request->rkey);
        if (xret < 0)
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to get information from redis server");
    }
free:
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

    *c = redisConnectWithTimeout(redis->addr_t.store_ip, redis->addr_t.store_port, timeout);
    if (*c == NULL || (*c)->err) {
        if (*c) {
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Sync connection error: %s", (*c)->errstr);
            redisFree(*c);
            *c = NULL;
        } else {
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Connection error: can't allocate redis context");
        }
        goto finish;
    }
    xret = 0;
finish:
    return xret;
}

static int
task_private_init(struct event_base *base, libevent_thread *info)
{
    int xret = -1;
    struct config_bucket_t *config = cert_default_config();

    /* Initialize the redis connection*/
    xret = redis_rsync_init(base, &info->cl_ctx);
    if (xret < 0 || !info->cl_ctx){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the redis connection is failure");
    }

    xret = redis_sync_init(&info->sync);
    if (xret < 0 || !info->sync){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Initialize the sync redis connection is failure");
    }

    if (config->local_debug)
    {
        /* Initialize the X509 CA*/
        xret = x509_key_pair_init(config->ca_path, &info->def.key, &info->def.root);
        if (xret < 0 || !(info->def.key) || !(info->def.root)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to initialize the x509 certificate");
            goto finish;
        }

        /* Initialize the insec CA*/
        xret = x509_key_pair_init(config->uninsec_path, &info->def.insec_key, &info->def.insec_root);
        if (xret < 0 || !(info->def.key) || !(info->def.root)){
            mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Failed to initialize the insec x509 certificate");
            goto finish;
        }
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
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Can'thread allocate event base");
        goto finish;
    }

    http = evhttp_new(base);
	if (!http) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "couldn'thread create evhttp. Exiting.");
		goto error;
	}
    thread->base = base;

    /* Context initialization */
    xret = task_private_init(base, thread);
    if (xret < 0){
        goto error;
    }
    evhttp_set_cb(http, "/ca", pthread_work_proc, thread);

    bound = evhttp_accept_socket_with_handle(http, thread->accept_fd);
    if (bound != NULL) {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Bound(%p) to port %d - Awaiting connections ... ", bound,
                        cert_default_config()->addr_t.e_port);
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

static void
redis_link_detection(uint32_t __attribute__((__unused__)) uid,
                    int __attribute__((__unused__))argc,
                    char **argv)
{
    int tid = 0, xret = 0;
    libevent_thread *info   = NULL;
    libevent_thread *threads = (libevent_thread *)argv;

    unsigned int thread_nu = cert_default_config()->thread_nu;
    for (tid = 0; tid < (int)thread_nu; tid++) {
        info  = threads + tid;
        if(info->cl_ctx->err != 0){
            if (info->sync)
                redisFree(info->sync);

            xret = redis_sync_init(&info->sync);
            if (xret < 0 || !info->sync){
                mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "[%d]trying to connect sync redis failed", tid);
                continue;
            }else{
                mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "[%d]trying to connect sync redis success", tid);
            }

            xret = redis_rsync_init(info->base, &info->cl_ctx);
            if (xret < 0 || !info->cl_ctx){
                mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "[%d]trying to connect rsync redis failed", tid);
            }else{
                mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "[%d]trying to connect rsync redis success", tid);
            }
        }
    }
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
    sin.sin_port   = htons(cert_default_config()->addr_t.e_port);
    accept_fd      = evhttp_listen_socket_byuser((struct sockaddr*)&sin, sizeof(struct sockaddr_in),
                                                 LEV_OPT_REUSEABLE_PORT|LEV_OPT_CLOSE_ON_FREE, -1);
    if (accept_fd < 0) {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "Could not create a listen!");
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
#ifdef RT_TMR_ADVANCED
    /*Create timers to monitor redis connections **/
    uint32_t tm_link_detetion = 0;
    tm_link_detetion = tmr_create(1, "Redis link detection",
                                  redis_link_detection, 1, (char **)threads, 5);
    if (((int32_t)tm_link_detetion < 0)){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s",
                        "Can not create link-detection timer for redis\n");
    }
    tmr_start(tm_link_detetion);
#endif
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
            free(thread->cl_ctx);
            redisFree(thread->sync);
        }
        event_base_free(thread->base);
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
	char stat_path[128] = {0};
    char pname[32]= {0}, buff[128] = {0};

	SGstats.handle = FS_internal_create_handle();

    rt_get_pname_by_pid(getpid(), &pname[0]);
	FS_internal_set_para(SGstats.handle, APP_NAME, pname, strlen(pname)+1);
    snprintf(stat_path, 128, "%s/fs2_%s.status", logging_sc_lid.run_log_path, pname);
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

static void
x509_get_fingerprint(X509 *x509, char *finger)
{
    int xret = -1;
    unsigned int len = 0, i = 0;
    unsigned char fdig[EVP_MAX_MD_SIZE] = {0};

    xret = X509_digest(x509, EVP_sha1(), fdig, &len);
    if (xret != 1)
        goto finish;
    for (i = 0; i < len ; ++i){
        sprintf(finger + i * sizeof(unsigned char) * 2, "%02x", fdig[i]);
    }
finish:
    return;
}

void keyring_table_new_cb(int __attribute__((__unused__))table_id, const char  __attribute__((__unused__))*key,
const char* table_line, MAAT_PLUGIN_EX_DATA* ad, long __attribute__((__unused__))argl, void __attribute__((__unused__))* argp)
{
    char profile_name[CT_ARRARY_LEN]={0};
    char private_file[CT_STRING_MAX] = {0}, public_file[CT_STRING_MAX]={0};
    char __attribute__((__unused__))_priv_file[CT_PATH_MAX] = {0};
    char __attribute__((__unused__))_publi_file[CT_PATH_MAX] = {0};
    int ret=0;

	struct pxy_obj_keyring *pxy_obj = NULL;

    pxy_obj = (struct pxy_obj_keyring *)malloc(sizeof(struct pxy_obj_keyring));
    if (!pxy_obj)
    {
        mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "Can not alloc, %s", strerror(errno));
        goto finish;
    }
    memset(pxy_obj, 0, sizeof(struct pxy_obj_keyring));
	atomic64_set(&pxy_obj->ref_cnt, 1);
	
	ret=sscanf(table_line, "%d\t%s\t%s\t%s\t%s\t%lu\t%s\t%s\t%d", &pxy_obj->keyring_id, profile_name,
		       pxy_obj->keyring_type, private_file, public_file, &pxy_obj->expire_after, pxy_obj->public_algo,
		       pxy_obj->v3_ctl, &pxy_obj->is_valid);
	if(ret!=9)
	{
        kfree(&pxy_obj);
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "certstore parse config failed: %s", table_line);
        goto finish;
	}

    /*Load PUBLICKEY***/
    if ((pxy_obj->root = cert_load_x509(public_file, &pxy_obj->stack_ca)) == NULL ){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "initialize the x509 publickey failed, the keyring id is %d",
                         pxy_obj->keyring_id);
		goto finish;
	}
    /*Load PRIVATEKEY**/
    if ((pxy_obj->key = cert_load_key(private_file)) == NULL){
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "initialize the x509 privatekey failed, the keyring id is %d",
                         pxy_obj->keyring_id);
        goto finish;
    }
    mesa_runtime_log(RLOG_LV_INFO, MODULE_NAME, "initialize the x509 certificate, the keyring id is %d",
                     pxy_obj->keyring_id);
    x509_get_fingerprint(pxy_obj->root, pxy_obj->finger);

	*ad = pxy_obj;
finish:
	return;
}

void keyring_table_dup_cb(int __attribute__((__unused__))table_id,	MAAT_PLUGIN_EX_DATA *to, MAAT_PLUGIN_EX_DATA *from,
long __attribute__((__unused__))argl, void __attribute__((__unused__))*argp)
{
	struct pxy_obj_keyring* pxy_obj=(struct pxy_obj_keyring*)(*from);
	atomic64_inc (&pxy_obj->ref_cnt);
	*to=pxy_obj;
}

int maat_table_ex_init(const char* table_name,
					   Maat_plugin_EX_new_func_t* new_func,
					   Maat_plugin_EX_free_func_t* free_func,
					   Maat_plugin_EX_dup_func_t* dup_func)
{
	int table_id = 0;

    struct config_bucket_t *rte = cert_default_config();

	table_id= rte->table_id = maat_table_register(rte->feather, table_name);
	if(table_id<0)
	{
		goto finish;
	}
	table_id=maat_plugin_EX_register(rte->feather,
 						             table_id,
 						             new_func,free_func,
 						             dup_func,NULL,0,NULL);
finish:
	return table_id;
}

int maat_feather_init()
{
    int ret = -1;
    Maat_feather_t feather = NULL;
	int scan_interval_ms = 1000;

    struct config_bucket_t *rte = cert_default_config();
    struct ntc_maat_t *maat_t = &rte->maat_t;

    int effective_interval_ms = maat_t->effective_interval_s * 1000;

	feather = maat_feather(rte->thread_nu, maat_t->info_path, logging_sc_lid.run_log_handle);

	maat_set_feather_opt(feather, MAAT_OPT_INSTANCE_NAME, "certstore", strlen("certstore") + 1);

    if (maat_t->maat_json_switch == 1){
        maat_set_feather_opt(feather, MAAT_OPT_JSON_FILE_PATH, maat_t->pxy_path, strlen(maat_t->pxy_path)+1);
    }
    if (maat_t->maat_json_switch == 0){
        maat_set_feather_opt(feather, MAAT_OPT_FULL_CFG_DIR, maat_t->full_cfg_dir, strlen(maat_t->full_cfg_dir)+1);
        maat_set_feather_opt(feather, MAAT_OPT_INC_CFG_DIR, maat_t->inc_cfg_dir, strlen(maat_t->inc_cfg_dir)+1);
    }
    if (maat_t->maat_json_switch == 2){
        maat_set_feather_opt(feather, MAAT_OPT_REDIS_IP, rte->addr_t.maat_ip, strlen(rte->addr_t.maat_ip)+1);
        maat_set_feather_opt(feather, MAAT_OPT_REDIS_PORT, &rte->addr_t.maat_port, sizeof(rte->addr_t.maat_port));
        maat_set_feather_opt(feather, MAAT_OPT_REDIS_INDEX, &rte->addr_t.dbindex, sizeof(rte->addr_t.dbindex));
    }

    maat_set_feather_opt(feather, MAAT_OPT_SCANDIR_INTERVAL_MS,&scan_interval_ms, sizeof(scan_interval_ms));
	maat_set_feather_opt(feather, MAAT_OPT_EFFECT_INVERVAL_MS,&effective_interval_ms, sizeof(effective_interval_ms));
    /***/
    const char* foregin_dir="./foreign_files/";
    maat_set_feather_opt(feather, MAAT_OPT_FOREIGN_CONT_DIR,foregin_dir, strlen(foregin_dir)+1);
	ret = maat_initiate_feather(feather);
	if (ret < 0)
	{
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "%s MAAT init failed.", __FUNCTION__);
	}
    rte->feather = feather;

    int table_id = maat_table_ex_init("PXY_PROFILE_KEYRING",
                                      keyring_table_new_cb,
        					          keyring_table_free_cb,
        					          keyring_table_dup_cb);
    if(table_id<0)
    {
        mesa_runtime_log(RLOG_LV_FATAL, MODULE_NAME, "certstore register table PXY_PROFILE_KEYRING failed");
    }

    return 0;
}

int cert_session_init()
{
    mesa_fiel_stat_init();

    maat_feather_init();

    libevent_socket_init();

    return 0;
}

