/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for ECDSA signature generation abstraction routines of FDO
 * library.
 */

#include "safe_lib.h"
#include "fdoCryptoHal.h"
#include "storage_al.h"
#include "unity.h"
#include "openssl/core_names.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/encoder.h>

// #define HEXDEBUG 1

#define CLR_TXT_LENGTH BUFF_SIZE_1K_BYTES
#define ECDSA_SIG_MAX_LENGTH 150
#define ECDSA_PK_MAX_LENGTH 200
#define DER_PUBKEY_LEN_MAX 512

#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
void test_fdo_cryptoECDSASign(void);

/*** Unity functions. ***/
void set_up(void)
{
}

void tear_down(void)
{
}
#endif

#if defined(ECDSA256_DA) || defined(ECDSA384_DA)

#if defined(HEXDEBUG)
// Helper function to convert binary to hex
static char *bytes_to_hex(const uint8_t bin[], size_t len)
{
	static const char hexchars[16] = "0123456789abcdef";
	static char hex[BUFF_SIZE_512_BYTES];
	size_t i;

	for (i = 0; i < len; ++i) {
		hex[2 * i] = hexchars[bin[i] / 16];
		hex[2 * i + 1] = hexchars[bin[i] % 16];
	}
	hex[2 * len] = '\0';
	return hex;
}

// Helper to print public keys
static void dump_pubkey(const char *title, void *ctx)
{
	uint8_t buf[512];
	size_t len = 0;

#if defined(USE_MBEDTLS)
	mbedtls_ecdsa_context *key = (mbedtls_ecdsa_context *)ctx;
	if (mbedtls_ecp_point_write_binary(&key->grp, &key->Q,
					   MBEDTLS_ECP_PF_UNCOMPRESSED, &len,
					   buf, sizeof(buf)) != 0) {
		printf("internal error\n");
		return;
	}
#endif
#if defined(USE_OPENSSL)
	uint8_t *pub_copy = buf;

	EVP_PKEY *eckey = (EVP_PKEY *)ctx;
	len = i2o_ECPublicKey(eckey, NULL);

	/* pub_copy is required, because i2o_ECPublicKey alters the input
	 * pointer */
	if (i2o_ECPublicKey(eckey, &pub_copy) != len) {
		printf("PUB KEY TO DATA FAIL\n");
	}
#endif
	printf("%s %s len:%ld\n", title, bytes_to_hex(buf, len), len);
}
#endif

static fdo_byte_array_t *getcleartext(int length)
{
	fdo_byte_array_t *cleartext = fdo_byte_array_alloc(length);
	if (!cleartext)
		return NULL;
	int i = length;
	random_init();
	crypto_hal_random_bytes(cleartext->bytes, cleartext->byte_sz);
	while (i) {
		cleartext->bytes[i - 1] = 'A' + (cleartext->bytes[i - 1] % 26);
		i--;
	}
#ifdef HEXDEBUG
	hexdump("CLEARTEXT", cleartext->bytes, cleartext->byte_sz);
#endif
	return cleartext;
}

//----------------------------------------------------
#ifdef USE_OPENSSL
static EVP_PKEY *generateECDSA_key(void)
{
	EVP_PKEY *evp_key = NULL;
	uint32_t group_name_nid;

#if defined(ECDSA256_DA)
	group_name_nid = NID_X9_62_prime256v1;
#else
	group_name_nid = NID_secp384r1;
#endif

	evp_key = EVP_EC_gen(OBJ_nid2sn(group_name_nid));
	if (!evp_key) {
		LOG(LOG_ERROR, "EC key generation failed\n");
		return NULL;
	}

	return evp_key;
}

#endif // USE_OPENSSL

#ifdef USE_MBEDTLS
#if defined(ECDSA256_DA)
#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1 // gen 256 ec curve
#elif defined(ECDSA384_DA)
#define ECPARAMS MBEDTLS_ECP_DP_SECP384R1 // gen 384 ec curve
#endif
static int generateECDSA_key(mbedtls_ecdsa_context *ctx_sign)
{
	int ret;
	char *pers = "ecdsa_genkey";
	size_t pers_len = strnlen_s(pers, FDO_MAX_STR_SIZE);
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	if (NULL == ctx_sign)
		return -1;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					 &entropy, (const unsigned char *)pers,
					 pers_len)) != 0) {
		return -1;
	}

	mbedtls_ecdsa_init(ctx_sign);
	if ((ret = mbedtls_ecdsa_genkey(ctx_sign, ECPARAMS,
					mbedtls_ctr_drbg_random, &ctr_drbg))) {
		return -1;
	}

	//	mbedtls_printf( " ok (key size: %d bits)\n", (int)
	// ctx_sign->grp.pbits);

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}

#endif // USE_MBEDTLS
#endif // PK_ENC_ECDSA || ECDSA256_DA || ECDSA384_DA
/*** Test functions. ***/

// Below test case is replacement of EPID with ECDSA
#if !(defined(ECDSA256_DA) || defined(ECDSA384_DA))
#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoECDSASign(void)
#else
TEST_CASE("fdo_cryptoECDSASign", "[ECDSARoutines][fdo]")
#endif
{
	TEST_IGNORE();
}

#else
#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoECDSASign(void)
#else
TEST_CASE("crypto_hal_ecdsa_sign", "[ECDSARoutines][fdo]")
#endif
{
	int result = -1;
	fdo_byte_array_t *testdata = getcleartext(CLR_TXT_LENGTH);
	TEST_ASSERT_NOT_NULL(testdata);
	size_t siglen = ECDSA_SIG_MAX_LENGTH;
	unsigned char *sigtestdata = fdo_alloc(ECDSA_SIG_MAX_LENGTH);
	TEST_ASSERT_NOT_NULL(sigtestdata);
	EVP_MD_CTX *mdctx = NULL;
	unsigned char *sig_r = NULL;
	unsigned char *sig_s = NULL;
	uint32_t der_sig_len = 0;
	uint8_t *der_sig = NULL;
	size_t hash_length = 0;

#if defined(ECDSA256_DA)
	hash_length = SHA256_DIGEST_SIZE;
#elif defined(ECDSA384_DA)
	hash_length = SHA384_DIGEST_SIZE;
#endif

// Create the context & create the key
#ifdef USE_OPENSSL
	EVP_PKEY *avalidkey = generateECDSA_key();
	TEST_ASSERT_NOT_NULL(avalidkey);
	int privatekey_buflen = hash_length;
	BIGNUM *r = NULL;
	BIGNUM *s = NULL;
	ECDSA_SIG *sig = NULL;
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_context ctx_sign = {0};
	result = generateECDSA_key(&ctx_sign);
	TEST_ASSERT_EQUAL(0, result);
	int privatekey_buflen = mbedtls_mpi_size(&ctx_sign.d);
#endif
	// Extracting private key from mbedtls structure
	unsigned char *privatekey = fdo_alloc(privatekey_buflen);
	TEST_ASSERT_NOT_NULL(privatekey);
	memset_s(privatekey, 0, privatekey_buflen);

// store private key for later use in pem /bin format
#if defined(ECDSA_PEM)
	BIO *outbio = BIO_new(BIO_s_mem());
	TEST_ASSERT_NOT_NULL(outbio);
	EVP_PKEY *privkey = EVP_PKEY_new();
	TEST_ASSERT_NOT_NULL(privkey);

	BIGNUM *priv;
	OSSL_PARAM_BLD *param_bld;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx; // Creating new EVP_PKEY context

	priv = BN_bin2bn(privatekey, privatekey_buflen, NULL);
	param_bld = OSSL_PARAM_BLD_new();

	if (priv != NULL && param_bld != NULL &&
	    OSSL_PARAM_BLD_push_utf8_string(param_bld, "group", "prime256v1",
					    0) &&
	    OSSL_PARAM_BLD_push_BN(param_bld, "priv", priv) &&
	    OSSL_PARAM_BLD_push_octet_string(param_bld, "pub", NULL, 0)) {
		params = OSSL_PARAM_BLD_to_param(param_bld);
	}

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

	if (ctx == NULL || params == NULL || EVP_PKEY_fromdata_init(ctx) <= 0 ||
	    EVP_PKEY_fromdata(ctx, &privkey, EVP_PKEY_KEYPAIR, params) <= 0) {
		exit(1);
	}

	size_t group_name_size;
	char group_name[64];

	EVP_PKEY_get_utf8_string_param(privkey, OSSL_PKEY_PARAM_GROUP_NAME,
				       NULL, 0, &group_name_size);
	if (group_name_size >= sizeof(group_name)) {
		LOG(LOG_ERROR, "Unexpected long group name : %zu for EC key\n",
		    group_name_size);
		exit(1);
	}

	if (!EVP_PKEY_get_utf8_string_param(privkey, OSSL_PKEY_PARAM_GROUP_NAME,
					    group_name, sizeof(group_name),
					    &group_name_size)) {
		LOG(LOG_ERROR, "Failed to get the group name fo EC EVP key\n");
		exit(1);
	}

	int group_nid = OBJ_sn2nid(group_name);
	const EC_GROUP *group = EC_GROUP_new_by_curve_name(group_nid);

	if (group == NULL) {
		LOG(LOG_ERROR, "Failed to get the group name fo EC EVP key\n");
		exit(1);
	}
	//  const EC_GROUP *group = EC_KEY_get0_group(avalidkey);

	//  PEM_write_bio_ECPKParameters(outbio, group);
	//  if (!PEM_write_bio_ECPrivateKey(outbio, avalidkey, NULL, NULL, 0,
	//  0,
	// 				 NULL))
	//      BIO_printf(outbio, "Error writing private key data in PEM
	//      format");

	if (!PEM_write_bio_Parameters(outbio, privkey)) {
		BIO_printf(outbio, "Error writing parameters in PEM format");
	}

	if (PEM_write_bio_PrivateKey(outbio, privkey, NULL, NULL, 0, 0, NULL) ==
	    0) {
		BIO_printf(outbio,
			   "Error writing private key data in PEM format");
	}

	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(outbio, &bptr);

	printf("buffer :\n %s", bptr->data);
	result = fdo_blob_write((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA,
				(const uint8_t *)bptr->data, bptr->length);
	TEST_ASSERT_NOT_EQUAL(-1, result);

#else // save in bin format

#ifdef USE_OPENSSL
	BIGNUM *privkey_bn = NULL;
	if (!EVP_PKEY_get_bn_param((const EVP_PKEY *)avalidkey,
				   OSSL_PKEY_PARAM_PRIV_KEY, &privkey_bn)) {
		LOG(LOG_ERROR, "Failed to get private key bn\n");
		result = -1;
	}
	if (BN_bn2bin(privkey_bn, privatekey))
		result = 0;
#endif
#ifdef USE_MBEDTLS
	result = mbedtls_mpi_write_binary(&ctx_sign.d, privatekey,
					  privatekey_buflen);
#endif

	TEST_ASSERT_EQUAL(0, result);

	/*TODO:When Protocol uses ECDSA private key:
	 * Read Protocol Private key in a buffer before overwrite
	 * and after test case completion, write it again to the
	 * file/partition
	 * using blob read/write, so we don't lose it*/
	// Writing Privatekey to a file
	result = fdo_blob_write((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA,
				privatekey, privatekey_buflen);
	TEST_ASSERT_NOT_EQUAL(-1, result);

#endif // save privkey in pem/bin format

	// Signature will be received as a part of sigtestdata.
	result = crypto_hal_ecdsa_sign(testdata->bytes, testdata->byte_sz,
				       sigtestdata, &siglen);
	TEST_ASSERT_EQUAL(0, result);

#ifdef USE_OPENSSL
	if (!(mdctx = EVP_MD_CTX_create())) {
		LOG(LOG_ERROR, "Msg Digest init failed \n");
		result = -1;
	}
#if defined(ECDSA256_DA)
	if (1 !=
	    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, avalidkey)) {
		LOG(LOG_ERROR, "EVP verify init failed \n");
		result = -1;
	}
#elif defined(ECDSA384_DA)
	if (1 !=
	    EVP_DigestVerifyInit(mdctx, NULL, EVP_sha384(), NULL, avalidkey)) {
		LOG(LOG_ERROR, "EVP verify init failed \n");
		result = -1;
	}
#endif

	if (1 !=
	    EVP_DigestVerifyUpdate(mdctx, testdata->bytes, testdata->byte_sz)) {
		LOG(LOG_ERROR, "EVP verify update failed \n");
		result = -1;
	}
	TEST_ASSERT_EQUAL(0, result);

	sig_r = fdo_alloc(siglen / 2);
	TEST_ASSERT_NOT_NULL(sig_r);
	memcpy_s(sig_r, siglen / 2, sigtestdata, siglen / 2);
	sig_s = fdo_alloc(siglen / 2);
	TEST_ASSERT_NOT_NULL(sig_s);
	memcpy_s(sig_s, siglen / 2, sigtestdata + siglen / 2, siglen / 2);
	r = BN_bin2bn((const unsigned char *)sig_r, siglen / 2, NULL);
	TEST_ASSERT_NOT_NULL(r);
	s = BN_bin2bn((const unsigned char *)sig_s, siglen / 2, NULL);
	TEST_ASSERT_NOT_NULL(s);

	sig = ECDSA_SIG_new();
	TEST_ASSERT_NOT_NULL(sig);
	if (1 != ECDSA_SIG_set0(sig, r, s)) {
		LOG(LOG_ERROR, "ECDSA Sig set failed\n");
		BN_free(r);
		BN_free(s);
		result = -1;
	}
	TEST_ASSERT_EQUAL(0, result);

	der_sig_len = i2d_ECDSA_SIG(sig, NULL);
	if (!der_sig_len) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		result = -1;
	}

	der_sig_len = i2d_ECDSA_SIG(sig, &der_sig);
	if (!der_sig_len || !der_sig) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		result = -1;
	}

	// verify the signature.
	if (1 != EVP_DigestVerifyFinal(mdctx, der_sig, der_sig_len)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		result = -1;
	}

	TEST_ASSERT_EQUAL(0, result);

	// Negative test case
	sigtestdata[4] = 'a';
	memcpy_s(sig_r, siglen / 2, sigtestdata, siglen / 2);
	ECDSA_SIG_free(sig);
	r = BN_bin2bn((const unsigned char *)sig_r, siglen / 2, NULL);
	TEST_ASSERT_NOT_NULL(r);
	s = BN_bin2bn((const unsigned char *)sig_s, siglen / 2, NULL);
	TEST_ASSERT_NOT_NULL(s);
	sig = ECDSA_SIG_new();
	TEST_ASSERT_NOT_NULL(sig);
	if (1 != ECDSA_SIG_set0(sig, r, s)) {
		LOG(LOG_ERROR, "ECDSA Sig set failed\n");
		BN_free(r);
		BN_free(s);
		result = -1;
	}
	TEST_ASSERT_EQUAL(0, result);

	der_sig_len = i2d_ECDSA_SIG(sig, NULL);
	if (!der_sig_len) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		result = -1;
	}

	der_sig_len = i2d_ECDSA_SIG(sig, &der_sig);
	if (!der_sig_len || !der_sig) {
		LOG(LOG_ERROR, "Failure in format conversion of signature \n");
		result = -1;
	}

	// verify the signature.
	if (1 != EVP_DigestVerifyFinal(mdctx, der_sig, der_sig_len)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		result = -1;
	}
	TEST_ASSERT_NOT_EQUAL(0, result);
#endif

#ifdef USE_MBEDTLS
	mbedtls_md_type_t hash_type = MBEDTLS_MD_NONE;
// create the hash of the plaintext
#if defined(ECDSA256_DA)
	hash_type = MBEDTLS_MD_SHA256;
#elif defined(ECDSA384_DA)
	hash_type = MBEDTLS_MD_SHA384;
#endif
	/* Calculate the hash over message and sign that hash */
	result = mbedtls_md(mbedtls_md_info_from_type(hash_type),
			    (const unsigned char *)testdata->bytes,
			    testdata->byte_sz, hash);
	TEST_ASSERT_EQUAL(0, result);

	// verify the signature.
	if ((result = mbedtls_ecdsa_read_signature(&ctx_sign, hash, hash_length,
						   sigtestdata, siglen)) != 0) {
		LOG(LOG_ERROR, "mbedtls_ecdsa_read_signature failed\n");
		result = -1;
	}

	TEST_ASSERT_EQUAL(0, result);

	// Negative test case
	sigtestdata[4] = 'a';
	if ((result = mbedtls_ecdsa_read_signature(&ctx_sign, hash, hash_length,
						   sigtestdata, siglen)) != 0) {
		LOG(LOG_ERROR, "mbedtls_ecdsa_read_signature failed\n");
		result = -1;
	}
	TEST_ASSERT_NOT_EQUAL(0, result);
#endif
	// Negative test case
	result = crypto_hal_ecdsa_sign(NULL, testdata->byte_sz, sigtestdata,
				       &siglen);
	TEST_ASSERT_NOT_EQUAL(0, result);

#ifdef USE_OPENSSL
#if defined(ECDSA_PEM)
	EVP_PKEY_free(privkey);
	BIO_free_all(outbio);
#endif
	if (avalidkey) {
		EVP_PKEY_free(avalidkey);
		avalidkey = NULL;
	}
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&ctx_sign);
#endif
	free(sigtestdata);
	free(privatekey);
	fdo_byte_array_free(testdata);
}
#endif
