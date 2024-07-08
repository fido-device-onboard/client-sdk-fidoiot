/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for crypto abstraction routines of FDO library.
 */

#include "crypto_utils.h"
#include "fdo_crypto.h"
#include "fdo_crypto_hal.h"
#include "unity.h"
#include "storage_al.h"
#include "safe_lib.h"
#include "stdlib.h"
#include "ecdsa_privkey.h"
#include "safe_lib.h"
#include "fdotypes.h"
#include "openssl/core_names.h"
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/ec.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/encoder.h>

#define PLAIN_TEXT_SIZE BUFF_SIZE_1K_BYTES
#define DER_PUBKEY_LEN_MAX 512
#define ECDSA_PK_MAX_LENGTH 200

static uint8_t test_buff1[] = {1, 2, 3, 4, 5, 6, 7, 8};
static uint8_t test_buff2[] = {6, 7, 8, 9, 10, 9, 8, 7};

uint8_t pub_key[] = {
    0x00, 0x00, 0x00, 0x0d, 0xdd, 0xdd, 0xcc, 0xcc, 0x00, 0x00, 0x00, 0x00,
    0xee, 0xee, 0xee, 0x05, 0xb3, 0x6f, 0xff, 0x81, 0xe2, 0x1b, 0x17, 0xeb,
    0x3d, 0x75, 0x3d, 0x61, 0x7e, 0x27, 0xb0, 0xcb, 0xd0, 0x6d, 0x8f, 0x9d,
    0x64, 0xce, 0xe3, 0xce, 0x43, 0x4c, 0x62, 0xfd, 0xb5, 0x80, 0xe0, 0x99,
    0x3a, 0x07, 0x56, 0x80, 0xe0, 0x88, 0x59, 0xa4, 0xfd, 0xb5, 0xb7, 0x9d,
    0xe9, 0x4d, 0xae, 0x9c, 0xee, 0x3d, 0x66, 0x42, 0x82, 0x45, 0x7e, 0x7f,
    0xd8, 0x69, 0x3e, 0xa1, 0x74, 0xf4, 0x59, 0xee, 0xd2, 0x74, 0x2e, 0x9f,
    0x63, 0xc2, 0x51, 0x8e, 0xd5, 0xdb, 0xca, 0x1c, 0x54, 0x74, 0x10, 0x7b,
    0xdc, 0x99, 0xed, 0x42, 0xd5, 0x5b, 0xa7, 0x04, 0x29, 0x66, 0x61, 0x63,
    0xbc, 0xdd, 0x7f, 0xe1, 0x76, 0x5d, 0xc0, 0x6e, 0xe3, 0x14, 0xac, 0x72,
    0x48, 0x12, 0x0a, 0xa6, 0xe8, 0x5b, 0x08, 0x7b, 0xda, 0x3f, 0x51, 0x7d,
    0xde, 0x4c, 0xea, 0xcb, 0x93, 0xa5, 0x6e, 0xcc, 0xe7, 0x8e, 0x10, 0x84,
    0xbd, 0x19, 0x5a, 0x95, 0xe2, 0x0f, 0xca, 0x1c, 0x50, 0x71, 0x94, 0x51,
    0x40, 0x1b, 0xa5, 0xb6, 0x78, 0x87, 0x53, 0xf6, 0x6a, 0x95, 0xca, 0xc6,
    0x8d, 0xcd, 0x36, 0x88, 0x07, 0x28, 0xe8, 0x96, 0xca, 0x78, 0x11, 0x5b,
    0xb8, 0x6a, 0xe7, 0xe5, 0xa6, 0x65, 0x7a, 0x68, 0x15, 0xd7, 0x75, 0xf8,
    0x24, 0x14, 0xcf, 0xd1, 0x0f, 0x6c, 0x56, 0xf5, 0x22, 0xd9, 0xfd, 0xe0,
    0xe2, 0xf4, 0xb3, 0xa1, 0x90, 0x21, 0xa7, 0xe0, 0xe8, 0xb3, 0xc7, 0x25,
    0xbc, 0x07, 0x72, 0x30, 0x5d, 0xee, 0xf5, 0x6a, 0x89, 0x88, 0x46, 0xdd,
    0x89, 0xc2, 0x39, 0x9c, 0x0a, 0x3b, 0x58, 0x96, 0x57, 0xe4, 0xf3, 0x3c,
    0x79, 0x51, 0x69, 0x36, 0x1b, 0xb6, 0xf7, 0x05, 0x5d, 0x0a, 0x88, 0xdb,
    0x1f, 0x3d, 0xea, 0xa2, 0xba, 0x6b, 0xf0, 0xda, 0x8e, 0x25, 0xc6, 0xad,
    0x83, 0x7d, 0x3e, 0x31, 0xee, 0x11, 0x40, 0xa9};

/*** Function Declarations ***/
EVP_PKEY *generateECDSA_key(int curve);
int sha_ECCsign(int curve, uint8_t *msg, uint32_t mlen, uint8_t *out,
		uint32_t *outlen, EVP_PKEY *eckey);
fdo_public_key_t *getFDOpk(int curve, EVP_PKEY *eckey);
void set_up(void);
void tear_down(void);
int32_t __wrap_crypto_hal_set_peer_random(void *context,
					  const uint8_t *peer_rand_value,
					  uint32_t peer_rand_length);
int32_t __wrap_crypto_hal_get_device_random(void *context,
					    uint8_t *dev_rand_value,
					    uint32_t *dev_rand_length);
int __wrap_crypto_init(void);
int __wrap_crypto_close(void);
fdo_byte_array_t *__wrap_fdo_byte_array_alloc(int byte_sz);
void *__wrap_fdo_alloc(size_t bytes);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value);
int __wrap_crypto_hal_sig_verify(
    uint8_t key_encoding, int key_algorithm, const uint8_t *message,
    uint32_t message_length, const uint8_t *message_signature,
    uint32_t signature_length, const uint8_t *key_param1,
    uint32_t key_param1Length, const uint8_t *key_param2,
    uint32_t key_param2Length);
// int __wrap_get_ec_key(void);
int __wrap_ECDSA_size(const EC_KEY *eckey);
int __wrap_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax);
void test_crypto_support_random(void);
void test_crypto_support_Private_key(void);
void test_crypto_support_crypto(void);
void test_crypto_support_fdo_msg_encrypt_valid(void);
void test_crypto_support_fdo_msg_encrypt_invalid_clear_text(void);
void test_crypto_support_fdo_msg_encrypt_invalid_clear_text_length(void);
void test_crypto_support_fdo_msg_encrypt_invalid_cipher_text_length(void);
void test_crypto_support_fdo_msg_encrypt_invalid_iv(void);
void test_crypto_support_fdo_msg_encrypt_invalid_tag(void);
void test_crypto_support_fdo_msg_encrypt_get_cipher_len_valid(void);
void test_crypto_support_fdo_msg_encrypt_get_cipher_len_verify(void);
void test_crypto_support_fdo_msg_decrypt_get_pt_len_valid(void);
void test_crypto_support_fdo_msg_decrypt_get_pt_len_verify(void);
void test_crypto_support_fdo_msg_decrypt_verify(void);
void test_crypto_support_fdo_msg_decrypt_valid(void);
void test_crypto_support_fdo_msg_decrypt_invalid_cipher(void);
void test_crypto_support_fdo_msg_decrypt_invalid_cipher_length(void);
void test_crypto_support_fdo_msg_decrypt_invalid_iv(void);
void test_crypto_support_fdo_msg_decrypt_invalid_tag(void);
void test_crypto_support_fdo_msg_decrypt_invalid_aad(void);
void test_crypto_support_fdo_kex_init(void);
void test_crypto_support_fdo_kex_close(void);
void test_crypto_support_fdo_kex_init_fdo_string_alloc_with_str_fail(void);
void test_crypto_support_fdo_kex_init_fdo_byte_array_alloc_fail(void);
void test_crypto_support_fdo_get_kex_paramB_crypto_hal_get_device_random_fail(
    void);
void test_crypto_support_fdo_get_kex_paramB_fdo_alloc_fail(void);
void test_crypto_support_fdo_get_kex_paramB_memset_s_fail(void);
void test_crypto_support_load_ecdsa_privkey(void);
void test_crypto_support_load_ecdsa_privkey_fdo_blob_size_fail(void);
void test_crypto_support_load_ecdsa_privkey_fdo_alloc_fail(void);
void test_crypto_support_load_ecdsa_privkey_fdo_blob_read_fail(void);
void test_fdo_ov_verify(void);
void test_fdo_ov_verify_invalid_message(void);
void test_fdo_ov_verify_invalid_message_length(void);
void test_fdo_ov_verify_invalid_message_signature(void);
void test_fdo_ov_verify_invalid_signature_len(void);
void test_fdo_ov_verify_invalid_pubkey(void);
void test_fdo_ov_verifyi_invalid_result(void);
void test_fdo_device_sign(void);
void test_fdo_device_sign_invalid_message(void);
void test_fdo_device_sign_invalid_message_len(void);
void testcrypto_hal_hash(void);
void testcrypto_hal_hash_SHA384(void);
void test_fdo_cryptoHASH_invalid_message(void);
void test_fdo_cryptoHASH_invalid_message_len(void);
void test_fdo_cryptoHASH_invalid_hash(void);
void test_fdo_cryptoHASH_invalid_hash_len(void);
void test_fdo_device_ov_hmac(void);
void test_fdo_device_ov_hmac_invalid_OVHdr(void);
void test_fdo_device_ov_hmac_invalid_OVHdr_len(void);
void test_fdo_device_ov_hmac_invalid_hmac(void);
void test_fdo_device_ov_hmac_invalid_hmac_len(void);
void test_crypto_hal_sig_verify_fail_case(void);
void test_get_ec_key_fail_case(void);
void test_ECDSA_size_fail_case(void);
void test_memcpy_s_fail_case(void);
void test_crypto_support_make_hash(void);
void test_crypto_support_make_hmac(void);
void test_crypto_support_make_hmac_chained(void);
int32_t __wrap_fdo_blob_read(char *name, fdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes);
int32_t __wrap_fdo_blob_size(char *name, uint32_t flags);
fdo_string_t *__wrap_fdo_string_alloc_with_str(char *data);
errno_t __wrap_strcmp_s(const char *dest, rsize_t dmax, const char *src,
			int *indicator);
static uint8_t *get_randomiv(void);

/*** Function Definitions ***/

static uint8_t key1[] = "testkey";
static uint8_t key2[] = "keytest";

static uint8_t *get_randomiv(void)
{
	uint8_t *iv = fdo_alloc(AES_IV_LEN * sizeof(char));
	if (!iv)
		return NULL;
	fdo_crypto_random_bytes(iv, AES_IV_LEN);
	return iv;
}

#ifdef USE_OPENSSL
static EVP_PKEY *Private_key(void)
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
#endif

#ifdef USE_MBEDTLS
static int Private_key(mbedtls_ecdsa_context *ctx_sign)
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

#if defined(ECDSA256_DA)
#define ECPARAMS MBEDTLS_ECP_DP_SECP256R1 // gen 256 ec curve
#else
#define ECPARAMS MBEDTLS_ECP_DP_SECP384R1 // gen 384 ec curve
#endif
	mbedtls_ecdsa_init(ctx_sign);
	if ((ret = mbedtls_ecdsa_genkey(ctx_sign, ECPARAMS,
					mbedtls_ctr_drbg_random, &ctr_drbg))) {
		return -1;
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}
#endif

#ifdef USE_OPENSSL
EVP_PKEY *generateECDSA_key(int curve)
{
	(void)curve;
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

// return 0 on success; -1 for failure
int sha_ECCsign(int curve, uint8_t *msg, uint32_t mlen, uint8_t *out,
		uint32_t *outlen, EVP_PKEY *evpKey)
{
	(void)curve;
	unsigned char *der_sig = NULL;
	size_t der_sig_len = 0;
	EVP_MD_CTX *mdctx = NULL;
	int result = -1;
	ECDSA_SIG *sig = NULL;
	unsigned char *sig_r = NULL;
	int sig_r_len = 0;
	unsigned char *sig_s = NULL;
	int sig_s_len = 0;

	// Create the Message Digest Context
	mdctx = EVP_MD_CTX_create();
	if (!mdctx) {
		LOG(LOG_ERROR, "Failed to create message digest context\n");
		goto done;
	}
#if defined(ECDSA256_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, evpKey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto done;
	}
#elif defined(ECDSA384_DA)
	if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, evpKey)) {
		LOG(LOG_ERROR, "EVP sign init failed \n");
		goto done;
	}
#endif
	if (1 != EVP_DigestSignUpdate(mdctx, msg, mlen)) {
		LOG(LOG_ERROR, "EVP sign update failed \n");
		goto done;
	}
	// First call with NULL param to obtain the DER encoded signature length
	if (1 != EVP_DigestSignFinal(mdctx, NULL, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final for size failed \n");
		goto done;
	}
	if (der_sig_len <= 0) {
		LOG(LOG_ERROR,
		    "EVP_DigestSignFinal returned invalid signature length.\n");
		goto done;
	}

	der_sig = fdo_alloc(der_sig_len);
	if (!der_sig) {
		LOG(LOG_ERROR, "Signature alloc Failed\n");
		goto done;
	}
	// second call with actual param to obtain the DEr encoded signature
	if (1 != EVP_DigestSignFinal(mdctx, der_sig, &der_sig_len)) {
		LOG(LOG_ERROR, "EVP sign final failed \n");
		goto done;
	}

	// Decode DER encoded signature to convert to raw format
	sig = ECDSA_SIG_new();
	const unsigned char *sig_input = der_sig;
	if (!sig || d2i_ECDSA_SIG(&sig, &sig_input, der_sig_len) == NULL) {
		LOG(LOG_ERROR, "DER to EC_KEY struct decoding failed!\n");
		goto done;
	}
	TEST_ASSERT_NOT_NULL(sig);

	// both r and s are maintained by sig, no need to free explicitly
	const BIGNUM *r = ECDSA_SIG_get0_r(sig);
	const BIGNUM *s = ECDSA_SIG_get0_s(sig);
	TEST_ASSERT_NOT_NULL(r);
	TEST_ASSERT_NOT_NULL(s);

	sig_r_len = BN_num_bytes(r);
	sig_r = fdo_alloc(sig_r_len);
	TEST_ASSERT_NOT_NULL(sig_r);
	BN_bn2bin(r, sig_r);

	sig_s_len = BN_num_bytes(s);
	sig_s = fdo_alloc(sig_s_len);
	TEST_ASSERT_NOT_NULL(sig_s);
	BN_bn2bin(s, sig_s);

	*outlen = sig_r_len + sig_s_len;
	;
	if (0 != memcpy_s(out, *outlen, (char *)sig_r, (size_t)sig_r_len)) {
		goto done;
	}
	if (0 != memcpy_s(out + sig_r_len, *outlen, (char *)sig_s,
			  (size_t)sig_s_len)) {
		goto done;
	}
	result = 1;

done:
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	if (der_sig) {
		fdo_free(der_sig);
		sig_input = NULL;
	}
	if (mdctx) {
		EVP_MD_CTX_free(mdctx);
		mdctx = NULL;
	}
	if (evpKey) {
		EVP_PKEY_free(evpKey);
		evpKey = NULL;
	}
	return result;
}

fdo_public_key_t *getFDOpk(int curve, EVP_PKEY *evpKey)
{
	(void)curve;
	unsigned char *key_buf = NULL;
	int key_buf_len = 0;
	EC_GROUP *ecgroup = NULL;
	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	int x_len = 0;
	int y_len = 0;
	fdo_public_key_t *pk = NULL;

#if defined(ECDSA256_DA)
	ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
#else
	ecgroup = EC_GROUP_new_by_curve_name(NID_secp384r1);
#endif
	TEST_ASSERT_NOT_NULL_MESSAGE(ecgroup, "Failed to get ECGROUP\n");

	const EC_POINT *pub = EC_POINT_new(ecgroup);
	TEST_ASSERT_NOT_NULL_MESSAGE(pub, "Failed to get ECPOINT\n");
	/* Get the public key co-ordinates in x and y*/
	if (EVP_PKEY_get_bn_param(evpKey, OSSL_PKEY_PARAM_EC_PUB_X, &x) &&
	    EVP_PKEY_get_bn_param(evpKey, OSSL_PKEY_PARAM_EC_PUB_Y, &y)) {
		x_len = BN_num_bytes(x);
		y_len = BN_num_bytes(y);
		key_buf_len = x_len + y_len;
		key_buf = fdo_alloc(key_buf_len);
		TEST_ASSERT_NOT_NULL(key_buf);
		BN_bn2bin(x, key_buf);
		BN_bn2bin(y, key_buf + x_len);

#if defined(ECDSA256_DA)
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
					  FDO_CRYPTO_PUB_KEY_ENCODING_X509,
					  key_buf_len, key_buf);
#else
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
					  FDO_CRYPTO_PUB_KEY_ENCODING_X509,
					  key_buf_len, key_buf);
#endif
	}

	if (!pk || !pk->key1) {
		return NULL;
	}

	pk->key2 = NULL;
	TEST_ASSERT_NOT_NULL(pk);

	if (ecgroup) {
		EC_GROUP_free(ecgroup);
	}
	if (x) {
		BN_free(x);
	}
	if (y) {
		BN_free(y);
	}
	if (evpKey) {
		EVP_PKEY_free(evpKey);
		evpKey = NULL;
	}
	return pk;
}
#endif // USE_OPENSSL

#ifdef USE_MBEDTLS
#if defined(PK_ENC_ECDSA)
#define EC256PARAMS MBEDTLS_ECP_DP_SECP256R1
#define EC384PARAMS MBEDTLS_ECP_DP_SECP384R1

static int generateECDSA_key(int curve, mbedtls_ecdsa_context *ctx_sign)
{
	int ret = -1;
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
					 &entropy, (const uint8_t *)pers,
					 pers_len)) != 0) {
		goto error;
	}

	mbedtls_ecdsa_init(ctx_sign);
#if defined(ECDSA256_DA)
	if ((ret = mbedtls_ecdsa_genkey(ctx_sign, EC256PARAMS,
					mbedtls_ctr_drbg_random, &ctr_drbg)))
		goto error;
#else
	if ((ret = mbedtls_ecdsa_genkey(ctx_sign, EC384PARAMS,
					mbedtls_ctr_drbg_random, &ctr_drbg)))
		goto error;
#endif
	ret = 0;
error:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}

int sha_ECCsign(int curve, uint8_t *msg, uint32_t mlen, uint8_t *out,
		uint32_t *outlen, mbedtls_ecdsa_context *ctx_sign)
{
	int ret = 0;
	mbedtls_ctr_drbg_context ctr_drbg;
	uint8_t hash[SHA512_DIGEST_SIZE];
	size_t hash_length = 0;
	uint8_t sig[MBEDTLS_MPI_MAX_SIZE];
	size_t sig_len = 0;
	mbedtls_md_type_t mbedhash_type = MBEDTLS_MD_NONE;

	if (NULL == msg || !mlen || NULL == out || !outlen || NULL == ctx_sign)
		return -1;

	mbedtls_ctr_drbg_init(&ctr_drbg);
#if defined(ECDSA256_DA)
	mbedhash_type = MBEDTLS_MD_SHA256;
	hash_length = SHA256_DIGEST_SIZE;
#else
	mbedhash_type = MBEDTLS_MD_SHA384;
	hash_length = SHA384_DIGEST_SIZE;
#endif

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(mbedhash_type), msg,
			      mlen, hash)) != 0)
		return 0;
	if ((ret = mbedtls_ecdsa_write_signature(
		 ctx_sign, mbedhash_type, hash, hash_length, sig, &sig_len,
		 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		LOG(LOG_ERROR, "signature creation failed ret:%d\n", ret);
		return 0;
	}

	*outlen = sig_len;
	if (memcpy_s(out, (size_t)sig_len, sig, (size_t)sig_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	return 1;
}

fdo_public_key_t *getFDOpk(int curve, mbedtls_ecdsa_context *ctx_sign)
{
	/* convert mbedtls struct to FDO struct   */
	uint8_t buf[ECDSA_PK_MAX_LENGTH];
	size_t buflen = 0;
	int ret = 0;
	fdo_public_key_t *pk = NULL;

	if (!ctx_sign)
		return NULL;

	ret = mbedtls_ecp_point_write_binary(&ctx_sign->grp, &ctx_sign->Q,
					     MBEDTLS_ECP_PF_UNCOMPRESSED,
					     &buflen, buf, sizeof(buf));
	if (ret) {
		printf("mbedtls_ecp_point_write_binary returned: %d\n", ret);
		return (NULL);
	}

#if defined(ECDSA256_DA)
	pk =
	    fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
				 FDO_CRYPTO_PUB_KEY_ENCODING_X509, buflen, buf);
#else
	pk =
	    fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
				 FDO_CRYPTO_PUB_KEY_ENCODING_X509, buflen, buf);
#endif
	if (!pk || !pk->key1) {
		return NULL;
	}

	pk->key2 = NULL;

	return pk;
}
#endif // PK_ENC_ECDSA
#endif // USE_MBEDTLS

#define SHA256_DIGEST_SZ SHA256_DIGEST_SIZE
#define SHA384_DIGEST_SZ SHA384_DIGEST_SIZE
#define TEST_BUFF_SZ BUFF_SIZE_8_BYTES // random buffer
#define TEST_KEY_SZ BUFF_SIZE_8_BYTES

/*** Unity functions. ***/
/**
 * set_up function is called at the beginning of each test-case in unity
 * framework. Declare, Initialize all mandatory variables needed at the start
 * to execute the test-case.
 * @return none.
 */
void set_up(void)
{
}

void tear_down(void)
{
}

bool crypto_init_fail_case = false;
bool crypto_close_fail_case = false;
bool fdo_string_alloc_with_str_fail_case = false;
bool fdo_byte_array_alloc_fail_case = false;
bool g_malloc_fail = false;
bool strcmp_s_fail_case = false;
bool crypto_hal_get_device_random_fail_case = false;
bool g_memset_fail = false;
bool crypto_hal_set_peer_random_fail_case = false;
bool fdo_blob_read_fail_case = false;
bool fdo_blob_size_fail_case = false;
bool crypto_hal_sig_verify_fail_flag = false;
bool get_ec_key_fail_flag = false;
bool ECDSA_size_fail_flag = false;
bool memcpy_s_fail_flag = false;

int32_t __real_fdo_blob_read(char *name, fdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes);
int32_t __wrap_fdo_blob_read(char *name, fdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes)
{
	if (fdo_blob_read_fail_case) {
		return -1;
	} else {
		return __real_fdo_blob_read(name, flags, buf, n_bytes);
	}
}

int32_t __real_fdo_blob_size(char *name, uint32_t flags);
int32_t __wrap_fdo_blob_size(char *name, uint32_t flags)
{
	if (fdo_blob_size_fail_case) {
		return -1;
	} else {
		return __real_fdo_blob_size(name, flags);
	}
}

int32_t __real_crypto_hal_set_peer_random(void *context,
					  const uint8_t *peer_rand_value,
					  uint32_t peer_rand_length);
int32_t __wrap_crypto_hal_set_peer_random(void *context,
					  const uint8_t *peer_rand_value,
					  uint32_t peer_rand_length)
{
	if (crypto_hal_set_peer_random_fail_case) {
		return -1;
	} else {
		return __real_crypto_hal_set_peer_random(
		    context, peer_rand_value, peer_rand_length);
	}
}

int32_t __real_crypto_hal_get_device_random(void *context,
					    uint8_t *dev_rand_value,
					    uint32_t *dev_rand_length);
int32_t __wrap_crypto_hal_get_device_random(void *context,
					    uint8_t *dev_rand_value,
					    uint32_t *dev_rand_length)
{
	if (crypto_hal_get_device_random_fail_case) {
		return -1;
	} else {
		return __real_crypto_hal_get_device_random(
		    context, dev_rand_value, dev_rand_length);
	}
}

int __real_crypto_init(void);
int __wrap_crypto_init(void)
{
	if (crypto_init_fail_case) {
		return -1;
	} else {
		return __real_crypto_init();
	}
}

int __real_crypto_close(void);
int __wrap_crypto_close(void)
{
	if (crypto_close_fail_case) {
		return -1;
	} else {
		return __real_crypto_close();
	}
}

fdo_string_t *__real_fdo_string_alloc_with_str(char *data);
fdo_string_t *__wrap_fdo_string_alloc_with_str(char *data)
{
	if (fdo_string_alloc_with_str_fail_case) {
		return NULL;
	} else {
		return __real_fdo_string_alloc_with_str(data);
	}
}

fdo_byte_array_t *__real_fdo_byte_array_alloc(int byte_sz);
fdo_byte_array_t *__wrap_fdo_byte_array_alloc(int byte_sz)
{
	if (fdo_byte_array_alloc_fail_case) {
		return NULL;
	} else {
		return __real_fdo_byte_array_alloc(byte_sz);
	}
}

void *__real_fdo_alloc(size_t bytes);
void *__wrap_fdo_alloc(size_t bytes)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_fdo_alloc(bytes);
}

errno_t __real_strcmp_s(const char *dest, rsize_t dmax, const char *src,
			int *indicator);
errno_t __wrap_strcmp_s(const char *dest, rsize_t dmax, const char *src,
			int *indicator)
{
	if (strcmp_s_fail_case)
		return -1;
	else
		return __real_strcmp_s(dest, dmax, src, indicator);
}

errno_t __real_memset_s(void *dest, rsize_t len, uint8_t value);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value)
{
	if (g_memset_fail)
		return FDO_ERROR;
	else
		return __real_memset_s(dest, len, value);
}

int __real_crypto_hal_sig_verify(
    uint8_t key_encoding, int key_algorithm, const uint8_t *message,
    uint32_t message_length, const uint8_t *message_signature,
    uint32_t signature_length, const uint8_t *key_param1,
    uint32_t key_param1Length, const uint8_t *key_param2,
    uint32_t key_param2Length);
int __wrap_crypto_hal_sig_verify(
    uint8_t key_encoding, int key_algorithm, const uint8_t *message,
    uint32_t message_length, const uint8_t *message_signature,
    uint32_t signature_length, const uint8_t *key_param1,
    uint32_t key_param1Length, const uint8_t *key_param2,
    uint32_t key_param2Length)
{
	if (crypto_hal_sig_verify_fail_flag) {
		return -1;
	} else {
		return __real_crypto_hal_sig_verify(
		    key_encoding, key_algorithm, message, message_length,
		    message_signature, signature_length, key_param1,
		    key_param1Length, key_param2, key_param2Length);
	}
}

#ifdef USE_OPENSSL
// int __real_get_ec_key(void);
// int __wrap_get_ec_key(void)
// {
// 	if (get_ec_key_fail_flag) {
// 		return 0;
// 	} else {
// 		return __real_get_ec_key();
// 	}
// }

int __real_ECDSA_size(const EC_KEY *eckey);
int __wrap_ECDSA_size(const EC_KEY *eckey)
{
	if (ECDSA_size_fail_flag) {
		return -1;
	} else {
		return __real_ECDSA_size(eckey);
	}
}
#endif

int __real_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax);
int __wrap_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax)
{
	if (memcpy_s_fail_flag) {
		return -1;
	} else {
		return __real_memcpy_s(dest, dmax, src, smax);
	}
}

/*** Test functions. ***/

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_random(void)
#else
TEST_CASE("crypto_support_random", "[crypto_support][fdo]")
#endif
{
#ifdef TARGET_OS_FREERTOS
	extern bool simulcrypto_hal_random_bytes;
	simulcrypto_hal_random_bytes = true;
#endif

	int ret;
	uint8_t random_data[TEST_BUFF_SZ] = {0};

	fdo_crypto_close();
	/* These functions should fail if random_init isn't called first. */
	ret = fdo_crypto_random_bytes(random_data, TEST_BUFF_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	ret = random_close();
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Start. */
	ret = random_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Valid input. */
	ret = fdo_crypto_random_bytes(random_data, TEST_BUFF_SZ);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Invalid input. */
	ret = fdo_crypto_random_bytes(NULL, TEST_BUFF_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/*  End. */
	ret = random_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
#ifdef TARGET_OS_FREERTOS
	simulcrypto_hal_random_bytes = false;
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_Private_key(void)
#else
TEST_CASE("crypto_support_Private_key", "[crypto_support][fdo]")
#endif
{
	// TEST_IGNORE();
	int ret = -1;
	int privatekey_buflen = 0;
#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	size_t hash_length = SHA256_DIGEST_SIZE;
#else
	size_t hash_length = SHA384_DIGEST_SIZE;
#endif

	EVP_PKEY *validkey = Private_key();
	TEST_ASSERT_NOT_NULL(validkey);
	privatekey_buflen = hash_length;
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_context ctx_sign = {0};
	ret = Private_key(&ctx_sign);
	TEST_ASSERT_EQUAL(0, ret);
	privatekey_buflen = mbedtls_mpi_size(&ctx_sign.d);
#endif
	uint8_t *privatekey = fdo_alloc(privatekey_buflen);
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
	EVP_PKEY_CTX *ctx;

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

	if (!PEM_write_bio_Parameters(outbio, privkey)) {
		BIO_printf(outbio, "Error writing parameters in PEM format");
	}

	if(PEM_write_bio_PrivateKey(outbio, privkey, NULL, NULL, 0, 0, NULL) == 0) {
		BIO_printf(outbio, "Error writing private key data in PEM format");
	}

	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(outbio, &bptr);

	ret = fdo_blob_write((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA,
			     (const uint8_t *)bptr->data, bptr->length);
	TEST_ASSERT_NOT_EQUAL(-1, ret);

#else

#ifdef USE_OPENSSL
	BIGNUM *privkey_bn = NULL;
	if (!EVP_PKEY_get_bn_param((const EVP_PKEY *)validkey,
				   OSSL_PKEY_PARAM_PRIV_KEY, &privkey_bn)) {
		LOG(LOG_ERROR, "Failed to get private key bn\n");
		ret = -1;
	}

	if (BN_bn2bin(privkey_bn, privatekey))
		ret = 0;
#endif
#ifdef USE_MBEDTLS
	ret = mbedtls_mpi_write_binary(&ctx_sign.d, privatekey,
				       privatekey_buflen);
#endif
	TEST_ASSERT_EQUAL(0, ret);

	// Writing Privatekey to a file
	ret = fdo_blob_write((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA,
			     privatekey, privatekey_buflen);
	TEST_ASSERT_NOT_EQUAL(-1, ret);
#endif

#ifdef USE_OPENSSL
#if defined(ECDSA_PEM)
	EVP_PKEY_free(privkey);
	EVP_PKEY_CTX_free(ctx);
	BIO_free_all(outbio);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(param_bld);
	BN_free(priv);
#endif
	if (validkey)
		EVP_PKEY_free(validkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&ctx_sign);
#endif
	fdo_free(privatekey);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_crypto(void)
#else
TEST_CASE("crypto_support_crypto", "[crypto_support][fdo]")
#endif
{
	int ret;

/*TODO: Adapt when fdosdk_close is implemented*/
#if 0
	/* fdo_crypto_close should fail if fdo_crypto_init isn't called first. */
    ret = fdo_crypto_close();
    TEST_ASSERT_NOT_EQUAL(0, ret);
#endif
	/* Start. */
	ret = fdo_crypto_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* End. */
	ret = fdo_crypto_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_valid(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_valid", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = random_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_invalid_clear_text(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_invalid_clear_text",
	  "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(NULL, clear_length, cipher, &cipher_length, iv1,
			      tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_invalid_clear_text_length(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_invalid_clear_text_length",
	  "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, 0, cipher, &cipher_length, iv1, tag,
			      AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_invalid_cipher_text_length(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_invalid_cipher_text_length",
	  "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, NULL, iv1, tag,
			      AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_invalid_iv(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_invalid_iv", "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = NULL;
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_invalid_tag(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_invalid_tag", "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_get_cipher_len_valid(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_get_cipher_len_valid",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_encrypt_get_cipher_len_verify(void)
#else
TEST_CASE("crypto_support_fdo_msg_encrypt_get_cipher_len_verify",
	  "[crypto_support][fdo]")
#endif
{
	int ret;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint32_t *Length = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	Length = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(Length);
	if (Length)
		fdo_free(Length);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_get_pt_len_valid(void)
#else
TEST_CASE("test_crypto_support_fdo_msg_decrypt_get_pt_len_valid",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_get_pt_len_verify(void)
#else
TEST_CASE("test_crypto_support_fdo_msg_decrypt_get_pt_len_verify",
	  "[crypto_support][fdo]")
#endif
{
	int ret;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	int *dptr = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	dptr = (int *)fdo_alloc(sizeof(char) * decrypthed_length);
	TEST_ASSERT_NOT_NULL(dptr);
	if (dptr)
		fdo_free(dptr);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_verify(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_verify", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = sizeof(test_buff1);
	int result_memcmp = 0;
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = memcmp_s(test_buff1, clear_length, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_valid(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_valid", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_invalid_cipher(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_invalid_cipher",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, NULL,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_invalid_cipher_length(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_invalid_cipher_length",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher, 0, iv1,
			      tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_invalid_iv(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_invalid_iv", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = NULL;
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_invalid_tag(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_invalid_tag", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	memset_s(tag, AES_TAG_LEN, 0);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_msg_decrypt_invalid_aad(void)
#else
TEST_CASE("crypto_support_fdo_msg_decrypt_invalid_aad", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();
	uint8_t *tag = NULL;
	uint8_t *aad = NULL;

	ret = fdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = fdo_alloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = fdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = fdo_alloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	// set different aad value
	memset_s(aad, 16, 1);

	ret = fdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1, tag, AES_TAG_LEN, aad, 16);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	if (cipher) {
		fdo_free(cipher);
	}
	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (tag) {
		fdo_free(tag);
	}
	if (aad) {
		fdo_free(aad);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_kex_init(void)
#else
TEST_CASE("crypto_support_fdo_kex_init", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_kex_close(void)
#else
TEST_CASE("crypto_support_fdo_kex_close", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_kex_init_fdo_string_alloc_with_str_fail(void)
#else
TEST_CASE("crypto_support_fdo_kex_init_fdo_string_alloc_with_str_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	fdo_string_alloc_with_str_fail_case = true;
	ret = fdo_kex_init();
	fdo_string_alloc_with_str_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	fdo_kex_close();
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_kex_init_fdo_byte_array_alloc_fail(void)
#else
TEST_CASE("crypto_support_fdo_kex_init_fdo_byte_array_alloc_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret = 0;
	fdo_byte_array_alloc_fail_case = true;
	ret = fdo_kex_init();
	fdo_byte_array_alloc_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	fdo_kex_close();
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_get_kex_paramB_crypto_hal_get_device_random_fail(
    void)
#else
TEST_CASE("crypto_support_fdo_get_kex_paramB_crypto_hal_get_device_random_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret;
	fdo_byte_array_t *xB = NULL;
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	crypto_hal_get_device_random_fail_case = true;
	ret = fdo_get_kex_paramB(&xB);
	crypto_hal_get_device_random_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_get_kex_paramB_fdo_alloc_fail(void)
#else
TEST_CASE("crypto_support_fdo_get_kex_paramB_fdo_alloc_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret;
	fdo_byte_array_t *xB = NULL;
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	g_malloc_fail = true;
	ret = fdo_get_kex_paramB(&xB);
	g_malloc_fail = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_fdo_get_kex_paramB_memset_s_fail(void)
#else
TEST_CASE("crypto_support_fdo_get_kex_paramB_memset_s_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret;
	fdo_byte_array_t *xB = NULL;
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	g_memset_fail = true;
	ret = fdo_get_kex_paramB(&xB);
	g_memset_fail = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey", "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	TEST_ASSERT_EQUAL_INT(0, ret);
	if (privkey) {
		fdo_free(privkey);
		privkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_fdo_blob_size_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_fdo_blob_size_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	fdo_blob_size_fail_case = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	fdo_blob_size_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	if (privkey) {
		fdo_free(privkey);
		privkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_fdo_alloc_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_fdo_alloc_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	g_malloc_fail = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	g_malloc_fail = false;
	if (privkey) {
		fdo_free(privkey);
		privkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_fdo_blob_read_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_fdo_blob_read_fail",
	  "[crypto_support][fdo]")
#endif
{
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	fdo_blob_read_fail_case = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	fdo_blob_read_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	if (privkey) {
		fdo_free(privkey);
		privkey = NULL;
	}
}

/* Test cases for fdo_ov_verify
 * message of length message_length is signed using ECDSA.
 * Same message is signed with puukey
 * fdo_ov_verify will check is both signature are same or not
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify(void)
#else
TEST_CASE("fdo_ov_verify", "[crypto_support][fdo]")
#endif
{
	// TO-DO: Update test case for X509-encoded public key types.
	TEST_IGNORE();
	int ret;
	uint8_t test_buff[] = {1, 2, 3, 4, 5};
	uint8_t *message = test_buff;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Positive test case
	 * verifying signature done by either ECDSA
	   with signature done by pubkey passes as parameter
	 */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = fdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(0, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing NULL as message to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify_invalid_message(void)
#else
TEST_CASE("fdo_ov_verify_invalid_message", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Negative test case */
	ret = fdo_ov_verify(NULL, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing 0 as message_length to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify_invalid_message_length(void)
#else
TEST_CASE("fdo_ov_verify_invalid_message_length", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Negative test case */
	ret = fdo_ov_verify(message, 0, message_signature, signature_len,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing NULL as message_signature to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify_invalid_message_signature(void)
#else
TEST_CASE("fdo_ov_verify_invalid_message_signature", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Negative test case */
	ret = fdo_ov_verify(message, message_length, NULL, signature_len,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing 0 as Signature_len to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify_invalid_signature_len(void)
#else
TEST_CASE("fdo_ov_verify_invalid_signature_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Negative test case */
	ret = fdo_ov_verify(message, message_length, message_signature, 0,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing NULL as pubkey to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verify_invalid_pubkey(void)
#else
TEST_CASE("fdo_ov_verify_invalid_pubkey", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* Negative test case */
	ret = fdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);

	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * passing NULL as result to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_fdo_ov_verifyi_invalid_result(void)
#else
TEST_CASE("fdo_ov_verify_invalid_result", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool *result = NULL;
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	// Negative test case
	ret = fdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
}

/* Test cases fot Device_sign */
#ifndef TARGET_OS_FREERTOS
void test_fdo_device_sign(void)
#else
TEST_CASE("fdo_device_sign", "[crypto_support][fdo]")
#endif
{
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	fdo_byte_array_t *signature = NULL;

	// Positive test case
	ret = fdo_device_sign(message, message_len, &signature, NULL);
	TEST_ASSERT_EQUAL(0, ret);
	if (signature) {
		fdo_byte_array_free(signature);
		signature = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_sign_invalid_message(void)
#else
TEST_CASE("fdo_device_sign_invalid_message", "[crypto_support][fdo]")
#endif
{
	int ret;
	size_t message_len = sizeof(test_buff1);
	fdo_byte_array_t *signature = NULL;

	/* Negative test case */
	ret = fdo_device_sign(NULL, message_len, &signature, NULL);
	TEST_ASSERT_EQUAL(-1, ret);
	if (signature) {
		fdo_byte_array_free(signature);
		signature = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_sign_invalid_message_len(void)
#else
TEST_CASE("fdo_device_sign_invalid_message_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	const uint8_t *message = test_buff1;
	fdo_byte_array_t *signature = NULL;

	/* Negative test case */
	ret = fdo_device_sign(message, 0, &signature, NULL);
	TEST_ASSERT_EQUAL(-1, ret);
	if (signature) {
		fdo_byte_array_free(signature);
		signature = NULL;
	}
}

/* Test cases for fdo_crypto_hash */
#ifndef TARGET_OS_FREERTOS
void testcrypto_hal_hash(void)
#else
TEST_CASE("fdo_crypto_hash", "[crypto_support][fdo]")
#endif
{
#if defined(ECDSA384_DA)
	TEST_IGNORE();
#endif
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);
	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Positive test case */
	ret = fdo_crypto_hash(message, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	fdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void testcrypto_hal_hash_SHA384(void)
#else
TEST_CASE("fdo_crypto_hash_SHA384", "[crypto_support][fdo]")
#endif
{
#if defined(ECDSA256_DA)
	TEST_IGNORE();
#endif
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_384, SHA384_DIGEST_SIZE);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Positive test case */
	ret = fdo_crypto_hash(message, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	fdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoHASH_invalid_message(void)
#else
TEST_CASE("fdo_cryptoHASH_invalid_message", "[crypto_support][fdo]")
#endif
{
	int ret;
	size_t message_len = TEST_BUFF_SZ;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = fdo_crypto_hash(NULL, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoHASH_invalid_message_len(void)
#else
TEST_CASE("fdo_cryptoHASH_invalid_message_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = fdo_crypto_hash(message, 0, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoHASH_invalid_hash(void)
#else
TEST_CASE("fdo_cryptoHASH_invalid_hash", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = fdo_crypto_hash(message, message_len, NULL, hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_cryptoHASH_invalid_hash_len(void)
#else
TEST_CASE("fdo_cryptoHASH_invalid_hash_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation of hashes
	TEST_ASSERT_NOT_NULL(hash1);

	// Negative test case
	ret = fdo_crypto_hash(message, message_len, hash1->hash->bytes, 0);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hash1);
}

/* Test cases for fdo_device_ov_hmac */
#ifndef TARGET_OS_FREERTOS
void test_fdo_device_ov_hmac(void)
#else
TEST_CASE("fdo_device_ov_hmac", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	fdo_byte_array_t *OVkey = fdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);

#if defined(ECDSA384_DA)
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_384, SHA384_DIGEST_SZ);
#else
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
#endif
	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Positive test case */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = fdo_device_ov_hmac(OVHdr, OVHdr_len, hmac, hmac_len, false);
	TEST_ASSERT_EQUAL(0, ret);

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
	fdo_hash_free(hmac1);
	if (OVkey) {
		fdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_ov_hmac_invalid_OVHdr(void)
#else
TEST_CASE("fdo_device_ov_hmac_invalid_OVHdr", "[crypto_support][fdo]")
#endif
{
	int ret;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	fdo_byte_array_t *OVkey = fdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = fdo_device_ov_hmac(NULL, OVHdr_len, hmac, hmac_len, false);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hmac1);
	if (OVkey) {
		fdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_ov_hmac_invalid_OVHdr_len(void)
#else
TEST_CASE("fdo_device_ov_hmac_invalid_OVHdr_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	fdo_byte_array_t *OVkey = fdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = fdo_device_ov_hmac(OVHdr, 0, hmac, hmac_len, false);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hmac1);
	if (OVkey) {
		fdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_ov_hmac_invalid_hmac(void)
#else
TEST_CASE("fdo_device_ov_hmac_invalid_hmac", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	fdo_byte_array_t *OVkey = fdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = fdo_device_ov_hmac(OVHdr, OVHdr_len, NULL, hmac_len, false);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hmac1);
	if (OVkey) {
		fdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_device_ov_hmac_invalid_hmac_len(void)
#else
TEST_CASE("fdo_device_ov_hmac_invalid_hmac_len", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	fdo_byte_array_t *OVkey = fdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = fdo_device_ov_hmac(OVHdr, OVHdr_len, hmac, 0, false);
	TEST_ASSERT_EQUAL(-1, ret);

	fdo_hash_free(hmac1);
	if (OVkey) {
		fdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

/* Test cases for fdo_ov_verify invalid message
 * message of length message_length is signed using ECDSA.
 * wraper flag is set to true, to fail internal API
 */
#ifndef TARGET_OS_FREERTOS
void test_crypto_hal_sig_verify_fail_case(void)
#else
TEST_CASE("crypto_hal_sig_verify_fail_case", "[crypto_support][fdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	int curve = 0;
	uint8_t *message_signature = fdo_alloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);
	fdo_public_key_t *pubkey = NULL;

#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EVP_PKEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif

#ifdef USE_MBEDTLS
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	mbedtls_ecdsa_context validkey;
	ret = generateECDSA_key(curve, &validkey);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	pubkey = getFDOpk(curve, &validkey);
	TEST_ASSERT_NOT_NULL(pubkey);

	/* convert ecdsa_context to pk_context */
	mbedtls_pk_context pk_ctx;
	pk_ctx.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

	ret = mbedtls_pk_setup(&pk_ctx,
			       mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
	TEST_ASSERT_EQUAL(0, ret);

	mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q), &(validkey.Q));
	mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d), &(validkey.d));
	mbedtls_pk_ec(pk_ctx)->grp = validkey.grp;

	unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *p_temp = temp;

	key_buf_len =
	    mbedtls_pk_write_pubkey_der(&pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

	/* fail if writing pubkey to der failed */
	if (key_buf_len <= 0)
		TEST_ASSERT_EQUAL(0, 1);

	/* mbedtls_pk_write_pubkey_der writes data at the end of the buffer! */
	ret = memcpy_s((uint8_t *)key_buf, key_buf_len,
		       (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX - key_buf_len)),
		       key_buf_len);
	TEST_ASSERT_EQUAL(0, ret);
	pubkey->key1->bytes = (uint8_t *)key_buf;
	pubkey->key1->byte_sz = (size_t)key_buf_len;
#endif

	/* if flag is true, fdo_ov_verify will fail due to wraper */
	crypto_hal_sig_verify_fail_flag = true;
	ret = fdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
	if (pubkey)
		fdo_public_key_free(pubkey);
	if (validkey)
		EVP_PKEY_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&validkey);
#endif

	if (message_signature) {
		fdo_free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
	crypto_hal_sig_verify_fail_flag = false;
}

#ifndef TARGET_OS_FREERTOS
void test_get_ec_key_fail_case(void)
#else
TEST_CASE("get_ec_key_fail_case", "[crypto_support][fdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	fdo_byte_array_t *signature = NULL;

	get_ec_key_fail_flag = true;
	ret = fdo_device_sign(message, message_len, &signature, NULL);
	TEST_ASSERT_EQUAL(-1, ret);

	get_ec_key_fail_flag = false;
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ECDSA_size_fail_case(void)
#else
TEST_CASE("ECDSA_size_fail_case", "[crypto_support][fdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	fdo_byte_array_t *signature = NULL;

	ECDSA_size_fail_flag = true;
	ret = fdo_device_sign(message, message_len, &signature, NULL);
	TEST_ASSERT_EQUAL(-1, ret);

	ECDSA_size_fail_flag = false;
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_memcpy_s_fail_case(void)
#else
TEST_CASE("memcpy_s_fail_case", "[crypto_support][fdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	fdo_byte_array_t *signature = NULL;

	memcpy_s_fail_flag = true;
	ret = fdo_device_sign(message, message_len, &signature, NULL);
	memcpy_s_fail_flag = false;
	TEST_ASSERT_EQUAL(-1, ret);
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hash(void)
#else
TEST_CASE("crypto_support_make_hash", "[crypto_support][fdo]")
#endif
{
	int ret;
	int i;
	bool flag = true;
	fdo_hash_t *hash1 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);
	fdo_hash_t *hash2 =
	    fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_USED, FDO_SHA_DIGEST_SIZE_USED);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);
	TEST_ASSERT_NOT_NULL(hash2);

	/* Negative case - null buffer. */
	ret = fdo_crypto_hash(NULL, TEST_BUFF_SZ, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - invalid  hash output buffer size*/
	ret = fdo_crypto_hash(test_buff1, 0, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - invalid  hash output buffer */
	ret = fdo_crypto_hash(test_buff1, TEST_BUFF_SZ, NULL,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - zero hash buffer size. */
	ret = fdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash1->hash->bytes, 0);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Positive case. */
	ret = fdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	/* Using the same buffer, we expect the same result. */
	ret = fdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash2->hash->bytes,
			      hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hash1->hash_type, hash2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hash1->hash->byte_sz, hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash1->hash->bytes, hash2->hash->bytes,
				      hash1->hash->byte_sz);

	/* Using a different buffer, we expect a different result. */
	ret = fdo_crypto_hash(test_buff2, TEST_BUFF_SZ, hash2->hash->bytes,
			      hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hash1->hash_type, hash2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hash1->hash->byte_sz, hash2->hash->byte_sz);

	flag = true;
	for (i = 0; (uint8_t)i < hash1->hash->byte_sz; i++) {
		flag &= (hash1->hash->bytes[i] == hash2->hash->bytes[i]);
	}

	TEST_ASSERT_FALSE(flag);
	fdo_hash_free(hash1);
	fdo_hash_free(hash2);
	fdo_crypto_close();
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hmac(void)
#else
TEST_CASE("crypto_support_make_hmac", "[crypto_support][fdo]")
#endif
{
	int ret;
	int i;
	bool flag;
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	fdo_hash_t *hmac2 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	TEST_ASSERT_NOT_NULL(hmac2);

	/* Negative case - invalid HMAC type. */
	ret = crypto_hal_hmac(-1, test_buff1, TEST_BUFF_SZ, hmac1->hash->bytes,
			      hmac1->hash->byte_sz, key1, TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - null buffer. */
	ret = crypto_hal_hmac(hmac1->hash_type, NULL, TEST_BUFF_SZ,
			      hmac1->hash->bytes, hmac1->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - zero buffer size. */
	ret =
	    crypto_hal_hmac(hmac1->hash_type, test_buff1, 0, hmac1->hash->bytes,
			    hmac1->hash->byte_sz, key1, TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - NULL hash pointer. */
	ret = crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ, NULL,
			      hmac1->hash->byte_sz, key1, TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - 0 hash buffer size. */
	ret = crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ,
			      hmac1->hash->bytes, 0, key1, TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - null key. */
	ret = crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ,
			      hmac1->hash->bytes, hmac1->hash->byte_sz, NULL,
			      TEST_KEY_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - zero key size. */
	ret =
	    crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ,
			    hmac1->hash->bytes, hmac1->hash->byte_sz, key1, 0);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Positive case. */
	ret = crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ,
			      hmac1->hash->bytes, hmac1->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_EQUAL(0, ret);

	/* Using the same buffer and key, we expect the same result. */
	ret = crypto_hal_hmac(hmac1->hash_type, test_buff1, TEST_BUFF_SZ,
			      hmac2->hash->bytes, hmac2->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hmac1->hash_type, hmac2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hmac1->hash->byte_sz, hmac2->hash->byte_sz);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hmac1->hash->bytes, hmac2->hash->bytes,
				      hmac1->hash->byte_sz);

	/* Using a different buffer, we expect a different result. */
	ret = crypto_hal_hmac(hmac2->hash_type, test_buff2, TEST_BUFF_SZ,
			      hmac2->hash->bytes, hmac2->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hmac1->hash_type, hmac2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hmac1->hash->byte_sz, hmac2->hash->byte_sz);

	flag = true;
	for (i = 0; (uint8_t)i < hmac1->hash->byte_sz; i++) {
		flag &= (hmac1->hash->bytes[i] == hmac2->hash->bytes[i]);
	}

	TEST_ASSERT_FALSE(flag);

	/* Using a different key, we expect a different result. */
	ret = crypto_hal_hmac(hmac2->hash_type, test_buff1, TEST_BUFF_SZ,
			      hmac2->hash->bytes, hmac2->hash->byte_sz, key2,
			      TEST_KEY_SZ);

	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hmac1->hash_type, hmac2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hmac1->hash->byte_sz, hmac2->hash->byte_sz);

	flag = true;
	for (i = 0; (uint8_t)i < hmac1->hash->byte_sz; i++) {
		flag &= (hmac1->hash->bytes[i] == hmac2->hash->bytes[i]);
	}

	TEST_ASSERT_FALSE(flag);

	fdo_hash_free(hmac1);
	fdo_hash_free(hmac2);
	fdo_crypto_close();
}
#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hmac_chained(void)
#else
TEST_CASE("crypto_support_make_hmac_chained", "[crypto_support][fdo]")
#endif
{
	int ret;
	fdo_hash_t *hmac1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	fdo_hash_t *hmac2 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	fdo_hash_t *chain1 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	fdo_hash_t *chain2 =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	TEST_ASSERT_NOT_NULL(hmac2);
	TEST_ASSERT_NOT_NULL(chain1);
	TEST_ASSERT_NOT_NULL(chain2);

	/* Start the chains, initialised from two different buffers. */
	ret = crypto_hal_hmac(chain1->hash_type, test_buff1, TEST_BUFF_SZ,
			      chain1->hash->bytes, chain1->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_EQUAL(0, ret);

	ret = crypto_hal_hmac(chain2->hash_type, test_buff2, TEST_BUFF_SZ,
			      chain2->hash->bytes, chain2->hash->byte_sz, key1,
			      TEST_KEY_SZ);
	TEST_ASSERT_EQUAL(0, ret);

	fdo_hash_free(hmac1);
	fdo_hash_free(hmac2);
	fdo_hash_free(chain2);
	fdo_hash_free(chain1);
	fdo_crypto_close();
}
