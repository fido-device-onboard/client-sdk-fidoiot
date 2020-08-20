/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for crypto abstraction routines of SDO library.
 */

#include "crypto_utils.h"
#include "sdoCrypto.h"
#include "sdoCryptoHal.h"
#include "unity.h"
#include "storage_al.h"
#include "safe_lib.h"
#include "stdlib.h"
#include "ecdsa_privkey.h"
#include "safe_lib.h"
#include "sdotypes.h"
#include "test_RSARoutines.h"

#if defined(KEX_DH_ENABLED) //(m size =2048)
#define DH_PEER_RANDOM_SIZE 256
#else // KEX_DH_3072_ENABLED  (m size 3072)
#define DH_PEER_RANDOM_SIZE 768
#endif
#define PLAIN_TEXT_SIZE BUFF_SIZE_1K_BYTES
#define DER_PUBKEY_LEN_MAX 512
#define ECDSA_PK_MAX_LENGTH 200

static uint8_t test_buff1[] = {1, 2, 3, 4, 5};
static uint8_t test_buff2[] = {6, 7, 8, 9, 10};

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
EC_KEY *generateECDSA_key(int curve);
int sha_ECCsign(int curve, uint8_t *msg, uint32_t mlen, uint8_t *out,
		uint32_t *outlen, EC_KEY *eckey);
sdo_public_key_t *getSDOpk(int curve, EC_KEY *eckey);
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
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz);
void *__wrap_sdo_alloc(size_t bytes);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value);
int __wrap_crypto_hal_sig_verify(
    uint8_t key_encoding, uint8_t key_algorithm, const uint8_t *message,
    uint32_t message_length, const uint8_t *message_signature,
    uint32_t signature_length, const uint8_t *key_param1,
    uint32_t key_param1Length, const uint8_t *key_param2,
    uint32_t key_param2Length);
int __wrap_get_ec_key(void);
int __wrap_ECDSA_size(const EC_KEY *eckey);
int __wrap_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax);
void test_crypto_support_random(void);
void test_crypto_support_Private_key(void);
void test_crypto_support_crypto(void);
void test_crypto_support_sdo_msg_encrypt_valid(void);
void test_crypto_support_sdo_msg_encrypt_invalid_clear_text(void);
void test_crypto_support_sdo_msg_encrypt_invalid_clear_text_length(void);
void test_crypto_support_sdo_msg_encrypt_invalid_cipher_text_length(void);
void test_crypto_support_sdo_msg_encrypt_invalid_iv(void);
void test_crypto_support_sdo_msg_encrypt_get_cipher_len_valid(void);
void test_crypto_support_sdo_msg_encrypt_get_cipher_len_verify(void);
void test_crypto_support_sdo_msg_decrypt_get_pt_len_valid(void);
void test_crypto_support_sdo_msg_decrypt_get_pt_len_verify(void);
void test_crypto_support_sdo_msg_decrypt_verify(void);
void test_crypto_support_sdo_msg_decrypt_valid(void);
void test_crypto_support_sdo_msg_decrypt_invalid_cipher(void);
void test_crypto_support_sdo_msg_decrypt_invalid_cipher_length(void);
void test_crypto_support_sdo_msg_decrypt_invalid_iv(void);
void test_crypto_support_sdo_kex_init(void);
void test_crypto_support_sdo_kex_close(void);
void test_crypto_support_sdo_kex_init_sdo_string_alloc_with_str_fail(void);
void test_crypto_support_sdo_kex_init_sdo_byte_array_alloc_fail(void);
void test_crypto_support_sdo_get_kex_paramB_valid(void);
void test_crypto_support_sdo_get_kex_paramB_crypto_hal_get_device_random_fail(
    void);
void test_crypto_support_sdo_get_kex_paramB_sdo_alloc_fail(void);
void test_crypto_support_sdo_get_kex_paramB_memset_s_fail(void);
void test_crypto_support_sdo_set_kex_paramA_valid(void);
void test_crypto_support_sdo_set_kex_paramA_invalid(void);
void test_crypto_support_sdo_set_kex_paramA_crypto_hal_set_peer_random_fail(
    void);
void test_crypto_support_load_ecdsa_privkey(void);
void test_crypto_support_load_ecdsa_privkey_sdo_blob_size_fail(void);
void test_crypto_support_load_ecdsa_privkey_sdo_alloc_fail(void);
void test_crypto_support_load_ecdsa_privkey_sdo_blob_read_fail(void);
void test_sdo_ov_verify(void);
void test_sdo_ov_verify_invalid_message(void);
void test_sdo_ov_verify_invalid_message_length(void);
void test_sdo_ov_verify_invalid_message_signature(void);
void test_sdo_ov_verify_invalid_signature_len(void);
void test_sdo_ov_verify_invalid_pubkey(void);
void test_sdo_ov_verifyi_invalid_result(void);
void test_sdo_device_sign(void);
void test_sdo_device_sign_invalid_message(void);
void test_sdo_device_sign_invalid_message_len(void);
void testcrypto_hal_hash(void);
void testcrypto_hal_hash_SHA384(void);
void test_sdo_cryptoHASH_invalid_message(void);
void test_sdo_cryptoHASH_invalid_message_len(void);
void test_sdo_cryptoHASH_invalid_hash(void);
void test_sdo_cryptoHASH_invalid_hash_len(void);
void test_sdo_to2_hmac(void);
void test_sdo_to2_hmac_SHA384(void);
void test_sdo_to2_hmac_invalid_to2Msg(void);
void test_sdo_to2_hmac_invalid_to2Msg_len(void);
void test_sdo_to2_hmac_invalid_hmac(void);
void test_sdo_to2_hmac_invalid_hmac_len(void);
void test_sdo_device_ov_hmac(void);
void test_sdo_device_ov_hmac_invalid_OVHdr(void);
void test_sdo_device_ov_hmac_invalid_OVHdr_len(void);
void test_sdo_device_ov_hmac_invalid_hmac(void);
void test_sdo_device_ov_hmac_invalid_hmac_len(void);
void test_crypto_hal_sig_verify_fail_case(void);
void test_get_ec_key_fail_case(void);
void test_ECDSA_size_fail_case(void);
void test_memcpy_s_fail_case(void);
void test_crypto_support_make_hash(void);
void test_crypto_support_make_hmac(void);
void test_crypto_support_make_hmac_chained(void);
int32_t __wrap_sdo_blob_read(char *name, sdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes);
int32_t __wrap_sdo_blob_size(char *name, uint32_t flags);
sdo_string_t *__wrap_sdo_string_alloc_with_str(char *data);
errno_t __wrap_strcmp_s(const char *dest, rsize_t dmax, const char *src,
			int *indicator);
static uint8_t *get_randomiv(void);
static EC_KEY *Private_key(void);
static RSA *generateRSA_pubkey(void);
int sha256_RSAsign(uint8_t *msg, uint32_t mlen, uint8_t *out, uint32_t *outlen,
		   RSA *r);
static sdo_public_key_t *getSDOpkey(RSA *r);

/*** Function Definitions ***/

static uint8_t key1[] = "test-key";
static uint8_t key2[] = "key-test";

static uint8_t *get_randomiv(void)
{
	uint8_t *iv = malloc(SDO_AES_IV_SIZE * sizeof(char));
	if (!iv)
		return NULL;
	sdo_crypto_random_bytes(iv, SDO_AES_IV_SIZE);
	return iv;
}

#ifdef USE_OPENSSL
static EC_KEY *Private_key(void)
{
	EC_KEY *eckey = NULL;

#if defined(ECDSA256_DA)
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
#else
	eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
#endif

	if (eckey == NULL)
		return NULL;
	/* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag */
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	if (eckey)
		if (EC_KEY_generate_key(eckey) == 0) {
			EC_KEY_free(eckey);
			eckey = NULL;
		}
	return eckey;
}
#endif

#ifdef USE_MBEDTLS
static int Private_key(mbedtls_ecdsa_context *ctx_sign)
{
	int ret;
	char *pers = "ecdsa_genkey";
	size_t pers_len = strnlen_s(pers, SDO_MAX_STR_SIZE);
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
static RSA *generateRSA_pubkey(void)
{
	int ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	uint64_t e = RSA_F4;
	int bits = BUFF_SIZE_256_BYTES * 8;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1) {
		BN_free(bne);
		return NULL;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1) {
		RSA_free(r);
		BN_free(bne);
		return NULL;
	}
	BN_free(bne);
	return r;
}

#if defined(PK_ENC_RSA)
int sha256_RSAsign(uint8_t *msg, uint32_t mlen, uint8_t *out, uint32_t *outlen,
		   RSA *r)
{
	uint8_t hash[SHA256_DIGEST_SIZE];

	if (SHA256(msg, mlen, hash) == NULL)
		return -1;

	int result =
	    RSA_sign(NID_sha256, hash, SHA256_DIGEST_SIZE, out, outlen, r);

	return result;
}
#endif // PK_ENC_RSA

static sdo_public_key_t *getSDOpkey(RSA *r)
{
	const BIGNUM *n = NULL;
	const BIGNUM *d = NULL;
	const BIGNUM *e = NULL;
	int sizeofpkmodulus = 0;
	uint8_t *pkmodulusbuffer = NULL;

	RSA_get0_key(r, &n, &e, &d);
	if (!n || !e)
		return NULL;
	sizeofpkmodulus = BN_num_bytes(n);

	pkmodulusbuffer = malloc(sizeofpkmodulus);
	BN_bn2bin(n, pkmodulusbuffer);

	sdo_public_key_t *pk =
	    sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_RSA,
				 SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
				 sizeofpkmodulus, pkmodulusbuffer);
	if (!pk || !pk->key1)
		return NULL;
	int pkexponent = BN_num_bytes(e);
	uint8_t *ebuff = malloc(pkexponent);
	if (!ebuff) {
		sdo_public_key_free(pk);
		return NULL;
	}

	if (BN_bn2bin(e, ebuff)) {
		pk->key2 =
		    sdo_byte_array_alloc_with_byte_array(ebuff, pkexponent);
		if (!pk->key2) {
			sdo_public_key_free(pk);
			pk = NULL;
		}
	} else {
		sdo_public_key_free(pk);
		pk = NULL;
	}
	if (ebuff)
		free(ebuff);
	if (pkmodulusbuffer)
		free(pkmodulusbuffer);
	return pk;
}

#if defined(PK_ENC_ECDSA)
EC_KEY *generateECDSA_key(int curve)
{
	(void)curve;
	EC_KEY *eckey = NULL;

#if defined(ECDSA256_DA)
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
#else
	eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
#endif
	if (eckey == NULL)
		return NULL;

	/* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag */
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	if (eckey)
		if (EC_KEY_generate_key(eckey) == 0) {
			EC_KEY_free(eckey);
			eckey = NULL;
		}
	return eckey;
}

// return 0 on success; -1 for failure
int sha_ECCsign(int curve, uint8_t *msg, uint32_t mlen, uint8_t *out,
		uint32_t *outlen, EC_KEY *eckey)
{
	(void)curve;
	uint8_t hash[SHA512_DIGEST_SIZE] = {0};
	size_t hashlength = 0;
	int result = -1;

#if defined(ECDSA256_DA)
	if (SHA256(msg, mlen, hash) == NULL)
		goto done;
	hashlength = SHA256_DIGEST_SIZE;
#else
	if (SHA384(msg, mlen, hash) == NULL)
		goto done;
	hashlength = SHA384_DIGEST_SIZE;
#endif

	result = ECDSA_sign(0, hash, hashlength, out, outlen, eckey);
	if (result == 0)
		goto done;

done:
	return result;
}

sdo_public_key_t *getSDOpk(int curve, EC_KEY *eckey)
{
	(void)curve;
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	unsigned char *kbuff = key_buf;

	int key_buf_len = 0;

	key_buf_len = i2d_EC_PUBKEY(eckey, &kbuff);
	TEST_ASSERT_NOT_EQUAL(0, key_buf_len);

	sdo_public_key_t *pk = NULL;

#if defined(ECDSA256_DA)
	pk = sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
				  SDO_CRYPTO_PUB_KEY_ENCODING_X509, key_buf_len,
				  key_buf);
#else
	pk = sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
				  SDO_CRYPTO_PUB_KEY_ENCODING_X509, key_buf_len,
				  key_buf);
#endif
	if (!pk || !pk->key1) {
		return NULL;
	}

	pk->key2 = NULL;
	return pk;
}
#endif // PK_ENC_ECDSA
#endif // USE_OPENSSL

#ifdef USE_MBEDTLS
static int generateRSA_pubkey(mbedtls_rsa_context *rsa)
{
	int ret;
	char *pers = "rsa_genkey";
	size_t pers_len = strnlen_s(pers, SDO_MAX_STR_SIZE);
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					 &entropy, (const uint8_t *)pers,
					 pers_len)) != 0) {
		return -1;
	}

	mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

	if ((ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
				       KEY_SIZE, EXPONENT)) != 0) {
		return -1;
	}

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}

#ifdef PK_ENC_RSA
int sha256_RSAsign(uint8_t *msg, uint32_t mlen, uint8_t *out, uint32_t *outlen,
		   mbedtls_rsa_context *rsa)
{
	int ret = 1;
	uint8_t hash[SHA256_DIGEST_SIZE];
	uint8_t buf[MBEDTLS_MPI_MAX_SIZE];
	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg,
			      mlen, hash)) != 0) {
		return -1;
	}

	if ((ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
					  MBEDTLS_MD_SHA256, SHA256_DIGEST_SIZE,
					  hash, buf)) != 0) {
		return -1;
	}
	*outlen = rsa->len;
	if (memcpy_s(out, (size_t)rsa->len, buf, (size_t)rsa->len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}
	return 1;
}
#endif // PK_ENC_RSA

static sdo_public_key_t *getSDOpkey(mbedtls_rsa_context *pkey)
{
	/* convert mbedtls struct to SDO struct   */
	int sizeofpkmodulus = pkey->len;
	uint8_t *pkmodulusbuffer = malloc(sizeofpkmodulus);
	if (!pkmodulusbuffer)
		return NULL;
	mbedtls_mpi_write_binary(&(pkey->N), (uint8_t *)pkmodulusbuffer,
				 sizeofpkmodulus);
	sdo_public_key_t *pk =
	    sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_RSA,
				 SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP,
				 sizeofpkmodulus, pkmodulusbuffer);
	if (!pk) {
		return NULL;
	}
	free(pkmodulusbuffer);

	int ebufflen = BUFF_SIZE_1K_BYTES;
	char ebuff[ebufflen];
	/* FIXME ... not sure how to extract the exponent correctly ,needs more
	 * investigation*/
	int len = mbedtls_mpi_size(&(pkey->E));
	mbedtls_mpi_write_binary(&(pkey->E), (uint8_t *)ebuff, len);
	pk->key2 = sdo_byte_array_alloc_with_byte_array((uint8_t *)&ebuff, len);

	return pk;
}

#if defined(PK_ENC_ECDSA)
#define EC256PARAMS MBEDTLS_ECP_DP_SECP256R1
#define EC384PARAMS MBEDTLS_ECP_DP_SECP384R1

static int generateECDSA_key(int curve, mbedtls_ecdsa_context *ctx_sign)
{
	int ret = -1;
	char *pers = "ecdsa_genkey";
	size_t pers_len = strnlen_s(pers, SDO_MAX_STR_SIZE);
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

sdo_public_key_t *getSDOpk(int curve, mbedtls_ecdsa_context *ctx_sign)
{
	/* convert mbedtls struct to SDO struct   */
	uint8_t buf[ECDSA_PK_MAX_LENGTH];
	size_t buflen = 0;
	int ret = 0;
	sdo_public_key_t *pk = NULL;

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
	    sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
				 SDO_CRYPTO_PUB_KEY_ENCODING_X509, buflen, buf);
#else
	pk =
	    sdo_public_key_alloc(SDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
				 SDO_CRYPTO_PUB_KEY_ENCODING_X509, buflen, buf);
#endif
	if (!pk || !pk->key1) {
		return NULL;
	}

	pk->key2 = NULL;

	return pk;
}
#endif // PK_ENC_ECDSA
#endif // USE_MBEDTLS

#if defined(KEX_ECDH_ENABLED)
static uint8_t adh_bytes[] = {
    0, 32, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 0, 32, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  0, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  1, 1, 1, 1, 1, 1};
#elif defined(KEX_ECDH384_ENABLED)
static uint8_t adh_bytes[] = {
    0, 48, 1, 1,  1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  1, 1,  1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  0, 48, 1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  1, 1,  1, 1,  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1,  1, 1,  0, 16, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

#elif defined(KEX_DH_ENABLED)
uint8_t *adh_bytes = NULL;
#else
static uint8_t adh_bytes[] = {0, 1, 2, 3, 4, 5, 6, 7};
#endif
static sdo_byte_array_t adh;

#define SHA256_DIGEST_SZ SHA256_DIGEST_SIZE
#define SHA384_DIGEST_SZ SHA384_DIGEST_SIZE
#define TEST_BUFF_SZ BUFF_SIZE_8_BYTES // random buffer
#define TEST_KEY_SZ BUFF_SIZE_8_BYTES

#ifdef TARGET_OS_LINUX
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
bool sdo_string_alloc_with_str_fail_case = false;
bool sdo_byte_array_alloc_fail_case = false;
bool g_malloc_fail = false;
bool strcmp_s_fail_case = false;
bool crypto_hal_get_device_random_fail_case = false;
bool g_memset_fail = false;
bool crypto_hal_set_peer_random_fail_case = false;
bool sdo_blob_read_fail_case = false;
bool sdo_blob_size_fail_case = false;
bool crypto_hal_sig_verify_fail_flag = false;
bool get_ec_key_fail_flag = false;
bool ECDSA_size_fail_flag = false;
bool memcpy_s_fail_flag = false;

int32_t __real_sdo_blob_read(char *name, sdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes);
int32_t __wrap_sdo_blob_read(char *name, sdo_sdk_blob_flags flags, uint8_t *buf,
			     uint32_t n_bytes)
{
	if (sdo_blob_read_fail_case) {
		return -1;
	} else {
		return __real_sdo_blob_read(name, flags, buf, n_bytes);
	}
}

int32_t __real_sdo_blob_size(char *name, uint32_t flags);
int32_t __wrap_sdo_blob_size(char *name, uint32_t flags)
{
	if (sdo_blob_size_fail_case) {
		return -1;
	} else {
		return __real_sdo_blob_size(name, flags);
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

sdo_string_t *__real_sdo_string_alloc_with_str(char *data);
sdo_string_t *__wrap_sdo_string_alloc_with_str(char *data)
{
	if (sdo_string_alloc_with_str_fail_case) {
		return NULL;
	} else {
		return __real_sdo_string_alloc_with_str(data);
	}
}

sdo_byte_array_t *__real_sdo_byte_array_alloc(int byte_sz);
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz)
{
	if (sdo_byte_array_alloc_fail_case) {
		return NULL;
	} else {
		return __real_sdo_byte_array_alloc(byte_sz);
	}
}

void *__real_sdo_alloc(size_t bytes);
void *__wrap_sdo_alloc(size_t bytes)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_sdo_alloc(bytes);
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
		return SDO_ERROR;
	else
		return __real_memset_s(dest, len, value);
}

int __real_crypto_hal_sig_verify(
    uint8_t key_encoding, uint8_t key_algorithm, const uint8_t *message,
    uint32_t message_length, const uint8_t *message_signature,
    uint32_t signature_length, const uint8_t *key_param1,
    uint32_t key_param1Length, const uint8_t *key_param2,
    uint32_t key_param2Length);
int __wrap_crypto_hal_sig_verify(
    uint8_t key_encoding, uint8_t key_algorithm, const uint8_t *message,
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
#if !defined(EPID_DA)
int __real_get_ec_key(void);
int __wrap_get_ec_key(void)
{
	if (get_ec_key_fail_flag) {
		return 0;
	} else {
		return __real_get_ec_key();
	}
}
#endif

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
#endif

/*** Test functions. ***/

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_random(void)
#else
TEST_CASE("crypto_support_random", "[crypto_support][sdo]")
#endif
{
#ifdef TARGET_OS_FREERTOS
	extern bool simulcrypto_hal_random_bytes;
	simulcrypto_hal_random_bytes = true;
#endif

	int ret;
	uint8_t random_data[TEST_BUFF_SZ] = {0};

	sdo_crypto_close();
	/* These functions should fail if random_init isn't called first. */
	ret = sdo_crypto_random_bytes(random_data, TEST_BUFF_SZ);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	ret = random_close();
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Start. */
	ret = random_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Valid input. */
	ret = sdo_crypto_random_bytes(random_data, TEST_BUFF_SZ);
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* Invalid input. */
	ret = sdo_crypto_random_bytes(NULL, TEST_BUFF_SZ);
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
TEST_CASE("crypto_support_Private_key", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
#ifdef USE_OPENSSL
#if defined(ECDSA256_DA)
	size_t hash_length = SHA256_DIGEST_SIZE;
#else
	size_t hash_length = SHA384_DIGEST_SIZE;
#endif

	EC_KEY *validkey = Private_key();
	TEST_ASSERT_NOT_NULL(validkey);
	int privatekey_buflen = hash_length;
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_context ctx_sign = {0};
	ret = Private_key(&ctx_sign);
	TEST_ASSERT_EQUAL(0, ret);
	int privatekey_buflen = mbedtls_mpi_size(&ctx_sign.d);
#endif
	uint8_t *privatekey = malloc(privatekey_buflen);
	TEST_ASSERT_NOT_NULL(privatekey);
	memset_s(privatekey, 0, privatekey_buflen);

// store private key for later use in pem /bin format
#if defined(ECDSA_PEM)
	BIO *outbio = BIO_new(BIO_s_mem());
	TEST_ASSERT_NOT_NULL(outbio);
	EVP_PKEY *privkey = EVP_PKEY_new();
	TEST_ASSERT_NOT_NULL(privkey);

	//      if (!EVP_PKEY_assign_EC_KEY(privkey,avalidkey))
	if (!EVP_PKEY_set1_EC_KEY(privkey, validkey))
		printf(" assigning ECC key to EVP_PKEY fail.\n");
	const EC_GROUP *group = EC_KEY_get0_group(validkey);

	PEM_write_bio_ECPKParameters(outbio, group);
	if (!PEM_write_bio_ECPrivateKey(outbio, validkey, NULL, NULL, 0, 0,
					NULL))
		BIO_printf(outbio,
			   "Error writing private key data in PEM format");

	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(outbio, &bptr);

	ret = sdo_blob_write((char *)ECDSA_PRIVKEY, SDO_SDK_RAW_DATA,
			     (const uint8_t *)bptr->data, bptr->length);
	TEST_ASSERT_NOT_EQUAL(-1, ret);

#else

#ifdef USE_OPENSSL
	if (BN_bn2bin(EC_KEY_get0_private_key((const EC_KEY *)validkey),
		      privatekey))
		ret = 0;
#endif
#ifdef USE_MBEDTLS
	ret = mbedtls_mpi_write_binary(&ctx_sign.d, privatekey,
				       privatekey_buflen);
#endif
	TEST_ASSERT_EQUAL(0, ret);

	// Writing Privatekey to a file
	ret = sdo_blob_write((char *)ECDSA_PRIVKEY, SDO_SDK_RAW_DATA,
			     privatekey, privatekey_buflen);
	TEST_ASSERT_NOT_EQUAL(-1, ret);
#endif

#ifdef USE_OPENSSL
#if defined(ECDSA_PEM)
	EVP_PKEY_free(privkey);
	BIO_free_all(outbio);
#endif
	if (validkey)
		EC_KEY_free(validkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&ctx_sign);
#endif
	free(privatekey);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_crypto(void)
#else
TEST_CASE("crypto_support_crypto", "[crypto_support][sdo]")
#endif
{
	int ret;

/*TODO: Adapt when sdosdk_close is implemented*/
#if 0
	/* sdo_crypto_close should fail if sdo_crypto_init isn't called first. */
    ret = sdo_crypto_close();
    TEST_ASSERT_NOT_EQUAL(0, ret);
#endif
	/* Start. */
	ret = sdo_crypto_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	/* End. */
	ret = sdo_crypto_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_valid(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_valid", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();

	ret = random_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1);
	if (cipher)
		free(cipher);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_invalid_clear_text(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_invalid_clear_text",
	  "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(NULL, clear_length, cipher, &cipher_length, iv1);
	if (cipher)
		free(cipher);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_invalid_clear_text_length(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_invalid_clear_text_length",
	  "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, 0, cipher, &cipher_length, iv1);
	if (cipher)
		free(cipher);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_invalid_cipher_text_length(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_invalid_cipher_text_length",
	  "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, clear_length, cipher, NULL, iv1);
	if (cipher)
		free(cipher);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_invalid_iv(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_invalid_iv", "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	uint8_t *cipher = NULL;
	uint32_t cipher_length;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = NULL;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(NULL, clear_length, cipher, &cipher_length, iv1);
	if (cipher)
		free(cipher);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_get_cipher_len_valid(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_get_cipher_len_valid",
	  "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_encrypt_get_cipher_len_verify(void)
#else
TEST_CASE("crypto_support_sdo_msg_encrypt_get_cipher_len_verify",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	uint32_t cipher_length;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint32_t *Length = NULL;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	Length = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(Length);
	if (Length)
		free(Length);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_get_pt_len_valid(void)
#else
TEST_CASE("test_crypto_support_sdo_msg_decrypt_get_pt_len_valid",
	  "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_get_pt_len_verify(void)
#else
TEST_CASE("test_crypto_support_sdo_msg_decrypt_get_pt_len_verify",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	int *dptr = NULL;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	dptr = (int *)malloc(sizeof(char) * decrypthed_length);
	TEST_ASSERT_NOT_NULL(dptr);
	if (dptr)
		free(dptr);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_verify(void)
#else
TEST_CASE("crypto_support_sdo_msg_decrypt_verify", "[crypto_support][sdo]")
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

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = sdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = memcmp_s(test_buff1, clear_length, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	if (cipher)
		free(cipher);
	if (decrypted_txt)
		free(decrypted_txt);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_valid(void)
#else
TEST_CASE("crypto_support_sdo_msg_decrypt_valid", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, clear_length, cipher, &cipher_length,
			      iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = sdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1);
	if (cipher)
		free(cipher);
	if (decrypted_txt)
		free(decrypted_txt);
	if (iv1)
		free(iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_invalid_cipher(void)
#else
TEST_CASE("crypto_support_sdo_msg_decrypt_invalid_cipher",
	  "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = sizeof(test_buff1);
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = sdo_msg_decrypt(decrypted_txt, &decrypthed_length, NULL,
			      cipher_length, iv1);
	if (iv1)
		free(iv1);
	if (decrypted_txt)
		free(decrypted_txt);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_invalid_cipher_length(void)
#else
TEST_CASE("crypto_support_sdo_msg_decrypt_invalid_cipher_length",
	  "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = get_randomiv();

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret =
	    sdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher, 0, iv1);
	if (iv1)
		free(iv1);
	if (cipher)
		free(cipher);
	if (decrypted_txt)
		free(decrypted_txt);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_msg_decrypt_invalid_iv(void)
#else
TEST_CASE("crypto_support_sdo_msg_decrypt_invalid_iv", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	uint8_t *cipher = NULL;
	uint8_t *decrypted_txt = NULL;
	uint32_t cipher_length = 0;
	uint32_t decrypthed_length = 0;
	uint32_t clear_length = PLAIN_TEXT_SIZE;
	uint8_t *iv1 = NULL;

	ret = sdo_msg_encrypt_get_cipher_len(clear_length, &cipher_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	cipher = malloc(sizeof(char) * cipher_length);
	TEST_ASSERT_NOT_NULL(cipher);

	ret = sdo_msg_encrypt(test_buff1, sizeof(test_buff1), cipher,
			      &cipher_length, iv1);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = sdo_msg_decrypt_get_pt_len(cipher_length, &decrypthed_length);
	TEST_ASSERT_EQUAL_INT(0, ret);
	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	ret = sdo_msg_decrypt(decrypted_txt, &decrypthed_length, cipher,
			      cipher_length, iv1);
	if (cipher)
		free(cipher);
	if (decrypted_txt)
		free(decrypted_txt);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_kex_init(void)
#else
TEST_CASE("crypto_support_sdo_kex_init", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_kex_close(void)
#else
TEST_CASE("crypto_support_sdo_kex_close", "[crypto_support][sdo]")
#endif
{
	int ret = -1;
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_kex_init_sdo_string_alloc_with_str_fail(void)
#else
TEST_CASE("crypto_support_sdo_kex_init_sdo_string_alloc_with_str_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	sdo_string_alloc_with_str_fail_case = true;
	ret = sdo_kex_init();
	sdo_string_alloc_with_str_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_kex_init_sdo_byte_array_alloc_fail(void)
#else
TEST_CASE("crypto_support_sdo_kex_init_sdo_byte_array_alloc_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret = 0;
	sdo_byte_array_alloc_fail_case = true;
	ret = sdo_kex_init();
	sdo_byte_array_alloc_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_get_kex_paramB_valid(void)
#else
TEST_CASE("crypto_support_sdo_get_kex_paramB_valid", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_byte_array_t *xB = NULL;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

#if defined(KEX_ASYM_ENABLED)
#ifdef USE_OPENSSL
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	sdo_public_key_t *encrypt_key = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	sdo_public_key_t *encrypt_key = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	set_encrypt_key_asym(kex_ctx->context, encrypt_key);
#endif
	ret = sdo_get_kex_paramB(&xB);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
#if defined(KEX_ASYM_ENABLED)
	if (encrypt_key)
		sdo_public_key_free(encrypt_key);
#ifdef USE_OPESSL
	if (validkey)
		RSA_free(validkey);
#endif

#ifdef USE_MBEDTLS
	mbedtls_rsa_free(&validkey);
#endif
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_get_kex_paramB_crypto_hal_get_device_random_fail(
    void)
#else
TEST_CASE("crypto_support_sdo_get_kex_paramB_crypto_hal_get_device_random_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_byte_array_t *xB = NULL;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	crypto_hal_get_device_random_fail_case = true;
	ret = sdo_get_kex_paramB(&xB);
	crypto_hal_get_device_random_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_get_kex_paramB_sdo_alloc_fail(void)
#else
TEST_CASE("crypto_support_sdo_get_kex_paramB_sdo_alloc_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_byte_array_t *xB = NULL;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	g_malloc_fail = true;
	ret = sdo_get_kex_paramB(&xB);
	g_malloc_fail = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_get_kex_paramB_memset_s_fail(void)
#else
TEST_CASE("crypto_support_sdo_get_kex_paramB_memset_s_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_byte_array_t *xB = NULL;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	g_memset_fail = true;
	ret = sdo_get_kex_paramB(&xB);
	g_memset_fail = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}
#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_set_kex_paramA_valid(void)
#else
TEST_CASE("crypto_support_sdo_set_kex_paramA_valid", "[crypto_support][sdo]")
#endif
{
#if 1
	int ret;
	sdo_public_key_t *encrypt_key = NULL;
#ifdef USE_OPENSSL
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	encrypt_key = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	encrypt_key = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = random_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
#if defined(KEX_DH_ENABLED)
	if (NULL == adh_bytes) {
		adh_bytes = sdo_alloc(DH_PEER_RANDOM_SIZE);
		if (!adh_bytes)
			goto error;
		if (0 !=
		    sdo_crypto_random_bytes(adh_bytes, DH_PEER_RANDOM_SIZE)) {
			goto error;
		}
	}
	adh.byte_sz = DH_PEER_RANDOM_SIZE;
#else
	adh.byte_sz = sizeof(adh_bytes);
#endif
	adh.bytes = adh_bytes;
	ret = sdo_set_kex_paramA(&adh, encrypt_key);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
#if defined(KEX_DH_ENABLED)
error:
	if (adh_bytes)
		sdo_free(adh_bytes);
#endif
	if (encrypt_key)
		sdo_public_key_free(encrypt_key);
#ifdef USE_OPENSSL
	if (validkey)
		RSA_free(validkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_free(&validkey);
#endif
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_set_kex_paramA_invalid(void)
#else
TEST_CASE("crypto_support_sdo_set_kex_paramA_invalid", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_public_key_t *encrypt_key = NULL;
#ifdef USE_OPENSSL
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	encrypt_key = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	encrypt_key = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
	sdo_byte_array_t pA;

	/* invalid key */
	pA.bytes = NULL;
	pA.byte_sz = 0;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	//	ret = sdo_set_kex_paramA(&pA, encrypt_key);
	//	TEST_ASSERT_EQUAL_INT(-1, ret);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
	if (encrypt_key)
		sdo_public_key_free(encrypt_key);
#ifdef USE_OPENSSL
	if (validkey)
		RSA_free(validkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_free(&validkey);
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_sdo_set_kex_paramA_crypto_hal_set_peer_random_fail(
    void)
#else
TEST_CASE("crypto_support_sdo_set_kex_paramA_crypto_hal_set_peer_random_fail",
	  "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_public_key_t *encrypt_key = NULL;
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);
#ifdef USE_OPENSSL
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	encrypt_key = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	encrypt_key = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(encrypt_key);
#endif
#if defined(KEX_DH_ENABLED)
	if (NULL == adh_bytes) {
		adh_bytes = sdo_alloc(DH_PEER_RANDOM_SIZE);
		if (adh_bytes == NULL) {
			goto error;
		}
		if (sdo_crypto_random_bytes(adh_bytes, DH_PEER_RANDOM_SIZE) !=
		    0) {
			goto error;
		}
	}
	adh.byte_sz = DH_PEER_RANDOM_SIZE;
#else
	adh.byte_sz = sizeof(adh_bytes);
#endif
	adh.bytes = adh_bytes;
	crypto_hal_set_peer_random_fail_case = true;
	ret = sdo_set_kex_paramA(&adh, encrypt_key);

	crypto_hal_set_peer_random_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
#if defined(KEX_DH_ENABLED)
error:
	if (adh_bytes)
		sdo_free(adh_bytes);
#endif
	if (encrypt_key)
		sdo_public_key_free(encrypt_key);
#ifdef USE_OPENSSL
	if (validkey)
		RSA_free(validkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_free(&validkey);
#endif
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey", "[crypto_support][sdo]")
#endif
{
#if !defined(EPID_DA)
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	TEST_ASSERT_EQUAL_INT(0, ret);
	if (privkey) {
		free(privkey);
		privkey = NULL;
	}
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_sdo_blob_size_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_sdo_blob_size_fail",
	  "[crypto_support][sdo]")
#endif
{
#if !defined(EPID_DA)
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	sdo_blob_size_fail_case = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	sdo_blob_size_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	if (privkey) {
		free(privkey);
		privkey = NULL;
	}
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_sdo_alloc_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_sdo_alloc_fail",
	  "[crypto_support][sdo]")
#endif
{
#if !defined(EPID_DA)
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	g_malloc_fail = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	g_malloc_fail = false;
	if (privkey) {
		free(privkey);
		privkey = NULL;
	}
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_load_ecdsa_privkey_sdo_blob_read_fail(void)
#else
TEST_CASE("crypto_support_load_ecdsa_privkey_sdo_blob_read_fail",
	  "[crypto_support][sdo]")
#endif
{
#if !defined(EPID_DA)
	int ret = -1;
	uint8_t *privkey = NULL;
	size_t privkey_size = 0;

	/* Get the private key from storage */
	sdo_blob_read_fail_case = true;
	ret = load_ecdsa_privkey(&privkey, &privkey_size);
	sdo_blob_read_fail_case = false;
	TEST_ASSERT_EQUAL_INT(-1, ret);
	if (privkey) {
		free(privkey);
		privkey = NULL;
	}
#else
	TEST_IGNORE();
#endif
}

/* Test cases for sdo_ov_verify
 * message of length message_length is signed using RSA or ECDSA.
 * Same message is signed with puukey
 * sdo_ov_verify will check is both signature are same or not
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify(void)
#else
TEST_CASE("sdo_ov_verify", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t test_buff[] = {1, 2, 3, 4, 5};
	uint8_t *message = test_buff;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;

#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Positive test case
	 * verifying signature done by either RSA or ECDSA
	   with signature done by pubkey passes as parameter
	 */
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(0, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing NULL as message to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify_invalid_message(void)
#else
TEST_CASE("sdo_ov_verify_invalid_message", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Negative test case */
	ret = sdo_ov_verify(NULL, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing 0 as message_length to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify_invalid_message_length(void)
#else
TEST_CASE("sdo_ov_verify_invalid_message_length", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Negative test case */
	ret = sdo_ov_verify(message, 0, message_signature, signature_len,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing NULL as message_signature to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify_invalid_message_signature(void)
#else
TEST_CASE("sdo_ov_verify_invalid_message_signature", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Negative test case */
	ret = sdo_ov_verify(message, message_length, NULL, signature_len,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing 0 as Signature_len to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify_invalid_signature_len(void)
#else
TEST_CASE("sdo_ov_verify_invalid_signature_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Negative test case */
	ret = sdo_ov_verify(message, message_length, message_signature, 0,
			    pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing NULL as pubkey to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verify_invalid_pubkey(void)
#else
TEST_CASE("sdo_ov_verify_invalid_pubkey", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = NULL;
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = NULL;
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* Negative test case */
	ret = sdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey != NULL) {
		sdo_public_key_free(pubkey);
	}
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
	if (result) {
		result = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * passing NULL as result to check invalid parameters
 */
#ifndef TARGET_OS_FREERTOS
void test_sdo_ov_verifyi_invalid_result(void)
#else
TEST_CASE("sdo_ov_verify_invalid_result", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool *result = NULL;

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	// Negative test case
	ret = sdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
		message_signature = NULL;
	}
}

/* Test cases fot Device_sign */
#ifndef TARGET_OS_FREERTOS
void test_sdo_device_sign(void)
#else
TEST_CASE("sdo_device_sign", "[crypto_support][sdo]")
#endif
{
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	sdo_byte_array_t *signature = NULL;

#if defined(EPID_DA)
	sdo_byte_array_t sig_rl;
	sdo_byte_array_t pubkey;

	sig_rl.bytes = NULL;
	sig_rl.byte_sz = 0;

	pubkey.bytes = pub_key;
	pubkey.byte_sz = sizeof(pub_key);

	sdo_set_device_sig_infoeB(&sig_rl, &pubkey);
	ret = dev_attestation_init();
	TEST_ASSERT_EQUAL(0, ret);
#endif
	// Positive test case
	ret = sdo_device_sign(message, message_len, &signature);
	TEST_ASSERT_EQUAL(0, ret);
	if (signature) {
		sdo_byte_array_free(signature);
		signature = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_sign_invalid_message(void)
#else
TEST_CASE("sdo_device_sign_invalid_message", "[crypto_support][sdo]")
#endif
{
	int ret;
	size_t message_len = sizeof(test_buff1);
	sdo_byte_array_t *signature = NULL;

	/* Negative test case */
	ret = sdo_device_sign(NULL, message_len, &signature);
	TEST_ASSERT_EQUAL(-1, ret);
	if (signature) {
		sdo_byte_array_free(signature);
		signature = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_sign_invalid_message_len(void)
#else
TEST_CASE("sdo_device_sign_invalid_message_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	const uint8_t *message = test_buff1;
	sdo_byte_array_t *signature = NULL;

	/* Negative test case */
	ret = sdo_device_sign(message, 0, &signature);
	TEST_ASSERT_EQUAL(-1, ret);
	if (signature) {
		sdo_byte_array_free(signature);
		signature = NULL;
	}
}

/* Test cases for sdo_crypto_hash */
#ifndef TARGET_OS_FREERTOS
void testcrypto_hal_hash(void)
#else
TEST_CASE("sdo_crypto_hash", "[crypto_support][sdo]")
#endif
{
#if defined(ECDSA384_DA)
	TEST_IGNORE();
#endif
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);
	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Positive test case */
	ret = sdo_crypto_hash(message, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	sdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void testcrypto_hal_hash_SHA384(void)
#else
TEST_CASE("sdo_crypto_hash_SHA384", "[crypto_support][sdo]")
#endif
{
#if defined(ECDSA256_DA)
	TEST_IGNORE();
#endif
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_384, SHA384_DIGEST_SIZE);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Positive test case */
	ret = sdo_crypto_hash(message, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	sdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_cryptoHASH_invalid_message(void)
#else
TEST_CASE("sdo_cryptoHASH_invalid_message", "[crypto_support][sdo]")
#endif
{
	int ret;
	size_t message_len = TEST_BUFF_SZ;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = sdo_crypto_hash(NULL, message_len, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_cryptoHASH_invalid_message_len(void)
#else
TEST_CASE("sdo_cryptoHASH_invalid_message_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = sdo_crypto_hash(message, 0, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_cryptoHASH_invalid_hash(void)
#else
TEST_CASE("sdo_cryptoHASH_invalid_hash", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);

	/* Negative test case */
	ret = sdo_crypto_hash(message, message_len, NULL, hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hash1);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_cryptoHASH_invalid_hash_len(void)
#else
TEST_CASE("sdo_cryptoHASH_invalid_hash_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	size_t message_len = TEST_BUFF_SZ;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation of hashes
	TEST_ASSERT_NOT_NULL(hash1);

	// Negative test case
	ret = sdo_crypto_hash(message, message_len, hash1->hash->bytes, 0);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hash1);
}

/* Test cases for sdo_to2_hmac */
#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac(void)
#else
TEST_CASE("sdo_to2_hmac", "[crypto_support][sdo]")
#endif
{
#if defined(ECDSA384_DA)
	TEST_IGNORE();
#endif
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation.
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *to2Msg = test_buff1;
	size_t to2Msg_len = TEST_BUFF_SZ;

	// Positve test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(to2Msg, to2Msg_len, hmac1->hash->bytes,
			   hmac1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac_SHA384(void)
#else
TEST_CASE("sdo_to2_hmac_SHA_384", "[crypto_support][sdo]")
#endif
{
#if defined(ECDSA256_DA)
	TEST_IGNORE();
#endif
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_384, SHA384_DIGEST_SIZE);

	// Check initialisation.
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *to2Msg = test_buff1;
	size_t to2Msg_len = TEST_BUFF_SZ;

	// Positve test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(to2Msg, to2Msg_len, hmac1->hash->bytes,
			   hmac1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac_invalid_to2Msg(void)
#else
TEST_CASE("sdo_to2_hmac", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation
	TEST_ASSERT_NOT_NULL(hmac1);
	size_t to2Msg_len = TEST_BUFF_SZ;

	// Negative test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(NULL, to2Msg_len, hmac1->hash->bytes,
			   hmac1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac_invalid_to2Msg_len(void)
#else
TEST_CASE("sdo_to2_hmac_invalid_to2Msg_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *to2Msg = test_buff1;

	// Negative test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(to2Msg, 0, hmac1->hash->bytes, hmac1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac_invalid_hmac(void)
#else
TEST_CASE("sdo_to2_hmac_invalid_hmac", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *to2Msg = test_buff1;
	size_t to2Msg_len = TEST_BUFF_SZ;

	// Negative test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(to2Msg, to2Msg_len, NULL, hmac1->hash->byte_sz);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_to2_hmac_invalid_hmac_len(void)
#else
TEST_CASE("sdo_to2_hmac_invalid_hmac_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	// Check initialisation
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *to2Msg = test_buff1;
	size_t to2Msg_len = TEST_BUFF_SZ;

	// Negative test case
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_to2_hmac(to2Msg, to2Msg_len, hmac1->hash->bytes, 0);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
}

/* Test cases for sdo_device_ov_hmac */
#ifndef TARGET_OS_FREERTOS
void test_sdo_device_ov_hmac(void)
#else
TEST_CASE("sdo_device_ov_hmac", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	sdo_byte_array_t *OVkey = sdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);

#if defined(ECDSA384_DA)
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_384, SHA384_DIGEST_SZ);
#else
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
#endif
	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Positive test case */
	ret = sdo_kex_init();
	TEST_ASSERT_EQUAL(0, ret);
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = sdo_device_ov_hmac(OVHdr, OVHdr_len, hmac, hmac_len);
	TEST_ASSERT_EQUAL(0, ret);

	ret = sdo_kex_close();
	TEST_ASSERT_EQUAL(0, ret);
	sdo_hash_free(hmac1);
	if (OVkey) {
		sdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_ov_hmac_invalid_OVHdr(void)
#else
TEST_CASE("sdo_device_ov_hmac_invalid_OVHdr", "[crypto_support][sdo]")
#endif
{
	int ret;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	sdo_byte_array_t *OVkey = sdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = sdo_device_ov_hmac(NULL, OVHdr_len, hmac, hmac_len);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	if (OVkey) {
		sdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_ov_hmac_invalid_OVHdr_len(void)
#else
TEST_CASE("sdo_device_ov_hmac_invalid_OVHdr_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	sdo_byte_array_t *OVkey = sdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = sdo_device_ov_hmac(OVHdr, 0, hmac, hmac_len);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	if (OVkey) {
		sdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_ov_hmac_invalid_hmac(void)
#else
TEST_CASE("sdo_device_ov_hmac_invalid_hmac", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	sdo_byte_array_t *OVkey = sdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	size_t hmac_len = (hmac1->hash->byte_sz);

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = sdo_device_ov_hmac(OVHdr, OVHdr_len, NULL, hmac_len);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	if (OVkey) {
		sdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

#ifndef TARGET_OS_FREERTOS
void test_sdo_device_ov_hmac_invalid_hmac_len(void)
#else
TEST_CASE("sdo_device_ov_hmac_invalid_hmac_len", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *OVHdr = test_buff1;
	size_t OVHdr_len = sizeof(test_buff1);
	size_t OVKey_len = BUFF_SIZE_32_BYTES;
	sdo_byte_array_t *OVkey = sdo_byte_array_alloc(OVKey_len);
	TEST_ASSERT_NOT_NULL(OVkey);
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

	/* Check initialisation. */
	TEST_ASSERT_NOT_NULL(hmac1);
	uint8_t *hmac = hmac1->hash->bytes;

	/* Negative test case */
	ret = set_ov_key(OVkey, OVKey_len);
	TEST_ASSERT_EQUAL(0, ret);
	ret = sdo_device_ov_hmac(OVHdr, OVHdr_len, hmac, 0);
	TEST_ASSERT_EQUAL(-1, ret);

	sdo_hash_free(hmac1);
	if (OVkey) {
		sdo_byte_array_free(OVkey);
		OVkey = NULL;
	}
}

/* Test cases for sdo_ov_verify invalid message
 * message of length message_length is signed using RSA or ECDSA.
 * wraper flag is set to true, to fail internal API
 */
#ifndef TARGET_OS_FREERTOS
void test_crypto_hal_sig_verify_fail_case(void)
#else
TEST_CASE("crypto_hal_sig_verify_fail_case", "[crypto_support][sdo]")
#endif
{
	int ret;
	uint8_t *message = test_buff1;
	uint32_t message_length = BUFF_SIZE_256_BYTES;
	uint32_t signature_len = BUFF_SIZE_256_BYTES;
	uint8_t *message_signature = malloc(signature_len);
	TEST_ASSERT_NOT_NULL(message_signature);
	bool val = 1;
	bool *result = &val;
	TEST_ASSERT_NOT_NULL(result);

	// Sign using RSApk
#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	RSA *validkey = generateRSA_pubkey();
	TEST_ASSERT_NOT_NULL(validkey);

	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
#if defined(ECDSA256_DA)
	curve = 256;
#else
	curve = 384;
#endif
	EC_KEY *validkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(validkey);
	ret = sha_ECCsign(curve, message, message_length, message_signature,
			  &signature_len, validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpk(curve, validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_context validkey;
	ret = generateRSA_pubkey(&validkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	ret = sha256_RSAsign(message, message_length, message_signature,
			     &signature_len, &validkey);
	TEST_ASSERT_EQUAL(1, ret);
	sdo_public_key_t *pubkey = getSDOpkey(&validkey);
	TEST_ASSERT_NOT_NULL(pubkey);
#else
	int curve = 0;
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
	sdo_public_key_t *pubkey = getSDOpk(curve, &validkey);
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
#endif

	/* if flag is true, sdo_ov_verify will fail due to wraper */
	crypto_hal_sig_verify_fail_flag = true;
	ret = sdo_ov_verify(message, message_length, message_signature,
			    signature_len, pubkey, result);
	TEST_ASSERT_EQUAL(-1, ret);

#ifdef USE_OPENSSL
#if defined(PK_ENC_RSA)
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		RSA_free(validkey);
#else
	if (pubkey)
		sdo_public_key_free(pubkey);
	if (validkey)
		EC_KEY_free(validkey);
#endif
#endif

#ifdef USE_MBEDTLS
#if defined(PK_ENC_RSA)
	mbedtls_rsa_free(&validkey);
#else
	mbedtls_ecdsa_free(&validkey);
#endif
#endif

	if (message_signature) {
		free(message_signature);
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
TEST_CASE("get_ec_key_fail_case", "[crypto_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	sdo_byte_array_t *signature = NULL;

	get_ec_key_fail_flag = true;
	ret = sdo_device_sign(message, message_len, &signature);
	TEST_ASSERT_EQUAL(-1, ret);

	get_ec_key_fail_flag = false;
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ECDSA_size_fail_case(void)
#else
TEST_CASE("ECDSA_size_fail_case", "[crypto_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	sdo_byte_array_t *signature = NULL;

	ECDSA_size_fail_flag = true;
	ret = sdo_device_sign(message, message_len, &signature);
	TEST_ASSERT_EQUAL(-1, ret);

	ECDSA_size_fail_flag = false;
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_memcpy_s_fail_case(void)
#else
TEST_CASE("memcpy_s_fail_case", "[crypto_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	const uint8_t *message = test_buff1;
	size_t message_len = sizeof(test_buff1);
	sdo_byte_array_t *signature = NULL;

	memcpy_s_fail_flag = true;
	ret = sdo_device_sign(message, message_len, &signature);
	memcpy_s_fail_flag = false;
	TEST_ASSERT_EQUAL(-1, ret);

#if defined(EPID_DA)
	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();
	device_ctx->eB->sig_rl = 0;
	device_ctx->eB->pubkey = 0;
#endif
#else
#if defined(EPID_DA)
	sdo_dev_key_ctx_t *device_ctx = getsdo_dev_key_ctx();
	device_ctx->eB->sig_rl = 0;
	device_ctx->eB->pubkey = 0;
#endif
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hash(void)
#else
TEST_CASE("crypto_support_make_hash", "[crypto_support][sdo]")
#endif
{
	int ret;
	int i;
	bool flag = true;
	sdo_hash_t *hash1 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);
	sdo_hash_t *hash2 =
	    sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_USED, SDO_SHA_DIGEST_SIZE_USED);

	/* Check initialisation of hashes. */
	TEST_ASSERT_NOT_NULL(hash1);
	TEST_ASSERT_NOT_NULL(hash2);

	/* Negative case - null buffer. */
	ret = sdo_crypto_hash(NULL, TEST_BUFF_SZ, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - invalid  hash output buffer size*/
	ret = sdo_crypto_hash(test_buff1, 0, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - invalid  hash output buffer */
	ret = sdo_crypto_hash(test_buff1, TEST_BUFF_SZ, NULL,
			      hash1->hash->byte_sz);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Negative case - zero hash buffer size. */
	ret = sdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash1->hash->bytes, 0);
	TEST_ASSERT_NOT_EQUAL(0, ret);

	/* Positive case. */
	ret = sdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash1->hash->bytes,
			      hash1->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	/* Using the same buffer, we expect the same result. */
	ret = sdo_crypto_hash(test_buff1, TEST_BUFF_SZ, hash2->hash->bytes,
			      hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hash1->hash_type, hash2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hash1->hash->byte_sz, hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(hash1->hash->bytes, hash2->hash->bytes,
				      hash1->hash->byte_sz);

	/* Using a different buffer, we expect a different result. */
	ret = sdo_crypto_hash(test_buff2, TEST_BUFF_SZ, hash2->hash->bytes,
			      hash2->hash->byte_sz);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(hash1->hash_type, hash2->hash_type);
	TEST_ASSERT_EQUAL_UINT(hash1->hash->byte_sz, hash2->hash->byte_sz);

	flag = true;
	for (i = 0; (uint8_t)i < hash1->hash->byte_sz; i++) {
		flag &= (hash1->hash->bytes[i] == hash2->hash->bytes[i]);
	}

	TEST_ASSERT_FALSE(flag);
	sdo_hash_free(hash1);
	sdo_hash_free(hash2);
	sdo_crypto_close();
}

#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hmac(void)
#else
TEST_CASE("crypto_support_make_hmac", "[crypto_support][sdo]")
#endif
{
	int ret;
	int i;
	bool flag;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	sdo_hash_t *hmac2 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

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

	sdo_hash_free(hmac1);
	sdo_hash_free(hmac2);
	sdo_crypto_close();
}
#ifndef TARGET_OS_FREERTOS
void test_crypto_support_make_hmac_chained(void)
#else
TEST_CASE("crypto_support_make_hmac_chained", "[crypto_support][sdo]")
#endif
{
	int ret;
	sdo_hash_t *hmac1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	sdo_hash_t *hmac2 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	sdo_hash_t *chain1 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);
	sdo_hash_t *chain2 =
	    sdo_hash_alloc(SDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SZ);

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

	sdo_hash_free(hmac1);
	sdo_hash_free(hmac2);
	sdo_hash_free(chain2);
	sdo_hash_free(chain1);
	sdo_crypto_close();
}
