/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for ECDSA signature verification abstraction routines of FDO library.
 */

#include "safe_lib.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"
#include "storage_al.h"
#include "unity.h"

//#define HEXDEBUG 1

#define CLR_TXT_LENGTH BUFF_SIZE_1K_BYTES
#define ECDSA_SIG_MAX_LENGTH 150
#define ECDSA_PK_MAX_LENGTH 200
#define DER_PUBKEY_LEN_MAX 512

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_ecdsa256sigverification(void);
void test_ecdsa384sigverification(void);

/*** Unity functions. ***/
void set_up(void)
{
}

void tear_down(void)
{
}
#endif


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

	EC_KEY *eckey = (EC_KEY *)ctx;
	len = i2o_ECPublicKey(eckey, NULL);

	/* pub_copy is required, because i2o_ECPublicKey alters the input
	 * pointer */
	if (i2o_ECPublicKey(eckey, &pub_copy) != len) {
		printf("PUB KEY TO DATA FAIL\n");
	}
#endif
	printf("%s %s len:%ld\n", title, bytes_to_hex(buf, len), len);
}
#endif // HEXDEBUG

static fdo_byte_array_t *getcleartext(int length)
{
	fdo_byte_array_t *cleartext = fdo_byte_array_alloc(length);
	if (!cleartext)
		return NULL;
	int i = length;
	random_init();
	fdo_crypto_random_bytes(cleartext->bytes, cleartext->byte_sz);
	while (i) {
		cleartext->bytes[i - 1] = 'A' + (cleartext->bytes[i - 1] % 26);
		i--;
	}
#ifdef HEXDEBUG
	hexdump("CLEARTEXT", cleartext->bytes, cleartext->byte_sz);
#endif
	return cleartext;
}
#ifdef HEXDEBUG
static void showPK(fdo_public_key_t *pk)
{
	char buf[ECDSA_PK_MAX_LENGTH];
	printf("PK: %s\n", fdo_public_key_toString(pk, buf, sizeof buf));
}
#endif
//----------------------------------------------------
#ifdef USE_OPENSSL
static EC_KEY *generateECDSA_key(int curve)
{
	EC_KEY *eckey = NULL;

	if (curve == 256)
		eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	else if (curve == 384)
		eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
	else
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

// return 1 on success; 0/-1 for failure
static int sha_ECCsign(int curve, unsigned char *msg, unsigned int mlen,
		       unsigned char *out, unsigned int *outlen, EC_KEY *eckey)
{
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	size_t hashlength = 0;
	unsigned char *signature = NULL;
	unsigned int siglen = 0;
	// ECDSA_sign return 1 on success, 0 on failure
	int result = 0;
	ECDSA_SIG *sig = NULL;
	unsigned char *sig_r = NULL;
	int sig_r_len = 0;
	unsigned char *sig_s = NULL;
	int sig_s_len = 0;

	siglen = ECDSA_size(eckey);
	signature = OPENSSL_malloc(siglen);

	if (curve == 256) {
		if (SHA256(msg, mlen, hash) == NULL)
			goto done;
		hashlength = SHA256_DIGEST_SIZE;
	} else if (curve == 384) {
		if (SHA384(msg, mlen, hash) == NULL)
			goto done;
		hashlength = SHA384_DIGEST_SIZE;
		// ECDSA_sign return 1 on success, 0 on failure

	} else {
		goto done;
	}

#ifdef HEXDEBUG
	hexdump("sha_sign:MESSAGE", msg, mlen);
	hexdump("sha_sign:SHAHASH", hash, hashlength);
#endif

	sig = ECDSA_do_sign(hash, hashlength, eckey);
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

	*outlen = sig_r_len + sig_s_len;;
	if (0 != memcpy_s(out, *outlen, (char *)sig_r,
		     (size_t)sig_r_len)) {
		goto done;
	}
	if (0 != memcpy_s(out + sig_r_len, *outlen, (char *)sig_s,
		     (size_t)sig_s_len)) {
		goto done;
	}
	result = 1;
#ifdef HEXDEBUG
	hexdump("sha256_sign:SIGNEDMESSAGE", out, *outlen);
#endif
done:
	OPENSSL_free(signature);
	if (sig) {
		ECDSA_SIG_free(sig);
	}
	if (sig_r) {
		fdo_free(sig_r);
	}
	if (sig_s) {
		fdo_free(sig_s);
	}
	return result;
}

static fdo_public_key_t *getFDOpk(int curve, EC_KEY *eckey)
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

	const EC_POINT *pub = EC_KEY_get0_public_key(eckey);
	TEST_ASSERT_NOT_NULL_MESSAGE(pub, "Failed to get ECPOINT\n");
	if (EC_POINT_get_affine_coordinates_GFp(ecgroup, pub, x, y, NULL)) {
		x_len = BN_num_bytes(x);
		y_len = BN_num_bytes(y);
		key_buf_len = x_len + y_len;
		key_buf = fdo_alloc(key_buf_len);
		TEST_ASSERT_NOT_NULL(key_buf);
        BN_bn2bin(x, key_buf);
		BN_bn2bin(y, key_buf + x_len);

#if defined(ECDSA256_DA)
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
				  FDO_CRYPTO_PUB_KEY_ENCODING_X509, key_buf_len,
				  key_buf);
#else
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
				  FDO_CRYPTO_PUB_KEY_ENCODING_X509, key_buf_len,
				  key_buf);
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

#ifdef HEXDEBUG
	dump_pubkey(" + Public key: ", eckey);
	hexdump("key1", (unsigned char *)pk->key1, pub_len);
	if (pk->key2)
		showPK(pk);
#endif

	return pk;
}
#endif // USE_OPENSSL

#ifdef USE_MBEDTLS

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
					 &entropy, (const unsigned char *)pers,
					 pers_len)) != 0) {
		goto error;
	}

	mbedtls_ecdsa_init(ctx_sign);
	if (curve == 256) {
		if ((ret = mbedtls_ecdsa_genkey(ctx_sign, EC256PARAMS,
						mbedtls_ctr_drbg_random,
						&ctr_drbg)))
			goto error;
	} else if (curve == 384) {
		if ((ret = mbedtls_ecdsa_genkey(ctx_sign, EC384PARAMS,
						mbedtls_ctr_drbg_random,
						&ctr_drbg)))
			goto error;
	} else {
		goto error;
	}

	//	mbedtls_printf( " ok (key size: %d bits)\n", (int)
	// ctx_sign->grp.pbits);
	ret = 0;
error:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return ret;
}
// return 1 for success; return 0/-1 on error
static int sha_ECCsign(int curve, unsigned char *msg, unsigned int mlen,
		       unsigned char *out, unsigned int *outlen,
		       mbedtls_ecdsa_context *ctx_sign)
{
	int ret = 0;
	mbedtls_ctr_drbg_context ctr_drbg;
	unsigned char hash[SHA512_DIGEST_SIZE];
	size_t hash_length = 0;
	unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
	size_t sig_len = 0;
	mbedtls_md_type_t mbedhash_type = MBEDTLS_MD_NONE;

	if (NULL == msg || !mlen || NULL == out || !outlen || NULL == ctx_sign)
		return -1;

	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (curve == 256) {
		mbedhash_type = MBEDTLS_MD_SHA256;
		hash_length = SHA256_DIGEST_SIZE;
	} else {
		mbedhash_type = MBEDTLS_MD_SHA384;
		hash_length = SHA384_DIGEST_SIZE;
	}

	if ((ret = mbedtls_md(mbedtls_md_info_from_type(mbedhash_type), msg,
			      mlen, hash)) != 0)
		return 0;
#ifdef HEXDEBUG
	hexdump("sha_sign: MESSAGE", msg, mlen);
	hexdump("sha_sign: SHAHASH", hash, hash_length);
#endif
	if ((ret = mbedtls_ecdsa_write_signature(
		 ctx_sign, mbedhash_type, hash, hash_length, sig, &sig_len,
		 mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		LOG(LOG_ERROR, "signature creation failed ret:%d\n", ret);
		return 0;
	}

#ifdef HEXDEBUG
	hexdump("sha_sign: SIGNED_MESSAGE", sig, sig_len);
#endif
	*outlen = sig_len;
	if (memcpy_s(out, (size_t)sig_len, sig, (size_t)sig_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}
	mbedtls_ctr_drbg_free(&ctr_drbg);
	return 1;
}

static fdo_public_key_t *getFDOpk(int curve, mbedtls_ecdsa_context *ctx_sign)
{
	/* convert mbedtls struct to FDO struct   */
	unsigned char buf[ECDSA_PK_MAX_LENGTH];
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

	if (curve == 256)
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp256,
					  FDO_CRYPTO_PUB_KEY_ENCODING_X509,
					  buflen, buf);
	else
		pk = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
					  FDO_CRYPTO_PUB_KEY_ENCODING_X509,
					  buflen, buf);
	if (!pk || !pk->key1) {
		return NULL;
	}

	pk->key2 = NULL;

#ifdef HEXDEBUG
	dump_pubkey(" + Public key: ", ctx_sign);
	hexdump("key1", (unsigned char *)pk->key1, buflen);
	showPK(pk);
#endif

	return pk;
}
#endif // USE_MBEDTLS

static void ec_sig_verification(int curve)
{
	int result = -1;
	fdo_byte_array_t *testdata = getcleartext(CLR_TXT_LENGTH);
	TEST_ASSERT_NOT_NULL(testdata);
	unsigned int siglen = ECDSA_SIG_MAX_LENGTH;
	unsigned char *sigtestdata = fdo_alloc(siglen);
	TEST_ASSERT_NOT_NULL(sigtestdata);
	fdo_public_key_t *pk = NULL;
	unsigned char key_buf[DER_PUBKEY_LEN_MAX] = {0};
	int key_buf_len = 0;
//	int curve = 256;
#ifdef USE_OPENSSL
	unsigned char *pubkey = key_buf;
	EC_KEY *avalidkey = generateECDSA_key(curve);
	TEST_ASSERT_NOT_NULL(avalidkey);

	if (1 ==
	    (result = sha_ECCsign(curve, testdata->bytes, testdata->byte_sz,
				  sigtestdata, &siglen, avalidkey))) {
		TEST_ASSERT_EQUAL(1, result);
		key_buf_len = i2d_EC_PUBKEY(avalidkey, &pubkey);
		TEST_ASSERT_NOT_EQUAL_MESSAGE(0, key_buf_len,
					      "DER encoding failed!");
		pk = getFDOpk(curve, avalidkey);
#endif

#ifdef USE_MBEDTLS
		mbedtls_ecdsa_context avalidkey;
		result = generateECDSA_key(curve, &avalidkey);
		TEST_ASSERT_EQUAL(0, result);

		LOG(LOG_INFO, "Signing message...\n");
		if (1 == (result = sha_ECCsign(curve, testdata->bytes,
					       testdata->byte_sz, sigtestdata,
					       &siglen, &avalidkey))) {
			TEST_ASSERT_EQUAL(1, result);
			pk = getFDOpk(curve, &avalidkey);

			/* convert ecdsa_context to pk_context */
			mbedtls_pk_context pk_ctx;
			pk_ctx.pk_info =
			    mbedtls_pk_info_from_type(MBEDTLS_PK_NONE);

			result = mbedtls_pk_setup(
			    &pk_ctx,
			    mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
			TEST_ASSERT_EQUAL(0, result);

			mbedtls_ecp_copy(&(mbedtls_pk_ec(pk_ctx)->Q),
					 &(avalidkey.Q));
			mbedtls_mpi_copy(&(mbedtls_pk_ec(pk_ctx)->d),
					 &(avalidkey.d));
			mbedtls_pk_ec(pk_ctx)->grp = avalidkey.grp;

			unsigned char temp[DER_PUBKEY_LEN_MAX] = {0};
			unsigned char *p_temp = temp;

			key_buf_len = mbedtls_pk_write_pubkey_der(
			    &pk_ctx, p_temp, DER_PUBKEY_LEN_MAX);

			/* fail if writing pubkey to der failed */
			if (key_buf_len <= 0)
				TEST_ASSERT_EQUAL(0, 1);

			/* mbedtls_pk_write_pubkey_der writes data at the end of
			 * the buffer! */
			result =
			    memcpy_s((uint8_t *)key_buf, key_buf_len,
				     (uint8_t *)(p_temp + (DER_PUBKEY_LEN_MAX -
							   key_buf_len)),
				     key_buf_len);
			TEST_ASSERT_EQUAL(0, result);

#endif
			TEST_ASSERT_NOT_NULL(pk);

			/* test positive outcome */
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    pk->key1->bytes, pk->key1->byte_sz, NULL, 0);

			TEST_ASSERT_EQUAL(0, result);

			/* force a failure by using wrong size signature */
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen - 1,
			    pk->key1->bytes, pk->key1->byte_sz, NULL, 0);
			TEST_ASSERT_NOT_EQUAL(0, result);

			fdo_public_key_t *anotherpk = NULL;
#ifdef USE_OPENSSL
			/* force a failure by using another/different key */
			EC_KEY *anotherkey = generateECDSA_key(curve);
			TEST_ASSERT_NOT_NULL(anotherkey);
			anotherpk = getFDOpk(curve, anotherkey);
#endif
#ifdef USE_MBEDTLS
			mbedtls_ecdsa_context anotherkey;
			result = generateECDSA_key(curve, &anotherkey);
			TEST_ASSERT_EQUAL(0, result);
			anotherpk = getFDOpk(curve, &anotherkey);
#endif
			TEST_ASSERT_NOT_NULL(anotherpk);
			result = crypto_hal_sig_verify(
			    anotherpk->pkenc, anotherpk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    anotherpk->key1->bytes, anotherpk->key1->byte_sz,
			    NULL, 0);
			TEST_ASSERT_NOT_EQUAL(0, result);

			/* force a failure by using a modified/different message
			 */
			fdo_crypto_random_bytes(testdata->bytes, 8);
#ifdef HEXDEBUG
			hexdump("MODIFIED CLEARTEXT", testdata->bytes,
				testdata->byte_sz);
#endif
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    pk->key1->bytes, pk->key1->byte_sz, NULL, 0);
			TEST_ASSERT_NOT_EQUAL(0, result);
			/* clean up */
			fdo_public_key_free(anotherpk);
#ifdef USE_OPENSSL
			if (anotherkey)
				EC_KEY_free(anotherkey);
#endif
#ifdef USE_MBEDTLS
			mbedtls_ecdsa_free(&anotherkey);
#endif
			fdo_public_key_free(pk);
		}

#ifdef USE_OPENSSL
		if (avalidkey) {
			EC_KEY_free(avalidkey);
		}
#endif
#ifdef USE_MBEDTLS
		mbedtls_ecdsa_free(&avalidkey);
#endif
		fdo_byte_array_free(testdata);
		free(sigtestdata);
	}

/*** Test functions. ***/
#ifndef TARGET_OS_FREERTOS
void test_ecdsa256sigverification(void)
#else
TEST_CASE("ecdsa256sigverification", "[ECDSARoutines][fdo]")
#endif
{
	//TO-DO: Update test case for X509-encoded public key types
	TEST_IGNORE();
#ifndef ECDSA256_DA
	TEST_IGNORE();
#endif
	ec_sig_verification(256);
}

#ifndef TARGET_OS_FREERTOS
void test_ecdsa384sigverification(void)
#else
TEST_CASE("ecdsa384sigverification", "[ECDSARoutines][fdo]")
#endif
{
	TEST_IGNORE();
#ifdef ECDSA256_DA
	TEST_IGNORE();
#endif
	ec_sig_verification(384);
}

