/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for RSA abstraction routines of SDO library.
 */
#include "test_RSARoutines.h"
#include "safe_lib.h"

//#define HEXDEBUG 1

#ifdef TARGET_OS_LINUX
/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_rsaencrypt(void);
void test_rsasigverification(void);
void showPK(sdo_public_key_t *pk);
RSA *generateRSA_key(void);
int sha256_sign(unsigned char *msg, unsigned int mlen, unsigned char *out,
		unsigned int *outlen, RSA *r);
sdo_public_key_t *getSDOpk(RSA *r);

/*** Unity functions. ***/
void set_up(void)
{
}

void tear_down(void)
{
}
#endif

#ifdef PK_ENC_RSA
/*** Wrapper functions (function stubbing). ***/

static sdo_byte_array_t *getcleartext(int length)
{
	sdo_byte_array_t *cleartext = sdo_byte_array_alloc(length);
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

void showPK(sdo_public_key_t *pk)
{
	char buf[BUFF_SIZE_1K_BYTES] = {0};
	char *ret_buf = NULL;
	TEST_ASSERT_NOT_NULL(pk);
	ret_buf = sdo_public_key_to_string(pk, buf, sizeof buf);
	TEST_ASSERT_NOT_NULL(ret_buf);
	printf("PK: %s\n", ret_buf);
}

#ifdef USE_OPENSSL
RSA *generateRSA_key(void)
{
	int ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	unsigned long e = RSA_F4;
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
#ifdef HEXDEBUG
	const BIGNUM *r_n = NULL;
	const BIGNUM *r_e = NULL;
	RSA_get0_key(r, &r_n, &r_e, NULL);
	hexdump("generateRSA_key:key1", (unsigned char *)r_n,
		BN_num_bytes(r_n));
	hexdump("generateRSA_key:key2", (unsigned char *)r_e,
		BN_num_bytes(r_e));
#endif
	BN_free(bne);
	return r;
}

int sha256_sign(unsigned char *msg, unsigned int mlen, unsigned char *out,
		unsigned int *outlen, RSA *r)
{
	unsigned char hash[SHA256_DIGEST_SIZE];

	if (SHA256(msg, mlen, hash) == NULL)
		return -1;
#ifdef HEXDEBUG
	hexdump("sha256_sign:MESSAGE", msg, mlen);
	hexdump("sha256_sign:SHA256HASH", hash, SHA256_DIGEST_SIZE);
#endif

	int result =
	    RSA_sign(NID_sha256, hash, SHA256_DIGEST_SIZE, out, outlen, r);

#ifdef HEXDEBUG
	hexdump("sha256_sign:SIGNEDMESSAGE", out, *outlen);
#endif
	return result;
}

sdo_public_key_t *getSDOpk(RSA *r)
{

	const BIGNUM *n = NULL;
	const BIGNUM *d = NULL;
	const BIGNUM *e = NULL;
	int sizeofpkmodulus = 0;
	unsigned char *pkmodulusbuffer = NULL;

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
	if (pkmodulusbuffer)
		free(pkmodulusbuffer);
	if (!pk || !pk->key1)
		return NULL;
	int pkexponent = BN_num_bytes(e);
	unsigned char *ebuff = malloc(pkexponent);
	if (!ebuff) {
		sdo_public_key_free(pk);
		return NULL;
	}

	if (BN_bn2bin(e, ebuff)) {
		pk->key2 =
		    sdo_byte_array_alloc_with_byte_array(ebuff, pkexponent);

#ifdef HEXDEBUG
		hexdump("key1", (unsigned char *)pk->key1, sizeofpkmodulus);
		hexdump("key2", (unsigned char *)pk->key2, pkexponent);
		showPK(pk);
#endif

		if (!pk->key2) {
			sdo_public_key_free(pk);
			pk = NULL;
		}
	} else {
		sdo_public_key_free(pk);
		pk = NULL;
	}
	free(ebuff);
	return pk;
}
#endif // USE_OPENSSL

#ifdef USE_MBEDTLS
int generateRSA_key(mbedtls_rsa_context *rsa)
{
	int ret;
	char *pers = "rsa_genkey";
	size_t pers_len = strnlen_s(pers, SDO_MAX_STR_SIZE);
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
					 &entropy, (const unsigned char *)pers,
					 pers_len)) != 0) {
		return -1;
	}

	mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

	if ((ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg,
				       KEY_SIZE, EXPONENT)) != 0) {
		return -1;
	}

#ifdef HEXDEBUG
	if (0 == mbedtls_rsa_check_pubkey(rsa)) {
		hexdump("generateRSA_key:key1", (unsigned char *)rsa->N.p,
			rsa->len);
		hexdump("generateRSA_key:key2", (unsigned char *)rsa->E.p,
			mbedtls_mpi_size((const mbedtls_mpi *)&rsa->E));
		/*  for debugging only
		size_t olen;
		int buflen = 1024;
		char buf[buflen];
		mbedtls_mpi_write_string(&(rsa->N), 16, buf, buflen, &olen);
		printf("\nmodulus(M): %s \n stringlen:%d", buf,(int)olen);
		mbedtls_mpi_write_string(&(rsa->E), 16, buf, buflen, &olen);
		printf("\nexponent(E): %s \n stringlen:%d", buf,(int)olen);
		*/
	}
#endif

	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	return 0;
}

int sha256_sign(unsigned char *msg, unsigned int mlen, unsigned char *out,
		unsigned int *outlen, mbedtls_rsa_context *rsa)
{
	int ret = 1;
	unsigned char hash[SHA256_DIGEST_SIZE];
	unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
	if ((ret = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg,
			      mlen, hash)) != 0) {
		return -1;
	}
#ifdef HEXDEBUG
	hexdump("sha256_sign: MESSAGE", msg, mlen);
	hexdump("sha256_sign: SHA256HASH", hash, SHA256_DIGEST_SIZE);
#endif

	if ((ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL, MBEDTLS_RSA_PRIVATE,
					  MBEDTLS_MD_SHA256, SHA256_DIGEST_SIZE,
					  hash, buf)) != 0) {
		return -1;
	}
#ifdef HEXDEBUG
	hexdump("sha256_sign: SIGNED_MESSAGE", buf, rsa->len);
#endif
	*outlen = rsa->len;
	if (memcpy_s(out, (size_t)rsa->len, buf, (size_t)rsa->len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		return -1;
	}
	return 1;
}

sdo_public_key_t *getSDOpk(mbedtls_rsa_context *pkey)
{
	/* convert mbedtls struct to SDO struct   */
	int sizeofpkmodulus = pkey->len;
	unsigned char *pkmodulusbuffer = malloc(sizeofpkmodulus);
	if (!pkmodulusbuffer)
		return NULL;
	mbedtls_mpi_write_binary(&(pkey->N), (unsigned char *)pkmodulusbuffer,
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
	mbedtls_mpi_write_binary(&(pkey->E), (unsigned char *)ebuff, len);
	pk->key2 = sdo_byte_array_alloc_with_byte_array((uint8_t *)&ebuff, len);

#ifdef HEXDEBUG
	hexdump("key1", (unsigned char *)pk->key1, pkey->len);
	if (pk->key2)
		hexdump("key2", (unsigned char *)pk->key2, len);
	showPK(pk);
#endif

	return pk;
}
#endif // USE_MBEDTLS
#endif // ifdef PK_ENC_RSA

/*** Test functions. ***/

#if !defined(PK_ENC_RSA)
#ifndef TARGET_OS_FREERTOS
void test_rsaencrypt(void)
#else
TEST_CASE("rsaencrypt", "[RSARoutines][sdo]")
#endif
{
	TEST_IGNORE();
}

#ifndef TARGET_OS_FREERTOS
void test_rsasigverification(void)
#else
TEST_CASE("rsasigverification", "[RSARoutines][sdo]")
#endif
{
	TEST_IGNORE();
}

#else

#ifndef TARGET_OS_FREERTOS
void test_rsaencrypt(void)
#else
TEST_CASE("rsaencrypt", "[RSARoutines][sdo]")
#endif
{
	int32_t cipher_length = 0;
	uint8_t *cipher_text = NULL;
	int ret;
	sdo_byte_array_t *testdata = getcleartext(BUFF_SIZE_128_BYTES);
	TEST_ASSERT_NOT_NULL(testdata);
#ifdef USE_OPENSSL
	RSA *avalidkey = generateRSA_key();
	TEST_ASSERT_NOT_NULL(avalidkey);
	sdo_public_key_t *pk = getSDOpk(avalidkey);
	TEST_ASSERT_NOT_NULL(pk);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_context avalidkey;
	ret = generateRSA_key(&avalidkey);
	TEST_ASSERT_EQUAL_INT(0, ret);
	sdo_public_key_t *pk = getSDOpk(&avalidkey);
	TEST_ASSERT_NOT_NULL(pk);
#endif

	/* Get cypher text length required by sending NULL as cypher_text */
	cipher_length = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    testdata->bytes, testdata->byte_sz, NULL, (uint32_t)cipher_length,
	    pk->key1->bytes, (uint32_t)pk->key1->byte_sz, pk->key2->bytes,
	    (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, cipher_length,
				      "Cypher size get failed");

	cipher_text = (uint8_t *)malloc(cipher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cipher_text);
	/* positive test case */
	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, (uint32_t)testdata->byte_sz,
	    cipher_text, (uint32_t)cipher_length, pk->key1->bytes,
	    pk->key1->byte_sz, pk->key2->bytes, (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "RSA Encryption Failed");
#ifdef HEXDEBUG
	hexdump("CYPHERTEXT", cipher_text, cipher_length);
#endif
	if (cipher_text != NULL) {
		free(cipher_text);
		cipher_text = NULL;
	}

	/* force a failure by using an invalid key */

	/*Negative test cases */

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    NULL, (uint32_t)testdata->byte_sz, cipher_text,
	    (uint32_t)cipher_length, pk->key1->bytes, pk->key1->byte_sz,
	    pk->key2->bytes, (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, 0, cipher_text, (uint32_t)cipher_length,
	    pk->key1->bytes, pk->key1->byte_sz, pk->key2->bytes,
	    (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, (uint32_t)testdata->byte_sz,
	    cipher_text, (uint32_t)cipher_length, NULL,
	    (uint32_t)pk->key1->byte_sz, pk->key2->bytes,
	    (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, (uint32_t)testdata->byte_sz,
	    cipher_text, (uint32_t)cipher_length, pk->key1->bytes, 0,
	    pk->key2->bytes, (uint32_t)pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, (uint32_t)testdata->byte_sz,
	    cipher_text, (uint32_t)cipher_length, pk->key1->bytes,
	    (uint32_t)pk->key1->byte_sz, NULL, pk->key2->byte_sz);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	ret = crypto_hal_rsa_encrypt(
	    (uint8_t)SDO_PK_HASH_SHA256, (uint8_t)pk->pkenc, (uint8_t)pk->pkalg,
	    (uint8_t *)testdata->bytes, (uint32_t)testdata->byte_sz,
	    cipher_text, (uint32_t)cipher_length, pk->key1->bytes,
	    (uint32_t)pk->key1->byte_sz, pk->key2->bytes, 0);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "RSA Encryption Failed");

	/* clean up */
	if (cipher_text != NULL) {
		free(cipher_text);
	}
	sdo_byte_array_free(testdata);
	sdo_public_key_free(pk);
#ifdef USE_OPENSSL
	if (avalidkey)
		RSA_free(avalidkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_rsa_free(&avalidkey);
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_rsasigverification(void)
#else
TEST_CASE("rsasigverification", "[RSARoutines][sdo]")
#endif
{
	int result = -1;
	sdo_byte_array_t *testdata = getcleartext(256);
	TEST_ASSERT_NOT_NULL(testdata);
	unsigned int siglen = testdata->byte_sz;
	unsigned char *sigtestdata = malloc(siglen);
	TEST_ASSERT_NOT_NULL(sigtestdata);

#ifdef USE_OPENSSL
	RSA *avalidkey = generateRSA_key();
	TEST_ASSERT_NOT_NULL(avalidkey);

	if (1 == (result = sha256_sign(testdata->bytes, testdata->byte_sz,
				       sigtestdata, &siglen, avalidkey))) {
		TEST_ASSERT_EQUAL(1, result);
		sdo_public_key_t *pk = getSDOpk(avalidkey);
#endif

#ifdef USE_MBEDTLS
		mbedtls_rsa_context avalidkey;
		result = generateRSA_key(&avalidkey);
		TEST_ASSERT_EQUAL(0, result);
		if (1 ==
		    (result = sha256_sign(testdata->bytes, testdata->byte_sz,
					  sigtestdata, &siglen, &avalidkey))) {
			TEST_ASSERT_EQUAL(1, result);
			sdo_public_key_t *pk = getSDOpk(&avalidkey);
#endif

			TEST_ASSERT_NOT_NULL(pk);

			/* test positive outcome */
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    pk->key1->bytes, pk->key1->byte_sz, pk->key2->bytes,
			    pk->key2->byte_sz);

			TEST_ASSERT_EQUAL(0, result);

			/* force a failure by using wrong size signature */
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen - 1,
			    pk->key1->bytes, pk->key1->byte_sz, pk->key2->bytes,
			    pk->key2->byte_sz);
			TEST_ASSERT_NOT_EQUAL(0, result);

#ifdef USE_OPENSSL
			/* force a failure by using another/different key */
			RSA *anotherkey = generateRSA_key();
			TEST_ASSERT_NOT_NULL(anotherkey);
			sdo_public_key_t *anotherpk = getSDOpk(anotherkey);
#endif
#ifdef USE_MBEDTLS
			mbedtls_rsa_context anotherkey;
			result = generateRSA_key(&anotherkey);
			TEST_ASSERT_EQUAL(0, result);
			sdo_public_key_t *anotherpk = getSDOpk(&anotherkey);
#endif
			TEST_ASSERT_NOT_NULL(anotherpk);
			result = crypto_hal_sig_verify(
			    anotherpk->pkenc, anotherpk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    anotherpk->key1->bytes, anotherpk->key1->byte_sz,
			    anotherpk->key2->bytes, anotherpk->key2->byte_sz);
			TEST_ASSERT_NOT_EQUAL(0, result);

			/* force a failure by using a modified/different message
			 */
			crypto_hal_random_bytes(testdata->bytes,
						BUFF_SIZE_8_BYTES);
#ifdef HEXDEBUG
			hexdump("MODIFIED CLEARTEXT", testdata->bytes,
				testdata->byte_sz);
#endif
			result = crypto_hal_sig_verify(
			    pk->pkenc, pk->pkalg, testdata->bytes,
			    testdata->byte_sz, sigtestdata, siglen,
			    pk->key1->bytes, pk->key1->byte_sz, pk->key2->bytes,
			    pk->key2->byte_sz);
			TEST_ASSERT_NOT_EQUAL(0, result);
			/* clean up */
			sdo_byte_array_free(testdata);
			sdo_public_key_free(anotherpk);
#ifdef USE_OPENSSL
			if (anotherkey)
				RSA_free(anotherkey);
#endif
#ifdef USE_MBEDTLS
			mbedtls_rsa_free(&anotherkey);
#endif
			sdo_public_key_free(pk);
		}

#ifdef USE_OPENSSL
		if (avalidkey)
			RSA_free(avalidkey);
#endif
#ifdef USE_MBEDTLS
		mbedtls_rsa_free(&avalidkey);
#endif
		free(sigtestdata);
	}

#endif
