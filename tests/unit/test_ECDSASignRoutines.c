/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for RSA abstraction routines of SDO library.
 */

#include "test_RSARoutines.h"
#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "storage_al.h"

//#define HEXDEBUG 1

#define CLR_TXT_LENGTH BUFF_SIZE_1K_BYTES
#define ECDSA_SIG_MAX_LENGTH 150
#define ECDSA_PK_MAX_LENGTH 200
#define DER_PUBKEY_LEN_MAX 512

#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
void test_sdo_cryptoECDSASign(void);

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
#endif

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

//----------------------------------------------------
#ifdef USE_OPENSSL
static EC_KEY *generateECDSA_key(void)
{
	EC_KEY *eckey = NULL;

#if defined(ECDSA256_DA)
	eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
#elif defined(ECDSA384_DA)
	eckey = EC_KEY_new_by_curve_name(NID_secp384r1);
#endif
	/* For cert signing, we use  the OPENSSL_EC_NAMED_CURVE flag */
	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

	if (eckey)
		if (EC_KEY_generate_key(eckey) == 0) {
			EC_KEY_free(eckey);
			eckey = NULL;
		}
	return eckey;
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
void test_sdo_cryptoECDSASign(void)
#else
TEST_CASE("sdo_cryptoECDSASign", "[ECDSARoutines][sdo]")
#endif
{
	TEST_IGNORE();
}

#else
#ifndef TARGET_OS_FREERTOS
void test_sdo_cryptoECDSASign(void)
#else
TEST_CASE("crypto_hal_ecdsa_sign", "[ECDSARoutines][sdo]")
#endif
{
	int result = -1;
	sdo_byte_array_t *testdata = getcleartext(CLR_TXT_LENGTH);
	TEST_ASSERT_NOT_NULL(testdata);
	size_t siglen = ECDSA_SIG_MAX_LENGTH;
	unsigned char *sigtestdata = malloc(ECDSA_SIG_MAX_LENGTH);
	TEST_ASSERT_NOT_NULL(sigtestdata);
	unsigned char hash[SHA512_DIGEST_SIZE] = {0};
	size_t hash_length = 0;

#if defined(ECDSA256_DA)
	hash_length = SHA256_DIGEST_SIZE;
#elif defined(ECDSA384_DA)
	hash_length = SHA384_DIGEST_SIZE;
#endif

// Create the context & create the key
#ifdef USE_OPENSSL
	EC_KEY *avalidkey = generateECDSA_key();
	TEST_ASSERT_NOT_NULL(avalidkey);
	int privatekey_buflen = hash_length;
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_context ctx_sign = {0};
	result = generateECDSA_key(&ctx_sign);
	TEST_ASSERT_EQUAL(0, result);
	int privatekey_buflen = mbedtls_mpi_size(&ctx_sign.d);
#endif
	// Extracting private key from mbedtls structure
	unsigned char *privatekey = malloc(privatekey_buflen);
	TEST_ASSERT_NOT_NULL(privatekey);
	memset_s(privatekey, 0, privatekey_buflen);

// store private key for later use in pem /bin format
#if defined(ECDSA_PEM)
	BIO *outbio = BIO_new(BIO_s_mem());
	TEST_ASSERT_NOT_NULL(outbio);
	EVP_PKEY *privkey = EVP_PKEY_new();
	TEST_ASSERT_NOT_NULL(privkey);

	//	if (!EVP_PKEY_assign_EC_KEY(privkey,avalidkey))
	if (!EVP_PKEY_set1_EC_KEY(privkey, avalidkey))
		printf(" assigning ECC key to EVP_PKEY fail.\n");
	const EC_GROUP *group = EC_KEY_get0_group(avalidkey);

	PEM_write_bio_ECPKParameters(outbio, group);
	if (!PEM_write_bio_ECPrivateKey(outbio, avalidkey, NULL, NULL, 0, 0,
					NULL))
		BIO_printf(outbio,
			   "Error writing private key data in PEM format");

	BUF_MEM *bptr = NULL;
	BIO_get_mem_ptr(outbio, &bptr);

	printf("buffer :\n %s", bptr->data);
	result = sdo_blob_write((char *)ECDSA_PRIVKEY, SDO_SDK_RAW_DATA,
				(const uint8_t *)bptr->data, bptr->length);
	TEST_ASSERT_NOT_EQUAL(-1, result);

#else // save in bin format

#ifdef USE_OPENSSL
	if (BN_bn2bin(EC_KEY_get0_private_key((const EC_KEY *)avalidkey),
		      privatekey))
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
	result = sdo_blob_write((char *)ECDSA_PRIVKEY, SDO_SDK_RAW_DATA,
				privatekey, privatekey_buflen);
	TEST_ASSERT_NOT_EQUAL(-1, result);

#endif // save privkey in pem/bin format

	// Signature will be received as a part of sigtestdata.
	result = crypto_hal_ecdsa_sign(testdata->bytes, testdata->byte_sz, sigtestdata,
				&siglen);
	TEST_ASSERT_EQUAL(0, result);

#ifdef USE_OPENSSL
	// create the hash of the plaintext
//		if (hash_length == SHA256_DIGEST_SIZE)
#if defined(ECDSA256_DA)
	if (SHA256((const unsigned char *)testdata->bytes, testdata->byte_sz,
		   hash) == NULL)
		result = -1;
#elif defined(ECDSA384_DA)
	if (SHA384((const unsigned char *)testdata->bytes, testdata->byte_sz,
		   hash) == NULL)
		result = -1;
#endif
	TEST_ASSERT_EQUAL(0, result);

	// verify the signature.
	if (1 != ECDSA_verify(0, hash, hash_length, sigtestdata, siglen,
			      avalidkey)) {
		LOG(LOG_ERROR, "ECDSA Sig verification failed\n");
		result = -1;
	}

	TEST_ASSERT_EQUAL(0, result);

	// Negative test case
	sigtestdata[4] = 'a';
	if (1 != ECDSA_verify(0, hash, hash_length, sigtestdata, siglen,
			      avalidkey)) {
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
	result = crypto_hal_ecdsa_sign(NULL, testdata->byte_sz, sigtestdata, &siglen);
	TEST_ASSERT_NOT_EQUAL(0, result);

#ifdef USE_OPENSSL
#if defined(ECDSA_PEM)
	EVP_PKEY_free(privkey);
	BIO_free_all(outbio);
#endif
	if (avalidkey)
		EC_KEY_free(avalidkey);
#endif
#ifdef USE_MBEDTLS
	mbedtls_ecdsa_free(&ctx_sign);
#endif
	free(sigtestdata);
	free(privatekey);
	sdo_byte_array_free(testdata);
}
#endif
