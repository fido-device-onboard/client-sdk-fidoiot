/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for crypto utility APIs of FDO library.
 */

#include <stdbool.h>
#include "safe_lib.h"
#include "fdotypes.h"
#include "util.h"
#include <stdlib.h>
#include "unity.h"
#include "safe_mem_lib.h"
#include "crypto_utils.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"

#ifdef TARGET_OS_LINUX
/*
 #define HEXDEBUG 1
*/

/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
int __wrap_malloc(size_t size);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value);
errno_t __wrap_memcpy_s(void *dest, rsize_t dmax, const void *src,
			rsize_t smax);
fdo_hash_t *__wrap_fdo_hash_alloc(int hash_type, int size);
void __wrap_fdo_hash_free(fdo_hash_t *hp);
int __wrap_crypto_hal_hmac(uint8_t hmac_type, uint8_t *buffer,
			   size_t buffer_length, uint8_t *output,
			   size_t output_length, uint8_t *key,
			   size_t key_length);
void test_aes_encrypt_packet(void);
void test_aes_decrypt_packet(void);

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
#endif

static uint8_t *get_randomiv(void)
{
	uint8_t *iv = malloc(FDO_AES_IV_SIZE * sizeof(char));
	if (!iv)
		return NULL;
	fdo_crypto_random_bytes(iv, FDO_AES_IV_SIZE);
	return iv;
}

#ifdef TARGET_OS_FREERTOS
extern bool g_malloc_fail;
bool g_memset_fail;
#endif

#ifdef TARGET_OS_LINUX
bool g_malloc_fail = false;
int __real_malloc(size_t size);
int __wrap_malloc(size_t size)
{
	if (g_malloc_fail)
		return 0;
	else
		return __real_malloc(size);
}

bool g_memset_fail = false;
errno_t __real_memset_s(void *dest, rsize_t len, uint8_t value);
errno_t __wrap_memset_s(void *dest, rsize_t len, uint8_t value)
{
	if (g_memset_fail)
		return -1;
	else
		return __real_memset_s(dest, len, value);
}
#endif

bool memcpy_fail_case = false;
errno_t __real_memcpy_s(void *dest, rsize_t dmax, const void *src,
			rsize_t smax);
errno_t __wrap_memcpy_s(void *dest, rsize_t dmax, const void *src, rsize_t smax)
{
	if (memcpy_fail_case)
		return -1;
	else
		return __real_memcpy_s(dest, dmax, src, smax);
}

bool hash_alloc_fail_case = false;
fdo_hash_t *__real_fdo_hash_alloc(int hash_type, int size);
fdo_hash_t *__wrap_fdo_hash_alloc(int hash_type, int size)
{
	if (hash_alloc_fail_case)
		return NULL;
	else
		return __real_fdo_hash_alloc(hash_type, size);
}

bool hash_free_fail_case = false;
void __real_fdo_hash_free(fdo_hash_t *hp);
void __wrap_fdo_hash_free(fdo_hash_t *hp)
{
	if (hash_free_fail_case)
		return;
	else
		__real_fdo_hash_free(hp);
}

bool hmac_fail_case = false;
int __real_crypto_hal_hmac(uint8_t hmac_type, uint8_t *buffer,
			   size_t buffer_length, uint8_t *output,
			   size_t output_length, uint8_t *key,
			   size_t key_length);
int __wrap_crypto_hal_hmac(uint8_t hmac_type, uint8_t *buffer,
			   size_t buffer_length, uint8_t *output,
			   size_t output_length, uint8_t *key,
			   size_t key_length)
{
	if (hmac_fail_case)
		return -1;
	else
		return __real_crypto_hal_hmac(hmac_type, buffer, buffer_length,
					      output, output_length, key,
					      key_length);
}

/**
 * Generate a random text of size provided in input.
 *
 * @param length
 *        Length of text to be generated.
 * @return ret
 *        Pointer to the string containing random text.
 */
static fdo_byte_array_t *getcleartext(int length)
{
	fdo_byte_array_t *cleartext = fdo_byte_array_alloc(length);
	if (!cleartext)
		return NULL;
	fdo_crypto_random_bytes(cleartext->bytes, cleartext->byte_sz);
/*int i = length;
while (i) {
	i--;
	cleartext->bytes[i] = 'A' + (cleartext->bytes[i] % 26);
}*/
#ifdef HEXDEBUG
	hexdump("CLEARTEXT", cleartext->bytes, cleartext->byte_sz);
#endif
	return cleartext;
}

/**
 * Generate a random key of size provided in input.
 *
 * @param length
 *    Length of text to be generated.
 * @return ret
 *        Pointer to the Byte_array containing key.
 */
static fdo_byte_array_t *getkey(int length)
{
	fdo_byte_array_t *cleartext = NULL;
	cleartext = fdo_byte_array_alloc(length);
	if (!cleartext)
		return NULL;
	if (0 != fdo_crypto_random_bytes(cleartext->bytes, cleartext->byte_sz))
		return NULL;
#ifdef HEXDEBUG
	hexdump("KEY", cleartext->bytes, cleartext->byte_sz);
#endif
	return cleartext;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("aes_encrypt_packet", "[crypto_utils][fdo]")
#else
void test_aes_encrypt_packet(void)
#endif
{
	int ret = 0;
	fdo_encrypted_packet_t *cipher_txt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_aes_keyset_t *keyset = fdo_alloc(sizeof(fdo_aes_keyset_t));
	fdo_encrypted_packet_t *last_pkt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_byte_array_t *clear_txt = getcleartext(PLAIN_TEXT_SIZE);

	TEST_ASSERT_NOT_NULL(keyset);
	TEST_ASSERT_NOT_NULL(last_pkt);
	TEST_ASSERT_NOT_NULL(cipher_txt);
	TEST_ASSERT_NOT_NULL(clear_txt);

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	keyset->sek = getkey(FDO_AES_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->sek);

	keyset->svk = getkey(HMAC_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->svk);

	/* Positive Test Case */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	TEST_ASSERT_NOT_NULL(cipher_txt->em_body);
	fdo_byte_array_free(cipher_txt->em_body);
	fdo_hash_free(cipher_txt->hmac);

	/* Positive Test Case */
	last_pkt->offset = 10;
	last_pkt->hmac =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SIZE);
	TEST_ASSERT_NOT_NULL(last_pkt->hmac);
	ret = crypto_hal_hmac(last_pkt->hmac->hash_type, clear_txt->bytes,
			      PLAIN_TEXT_SIZE, last_pkt->hmac->hash->bytes,
			      last_pkt->hmac->hash->byte_sz, keyset->svk->bytes,
			      keyset->svk->byte_sz);

	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "HMAC Generation Failed");

	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	last_pkt->offset = 0;
	if (cipher_txt->hmac) {
		fdo_hash_free(cipher_txt->hmac);
		cipher_txt->hmac = NULL;
	}
	if (cipher_txt->em_body) {
		fdo_byte_array_free(cipher_txt->em_body);
		cipher_txt->em_body = NULL;
	}
	if (last_pkt->hmac) {
		fdo_hash_free(last_pkt->hmac);
		last_pkt->hmac = NULL;
	}

	/* Negative Test Case */
	ret = aes_encrypt_packet(NULL, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");

	/* Negative Test Case */
	hmac_fail_case = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	hmac_fail_case = false;

	/* Negative Test Case */
	g_malloc_fail = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	g_malloc_fail = false;

	/* Negative Test Case */
	last_pkt->offset = 10;
	hash_alloc_fail_case = true;
	hash_free_fail_case = true;
	g_malloc_fail = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	g_malloc_fail = false;

	/* Negative Test Case */
	memcpy_fail_case = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	memcpy_fail_case = false;

	/* Negative Test Case */
	g_memset_fail = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	g_memset_fail = false;
	hash_alloc_fail_case = false;
	hash_free_fail_case = false;

	if (last_pkt->hmac != NULL) {
		fdo_hash_free(last_pkt->hmac);
	}
	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);

	free(last_pkt);
	free(cipher_txt);
	fdo_bits_free(clear_txt);
	fdo_bits_free(keyset->sek);
	fdo_byte_array_free(keyset->svk);
	free(keyset);
}
#ifdef TARGET_OS_FREERTOS
TEST_CASE("aes_decrypt_packet", "[crypto_utils][fdo]")
#else
void test_aes_decrypt_packet(void)
#endif
{
	int ret = 0;
	fdo_encrypted_packet_t *last_pkt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_encrypted_packet_t *cipher_txt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_aes_keyset_t *keyset = fdo_alloc(sizeof(fdo_aes_keyset_t));
	fdo_string_t *clear_txt = fdo_string_alloc();
	fdo_byte_array_t *cleartext = getcleartext(PLAIN_TEXT_SIZE);

	TEST_ASSERT_NOT_NULL(last_pkt);
	TEST_ASSERT_NOT_NULL(cipher_txt);
	TEST_ASSERT_NOT_NULL(keyset);
	TEST_ASSERT_NOT_NULL(clear_txt);
	TEST_ASSERT_NOT_NULL(cleartext);

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	keyset->sek = getkey(FDO_AES_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->sek);

	keyset->svk = getkey(HMAC_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->svk);

	/* Positive Test Case */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	uint8_t *iv1 = get_randomiv();
	fdo_to2Sym_enc_ctx_t *to2sym_ctx = get_fdo_to2_ctx();
	to2sym_ctx->initialization_vector = iv1;

	last_pkt->offset = 0;
	ret = aes_encrypt_packet(cipher_txt, cleartext->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	/* last pkt is no longer needed */
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");

	if (cipher_txt->em_body) {
		fdo_byte_array_free(cipher_txt->em_body);
		cipher_txt->em_body = NULL;
	}
	if (cipher_txt->hmac) {
		fdo_hash_free(cipher_txt->hmac);
		cipher_txt->hmac = NULL;
	}

	/* Positive Test Case */
	last_pkt->offset = 10;
	ret = aes_encrypt_packet(cipher_txt, cleartext->bytes, PLAIN_TEXT_SIZE);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");

	/* Negative Test Case */
	ret = aes_decrypt_packet(NULL, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	if (cipher_txt->hmac) {
		fdo_hash_free(cipher_txt->hmac);
		cipher_txt->hmac = NULL;
	}

	/* Negative Test Case */
	hmac_fail_case = true;
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	hmac_fail_case = false;

	/* Negative Test Case */
	last_pkt->offset = 10;
	last_pkt->hmac =
	    fdo_hash_alloc(FDO_CRYPTO_HMAC_TYPE_SHA_256, SHA256_DIGEST_SIZE);
	TEST_ASSERT_NOT_NULL(last_pkt->hmac);
	//	last_pkt->hmac->hash->bytes =	clear_txt;
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	last_pkt->offset = 0;

	/* Negative Test Case */
	g_malloc_fail = true;
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	g_malloc_fail = false;

	/* Negative Test Case */
	last_pkt->offset = 10;
	hash_alloc_fail_case = true;
	hash_free_fail_case = true;
	g_malloc_fail = true;
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	g_malloc_fail = false;
	hash_alloc_fail_case = false;
	hash_free_fail_case = false;

#ifdef AES_MODE_CTR_ENABLED
	/* Negative Test Case */
	memcpy_fail_case = true;
	printf("Calling memcpy fail case\n");
	ret = aes_decrypt_packet(cipher_txt, clear_txt);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	memcpy_fail_case = false;
#endif

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);

	if (last_pkt->hmac)
		fdo_hash_free(last_pkt->hmac);
	fdo_free(last_pkt);
	fdo_bits_free(keyset->sek);
	fdo_byte_array_free(keyset->svk);
	fdo_byte_array_free(cleartext);
	if (cipher_txt->em_body)
		fdo_byte_array_free(cipher_txt->em_body);
	free(cipher_txt);
	free(keyset);
	fdo_string_free(clear_txt);
}
