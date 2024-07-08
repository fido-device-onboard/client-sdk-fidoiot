/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
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
#include "fdo_crypto_hal.h"
#include "fdo_crypto.h"

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
	if (!cleartext) {
		return NULL;
	}
	fdo_crypto_random_bytes(cleartext->bytes, cleartext->byte_sz);
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
	fdo_byte_array_t *key = NULL;
	key = fdo_byte_array_alloc(length);
	if (!key) {
		return NULL;
	}
	if (0 != fdo_crypto_random_bytes(key->bytes, key->byte_sz)) {
		return NULL;
	}
#ifdef HEXDEBUG
	hexdump("KEY", cleartext->bytes, cleartext->byte_sz);
#endif
	return key;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("aes_encrypt_packet", "[crypto_utils][fdo]")
#else
void test_aes_encrypt_packet(void)
#endif
{
	int ret = -1;
	fdo_encrypted_packet_t *cipher_txt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_aes_keyset_t *keyset = fdo_alloc(sizeof(fdo_aes_keyset_t));
	fdo_byte_array_t *clear_txt = getcleartext(PLAIN_TEXT_SIZE);
	uint8_t *aad = NULL;

	TEST_ASSERT_NOT_NULL(keyset);
	TEST_ASSERT_NOT_NULL(cipher_txt);
	TEST_ASSERT_NOT_NULL(clear_txt);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	keyset->sek = getkey(FDO_AES_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->sek);

	keyset->svk = getkey(HMAC_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->svk);

	/* Positive Test Case */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE,
				 aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	TEST_ASSERT_NOT_NULL(cipher_txt->em_body);

	if (cipher_txt->em_body) {
		fdo_byte_array_free(cipher_txt->em_body);
		cipher_txt->em_body = NULL;
	}

	/* Negative Test Case */
	ret = aes_encrypt_packet(NULL, clear_txt->bytes, PLAIN_TEXT_SIZE, NULL,
				 sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");

	/* Negative Test Case */
	g_malloc_fail = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE,
				 aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	g_malloc_fail = false;

	/* Negative Test Case */
	g_memset_fail = true;
	ret = aes_encrypt_packet(cipher_txt, clear_txt->bytes, PLAIN_TEXT_SIZE,
				 aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Encryption Failed");
	g_memset_fail = false;

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdo_free(cipher_txt);
	fdo_bits_free(clear_txt);
	fdo_bits_free(keyset->sek);
	fdo_byte_array_free(keyset->svk);
	fdo_free(keyset);
	fdo_free(aad);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("aes_decrypt_packet", "[crypto_utils][fdo]")
#else
void test_aes_decrypt_packet(void)
#endif
{
	int ret = -1;
	fdo_encrypted_packet_t *cipher_txt =
	    fdo_alloc(sizeof(fdo_encrypted_packet_t));
	fdo_aes_keyset_t *keyset = fdo_alloc(sizeof(fdo_aes_keyset_t));
	fdo_byte_array_t *cleartext = getcleartext(PLAIN_TEXT_SIZE);
	fdo_byte_array_t *cleartext_decrypted =
	    fdo_byte_array_alloc(PLAIN_TEXT_SIZE);
	uint8_t *aad = NULL;

	TEST_ASSERT_NOT_NULL(cipher_txt);
	TEST_ASSERT_NOT_NULL(keyset);
	TEST_ASSERT_NOT_NULL(cleartext_decrypted);
	TEST_ASSERT_NOT_NULL(cleartext);

	// 16-byte AAD
	aad = fdo_alloc(16);
	TEST_ASSERT_NOT_NULL(aad);

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	keyset->sek = getkey(FDO_AES_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->sek);

	keyset->svk = getkey(HMAC_KEY_LENGTH);
	TEST_ASSERT_NOT_NULL(keyset->svk);

	/* Positive Test Case */
	ret = fdo_kex_init();
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = aes_encrypt_packet(cipher_txt, cleartext->bytes, PLAIN_TEXT_SIZE,
				 aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");
	ret = aes_decrypt_packet(cipher_txt, cleartext_decrypted, aad,
				 sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	if (cipher_txt->em_body) {
		fdo_byte_array_free(cipher_txt->em_body);
		cipher_txt->em_body = NULL;
	}

	/* Negative Test Case */
	ret = aes_decrypt_packet(NULL, cleartext_decrypted, NULL, 0);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");

	/* Negative Test Case */
	g_malloc_fail = true;
	ret = aes_decrypt_packet(cipher_txt, cleartext_decrypted, aad,
				 sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "AES Decryption Failed");
	g_malloc_fail = false;

	ret = fdo_kex_close();
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdo_bits_free(keyset->sek);
	fdo_byte_array_free(keyset->svk);
	fdo_byte_array_free(cleartext);
	if (cipher_txt->em_body)
		fdo_byte_array_free(cipher_txt->em_body);
	fdo_free(cipher_txt);
	fdo_free(keyset);
	fdo_byte_array_free(cleartext_decrypted);
}
