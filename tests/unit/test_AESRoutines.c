/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for AES abstraction routines of FDO library.
 */

#include "test_AESRoutines.h"
#include "safe_lib.h"
#include "util.h"

#define PLAIN_TEXT_SIZE BUFF_SIZE_1K_BYTES

/*
#define HEXDEBUG 1
*/
#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
uint8_t *getkey(size_t length);
void test_aes_encrypt(void);

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
/**
 * Generate a random text of size provided in input.
 *
 * @param length
 *        Length of text to be generated.
 * @return ret
 *        Pointer to the string containing random text.
 */
static uint8_t *getcleartext(size_t length)
{
	uint8_t *cleartext = fdo_alloc(length);
	if (!cleartext) {
		return NULL;
	}
	int i = length;
	crypto_hal_random_bytes(cleartext, length);
	while (i) {
		cleartext[i - 1] = 'A' + (cleartext[i - 1] % 26);
		i--;
	}
#ifdef HEXDEBUG
	hexdump("CLEARTEXT", cleartext, length);
#endif
	return cleartext;
}

/**
 * Generate a random key of size provided in input.
 *
 * @param length
 *        Length of text to be generated.
 * @return ret
 *        Pointer to the Byte_array containing key.
 */
uint8_t *getkey(size_t length)
{
	uint8_t *getkey = fdo_alloc(length);
	if (!getkey) {
		return NULL;
	}
	int i = length;
	crypto_hal_random_bytes(getkey, length);
	while (i) {
		getkey[i - 1] = 'A' + (getkey[i - 1] % 26);
		i--;
	}
#ifdef HEXDEBUG
	hexdump("KEY", getkey, length);
#endif
	return getkey;
}
static uint8_t *get_randomiv(void)
{
	uint8_t *iv = fdo_alloc(AES_IV_LEN);
	if (!iv) {
		return NULL;
	}
	crypto_hal_random_bytes(iv, AES_IV_LEN);
#ifdef HEXDEBUG
	hexdump("IV", iv, AES_IV_LEN);
#endif
	return iv;
}

#ifndef TARGET_OS_FREERTOS
void test_aes_encrypt(void)
#else
TEST_CASE("aes_encrypt", "[AESRoutines][fdo]")
#endif
{
	uint32_t cipher_length = 0;
	uint8_t *cipher_text = NULL;
	uint8_t *key1 = NULL;
	uint8_t *key2 = NULL;
	uint8_t *tag = NULL;
	uint32_t key1Length = 0, key2Length = 0;

	int ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	uint8_t *clear_txt = getcleartext(PLAIN_TEXT_SIZE);
	size_t clear_txt_size = PLAIN_TEXT_SIZE;
	TEST_ASSERT_NOT_NULL(clear_txt);

	uint8_t *iv1 = get_randomiv();
	TEST_ASSERT_NOT_NULL(iv1);

	uint8_t *decrypted_txt = NULL;
	uint32_t decrypted_length = 0;
	int result_memcmp = 0;

	uint8_t aad[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			   0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

#if defined(ECDSA384_DA)
	uint8_t key_1[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
			     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	uint8_t key_2[32] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0xdc,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
			     0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6};
#else

	uint8_t key_1[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	uint8_t key_2[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
			     0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0xdc};
#endif

	key1 = key_1;
	key1Length = sizeof(key_1);
	key2 = key_2;
	key2Length = sizeof(key_2);

	tag = fdo_alloc(AES_TAG_LEN);
	TEST_ASSERT_NOT_NULL(tag);

	// check for any NULL parameter
	ret = crypto_hal_aes_encrypt(
	    clear_txt, clear_txt_size, NULL, &cipher_length, FDO_AES_BLOCK_SIZE,
	    iv1, key1, key1Length, tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_LESS_OR_EQUAL_INT32_MESSAGE(-1, ret,
						"Invalid return value");

	// check for encrypted data length less than clear data length
	cipher_length = 0;
	ret = crypto_hal_aes_encrypt(
	    clear_txt, clear_txt_size, NULL, &cipher_length, FDO_AES_BLOCK_SIZE,
	    iv1, key1, key1Length, tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_LESS_OR_EQUAL_INT32_MESSAGE(-1, ret,
						"Invalid return value");

	cipher_length = clear_txt_size;
	cipher_text = fdo_alloc(cipher_length);
	TEST_ASSERT_NOT_NULL(cipher_text);

	// encrypt
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cipher_text,
				     &cipher_length, FDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length, tag, AES_TAG_LEN, aad,
				     sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	// check for any NULL parameter
	ret = crypto_hal_aes_decrypt(NULL, &decrypted_length, cipher_text,
				     cipher_length, FDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length, tag, AES_TAG_LEN, aad,
				     sizeof(aad));

	TEST_ASSERT_LESS_OR_EQUAL_INT32_MESSAGE(-1, ret,
						"Invalid return value");

	// check for clear data length less than encrypted data length
	ret = crypto_hal_aes_decrypt(NULL, &decrypted_length, cipher_text,
				     cipher_length, FDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length, tag, AES_TAG_LEN, aad,
				     sizeof(aad));

	TEST_ASSERT_LESS_OR_EQUAL_INT32_MESSAGE(-1, ret,
						"Invalid return value");

	decrypted_length = cipher_length;
	decrypted_txt = fdo_alloc(decrypted_length);
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	// decrypt
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypted_length,
				     cipher_text, cipher_length,
				     FDO_AES_BLOCK_SIZE, iv1, key1, key1Length,
				     tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypted_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");

	// decrypt with wrong key
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypted_length,
				     cipher_text, cipher_length,
				     FDO_AES_BLOCK_SIZE, iv1, key2, key2Length,
				     tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	// encrypt->decrypt->change iv->decrypt again
	memset_s(iv1, AES_IV_LEN, 1);
	memset_s(tag, AES_TAG_LEN, 0);
	memset_s(decrypted_txt, decrypted_length, 0);

	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cipher_text,
				     &cipher_length, FDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length, tag, AES_TAG_LEN, aad,
				     sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	decrypted_length = cipher_length;
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypted_length,
				     cipher_text, cipher_length,
				     FDO_AES_BLOCK_SIZE, iv1, key1, key1Length,
				     tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypted_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(
	    0, result_memcmp,
	    "Decrypted doesn't match with cleartxt with same iv");

	memset_s(iv1, AES_IV_LEN, 0);
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypted_length,
				     cipher_text, cipher_length,
				     FDO_AES_BLOCK_SIZE, iv1, key1, key1Length,
				     tag, AES_TAG_LEN, aad, sizeof(aad));
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = random_close();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup close Failed");

	if (decrypted_txt) {
		fdo_free(decrypted_txt);
	}
	if (cipher_text) {
		fdo_free(cipher_text);
	}
	if (clear_txt) {
		fdo_free(clear_txt);
	}
	if (iv1) {
		fdo_free(iv1);
	}
	if (tag) {
		fdo_free(tag);
	}
}
