/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for AES abstraction routines of SDO library.
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
uint8_t *getkey(int length);
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
static uint8_t *getcleartext(int length)
{
	uint8_t *cleartext = malloc(length * sizeof(char));
	if (!cleartext)
		return NULL;
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
uint8_t *getkey(int length)
{
	uint8_t *getkey = malloc(length * sizeof(char));
	if (!getkey)
		return NULL;
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
	uint8_t *iv = malloc(SDO_AES_IV_SIZE * sizeof(char));
	if (!iv)
		return NULL;
	crypto_hal_random_bytes(iv, SDO_AES_IV_SIZE);
#ifdef HEXDEBUG
	hexdump("IV", iv, length);
#endif
	return iv;
}

#ifndef TARGET_OS_FREERTOS
void test_aes_encrypt(void)
#else
TEST_CASE("aes_encrypt", "[AESRoutines][sdo]")
#endif
{
#ifdef AES_MODE_CTR_ENABLED
	uint32_t cypher_length = 0;
	uint8_t *cypher_text = NULL;
	uint8_t *key1 = NULL;
	uint8_t *key2 = NULL;
	uint32_t key1Length = 0, key2Length = 0;
	uint8_t *clear_txt = getcleartext(PLAIN_TEXT_SIZE);
	size_t clear_txt_size = PLAIN_TEXT_SIZE;
	TEST_ASSERT_NOT_NULL(clear_txt);

	uint8_t *iv1 = get_randomiv();
	TEST_ASSERT_NOT_NULL(clear_txt);

	uint8_t *decrypted_txt = NULL;
	uint32_t decrypthed_length = 0;
	int ret = 0;
	int result_memcmp = 0;

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

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	/* Get cypher text length required by sending NULL as cypher_text */
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, NULL,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, cypher_length,
				      "Cypher size get failed");

	cypher_text = malloc(cypher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cypher_text);

	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	/* Get the decrypted text size */
	ret = crypto_hal_aes_decrypt(NULL, &decrypthed_length, cypher_text,
				     cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);

	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, decrypthed_length,
				      "Clear txt size get failed");

	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	/* Do a decryption */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");

	/* Do a decryption with wrong key */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key2, key2Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	/* Should not get the original text */
	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(
	    0, result_memcmp, "Decrypt with wrong key gives orignal text");

	/* not unique iv ? */
	ret = memcpy_s(iv1, AES_IV, key_1, AES_IV);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Memcpy Failed");

	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(
	    0, result_memcmp,
	    "Decrypted doesn't match with cleartxt with same iv");

	ret = memcpy_s(iv1, AES_IV, key_2, AES_IV);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Memcpy Failed");

	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(
	    0, result_memcmp, "Decrypt with wrong iv gives original text ");

	if (decrypted_txt)
		free(decrypted_txt);
	if (cypher_text)
		free(cypher_text);
	if (clear_txt)
		free(clear_txt);
	if (iv1)
		free(iv1);
#endif
#ifdef AES_MODE_CBC_ENABLED
	uint32_t cypher_length = 0;
	uint8_t *cypher_text = NULL;

	uint8_t *key1 = NULL;
	uint8_t *key2 = NULL;
	uint32_t key1Length = 16, key2Length = 16;
#if defined(ECDSA384_DA)
	uint8_t key_1[BUFF_SIZE_32_BYTES] = {
	    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
	    0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
	    0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

	uint8_t key_2[BUFF_SIZE_32_BYTES] = {
	    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
	    0x88, 0x09, 0xcf, 0x4f, 0xdc, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
	    0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6};
#else

	uint8_t key_1[BUFF_SIZE_16_BYTES] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
					     0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
					     0x09, 0xcf, 0x4f, 0x3c};

	uint8_t key_2[BUFF_SIZE_16_BYTES] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
					     0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
					     0x09, 0xcf, 0x4f, 0xdc};

#endif
	key1 = key_1;
	key1Length = sizeof(key_1);
	key2 = key_2;
	key2Length = sizeof(key_2);

	uint8_t *clear_txt = getcleartext(PLAIN_TEXT_SIZE);
	size_t clear_txt_size = PLAIN_TEXT_SIZE;
	TEST_ASSERT_NOT_NULL(clear_txt);

	uint8_t *iv1 = get_randomiv();
	TEST_ASSERT_NOT_NULL(clear_txt);

	uint8_t *decrypted_txt = NULL;
	uint32_t decrypthed_length = 0;
	int ret = 0;
	int result_memcmp = 0;

	ret = random_init();
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "Entropy setup Failed");

	/* Get cypher text length required by sending NULL as cypher_text */
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, NULL,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, cypher_length,
				      "Cypher size get failed");

	cypher_text = malloc(cypher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cypher_text);

	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	/* Get the decrypted text size */
	ret = crypto_hal_aes_decrypt(NULL, &decrypthed_length, cypher_text,
				     cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);

	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, decrypthed_length,
				      "Clear txt size get failed");

	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	/* Do a decryption */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");

	/* negative test, NULL cleartxt */
	ret = crypto_hal_aes_encrypt(NULL, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(
	    0, ret, "AES Encryption passed with Clear text NULL");

	/* Negative test, expected return +ve value */
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, NULL,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key1, key1Length);
	TEST_ASSERT_EQUAL_MESSAGE(
	    0, ret, "AES Encryption passed with Cipher text NULL");

	/* negative test, 0 cleartextsize */
	ret = crypto_hal_aes_encrypt(clear_txt, 0, cypher_text, &cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(
	    0, ret, "AES Encryption passed with Clear text of size 0");

	/* negative test, NULL key */
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     NULL, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, ret,
				      "AES Encryption passed with Key NULL");

	/* TODO: Above part is common? ^^ */

	if (clear_txt)
		free(clear_txt);
	if (decrypted_txt)
		free(decrypted_txt);
	if (cypher_text)
		free(cypher_text);

	/* now do 1025 byte encryption, odd bytes, so padding will be added */
	clear_txt = getcleartext(1 + PLAIN_TEXT_SIZE);
	TEST_ASSERT_NOT_NULL(clear_txt);
	clear_txt_size = 1 + PLAIN_TEXT_SIZE;
	ret = 0;

	/* Get cypher text length required by sending NULL as cypher_text */
	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, NULL,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key2, key2Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, cypher_length,
				      "Cypher size get failed");

	cypher_text = malloc(cypher_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(cypher_text);

	ret = crypto_hal_aes_encrypt(clear_txt, clear_txt_size, cypher_text,
				     &cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key2, key2Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Encryption Failed");

	/* Get the decrypted text size */
	ret = crypto_hal_aes_decrypt(NULL, &decrypthed_length, cypher_text,
				     cypher_length, SDO_AES_BLOCK_SIZE, iv1,
				     key2, key2Length);

	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, decrypthed_length,
				      "Clear txt size get failed");

	decrypted_txt = malloc(decrypthed_length * sizeof(char));
	TEST_ASSERT_NOT_NULL(decrypted_txt);

	/* Do a decryption */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key2, key2Length);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_EQUAL_MESSAGE(0, result_memcmp,
				  "Decrypted doesn't match with cleartxt");

	memset_s(decrypted_txt, decrypthed_length, 0);

// Decryption passes but memcmp will fail here
#ifdef USE_MBEDTLS
	/* Do a decryption with wrong key */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");

	ret = memcmp_s(clear_txt, clear_txt_size, decrypted_txt,
		       decrypthed_length, &result_memcmp);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(
	    0, result_memcmp, "Decrypted shouldn't match with cleartxt");
#endif

// Decryption Fails if the paddding is not correct after decryption in openssl
#ifdef USE_OPENSSL
	/* Do a decryption with wrong key */
	ret = crypto_hal_aes_decrypt(decrypted_txt, &decrypthed_length,
				     cypher_text, cypher_length,
				     SDO_AES_BLOCK_SIZE, iv1, key1, key1Length);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(0, ret, "AES Decryption Failed");
#endif

	if (decrypted_txt)
		free(decrypted_txt);
	if (cypher_text)
		free(cypher_text);
	if (clear_txt)
		free(clear_txt);
	if (iv1)
		free(iv1);

#endif
}
