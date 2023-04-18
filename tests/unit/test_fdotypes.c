/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "unity.h"
#include "crypto_utils.h"
#include "fdoprot.h"
#include "fdotypes.h"
#include "fdoCrypto.h"
#include "fdoCryptoHal.h"
#include "util.h"
#include "fdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

/***!
 * \file
 * \brief Unit tests for FDO defined data structure parsing/packing routines.
**/

/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_fdo_bits_init(void);
void test_fdo_bits_alloc_with(void);
void test_fdo_bits_fill(void);
void test_fdo_byte_array_append(void);
void test_fdo_string_alloc_with(void);
void test_fdo_string_alloc_str(void);
void test_fdo_string_resize(void);
void test_fdo_string_resize_with(void);
void test_fdo_nonce_equal(void);
void test_fdo_hash_read(void);
void test_fdo_init_ipv4_address(void);
void test_fdoIPAddress_toString(void);
void test_fdo_read_ipaddress(void);
void test_fdo_public_key_clone(void);
void test_fdo_compare_public_keys(void);
void test_fdo_public_key_free(void);
void test_fdo_public_key_write(void);
void test_fdo_public_key_read(void);
void test_fdo_rendezvous_free(void);
void test_fdo_rendezvous_list_add(void);
void test_fdo_rendezvous_list_get(void);
void test_fdo_rendezvous_list_read(void);
void test_fdo_rendezvous_list_write(void);
void test_fdo_encrypted_packet_read(void);
void test_fdo_encrypted_packet_windup(void);
void test_fdo_aad_write(void);
void test_fdo_emblock_write(void);
void test_fdo_eat_write_payloadbasemap(void);
void test_fdo_eat_write(void);
void test_fdo_cose_read(void);
void test_fdo_cose_write(void);
void test_fdo_siginfo_read(void);
void test_fdo_siginfo_write(void);
void test_fdo_signature_verification(void);
void test_fdo_kv_alloc_with_str(void);
void test_fdo_service_info_add_kv_str(void);
void test_fdo_service_info_add_kv_int(void);
void test_fdo_service_info_add_kv_bool(void);
void test_fdo_service_info_add_kv_bin(void);
void test_fdo_service_info_add_kv(void);
void test_fdo_serviceinfo_invalid_modname_add(void);
void test_fdo_compare_hashes(void);
void test_fdo_compare_byte_arrays(void);
void test_fdo_compare_rvLists(void);


/*** Unity functions. ***/
/*
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

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_bits_init", "[fdo_types][fdo]")
#else
void test_fdo_bits_init(void)
#endif
{
	fdo_bits_t *b;
	fdo_bits_t *ret = NULL;

	ret = fdo_bits_init(NULL, 100);
	TEST_ASSERT_NULL(ret);

	b = fdo_alloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);

	ret = fdo_bits_init(b, 100);
	TEST_ASSERT_NOT_NULL(ret);

	fdo_bits_free(b);

	b = fdo_alloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);
	b->bytes = fdo_alloc(5);
	TEST_ASSERT_NOT_NULL(b->bytes);
	ret = fdo_bits_init(b, 0);
	TEST_ASSERT_NOT_NULL(ret);

	fdo_bits_free(b);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_bits_alloc_with", "[fdo_types][fdo]")
#else
void test_fdo_bits_alloc_with(void)
#endif
{
	LOG(LOG_ERROR, "FDOW memset() failed!\n");
	uint8_t *data;
	fdo_bits_t *ret;

	data = fdo_alloc(100);
	TEST_ASSERT_NOT_NULL(data);

	ret = fdo_bits_alloc_with(100, data);
	TEST_ASSERT_NOT_NULL(ret);
	fdo_bits_free(ret);

	ret = fdo_bits_alloc_with(0, data);
	TEST_ASSERT_NULL(ret);

	ret = fdo_bits_alloc_with(100, NULL);
	TEST_ASSERT_NULL(ret);

	ret = fdo_bits_alloc_with(0, NULL);
	TEST_ASSERT_NULL(ret);

	fdo_free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_bits_fill", "[fdo_types][fdo]")
#else
void test_fdo_bits_fill(void)
#endif
{
	fdo_bits_t *bits;
	bool ret;

	ret = fdo_bits_fill(NULL);
	TEST_ASSERT_FALSE(ret);

	bits = fdo_alloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = NULL;
	bits->byte_sz = 0;
	ret = fdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	fdo_bits_free(bits);

	bits = fdo_alloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = fdo_alloc(100);
	TEST_ASSERT_NOT_NULL(bits->bytes);
	bits->byte_sz = 0;
	ret = fdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	fdo_free(bits);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_byte_array_append", "[fdo_types][fdo]")
#else
void test_fdo_byte_array_append(void)
#endif
{
	fdo_byte_array_t *baA;
	fdo_byte_array_t *baB;
	fdo_byte_array_t *ret;

	ret = fdo_byte_array_append(NULL, NULL);
	TEST_ASSERT_NULL(ret);

	baA = fdo_alloc(sizeof(fdo_byte_array_t));
	TEST_ASSERT_NOT_NULL(baA);
	baB = fdo_alloc(sizeof(fdo_byte_array_t));
	TEST_ASSERT_NOT_NULL(baB);

	baA->byte_sz = 0;
	baB->byte_sz = 10;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = fdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 0;
	baB->byte_sz = 0;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = fdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 10;
	baB->byte_sz = 10;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = fdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 10;
	baB->byte_sz = 10;
	baA->bytes = fdo_alloc(10);
	baB->bytes = fdo_alloc(10);

	ret = fdo_byte_array_append(baA, baB);
	TEST_ASSERT_NOT_NULL(ret);
	fdo_byte_array_free(ret);

	fdo_free(baB->bytes);
	fdo_free(baA->bytes);
	fdo_free(baA);
	fdo_free(baB);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_string_alloc_with", "[fdo_types][fdo]")
#else
void test_fdo_string_alloc_with(void)
#endif
{
	fdo_string_t *ret;
	char *data;

	ret = fdo_string_alloc_with(NULL, 0);
	TEST_ASSERT_NULL(ret);

	data = fdo_alloc(10);
	TEST_ASSERT_NOT_NULL(data);
	ret = fdo_string_alloc_with(data, 1);
	TEST_ASSERT_NOT_NULL(ret);
	fdo_string_free(ret);
	fdo_free(data);

	ret = fdo_string_alloc_with(NULL, 10);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_string_alloc_str", "[fdo_types][fdo]")
#else
void test_fdo_string_alloc_str(void)
#endif
{
	fdo_string_t *ret;
	char *data;

	ret = fdo_string_alloc_with_str(NULL);
	TEST_ASSERT_NULL(ret);

	data = fdo_alloc(FDO_MAX_STR_SIZE * 2);
	TEST_ASSERT_NOT_NULL(data);
	memset_s(data, FDO_MAX_STR_SIZE * 2, 'a');
	data[(FDO_MAX_STR_SIZE * 2) - 1] = 0;

	ret = fdo_string_alloc_with_str(data);
	TEST_ASSERT_NULL(ret);

	fdo_free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_string_resize", "[fdo_types][fdo]")
#else
void test_fdo_string_resize(void)
#endif
{
	fdo_string_t b = {
	    0,
	};
	bool ret;

	ret = fdo_string_resize(NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_string_resize(&b, 0);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_string_resize_with", "[fdo_types][fdo]")
#else
void test_fdo_string_resize_with(void)
#endif
{
	fdo_string_t b = {
	    0,
	};
	char *data;
	bool ret;

	ret = fdo_string_resize_with(NULL, 0, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_string_resize_with(&b, 0, NULL);
	TEST_ASSERT_FALSE(ret);

	data = fdo_alloc(100);
	TEST_ASSERT_NOT_NULL(data);
	ret = fdo_string_resize_with(&b, 0, data);
	TEST_ASSERT_TRUE(ret);
	fdo_free(b.bytes);
	b.bytes = NULL;

	ret = fdo_string_resize_with(&b, -1, data);
	TEST_ASSERT_TRUE(ret);
	fdo_free(b.bytes);
	b.bytes = NULL;

	ret = fdo_string_resize_with(&b, 100, data);
	TEST_ASSERT_TRUE(ret);
	fdo_free(b.bytes);
	fdo_free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_nonce_equal", "[fdo_types][fdo]")
#else
void test_fdo_nonce_equal(void)
#endif
{
	fdo_byte_array_t n1 = {
	    0,
	};
	fdo_byte_array_t n2 = {
	    0,
	};
	bool ret;

	ret = fdo_nonce_equal(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	n1.byte_sz = 10;
	ret = fdo_nonce_equal(&n1, &n2);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_hash_read", "[fdo_types][fdo]")
#else
void test_fdo_hash_read(void)
#endif
{
	fdor_t *fdor = NULL;
	fdo_hash_t *hash = NULL;
	int ret;
	// sample CBOR encoded HMAC with HMAC-SHA384 data
	uint8_t hmac_cbor[] = {
		0x82, 0x06, 0x58, 0x30, 0x89, 0x5B, 0xD7, 0x23, 0x65, 0xFE, 0xE9, 0x3F, 0x89,
		0x65, 0xBB, 0x5E, 0xB7, 0xDF, 0x6E, 0x74, 0xF6, 0xA8, 0x64, 0x21, 0xA7, 0x22,
		0x74, 0xC5, 0xAC, 0xC5, 0x48, 0x81, 0x3E, 0x8F, 0x60, 0x1A, 0x05, 0xE4, 0xA6,
		0x28, 0xDC, 0x79, 0x1E, 0x30, 0xCB, 0x49, 0x6E, 0x69, 0xB9, 0x9B, 0x0F, 0x1C
	};

	ret = fdo_hash_read(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(hmac_cbor), hmac_cbor, sizeof(hmac_cbor));
	fdor->b.block_size = sizeof(hmac_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	hash = fdo_hash_alloc_empty();
	TEST_ASSERT_NOT_NULL(hash);

	ret = fdo_hash_read(fdor, hash);
	TEST_ASSERT_GREATER_THAN(1, ret);
	if (hash) {
		fdo_hash_free(hash);
	}
	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_init_ipv4_address", "[fdo_types][fdo]")
#else
void test_fdo_init_ipv4_address(void)
#endif
{
	fdo_ip_address_t fdoip = {
	    0,
	};
	uint8_t ipv4;

	// function returns void, so call only to see NULL check
	fdo_init_ipv4_address(NULL, NULL);
	TEST_ASSERT_TRUE(1);

	fdo_init_ipv4_address(&fdoip, &ipv4);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_ipaddress_to_string", "[fdo_types][fdo]")
#else
void test_fdoIPAddress_toString(void)
#endif
{
	fdo_ip_address_t fdoip;
	char buf[100] = "IPTo_string";
	int buf_sz = sizeof("IPTo_string");
	char *ret;

	ret = fdo_ipaddress_to_string(NULL, NULL, 0);
	TEST_ASSERT_NULL(ret);

	fdoip.length = 16;
	ret = fdo_ipaddress_to_string(&fdoip, buf, buf_sz);
	TEST_ASSERT_NOT_NULL(ret);

	ret = fdo_ipaddress_to_string(&fdoip, buf, 5);
	TEST_ASSERT_NULL(ret);

	ret = fdo_ipaddress_to_string(&fdoip, buf, buf_sz + 16);
	TEST_ASSERT_NOT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_read_ipaddress", "[fdo_types][fdo]")
#else
void test_fdo_read_ipaddress(void)
#endif
{
	fdor_t *fdor = NULL;
	fdo_ip_address_t fdoip = {0};
	bool ret;
	// sample CBOR encoded IPV4 address
	uint8_t ipv4_cbor[] = {
		0x44, 0x7F, 0x00, 0x00, 0x01
	};

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(ipv4_cbor), ipv4_cbor, sizeof(ipv4_cbor));
	fdor->b.block_size = sizeof(ipv4_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	ret = fdo_read_ipaddress(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_read_ipaddress(fdor, &fdoip);
	TEST_ASSERT_TRUE(ret);

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_clone", "[fdo_types][fdo]")
#else
void test_fdo_public_key_clone(void)
#endif
{
	fdo_public_key_t pk = {
	    0,
	};
	fdo_public_key_t *ret;

	ret = fdo_public_key_clone(NULL);
	TEST_ASSERT_NULL(ret);

	ret = fdo_public_key_clone(&pk);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_compare_public_keys", "[fdo_types][fdo]")
#else
void test_fdo_compare_public_keys(void)
#endif
{
	fdo_public_key_t pk1 = {0};
	fdo_public_key_t pk2 = {0};
	fdo_byte_array_t key1 = {0};
	fdo_byte_array_t key2 = {0};
	fdo_byte_array_t key3 = {0};
	fdo_byte_array_t key4 = {0};
	bool ret;

	ret = fdo_compare_public_keys(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.key1 = &key1;
	pk1.key2 = &key2;

	pk2.key1 = &key3;
	pk2.key2 = &key4;

	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkalg = 3;
	pk2.pkalg = 4;
	pk1.pkenc = 1;
	pk2.pkenc = 1;

	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkalg = 3;
	pk2.pkalg = 3;

	pk1.pkenc = 1;
	pk2.pkenc = 2;
	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkenc = 1;
	pk2.pkenc = 1;
	key1.byte_sz = 0;
	key2.byte_sz = 0;
	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkenc = 1;
	pk2.pkenc = 1;
	key1.byte_sz = 10;
	key1.bytes = fdo_alloc(10);
	memset_s(key1.bytes, 10, 0);
	key3.byte_sz = 10;
	key3.bytes = fdo_alloc(10);
	memset_s(key3.bytes, 10, 0);
	key2.byte_sz = 0;
	key4.byte_sz = 0;
	ret = fdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);
	if (key1.bytes) {
		fdo_free(key1.bytes);
	}
	if (key2.byte_sz != 0) {
		fdo_free(key2.bytes);
	}
	if (key3.bytes) {
		fdo_free(key3.bytes);
	}
	if (key4.byte_sz != 0) {
		fdo_free(key4.bytes);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_free", "[fdo_types][fdo]")
#else
void test_fdo_public_key_free(void)
#endif
{
	// function returns void so call only to see NULL check

	fdo_public_key_free(NULL);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_write", "[fdo_types][fdo]")
#else
void test_fdo_public_key_write(void)
#endif
{
	fdow_t *fdow = NULL;
	fdo_public_key_t *fdopubkey = NULL;
	uint8_t pkey[100] = {0};
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	fdopubkey = fdo_public_key_alloc(FDO_CRYPTO_PUB_KEY_ALGO_ECDSAp384,
		FDO_CRYPTO_PUB_KEY_ENCODING_X509, sizeof(pkey), pkey);
	TEST_ASSERT_NOT_NULL(fdopubkey);

	ret = fdo_public_key_write(NULL, fdopubkey);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_public_key_write(fdow, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_public_key_write(fdow, fdopubkey);
	TEST_ASSERT_TRUE(ret);
	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (fdopubkey) {
		fdo_public_key_free(fdopubkey);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_read", "[fdo_types][fdo]")
#else
void test_fdo_public_key_read(void)
#endif
{
#if !defined (AES_MODE_GCM_ENABLED) || AES_BITS == 256
	TEST_IGNORE();
#endif
	fdor_t *fdor = NULL;
	fdo_public_key_t *fdopubkey = NULL;
	// sample CBOR encoded public key
	uint8_t pubkey_cbor[] = {
		0x83, 0x0A, 0x01, 0x58, 0x60, 0x92, 0x11, 0x12, 0xFD, 0x17, 0xEC, 0x7F, 0x33,0x05,
		0x24, 0xFD, 0x4D, 0xE3, 0x18, 0xE5, 0x0A, 0x85, 0x93, 0x3A, 0xDA, 0xFF, 0x6B, 0x2F,
		0x1B, 0x7C, 0x51, 0xE5, 0x5D, 0xFB, 0x52, 0x71, 0x02, 0x33, 0x94, 0xAE, 0x3F, 0x7D,
		0x1F, 0xDE, 0x29, 0x82, 0x27, 0x30, 0x4A, 0x01, 0xE5, 0x4B, 0x08, 0x90, 0xFE, 0x98,
		0xA3, 0xEA, 0x09, 0xD4, 0x01, 0x1C, 0xE0, 0xCC, 0xC5, 0x37, 0xCD, 0xCD, 0xFF, 0x55,
		0x3B, 0x21, 0x83, 0x24, 0x93, 0x3C, 0x72, 0x55, 0xE2, 0x49, 0xB4, 0xA3, 0xF5, 0x38,
		0x0E, 0x0D, 0x16, 0x58, 0x97, 0x15, 0xCE, 0x9F, 0x0B, 0xC7, 0xB2, 0xE8, 0x0F, 0xAF,
		0xB6, 0x15, 0x89
	};

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(pubkey_cbor), pubkey_cbor, sizeof(pubkey_cbor));
	fdor->b.block_size = sizeof(pubkey_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	fdopubkey = fdo_public_key_read(NULL);
	TEST_ASSERT_NULL(fdopubkey);

	fdopubkey = fdo_public_key_read(fdor);
	TEST_ASSERT_NOT_NULL(fdopubkey);

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	if (fdopubkey) {
		fdo_public_key_free(fdopubkey);
	}

}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_free", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_free(void)
#endif
{
	fdo_rendezvous_t *rv = NULL;

	fdo_rendezvous_free(NULL);
	rv = fdo_alloc(sizeof(fdo_rendezvous_t));
	TEST_ASSERT_NOT_NULL(rv);
	memset_s(rv, sizeof(fdo_rendezvous_t), 0);
	rv->ip = fdo_alloc(sizeof(fdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 32);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 48);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = fdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = fdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = fdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = fdo_alloc(sizeof(uint64_t));
	TEST_ASSERT_NOT_NULL(rv->me);
	rv->bypass = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->bypass);
	rv->dev_only = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->bypass);

	if (rv) {
		fdo_rendezvous_free(rv);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_write", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_write(void)
#endif
{

	fdow_t *fdow = NULL;
	fdo_rendezvous_t *rv = NULL;
	fdo_rendezvous_list_t *rvlist = NULL;
	fdo_rendezvous_directive_t *rvdirectives = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_rendezvous_list_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rv = fdo_rendezvous_alloc();
	TEST_ASSERT_NOT_NULL(rv);

	rv->ip = fdo_alloc(sizeof(fdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 32);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 32);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = fdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = fdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = fdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = fdo_alloc(sizeof(uint64_t));
	TEST_ASSERT_NOT_NULL(rv->me);
	rv->bypass = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->bypass);
	rv->dev_only = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv->bypass);

	// create and add the rv structure to the directive
	rvdirectives = fdo_alloc(sizeof(fdo_rendezvous_directive_t));
	TEST_ASSERT_NOT_NULL(rvdirectives);
	ret = fdo_rendezvous_list_add(rvdirectives, rv);
	TEST_ASSERT_EQUAL_INT(1, ret);

	// create and add the directive to the rv list
	rvlist = fdo_rendezvous_list_alloc();
	TEST_ASSERT_NOT_NULL(rvlist);
	ret = fdo_rendezvous_directive_add(rvlist, rvdirectives);
	TEST_ASSERT_EQUAL_INT(1, ret);

	ret = fdo_rendezvous_list_write(fdow, rvlist);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (rvlist) {
		fdo_rendezvous_list_free(rvlist);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_read", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_read(void)
#endif
{
	//TO-DO: Encapsulate sample CBOR encoded RV blob with byte strings
	TEST_IGNORE();
	fdor_t *fdor = NULL;
	fdo_rendezvous_list_t *rvlist = NULL;
	bool ret;
	// sample CBOR encoded RV blob
	uint8_t rv_cbor[] = {
		0x81, 0x85, 0x82, 0x05, 0x69, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74,
		0x82, 0x03, 0x19, 0x1F, 0x68, 0x82, 0x0C, 0x01, 0x82, 0x02, 0x44, 0x7F, 0x00, 0x00,
		0x01, 0x82, 0x04, 0x19, 0x20, 0xFB
	};

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(rv_cbor), rv_cbor, sizeof(rv_cbor));
	fdor->b.block_size = sizeof(rv_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	ret = fdo_rendezvous_list_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rvlist = fdo_rendezvous_list_alloc();
	TEST_ASSERT_NOT_NULL(rvlist);
	ret = fdo_rendezvous_list_read(fdor, rvlist);
	TEST_ASSERT_TRUE(ret);

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	if (rvlist) {
		fdo_rendezvous_list_free(rvlist);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_add", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_add(void)
#endif
{
	fdo_rendezvous_directive_t directives = {0};
	fdo_rendezvous_t rv1 = {0};
	fdo_rendezvous_t rv2 = {0};
	int ret;

	ret = fdo_rendezvous_list_add(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	rv1.dev_only = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv1.dev_only);
	ret = fdo_rendezvous_list_add(&directives, &rv1);
	TEST_ASSERT_EQUAL_INT(1, ret);

	rv2.dev_only = fdo_alloc(sizeof(bool));
	TEST_ASSERT_NOT_NULL(rv2.dev_only);
	ret = fdo_rendezvous_list_add(&directives, &rv2);
	TEST_ASSERT_EQUAL_INT(2, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_get", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_get(void)
#endif
{
	fdo_rendezvous_t *ret = NULL;

	ret = fdo_rendezvous_list_get(NULL, 0);
	TEST_ASSERT_NULL(ret);


}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_read", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_read(void)
#endif
{
	//TO-DO: Update sample CBOR encoded Encrypted Message body with COSE Tag
	TEST_IGNORE();
	fdor_t *fdor = NULL;
	fdo_encrypted_packet_t *pkt = NULL;
	// sample CBOR encoded Encrypted Message body
	// the changes are in
	// protected header alg type {1 : 1/3/30/31}
	// IV 12/7 bytes
#if COSE_ENC_TYPE == 1
	uint8_t enc_msg_cbor[] = {
		0x83, 0x43, 0xa1, 0x01, 0x01, 0xa1, 0x05, 0x4c, 0xfe, 0x6b, 0x0d,
		0x51, 0x5a, 0x74, 0xe6, 0xe8, 0xb5, 0xa0, 0x07, 0x89, 0x54, 0x48,
		0x66, 0x0b, 0x35, 0xbc, 0x04, 0xd1, 0x05, 0x07, 0x9a, 0x0a, 0x2f,
		0xfa, 0x25, 0x28, 0xd3, 0x53, 0x5e, 0xb5, 0x1e
	};
#elif COSE_ENC_TYPE == 3
	uint8_t enc_msg_cbor[] = {
		0x83, 0x43, 0xa1, 0x01, 0x03, 0xa1, 0x05, 0x4c, 0xfe, 0x6b, 0x0d,
		0x51, 0x5a, 0x74, 0xe6, 0xe8, 0xb5, 0xa0, 0x07, 0x89, 0x54, 0x48,
		0x66, 0x0b, 0x35, 0xbc, 0x04, 0xd1, 0x05, 0x07, 0x9a, 0x0a, 0x2f,
		0xfa, 0x25, 0x28, 0xd3, 0x53, 0x5e, 0xb5, 0x1e
	};
#elif COSE_ENC_TYPE == 32
	uint8_t enc_msg_cbor[] = {
		0x83, 0x44, 0xa1, 0x01, 0x18, 0x20, 0xa1, 0x05, 0x47, 0xfe, 0x6b,
		0x0d, 0x51, 0x5a, 0x74, 0xe6, 0x54,
		0x48, 0x66, 0x0b, 0x35, 0xbc, 0x04, 0xd1, 0x05, 0x07, 0x9a, 0x0a,
		0x2f, 0xfa, 0x25, 0x28, 0xd3, 0x53, 0x5e, 0xb5, 0x1e
	};
#else
	uint8_t enc_msg_cbor[] = {
		0x83, 0x44, 0xa1, 0x01, 0x18, 0x21, 0xa1, 0x05, 0x47, 0xfe, 0x6b,
		0x0d, 0x51, 0x5a, 0x74, 0xe6, 0x54,
		0x48, 0x66, 0x0b, 0x35, 0xbc, 0x04, 0xd1, 0x05, 0x07, 0x9a, 0x0a,
		0x2f, 0xfa, 0x25, 0x28, 0xd3, 0x53, 0x5e, 0xb5, 0x1e
	};
#endif

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(enc_msg_cbor), enc_msg_cbor, sizeof(enc_msg_cbor));
	fdor->b.block_size = sizeof(enc_msg_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	pkt = fdo_encrypted_packet_read(NULL);
	TEST_ASSERT_NULL(pkt);

	// positive test-case
	pkt = fdo_encrypted_packet_read(fdor);
	TEST_ASSERT_NOT_NULL(pkt);
	if (pkt) {
		fdo_encrypted_packet_free(pkt);
		pkt = NULL;
	}

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	if (pkt) {
		fdo_encrypted_packet_free(pkt);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_windup", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_windup(void)
#endif
{
	// test this when encryption is mocked, add 'fdo_encrypted_packet_unwind()' as well
	// ignore the test for now
	TEST_IGNORE();

	fdow_t *fdow = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_encrypted_packet_windup(NULL, 0);
	TEST_ASSERT_FALSE(ret);

	// empty fdow.b.block cannot be written, since there is nothing to write
	ret = fdo_encrypted_packet_windup(fdow, 70);
	TEST_ASSERT_FALSE(ret);

	// random CBOR data being generated
	TEST_ASSERT_TRUE(fdow_boolean(fdow, true));
	ret = fdo_encrypted_packet_windup(fdow, 70);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_aad_write", "[fdo_types][fdo]")
#else
void test_fdo_aad_write(void)
#endif
{

	fdow_t *fdow = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_aad_write(NULL, COSE_ENC_TYPE);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_aad_write(fdow, COSE_ENC_TYPE);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_emblock_write", "[fdo_types][fdo]")
#else
void test_fdo_emblock_write(void)
#endif
{

	fdow_t *fdow = NULL;
	fdo_encrypted_packet_t *pkt = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_emblock_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	pkt = fdo_encrypted_packet_alloc();
	TEST_ASSERT_NOT_NULL(pkt);
	pkt->aes_plain_type = COSE_ENC_TYPE;
	pkt->em_body = fdo_byte_array_alloc(10);
	ret = fdo_emblock_write(fdow, pkt);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (pkt) {
		fdo_encrypted_packet_free(pkt);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_eat_write_payloadbasemap", "[fdo_types][fdo]")
#else
void test_fdo_eat_write_payloadbasemap(void)
#endif
{
	fdow_t *fdow = NULL;
	fdo_eat_payload_base_map_t *payload = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_eat_write_payloadbasemap(NULL, NULL);
	TEST_ASSERT_FALSE(ret);
	payload = fdo_alloc(sizeof(fdo_eat_payload_base_map_t));
	TEST_ASSERT_NOT_NULL(payload);
	ret = fdo_eat_write_payloadbasemap(fdow, payload);
	TEST_ASSERT_TRUE(ret);

	payload->eatpayloads = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(payload->eatpayloads);
	memset_s(fdow->b.block, fdow->b.block_size, 0);
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));
	ret = fdo_eat_write_payloadbasemap(fdow, payload);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (payload) {
		fdo_byte_array_free(payload->eatpayloads);
		fdo_free(payload);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_eat_write", "[fdo_types][fdo]")
#else
void test_fdo_eat_write(void)
#endif
{

	fdow_t *fdow = NULL;
	fdo_eat_t *eat = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_eat_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	eat = fdo_eat_alloc();
	TEST_ASSERT_NOT_NULL(eat);
	eat->eat_payload = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(eat->eat_payload);
	eat->eat_signature = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(eat->eat_signature);

	ret = fdo_eat_write(fdow, eat);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (eat) {
		fdo_eat_free(eat);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_cose_read", "[fdo_types][fdo]")
#else
void test_fdo_cose_read(void)
#endif
{
	//TO-DO: Update sample COSE CBOR with COSE Tag
	TEST_IGNORE();
	fdor_t *fdor = NULL;
	fdo_cose_t *cose = NULL;
	bool ret;
	uint8_t cose_cbor[] = {
		0x84, 0x44, 0xA1, 0x01, 0x38, 0x22, 0xA0, 0x41, 0x02, 0x41, 0x02
	};

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(cose_cbor), cose_cbor, sizeof(cose_cbor));
	fdor->b.block_size = sizeof(cose_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	ret = fdo_cose_read(NULL, NULL, true);
	TEST_ASSERT_FALSE(ret);

	cose = fdo_alloc(sizeof(fdo_cose_t));
	ret = fdo_cose_read(fdor, cose, true);
	TEST_ASSERT_TRUE(ret);

	memcpy_s(fdor->b.block, sizeof(cose_cbor), cose_cbor, sizeof(cose_cbor));
	fdor->b.block_size = sizeof(cose_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));
	ret = fdo_cose_read(fdor, cose, false);
	TEST_ASSERT_FALSE(ret);

	cose_cbor[0] = 0x83;
	memcpy_s(fdor->b.block, sizeof(cose_cbor), cose_cbor, sizeof(cose_cbor));
	fdor->b.block_size = sizeof(cose_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));
	ret = fdo_cose_read(fdor, cose, true);
	TEST_ASSERT_FALSE(ret);

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_cose_write", "[fdo_types][fdo]")
#else
void test_fdo_cose_write(void)
#endif
{
	fdow_t *fdow = NULL;
	fdo_cose_t *cose = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_cose_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	cose = fdo_alloc(sizeof(fdo_cose_t));
	TEST_ASSERT_NOT_NULL(cose);
	cose->cose_payload = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(cose->cose_payload);
	cose->cose_signature = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(cose->cose_signature);

	// missing parameters
	ret = fdo_cose_write(fdow, cose);
	TEST_ASSERT_FALSE(ret);

	cose->cose_ph = fdo_alloc(sizeof(fdo_cose_protected_header_t));
	TEST_ASSERT_NOT_NULL(cose->cose_ph);
	cose->cose_uph = fdo_alloc(sizeof(fdo_cose_unprotected_header_t));
	TEST_ASSERT_NOT_NULL(cose->cose_uph);
	ret = fdo_cose_write(fdow, cose);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
	if (cose) {
		fdo_cose_free(cose);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_siginfo_read", "[fdo_types][fdo]")
#else
void test_fdo_siginfo_read(void)
#endif
{
	fdor_t *fdor = NULL;
	bool ret;
#if defined(ECDSA384_DA)
	uint8_t siginfo_cbor[] = {
		0x82, 0x38, 0x22, 0x40
	};
#else
	uint8_t siginfo_cbor[] = {
		0x82, 0x26, 0x40
	};
#endif

	fdor = fdo_alloc(sizeof(fdor_t));
	TEST_ASSERT_NOT_NULL(fdor);
	TEST_ASSERT_TRUE(fdor_init(fdor));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdor->b));
	memcpy_s(fdor->b.block, sizeof(siginfo_cbor), siginfo_cbor, sizeof(siginfo_cbor));
	fdor->b.block_size = sizeof(siginfo_cbor);
	TEST_ASSERT_TRUE(fdor_parser_init(fdor));

	ret = fdo_siginfo_read(NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_siginfo_read(fdor);
	TEST_ASSERT_TRUE(ret);

	if (fdor) {
		fdor_flush(fdor);
		fdo_free(fdor);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_siginfo_write", "[fdo_types][fdo]")
#else
void test_fdo_siginfo_write(void)
#endif
{
	fdow_t *fdow = NULL;
	bool ret;

	fdow = fdo_alloc(sizeof(fdow_t));
	TEST_ASSERT_NOT_NULL(fdow);
	TEST_ASSERT_TRUE(fdow_init(fdow));
	TEST_ASSERT_TRUE(fdo_block_alloc(&fdow->b));
	TEST_ASSERT_TRUE(fdow_encoder_init(fdow));

	ret = fdo_siginfo_write(NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_siginfo_write(fdow);
	TEST_ASSERT_TRUE(ret);

	if (fdow) {
		fdow_flush(fdow);
		fdo_free(fdow);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_signature_verification", "[fdo_types][fdo]")
#else
void test_fdo_signature_verification(void)
#endif
{
	fdo_byte_array_t plain_text = {
	    0,
	};
	fdo_byte_array_t sg = {
	    0,
	};
	fdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = fdo_signature_verification(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_signature_verification(&plain_text, &sg, &pk);
	TEST_ASSERT_FALSE(ret);

	// Random bytes
	plain_text.bytes = fdo_alloc(100);
	plain_text.byte_sz = 100;
	sg.bytes = fdo_alloc(100);
	sg.byte_sz = 100;
	ret = fdo_signature_verification(&plain_text, &sg, &pk);
	TEST_ASSERT_FALSE(ret);
	fdo_free(plain_text.bytes);
	fdo_free(sg.bytes);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_kv_alloc_with_str", "[fdo_types][fdo]")
#else
void test_fdo_kv_alloc_with_str(void)
#endif
{
	fdo_key_value_t *ret;

	ret = fdo_kv_alloc_with_str(NULL, NULL);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_service_info_add_kv_str", "[fdo_types][fdo]")
#else
void test_fdo_service_info_add_kv_str(void)
#endif
{
	fdo_service_info_t *si = NULL;
	bool ret;

	// sanity negative case
	ret = fdo_service_info_add_kv_str(si, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	si = fdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	// value=NULL is a positive case
	ret = fdo_service_info_add_kv_str(si, "dummy_key", "");
	TEST_ASSERT_TRUE(ret);

	// key=NULL is a negative case
	ret = fdo_service_info_add_kv_str(si, "", "dummy_value");
	TEST_ASSERT_FALSE(ret);

	// key=non-NULL and val=non-NULL is a positive case
	ret =
	    fdo_service_info_add_kv_str(si, "dummy_key", "dummy_initial_value");
	TEST_ASSERT_TRUE(ret);

	// update existing key with updated value is a positive case
	ret =
	    fdo_service_info_add_kv_str(si, "dummy_key", "dummy_updated_value");
	TEST_ASSERT_TRUE(ret);
	if (si)
		fdo_service_info_free(si);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_service_info_add_kv_bool", "[fdo_types][fdo]")
#else
void test_fdo_service_info_add_kv_bool(void)
#endif
{
	fdo_service_info_t *si = NULL;
	bool ret;

	// sanity negative case
	ret = fdo_service_info_add_kv_bool(si, NULL, false);
	TEST_ASSERT_FALSE(ret);

	si = fdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	// value=NULL is a positive case
	ret = fdo_service_info_add_kv_bool(si, "dummy_key", true);
	TEST_ASSERT_TRUE(ret);

	// key=NULL is a negative case
	ret = fdo_service_info_add_kv_bool(si, "", false);
	TEST_ASSERT_FALSE(ret);

	// update existing key with updated value is a positive case
	ret =
	    fdo_service_info_add_kv_bool(si, "dummy_key", false);
	TEST_ASSERT_TRUE(ret);

	if (si) {
		fdo_service_info_free(si);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_service_info_add_kv_int", "[fdo_types][fdo]")
#else
void test_fdo_service_info_add_kv_int(void)
#endif
{
	fdo_service_info_t *si = NULL;
	bool ret;

	// sanity negative case
	ret = fdo_service_info_add_kv_int(si, NULL, 0);
	TEST_ASSERT_FALSE(ret);

	si = fdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	// positive case
	ret = fdo_service_info_add_kv_int(si, "dummy_key", -1);
	TEST_ASSERT_TRUE(ret);

	// key=NULL is a negative case
	ret = fdo_service_info_add_kv_int(si, "", 7);
	TEST_ASSERT_FALSE(ret);

	// update existing key with updated value is a positive case
	ret =
	    fdo_service_info_add_kv_int(si, "dummy_key", 7);
	TEST_ASSERT_TRUE(ret);

	if (si) {
		fdo_service_info_free(si);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_service_info_add_kv_bin", "[fdo_types][fdo]")
#else
void test_fdo_service_info_add_kv_bin(void)
#endif
{
	fdo_service_info_t *si = NULL;
	fdo_byte_array_t *bytes = NULL;
	bool ret;

	// sanity negative case
	ret = fdo_service_info_add_kv_bin(si, NULL, 0);
	TEST_ASSERT_FALSE(ret);

	si = fdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	// positive case
	bytes = fdo_byte_array_alloc(10);
	TEST_ASSERT_NOT_NULL(bytes);
	ret = fdo_service_info_add_kv_bin(si, "dummy_key", bytes);
	TEST_ASSERT_TRUE(ret);

	// key=NULL is a negative case
	ret = fdo_service_info_add_kv_bin(si, "", bytes);
	TEST_ASSERT_FALSE(ret);

	// update existing key with updated value is a positive case
	memset_s(bytes->bytes, 10, 1);
	ret =
	    fdo_service_info_add_kv_bin(si, "dummy_key", bytes);
	TEST_ASSERT_TRUE(ret);

	if (si) {
		fdo_service_info_free(si);
	}
	if (bytes){
		fdo_byte_array_free(bytes);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_service_info_add_kv", "[fdo_types][fdo]")
#else
void test_fdo_service_info_add_kv(void)
#endif
{
	fdo_service_info_t si = {
	    0,
	};
	fdo_key_value_t kvs = {
	    0,
	};
	bool ret;

	ret = fdo_service_info_add_kv(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_service_info_add_kv(&si, &kvs);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("_fdo_serviceinfo_invalid_modname_add", "[fdo_types][fdo]")
#else
void test_fdo_serviceinfo_invalid_modname_add(void)
#endif
{
	bool ret = false;
	fdo_sv_invalid_modnames_t *serviceinfo_invalid_modnames = NULL;

	ret = fdo_serviceinfo_invalid_modname_add("testmod1", &serviceinfo_invalid_modnames);
	TEST_ASSERT_TRUE(ret);
	TEST_ASSERT_NOT_NULL(serviceinfo_invalid_modnames);

	ret = fdo_serviceinfo_invalid_modname_add("testmod1", &serviceinfo_invalid_modnames);
	TEST_ASSERT_TRUE(ret);
	TEST_ASSERT_NOT_NULL(serviceinfo_invalid_modnames);

	ret = fdo_serviceinfo_invalid_modname_add("testmod2", &serviceinfo_invalid_modnames);
	TEST_ASSERT_TRUE(ret);
	TEST_ASSERT_NOT_NULL(serviceinfo_invalid_modnames->next);

	ret = fdo_serviceinfo_invalid_modname_add("testmod1", NULL);
	TEST_ASSERT_FALSE(ret);

	fdo_serviceinfo_invalid_modname_free(serviceinfo_invalid_modnames);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_compare_hashes", "[fdo_types][fdo]")
#else
void test_fdo_compare_hashes(void)
#endif
{
	int ret = -1;
	fdo_hash_t *h1 = NULL;
	fdo_hash_t *h2 = NULL;

	char hash1[50] = "this is a sample hash1";
	char hash2[50] = "this is a sample hash2";

	h1 = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 50);
	TEST_ASSERT_NOT_EQUAL(h1, NULL);

	ret = memcpy_s(h1->hash->bytes, 50, (uint8_t *)hash1,
		       strnlen_s(hash1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	h2 = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_SHA_256, 50);
	TEST_ASSERT_NOT_EQUAL(h2, NULL);

	// same hash content
	ret = memcpy_s(h2->hash->bytes, 50, (uint8_t *)hash1,
		       strnlen_s(hash1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	// positive case
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, h2), true);

	// Negative cases
	TEST_ASSERT_EQUAL(fdo_compare_hashes(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_hashes(NULL, h2), false);
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, NULL), false);

	h1->hash_type = FDO_CRYPTO_HASH_TYPE_SHA_384;
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, h2), false);

	// different hash content
	ret = memcpy_s(h2->hash->bytes, 50, (uint8_t *)hash2,
		       strnlen_s(hash2, 50));
	TEST_ASSERT_EQUAL(ret, 0);
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, h2), false);

	fdo_hash_free(h1);
	fdo_hash_free(h2);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_compare_byte_arrays", "[fdo_types][fdo]")
#else
void test_fdo_compare_byte_arrays(void)
#endif
{
	int ret = -1;
	fdo_byte_array_t *ba1 = NULL;
	fdo_byte_array_t *ba2 = NULL;

	char array1[50] = "this is a sample array1";
	char array2[50] = "this is a sample array2";

	ba1 = fdo_byte_array_alloc(50);
	TEST_ASSERT_NOT_EQUAL(ba1, NULL);

	ret =
	    memcpy_s(ba1->bytes, 50, (uint8_t *)array1, strnlen_s(array1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	ba2 = fdo_byte_array_alloc(50);
	TEST_ASSERT_NOT_EQUAL(ba2, NULL);

	// same array content
	ret =
	    memcpy_s(ba2->bytes, 50, (uint8_t *)array1, strnlen_s(array1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	// positive case
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(ba1, ba2), true);

	// Negative cases
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(NULL, ba2), false);
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(ba1, NULL), false);

	// different array content
	ret =
	    memcpy_s(ba2->bytes, 50, (uint8_t *)array2, strnlen_s(array2, 50));
	TEST_ASSERT_EQUAL(ret, 0);
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(ba1, ba2), false);

	fdo_byte_array_free(ba1);
	fdo_byte_array_free(ba2);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_compare_rv_lists", "[fdo_types][fdo]")
#else
void test_fdo_compare_rvLists(void)
#endif
{
	fdo_rendezvous_list_t list1 = {0};
	fdo_rendezvous_list_t list2 = {0};

	// positive case
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(&list1, &list2), true);

	// Negative cases
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(NULL, &list2), false);
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(&list1, NULL), false);
}
