#include "unity.h"
#include "crypto_utils.h"
#include "fdoprot.h"
#include "base64.h"
#include "fdotypes.h"
#include "fdoCryptoHal.h"
#include "util.h"
#include "fdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

/*!
 * \file
 * \brief Unit tests for FDO defined data structure parsing/packing routines.
 */

/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_fdo_bits_init(void);
void test_fdo_bits_alloc_with(void);
void test_fdo_bits_fill(void);
void test_fdo_bits_toString(void);
void test_fdo_byte_array_append(void);
void test_fdo_byte_array_read_chars(void);
void test_fdo_byte_array_read(void);
void test_fdo_byte_array_read_with_type(void);
void test_fdo_string_alloc_with(void);
void test_fdo_string_alloc_str(void);
void test_fdo_string_resize(void);
void test_fdo_string_resize_with(void);
void test_fdo_string_read(void);
void test_fdo_nonce_equal(void);
void test_fdo_hash_read(void);
void test_fdo_hash_null_write(void);
void test_fdo_init_ipv4_address(void);
void test_fdoIPAddress_toString(void);
void test_fdo_read_ipaddress(void);
void test_fdo_public_key_clone(void);
void test_fdo_compare_public_keys(void);
void test_fdo_public_key_free(void);
void test_fdoPKAlg_toString(void);
void test_fdoPKEnc_toString(void);
void test_fdo_public_key_write(void);
void test_fdo_public_key_toString(void);
void test_fdo_public_key_read(void);
void test_fdo_rendezvous_free(void);
void test_fdo_rendezvous_write(void);
void test_keyfromstring(void);
void test_fdo_rendezvous_read(void);
void test_fdo_rendezvous_list_add(void);
void test_fdo_rendezvous_list_get(void);
void test_fdo_rendezvous_list_read(void);
void test_fdo_rendezvous_list_write(void);
void test_fdo_encrypted_packet_read(void);
void test_fdo_get_iv(void);
void test_fdo_write_iv(void);
void test_fdo_encrypted_packet_write(void);
void test_fdo_encrypted_packet_write_unwind(void);
void test_fdo_encrypted_packet_windup(void);
void test_fdo_begin_write_signature(void);
void test_fdo_end_write_signature(void);
void test_fdo_begin_readHMAC(void);
void test_fdo_end_readHMAC(void);
void test_fdo_begin_read_signature(void);
void test_fdo_end_read_signature_full(void);
void test_fdo_signature_verification(void);
void test_fdo_read_pk_null(void);
void test_fdoOVSignature_verification(void);
void test_fdo_kv_alloc_with_array(void);
void test_fdo_kv_alloc_with_str(void);
void test_fdo_service_info_alloc_with(void);
void test_fdo_service_info_add_kv_str(void);
void test_fdo_service_info_add_kv(void);
void test_psiparsing(void);
void test_fdo_get_module_name_msg_value(void);
void test_fdo_mod_data_kv(void);
void test_fdo_osi_parsing(void);
static int cb(fdo_sdk_si_type type, int *count, fdo_sdk_si_key_value *si);
void test_fdo_get_dsi_count(void);
void test_fdo_supply_moduleOSI(void);
void test_fdo_supply_modulePSI(void);
void test_fdo_construct_module_dsi(void);
void test_fdo_compare_hashes(void);
void test_fdo_compare_byte_arrays(void);
void test_fdo_compare_rvLists(void);

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

	b = malloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);

	ret = fdo_bits_init(b, 100);
	TEST_ASSERT_NOT_NULL(ret);

	fdo_bits_free(b);

	b = malloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);
	b->bytes = malloc(5);
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

	data = malloc(100);
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

	free(data);
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

	bits = malloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = NULL;
	bits->byte_sz = 0;
	ret = fdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	fdo_bits_free(bits);

	bits = malloc(sizeof(fdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = malloc(100);
	TEST_ASSERT_NOT_NULL(bits->bytes);
	bits->byte_sz = 0;
	ret = fdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	free(bits);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_bits_to_string", "[fdo_types][fdo]")
#else
void test_fdo_bits_toString(void)
#endif
{
	fdo_bits_t b;
	char *typename = "test";
	char *buf = "test_string";
	int buf_sz;
	char *ret;

	buf_sz = 10;
	ret = fdo_bits_to_string(NULL, typename, buf, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = fdo_bits_to_string(&b, NULL, buf, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = fdo_bits_to_string(&b, typename, NULL, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = fdo_bits_to_string(&b, typename, buf, 0);
	TEST_ASSERT_NOT_NULL(ret);
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

	baA = malloc(sizeof(fdo_byte_array_t));
	TEST_ASSERT_NOT_NULL(baA);
	baB = malloc(sizeof(fdo_byte_array_t));
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
	baA->bytes = malloc(10);
	baB->bytes = malloc(10);

	ret = fdo_byte_array_append(baA, baB);
	TEST_ASSERT_NOT_NULL(ret);
	fdo_byte_array_free(ret);

	free(baB->bytes);
	free(baA->bytes);
	free(baA);
	free(baB);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_byte_array_read_chars", "[fdo_types][fdo]")
#else
void test_fdo_byte_array_read_chars(void)
#endif
{
	fdor_t fdor;
	fdo_byte_array_t ba;
	int ret;

	ret = fdo_byte_array_read_chars(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	memset_s(&fdor, sizeof(fdor), 0);
	memset_s(&ba, sizeof(ba), 0);

	ret = fdo_byte_array_read_chars(&fdor, &ba);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_byte_array_read", "[fdo_types][fdo]")
#else
void test_fdo_byte_array_read(void)
#endif
{
	fdor_t fdor;
	fdo_byte_array_t ba;
	int ret;

	ret = fdo_byte_array_read(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	memset_s(&fdor, sizeof(fdor), 0);
	memset_s(&ba, sizeof(ba), 0);

	ret = fdo_byte_array_read(&fdor, &ba);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_byte_array_read_with_type", "[fdo_types][fdo]")
#else
void test_fdo_byte_array_read_with_type(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_byte_array_t ba = {
	    0,
	};
	uint8_t type;
	int ret;
	fdo_byte_array_t *ctp = NULL;

	ret = fdo_byte_array_read_with_type(NULL, NULL, NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = fdo_byte_array_read_with_type(&fdor, &ba, &ctp, &type);
	TEST_ASSERT_EQUAL_INT(0, ret);
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

	data = malloc(10);
	TEST_ASSERT_NOT_NULL(data);
	ret = fdo_string_alloc_with(data, 1);
	TEST_ASSERT_NOT_NULL(ret);
	fdo_string_free(ret);
	free(data);

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

	data = malloc(FDO_MAX_STR_SIZE * 2);
	TEST_ASSERT_NOT_NULL(data);
	memset_s(data, FDO_MAX_STR_SIZE * 2, 'a');
	data[(FDO_MAX_STR_SIZE * 2) - 1] = 0;

	ret = fdo_string_alloc_with_str(data);
	TEST_ASSERT_NULL(ret);

	free(data);
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

	data = malloc(100);
	TEST_ASSERT_NOT_NULL(data);
	ret = fdo_string_resize_with(&b, 0, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	b.bytes = NULL;

	ret = fdo_string_resize_with(&b, -1, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	b.bytes = NULL;

	ret = fdo_string_resize_with(&b, 100, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_string_read", "[fdo_types][fdo]")
#else
void test_fdo_string_read(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_string_t b = {
	    0,
	};
	bool ret;

	ret = fdo_string_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_string_read(&fdor, &b);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
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
	fdor_t fdor = {
	    0,
	};
	fdo_hash_t hp = {
	    0,
	};
	int ret;

	ret = fdo_hash_read(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 10, '[');
	ret = fdo_hash_read(&fdor, &hp);
	TEST_ASSERT_EQUAL_INT(0, ret);
	if (hp.hash) {
		fdo_byte_array_free(hp.hash);
	}
	if (fdor.b.block_size != 0) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_hash_null_write", "[fdo_types][fdo]")
#else
void test_fdo_hash_null_write(void)
#endif
{
	/*function returns void
	 * so call only to see NULL check*/
	fdo_hash_null_write(NULL);
	TEST_ASSERT_TRUE(1);
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

	/*function returns void
	 * so call only to see NULL check*/
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
	fdor_t fdor = {
	    0,
	};
	fdo_ip_address_t fdoip = {
	    0,
	};
	bool ret;

	ret = fdo_read_ipaddress(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_read_ipaddress(&fdor, &fdoip);
	TEST_ASSERT_FALSE(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 10, '[');

	ret = fdo_read_ipaddress(&fdor, &fdoip);
	TEST_ASSERT_FALSE(ret);
	if (fdor.b.block_size != 0) {
		free(fdor.b.block);
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
	key1.bytes = malloc(10);
	memset_s(key1.bytes, 10, 0);
	key3.byte_sz = 10;
	key3.bytes = malloc(10);
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
	/*function returns void
	 * so call only to see NULL check*/

	fdo_public_key_free(NULL);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_pk_alg_to_string", "[fdo_types][fdo]")
#else
void test_fdoPKAlg_toString(void)
#endif
{
	const char *ret;

	ret = fdo_pk_alg_to_string(FDO_CRYPTO_PUB_KEY_ALGO_NONE);
	TEST_ASSERT_EQUAL_STRING("AlgNONE", ret);

	ret = fdo_pk_alg_to_string(FDO_CRYPTO_PUB_KEY_ALGO_RSA);
	TEST_ASSERT_EQUAL_STRING("AlgRSA", ret);

	ret = fdo_pk_alg_to_string(FDO_CRYPTO_PUB_KEY_ALGO_EPID_1_1);
	TEST_ASSERT_EQUAL_STRING("AlgEPID11", ret);

	ret = fdo_pk_alg_to_string(FDO_CRYPTO_PUB_KEY_ALGO_EPID_2_0);
	TEST_ASSERT_EQUAL_STRING("AlgEPID20", ret);

	ret = fdo_pk_alg_to_string(-1);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_pk_enc_to_string", "[fdo_types][fdo]")
#else
void test_fdoPKEnc_toString(void)
#endif
{
	const char *ret;

	ret = fdo_pk_enc_to_string(FDO_CRYPTO_PUB_KEY_ENCODING_X509);
	TEST_ASSERT_EQUAL_STRING("EncX509", ret);

	ret = fdo_pk_enc_to_string(FDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP);
	TEST_ASSERT_EQUAL_STRING("EncRSAMODEXP", ret);

	ret = fdo_pk_enc_to_string(FDO_CRYPTO_PUB_KEY_ENCODING_EPID);
	TEST_ASSERT_EQUAL_STRING("EncEPID", ret);

	ret = fdo_pk_enc_to_string(-1);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_write", "[fdo_types][fdo]")
#else
void test_fdo_public_key_write(void)
#endif
{
	fdow_t fdow = {
	    0,
	};
	fdo_public_key_t pk;
	/*function returns void
	 * so call only to see NULL check*/
	fdo_public_key_write(NULL, &pk);
	TEST_ASSERT_TRUE(1);

	fdo_public_key_write(&fdow, NULL);
	TEST_ASSERT_TRUE(1);
	if (fdow.b.block != NULL) {
		fdo_free(fdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_to_string", "[fdo_types][fdo]")
#else
void test_fdo_public_key_toString(void)
#endif
{
	char *ret;
	char buf[128] = {
	    0,
	};
	fdo_public_key_t pk = {
	    0,
	};

	ret = fdo_public_key_to_string(NULL, NULL, 0);
	TEST_ASSERT_NULL(ret);

	ret = fdo_public_key_to_string(&pk, buf, 0);
	TEST_ASSERT_NULL(ret);

	ret = fdo_public_key_to_string(&pk, buf, 3);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_public_key_read", "[fdo_types][fdo]")
#else
void test_fdo_public_key_read(void)
#endif
{
	fdo_public_key_t *ret;
	fdor_t fdor = {
	    0,
	};

	ret = fdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 3, '[');
	ret = fdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 3, '[');
	memset_s(fdor.b.block + 3, 5, ']');
	ret = fdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 3, '[');
	memset_s(fdor.b.block + 3, 7, '[');
	ret = fdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);
	if (fdor.b.block_size != 0) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_free", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_free(void)
#endif
{
	fdo_rendezvous_t *rv;

	fdo_rendezvous_free(NULL);
	rv = malloc(sizeof(fdo_rendezvous_t));
	TEST_ASSERT_NOT_NULL(rv);
	memset_s(rv, sizeof(fdo_rendezvous_t), 0);
	rv->ip = malloc(sizeof(fdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_NONE,
				 FDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_NONE,
				 FDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = malloc(sizeof(uint32_t));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = fdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = fdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = fdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = fdo_string_alloc_with_str("Test str 4");
	TEST_ASSERT_NOT_NULL(rv->me);
	fdo_rendezvous_free(rv);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_write", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_write(void)
#endif
{

	fdow_t fdow = {
	    0,
	};
	fdo_rendezvous_t *rv;
	bool ret;

	ret = fdo_rendezvous_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rv = malloc(sizeof(fdo_rendezvous_t));
	TEST_ASSERT_NOT_NULL(rv);
	memset_s(rv, sizeof(fdo_rendezvous_t), 0);
	rv->ip = malloc(sizeof(fdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_NONE,
				 FDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = fdo_hash_alloc(FDO_CRYPTO_HASH_TYPE_NONE,
				 FDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = malloc(sizeof(uint32_t));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = fdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = fdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = fdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = fdo_string_alloc_with_str("Test str 4");
	TEST_ASSERT_NOT_NULL(rv->me);

	ret = fdo_rendezvous_write(&fdow, rv);
	TEST_ASSERT_TRUE(ret);
	fdo_rendezvous_free(rv);
	if (fdow.b.block != NULL) {
		fdo_free(fdow.b.block);
	}
}

extern int keyfromstring(char *key);
#ifdef TARGET_OS_FREERTOS
TEST_CASE("keyfromstring", "[fdo_types][fdo]")
#else
void test_keyfromstring(void)
#endif
{
	char *key = "Invalid";
	int ret;

	ret = keyfromstring(NULL);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	ret = keyfromstring(key);
	TEST_ASSERT_EQUAL_INT(-1, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_read", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_read(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_rendezvous_t *rv;
	bool ret;

	ret = fdo_rendezvous_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rv = malloc(sizeof(fdo_rendezvous_t));
	memset_s(rv, sizeof(fdo_rendezvous_t), 0);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 10, '[');
	ret = fdo_rendezvous_read(&fdor, rv);
	TEST_ASSERT_FALSE(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 5, '[');

	fdow_begin_sequence((fdow_t *)&fdor);
	ret = fdo_rendezvous_read(&fdor, rv);
	TEST_ASSERT_FALSE(ret);
	free(rv);
	if (fdor.b.block_size != 0) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_add", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_add(void)
#endif
{
	fdo_rendezvous_list_t list = {
	    0,
	};
	fdo_rendezvous_t rv = {
	    0,
	};
	int ret;

	ret = fdo_rendezvous_list_add(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_rendezvous_list_add(&list, &rv);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_get", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_get(void)
#endif
{
	fdo_rendezvous_t *ret;

	ret = fdo_rendezvous_list_get(NULL, 0);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_read", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_read(void)
#endif
{
	int ret;
	fdor_t fdor = {
	    0,
	};
	fdo_rendezvous_list_t list = {
	    0,
	};

	ret = fdo_rendezvous_list_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_rendezvous_list_read(&fdor, &list);
	TEST_ASSERT_FALSE(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 10, '[');
	ret = fdo_rendezvous_list_read(&fdor, &list);
	TEST_ASSERT_FALSE(ret);
	if (fdor.b.block_size != 0) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_rendezvous_list_write", "[fdo_types][fdo]")
#else
void test_fdo_rendezvous_list_write(void)
#endif
{
	int ret;
	fdow_t fdow = {
	    0,
	};
	fdo_rendezvous_list_t list = {
	    0,
	};

	ret = fdo_rendezvous_list_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_rendezvous_list_write(&fdow, &list);
	TEST_ASSERT_TRUE(ret);
	if (fdow.b.block != NULL) {
		fdo_free(fdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_read", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_read(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_encrypted_packet_t *ret;

	ret = fdo_encrypted_packet_read(NULL);
	TEST_ASSERT_NULL(ret);

	ret = fdo_encrypted_packet_read(&fdor);
	TEST_ASSERT_NULL(ret);

	fdow_begin_sequence((fdow_t *)&fdor);
	// Increse the block size to pass sequence read
	fdor.b.block_size += 10;
	memset_s(fdor.b.block, 10, '[');

	ret = fdo_encrypted_packet_read(&fdor);
	TEST_ASSERT_NULL(ret);
	if (fdor.b.block_size != 0) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_get_iv", "[fdo_types][fdo]")
#else
void test_fdo_get_iv(void)
#endif
{
	bool ret;

	ret = fdo_get_iv(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_write", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_write(void)
#endif
{
	fdow_t fdow = {
	    0,
	};
	fdo_encrypted_packet_t pkt = {
	    0,
	};

	fdo_encrypted_packet_write(NULL, NULL);
	fdo_encrypted_packet_write(&fdow, &pkt);
	TEST_ASSERT_TRUE(1);
	if (fdow.b.block != NULL) {
		fdo_free(fdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_write_unwind", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_write_unwind(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_encrypted_packet_t *pkt = NULL;
	bool ret;

	ret = fdo_encrypted_packet_unwind(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_encrypted_packet_unwind(&fdor, pkt);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_encrypted_packet_windup", "[fdo_types][fdo]")
#else
void test_fdo_encrypted_packet_windup(void)
#endif
{
	fdow_t fdow = {
	    0,
	};
	bool ret;

	ret = fdo_encrypted_packet_windup(NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_encrypted_packet_windup(&fdow, 0);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_begin_write_signature", "[fdo_types][fdo]")
#else
void test_fdo_begin_write_signature(void)
#endif
{
	fdow_t fdow = {
	    0,
	};
	fdo_sig_t sig = {
	    0,
	};
	fdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = fdo_begin_write_signature(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_begin_write_signature(&fdow, NULL, &pk);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_begin_write_signature(&fdow, &sig, &pk);
	TEST_ASSERT_TRUE(ret);
	if (fdow.b.block != NULL) {
		fdo_free(fdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_end_write_signature", "[fdo_types][fdo]")
#else
void test_fdo_end_write_signature(void)
#endif
{
	bool ret = false;
	fdow_t fdow = {0};
	fdo_sig_t sig = {0};

	ret = fdo_end_write_signature(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_end_write_signature(&fdow, &sig);
	TEST_ASSERT_FALSE(ret);

	fdow.b.cursor = 10;

#if defined(EPID_DA)
	ret = fdo_end_write_signature(&fdow, &sig);
	TEST_ASSERT_FALSE(ret);
#endif
	if (fdow.b.block != NULL) {
		free(fdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_begin_readHMAC", "[fdo_types][fdo]")
#else
void test_fdo_begin_readHMAC(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	int sig_block_start;
	bool ret;

	ret = fdo_begin_readHMAC(NULL, &sig_block_start);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_begin_readHMAC(&fdor, &sig_block_start);
	TEST_ASSERT_FALSE(ret);

	fdow_begin_object((fdow_t *)&fdor);
	fdow_begin_object((fdow_t *)&fdor);
	fdow_begin_object((fdow_t *)&fdor);
	ret = fdo_begin_readHMAC(&fdor, &sig_block_start);
	TEST_ASSERT_FALSE(ret);
	if (fdor.b.block != NULL) {
		free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_end_readHMAC", "[fdo_types][fdo]")
#else
void test_fdo_end_readHMAC(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_hash_t *hmac;
	bool ret;

	ret = fdo_end_readHMAC(NULL, NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_end_readHMAC(&fdor, &hmac, 0);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_begin_read_signature", "[fdo_types][fdo]")
#else
void test_fdo_begin_read_signature(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_sig_t sig = {
	    0,
	};
	bool ret;

	ret = fdo_begin_read_signature(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_begin_read_signature(&fdor, &sig);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_end_read_signature_full", "[fdo_types][fdo]")
#else
void test_fdo_end_read_signature_full(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	fdo_sig_t sig = {
	    0,
	};
	fdo_public_key_t *getpk = NULL;
	bool ret;

	ret = fdo_end_read_signature_full(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_end_read_signature_full(&fdor, &sig, &getpk);
	TEST_ASSERT_FALSE(ret);

	fdor.b.cursor = 10;
	ret = fdo_end_read_signature_full(&fdor, &sig, &getpk);
	TEST_ASSERT_FALSE(ret);
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

	/*Random bytes*/
	plain_text.bytes = malloc(100);
	plain_text.byte_sz = 100;
	sg.bytes = malloc(100);
	sg.byte_sz = 100;
	ret = fdo_signature_verification(&plain_text, &sg, &pk);
	TEST_ASSERT_FALSE(ret);
	free(plain_text.bytes);
	free(sg.bytes);
}

bool fdo_read_pk_null(fdor_t *fdor);

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_read_pk_null", "[fdo_types][fdo]")
#else
void test_fdo_read_pk_null(void)
#endif
{
	fdor_t fdor = {
	    0,
	};
	bool ret;

	ret = fdo_read_pk_null(NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_read_pk_null(&fdor);
	TEST_ASSERT_FALSE(ret);

	fdo_write_tag((fdow_t *)&fdor, "pk");
	ret = fdo_read_pk_null(&fdor);
	TEST_ASSERT_FALSE(ret);

	if (fdor.b.block != NULL) {
		fdo_free(fdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdoOVSignature_verification", "[fdo_types][fdo]")
#else
void test_fdoOVSignature_verification(void)
#endif
{
	fdor_t fdor = {0};
	fdo_sig_t sig = {
	    0,
	};
	fdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = fdoOVSignature_verification(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = fdoOVSignature_verification(&fdor, &sig, &pk);
	TEST_ASSERT_FALSE(ret);

	/*Random len*/
	fdor.b.cursor = 10;
	fdor.b.block_size = 20;
	ret = fdoOVSignature_verification(&fdor, &sig, &pk);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_kv_alloc_with_array", "[fdo_types][fdo]")
#else
void test_fdo_kv_alloc_with_array(void)
#endif
{
	fdo_key_value_t *ret;

	ret = fdo_kv_alloc_with_array(NULL, NULL);
	TEST_ASSERT_NULL(ret);
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
TEST_CASE("fdo_service_info_alloc_with", "[fdo_types][fdo]")
#else
void test_fdo_service_info_alloc_with(void)
#endif
{
	char key = 0;
	char val = 0;
	fdo_service_info_t *ret;

	ret = fdo_service_info_alloc_with(NULL, NULL);
	TEST_ASSERT_NULL(ret);

	ret = fdo_service_info_alloc_with(&key, &val);
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

	/* sanity negative case */
	ret = fdo_service_info_add_kv_str(si, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	si = fdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	/* value=NULL is a positive case */
	ret = fdo_service_info_add_kv_str(si, "dummy_key", "");
	TEST_ASSERT_TRUE(ret);

	/* key=NULL is a negative case */
	ret = fdo_service_info_add_kv_str(si, "", "dummy_value");
	TEST_ASSERT_FALSE(ret);

	/* key=non-NULL and val=non-NULL is a positive case */
	ret =
	    fdo_service_info_add_kv_str(si, "dummy_key", "dummy_initial_value");
	TEST_ASSERT_TRUE(ret);

	/* update existing key with updated value is a positive case */
	ret =
	    fdo_service_info_add_kv_str(si, "dummy_key", "dummy_updated_value");
	TEST_ASSERT_TRUE(ret);
	if (si)
		fdo_service_info_free(si);
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
TEST_CASE("psiparsing", "[fdo_types][fdo]")
#else
void test_psiparsing(void)
#endif
{
	char psi_valid_string[100] = "devconfig:maxver~1,devconfig:minver~1";
	int psi_len = 0;
	bool ret = 0;
	int cbret = 0;
	fdo_sdk_service_info_module_list_t list;

	fdo_string_t *psi = malloc(sizeof(fdo_string_t));
	TEST_ASSERT_NOT_NULL(psi);
	psi->bytes = psi_valid_string;
	psi_len = strnlen_s(psi_valid_string, FDO_MAX_STR_SIZE);
	TEST_ASSERT_TRUE(psi_len != 0);
	psi->byte_sz = psi_len;

	// NULL check case
	ret = fdo_psi_parsing(&list, psi->bytes, psi_len, NULL);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, 0);

	// No module case
	ret = fdo_psi_parsing(NULL, psi->bytes, psi_len, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, FDO_SI_SUCCESS);
	free(psi);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_get_module_name_msg_value", "[fdo_types][fdo]")
#else
void test_fdo_get_module_name_msg_value(void)
#endif
{
	char psi[FDO_MAX_STR_SIZE];
	char *psi_tuple = psi;
	int psi_len = 0;
	bool ret = 0;
	int cbret = 0;
	char mod_name[16];
	char msg_name[16];
	char val_name[16];

	/*++++++++++++++++ Positive Cases +++++++++++++++++++*/

	/*======== iteration-0 ========*/
	psi_len = strnlen_s("devconfig:minver~1", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver~1")), 0);
	strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver~1");

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "devconfig");
	TEST_ASSERT_EQUAL_STRING(msg_name, "minver");
	TEST_ASSERT_EQUAL_STRING(val_name, "1");

	/*======== iteration-1 ========*/
	psi_len = strnlen_s("keypair:maxver~2", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair:maxver~2")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "keypair");
	TEST_ASSERT_EQUAL_STRING(msg_name, "maxver");
	TEST_ASSERT_EQUAL_STRING(val_name, "2");

	/*======== iteration-2 ========*/
	psi_len = strnlen_s("keypair:gen~1/RSA", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair:gen~1/RSA")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "keypair");
	TEST_ASSERT_EQUAL_STRING(msg_name, "gen");
	TEST_ASSERT_EQUAL_STRING(val_name, "1/RSA");

	/*======== iteration-3 ========*/
	psi_len = strnlen_s("some_mod:some_msg~", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "some_mod:some_msg~")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "some_mod");
	TEST_ASSERT_EQUAL_STRING(msg_name, "some_msg");
	TEST_ASSERT_EQUAL_STRING(val_name, "");

	/*++++++++++++++++Negative Cases+++++++++++++++++++*/

	/*======== iteration-0 ========*/
	psi_len = strnlen_s("devconfig~minver:12", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig~minver:12")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-1 ========*/
	psi_len = strnlen_s("keypair~maxver:12", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair~maxver:12")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-2 ========*/
	psi_len = strnlen_s("devconfig:minver:1", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver:1")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-3 ========*/
	psi_len = strnlen_s("keypair~maxver~1", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair~maxver~1")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-4 ========*/
	psi_len = strnlen_s("keypair~gen::", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL((strcpy_s(psi_tuple, psi_len + 1, "keypair~gen::")),
			  0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-5 ========*/
	psi_len = strnlen_s("keypair#gen:1/RSA", FDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair#gen:1/RSA")), 0);

	ret = fdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-6 ========*/
	psi_len =
	    strnlen_s("devconfig:minver~"
		      "01234567890123456789012345678901234567890123456789012345"
		      "67890123456789012345678901234567890123456789"
		      "01234567890123456789012345678901234567890123456789012345"
		      "67890123456789012345678901234567890123456789"
		      "01234567890123456789012345678901234567890123456789012345"
		      "67890123456789012345678901234567890123456789",
		      2048);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);

	char *invalid_psi = malloc(psi_len + 1);
	strcpy_s(invalid_psi, psi_len + 1,
		 "devconfig:minver~"
		 "0123456789012345678901234567890123456789012345678901234567890"
		 "123456789012345678901234567890123456789"
		 "0123456789012345678901234567890123456789012345678901234567890"
		 "123456789012345678901234567890123456789"
		 "0123456789012345678901234567890123456789012345678901234567890"
		 "123456789012345678901234567890123456789");

	ret = fdo_get_module_name_msg_value(invalid_psi, psi_len, mod_name,
					    msg_name, val_name, &cbret);
	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, FDO_SI_CONTENT_ERROR);
	free(invalid_psi);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_mod_data_kv", "[fdo_types][fdo]")
#else
void test_fdo_mod_data_kv(void)
#endif
{
	fdo_sdk_si_key_value sv_kv;
	int ret = 0;
	int res_indicator = 0;
	sv_kv.key = "pubkey";
	sv_kv.value = "pubkey sample of 1024 bytes";
	char mod_name[] = "keypair";
	ret = fdo_mod_data_kv(mod_name, &sv_kv);
	TEST_ASSERT_TRUE(ret);
	strcmp_s(sv_kv.key, 18, "keypair:pubkey", &res_indicator);
	TEST_ASSERT_TRUE(res_indicator == 0);
	strcmp_s(sv_kv.value, 27, "pubkey sample of 1024 bytes",
		 &res_indicator);
	TEST_ASSERT_TRUE(res_indicator == 0);

	// Negative Test cases
	ret = fdo_mod_data_kv(mod_name, NULL);
	TEST_ASSERT_FALSE(ret);
	if (sv_kv.key)
		fdo_free(sv_kv.key);
	if (sv_kv.value)
		fdo_free(sv_kv.value);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_osi_parsing", "[fdo_types][fdo]")
#else
void test_fdo_osi_parsing(void)
#endif
{
	fdor_t test_fdor;
	fdo_sdk_si_key_value kv;
	fdo_sdk_service_info_module_list_t module_list = {0};
	bool ret;
	int retval = 0;

	test_fdor.need_comma = 0;
	test_fdor.b.cursor = 0;
	test_fdor.b.block_max = 100;
	test_fdor.b.block_size = 51;
	test_fdor.need_comma = 0;

	char in[100] =
	    "{\"mcu_service:read\":\"abcde\",\"devname:maxver\":\"1.11\"}";
	test_fdor.b.block = (uint8_t *)in;

	fdor_begin_object(&test_fdor);
	ret = fdo_osi_parsing(&test_fdor, &module_list, &kv, &retval);
	TEST_ASSERT_TRUE(ret);

	ret = fdo_osi_parsing(NULL, NULL, NULL, &retval);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_osi_parsing(NULL, NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);
}

static int cb(fdo_sdk_si_type type, int *count, fdo_sdk_si_key_value *si)
{
	(void)type;
	(void)count;
	(void)si;
	return FDO_SI_CONTENT_ERROR;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_get_dsi_count", "[fdo_types][fdo]")
#else
void test_fdo_get_dsi_count(void)
#endif
{
	fdo_sdk_service_info_module_list_t module_list = {0};
	bool ret = false;
	int mod_mes_count = 2;
	int cb_return_val = 0;

	ret = fdo_get_dsi_count(&module_list, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	module_list.module.service_info_callback = cb;
	ret = fdo_get_dsi_count(&module_list, &mod_mes_count, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_supply_moduleOSI", "[fdo_types][fdo]")
#else
void test_fdo_supply_moduleOSI(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;

	ret = fdo_supply_moduleOSI(NULL, NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_supply_modulePSI", "[fdo_types][fdo]")
#else
void test_fdo_supply_modulePSI(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;
	fdo_sdk_si_key_value sv_kv;
	char mod_name;

	ret = fdo_supply_modulePSI(NULL, NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	ret = fdo_supply_modulePSI(NULL, &mod_name, &sv_kv, &cb_return_val);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_construct_module_dsi", "[fdo_types][fdo]")
#else
void test_fdo_construct_module_dsi(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;
	fdo_sdk_service_info_module_list_t list_dsi;
	fdo_sv_info_dsi_info_t dsi_info;

	ret = fdo_construct_module_dsi(NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	dsi_info.list_dsi = &list_dsi;
	dsi_info.list_dsi->module.service_info_callback = cb;
	ret = fdo_construct_module_dsi(&dsi_info, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
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

	/* same hash content */
	ret = memcpy_s(h2->hash->bytes, 50, (uint8_t *)hash1,
		       strnlen_s(hash1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	/* positive case */
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, h2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(fdo_compare_hashes(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_hashes(NULL, h2), false);
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, NULL), false);

	h1->hash_type = FDO_CRYPTO_HASH_TYPE_SHA_384;
	TEST_ASSERT_EQUAL(fdo_compare_hashes(h1, h2), false);

	/* different hash content */
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

	/* same array content */
	ret =
	    memcpy_s(ba2->bytes, 50, (uint8_t *)array1, strnlen_s(array1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	/* positive case */
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(ba1, ba2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(NULL, ba2), false);
	TEST_ASSERT_EQUAL(fdo_compare_byte_arrays(ba1, NULL), false);

	/* different array content */
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

	/* positive case */
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(&list1, &list2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(NULL, NULL), false);
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(NULL, &list2), false);
	TEST_ASSERT_EQUAL(fdo_compare_rv_lists(&list1, NULL), false);
}
