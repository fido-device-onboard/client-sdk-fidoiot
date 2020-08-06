#include "unity.h"
#include "crypto_utils.h"
#include "sdoprot.h"
#include "base64.h"
#include "sdotypes.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "sdo.h"
#include <stdlib.h>
#include <inttypes.h>
#include "safe_lib.h"
#include "snprintf_s.h"

/*!
 * \file
 * \brief Unit tests for SDO defined data structure parsing/packing routines.
 */

/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
void test_sdo_bits_init(void);
void test_sdo_bits_alloc_with(void);
void test_sdo_bits_fill(void);
void test_sdo_bits_toString(void);
void test_sdo_byte_array_append(void);
void test_sdo_byte_array_read_chars(void);
void test_sdo_byte_array_read(void);
void test_sdo_byte_array_read_with_type(void);
void test_sdo_string_alloc_with(void);
void test_sdo_string_alloc_str(void);
void test_sdo_string_resize(void);
void test_sdo_string_resize_with(void);
void test_sdo_string_read(void);
void test_sdo_nonce_equal(void);
void test_sdo_hash_read(void);
void test_sdo_hash_null_write(void);
void test_sdo_init_ipv4_address(void);
void test_sdoIPAddress_toString(void);
void test_sdo_read_ipaddress(void);
void test_sdo_public_key_clone(void);
void test_sdo_compare_public_keys(void);
void test_sdo_public_key_free(void);
void test_sdoPKAlg_toString(void);
void test_sdoPKEnc_toString(void);
void test_sdo_public_key_write(void);
void test_sdo_public_key_toString(void);
void test_sdo_public_key_read(void);
void test_sdo_rendezvous_free(void);
void test_sdo_rendezvous_write(void);
void test_keyfromstring(void);
void test_sdo_rendezvous_read(void);
void test_sdo_rendezvous_list_add(void);
void test_sdo_rendezvous_list_get(void);
void test_sdo_rendezvous_list_read(void);
void test_sdo_rendezvous_list_write(void);
void test_sdo_encrypted_packet_read(void);
void test_sdo_get_iv(void);
void test_sdo_write_iv(void);
void test_sdo_encrypted_packet_write(void);
void test_sdo_encrypted_packet_write_unwind(void);
void test_sdo_encrypted_packet_windup(void);
void test_sdo_begin_write_signature(void);
void test_sdo_end_write_signature(void);
void test_sdo_begin_readHMAC(void);
void test_sdo_end_readHMAC(void);
void test_sdo_begin_read_signature(void);
void test_sdo_end_read_signature_full(void);
void test_sdo_signature_verification(void);
void test_sdo_read_pk_null(void);
void test_sdoOVSignature_verification(void);
void test_sdo_kv_alloc_with_array(void);
void test_sdo_kv_alloc_with_str(void);
void test_sdo_service_info_alloc_with(void);
void test_sdo_service_info_add_kv_str(void);
void test_sdo_service_info_add_kv(void);
void test_psiparsing(void);
void test_sdo_get_module_name_msg_value(void);
void test_sdo_mod_data_kv(void);
void test_sdo_osi_parsing(void);
static int cb(sdo_sdk_si_type type, int *count, sdo_sdk_si_key_value *si);
void test_sdo_get_dsi_count(void);
void test_sdo_supply_moduleOSI(void);
void test_sdo_supply_modulePSI(void);
void test_sdo_construct_module_dsi(void);
void test_sdo_compare_hashes(void);
void test_sdo_compare_byte_arrays(void);
void test_sdo_compare_rvLists(void);

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
TEST_CASE("sdo_bits_init", "[sdo_types][sdo]")
#else
void test_sdo_bits_init(void)
#endif
{
	sdo_bits_t *b;
	sdo_bits_t *ret = NULL;

	ret = sdo_bits_init(NULL, 100);
	TEST_ASSERT_NULL(ret);

	b = malloc(sizeof(sdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);

	ret = sdo_bits_init(b, 100);
	TEST_ASSERT_NOT_NULL(ret);

	sdo_bits_free(b);

	b = malloc(sizeof(sdo_bits_t));
	TEST_ASSERT_NOT_NULL(b);
	b->bytes = malloc(5);
	TEST_ASSERT_NOT_NULL(b->bytes);
	ret = sdo_bits_init(b, 0);
	TEST_ASSERT_NOT_NULL(ret);

	sdo_bits_free(b);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_bits_alloc_with", "[sdo_types][sdo]")
#else
void test_sdo_bits_alloc_with(void)
#endif
{
	uint8_t *data;
	sdo_bits_t *ret;

	data = malloc(100);
	TEST_ASSERT_NOT_NULL(data);

	ret = sdo_bits_alloc_with(100, data);
	TEST_ASSERT_NOT_NULL(ret);
	sdo_bits_free(ret);

	ret = sdo_bits_alloc_with(0, data);
	TEST_ASSERT_NULL(ret);

	ret = sdo_bits_alloc_with(100, NULL);
	TEST_ASSERT_NULL(ret);

	ret = sdo_bits_alloc_with(0, NULL);
	TEST_ASSERT_NULL(ret);

	free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_bits_fill", "[sdo_types][sdo]")
#else
void test_sdo_bits_fill(void)
#endif
{
	sdo_bits_t *bits;
	bool ret;

	ret = sdo_bits_fill(NULL);
	TEST_ASSERT_FALSE(ret);

	bits = malloc(sizeof(sdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = NULL;
	bits->byte_sz = 0;
	ret = sdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	sdo_bits_free(bits);

	bits = malloc(sizeof(sdo_bits_t));
	TEST_ASSERT_NOT_NULL(bits);
	bits->bytes = malloc(100);
	TEST_ASSERT_NOT_NULL(bits->bytes);
	bits->byte_sz = 0;
	ret = sdo_bits_fill(&bits);
	TEST_ASSERT_FALSE(ret);
	free(bits);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_bits_to_string", "[sdo_types][sdo]")
#else
void test_sdo_bits_toString(void)
#endif
{
	sdo_bits_t b;
	char *typename = "test";
	char *buf = "test_string";
	int buf_sz;
	char *ret;

	buf_sz = 10;
	ret = sdo_bits_to_string(NULL, typename, buf, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = sdo_bits_to_string(&b, NULL, buf, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = sdo_bits_to_string(&b, typename, NULL, buf_sz);
	TEST_ASSERT_NULL(ret);

	ret = sdo_bits_to_string(&b, typename, buf, 0);
	TEST_ASSERT_NOT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_byte_array_append", "[sdo_types][sdo]")
#else
void test_sdo_byte_array_append(void)
#endif
{
	sdo_byte_array_t *baA;
	sdo_byte_array_t *baB;
	sdo_byte_array_t *ret;

	ret = sdo_byte_array_append(NULL, NULL);
	TEST_ASSERT_NULL(ret);

	baA = malloc(sizeof(sdo_byte_array_t));
	TEST_ASSERT_NOT_NULL(baA);
	baB = malloc(sizeof(sdo_byte_array_t));
	TEST_ASSERT_NOT_NULL(baB);

	baA->byte_sz = 0;
	baB->byte_sz = 10;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = sdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 0;
	baB->byte_sz = 0;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = sdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 10;
	baB->byte_sz = 10;
	baA->bytes = NULL;
	baB->bytes = NULL;

	ret = sdo_byte_array_append(baA, baB);
	TEST_ASSERT_NULL(ret);

	baA->byte_sz = 10;
	baB->byte_sz = 10;
	baA->bytes = malloc(10);
	baB->bytes = malloc(10);

	ret = sdo_byte_array_append(baA, baB);
	TEST_ASSERT_NOT_NULL(ret);
	sdo_byte_array_free(ret);

	free(baB->bytes);
	free(baA->bytes);
	free(baA);
	free(baB);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_byte_array_read_chars", "[sdo_types][sdo]")
#else
void test_sdo_byte_array_read_chars(void)
#endif
{
	sdor_t sdor;
	sdo_byte_array_t ba;
	int ret;

	ret = sdo_byte_array_read_chars(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	memset_s(&sdor, sizeof(sdor), 0);
	memset_s(&ba, sizeof(ba), 0);

	ret = sdo_byte_array_read_chars(&sdor, &ba);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_byte_array_read", "[sdo_types][sdo]")
#else
void test_sdo_byte_array_read(void)
#endif
{
	sdor_t sdor;
	sdo_byte_array_t ba;
	int ret;

	ret = sdo_byte_array_read(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	memset_s(&sdor, sizeof(sdor), 0);
	memset_s(&ba, sizeof(ba), 0);

	ret = sdo_byte_array_read(&sdor, &ba);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_byte_array_read_with_type", "[sdo_types][sdo]")
#else
void test_sdo_byte_array_read_with_type(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_byte_array_t ba = {
	    0,
	};
	uint8_t type;
	int ret;
	sdo_byte_array_t *ctp = NULL;

	ret = sdo_byte_array_read_with_type(NULL, NULL, NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	ret = sdo_byte_array_read_with_type(&sdor, &ba, &ctp, &type);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_string_alloc_with", "[sdo_types][sdo]")
#else
void test_sdo_string_alloc_with(void)
#endif
{
	sdo_string_t *ret;
	char *data;

	ret = sdo_string_alloc_with(NULL, 0);
	TEST_ASSERT_NULL(ret);

	data = malloc(10);
	TEST_ASSERT_NOT_NULL(data);
	ret = sdo_string_alloc_with(data, 1);
	TEST_ASSERT_NOT_NULL(ret);
	sdo_string_free(ret);
	free(data);

	ret = sdo_string_alloc_with(NULL, 10);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_string_alloc_str", "[sdo_types][sdo]")
#else
void test_sdo_string_alloc_str(void)
#endif
{
	sdo_string_t *ret;
	char *data;

	ret = sdo_string_alloc_with_str(NULL);
	TEST_ASSERT_NULL(ret);

	data = malloc(SDO_MAX_STR_SIZE * 2);
	TEST_ASSERT_NOT_NULL(data);
	memset_s(data, SDO_MAX_STR_SIZE * 2, 'a');
	data[(SDO_MAX_STR_SIZE * 2) - 1] = 0;

	ret = sdo_string_alloc_with_str(data);
	TEST_ASSERT_NULL(ret);

	free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_string_resize", "[sdo_types][sdo]")
#else
void test_sdo_string_resize(void)
#endif
{
	sdo_string_t b = {
	    0,
	};
	bool ret;

	ret = sdo_string_resize(NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_string_resize(&b, 0);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_string_resize_with", "[sdo_types][sdo]")
#else
void test_sdo_string_resize_with(void)
#endif
{
	sdo_string_t b = {
	    0,
	};
	char *data;
	bool ret;

	ret = sdo_string_resize_with(NULL, 0, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_string_resize_with(&b, 0, NULL);
	TEST_ASSERT_FALSE(ret);

	data = malloc(100);
	TEST_ASSERT_NOT_NULL(data);
	ret = sdo_string_resize_with(&b, 0, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	b.bytes = NULL;

	ret = sdo_string_resize_with(&b, -1, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	b.bytes = NULL;

	ret = sdo_string_resize_with(&b, 100, data);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
	free(data);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_string_read", "[sdo_types][sdo]")
#else
void test_sdo_string_read(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_string_t b = {
	    0,
	};
	bool ret;

	ret = sdo_string_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_string_read(&sdor, &b);
	TEST_ASSERT_TRUE(ret);
	free(b.bytes);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_nonce_equal", "[sdo_types][sdo]")
#else
void test_sdo_nonce_equal(void)
#endif
{
	sdo_byte_array_t n1 = {
	    0,
	};
	sdo_byte_array_t n2 = {
	    0,
	};
	bool ret;

	ret = sdo_nonce_equal(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	n1.byte_sz = 10;
	ret = sdo_nonce_equal(&n1, &n2);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_hash_read", "[sdo_types][sdo]")
#else
void test_sdo_hash_read(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_hash_t hp = {
	    0,
	};
	int ret;

	ret = sdo_hash_read(NULL, NULL);
	TEST_ASSERT_EQUAL_INT(0, ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 10, '[');
	ret = sdo_hash_read(&sdor, &hp);
	TEST_ASSERT_EQUAL_INT(0, ret);
	if (hp.hash) {
		sdo_byte_array_free(hp.hash);
	}
	if (sdor.b.block_size != 0) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_hash_null_write", "[sdo_types][sdo]")
#else
void test_sdo_hash_null_write(void)
#endif
{
	/*function returns void
	 * so call only to see NULL check*/
	sdo_hash_null_write(NULL);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_init_ipv4_address", "[sdo_types][sdo]")
#else
void test_sdo_init_ipv4_address(void)
#endif
{
	sdo_ip_address_t sdoip = {
	    0,
	};
	uint8_t ipv4;

	/*function returns void
	 * so call only to see NULL check*/
	sdo_init_ipv4_address(NULL, NULL);
	TEST_ASSERT_TRUE(1);

	sdo_init_ipv4_address(&sdoip, &ipv4);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_ipaddress_to_string", "[sdo_types][sdo]")
#else
void test_sdoIPAddress_toString(void)
#endif
{
	sdo_ip_address_t sdoip;
	char buf[100] = "IPTo_string";
	int buf_sz = sizeof("IPTo_string");
	char *ret;

	ret = sdo_ipaddress_to_string(NULL, NULL, 0);
	TEST_ASSERT_NULL(ret);

	sdoip.length = 16;
	ret = sdo_ipaddress_to_string(&sdoip, buf, buf_sz);
	TEST_ASSERT_NOT_NULL(ret);

	ret = sdo_ipaddress_to_string(&sdoip, buf, 5);
	TEST_ASSERT_NULL(ret);

	ret = sdo_ipaddress_to_string(&sdoip, buf, buf_sz + 16);
	TEST_ASSERT_NOT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_read_ipaddress", "[sdo_types][sdo]")
#else
void test_sdo_read_ipaddress(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_ip_address_t sdoip = {
	    0,
	};
	bool ret;

	ret = sdo_read_ipaddress(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_read_ipaddress(&sdor, &sdoip);
	TEST_ASSERT_FALSE(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 10, '[');

	ret = sdo_read_ipaddress(&sdor, &sdoip);
	TEST_ASSERT_FALSE(ret);
	if (sdor.b.block_size != 0) {
		free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_public_key_clone", "[sdo_types][sdo]")
#else
void test_sdo_public_key_clone(void)
#endif
{
	sdo_public_key_t pk = {
	    0,
	};
	sdo_public_key_t *ret;

	ret = sdo_public_key_clone(NULL);
	TEST_ASSERT_NULL(ret);

	ret = sdo_public_key_clone(&pk);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_compare_public_keys", "[sdo_types][sdo]")
#else
void test_sdo_compare_public_keys(void)
#endif
{
	sdo_public_key_t pk1 = {0};
	sdo_public_key_t pk2 = {0};
	sdo_byte_array_t key1 = {0};
	sdo_byte_array_t key2 = {0};
	sdo_byte_array_t key3 = {0};
	sdo_byte_array_t key4 = {0};
	bool ret;

	ret = sdo_compare_public_keys(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.key1 = &key1;
	pk1.key2 = &key2;

	pk2.key1 = &key3;
	pk2.key2 = &key4;

	ret = sdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkalg = 3;
	pk2.pkalg = 4;
	pk1.pkenc = 1;
	pk2.pkenc = 1;

	ret = sdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkalg = 3;
	pk2.pkalg = 3;

	pk1.pkenc = 1;
	pk2.pkenc = 2;
	ret = sdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);

	pk1.pkenc = 1;
	pk2.pkenc = 1;
	key1.byte_sz = 0;
	key2.byte_sz = 0;
	ret = sdo_compare_public_keys(&pk1, &pk2);
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
	ret = sdo_compare_public_keys(&pk1, &pk2);
	TEST_ASSERT_FALSE(ret);
	if (key1.bytes) {
		sdo_free(key1.bytes);
	}
	if (key2.byte_sz != 0) {
		sdo_free(key2.bytes);
	}
	if (key3.bytes) {
		sdo_free(key3.bytes);
	}
	if (key4.byte_sz != 0) {
		sdo_free(key4.bytes);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_public_key_free", "[sdo_types][sdo]")
#else
void test_sdo_public_key_free(void)
#endif
{
	/*function returns void
	 * so call only to see NULL check*/

	sdo_public_key_free(NULL);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_pk_alg_to_string", "[sdo_types][sdo]")
#else
void test_sdoPKAlg_toString(void)
#endif
{
	const char *ret;

	ret = sdo_pk_alg_to_string(SDO_CRYPTO_PUB_KEY_ALGO_NONE);
	TEST_ASSERT_EQUAL_STRING("AlgNONE", ret);

	ret = sdo_pk_alg_to_string(SDO_CRYPTO_PUB_KEY_ALGO_RSA);
	TEST_ASSERT_EQUAL_STRING("AlgRSA", ret);

	ret = sdo_pk_alg_to_string(SDO_CRYPTO_PUB_KEY_ALGO_EPID_1_1);
	TEST_ASSERT_EQUAL_STRING("AlgEPID11", ret);

	ret = sdo_pk_alg_to_string(SDO_CRYPTO_PUB_KEY_ALGO_EPID_2_0);
	TEST_ASSERT_EQUAL_STRING("AlgEPID20", ret);

	ret = sdo_pk_alg_to_string(-1);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_pk_enc_to_string", "[sdo_types][sdo]")
#else
void test_sdoPKEnc_toString(void)
#endif
{
	const char *ret;

	ret = sdo_pk_enc_to_string(SDO_CRYPTO_PUB_KEY_ENCODING_X509);
	TEST_ASSERT_EQUAL_STRING("EncX509", ret);

	ret = sdo_pk_enc_to_string(SDO_CRYPTO_PUB_KEY_ENCODING_RSA_MOD_EXP);
	TEST_ASSERT_EQUAL_STRING("EncRSAMODEXP", ret);

	ret = sdo_pk_enc_to_string(SDO_CRYPTO_PUB_KEY_ENCODING_EPID);
	TEST_ASSERT_EQUAL_STRING("EncEPID", ret);

	ret = sdo_pk_enc_to_string(-1);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_public_key_write", "[sdo_types][sdo]")
#else
void test_sdo_public_key_write(void)
#endif
{
	sdow_t sdow = {
	    0,
	};
	sdo_public_key_t pk;
	/*function returns void
	 * so call only to see NULL check*/
	sdo_public_key_write(NULL, &pk);
	TEST_ASSERT_TRUE(1);

	sdo_public_key_write(&sdow, NULL);
	TEST_ASSERT_TRUE(1);
	if (sdow.b.block != NULL) {
		sdo_free(sdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_public_key_to_string", "[sdo_types][sdo]")
#else
void test_sdo_public_key_toString(void)
#endif
{
	char *ret;
	char buf[128] = {
	    0,
	};
	sdo_public_key_t pk = {
	    0,
	};

	ret = sdo_public_key_to_string(NULL, NULL, 0);
	TEST_ASSERT_NULL(ret);

	ret = sdo_public_key_to_string(&pk, buf, 0);
	TEST_ASSERT_NULL(ret);

	ret = sdo_public_key_to_string(&pk, buf, 3);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_public_key_read", "[sdo_types][sdo]")
#else
void test_sdo_public_key_read(void)
#endif
{
	sdo_public_key_t *ret;
	sdor_t sdor = {
	    0,
	};

	ret = sdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 3, '[');
	ret = sdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 3, '[');
	memset_s(sdor.b.block + 3, 5, ']');
	ret = sdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 3, '[');
	memset_s(sdor.b.block + 3, 7, '[');
	ret = sdo_public_key_read(NULL);
	TEST_ASSERT_NULL(ret);
	if (sdor.b.block_size != 0) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_free", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_free(void)
#endif
{
	sdo_rendezvous_t *rv;

	sdo_rendezvous_free(NULL);
	rv = malloc(sizeof(sdo_rendezvous_t));
	TEST_ASSERT_NOT_NULL(rv);
	memset_s(rv, sizeof(sdo_rendezvous_t), 0);
	rv->ip = malloc(sizeof(sdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_NONE,
				 SDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_NONE,
				 SDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = malloc(sizeof(uint32_t));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = sdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = sdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = sdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = sdo_string_alloc_with_str("Test str 4");
	TEST_ASSERT_NOT_NULL(rv->me);
	sdo_rendezvous_free(rv);
	TEST_ASSERT_TRUE(1);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_write", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_write(void)
#endif
{

	sdow_t sdow = {
	    0,
	};
	sdo_rendezvous_t *rv;
	bool ret;

	ret = sdo_rendezvous_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rv = malloc(sizeof(sdo_rendezvous_t));
	TEST_ASSERT_NOT_NULL(rv);
	memset_s(rv, sizeof(sdo_rendezvous_t), 0);
	rv->ip = malloc(sizeof(sdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(rv->ip);
	rv->sch = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_NONE,
				 SDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->sch);
	rv->cch = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_NONE,
				 SDO_CRYPTO_HASH_TYPE_SHA_256);
	TEST_ASSERT_NOT_NULL(rv->cch);
	rv->ui = malloc(sizeof(uint32_t));
	TEST_ASSERT_NOT_NULL(rv->ui);
	rv->ss = sdo_string_alloc_with_str("Test str 1");
	TEST_ASSERT_NOT_NULL(rv->ss);
	rv->pw = sdo_string_alloc_with_str("Test str 2");
	TEST_ASSERT_NOT_NULL(rv->pw);
	rv->wsp = sdo_string_alloc_with_str("Test str 3");
	TEST_ASSERT_NOT_NULL(rv->wsp);
	rv->me = sdo_string_alloc_with_str("Test str 4");
	TEST_ASSERT_NOT_NULL(rv->me);

	ret = sdo_rendezvous_write(&sdow, rv);
	TEST_ASSERT_TRUE(ret);
	sdo_rendezvous_free(rv);
	if (sdow.b.block != NULL) {
		sdo_free(sdow.b.block);
	}
}

extern int keyfromstring(char *key);
#ifdef TARGET_OS_FREERTOS
TEST_CASE("keyfromstring", "[sdo_types][sdo]")
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
TEST_CASE("sdo_rendezvous_read", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_read(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_rendezvous_t *rv;
	bool ret;

	ret = sdo_rendezvous_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	rv = malloc(sizeof(sdo_rendezvous_t));
	memset_s(rv, sizeof(sdo_rendezvous_t), 0);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 10, '[');
	ret = sdo_rendezvous_read(&sdor, rv);
	TEST_ASSERT_FALSE(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 5, '[');

	sdow_begin_sequence((sdow_t *)&sdor);
	ret = sdo_rendezvous_read(&sdor, rv);
	TEST_ASSERT_FALSE(ret);
	free(rv);
	if (sdor.b.block_size != 0) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_list_add", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_list_add(void)
#endif
{
	sdo_rendezvous_list_t list = {
	    0,
	};
	sdo_rendezvous_t rv = {
	    0,
	};
	int ret;

	ret = sdo_rendezvous_list_add(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_rendezvous_list_add(&list, &rv);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_list_get", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_list_get(void)
#endif
{
	sdo_rendezvous_t *ret;

	ret = sdo_rendezvous_list_get(NULL, 0);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_list_read", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_list_read(void)
#endif
{
	int ret;
	sdor_t sdor = {
	    0,
	};
	sdo_rendezvous_list_t list = {
	    0,
	};

	ret = sdo_rendezvous_list_read(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_rendezvous_list_read(&sdor, &list);
	TEST_ASSERT_FALSE(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 10, '[');
	ret = sdo_rendezvous_list_read(&sdor, &list);
	TEST_ASSERT_FALSE(ret);
	if (sdor.b.block_size != 0) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_rendezvous_list_write", "[sdo_types][sdo]")
#else
void test_sdo_rendezvous_list_write(void)
#endif
{
	int ret;
	sdow_t sdow = {
	    0,
	};
	sdo_rendezvous_list_t list = {
	    0,
	};

	ret = sdo_rendezvous_list_write(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_rendezvous_list_write(&sdow, &list);
	TEST_ASSERT_TRUE(ret);
	if (sdow.b.block != NULL) {
		sdo_free(sdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_encrypted_packet_read", "[sdo_types][sdo]")
#else
void test_sdo_encrypted_packet_read(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_encrypted_packet_t *ret;

	ret = sdo_encrypted_packet_read(NULL);
	TEST_ASSERT_NULL(ret);

	ret = sdo_encrypted_packet_read(&sdor);
	TEST_ASSERT_NULL(ret);

	sdow_begin_sequence((sdow_t *)&sdor);
	// Increse the block size to pass sequence read
	sdor.b.block_size += 10;
	memset_s(sdor.b.block, 10, '[');

	ret = sdo_encrypted_packet_read(&sdor);
	TEST_ASSERT_NULL(ret);
	if (sdor.b.block_size != 0) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_get_iv", "[sdo_types][sdo]")
#else
void test_sdo_get_iv(void)
#endif
{
	bool ret;

	ret = sdo_get_iv(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_write_iv", "[sdo_types][sdo]")
#else
void test_sdo_write_iv(void)
#endif
{
	sdo_encrypted_packet_t pkt = {
	    0,
	};
	sdo_iv_t ps_iv = {
	    0,
	};
	bool ret;

	ret = sdo_write_iv(NULL, NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_write_iv(&pkt, &ps_iv, 0);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_encrypted_packet_write", "[sdo_types][sdo]")
#else
void test_sdo_encrypted_packet_write(void)
#endif
{
	sdow_t sdow = {
	    0,
	};
	sdo_encrypted_packet_t pkt = {
	    0,
	};

	sdo_encrypted_packet_write(NULL, NULL);
	sdo_encrypted_packet_write(&sdow, &pkt);
	TEST_ASSERT_TRUE(1);
	if (sdow.b.block != NULL) {
		sdo_free(sdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_encrypted_packet_write_unwind", "[sdo_types][sdo]")
#else
void test_sdo_encrypted_packet_write_unwind(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_encrypted_packet_t *pkt = NULL;
	sdo_iv_t iv;
	bool ret;

	ret = sdo_encrypted_packet_unwind(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_encrypted_packet_unwind(&sdor, pkt, &iv);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_encrypted_packet_windup", "[sdo_types][sdo]")
#else
void test_sdo_encrypted_packet_windup(void)
#endif
{
	sdow_t sdow = {
	    0,
	};
	sdo_iv_t iv = {
	    0,
	};
	bool ret;

	ret = sdo_encrypted_packet_windup(NULL, 0, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_encrypted_packet_windup(&sdow, 0, &iv);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_begin_write_signature", "[sdo_types][sdo]")
#else
void test_sdo_begin_write_signature(void)
#endif
{
	sdow_t sdow = {
	    0,
	};
	sdo_sig_t sig = {
	    0,
	};
	sdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = sdo_begin_write_signature(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_begin_write_signature(&sdow, NULL, &pk);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_begin_write_signature(&sdow, &sig, &pk);
	TEST_ASSERT_TRUE(ret);
	if (sdow.b.block != NULL) {
		sdo_free(sdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_end_write_signature", "[sdo_types][sdo]")
#else
void test_sdo_end_write_signature(void)
#endif
{
	bool ret = false;
	sdow_t sdow = {0};
	sdo_sig_t sig = {0};

	ret = sdo_end_write_signature(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_end_write_signature(&sdow, &sig);
	TEST_ASSERT_FALSE(ret);

	sdow.b.cursor = 10;

#if defined(EPID_DA)
	ret = sdo_end_write_signature(&sdow, &sig);
	TEST_ASSERT_FALSE(ret);
#endif
	if (sdow.b.block != NULL) {
		free(sdow.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_begin_readHMAC", "[sdo_types][sdo]")
#else
void test_sdo_begin_readHMAC(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	int sig_block_start;
	bool ret;

	ret = sdo_begin_readHMAC(NULL, &sig_block_start);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_begin_readHMAC(&sdor, &sig_block_start);
	TEST_ASSERT_FALSE(ret);

	sdow_begin_object((sdow_t *)&sdor);
	sdow_begin_object((sdow_t *)&sdor);
	sdow_begin_object((sdow_t *)&sdor);
	ret = sdo_begin_readHMAC(&sdor, &sig_block_start);
	TEST_ASSERT_FALSE(ret);
	if (sdor.b.block != NULL) {
		free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_end_readHMAC", "[sdo_types][sdo]")
#else
void test_sdo_end_readHMAC(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_hash_t *hmac;
	bool ret;

	ret = sdo_end_readHMAC(NULL, NULL, 0);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_end_readHMAC(&sdor, &hmac, 0);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_begin_read_signature", "[sdo_types][sdo]")
#else
void test_sdo_begin_read_signature(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_sig_t sig = {
	    0,
	};
	bool ret;

	ret = sdo_begin_read_signature(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_begin_read_signature(&sdor, &sig);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_end_read_signature_full", "[sdo_types][sdo]")
#else
void test_sdo_end_read_signature_full(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	sdo_sig_t sig = {
	    0,
	};
	sdo_public_key_t *getpk = NULL;
	bool ret;

	ret = sdo_end_read_signature_full(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_end_read_signature_full(&sdor, &sig, &getpk);
	TEST_ASSERT_FALSE(ret);

	sdor.b.cursor = 10;
	ret = sdo_end_read_signature_full(&sdor, &sig, &getpk);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_signature_verification", "[sdo_types][sdo]")
#else
void test_sdo_signature_verification(void)
#endif
{
	sdo_byte_array_t plain_text = {
	    0,
	};
	sdo_byte_array_t sg = {
	    0,
	};
	sdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = sdo_signature_verification(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_signature_verification(&plain_text, &sg, &pk);
	TEST_ASSERT_FALSE(ret);

	/*Random bytes*/
	plain_text.bytes = malloc(100);
	plain_text.byte_sz = 100;
	sg.bytes = malloc(100);
	sg.byte_sz = 100;
	ret = sdo_signature_verification(&plain_text, &sg, &pk);
	TEST_ASSERT_FALSE(ret);
	free(plain_text.bytes);
	free(sg.bytes);
}

bool sdo_read_pk_null(sdor_t *sdor);

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_read_pk_null", "[sdo_types][sdo]")
#else
void test_sdo_read_pk_null(void)
#endif
{
	sdor_t sdor = {
	    0,
	};
	bool ret;

	ret = sdo_read_pk_null(NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_read_pk_null(&sdor);
	TEST_ASSERT_FALSE(ret);

	sdo_write_tag((sdow_t *)&sdor, "pk");
	ret = sdo_read_pk_null(&sdor);
	TEST_ASSERT_FALSE(ret);

	if (sdor.b.block != NULL) {
		sdo_free(sdor.b.block);
	}
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdoOVSignature_verification", "[sdo_types][sdo]")
#else
void test_sdoOVSignature_verification(void)
#endif
{
	sdor_t sdor = {0};
	sdo_sig_t sig = {
	    0,
	};
	sdo_public_key_t pk = {
	    0,
	};
	bool ret;

	ret = sdoOVSignature_verification(NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdoOVSignature_verification(&sdor, &sig, &pk);
	TEST_ASSERT_FALSE(ret);

	/*Random len*/
	sdor.b.cursor = 10;
	sdor.b.block_size = 20;
	ret = sdoOVSignature_verification(&sdor, &sig, &pk);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_kv_alloc_with_array", "[sdo_types][sdo]")
#else
void test_sdo_kv_alloc_with_array(void)
#endif
{
	sdo_key_value_t *ret;

	ret = sdo_kv_alloc_with_array(NULL, NULL);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_kv_alloc_with_str", "[sdo_types][sdo]")
#else
void test_sdo_kv_alloc_with_str(void)
#endif
{
	sdo_key_value_t *ret;

	ret = sdo_kv_alloc_with_str(NULL, NULL);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_service_info_alloc_with", "[sdo_types][sdo]")
#else
void test_sdo_service_info_alloc_with(void)
#endif
{
	char key = 0;
	char val = 0;
	sdo_service_info_t *ret;

	ret = sdo_service_info_alloc_with(NULL, NULL);
	TEST_ASSERT_NULL(ret);

	ret = sdo_service_info_alloc_with(&key, &val);
	TEST_ASSERT_NULL(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_service_info_add_kv_str", "[sdo_types][sdo]")
#else
void test_sdo_service_info_add_kv_str(void)
#endif
{
	sdo_service_info_t *si = NULL;
	bool ret;

	/* sanity negative case */
	ret = sdo_service_info_add_kv_str(si, NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	si = sdo_service_info_alloc();
	TEST_ASSERT_NOT_NULL(si);

	/* value=NULL is a positive case */
	ret = sdo_service_info_add_kv_str(si, "dummy_key", "");
	TEST_ASSERT_TRUE(ret);

	/* key=NULL is a negative case */
	ret = sdo_service_info_add_kv_str(si, "", "dummy_value");
	TEST_ASSERT_FALSE(ret);

	/* key=non-NULL and val=non-NULL is a positive case */
	ret =
	    sdo_service_info_add_kv_str(si, "dummy_key", "dummy_initial_value");
	TEST_ASSERT_TRUE(ret);

	/* update existing key with updated value is a positive case */
	ret =
	    sdo_service_info_add_kv_str(si, "dummy_key", "dummy_updated_value");
	TEST_ASSERT_TRUE(ret);
	if (si)
		sdo_service_info_free(si);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_service_info_add_kv", "[sdo_types][sdo]")
#else
void test_sdo_service_info_add_kv(void)
#endif
{
	sdo_service_info_t si = {
	    0,
	};
	sdo_key_value_t kvs = {
	    0,
	};
	bool ret;

	ret = sdo_service_info_add_kv(NULL, NULL);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_service_info_add_kv(&si, &kvs);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("psiparsing", "[sdo_types][sdo]")
#else
void test_psiparsing(void)
#endif
{
	char psi_valid_string[100] = "devconfig:maxver~1,devconfig:minver~1";
	int psi_len = 0;
	bool ret = 0;
	int cbret = 0;
	sdo_sdk_service_info_module_list_t list;

	sdo_string_t *psi = malloc(sizeof(sdo_string_t));
	TEST_ASSERT_NOT_NULL(psi);
	psi->bytes = psi_valid_string;
	psi_len = strnlen_s(psi_valid_string, SDO_MAX_STR_SIZE);
	TEST_ASSERT_TRUE(psi_len != 0);
	psi->byte_sz = psi_len;

	// NULL check case
	ret = sdo_psi_parsing(&list, psi->bytes, psi_len, NULL);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, 0);

	// No module case
	ret = sdo_psi_parsing(NULL, psi->bytes, psi_len, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, SDO_SI_SUCCESS);
	free(psi);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_get_module_name_msg_value", "[sdo_types][sdo]")
#else
void test_sdo_get_module_name_msg_value(void)
#endif
{
	char psi[SDO_MAX_STR_SIZE];
	char *psi_tuple = psi;
	int psi_len = 0;
	bool ret = 0;
	int cbret = 0;
	char mod_name[16];
	char msg_name[16];
	char val_name[16];

	/*++++++++++++++++ Positive Cases +++++++++++++++++++*/

	/*======== iteration-0 ========*/
	psi_len = strnlen_s("devconfig:minver~1", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver~1")), 0);
	strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver~1");

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "devconfig");
	TEST_ASSERT_EQUAL_STRING(msg_name, "minver");
	TEST_ASSERT_EQUAL_STRING(val_name, "1");

	/*======== iteration-1 ========*/
	psi_len = strnlen_s("keypair:maxver~2", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair:maxver~2")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "keypair");
	TEST_ASSERT_EQUAL_STRING(msg_name, "maxver");
	TEST_ASSERT_EQUAL_STRING(val_name, "2");

	/*======== iteration-2 ========*/
	psi_len = strnlen_s("keypair:gen~1/RSA", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair:gen~1/RSA")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "keypair");
	TEST_ASSERT_EQUAL_STRING(msg_name, "gen");
	TEST_ASSERT_EQUAL_STRING(val_name, "1/RSA");

	/*======== iteration-3 ========*/
	psi_len = strnlen_s("some_mod:some_msg~", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "some_mod:some_msg~")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, true);
	TEST_ASSERT_EQUAL(cbret, 0);
	TEST_ASSERT_EQUAL_STRING(mod_name, "some_mod");
	TEST_ASSERT_EQUAL_STRING(msg_name, "some_msg");
	TEST_ASSERT_EQUAL_STRING(val_name, "");

	/*++++++++++++++++Negative Cases+++++++++++++++++++*/

	/*======== iteration-0 ========*/
	psi_len = strnlen_s("devconfig~minver:12", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig~minver:12")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-1 ========*/
	psi_len = strnlen_s("keypair~maxver:12", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair~maxver:12")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-2 ========*/
	psi_len = strnlen_s("devconfig:minver:1", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "devconfig:minver:1")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-3 ========*/
	psi_len = strnlen_s("keypair~maxver~1", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair~maxver~1")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-4 ========*/
	psi_len = strnlen_s("keypair~gen::", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL((strcpy_s(psi_tuple, psi_len + 1, "keypair~gen::")),
			  0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
					    msg_name, val_name, &cbret);

	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, MESSAGE_BODY_ERROR);

	/*======== iteration-5 ========*/
	psi_len = strnlen_s("keypair#gen:1/RSA", SDO_MAX_STR_SIZE);
	TEST_ASSERT_NOT_EQUAL(psi_len, 0);
	TEST_ASSERT_EQUAL(
	    (strcpy_s(psi_tuple, psi_len + 1, "keypair#gen:1/RSA")), 0);

	ret = sdo_get_module_name_msg_value(psi_tuple, psi_len, mod_name,
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

	ret = sdo_get_module_name_msg_value(invalid_psi, psi_len, mod_name,
					    msg_name, val_name, &cbret);
	TEST_ASSERT_EQUAL(ret, false);
	TEST_ASSERT_EQUAL(cbret, SDO_SI_CONTENT_ERROR);
	free(invalid_psi);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_mod_data_kv", "[sdo_types][sdo]")
#else
void test_sdo_mod_data_kv(void)
#endif
{
	sdo_sdk_si_key_value sv_kv;
	int ret = 0;
	int res_indicator = 0;
	sv_kv.key = "pubkey";
	sv_kv.value = "pubkey sample of 1024 bytes";
	char mod_name[] = "keypair";
	ret = sdo_mod_data_kv(mod_name, &sv_kv);
	TEST_ASSERT_TRUE(ret);
	strcmp_s(sv_kv.key, 18, "keypair:pubkey", &res_indicator);
	TEST_ASSERT_TRUE(res_indicator == 0);
	strcmp_s(sv_kv.value, 27, "pubkey sample of 1024 bytes",
		 &res_indicator);
	TEST_ASSERT_TRUE(res_indicator == 0);

	// Negative Test cases
	ret = sdo_mod_data_kv(mod_name, NULL);
	TEST_ASSERT_FALSE(ret);
	if (sv_kv.key)
		sdo_free(sv_kv.key);
	if (sv_kv.value)
		sdo_free(sv_kv.value);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_osi_parsing", "[sdo_types][sdo]")
#else
void test_sdo_osi_parsing(void)
#endif
{
	sdor_t test_sdor;
	sdo_sdk_si_key_value kv;
	sdo_sdk_service_info_module_list_t module_list = {0};
	bool ret;
	int retval = 0;

	test_sdor.need_comma = 0;
	test_sdor.b.cursor = 0;
	test_sdor.b.block_max = 100;
	test_sdor.b.block_size = 51;
	test_sdor.need_comma = 0;

	char in[100] =
	    "{\"mcu_service:read\":\"abcde\",\"devname:maxver\":\"1.11\"}";
	test_sdor.b.block = (uint8_t *)in;

	sdor_begin_object(&test_sdor);
	ret = sdo_osi_parsing(&test_sdor, &module_list, &kv, &retval);
	TEST_ASSERT_TRUE(ret);

	ret = sdo_osi_parsing(NULL, NULL, NULL, &retval);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_osi_parsing(NULL, NULL, NULL, NULL);
	TEST_ASSERT_FALSE(ret);
}

static int cb(sdo_sdk_si_type type, int *count, sdo_sdk_si_key_value *si)
{
	(void)type;
	(void)count;
	(void)si;
	return SDO_SI_CONTENT_ERROR;
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_get_dsi_count", "[sdo_types][sdo]")
#else
void test_sdo_get_dsi_count(void)
#endif
{
	sdo_sdk_service_info_module_list_t module_list = {0};
	bool ret = false;
	int mod_mes_count = 2;
	int cb_return_val = 0;

	ret = sdo_get_dsi_count(&module_list, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	module_list.module.service_info_callback = cb;
	ret = sdo_get_dsi_count(&module_list, &mod_mes_count, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_supply_moduleOSI", "[sdo_types][sdo]")
#else
void test_sdo_supply_moduleOSI(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;

	ret = sdo_supply_moduleOSI(NULL, NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_supply_modulePSI", "[sdo_types][sdo]")
#else
void test_sdo_supply_modulePSI(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;
	sdo_sdk_si_key_value sv_kv;
	char mod_name;

	ret = sdo_supply_modulePSI(NULL, NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	ret = sdo_supply_modulePSI(NULL, &mod_name, &sv_kv, &cb_return_val);
	TEST_ASSERT_TRUE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_construct_module_dsi", "[sdo_types][sdo]")
#else
void test_sdo_construct_module_dsi(void)
#endif
{
	bool ret = 0;
	int cb_return_val = 0;
	sdo_sdk_service_info_module_list_t list_dsi;
	sdo_sv_info_dsi_info_t dsi_info;

	ret = sdo_construct_module_dsi(NULL, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);

	dsi_info.list_dsi = &list_dsi;
	dsi_info.list_dsi->module.service_info_callback = cb;
	ret = sdo_construct_module_dsi(&dsi_info, NULL, &cb_return_val);
	TEST_ASSERT_FALSE(ret);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_compare_hashes", "[sdo_types][sdo]")
#else
void test_sdo_compare_hashes(void)
#endif
{
	int ret = -1;
	sdo_hash_t *h1 = NULL;
	sdo_hash_t *h2 = NULL;

	char hash1[50] = "this is a sample hash1";
	char hash2[50] = "this is a sample hash2";

	h1 = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, 50);
	TEST_ASSERT_NOT_EQUAL(h1, NULL);

	ret = memcpy_s(h1->hash->bytes, 50, (uint8_t *)hash1,
		       strnlen_s(hash1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	h2 = sdo_hash_alloc(SDO_CRYPTO_HASH_TYPE_SHA_256, 50);
	TEST_ASSERT_NOT_EQUAL(h2, NULL);

	/* same hash content */
	ret = memcpy_s(h2->hash->bytes, 50, (uint8_t *)hash1,
		       strnlen_s(hash1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	/* positive case */
	TEST_ASSERT_EQUAL(sdo_compare_hashes(h1, h2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(sdo_compare_hashes(NULL, NULL), false);
	TEST_ASSERT_EQUAL(sdo_compare_hashes(NULL, h2), false);
	TEST_ASSERT_EQUAL(sdo_compare_hashes(h1, NULL), false);

	h1->hash_type = SDO_CRYPTO_HASH_TYPE_SHA_384;
	TEST_ASSERT_EQUAL(sdo_compare_hashes(h1, h2), false);

	/* different hash content */
	ret = memcpy_s(h2->hash->bytes, 50, (uint8_t *)hash2,
		       strnlen_s(hash2, 50));
	TEST_ASSERT_EQUAL(ret, 0);
	TEST_ASSERT_EQUAL(sdo_compare_hashes(h1, h2), false);

	sdo_hash_free(h1);
	sdo_hash_free(h2);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_compare_byte_arrays", "[sdo_types][sdo]")
#else
void test_sdo_compare_byte_arrays(void)
#endif
{
	int ret = -1;
	sdo_byte_array_t *ba1 = NULL;
	sdo_byte_array_t *ba2 = NULL;

	char array1[50] = "this is a sample array1";
	char array2[50] = "this is a sample array2";

	ba1 = sdo_byte_array_alloc(50);
	TEST_ASSERT_NOT_EQUAL(ba1, NULL);

	ret =
	    memcpy_s(ba1->bytes, 50, (uint8_t *)array1, strnlen_s(array1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	ba2 = sdo_byte_array_alloc(50);
	TEST_ASSERT_NOT_EQUAL(ba2, NULL);

	/* same array content */
	ret =
	    memcpy_s(ba2->bytes, 50, (uint8_t *)array1, strnlen_s(array1, 50));
	TEST_ASSERT_EQUAL(ret, 0);

	/* positive case */
	TEST_ASSERT_EQUAL(sdo_compare_byte_arrays(ba1, ba2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(sdo_compare_byte_arrays(NULL, NULL), false);
	TEST_ASSERT_EQUAL(sdo_compare_byte_arrays(NULL, ba2), false);
	TEST_ASSERT_EQUAL(sdo_compare_byte_arrays(ba1, NULL), false);

	/* different array content */
	ret =
	    memcpy_s(ba2->bytes, 50, (uint8_t *)array2, strnlen_s(array2, 50));
	TEST_ASSERT_EQUAL(ret, 0);
	TEST_ASSERT_EQUAL(sdo_compare_byte_arrays(ba1, ba2), false);

	sdo_byte_array_free(ba1);
	sdo_byte_array_free(ba2);
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("sdo_compare_rv_lists", "[sdo_types][sdo]")
#else
void test_sdo_compare_rvLists(void)
#endif
{
	sdo_rendezvous_list_t list1 = {0};
	sdo_rendezvous_list_t list2 = {0};

	/* positive case */
	TEST_ASSERT_EQUAL(sdo_compare_rv_lists(&list1, &list2), true);

	/* Negative cases */
	TEST_ASSERT_EQUAL(sdo_compare_rv_lists(NULL, NULL), false);
	TEST_ASSERT_EQUAL(sdo_compare_rv_lists(NULL, &list2), false);
	TEST_ASSERT_EQUAL(sdo_compare_rv_lists(&list1, NULL), false);
}
