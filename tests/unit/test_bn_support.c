/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for bignum format encoding/decoding routines of SDO
 * library.
 */

#include "unity.h"
#include <sdoCryptoHal.h>
#include <assert.h>
#include <stdlib.h>
#include "BN_support.h"

/*
 * It's ok to use invalid pointer as long as it's not null, because for the
 * unit test, big number are not really used, but some function like
 * byte_array_to_bn do some sanity check and verify that big number parameter
 * is not null.
 */
#define VALID_BN (bignum_t *)1;

/* All test below are done with 8 bytes data. */
static uint8_t tab_8[] = {
    0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
};

/* bn_to_byte_array allocate one extra byte for internal need. */
static uint8_t tab_9[] = {
    1, 0x4, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
};

/* Simulate a situation where malloc is failing. */
bool simul_out_of_mem = false;
bool simul_9_byte_alloc = false;

/* Needed by bn_to_byte_array to test case error.  */
bool simul_bn_bn2bin_error = false;
bool real_bn2bin_enabled = true;
bool simul_bn_bin2bn_error = false;
bool real_bin2bn_enabled = true;
bool simul_bn_rand_error = false;
bool simul_bn_mod_exp_error = false;
bool simul_bn_mbedtls_mpi_size = false;
bool simul_crypto_hal_random_bytes = false;

#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
int __wrap_BN_num_bits(const bignum_t *a);
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz);
bignum_t *__wrap_BN_bin2bn(const unsigned char *s, int len, bignum_t *ret);
int __wrap_BN_bn2bin(const bignum_t *a, unsigned char *to);
int __wrap_BN_mod_exp(bignum_t *r, bignum_t *a, const bignum_t *p,
                       const bignum_t *m, BN_CTX *ctx);
int __wrap_crypto_hal_random_bytes(const uint8_t *rand_data, size_t num_bytes);
int __wrap_BN_rand(BIGNUM *rnd, int bits, int top, int bottom);
void test_bn_bin2bn(void);
void test_bn_bn2bin(void);
void test_bn_rand(void);
void test_bn_mod_exp(void);
void test_bn_num_bytes(void);
void test_byte_array_to_bn(void);
void test_bn_to_byte_array(void);

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
/*** Wrapper functions (function stubbing). ***/

#ifdef USE_MBEDTLS

/* Needed by bn_bn2bin */
int __real_mbedtls_mpi_size(const bignum_t *a);
int __real_mbedtls_mpi_write_binary(const mbedtls_mpi *X, unsigned char *buf,
				    size_t buflen);
int __real_mbedtls_mpi_read_binary(mbedtls_mpi *X, const unsigned char *buf,
				   size_t buflen);

int __wrap_mbedtls_mpi_size(const bignum_t *a)
{

	if (simul_bn_mbedtls_mpi_size)
		return sizeof(tab_8);
	else
		return __real_mbedtls_mpi_size(a);
}

#else /* USE_OPENSSL*/

/*
 * BN_num_bytes is the needed function to abstract but this function is inlined
 * and use BN_num_bits.
 */
int __wrap_BN_num_bits(const bignum_t *a)
{
	(void)a;
	return sizeof(tab_8) * 8;
}

#endif /* USE_OPENSSL */

extern sdo_byte_array_t *__real_sdo_byte_array_alloc(int byte_sz);

/* Needed by bn_to_byte_array. */
sdo_byte_array_t *__wrap_sdo_byte_array_alloc(int byte_sz)
{
	static sdo_byte_array_t *a;

	if (simul_out_of_mem) {
		return NULL;
	}

	/*
	 * For this unit test, only 8 bytes array are used, but bn_tobyte_array
	 * allocate one extra byte for internal need.
	 */
	if (simul_9_byte_alloc) {
		a = sdo_byte_array_alloc_with_byte_array(tab_9, sizeof(tab_9));
		return a;
	}

	a = __real_sdo_byte_array_alloc(byte_sz);

	return a;
}

#ifdef USE_MBEDTLS

/* Needed by bn_bin2bn */
int __wrap_mbedtls_mpi_read_binary(bignum_t *n, const unsigned char *s, int len)
{
	if (real_bin2bn_enabled)
		return __real_mbedtls_mpi_read_binary(n, s, len);
	if (simul_bn_bin2bn_error) {
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	} else {
		/* Success */
		return 0;
	}
}

/* Needed by bn_bn2bin */
int __wrap_mbedtls_mpi_write_binary(const mbedtls_mpi *X, unsigned char *buf,
				    size_t buflen)
{
	if (real_bn2bin_enabled)
		return __real_mbedtls_mpi_write_binary(X, buf, buflen);

	if (simul_out_of_mem || simul_bn_bn2bin_error) {
		return MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL;
	} else {
		/* Success */
		return 0;
	}
}
#else  /* USE_OPENSSL */
bignum_t *__wrap_BN_bin2bn(const unsigned char *s, int len, bignum_t *ret)
{
	(void)s; (void)len;
	printf("BN_bin2bn with err=%d\n", simul_bn_bin2bn_error);
	if (simul_bn_bin2bn_error) {
		return NULL;
	}

	return ret;
}

/* Needed for bn_bn2bin */
int __wrap_BN_bn2bin(const bignum_t *a, unsigned char *to)
{
	(void)a; (void)to;
	if (simul_bn_bn2bin_error) {
		return 0;
	}

	return sizeof(tab_8);
}
#endif /* USE_OPENSSL */

/* Needed for bn_mod_exp */
#ifdef USE_MBEDTLS
int __wrap_mbedtls_mpi_exp_mod(bignum_t *r, bignum_t *a, const bignum_t *p,
			       const bignum_t *m, BN_CTX *ctx)
{
	if (simul_bn_mod_exp_error) {
		return MBEDTLS_ERR_MPI_ALLOC_FAILED;
	}

	/* Success */
	return 0;
}
#else  /* USE_OPENSSL */
int __wrap_BN_mod_exp(bignum_t *r, bignum_t *a, const bignum_t *p,
		      const bignum_t *m, BN_CTX *ctx)
{
	(void)r; (void)a; (void)p; (void)m; (void)ctx;
	if (simul_bn_mod_exp_error) {
		return 0;
	}

	/* Success */
	return 1;
}
#endif /* USE_OPENSSL */

#ifdef USE_MBEDTLS
/* Needed function for bn_rand*/
int __wrap_mbedtls_mpi_grow(bignum_t *X, size_t nblimbs)
{
	/* success */
	return 0;
}
#endif /* USE_MBEDTLS */

int __real_crypto_hal_random_bytes(const uint8_t *rand_data, size_t num_bytes);
int __wrap_crypto_hal_random_bytes(const uint8_t *rand_data, size_t num_bytes)
{
	if (simul_bn_rand_error) {
		return -1;
	}

	if (simul_crypto_hal_random_bytes) {
		return __real_crypto_hal_random_bytes(rand_data, num_bytes);
	}

	return 0;
}

#ifdef USE_OPENSSL
int __wrap_BN_rand(BIGNUM *rnd, int bits, int top, int bottom)
{
	(void)rnd; (void)bits; (void)top; (void)bottom;
	if (simul_bn_rand_error) {
		return 0;
	}

	/* success */
	return 1;
}
#endif

/*** Test functions. ***/

#ifndef TARGET_OS_FREERTOS
void test_bn_bin2bn(void)
#else
TEST_CASE("bn_bin2bn", "[bn_support][sdo]")
#endif
{
	simul_bn_mbedtls_mpi_size = true;
	int ret;
	bignum_t *n = VALID_BN;

	real_bin2bn_enabled = false;
	/* Error case. */
	simul_bn_bin2bn_error = true;
	ret = bn_bin2bn(tab_8, sizeof(tab_8), n);
	TEST_ASSERT_NOT_EQUAL(0, ret);
	simul_bn_bin2bn_error = false;

	/* Valid case. */
	ret = bn_bin2bn(tab_8, sizeof(tab_8), n);
	TEST_ASSERT_EQUAL(0, ret);
	simul_bn_mbedtls_mpi_size = false;
	real_bin2bn_enabled = true;
}

#ifndef TARGET_OS_FREERTOS
void test_bn_bn2bin(void)
#else
TEST_CASE("bn_bn2bin", "[bn_support][sdo]")
#endif
{
	simul_bn_mbedtls_mpi_size = true;
	int ret;
	uint8_t out[8] = {
	    0,
	};
	bignum_t *n = NULL;
	real_bn2bin_enabled = false;

	/* Error case. */
	simul_bn_bn2bin_error = true;
	ret = bn_bn2bin(n, out);
	TEST_ASSERT_EQUAL(0, ret);
	simul_bn_bn2bin_error = false;

	/* Valid case. */
	ret = bn_bn2bin(n, out);
	TEST_ASSERT_EQUAL(sizeof(tab_8), ret);
	simul_bn_mbedtls_mpi_size = false;
	real_bn2bin_enabled = true;
}

#ifndef TARGET_OS_FREERTOS
void test_bn_rand(void)
#else
TEST_CASE("bn_rand", "[bn_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	simul_bn_mbedtls_mpi_size = true;
	int ret;
	bignum_t *prnd = NULL;

#ifdef USE_MBEDTLS
	/*
	 * bn_rand need to access p field inside of rnd.
	 * note: in openssl declaring bignum_t rnd like we
	 * do below is deprecated, but it's ok because bn_rand
	 * doesn't access p field for openssl implementation.
	 */
	bignum_t rnd;
	prnd = &rnd;
#endif /* USE_MBEDTLS */

	/* Error case */
	simul_bn_rand_error = true;
	ret = bn_rand(prnd, sizeof(tab_8));
	TEST_ASSERT_EQUAL(-1, ret);
	simul_bn_rand_error = false;

	/* Valid call. */
#ifdef USE_OPENSSL
	prnd = BN_new();
#endif
	ret = bn_rand(prnd, sizeof(tab_8));
	TEST_ASSERT_EQUAL(0, ret);
	simul_bn_mbedtls_mpi_size = true;

#ifdef USE_OPENSSL
	if (prnd)
		BN_clear_free(prnd);
#endif
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_bn_mod_exp(void)
#else
TEST_CASE("bn_mod_exp", "[bn_support][sdo]")
#endif
{
	simul_bn_mbedtls_mpi_size = true;
	int ret;
	BN_CTX *ctx = NULL;
	bignum_t *r = NULL, *a = NULL, *p = NULL, *m = NULL;

	/* Error case. */
	simul_bn_mod_exp_error = true;
	ret = bn_mod_exp(r, a, p, m, ctx);
	TEST_ASSERT_NOT_EQUAL(0, ret);
	simul_bn_mod_exp_error = false;

	/* Valid case. */
	ret = bn_mod_exp(r, a, p, m, ctx);
	TEST_ASSERT_EQUAL(0, ret);
	simul_bn_mbedtls_mpi_size = false;
}

#ifndef TARGET_OS_FREERTOS
void test_bn_num_bytes(void)
#else
TEST_CASE("bn_num_bytes", "[bn_support][sdo]")
#endif
{
	simul_bn_mbedtls_mpi_size = true;
	int ret;
	bignum_t *n = NULL;

	ret = bn_num_bytes(n);
	TEST_ASSERT_EQUAL(sizeof(tab_8), ret);
	simul_bn_mbedtls_mpi_size = false;
}

#ifndef TARGET_OS_FREERTOS
void test_byte_array_to_bn(void)
#else
TEST_CASE("byte_array_to_bn", "[bn_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	simul_bn_mbedtls_mpi_size = true;
	sdo_byte_array_t ba;
	bignum_t *n = VALID_BN;
	int ret;

	ba.bytes = NULL;
	ba.byte_sz = 0;
	real_bin2bn_enabled = false;

	/* Invalid argument. */
	ret = byte_array_to_bn(n, NULL);
	TEST_ASSERT_EQUAL(-1, ret);
	ret = byte_array_to_bn(NULL, &ba);
	TEST_ASSERT_EQUAL(-1, ret);

	/* Invalid byte array. */
	ba.bytes = NULL;
	ba.byte_sz = 1;
	ret = byte_array_to_bn(n, &ba);
	TEST_ASSERT_EQUAL(-1, ret);
	ba.bytes = tab_8;
	ba.byte_sz = 0;
	ret = byte_array_to_bn(n, &ba);
	TEST_ASSERT_EQUAL(-1, ret);

	/* Valid call. */
	ba.bytes = tab_8;
	ba.byte_sz = sizeof(tab_8);
	ret = byte_array_to_bn(n, &ba);
	TEST_ASSERT_EQUAL(0, ret);
	simul_bn_mbedtls_mpi_size = false;
	real_bin2bn_enabled = true;
#else
	TEST_IGNORE();
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_bn_to_byte_array(void)
#else
TEST_CASE("bn_to_byte_array", "[bn_support][sdo]")
#endif
{
#ifdef USE_OPENSSL
	simul_bn_mbedtls_mpi_size = true;
	sdo_byte_array_t *ba = NULL;
	bignum_t *n = VALID_BN;
	simul_9_byte_alloc = true;
	real_bn2bin_enabled = false;

	/* Invalid input. */
	ba = bn_to_byte_array(NULL);
	TEST_ASSERT_NULL(ba);
	if (ba)
		sdo_byte_array_free(ba);

	/* Test out of memory case. */
	simul_out_of_mem = true;
	ba = bn_to_byte_array(n);
	TEST_ASSERT_NULL(ba);
	simul_out_of_mem = false;
	if (ba)
		sdo_byte_array_free(ba);

	/* Test bn_bn2bin failure. */
	simul_bn_bn2bin_error = true;
	ba = bn_to_byte_array(n);
	TEST_ASSERT_NULL(ba);
	simul_bn_bn2bin_error = false;
	if (ba)
		sdo_byte_array_free(ba);

	/* Valid call. */
	ba = bn_to_byte_array(n);
	TEST_ASSERT_NOT_NULL(ba);
	if (ba)
		sdo_byte_array_free(ba);
	simul_9_byte_alloc = false;
	simul_bn_mbedtls_mpi_size = false;
	real_bn2bin_enabled = true;
#else
	TEST_IGNORE();
#endif
}
