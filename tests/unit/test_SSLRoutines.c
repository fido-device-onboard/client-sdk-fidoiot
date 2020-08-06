/*
 * Copyright (C) 2017 Intel Corporation All Rights Reserved
 */

/*!
 * \file
 * \brief Unit tests for SSL abstraction routines of SDO library.
 */

#include <netinet/in.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h> //hostent
#include <arpa/inet.h>
#include <test_crypto.h>
#include "util.h"
#include "sdoCryptoHal.h"
#include "unity.h"

#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
void __wrap_SSL_free(SSL *ssl);
int __wrap_SSL_connect(void);
int __wrap_SSL_shutdown(void);
int __wrap_SSL_read(void);
int __wrap_SSL_write(void);
int __wrap_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
SSL_CTX *__wrap_SSL_CTX_new(void);
SSL_METHOD *__wrap_TLS_method(void);
SSL *__wrap_SSL_new(void);
SSL *test_ssl_init(void);
void test_ssl_setup(void);
void test_ssl_connect(void);
void test_ssl_close(void);
void test_ssl_read(void);
void test_ssl_write(void);

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
bool ret_method, ret_ctx, ret_ssl;
int ret_connect;
int ret_shutdown;
int ret_read;
int ret_write;

#if defined(USE_OPENSSL)
#ifdef TARGET_OS_LINUX
uint32_t ssl_free;
uint32_t ssl_shutdown;

void __real_SSL_free(SSL *ssl);
void __wrap_SSL_free(SSL *ssl)
{
	if (ssl_free) {
		__real_SSL_free(ssl);
		return;
	}
	(void)ssl;
	return;
}

int __wrap_SSL_connect(void)
{
	return ret_connect;
}

int __real_SSL_shutdown(void);
int __wrap_SSL_shutdown(void)
{
	if (ssl_shutdown)
		return __real_SSL_shutdown();
	else
		return ret_shutdown;
}

int __wrap_SSL_read(void)
{
	return ret_read;
}

int __wrap_SSL_write(void)
{
	return ret_write;
}

int __wrap_SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)
{
	(void)ctx;
	(void)str;
	return 1;
}
SSL_CTX *__real_SSL_CTX_new(void);
SSL_CTX *__wrap_SSL_CTX_new(void)
{
	if (ret_ctx)
		return __real_SSL_CTX_new();
	else
		return NULL;
}

/* On openssl 1.1 SSLv23 is macro,wrapping failed,
 * so used internal function */
SSL_METHOD *__real_TLS_method(void);
SSL_METHOD *__wrap_TLS_method(void)
{
	if (ret_method)
		return __real_TLS_method();
	else
		return NULL;
}

SSL *__real_SSL_new(void);
SSL *__wrap_SSL_new(void)
{
	if (ret_ssl)
		return __real_SSL_new();
	else
		return NULL;
}

SSL_CTX *test_ctx = NULL;
SSL *test_ssl_init(void)
{

	SSL *ssl = NULL;
	const SSL_METHOD *method;
	const long flags =
	    SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
	const char *const PREFERRED_CIPHERS =
	    "HIGH:!aNULL:!NULL:!EXT:!DSS:!kRSA:!PSK:!SRP:!MD5:!RC4";
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();
	method = SSLv23_method();
	if (!(NULL != method)) {
		goto err;
	}

	test_ctx = SSL_CTX_new(method);
	if (!(test_ctx != NULL)) {
		goto err;
	}

	SSL_CTX_set_options(test_ctx, flags);
	if (0 == SSL_CTX_set_cipher_list(test_ctx, PREFERRED_CIPHERS)) {
		LOG(LOG_ERROR, "SSL cipher suite set failed");
		goto err;
	}

	ssl = SSL_new(test_ctx);
	if (ssl == NULL) {
		goto err;
	}

	return ssl;
err:
	if (test_ctx) {
		SSL_CTX_free(test_ctx);
		test_ctx = NULL;
	}
	if (ssl != NULL) {
		SSL_free(ssl);
	}
	return NULL;
}

#endif
#endif

void cleanup_ssl_struct(void *ssl);
void cleanup_ssl_struct(void *ssl)
{
	if (ssl) {
		sdo_ssl_close(ssl);
		SSL_free((SSL *)ssl);
	}
	if (test_ctx) {
		SSL_CTX_free(test_ctx);
	}
}

#ifndef TARGET_OS_FREERTOS
void test_ssl_setup(void)
#else
TEST_CASE("ssl_setup", "[SSLRoutines][sdo]")
#endif
{
#ifdef USE_OPENSSL
	/* Positive Test Case */
	int sock = 3;
	void *ssl = NULL;

	ret_method = 1;
	ret_ctx = 1;
	ret_ssl = 1;
	ssl_free = 1;
	ssl_shutdown = 1;
	ssl = sdo_ssl_setup(sock);
	TEST_ASSERT_NOT_EQUAL_MESSAGE(NULL, ssl, "SSL Setup Failed");
	cleanup_ssl_struct(ssl);

	/* Negative Test Cases */
	ret_method = 0;
	ret_ctx = 1;
	ret_ssl = 1;
	ssl = sdo_ssl_setup(sock);
	TEST_ASSERT_EQUAL_MESSAGE(NULL, ssl, "-ve:1 SSL Setup Failed");
	cleanup_ssl_struct(ssl);

	ret_method = 1;
	ret_ctx = 0;
	ret_ssl = 1;
	ssl = sdo_ssl_setup(sock);
	TEST_ASSERT_EQUAL_MESSAGE(NULL, ssl, "-ve:2 SSL Setup Failed");
	cleanup_ssl_struct(ssl);

	ret_method = 1;
	ret_ctx = 1;
	ret_ssl = 0;
	ssl = sdo_ssl_setup(sock);
	TEST_ASSERT_EQUAL_MESSAGE(NULL, ssl, "-ve:3 SSL Setup Failed");
	cleanup_ssl_struct(ssl);
	ret_ssl = 1;

#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ssl_connect(void)
#else
TEST_CASE("ssl_connect", "[SSLRoutines][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	SSL *ssl = test_ssl_init();
	if (ssl == NULL)
		goto err;

	ret_connect = 1;
	ret = sdo_ssl_connect((void *)ssl);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "SSL connect Failed");

	/* Negative Test Cases */
	ret_connect = -1;
	ret = sdo_ssl_connect((void *)ssl);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "-ve:1 SSL Setup Failed");

err:
	cleanup_ssl_struct(ssl);
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ssl_close(void)
#else
TEST_CASE("ssl_close", "[SSLRoutines][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	SSL *ssl = test_ssl_init();
	if (ssl == NULL)
		goto err;

	ret_shutdown = 1;
	ssl_shutdown = 0;
	ret = sdo_ssl_close((void *)ssl);
	TEST_ASSERT_EQUAL_MESSAGE(0, ret, "SSL shutdown Failed");

	/* Negative Test Cases */
	ret_shutdown = -1;
	ret = sdo_ssl_close((void *)ssl);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "-ve:1 SSL shutdown Failed");
err:
	ssl_shutdown = 1;
	if (test_ctx) {
		SSL_CTX_free(test_ctx);
	}
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ssl_read(void)
#else
TEST_CASE("ssl_read", "[SSLRoutines][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	SSL *ssl = test_ssl_init();
	if (ssl == NULL)
		goto err;
	char buf[20] = {
	    0,
	};
	int num = 20;

	ret_read = 20;
	ret = sdo_ssl_read((void *)ssl, buf, num);
	TEST_ASSERT_EQUAL_MESSAGE(20, ret, "SSL read Failed");

	/* Negative Test Cases */
	ret_read = 0;
	ret = sdo_ssl_read((void *)ssl, buf, num);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "-ve:1 SSL read Failed");
err:
	cleanup_ssl_struct(ssl);
#endif
}

#ifndef TARGET_OS_FREERTOS
void test_ssl_write(void)
#else
TEST_CASE("ssl_write", "[SSLRoutines][sdo]")
#endif
{
#ifdef USE_OPENSSL
	int ret;
	char buf[20] = {
	    0,
	};
	int num = 20;
	SSL *ssl = test_ssl_init();

	if (ssl == NULL)
		goto err;

	ret_write = 20;
	ret = sdo_ssl_write((void *)&ssl, buf, num);
	TEST_ASSERT_EQUAL_MESSAGE(20, ret, "SSL write Failed");

	/* Negative Test Cases */
	ret_write = 0;
	ret = sdo_ssl_write((void *)&ssl, buf, num);
	TEST_ASSERT_EQUAL_MESSAGE(-1, ret, "-ve:1 SSL write Failed");
err:
	cleanup_ssl_struct(ssl);
#endif
}
