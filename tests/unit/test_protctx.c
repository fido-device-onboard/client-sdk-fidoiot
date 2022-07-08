/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for 'protocol context' routines of FDO library.
 */

#include "network_al.h"
#include "unity.h"
#include "test_crypto.h"
#include <stdlib.h>
#include "fdoCryptoHal.h"
#include "fdoprotctx.h"
#include "fdoprot.h"
#include "fdoblockio.h"
#include "safe_str_lib.h"
#include "snprintf_s.h"
#define WRAPPER_FN_TEST_VAR 5

static int strcat_normal = 1;
static int snprintf_normal = 1;
static int snprintf2_normal = 1;

#ifdef TARGET_OS_FREERTOS
extern bool g_malloc_fail;
#endif

#ifdef TARGET_OS_LINUX
/*** Unity Declarations ***/
void set_up(void);
void tear_down(void);
void *__wrap_fdo_alloc(size_t bytes);
int __wrap_fdo_read_string_sz(fdor_t *fdor);
int __wrap_snprintf_s_si(char *dest, rsize_t dmax, const char *format, char *s,
			 int a);
int __wrap_snprintf_s_i(char *dest, rsize_t dmax, const char *format, int a);
void test_fdo_prot_ctx_alloc(void);
int __wrap_fdo_socket_read(int sock, uint8_t *buf, ssize_t nbytes, void *ssl);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags);
int __wrap_socket(int domain, int type, int protocol);
void test_fdo_prot_ctx_run(void);
errno_t __wrap_strncpy_s(char *dest, rsize_t dmax, const char *src,
			 rsize_t slen);
errno_t __wrap_strcat_s(char *dest, rsize_t dmax, const char *src);
bool fdo_prot_dummy(fdo_prot_t *ps);

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

bool g_malloc_fail;

void *__real_fdo_alloc(size_t bytes);
void *__wrap_fdo_alloc(size_t bytes)
{
	if (g_malloc_fail)
		return NULL;
	else
		return __real_fdo_alloc(bytes);
}
#endif

char sample_rest[] = "I am test sample test file\n2nd part shouldn't come\r\n"
		     "Can I really break the code?";
char sample_rest2[] = " ";
char *start = sample_rest;
static int return_socket = -1;
static int strncpy_normal = true;
static int recv_configured = 1;

/*** Wrapper functions (function stubbing). ***/

int __wrap_fdo_read_string_sz(fdor_t *fdor)
{
	(void)fdor;
	return WRAPPER_FN_TEST_VAR;
}

/*** Test functions. ***/

/* Dummy test function to illustrate that the FIDO Device Onboard
 * librarys are being linked correctly. */

int __real_snprintf_s_si(char *dest, rsize_t dmax, const char *format, char *s,
			 int a);
int __wrap_snprintf_s_si(char *dest, rsize_t dmax, const char *format, char *s,
			 int a)
{
	if (snprintf_normal)
		return __real_snprintf_s_si(dest, dmax, format, s, a);
	else
		return -1;
}

#if 1
int __real_snprintf_s_i(char *dest, rsize_t dmax, const char *format, int a);
int __wrap_snprintf_s_i(char *dest, rsize_t dmax, const char *format, int a)
{
	if (snprintf2_normal)
		return __real_snprintf_s_i(dest, dmax, format, a);
	else
		return -11;
}
#endif
errno_t __real_strncpy_s(char *dest, rsize_t dmax, const char *src,
			 rsize_t slen);
errno_t __wrap_strncpy_s(char *dest, rsize_t dmax, const char *src,
			 rsize_t slen)
{
	if (strncpy_normal)
		return __real_strncpy_s(dest, dmax, src, slen);
	else
		return 1;
}

errno_t __real_strcat_s(char *dest, rsize_t dmax, const char *src);
errno_t __wrap_strcat_s(char *dest, rsize_t dmax, const char *src)
{
	if (strcat_normal)
		return __real_strcat_s(dest, dmax, src);
	else
		return 1;
}

bool fdo_prot_dummy(fdo_prot_t *ps)
{
	(void)ps;
	return true;
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_prot_ctx_alloc(void)
#else
TEST_CASE("fdo_prot_ctx_alloc", "[protctx][fdo]")
#endif
{
	fdo_prot_t protdata;
	char host_dns[] = "host.docker.internal";
	uint16_t host_port = 5000;
	fdo_prot_ctx_t *prot_ctx = NULL;

	// positive test case, prot_ctx is allocated
	prot_ctx = fdo_prot_ctx_alloc(&fdo_prot_dummy, &protdata, NULL,
				      host_dns, host_port, false);
	TEST_ASSERT_NOT_NULL(prot_ctx);
	fdo_prot_ctx_free(prot_ctx);
	fdo_free(prot_ctx);

	// positive test case, prot_ctx is allocated
	prot_ctx = fdo_prot_ctx_alloc(&fdo_prot_dummy, &protdata, NULL,
				      host_dns, host_port, true);
	TEST_ASSERT_NOT_NULL(prot_ctx);
	fdo_prot_ctx_free(prot_ctx);
	fdo_free(prot_ctx);

	g_malloc_fail = true;
	prot_ctx = fdo_prot_ctx_alloc(&fdo_prot_dummy, &protdata, NULL,
				      host_dns, host_port, true);
	TEST_ASSERT_NULL(prot_ctx);
	g_malloc_fail = false;
	// use http_proxy, host_ip and host_dns is null
	prot_ctx = fdo_prot_ctx_alloc(&fdo_prot_dummy, &protdata, NULL, NULL,
				      host_port, true);
	TEST_ASSERT_NULL(prot_ctx);
}

ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
{
	(void)sockfd;
	(void)buf;
	(void)len;
	(void)flags;
	if (recv_configured == 0)
		return -1;
	else
		return 33;
}

int __wrap_socket(int domain, int type, int protocol)
{
	(void)domain;
	(void)type;
	(void)protocol;
	return return_socket;
}

#ifndef TARGET_OS_FREERTOS
void test_fdo_prot_ctx_run(void)
#else
TEST_CASE("fdo_prot_ctx_run", "[protctx][fdo]")
#endif
{
/* TODO: Fix the test for use with opensll as well as mbedtls */
#if defined(USE_OPENSSL)

	int ret = -1;
	// char tmp_buf[512];
	char host_dns[] = "host.docker.internal";
	uint16_t host_port = 5000;

	fdo_prot_ctx_t *prot_ctx = fdo_alloc(sizeof(fdo_prot_ctx_t));
	TEST_ASSERT_NOT_NULL(prot_ctx);

	ret = memset_s(prot_ctx, sizeof(fdo_prot_ctx_t), 0);
	TEST_ASSERT_EQUAL_INT(0, ret);

	prot_ctx->host_ip = fdo_alloc(sizeof(fdo_ip_address_t));
	TEST_ASSERT_NOT_NULL(prot_ctx->host_ip);

	prot_ctx->protdata = fdo_alloc(sizeof(fdo_prot_t));
	TEST_ASSERT_NOT_NULL(prot_ctx->protdata);

	prot_ctx->sock_hdl = FDO_CON_INVALID_HANDLE;
	return_socket = -1;
	prot_ctx->protrun = &fdo_prot_dummy;
	prot_ctx->host_port = host_port;
	prot_ctx->protdata->state = 0;
	prot_ctx->protdata->fdow.msg_type = 0;
	prot_ctx->protdata->fdor.msg_type = 0;

	// negative case
	// host_dns is not null, but null size string
	prot_ctx->host_dns = "";
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	// posturl malloc failed
	prot_ctx->host_dns = host_dns;
	g_malloc_fail = false;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	g_malloc_fail = true;

	// protrun NULL
	prot_ctx->protrun = NULL;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	prot_ctx->protrun = &fdo_prot_dummy;

	// snprintf_s_si failed when host_dns present
	prot_ctx->host_dns = host_dns;
	snprintf_normal = 0;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	snprintf_normal = 1;

	// host_dns is NULL , snprintf_s_i fail
	prot_ctx->host_dns = NULL;
	snprintf2_normal = 0;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	snprintf2_normal = 1;

	// snrncpy_s failed when state FDO_STATE_T01_SND_HELLO_FDO
	prot_ctx->protdata->state = FDO_STATE_T01_SND_HELLO_FDO;
	strncpy_normal = 0;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);

	// snrncpy_s failed when state FDO_STATE_TO2_SND_DONE
	prot_ctx->protdata->state = FDO_STATE_TO2_SND_DONE;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	strncpy_normal = 1;

	// snrncat_s failed when state FDO_STATE_TO2_SND_DONE
	prot_ctx->protdata->state = FDO_STATE_TO2_SND_DONE;
	strcat_normal = 0;
	ret = fdo_prot_ctx_run(prot_ctx);
	TEST_ASSERT_EQUAL_INT(-1, ret);
	strcat_normal = 1;

	free(prot_ctx->protdata);
	free(prot_ctx->host_ip);
	free(prot_ctx);
#endif
}
