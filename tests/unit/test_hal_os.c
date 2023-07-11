/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Unit tests for OS abstraction layer of FDO library.
 */

#include <sys/socket.h>
#include "network_al.h"
#include <stdlib.h>
#include "fdoCryptoHal.h"
#include "fdoprotctx.h"
#include "rest_interface.h"
#include <openssl/ssl.h>
#include "safe_str_lib.h"
#include "unity.h"
#include "util.h"

#ifdef TARGET_OS_LINUX

/* Declaring internal structure here */
struct fdo_sock_handle {
	int sockfd;
} g_handle;

/*** Unity Declarations. ***/
void set_up(void);
void tear_down(void);
int __wrap_close(int sockfd);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap_send(int socket, const void *buffer, size_t length, int flags);
int __wrap_socket(int domain, int type, int protocol);
int __wrap_connect(int socket, const struct sockaddr *address,
		   uint8_t address_len);
void test_fdo_con_connect(void);
void test_fdo_con_disconnect(void);
void test_fdo_con_recv_message(void);
void test_fdo_con_send_message(void);
void test_read_until_new_line(void);

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

static int return_socket = -1;
static int recv_configured = 1;
/*** Wrapper functions (function stubbing). ***/

#ifdef TARGET_OS_FREERTOS
int __wrap_lwip_close_r(int domain, int type, int protocol)
#else
int __wrap_close(int sockfd)
#endif
{
	(void)sockfd;
	return 0;
}

#ifdef TARGET_OS_FREERTOS
int __wrap_lwip_recv_r(int domain, int type, int protocol)
#else
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags)
#endif
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

#ifdef TARGET_OS_FREERTOS
int __wrap_lwip_send_r(int domain, int type, int protocol)
#else
ssize_t __wrap_send(int socket, const void *buffer, size_t length, int flags)
#endif
{
	(void)socket;
	(void)buffer;
	(void)length;
	(void)flags;
	return 42;
}

#ifdef TARGET_OS_FREERTOS
int __wrap_lwip_socket(int domain, int type, int protocol)
#else
int __wrap_socket(int domain, int type, int protocol)
#endif
{
	(void)domain;
	(void)type;
	(void)protocol;
	return return_socket;
}

#ifdef TARGET_OS_FREERTOS
int __wrap_lwip_connect_r(int socket, const struct sockaddr *name,
			  socklen_t namelen)
#else
int __wrap_connect(int socket, const struct sockaddr *address,
		   uint8_t address_len)
#endif
{
	(void)address;
	(void)address_len;
	if (socket == 0) {
		return -1;
	}
	return socket;
}

/**
 * Read until new-line is encountered.
 * Note: This function is copied from NW HAL just for testing purpose.
 * The same function is a static function in NW HAL.
 *
 * @param out - out pointer to REST header line.
 * @param size - REST header size.
 * @retval true if line read was successful, false otherwise.
 */
static bool read_until_new_line(char *out, size_t size)
{
	int sz;
	char c;
	char curl_buf_offset = 0;
	static int curl_buf[50];
	char alphabet[27] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
			     'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r',
			     's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '\n'};

	// create random int and store in randomArray
	for (int i = 0; i < 50; i++) {
		curl_buf[i] = alphabet[rand() % 27];
	}

	if (!out || !size)
		return false;

	--size; // leave room for NULL
	sz = 0;
	for (;;) {
		c = curl_buf[curl_buf_offset + sz];

		if ((uint8_t)sz < size)
			out[sz++] = c;

		if (c == '\n') {
			curl_buf_offset += sz;
			break;
		}
	}
	out[sz] = 0;
	/* remove \n and \r and don't process invalid string */
	if (((uint8_t)sz < size) && ((uint8_t)sz >= 1)) {
		out[--sz] = 0; // remove NL
		if ((sz >= 1) && (out[sz - 1] == '\r'))
			out[--sz] = 0; // ... remove CRNL
	}

	return true;
}

/*** Test functions. ***/
#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_con_connect", "[OS][HAL][fdo]")
#else
void test_fdo_con_connect(void)
#endif
{
	TEST_IGNORE();

	fdo_ip_address_t fdoip = {
	    0,
	};
	uint16_t port = 8085;

	fdoip.length = 4;
	curl = curl_easy_init();

	// setup rest protocol
	TEST_ASSERT_EQUAL_INT(0, fdo_con_setup(NULL, NULL, 0));

	/* False tests */
	return_socket = -1;
	TEST_ASSERT_EQUAL_INT(-1,
			      fdo_con_connect(&fdoip, NULL, port,
					      NULL)); /* socket() returns -1 */
	return_socket = 0;
	TEST_ASSERT_EQUAL_INT(-1,
			      fdo_con_connect(&fdoip, NULL, port,
					      NULL)); /* connect() returns -1 */

	/* Pass tests */
	return_socket = 123;
	int ret_val;
	ret_val = fdo_con_connect(&fdoip, NULL, port, NULL);
	TEST_ASSERT_NOT_EQUAL(-1, ret_val);

	// undo setup rest protocol
	fdo_con_teardown();
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_con_disconnect", "[OS][HAL][fdo]")
#else
void test_fdo_con_disconnect(void)
#endif
{
	curl = curl_easy_init();
	TEST_ASSERT_EQUAL_INT(0, fdo_con_disconnect());
}
#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_con_recv_message", "[OS][HAL][fdo]")
#else
void test_fdo_con_recv_message(void)
#endif
{
	uint8_t buf[5];
	char curl_buf[5];
	ssize_t nbytes = 5;

	for (int i = 0; i < 5; i++) {
		curl_buf[i] = rand() % 100 + 1;
	}

	curl = curl_easy_init();
	TEST_ASSERT_EQUAL_INT(0, fdo_con_parse_msg_body(buf, nbytes, curl_buf));
}

#ifdef TARGET_OS_FREERTOS
TEST_CASE("fdo_con_send_message", "[OS][HAL][fdo]")
#else
void test_fdo_con_send_message(void)
#endif
{
	uint8_t buf[42];
	ssize_t nbytes = 42;
	curl = curl_easy_init();

	// setup rest protocol
	TEST_ASSERT_EQUAL_INT(0, fdo_con_setup(NULL, NULL, 0));

	TEST_ASSERT_EQUAL_INT(
	    -1, fdo_con_send_recv_message(0, 0, buf, nbytes, NULL, NULL, NULL));

	// undo setup rest protocol
	fdo_con_teardown();
}

#ifndef TARGET_OS_FREERTOS
void test_read_until_new_line(void)
#else
TEST_CASE("read_until_new_line", "[OS][HAL][fdo]")
#endif
{
	char buff[50];
	int bufsize = 22, ret;
	bool retval;

	fdo_prot_ctx_t *prot_ctx = fdo_alloc(sizeof(fdo_prot_ctx_t));
	TEST_ASSERT_NOT_NULL(prot_ctx);
	ret = memset_s(prot_ctx, sizeof(fdo_prot_ctx_t), 0);
	TEST_ASSERT_EQUAL_INT(0, ret);
	// prot_ctx->ssl = NULL;

	recv_configured = 0;
	retval = read_until_new_line(buff, bufsize);
	TEST_ASSERT_TRUE(retval);
	recv_configured = 1;
	free(prot_ctx);
}
