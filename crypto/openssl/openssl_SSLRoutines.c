/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Abstraction layer for SSL setup and send/recv APIs of openssl library.
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>

static SSL_CTX *ctx;
/**
 * Set up a SSL/TLS connection bound to socket fd passed to the API.
 *
 * @param sock
 *        Socket fd to bind the TLS/SSL connection to.
 * @return ssl
 *        return pointer to ssl structure on success. NULL on failure.
 */
void *sdo_ssl_setup(int sock)
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

	ctx = SSL_CTX_new(method);
	if (!(ctx != NULL)) {
		goto err;
	}

	SSL_CTX_set_options(ctx, flags);
	if (0 == SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS)) {
		LOG(LOG_ERROR, "SSL cipher suite set failed");
		goto err;
	}

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		goto err;
	}
	if (0 == SSL_set_fd(ssl, sock)) {
		goto err;
	}

	return (void *)ssl;
err:
	if(ctx) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}

	if (ssl) {
		SSL_free(ssl);
	}
	return NULL;
}

/**
 * Initate the TLS/SSL handshake with the TLS/SSL server.
 *
 * @param ssl
 *        ssl handle containing the TLS/SSL connection context.
 * @return
 *        return 0 on success. -1 on failure.
 */
int sdo_ssl_connect(void *ssl)
{
	int ret = SSL_connect((SSL *)ssl);

	if (ret <= 0) {
		LOG(LOG_ERROR, "SSL Connection error: %d, errno: %lu\n",
		    SSL_get_error((SSL *)ssl, ret), ERR_get_error());
		return -1;
	}

	LOG(LOG_DEBUG, "ssl connection successful\n");

	return 0;
}

/**
 * Shuts down an active TLS/SSL connection. It sends the "close notify"
 * shutdown alert to the peer. Also free the TLS/SSL connection context.
 *
 * @param ssl
 *        ssl handle containing the TLS/SSL connection context.
 * @return
 *        return 0 on success. -1 on failure.
 */
int sdo_ssl_close(void *ssl)
{
	if(NULL == ssl) {
		return -1;
	}

	int ret = SSL_shutdown((SSL *)ssl);

	if (ret <= 0) {
		if (ret == 0) {
			/* If SSL_shutdown returns 0, call for a second time,
			 * if a bidirectional shutdown should be performed.
			 * The output of SSL_get_error() may be misleading,
			 * as an erroneous SSL_ERROR_SYSCALL may be flagged
			 * even though no error occured.
			 */
			ret = SSL_shutdown((SSL *)ssl);
		}
		if (ret <= 0) {
			LOG(LOG_ERROR,
			    "SSL Connection shutdown error: %d, ret = %d\n",
			    SSL_get_error((SSL *)ssl, ret), ret);
			return -1;
		}
	}

	SSL_free((SSL *)ssl);
	if(ctx) {
		SSL_CTX_free(ctx);
		ctx = NULL;
	}

	return 0;
}

/**
 * Reads "num" bytes into buffer received over a TLS/SSL connection.
 *
 * @param ssl
 *        ssl handle containing the TLS/SSL connection context.
 * @param buf
 *        Buffer containing data to be transmitted over TLS/SSL context.
 * @param num
 *        Length of data to be transmitted.
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int sdo_ssl_read(void *ssl, void *buf, int num)
{
	int ret = SSL_read((SSL *)ssl, buf, num);

	if (ret <= 0) {
		LOG(LOG_ERROR, "SSL Connection read error: %d\n",
		    SSL_get_error((SSL *)ssl, ret));
		return -1;
	}

	return ret;
}

/**
 * Sends "num" bytes from buffer over a TLS/SSL connection.
 *
 * @param ssl
 *        ssl handle containing the TLS/SSL connectin context.
 * @param buf
 *        Buffer containing data to be transmitted over TLS/SSL context.
 * @param num
 *        Length of data to be transmitted.
 * @return ret
 *        return no of byte on success. <=0 on failure.
 */
int sdo_ssl_write(void *ssl, const void *buf, int num)
{
	int ret = SSL_write((SSL *)ssl, buf, num);

	if (ret <= 0) {
		LOG(LOG_ERROR, "SSL Connection write error: %d errno: %lu\n",
		    SSL_get_error((SSL *)ssl, ret), ERR_get_error());
		return -1;
	}

	return ret;
}
