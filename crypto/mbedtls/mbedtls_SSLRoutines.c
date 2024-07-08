/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "fdo_crypto_hal.h"
#include "util.h"
#include "crypto_utils.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "stdlib.h"
#include "safe_lib.h"
#include "network_al.h"

#define MIN_BIT_LENGTH_DHM 2048

/* The list of recommended cipher suites to be used in TLS setup with server */
static const int ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_RSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM,
    MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
};

#if !defined(TARGET_OS_MBEDOS) // non mbedos platform
static ssl_info ssl_info_var = {0};
static ssl_info *p_ssl_info = &ssl_info_var;
#endif

#if defined(TARGET_OS_MBEDOS)
#include "mbed_net_al.h"
typedef struct {
	void *socket;
	ssl_info mbed_ssl_info;
} sinfoextra;

static sinfoextra ssl_info_var = {0};
static ssl_info *p_ssl_info = &ssl_info_var.mbed_ssl_info;

/**
 * Internal API
 */
static int mbed_ssl_rawread(void *sock, unsigned char *buf, size_t num)
{

	int ret = -1;

	if (!sock || !buf) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		return -1;
	}

	ret =
	    mos_socket_recv((fdo_con_handle)sock, (unsigned char *)buf, num, 0);
	if (ret < 0) {
		LOG(LOG_ERROR, "!mbed rawread returned %d\n\n", ret);
		return -1;
	}
	return ret;
}

int mbed_ssl_rawwrite(void *sock, const unsigned char *buf, size_t num)
{
	int ret = -1;

	if (!sock || !buf) {
		LOG(LOG_ERROR, "Invalid arguments!\n");
		return -1;
	}
	/* At a time maximum length can be written is 16384(Maximum fragmented
	 * length defined by mbedtls api) bytes of num.
	 */
	while ((ret = mos_socket_send((fdo_con_handle)sock, (char *)buf, num,
				      0)) <= 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG(LOG_ERROR, "mbed_raw_write returned -0x%x\n", -ret);
			return -1;
		}
	}
	return ret;
}
fdo_con_handle get_ssl_socket(void)
{
	return ssl_info_var.socket;
}
#endif
/**
 * Set_up & Initate the TLS/SSL handshake with the TLS/SSL server.
 *
 * @param SERVER_NAME
 *        It will hold ip/dns address/name of type char.
 * @param SERVER_PORT
 *        It will hold port of type char.
 * @return ssl
 *        return pointer to ssl structure on success. NULL on failure.
 */
void *fdo_ssl_setup_connect(char *SERVER_NAME, char *SERVER_PORT)
{
	int ret = 0;
	const char *DRBG_PERSONALIZED_STR = "Mbed TLS client";

// Initialization of SSL
#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_init(&(p_ssl_info->server_fd));
#endif
	mbedtls_entropy_init(&(p_ssl_info->entropy));
	mbedtls_ctr_drbg_init(&(p_ssl_info->ctr_drbg));
	mbedtls_ssl_init(&(p_ssl_info->ssl));
	mbedtls_ssl_config_init(&(p_ssl_info->conf));
	ret = mbedtls_ctr_drbg_seed(
	    &(p_ssl_info->ctr_drbg), mbedtls_entropy_func,
	    &(p_ssl_info->entropy), (unsigned char *)DRBG_PERSONALIZED_STR,
	    strlen((char *)DRBG_PERSONALIZED_STR) + 1);
	if (ret != 0) {
		LOG(LOG_ERROR, "mbedtls_ctr_drbg_seed returned %d", ret);
		goto exit;
	}

#if !defined(TARGET_OS_MBEDOS)
	ret = mbedtls_net_connect(
	    &(p_ssl_info->server_fd), (const char *)SERVER_NAME,
	    (const char *)SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
	if (ret != 0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}
#else
	fdo_con_handle *socket = mos_socket_open();

	if (!socket) {
		LOG(LOG_ERROR, "mos_socket_open() failed!\n");
		goto exit;
	}
	ssl_info_var.socket = socket;
#endif
	ret = mbedtls_ssl_config_defaults(
	    &(p_ssl_info->conf), MBEDTLS_SSL_IS_CLIENT,
	    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
		    ret);
		goto exit;
	}

	/* The minimum size of DHM set to 2048 from default of 1024. */
	mbedtls_ssl_conf_dhm_min_bitlen(&(p_ssl_info->conf),
					MIN_BIT_LENGTH_DHM);

	/* Override default ciphersuites with the recommended ones*/
	mbedtls_ssl_conf_ciphersuites(&p_ssl_info->conf, ciphersuites);

	/* Explicitly set the max TLS version = v1.2 and min TLS = v1.1 */
	mbedtls_ssl_conf_max_version(&p_ssl_info->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_min_version(&p_ssl_info->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_2);

	mbedtls_ssl_conf_authmode(&(p_ssl_info->conf), MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&(p_ssl_info->conf), mbedtls_ctr_drbg_random,
			     &(p_ssl_info->ctr_drbg));
#ifdef CONFIG_MBEDTLS_DEBUG
	mbedtls_esp_enable_debug_log(&(p_ssl_info->conf), 4);
#endif

	ret = mbedtls_ssl_setup(&(p_ssl_info->ssl), &(p_ssl_info->conf));
	if (ret != 0) {
		LOG(LOG_ERROR, "failed\n  ! mbedtls_ssl_setup returned %d\n\n",
		    ret);
		goto exit;
	}

	ret = mbedtls_ssl_set_hostname(&(p_ssl_info->ssl),
				       (const char *)SERVER_NAME);
	if (ret != 0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n",
		    ret);
		goto exit;
	}

#if !defined(TARGET_OS_MBEDOS)
	mbedtls_ssl_set_bio(&(p_ssl_info->ssl), &(p_ssl_info->server_fd),
			    mbedtls_net_send, mbedtls_net_recv, NULL);
#else
	mbedtls_ssl_set_bio(&(p_ssl_info->ssl), (void *)ssl_info_var.socket,
			    mbed_ssl_rawwrite, mbed_ssl_rawread, NULL);
#endif

#if defined(TARGET_OS_MBEDOS)
	fdo_ip_address_t binip = {0};

	if (fdo_printable_to_net(SERVER_NAME, (void *)&binip.addr) != 1) {
		LOG(LOG_ERROR, "ip ascii to net format conversion fail.\n");
		goto exit;
	}
	if (-1 ==
	    mos_socket_con_only(socket, (void *)&binip, atoi(SERVER_PORT))) {
		LOG(LOG_ERROR, "mos_socket_con_only failed\n");
		goto exit;
	}
#endif

	while ((ret = mbedtls_ssl_handshake(&(p_ssl_info->ssl))) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG(LOG_ERROR,
			    "mbedtls_ssl_handshake returned -0x%x\n\n", ret);
			goto exit;
		}
	}

	ret = mbedtls_ssl_get_verify_result(&(p_ssl_info->ssl));
	if (ret != 0) {
		LOG(LOG_ERROR, "failed\n  ! Verification failed %d\n\n", ret);
		goto exit;
	}

	return (void *)p_ssl_info;

exit:
#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_free(&(p_ssl_info->server_fd));
#endif
	mbedtls_ssl_free(&(p_ssl_info->ssl));
	mbedtls_ssl_config_free(&(p_ssl_info->conf));
	mbedtls_ctr_drbg_free(&(p_ssl_info->ctr_drbg));
	mbedtls_entropy_free(&(p_ssl_info->entropy));
	return NULL;
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
int fdo_ssl_close(void *ssl)
{

	if (!ssl) {
		LOG(LOG_ERROR, "Invalid mbed SSL context!\n");
		return -1;
	}

	ssl_info *sslC = (ssl_info *)ssl;

#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_free(&(p_ssl_info->server_fd));
#endif
	mbedtls_entropy_free(&(sslC->entropy));
	mbedtls_ctr_drbg_free(&(sslC->ctr_drbg));
	mbedtls_ssl_free(&(sslC->ssl));
	mbedtls_ssl_config_free(&(sslC->conf));
	sslC = NULL;
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
 *        return number of bytes read on success. -1 on failure.
 */
int fdo_ssl_read(void *ssl, void *buf, int num)
{

	int ret = -1;

	if (!ssl || !buf) {
		LOG(LOG_ERROR, "Invalid arguments in %s!\n", __func__);
		return -1;
	}

	ssl_info *sslR = (ssl_info *)ssl;

	ret = mbedtls_ssl_read(&(sslR->ssl), (unsigned char *)buf, num);
	if (ret < 0) {
		LOG(LOG_ERROR,
		    "LOG_failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
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
 *        return number of bytes written on success. -1 on failure.
 */
int fdo_ssl_write(void *ssl, const void *buf, int num)
{
	int ret = -1;

	if (!ssl || !buf) {
		LOG(LOG_ERROR, "Invalid arguments in %s!\n", __func__);
		return -1;
	}

	ssl_info *sslW = (ssl_info *)ssl;

	/* At a time maximum length can be written is 16384(Maximum fragmented
	 * length defined by mbedtls api) bytes of num.
	 */
	while ((ret = mbedtls_ssl_write(
		    &(sslW->ssl), (const unsigned char *)buf, num)) <= 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG(LOG_ERROR, "mbedtls_ssl_write() returned -0x%x\n",
			    -ret);
			return -1;
		}
	}
	return ret;
}
