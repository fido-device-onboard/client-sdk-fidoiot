/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdoCryptoHal.h"
#include "util.h"
#include "crypto_utils.h"
#include "mbedtls/net.h"
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
static sslInfo sslInfoVar = {0};
static sslInfo *p_sslInfo = &sslInfoVar;
#endif

#if defined(TARGET_OS_MBEDOS)
#include "mbed_net_al.h"
typedef struct {
	void *socket;
	sslInfo mbed_sslInfo;
} sinfoextra;

static sinfoextra sslInfoVar = {0};
static sslInfo *p_sslInfo = &sslInfoVar.mbed_sslInfo;

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

	ret = mos_socketRecv((sdoConHandle)sock, (unsigned char *)buf, num, 0);
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
	 * length defined by mbedtls api) bytes of num.*/
	while ((ret = mos_socketSend((sdoConHandle)sock, (char *)buf, num,
				     0)) <= 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG(LOG_ERROR, "mbed_raw_write returned -0x%x\n", -ret);
			return -1;
		}
	}
	return ret;
}
sdoConHandle get_ssl_socket(void)
{
	return sslInfoVar.socket;
}
#endif
/**
 * SetUp & Initate the TLS/SSL handshake with the TLS/SSL server.
 *
 * @param SERVER_NAME
 *        It will hold ip/dns address/name of type char.
 * @param SERVER_PORT
 *        It will hold port of type char.
 * @return ssl
 *        return pointer to ssl structure on success. NULL on failure.
 */
void *sdo_ssl_setup_connect(char *SERVER_NAME, char *SERVER_PORT)
{
	int ret = 0;
	const char *DRBG_PERSONALIZED_STR = "Mbed TLS client";

// Initialization of SSL
#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_init(&(p_sslInfo->server_fd));
#endif
	mbedtls_entropy_init(&(p_sslInfo->entropy));
	mbedtls_ctr_drbg_init(&(p_sslInfo->ctr_drbg));
	mbedtls_ssl_init(&(p_sslInfo->ssl));
	mbedtls_ssl_config_init(&(p_sslInfo->conf));
	if ((ret = mbedtls_ctr_drbg_seed(
		 &(p_sslInfo->ctr_drbg), mbedtls_entropy_func,
		 &(p_sslInfo->entropy), (unsigned char *)DRBG_PERSONALIZED_STR,
		 strlen((char *)DRBG_PERSONALIZED_STR) + 1)) != 0) {
		LOG(LOG_ERROR, "mbedtls_ctr_drbg_seed returned %d", ret);
		goto exit;
	}

#if !defined(TARGET_OS_MBEDOS)
	if ((ret = mbedtls_net_connect(
		 &(p_sslInfo->server_fd), (const char *)SERVER_NAME,
		 (const char *)SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
		goto exit;
	}
#else
	sdoConHandle *socket = mos_socketOpen();
	if (!socket) {
		LOG(LOG_ERROR, "mos_socketOpen() failed!\n");
		goto exit;
	}
	sslInfoVar.socket = socket;
#endif

	if ((ret = mbedtls_ssl_config_defaults(
		 &(p_sslInfo->conf), MBEDTLS_SSL_IS_CLIENT,
		 MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) !=
	    0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
		    ret);
		goto exit;
	}

	/* The minimum size of DHM set to 2048 from default of 1024. */
	mbedtls_ssl_conf_dhm_min_bitlen(&(p_sslInfo->conf), MIN_BIT_LENGTH_DHM);

	/* Override default ciphersuites with the recommended ones*/
	mbedtls_ssl_conf_ciphersuites(&p_sslInfo->conf, ciphersuites);

	/* Explicitly set the max TLS version = v1.2 and min TLS = v1.1 */
	mbedtls_ssl_conf_max_version(&p_sslInfo->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_min_version(&p_sslInfo->conf,
				     MBEDTLS_SSL_MAJOR_VERSION_3,
				     MBEDTLS_SSL_MINOR_VERSION_2);

	mbedtls_ssl_conf_authmode(&(p_sslInfo->conf), MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&(p_sslInfo->conf), mbedtls_ctr_drbg_random,
			     &(p_sslInfo->ctr_drbg));
#ifdef CONFIG_MBEDTLS_DEBUG
	mbedtls_esp_enable_debug_log(&(p_sslInfo->conf), 4);
#endif

	if ((ret = mbedtls_ssl_setup(&(p_sslInfo->ssl), &(p_sslInfo->conf))) !=
	    0) {
		LOG(LOG_ERROR, "failed\n  ! mbedtls_ssl_setup returned %d\n\n",
		    ret);
		goto exit;
	}

	if ((ret = mbedtls_ssl_set_hostname(&(p_sslInfo->ssl),
					    (const char *)SERVER_NAME)) != 0) {
		LOG(LOG_ERROR,
		    "failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n",
		    ret);
		goto exit;
	}

#if !defined(TARGET_OS_MBEDOS)
	mbedtls_ssl_set_bio(&(p_sslInfo->ssl), &(p_sslInfo->server_fd),
			    mbedtls_net_send, mbedtls_net_recv, NULL);
#else
	mbedtls_ssl_set_bio(&(p_sslInfo->ssl), (void *)sslInfoVar.socket,
			    mbed_ssl_rawwrite, mbed_ssl_rawread, NULL);
#endif

#if defined(TARGET_OS_MBEDOS)
	SDOIPAddress_t binip = {0};
	if (sdoPrintableToNet(SERVER_NAME, (void *)&binip.addr) != 1) {
		LOG(LOG_ERROR, "ip ascii to net format conversion fail.\n");
		goto exit;
	}
	if (-1 ==
	    mos_socketConOnly(socket, (void *)&binip, atoi(SERVER_PORT))) {
		LOG(LOG_ERROR, "mos_socketConOnly failed \n");
		goto exit;
	}
#endif

	while ((ret = mbedtls_ssl_handshake(&(p_sslInfo->ssl))) != 0) {
		if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
		    ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			LOG(LOG_ERROR,
			    "mbedtls_ssl_handshake returned -0x%x\n\n", ret);
			goto exit;
		}
	}

	if ((ret = mbedtls_ssl_get_verify_result(&(p_sslInfo->ssl))) != 0) {
		LOG(LOG_ERROR, "failed\n  ! Verification failed %d\n\n", ret);
		goto exit;
	}

	return (void *)p_sslInfo;

exit:
#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_free(&(p_sslInfo->server_fd));
#endif
	mbedtls_ssl_free(&(p_sslInfo->ssl));
	mbedtls_ssl_config_free(&(p_sslInfo->conf));
	mbedtls_ctr_drbg_free(&(p_sslInfo->ctr_drbg));
	mbedtls_entropy_free(&(p_sslInfo->entropy));
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
int sdo_ssl_close(void *ssl)
{

	if (!ssl) {
		LOG(LOG_ERROR, "Invalid mbed SSL context!\n");
		return -1;
	}

	sslInfo *sslC = (sslInfo *)ssl;

#if !defined(TARGET_OS_MBEDOS)
	mbedtls_net_free(&(p_sslInfo->server_fd));
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
int sdo_ssl_read(void *ssl, void *buf, int num)
{

	int ret = -1;

	if (!ssl || !buf) {
		LOG(LOG_ERROR, "Invalid arguments in sdo_ssl_read()!\n");
		return -1;
	}

	sslInfo *sslR = (sslInfo *)ssl;

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
int sdo_ssl_write(void *ssl, const void *buf, int num)
{
	int ret = -1;

	if (!ssl || !buf) {
		LOG(LOG_ERROR, "Invalid arguments in sdo_ssl_write()!\n");
		return -1;
	}

	sslInfo *sslW = (sslInfo *)ssl;

	/* At a time maximum length can be written is 16384(Maximum fragmented
	 * length defined by mbedtls api) bytes of num.*/
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
