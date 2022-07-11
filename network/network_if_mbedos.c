/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Abstraction Layer Library
 *
 * The file implements an abstraction layer for mbedos cortex M boards .
 */

#include "util.h"
#include "network_al.h"
#include "fdoCryptoHal.h"
#include "fdoprotctx.h"
#include "fdonet.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"
#include "def.h"
#include "mbed_wait_api.h"
#include "platform/mbed_thread.h"
#include <lwip/ip4_addr.h>
#include <lwip/sockets.h>

/**
 * Read from socket until new-line is encountered.
 *
 * @param handle - socket-handle.
 * @param out -  out pointer for REST header line.
 * @param size - out REST header line length.
 * @param ssl -  SSL pointer if TLS is active
 * @retval true if line read was successful, false otherwise.
 */
static bool read_until_new_line(fdo_con_handle handle, char *out, size_t size,
				void *ssl)
{
	size_t sz = 0;
	int n = 0;
	char c = 0;

	if (!out || !size) {
		return false;
	}

	--size; // leave room for NULL
	sz = 0;
	for (;;) {

		if (ssl) {
			n = fdo_ssl_read(ssl, (uint8_t *)&c, 1);
		} else {
			n = mos_socket_recv(handle, (uint8_t *)&c, 1, 0);
		}

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket Read Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);
			return false;
		}
		if (sz < size) {
			out[sz++] = c;
		}

		if (c == '\n') {
			break;
		}
	}
	out[sz] = 0;
	/* remove \n and \r and don't process invalid string */
	if ((sz < size) && (sz >= 1)) {
		out[--sz] = 0; // remove NL
		if ((sz >= 1) && (out[sz - 1] == '\r')) {
			out[--sz] = 0; // ... remove CRNL
		}
	}
	return true;
}

/**
 * fdo_con_setup Connection Setup.
 *
 * @param medium - specified network medium to connect to
 * @param params - parameters(if any) supported for 'medium'
 * @param count - number of valid string in params
 * @return 0 on success. -1 on failure
 */
int32_t fdo_con_setup(char *medium, char **params, uint32_t count)
{
	/*TODO: make use of input params (if required ?)*/
	(void)medium;
	(void)params;
	(void)count;

	// Initiate REST context
	if (!init_rest_context()) {
		LOG(LOG_ERROR, "init_rest_context() failed!\n");
		return -1;
	}
	return 0;
}

/**
 * Perform a DNS look for a specified host.
 *
 * @param url - host's URL.
 * @param ip_list - output IP address list for specified host URL.
 * @param ip_list_size - output number of IP address in ip_list
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_dns_lookup(const char *url, fdo_ip_address_t **ip_list,
			   uint32_t *ip_list_size)
{
	int ret = -1;
	fdo_ip_address_t *fdotmpip = NULL;
	uint8_t resolved_ip[IP_TAG_LEN] = {0};

	if (!url || !ip_list || !ip_list_size) {
		LOG(LOG_ERROR, "Bad parameters received\n");
		goto err;
	}

	fdotmpip = (fdo_ip_address_t *)fdo_alloc(sizeof(fdo_ip_address_t));
	if (!fdotmpip) {
		LOG(LOG_ERROR, "Out of memory for ip_list\n");
		goto err;
	}

	if (mos_resolvedns((char *)url, (char *)resolved_ip) != 0) {
		LOG(LOG_ERROR, "mos_resolve dns faileds\n");
		goto err;
	}
	fdotmpip->length = IPV4_ADDR_LEN;

	if (fdo_printable_to_net((const char *)resolved_ip,
				 (void *)fdotmpip->addr) != 1) {
		LOG(LOG_ERROR, "ascii ip to bin conversion failed\n");
		goto err;
	}

	*ip_list = (fdo_ip_address_t *)fdotmpip;
	*ip_list_size = 1;

	ret = 0;
err:
	return ret;
}

/**
 * fdo_con_connect connects to the network socket
 *
 * @param ip_addr - pointer to IP address info
 * @param port - port number to connect
 * @param ssl - ssl handler in case of tls connection.
 * @return connection handle on success. -ve value on failure
 */

fdo_con_handle fdo_con_connect(fdo_ip_address_t *ip_addr, uint16_t port,
			       void **ssl)
{
	fdo_con_handle sock = FDO_CON_INVALID_HANDLE;
	char *ipv4 = NULL;
	char port_s[MAX_PORT_SIZE] = {0};

	if (!ip_addr) {
		goto end;
	}
	if (ssl) {
		/*
		 * Convert ip binary to string format as required by
		 * mbedtls ssl connect
		 */
		ipv4 = ip4addr_ntoa((const void *)ip_addr->addr);
		if (ipv4 == NULL) {
			LOG(LOG_ERROR, "net to ascii ip failed failed!\n");
			goto end;
		}

		if (snprintf_s_i(port_s, sizeof(port_s), "%d", port) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto end;
		}

		*ssl = fdo_ssl_setup_connect(ipv4, port_s);

		if (NULL == *ssl) {
			LOG(LOG_ERROR, "TLS connection "
				       "setup "
				       "failed\n");
			goto end;
		}
		sock = (fdo_con_handle *)get_ssl_socket();
		return sock;
	}
	sock = mos_socket_connect(ip_addr, port);

end:
	return sock;
}

/**
 * Disconnect the connection for a given connection handle.
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param ssl - SSL handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_disconnect(fdo_con_handle handle, void *ssl)
{
	if (ssl) { // SSL disconnect
		fdo_ssl_close(ssl);
	}

	mos_socket_close(handle);
	return 0;
}

/**
 * Receive(read) protocol version, message type and length of rest body
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param protocol_version - out FDO protocol version
 * @param message_type - out message type of incoming FDO message.
 * @param msglen - out Number of received bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_recv_msg_header(fdo_con_handle handle,
				uint32_t *protocol_version,
				uint32_t *message_type, uint32_t *msglen,
				void *ssl)
{
	int32_t ret = -1;
	char hdr[REST_MAX_MSGHDR_SIZE] = {0};
	char tmp[REST_MAX_MSGHDR_SIZE];
	size_t tmplen;
	size_t hdrlen;
	rest_ctx_t *rest = NULL;

	if (!protocol_version || !message_type || !msglen) {
		goto err;
	}

	// read REST header
	for (;;) {
		if (memset_s(tmp, sizeof(tmp), 0) != 0) {
			LOG(LOG_ERROR, "Memset() failed!\n");
			goto err;
		}

		if (!read_until_new_line(handle, tmp, REST_MAX_MSGHDR_SIZE,
					 ssl)) {
			LOG(LOG_ERROR, "read_until_new_line() failed!\n");
			goto err;
		}

		// end of header
		if (tmp[0] == get_rest_hdr_body_separator()) {
			break;
		}

		if (!tmplen || tmplen == REST_MAX_MSGHDR_SIZE) {
			LOG(LOG_ERROR, "Strlen() failed!\n")
			goto err;
		}

		// accumulate header content
		if (strncat_s(hdr, REST_MAX_MSGHDR_SIZE, tmp, tmplen) != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}

		// append new line for convenient parsing in REST
		if (strcat_s(hdr, REST_MAX_MSGHDR_SIZE, "\n") != 0) {
			LOG(LOG_ERROR, "Strcat() failed!\n");
			goto err;
		}
	}

	hdrlen = strnlen_s(hdr, REST_MAX_MSGHDR_SIZE);
	if (!hdrlen || hdrlen == REST_MAX_MSGHDR_SIZE) {
		LOG(LOG_ERROR, "hdr is not NULL terminated.\n");
		goto err;
	}	

	/* Process REST header and get content-length of body */
	if (!get_rest_content_length(hdr, hdrlen, msglen)) {
		LOG(LOG_ERROR, "REST Header processing failed!!\n");
		goto err;
	}

	rest = get_rest_context();
	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// copy protver from REST context
	*protocol_version = rest->prot_ver;
	*message_type = rest->msg_type;

	ret = 0;

err:
	return ret;
}

/**
 * Receive(read) Msg_body
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param buf - data buffer to read into.
 * @param length - Number of received bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, number of bytes read on success.
 */
int32_t fdo_con_recv_msg_body(fdo_con_handle handle, uint8_t *buf,
			      size_t length, void *ssl)
{
	int n = 0;
	int32_t ret = -1;
	uint8_t *bufp = buf;
	int sz = length;

	if (!buf || !length) {
		goto err;
	}
	do {
		bufp = bufp + n;
		if (ssl) {
			n = fdo_ssl_read(ssl, bufp, sz);
		} else {
			n = mos_socket_recv(handle, bufp, sz, 0);
		}

		LOG(LOG_DEBUG, "Expected %d , got %d\n", sz, n);
		sz = sz - n;
		if (n < 0) {
			ret = -1;
			goto err;
		}
	} while (sz > 0);
	ret = length;
err:
	return ret;
}

/**
 * Send(write) data.
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param protocol_version - FDO protocol version
 * @param message_type - message type of outgoing FDO message.
 * @param buf - data buffer to write from.
 * @param length - Number of sent bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, number of bytes written.
 */
int32_t fdo_con_send_message(fdo_con_handle handle, uint32_t protocol_version,
			     uint32_t message_type, const uint8_t *buf,
			     size_t length, void *ssl)
{
	int ret = -1;
	int n;
	rest_ctx_t *rest = NULL;
	char rest_hdr[REST_MAX_MSGHDR_SIZE] = {0};
	size_t header_len = 0;

	if (!buf || !length) {
		goto err;
	}

	rest = get_rest_context();

	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// supply info to REST for POST-URL construction
	rest->prot_ver = protocol_version;
	rest->msg_type = message_type;
	rest->content_length = length;
	if (ssl) {
		rest->tls = true;
	}

	if (!construct_rest_header(rest, rest_hdr, REST_MAX_MSGHDR_SIZE)) {
		LOG(LOG_ERROR, "Error during constrcution of REST hdr!\n");
		goto err;
	}

	header_len = strnlen_s(rest_hdr, FDO_MAX_STR_SIZE);

	if (!header_len || header_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "Strlen() failed!\n");
		goto err;
	}

	/* Send REST header */
	if (ssl) {
		n = fdo_ssl_write(ssl, rest_hdr, header_len);

		if (n < 0) {
			LOG(LOG_ERROR, "SSL Header write Failed!\n");
			goto hdrerr;
		}
	} else {
		n = mos_socket_send(handle, rest_hdr, header_len, 0);

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket write Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);

			if (fdo_con_disconnect(handle, ssl)) {
				LOG(LOG_ERROR, "Error during socket close()\n");
				goto hdrerr;
			}
			goto hdrerr;

		} else if (n < (int)header_len) {
			LOG(LOG_ERROR,
			    "Rest Header write returns %d/%u bytes\n", n,
			    header_len);
			goto hdrerr;

		} else {
			LOG(LOG_DEBUG,
			    "Rest Header write returns %d/%u bytes\n\n", n,
			    header_len);
		}
	}

	LOG(LOG_DEBUG, "REST:header(%u):%s\n", header_len, rest_hdr);

	/* Send REST body */
	if (ssl) {
		n = fdo_ssl_write(ssl, buf, length);
		if (n < 0) {
			LOG(LOG_ERROR, "SSL Body write Failed!\n");
			goto bodyerr;
		}
	} else {
		n = mos_socket_send(handle, (void *)buf, length, 0);

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket write Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);

			if (fdo_con_disconnect(handle, ssl)) {
				LOG(LOG_ERROR, "Error during socket close()\n");
				goto bodyerr;
			}
			goto bodyerr;

		} else if (n < (int)length) {
			LOG(LOG_ERROR, "Rest Body write returns %d/%u bytes\n",
			    n, length);
			goto bodyerr;

		} else {
			LOG(LOG_DEBUG,
			    "Rest Body write returns %d/%u bytes\n\n", n,
			    length);
		}
	}

	return n;

hdrerr:
	LOG(LOG_ERROR, "REST Header write not successful!\n");
	goto err;
bodyerr:
	LOG(LOG_ERROR, "REST Body write not successful!\n");
err:
	return ret;
}

/**
 * fdo_con_tear_down connection tear-down.
 *
 * @return 0 on success, -1 on failure
 */
int32_t fdo_con_teardown(void)
{
	/* REST context over */
	exit_rest_context();
	return 0;
}

/**
 * Put the FDO device to low power state
 *
 * @param sec
 *        number of seconds to put the device to low power state
 *
 * @return none
 */
void fdo_sleep(int sec)
{
	thread_sleep_for(sec * 1000);
}

/**
 * Convert from Network to Host byte order
 *
 * @param value
 *        Number in network byte order.
 *
 * @return
 *         Value in Host byte order.
 */
uint32_t fdo_net_to_host_long(uint32_t value)
{
	return ntohl(value);
}

/**
 * Convert from Host to Network byte order
 *
 * @param value
 *         Value in Host byte order.
 *
 * @return
 *        Number in network byte order.
 */
uint32_t fdo_host_to_net_long(uint32_t value)
{
	return htonl(value);
}

/**
 * Convert from ASCII to string format
 *
 * @param src
 *         Source address in ASCII format.
 * @param addr
 *         Source address in string.
 *
 * @return
 *        1 on success. -1 on error. 0 if input format is invalid
 */
int32_t fdo_printable_to_net(const char *src, void *addr)
{
	return ip4addr_aton(src, addr);
}

/**
 * get device model
 *
 * @return
 *        returns model as string
 */
const char *get_device_model(void)
{
	return "Intel-FDO-f32m7";
}

/**
 *  get device serial number
 *
 * @return
 *        returns device serial number as string.
 */
const char *get_device_serial_number(void)
{
	return "fdo-f32m7-1234";
}

/**
 * fdo_random generates random number and returns
 *
 * Note: this is only to be used for calculating random
 * network delay for retransmissions and NOT for crypto

 * @return
 *        returns random number
 */
int fdo_random(void)
{
	return rand();
}
