/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Abstraction Layer Library
 *
 * The file implements an abstraction layer for Linux OS running on PC.
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

#include "util.h"
#include "network_al.h"
#include "sdoCryptoHal.h"
#include "sdoprotctx.h"
#include "sdonet.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"

/**
 * Read from socket until new-line is encountered.
 *
 * @param sock - socket-id.
 * @param out -  out pointer for REST header line.
 * @param size - out REST header line length.
 * @param ssl -  SSL pointer if TLS is active
 * @retval true if line read was successful, false otherwise.
 */
static bool readUntilNewLine(uint32_t sock, char *out, size_t size, void *ssl)
{
	int sz, n;
	char c;

	if (!out || !size)
		return false;

	--size; // leave room for NULL
	sz = 0;
	for (;;) {

		if (ssl)
			n = sdo_ssl_read(ssl, (uint8_t *)&c, 1);
		else
			n = recv(sock, (uint8_t *)&c, 1, MSG_WAITALL);

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket Read Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);
			return false;
		}
		if (sz < size)
			out[sz++] = c;

		if (c == '\n')
			break;
	}
	out[sz] = 0;
	/* remove \n and \r and don't process invalid string */
	if ((sz < size) && (sz >= 1)) {
		out[--sz] = 0; // remove NL
		if ((sz >= 1) && (out[sz - 1] == '\r'))
			out[--sz] = 0; // ... remove CRNL
	}

	return true;
}

/**
 * sdoConSetup Connection Setup.
 *
 * @param medium - specified network medium to connect to
 * @param params - parameters(if any) supported for 'medium'
 * @param count - number of valid string in params
 * @return 0 on success. -1 on failure
 */
int32_t sdoConSetup(char *medium, char **params, uint32_t count)
{
	/*TODO: make use of input params (if required ?)*/
	(void)medium;
	(void)params;
	(void)count;

	// Initiate REST context
	if (!initRESTContext()) {
		LOG(LOG_ERROR, "initRESTContext() failed!\n");
		return -1;
	}
	return 0;
}

/**
 * Perform a DNS look for a specified host.
 * Note : return ip address in network format.
 * @param url - host's URL.
 * @param ipList - output IP address list for specified host URL.
 * @param ipListSize - output number of IP address in ipList
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConDnsLookup(const char *url, SDOIPAddress_t **ipList,
			uint32_t *ipListSize)
{
	int idx;
	struct addrinfo *result = NULL, *it = NULL;
	struct addrinfo hints;
	struct sockaddr_in *sa_in = NULL;
	SDOIPAddress_t *ip_list = NULL;
	int32_t ret = -1;

	if (!url || !ipList || !ipListSize)
		return ret;

	LOG(LOG_DEBUG, "Resolving DNS-URL: <%s>\n", url);

	if (memset_s(&hints, sizeof hints, 0) != 0) {
		LOG(LOG_ERROR, "Memset failed\n");
		goto end;
	}

	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM;

	// get the list-of IP addresses
	if (getaddrinfo(url, NULL, &hints, &result) != 0) {
		LOG(LOG_ERROR, "getaddrinfo() failed!\n");
		goto end;
	}

	int len = 0;

	// get length of the ip-address LL
	for (it = result; it != NULL; it = it->ai_next) {
		++len;
	}

	ip_list = sdoAlloc(sizeof(SDOIPAddress_t) * len);

	if (!ip_list) {
		LOG(LOG_ERROR, "Malloc failed!\n");
		goto end;
	}

	// iterate and store IP-addresses
	for (idx = 0, it = result; it != NULL; ++idx, it = it->ai_next) {
		sa_in = (struct sockaddr_in *)it->ai_addr;

#if LOG_LEVEL == LOG_MAX_LEVEL
		// for trace purpose
		char host[16];
		inet_ntop(AF_INET, &(sa_in->sin_addr), host, 16);
		LOG(LOG_DEBUG, "Resolved into IP-Address: <%s>\n", host);
#endif
		(ip_list + idx)->length = IPV4_ADDR_LEN;

		if (memcpy_s((ip_list + idx)->addr, ip_list->length,
			     &(sa_in->sin_addr.s_addr), ip_list->length) != 0) {
			LOG(LOG_ERROR, "Memcpy failed\n");
			goto end;
		}
	}

	*ipList = ip_list;
	*ipListSize = len;
	ret = 0;

end:
	// avoid leak in case DNS look-up operation was not successful.
	if (ret != 0) {
		*ipListSize = 0;
		if (ip_list) {
			sdoFree(ip_list);
		}
	}
	if (result)
		freeaddrinfo(result); // free the addr list always
	return ret;
}

/**
 * sdoConConnect connects to the network socket
 *
 * @param ip_addr - pointer to IP address info
 * @param port - port number to connect
 * @param ssl - ssl handler in case of tls connection.
 * @return connection handle on success. -ve value on failure
 */

sdoConHandle sdoConConnect(SDOIPAddress_t *ip_addr, uint16_t port, void **ssl)
{
	int sock = SDO_CON_INVALID_HANDLE;
	struct sockaddr_in haddr;

	if (!ip_addr)
		goto end;

	if (memset_s(&haddr, sizeof haddr, 0) != 0) {
		LOG(LOG_ERROR, "Memset failed\n");
		goto end;
	}

	if (memcpy_s(&haddr.sin_addr.s_addr, ip_addr->length, &ip_addr->addr[0],
		     ip_addr->length) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		goto end;
	}

	haddr.sin_family = AF_INET; // IPV4
	haddr.sin_port = htons(port);

#ifdef USE_MBEDTLS

	if (ssl) {
		char ipv4[IP_TAG_LEN] = {0};
		char port_s[MAX_PORT_SIZE] = {0};
		uint8_t octlet_size =
		    4; // e.g 192.168.0.100, max 3char + 1null/oct.

		if (!ip_addr)
			goto end;

		/*
		 * Convert ip binary to string format as required by
		 * mbed connect
		 */
		if ((snprintf_s_i(ipv4, octlet_size, "%d", ip_addr->addr[0]) <
		     0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[1]) < 0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[2]) < 0) ||
		    (snprintf_s_i((ipv4 + strnlen_s(ipv4, IP_TAG_LEN)),
				  octlet_size + 1, ".%d",
				  ip_addr->addr[3]) < 0)) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto end;
		}
		if (snprintf_s_i(port_s, sizeof port_s, "%d", port) < 0) {
			LOG(LOG_ERROR, "Snprintf() failed!\n");
			goto end;
		}

		*ssl = sdo_ssl_setup_connect(ipv4, port_s);

		if (NULL == *ssl) {
			LOG(LOG_ERROR, "TLS connection "
				       "setup "
				       "failed\n");
			goto end;
		}
		return MBEDTLS_NET_DUMMY_SOCKET;
	}
#endif
	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0)
		goto end;

	if (connect(sock, (struct sockaddr *)&haddr, sizeof haddr) < 0) {
		LOG(LOG_ERROR, "Socket Connect failed, trying next IP\n");
		close(sock);
		sock = -1;
		goto end;
	}
#if defined(USE_OPENSSL)
	if (ssl) {
		*ssl = sdo_ssl_setup(sock);

		if (NULL == *ssl) {
			LOG(LOG_ERROR, "TLS connection setup failed\n");
			close(sock);
			sock = SDO_CON_INVALID_HANDLE;
		}

		if (sdo_ssl_connect(*ssl)) {
			LOG(LOG_ERROR, "TLS connect failed\n");
			close(sock);
			sock = SDO_CON_INVALID_HANDLE;
		}
	}
#endif
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
int32_t sdoConDisconnect(sdoConHandle handle, void *ssl)
{
	if (ssl) {
		sdo_ssl_close(ssl);

#ifdef USE_MBEDTLS
		return 0;
#endif
	}
	// close() returns 0 on success
	if (!close(handle))
		return 0;
	else
		return -1;
}

/**
 * Receive(read) protocol version, message type and length of rest body
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param protocolVersion - out SDO protocol version
 * @param messageType - out message type of incoming SDO message.
 * @param msglen - out Number of received bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConRecvMsgHeader(sdoConHandle handle, uint32_t *protocolVersion,
			    uint32_t *messageType, uint32_t *msglen, void *ssl)
{
	int32_t ret = -1;
	char hdr[REST_MAX_MSGHDR_SIZE] = {0};
	char tmp[REST_MAX_MSGHDR_SIZE];
	size_t hdrlen;
	RestCtx_t *rest = NULL;

	if (!protocolVersion || !messageType || !msglen)
		goto err;

	// read REST header
	for (;;) {
		if (memset_s(tmp, sizeof(tmp), 0) != 0) {
			LOG(LOG_ERROR, "Memset() failed!\n");
			goto err;
		}

		if (!readUntilNewLine(handle, tmp, REST_MAX_MSGHDR_SIZE, ssl)) {
			LOG(LOG_ERROR, "readUntilNewLine() failed!\n");
			goto err;
		}

		// end of header
		if (tmp[0] == getRESTHdrBodySeparator())
			break;

		// accumulate header content
		if (strncat_s(hdr, REST_MAX_MSGHDR_SIZE, tmp,
			      strnlen_s(tmp, REST_MAX_MSGHDR_SIZE)) != 0) {
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

	/* Process REST header and get content-length of body */
	if (!getRESTContentLength(hdr, hdrlen, msglen)) {
		LOG(LOG_ERROR, "REST Header processing failed!!\n");
		goto err;
	}

	rest = getRESTContext();
	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// copy protver from REST context
	*protocolVersion = rest->protVer;
	*messageType = rest->msgType;

	ret = 0;

err:
	return ret;
}

/**
 * Receive(read) MsgBody
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param buf - data buffer to read into.
 * @param length - Number of received bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, number of bytes read on success.
 */
int32_t sdoConRecvMsgBody(sdoConHandle handle, uint8_t *buf, size_t length,
			  void *ssl)
{
	int n;
	int32_t ret = -1;

	if (!buf || !length)
		goto err;

	if (ssl)
		n = sdo_ssl_read(ssl, buf, length);
	else
		n = recv(handle, buf, length, MSG_WAITALL);

	if (n <= 0) {
		ret = -1;
		goto err;
	}
	ret = n;
err:
	return ret;
}

/**
 * Send(write) data.
 *
 * @param handle - connection handler (for ex: socket-id)
 * @param protocolVersion - SDO protocol version
 * @param messageType - message type of outgoing SDO message.
 * @param buf - data buffer to write from.
 * @param length - Number of sent bytes.
 * @param ssl - handler in case of tls connection.
 * @retval -1 on failure, number of bytes written.
 */
int32_t sdoConSendMessage(sdoConHandle handle, uint32_t protocolVersion,
			  uint32_t messageType, const uint8_t *buf,
			  size_t length, void *ssl)
{
	int ret = -1;
	int n;
	RestCtx_t *rest = NULL;
	char restHdr[REST_MAX_MSGHDR_SIZE] = {0};
	size_t headerLen = 0;

	if (!buf || !length)
		goto err;

	rest = getRESTContext();

	if (!rest) {
		LOG(LOG_ERROR, "REST context is NULL!\n");
		goto err;
	}

	// supply info to REST for POST-URL construction
	rest->protVer = protocolVersion;
	rest->msgType = messageType;
	rest->contentLength = length;

	if (!constructRESTHeader(rest, restHdr, REST_MAX_MSGHDR_SIZE)) {
		LOG(LOG_ERROR, "Error during constrcution of REST hdr!\n");
		goto err;
	}

	headerLen = strnlen_s(restHdr, REST_MAX_MSGHDR_SIZE);

	if (!headerLen || headerLen == REST_MAX_MSGHDR_SIZE) {
		LOG(LOG_ERROR, "Strlen() failed!\n");
		goto err;
	}

	/* Send REST header */
	if (ssl) {
		n = sdo_ssl_write(ssl, restHdr, headerLen);

		if (n <= 0) {
			LOG(LOG_ERROR, "SSL Header write Failed!\n");
			goto hdrerr;
		}
	} else {

		n = send(handle, restHdr, headerLen, 0);

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket write Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);

			if (sdoConDisconnect(handle, ssl)) {
				LOG(LOG_ERROR, "Error during socket close()\n");
				goto hdrerr;
			}
			goto hdrerr;

		} else if (n < headerLen) {
			LOG(LOG_ERROR,
			    "Rest Header write returns %d/%zu bytes\n", n,
			    headerLen);
			goto hdrerr;

		} else
			LOG(LOG_DEBUG,
			    "Rest Header write returns %d/%zu bytes\n\n", n,
			    headerLen);
	}

	LOG(LOG_DEBUG, "REST:header(%zu):%s\n", headerLen, restHdr);

	/* Send REST body */
	if (ssl) {
		n = sdo_ssl_write(ssl, buf, length);
		if (n <= 0) {
			LOG(LOG_ERROR, "SSL Body write Failed!\n");
			goto bodyerr;
		}
	} else {
		n = send(handle, buf, length, 0);

		if (n <= 0) {
			LOG(LOG_ERROR,
			    "Socket write Failed, ret=%d, "
			    "errno=%d, %d\n",
			    n, errno, __LINE__);

			if (sdoConDisconnect(handle, ssl)) {
				LOG(LOG_ERROR, "Error during socket close()\n");
				goto bodyerr;
			}
			goto bodyerr;

		} else if (n < length) {
			LOG(LOG_ERROR, "Rest Body write returns %d/%zu bytes\n",
			    n, length);
			goto bodyerr;

		} else
			LOG(LOG_DEBUG,
			    "Rest Body write returns %d/%zu bytes\n\n", n,
			    length);
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
 * sdoConTearDown connection tear-down.
 *
 * @return 0 on success, -1 on failure
 */
int32_t sdoConTeardown(void)
{
	/* REST context over */
	exitRESTContext();
	return 0;
}

/**
 * Put the SDO device to low power state
 *
 * @param sec
 *        number of seconds to put the device to low power state
 *
 * @return none
 */
void sdoSleep(int sec)
{
	sleep(sec);
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
uint32_t sdoNetToHostLong(uint32_t value)
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
uint32_t sdoHostToNetLong(uint32_t value)
{
	return htonl(value);
}

/**
 * Convert from ASCII to Network format
 *
 * @param src
 *         Source address in ASCII format.
 * @param addr
 *         Source address in network format.
 *
 * @return
 *        1 on success. -1 on error. 0 if input format is invalie
 */
int32_t sdoPrintableToNet(const char *src, void *addr)
{
	return inet_pton(AF_INET, src, addr);
}

/**
 * get device model
 *
 * @return
 *        returns model as string
 */
const char *get_device_model(void)
{
	return "Intel-SDO-Linux";
}

/**
 *  get device serial number
 *
 * @return
 *        returns device serial number as string.
 */
const char *get_device_serial_number(void)
{
	return "sdo-linux-1234";
}

/**
 * sdo_random generates random number and returns
 *
 * Note: this is only to be used for calculating random
 * network delay for retransmissions and NOT for crypto
 *
 * @return
 *        returns random number
 */
int sdoRandom(void)
{
	return rand();
}
