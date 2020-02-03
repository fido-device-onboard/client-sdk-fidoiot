/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \The file implements an internal low level abstraction layer for mbedos
 * netework running on Cortex-M.
 */
#include "mbed.h"
#include "network_al.h"
#include "util.h"

extern "C" {
extern int strncpy_s(char *dest, size_t dmax, const char *src, size_t slen);
size_t strnlen_s(const char *dest, size_t dmax);
}
extern NetworkInterface *getNetinterface(void);

int mos_resolvedns(char *dn, char *ip)
{
	NetworkInterface *net = getNetinterface();
	SocketAddress addr;
	const char *tmpip = NULL;

	if (!net || !dn || !ip) {
		LOG(LOG_ERROR, "Bad parameters received\n");
		return -1;
	}
	int err = net->gethostbyname(dn, &addr);
	if (err) {
		LOG(LOG_ERROR, "gethostbynam failed\n");
		return -1;
	}

	tmpip = addr.get_ip_address();
	if (!tmpip) {
		LOG(LOG_ERROR, "sockaddress not allocated\n");
		return -1;
	}

	LOG(LOG_DEBUG, "DNS: query \"%s\" => \"%s\"\n", dn, tmpip);
	if (strncpy_s(ip, strnlen_s(tmpip, SDO_MAX_STR_SIZE) + 1, tmpip,
		      strnlen_s(tmpip, SDO_MAX_STR_SIZE) + 1) != 0) {
		LOG(LOG_ERROR, " ip from dns, copy failed\n");
		return -1;
	}
	return 0;
}

sdoConHandle *mos_socketOpen(void)
{
	NetworkInterface *net = getNetinterface();
	sdoConHandle *socket = new sdoConHandle;
	int r = -1;

	if (!net) {
		LOG(LOG_ERROR, "net interface not initialized\n");
		return NULL;
	}

	if (!socket) {
		LOG(LOG_ERROR, "create socket instance failed\n");
		return NULL;
	}
	r = socket->open(net);
	if (r != 0) {
		LOG(LOG_ERROR, "socket.open() returned: %d\n", r);
		delete socket;
		return NULL;
	}

	return socket;
}

int mos_socketConOnly(sdoConHandle *socket, SDOIPAddress_t *ip_addr,
		      uint16_t port)
{
	int r = -1;

	if (!socket || !ip_addr || !port) {
		LOG(LOG_ERROR, "socket params not correct\n");
		return 0;
	}
	SocketAddress sockaddr((const void *)(ip_addr->addr), NSAPI_IPv4, port);
	r = socket->connect(sockaddr);
	if (r != 0) {
		LOG(LOG_ERROR, "socket.connect() returned: %d\n", r);
		socket->close();
		return -1;
	}
	socket->set_blocking(true);
	socket->set_timeout(MBED_SOCKET_TIMEOUT);
	return r;
}

sdoConHandle *mos_socketConnect(SDOIPAddress_t *ip_addr, uint16_t port)
{
	int r = -1;
	sdoConHandle *socket = NULL;
	if (!ip_addr || !port) {
		LOG(LOG_ERROR, "socket params not correct\n");
		return NULL;
	}
	socket = mos_socketOpen();
	if (socket == NULL) {
		LOG(LOG_ERROR, "socket.open() returned: %d\n", r);
		return NULL;
	}

	r = mos_socketConOnly(socket, ip_addr, port);
	if (r != 0) {
		LOG(LOG_ERROR, "socket.open() returned: %d\n", r);
		goto err;
	}
	return socket;
err:
	mos_socketClose(socket);
	return NULL;
}

void mos_socketClose(sdoConHandle *socket)
{
	if (socket) {
		socket->close();
		delete socket;
	}
}

int mos_socketSend(sdoConHandle *socket, void *buf, size_t len, int flags)
{
	if (socket) {
		return (socket->send((char *)buf, len));
	}
	return -1;
}

int mos_socketRecv(sdoConHandle *socket, void *buf, size_t len, int flags)
{
	if (socket) {
		return (socket->recv((char *)buf, len));
	}
	return -1;
}
