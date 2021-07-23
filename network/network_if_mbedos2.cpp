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
#include "safe_lib.h"

extern NetworkInterface *getNetinterface(void);

int mos_resolvedns(char *dn, char *ip)
{
	NetworkInterface *net = getNetinterface();
	SocketAddress addr;
	const char *tmpip = NULL;
	size_t tmpip_len = 0;

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

	tmpip_len = strnlen_s(tmpip, FDO_MAX_STR_SIZE);
	if (!tmpip_len || tmpip_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "Strlen() failed for temp IP data\n");
		return -1;
	}

	LOG(LOG_DEBUG, "DNS: query \"%s\" => \"%s\"\n", dn, tmpip);
	if (strncpy_s(ip, tmpip_len + 1, tmpip, tmpip_len + 1) != 0) {
		LOG(LOG_ERROR, " ip from dns, copy failed\n");
		return -1;
	}
	return 0;
}

fdo_con_handle *mos_socket_open(void)
{
	NetworkInterface *net = getNetinterface();
	fdo_con_handle *socket = new fdo_con_handle;
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

int mos_socket_con_only(fdo_con_handle *socket, fdo_ip_address_t *ip_addr,
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

fdo_con_handle *mos_socket_connect(fdo_ip_address_t *ip_addr, uint16_t port)
{
	int r = -1;
	fdo_con_handle *socket = NULL;
	if (!ip_addr || !port) {
		LOG(LOG_ERROR, "socket params not correct\n");
		return NULL;
	}
	socket = mos_socket_open();
	if (socket == NULL) {
		LOG(LOG_ERROR, "socket.open() returned: %d\n", r);
		return NULL;
	}

	r = mos_socket_con_only(socket, ip_addr, port);
	if (r != 0) {
		LOG(LOG_ERROR, "socket.open() returned: %d\n", r);
		goto err;
	}
	return socket;
err:
	mos_socket_close(socket);
	return NULL;
}

void mos_socket_close(fdo_con_handle *socket)
{
	if (socket) {
		socket->close();
		delete socket;
	}
}

int mos_socket_send(fdo_con_handle *socket, void *buf, size_t len, int flags)
{
	if (socket) {
		return (socket->send((char *)buf, len));
	}
	return -1;
}

int mos_socket_recv(fdo_con_handle *socket, void *buf, size_t len, int flags)
{
	if (socket) {
		return (socket->recv((char *)buf, len));
	}
	return -1;
}
