/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Abstraction Layer
 *
 * This file is header implementation of mbedos network/socket layer interface
 * of network abstraction layer for Cortex M4/7 boards.
 *
 */
#ifdef __cplusplus
#include "TCPSocket.h"
extern "C" {
#endif

#ifdef __cplusplus
class sdo_con_handle : public TCPSocket
{
};
#else
#include "mbedtls/ssl.h"
#include "sdoCryptoHal.h"
typedef void *sdo_con_handle;
#define SDO_CON_INVALID_HANDLE NULL
#endif

int mos_resolvedns(char *dn, char *ip);
sdo_con_handle *mos_socket_connect(sdo_ip_address_t *ip, uint16_t port);
sdo_con_handle *mos_socket_open(void);
int mos_socket_con_only(sdo_con_handle *socket, sdo_ip_address_t *ip,
			uint16_t port);
void mos_socket_close(sdo_con_handle *socket);
int mos_socket_send(sdo_con_handle *socket, void *buf, size_t len, int flags);
int mos_socket_recv(sdo_con_handle *socket, void *buf, size_t len, int flags);
sdo_con_handle get_ssl_socket(void);

#define MBED_SOCKET_TIMEOUT 10000
#ifdef __cplusplus
} // endof externc (CPP code)
#endif
