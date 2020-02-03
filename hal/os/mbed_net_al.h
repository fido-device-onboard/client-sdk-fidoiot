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
class sdoConHandle : public TCPSocket
{
};
#else
#include "mbedtls/ssl.h"
#include "sdoCryptoHal.h"
typedef void *sdoConHandle;
#define SDO_CON_INVALID_HANDLE NULL
#endif

int mos_resolvedns(char *dn, char *ip);
sdoConHandle *mos_socketConnect(SDOIPAddress_t *ip, uint16_t port);
sdoConHandle *mos_socketOpen(void);
int mos_socketConOnly(sdoConHandle *socket, SDOIPAddress_t *ip, uint16_t port);
void mos_socketClose(sdoConHandle *socket);
int mos_socketSend(sdoConHandle *socket, void *buf, size_t len, int flags);
int mos_socketRecv(sdoConHandle *socket, void *buf, size_t len, int flags);
sdoConHandle get_ssl_socket(void);

#define MBED_SOCKET_TIMEOUT 10000
#ifdef __cplusplus
} // endof externc (CPP code)
#endif
