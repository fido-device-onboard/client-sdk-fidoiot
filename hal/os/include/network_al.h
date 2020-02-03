/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Abstraction Layer
 *
 * This file is a header implementation of network abstraction layer for Linux
 * OS and ESP32.
 *
 */
#ifndef __NETWORK_AL_H__
#define __NETWORK_AL_H__

#include "sdotypes.h"
#include "sdoprotctx.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#define IPV4_ADDR_LEN 4

#if defined(TARGET_OS_OPTEE)
typedef void *sdoConHandle;
#define SDO_CON_INVALID_HANDLE NULL

#elif defined(TARGET_OS_MBEDOS)
#include "mbed_net_al.h"

#else
typedef int32_t sdoConHandle;
#define SDO_CON_INVALID_HANDLE -1
#endif

/*
 * Network Connection Setup.
 *
 * @param[in] medium: specified network medium to connect to.
 * @param[in] params: parameters(if any) supported for 'medium'.
 * @param[in] count: number of valid string in params
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConSetup(char *medium, char **params, uint32_t count);

/*
 * Perform a DNS look for a specified host.
 *
 * @param[in] url: host's URL.
 * @param[out] ipList: IP address list for specified host URL.
 * @param[out] ipListSize: number of IP address in ipList
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConDnsLookup(const char *url, SDOIPAddress_t **ipList,
			uint32_t *ipListSize);

/*
 * Open a connection specified by IP address and port.
 *
 * @param[in] addr: IP Address to connect to.
 * @param[in] port: port number to connect to.
 * @param[in] ssl: SSL handler in case of tls connection.
 * @retval -1 on failure, connection handle on success.
 */
sdoConHandle sdoConConnect(SDOIPAddress_t *addr, uint16_t port, void **ssl);

/*
 * Disconnect the connection.
 *
 * @param[in] handle: connection handler (for ex: socket-id)
 * @param[in] ssl: SSL handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConDisconnect(sdoConHandle handle, void *ssl);

/*
 * Receive(read) length of incoming sdo packet.
 *
 * @param[in] handle: connection handler (for ex: socket-id)
 * @param[out] protocolVersion: SDO protocol version
 * @param[out] messageType: message type of incoming SDO message.
 * @param[out] msglen: length of incoming message.
 * @param[in] ssl handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConRecvMsgHeader(sdoConHandle handle, uint32_t *protocolVersion,
			    uint32_t *messageType, uint32_t *msglen, void *ssl);

/*
 * Receive(read) incoming sdo packet.
 *
 * @param[in] handle: connection handler (for ex: socket-id)
 * @param[out] buf: data buffer to read into.
 * @param[in] length: Number of received bytes to be read.
 * @param[in] ssl handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConRecvMsgBody(sdoConHandle handle, uint8_t *buf, size_t length,
			  void *ssl);

/*
 * Send(write) data.
 *
 * @param[in] handle: connection handler (for ex: socket-id)
 * @param[in] protocolVersion: SDO protocol version
 * @param[in] messageType: message type of outgoing SDO message.
 * @param[in] buf: data buffer to write from.
 * @param[in] length: Number of sent bytes.
 * @param[in] ssl handler in case of tls connection.
 * @retval -1 on failure, 0 on success.
 */
int32_t sdoConSendMessage(sdoConHandle handle, uint32_t protocolVersion,
			  uint32_t messageType, const uint8_t *buf,
			  size_t length, void *ssl);

/*
 * Network Connection tear down.
 * This API is counter to sdoConSetup().
 *
 */
int32_t sdoConTeardown(void);

/* put SDO device in Low power mode */
// FIXME: we might have to find a suitable place for this API
void sdoSleep(int sec);

/* Convert from Network to Host byte order */
uint32_t sdoNetToHostLong(uint32_t value);

/* Convert from Host to Network byte order */
uint32_t sdoHostToNetLong(uint32_t value);

/* Convert from ASCII to Network byte order format */
int32_t sdoPrintableToNet(const char *src, void *addr);

/* get device model number */
const char *get_device_model(void);

/* get device serial number */
const char *get_device_serial_number(void);

/* generate random number */
int sdoRandom(void);

#endif /* __NETWORK_AL_H__ */
