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

#include "fdotypes.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#define IPV4_ADDR_LEN 4
#define MAX_TIME_OUT 60000L

#ifndef TARGET_OS_MBEDOS
#define FDO_CON_INVALID_HANDLE NULL
#endif

#if defined(TARGET_OS_MBEDOS)
#include "mbed_net_al.h"
#endif

/*
 * Network Connection Setup.
 *
 * @param[in] medium: specified network medium to connect to.
 * @param[in] params: parameters(if any) supported for 'medium'.
 * @param[in] count: number of valid string in params
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_setup(char *medium, char **params, uint32_t count);

/*
 * Perform a DNS look for a specified host.
 *
 * @param[in] url: host's URL.
 * @param[out] ip_list: IP address list for specified host URL.
 * @param[out] ip_list_size: number of IP address in ip_list
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_dns_lookup(const char *url, fdo_ip_address_t **ip_list,
			   uint32_t *ip_list_size);

/*
 * Open a connection specified by IP address and port.
 *
 * @param[in] addr: IP Address to connect to.
 * @param dn: Domain name of the server
 * @param[in] port: port number to connect to.
 * @param[in] tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @retval -1 on failure, connection handle on success.
 */
int32_t fdo_con_connect(fdo_ip_address_t *addr, const char *dn, uint16_t port,
			bool tls);

/*
 * Disconnect the connection.
 *
 * @param[in] tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_disconnect(void);

/*
 * Check the REST header for given REST response buffer and offset.
 *
 * @param[in] curl_buf: Input buffer that contains the REST header
 * @param[in] header_start_offset: offset in the buffer that points to the start
 * of REST header
 * @retval true if header is valid and complete and false otherwise.
 */
bool has_header(char *buf, size_t header_start_offset);

/*
 * Get the message length from the given REST response buffer.
 *
 * @param[in] curl_buf: Input buffer that contains the REST header
 * @param[in/out] cur_offset: offset in the buffer that initially points to the
 * start of REST header. This gets updated to point to start of message body
 * after successful parsing
 * @param[out] msglen:  Message length as specified in the REST header
 * @retval bool returns true for success and false in case of invalid/incomplete
 * content/parsing failure.
 */
bool get_msg_length(char *curl_buf, size_t *cur_offset, uint32_t *msglen);

/*
 * Receive(read) length of incoming FDO packet.
 *
 * @param[out] protocol_version: FDO protocol version
 * @param[out] message_type: message type of incoming FDO message.
 * @param[out] msglen: length of incoming message.
 * @param[in] hdr_buf: data buffer to parse msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_parse_msg_header(uint32_t *protocol_version,
				 uint32_t *message_type, uint32_t *msglen,
				 char *hdr_buf);

/*
 * Receive(read) incoming FDO packet.
 *
 * @param[out] buf: data buffer to read into.
 * @param[in] length: Number of received bytes to be read.
 * @param[in] body_buf: data buffer to parse msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_parse_msg_body(uint8_t *buf, size_t length, char *body_buf);

/*
 * Send(write) data.
 *
 * @param[in] protocol_version: FDO protocol version
 * @param[in] message_type: message type of outgoing FDO message.
 * @param[in] buf: data buffer to write from.
 * @param[in] length: Number of sent bytes.
 * @param[in] tls: flag describing whether HTTP (false) or HTTPS (true) is
 * @param[in] header_buf: header data buffer to read into  msg received by curl.
 * @param[in] body_buf: body data buffer to read into  msg received by curl.
 * @retval -1 on failure, 0 on success.
 */
int32_t fdo_con_send_recv_message(uint32_t protocol_version,
				  uint32_t message_type, const uint8_t *buf,
				  size_t length, bool tls, char *header_buf,
				  char *body_buf);

/*
 * Network Connection tear down.
 * This API is counter to fdo_con_setup().
 *
 */
int32_t fdo_con_teardown(void);

/* put FDO device in Low power mode */
// FIXME: we might have to find a suitable place for this API
void fdo_sleep(int sec);

/* Convert from Network to Host byte order */
uint32_t fdo_net_to_host_long(uint32_t value);

/* Convert from Host to Network byte order */
uint32_t fdo_host_to_net_long(uint32_t value);

/* Convert from ASCII to Network byte order format */
int32_t fdo_printable_to_net(const char *src, void *addr);

/* get device model number */
const char *get_device_model(void);

/* get device serial number */
const char *get_device_serial_number(void);

/* generate random number */
int fdo_random(void);

/**
 * fdo_curl_connect connects to the given ip_addr via curl API
 *
 * @param ip_addr[in] - pointer to IP address info
 * @param dn: Domain name of the server
 * @param port[in] - port number to connect
 * @return 0 on success. -1 on failure
 */
int32_t fdo_curl_connect(fdo_ip_address_t *ip_addr, const char *dn,
			 uint16_t port, bool tls);

/**
 * fdo_curl_proxy set up the proxy connection via curl API
 *
 * @param ip_addr[in] - pointer to IP address of proxy
 * @param port[in] - proxy port number to connect
 * @return true on success. false value on failure
 */
bool fdo_curl_proxy(fdo_ip_address_t *ip_addr, uint16_t port);

#endif /* __NETWORK_AL_H__ */
