/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * REST Layer
 *
 * This file is a header implementation of REST layer, which sits behind NETWORK
 * HAL.
 *
 */

#ifndef __REST_INTERFACE_H__
#define __REST_INTERFACE_H__

#include "fdotypes.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <curl/curl.h>

#define HTTP_MAX_URL_SIZE 150
#define REST_MAX_MSGHDR_SIZE 1024
// maximum supported length is 8192 + 700. Rounding it to 9000
#define REST_MAX_MSGBODY_SIZE 9000
#define HTTP_SUCCESS_OK 200
#define IP_TAG_LEN 16   // e.g. 192.168.111.111
#define MAX_PORT_SIZE 6 // max port size is 65536 + 1null char

#define ISASCII(ch) ((ch & ~0x7f) == 0)

// REST context
typedef struct Rest_ctx_s {
	uint32_t prot_ver;
	uint32_t msg_type;
	bool tls;
	size_t content_length;
	bool keep_alive;
	char *authorization;
	char *x_token_authorization;
	fdo_ip_address_t *host_ip;
	uint16_t portno;
	char *host_dns;
	bool is_dns;
} rest_ctx_t;

extern CURL *curl;

bool cache_host_dns(const char *dns);
bool cache_host_ip(fdo_ip_address_t *ip);
bool cache_host_port(uint16_t port);
bool cache_tls_connection(void);
bool init_rest_context(void);
rest_ctx_t *get_rest_context(void);
bool construct_rest_header(rest_ctx_t *rest, char *header, size_t header_len);
char get_rest_hdr_body_separator(void);
bool get_rest_content_length(char *hdr, size_t hdrlen, uint32_t *cont_len);
void exit_rest_context(void);
bool ip_bin_to_ascii(fdo_ip_address_t *ip, char *ip_ascii);
#endif // __REST_INTERFACE_H__
