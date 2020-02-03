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

#include "sdotypes.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define HTTP_MAX_URL_SIZE 150
#define REST_MAX_MSGHDR_SIZE 512
#define REST_MAX_MSGBODY_SIZE 4096
#define HTTP_SUCCESS_OK 200
#define DEFAULT_DELAYSEC 120
#define IP_TAG_LEN 16   // e.g. 192.168.111.111
#define MAX_PORT_SIZE 6 // max port size is 65536 + 1null char

// REST context
typedef struct Rest_ctx_s {
	uint32_t protVer;
	uint32_t msgType;
	bool tls;
	size_t contentLength;
	bool keepAlive;
	char *authorization;
	char *xTokenAuthorization;
	SDOIPAddress_t *hostIP;
	uint16_t portno;
	char *hostDNS;
	bool isDNS;
} RestCtx_t;

bool cacheHostDns(const char *dns);
bool cacheHostIP(SDOIPAddress_t *ip);
bool cacheHostPort(uint16_t port);
bool cacheTLSConnection(void);
bool initRESTContext(void);
RestCtx_t *getRESTContext(void);
bool constructRESTHeader(RestCtx_t *rest, char *header, size_t headerLen);
char getRESTHdrBodySeparator(void);
bool getRESTContentLength(char *hdr, size_t hdrlen, uint32_t *contLen);
void exitRESTContext(void);

#endif // __REST_INTERFACE_H__
