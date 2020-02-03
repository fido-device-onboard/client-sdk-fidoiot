/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDOPROTCTX_H__
#define __SDOPROTCTX_H__

#include "sdoblockio.h"
#include "sdoprot.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
	int minMsgID;
	int maxMsgID;
	int numURLs;
	sdourl_t url[1]; // sdourl_t[numURL]
} SDOTypeToURL_t;

// SDO protocol context
typedef struct SDOProt_Ctx_s {
	int sock;
	void *ssl;
	bool tls;
	int msgType;
	SDOProt_t *protdata;
	bool (*protrun)();
	SDOIPAddress_t *host_ip;
	uint16_t host_port;
	char *host_dns;
	SDOIPAddress_t *resolved_ip;
} SDOProtCtx_t;

SDOProtCtx_t *sdoProtCtxAlloc(bool (*protrun)(), SDOProt_t *protdata,
			      SDOIPAddress_t *host_ip, char *host_dns,
			      uint16_t host_port, bool tls);

int sdoProtCtxRun(SDOProtCtx_t *prot_ctx);
void sdoProtCtxFree(SDOProtCtx_t *prot_ctx);

#endif /* __SDOPROTCTX_H__ */
