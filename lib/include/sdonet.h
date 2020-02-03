/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __SDONET_H__
#define __SDONET_H__

#include "sdoprotctx.h"

#define MANUFACTURER_CONNECT_RETRIES 2
#define RENDEZVOUS_CONNECT_RETRIES 2
#define OWNER_CONNECT_RETRIES 2
#define RETRY_DELAY 1

void sdoNetInit(void);
bool is_rv_proxy_defined(void);
bool is_mfg_proxy_defined(void);
bool is_owner_proxy_defined(void);
bool setup_http_proxy(const char *filename, SDOIPAddress_t *sdoip,
		      uint16_t *port_num);

bool ResolveDn(const char *dn, SDOIPAddress_t **ip, uint16_t port, void **ssl,
	       bool proxy);

bool ConnectToManufacturer(SDOIPAddress_t *ip, uint16_t port, int *sock,
			   void **ssl);

bool ConnectToRendezvous(SDOIPAddress_t *ip, uint16_t port, int *sock,
			 void **ssl);

bool ConnectToOwner(SDOIPAddress_t *ip, uint16_t port, int *sock, void **ssl);

/* Try reconnecting to server if connection lost */
int sdoConnectionRestablish(SDOProtCtx_t *prot_ctx);

#endif /*__SDONET_H__ */
