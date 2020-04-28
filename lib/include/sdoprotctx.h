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
	int min_msg_id;
	int max_msg_id;
	int num_urls;
	sdourl_t url[1]; // sdourl_t[numURL]
} sdo_type_to_url_t;

// SDO protocol context
typedef struct sdo_prot_ctx_s {
	sdo_con_handle sock_hdl;
	void *ssl;
	bool tls;
	int msg_type;
	sdo_prot_t *protdata;
	bool (*protrun)(sdo_prot_t *ps);
	sdo_ip_address_t *host_ip;
	uint16_t host_port;
	const char *host_dns;
	sdo_ip_address_t *resolved_ip;
} sdo_prot_ctx_t;

sdo_prot_ctx_t *sdo_prot_ctx_alloc(bool (*protrun)(sdo_prot_t *ps),
				   sdo_prot_t *protdata,
				   sdo_ip_address_t *host_ip,
				   const char *host_dns, uint16_t host_port,
				   bool tls);

int sdo_prot_ctx_run(sdo_prot_ctx_t *prot_ctx);
void sdo_prot_ctx_free(sdo_prot_ctx_t *prot_ctx);

#endif /* __SDOPROTCTX_H__ */
