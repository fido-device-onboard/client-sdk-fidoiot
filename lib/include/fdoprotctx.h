/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDOPROTCTX_H__
#define __FDOPROTCTX_H__

#include "fdoblockio.h"
#include "fdoprot.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
	int min_msg_id;
	int max_msg_id;
	int num_urls;
	fdourl_t url[1]; // fdourl_t[numURL]
} fdo_type_to_url_t;

// FDO protocol context
typedef struct fdo_prot_ctx_s {
	fdo_con_handle sock_hdl;
	bool tls;
	int msg_type;
	fdo_prot_t *protdata;
	bool (*protrun)(fdo_prot_t *ps);
	fdo_ip_address_t *host_ip;
	uint16_t host_port;
	const char *host_dns;
	fdo_ip_address_t *resolved_ip;
} fdo_prot_ctx_t;

fdo_prot_ctx_t *fdo_prot_ctx_alloc(bool (*protrun)(fdo_prot_t *ps),
				   fdo_prot_t *protdata,
				   fdo_ip_address_t *host_ip,
				   const char *host_dns, uint16_t host_port,
				   bool tls);

int fdo_prot_ctx_run(fdo_prot_ctx_t *prot_ctx);
void fdo_prot_ctx_free(fdo_prot_ctx_t *prot_ctx);

#endif /* __FDOPROTCTX_H__ */
