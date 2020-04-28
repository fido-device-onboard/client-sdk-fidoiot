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

void sdo_net_init(void);
bool is_rv_proxy_defined(void);
bool is_mfg_proxy_defined(void);
bool is_owner_proxy_defined(void);
bool setup_http_proxy(const char *filename, sdo_ip_address_t *sdoip,
		      uint16_t *port_num);

bool resolve_dn(const char *dn, sdo_ip_address_t **ip, uint16_t port,
		void **ssl, bool proxy);

bool connect_to_manufacturer(sdo_ip_address_t *ip, uint16_t port,
			     sdo_con_handle *sock_hdl, void **ssl);

bool connect_to_rendezvous(sdo_ip_address_t *ip, uint16_t port,
			   sdo_con_handle *sock_hdl, void **ssl);

bool connect_to_owner(sdo_ip_address_t *ip, uint16_t port,
		      sdo_con_handle *sock_hdl, void **ssl);

/* Try reconnecting to server if connection lost */
int sdo_connection_restablish(sdo_prot_ctx_t *prot_ctx);

#endif /*__SDONET_H__ */
