/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDONET_H__
#define __FDONET_H__

#include "fdoprotctx.h"

#define MANUFACTURER_CONNECT_RETRIES 2
#define RENDEZVOUS_CONNECT_RETRIES 2
#define OWNER_CONNECT_RETRIES 2
#define RETRY_DELAY 1

void fdo_net_init(void);
bool is_rv_proxy_defined(void);
bool is_mfg_proxy_defined(void);
bool is_owner_proxy_defined(void);
bool setup_http_proxy(const char *filename, fdo_ip_address_t *fdoip,
		      uint16_t *port_num);

bool resolve_dn(const char *dn, fdo_ip_address_t **ip, uint16_t port,
		bool tls, bool proxy);

bool connect_to_manufacturer(fdo_ip_address_t *ip, uint16_t port,
			     fdo_con_handle *sock_hdl, bool tls);

bool connect_to_rendezvous(fdo_ip_address_t *ip, uint16_t port,
			   fdo_con_handle *sock_hdl, bool tls);

bool connect_to_owner(fdo_ip_address_t *ip, uint16_t port,
		      fdo_con_handle *sock_hdl, bool tls);

/* Try reconnecting to server if connection lost */
int fdo_connection_restablish(fdo_prot_ctx_t *prot_ctx);

#endif /*__FDONET_H__ */
