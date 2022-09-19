/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of FDO Protocols (DI/TO1/TO2) contexts.
 *
 * This includes:
 *      1. Allocation of protocol contexts.
 *      2. Send/Receive protocol messages to/from MFG/RV/OWNER server.
 *      3. De-allocation of protocol contexts on completion.
 */

#include "util.h"
#include "fdoprot.h"
#include "network_al.h"
#include "fdoprotctx.h"
#include "fdonet.h"
#include <stdlib.h>
#include "load_credentials.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "rest_interface.h"

#define CONNECTION_RETRY 2

/**
 * fdo_prot_ctx_alloc responsible for allocation of required protocol context.
 * @param protrun - pointer to function for intended protocol (DI/TO1/TO2).
 * @param protdata - pointer of type fdo_prot_t, hold protocol related data.
 * @param host_ip, - Pointer to intended HOST's IP address.
 * @param host_dns - Pointer to intended HOST's DNS.
 * @param host_port - port no of intended HOST.
 * @param tls - boolean denoting if transport level security is applicable.
 * @return pointer to required protocol context on success, NULL if any error
 * occured.
 */
fdo_prot_ctx_t *fdo_prot_ctx_alloc(bool (*protrun)(fdo_prot_t *ps),
				   fdo_prot_t *protdata,
				   fdo_ip_address_t *host_ip,
				   const char *host_dns, uint16_t host_port,
				   bool tls)
{
	if (NULL == host_ip && NULL == host_dns) {
		LOG(LOG_ERROR, "IP and DNS, both are found NULL!!\n please set "
			       "Server's IP/DNS and then proceed.\n");
		return NULL;
	}

	fdo_prot_ctx_t *prot_ctx = fdo_alloc(sizeof(fdo_prot_ctx_t));

	if (prot_ctx == NULL) {
		return NULL;
	}

	// copy the IP, instead of using it directly, since the IP might be
	// coming in from DeviceCredentials that gets cleared at msg/70
	if (host_ip) {
		prot_ctx->host_ip = fdo_ipaddress_alloc();
		if (!prot_ctx->host_ip) {
			LOG(LOG_ERROR, "Failed to alloc host IP\n");
			goto err;
		}
		prot_ctx->host_ip->length = host_ip->length;
		if (0 != memcpy_s(prot_ctx->host_ip->addr, sizeof(host_ip->addr),
			host_ip->addr, sizeof(host_ip->addr))) {
			LOG(LOG_ERROR, "Failed to copy host IP\n");
			goto err;
		}
	}

	// use the DNS directly, since the DNS is resolved and cached,
	// and the resolved IP is used directly
	if (host_dns) {
		prot_ctx->host_dns = host_dns;
	}

	prot_ctx->protdata = protdata;
	prot_ctx->protrun = protrun;

	prot_ctx->host_port = host_port;
	prot_ctx->tls = tls;
	return prot_ctx;
err:
	if (prot_ctx->host_ip) {
		fdo_free(prot_ctx->host_ip);
	}
	return NULL;
}

/**
 * Internal API
 */
void fdo_prot_ctx_free(fdo_prot_ctx_t *prot_ctx)
{
	if (prot_ctx) {
		if (prot_ctx->resolved_ip) {
			fdo_free(prot_ctx->resolved_ip);
		}
		if (prot_ctx->host_ip) {
			fdo_free(prot_ctx->host_ip);
		}
	}
}

/**
 * Internal API
 */
static bool fdo_prot_ctx_connect(fdo_prot_ctx_t *prot_ctx)
{
	bool ret = false;
	static int prevstate;

	if (prot_ctx->protdata->state == FDO_STATE_ERROR) {
		prot_ctx->protdata->state = prevstate;
	}

	switch (prot_ctx->protdata->state) {
	case FDO_STATE_DI_APP_START: /* type 10 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_DI_SET_CREDENTIALS: /* type 11 */
		if (prot_ctx->host_dns) {
			if (prot_ctx->resolved_ip) {
				fdo_free(prot_ctx->resolved_ip);
			}
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port,
					prot_ctx->tls,
					is_mfg_proxy_defined())) {
				ret = false;
				break;
			}
		}
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_DI_SET_HMAC: /* type 12 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_DI_DONE: /* type 13 */
		ret = connect_to_manufacturer(
			      prot_ctx->resolved_ip ? prot_ctx->resolved_ip : prot_ctx->host_ip,
			      prot_ctx->host_port,
			      &prot_ctx->sock_hdl,
			      prot_ctx->tls);
		break;
	case FDO_STATE_T01_SND_HELLO_FDO: /* type 30 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO1_RCV_HELLO_FDOACK: /* type 31 */
		if (prot_ctx->host_dns) {
			if (prot_ctx->resolved_ip) {
				fdo_free(prot_ctx->resolved_ip);
			}
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port,
					prot_ctx->tls,
					is_rv_proxy_defined())) {
				ret = false;
				fdo_free(prot_ctx->resolved_ip);
			}
		}
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO1_SND_PROVE_TO_FDO: /* type 32 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO1_RCV_FDO_REDIRECT: /* type 33 */
		// try DNS's resolved IP first, if it fails, try given IP address
		ret = connect_to_rendezvous(
		    prot_ctx->resolved_ip, prot_ctx->host_port, &prot_ctx->sock_hdl,
		    prot_ctx->tls);
		if (!ret) {
			ret = connect_to_rendezvous(
				prot_ctx->host_ip, prot_ctx->host_port, &prot_ctx->sock_hdl,
				prot_ctx->tls);
		}
		break;
	case FDO_STATE_T02_SND_HELLO_DEVICE: /* type 60 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_RCV_PROVE_OVHDR: /* type 61 */
		if (prot_ctx->host_dns) {
			if (prot_ctx->resolved_ip) {
				fdo_free(prot_ctx->resolved_ip);
			}
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port,
					prot_ctx->tls,
					is_owner_proxy_defined())) {
				ret = false;
				fdo_free(prot_ctx->resolved_ip);
			}
		}
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY: /* type 62 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_T02_RCV_OP_NEXT_ENTRY: /* type 63 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_SND_PROVE_DEVICE: /* type 64 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO: /* type 65 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO: /* type 66 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_RCV_SETUP_DEVICE: /* type 67 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO: /* type 68 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO: /* type 69 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_SND_DONE: /* type 70 */
		ATTRIBUTE_FALLTHROUGH;
	case FDO_STATE_TO2_RCV_DONE_2: /* type 71 */
		// try DNS's resolved IP first, if it fails, try given IP address
		ret = connect_to_owner(prot_ctx->resolved_ip, prot_ctx->host_port,
				       &prot_ctx->sock_hdl, prot_ctx->tls);
		if (!ret) {
			ret = connect_to_owner(prot_ctx->host_ip, prot_ctx->host_port,
				       &prot_ctx->sock_hdl, prot_ctx->tls);
		}
		break;
	default:
		LOG(LOG_ERROR, "%s reached unknown state\n", __func__);
		break;
	}
	prevstate = prot_ctx->protdata->state;
	return ret;
}

/**
 * fdo_prot_ctx_run responsible for running/maintaining DI, T01, T02 protocol
 * contexts and respond according to the state specified.
 * Managing the JSON packet to/from device to server is taken care.
 * Managing the ip/dns-to-ip resolution is taken care.
 * @param prot_ctx - Pointer of type fdo_prot_ctx_t, holds the all the
 * information,
 * @return 0 on success, -1 on error.
 */

int fdo_prot_ctx_run(fdo_prot_ctx_t *prot_ctx)
{
	int ret = 0;
	int n, size;
	int retries = 0;
	fdor_t *fdor = NULL;
	fdow_t *fdow = NULL;

	if (!prot_ctx || !prot_ctx->protdata) {
		return -1;
	}
	fdor = &prot_ctx->protdata->fdor;
	fdow = &prot_ctx->protdata->fdow;

	// init connection set-up for send/receive packets
	if (fdo_con_setup(NULL, NULL, 0)) {
		LOG(LOG_ERROR, "Connection setup failed!\n");
		return -1;
	}

	for (;;) {

		// initialize the encoder before every write operation
		if (!fdow_encoder_init(fdow)) {
			LOG(LOG_ERROR, "Failed to initilize FDOW encoder\n");
			return -1;
		}

		if (prot_ctx->protrun) {
			(*prot_ctx->protrun)(prot_ctx->protdata);
		} else {
			ret = -1;
			break;
		}

		/* ========================================================== */
		/*  Transmit outbound packet */


		/*  Protocol sets State as FDO_STATE_DONE at the end of the*/
		/*  protocol(DI/T01/TO2) */
		/*  Hence, when state = FDO_STATE_DONE, we have nothing more*/
		/*  left to */
		/*  send. Exit!! */
		if (prot_ctx->protdata->state == FDO_STATE_DONE) {
			ret = 0;
			break;
		}

		if ((fdow->msg_type < FDO_DI_APP_START) ||
		    (fdow->msg_type > FDO_TYPE_ERROR)) {
			ret = -1;
			break;
		}

		// update the final encoded length in the FDOW block after every successfull write.
		if (!fdow_encoded_length(fdow, &fdow->b.block_size)) {
			LOG(LOG_ERROR, "Failed to get encoded length in FDOW\n");
			ret = -1;
			break;
		}
		LOG(LOG_DEBUG, "%s Tx Request Body length: %zu\n", __func__, fdow->b.block_size);
		LOG(LOG_DEBUG, "%s Tx Request Body:\n", __func__);
		fdo_log_block(&fdow->b);

		if (!fdo_prot_ctx_connect(prot_ctx)) {
			/* Giving up, we tried enough to
			 * re-establish
			 */
			ret = -1;
			break;
		}

		size = fdow->b.block_size;

		fdow->b.block[size] = 0;
		retries = CONNECTION_RETRY;
		do {
			n = fdo_con_send_message(
			    prot_ctx->sock_hdl, FDO_PROT_SPEC_VERSION,
			    fdow->msg_type, &fdow->b.block[0], size,
			    prot_ctx->tls);

			if (n <= 0) {
				if (fdo_con_disconnect(prot_ctx->sock_hdl)) {
					LOG(LOG_ERROR,
					    "Error during socket close()\n");
					ret = -1;
					break;
				}

				if (fdo_connection_restablish(prot_ctx)) {
					/* Giving up, we tried enough to
					 * re-establish
					 */
					ret = -1;
					break;
				}
			}
		} while (n < 0 && retries--);

		if (n < 0) {
			ret = -1;
			break;
		}

		// clear the block contents in preparation for the next FDOW write operation
		fdo_block_reset(&fdow->b);
		fdow->b.block_size = prot_ctx->protdata->prot_buff_sz;

		/* ========================================================== */
		/*  Receive response */

		uint32_t msglen = 0;
		uint32_t protver = 0;
		char curl_buf[REST_MAX_MSGBODY_SIZE];
		size_t curl_buf_offset = 0;

		if (memset_s(curl_buf, REST_MAX_MSGBODY_SIZE, 0) != 0) {
				LOG(LOG_ERROR, "Memset() failed!\n");
				return false;
			}

		ret = fdo_con_recv_msg_header(prot_ctx->sock_hdl, &protver,
					      (uint32_t *)&fdor->msg_type,
					      &msglen, curl_buf, &curl_buf_offset);
		if (ret == -1) {
			LOG(LOG_ERROR, "fdo_con_recv_msg_header() Failed!\n");
			ret = -1;
			break;
		}

		// clear the block contents in preparation for the next FDOR read operation
		fdo_block_reset(&fdor->b);
		// set the received msg length in the block
		fdor->b.block_size = msglen;

		if (msglen > 0 && msglen <= prot_ctx->protdata->prot_buff_sz) {
			retries = CONNECTION_RETRY;
			n = 0;
			do {
				n = fdo_con_recv_msg_body(&fdor->b.block[0], msglen,
				    curl_buf, curl_buf_offset);
				if (n < 0) {
					if (fdo_con_disconnect(
						prot_ctx->sock_hdl)) {
						LOG(LOG_ERROR, "Error during "
							       "socket "
							       "close()\n");
						ret = -1;
						break;
					}

					if (fdo_connection_restablish(
						prot_ctx)) {
						/* Giving up, we tried enough to
						 * re-establish
						 */
						ret = -1;
						break;
					}
				}
			} while (n < 0 && retries--);

			if (n <= 0) {
				LOG(LOG_ERROR, "Socket read not successful "
					       "after retries!\n");
				fdo_block_reset(&fdor->b);
				ret = -1;
				break;
			}
		}

		if (fdo_con_disconnect(prot_ctx->sock_hdl)) {
			LOG(LOG_ERROR, "Error during socket close()\n");
			ret = -1;
			break;
		}

		if (msglen > prot_ctx->protdata->prot_buff_sz) {
			LOG(LOG_ERROR, "Response body size is more than allocated memory\n");
			ret = -1;
			break;
		}

		LOG(LOG_DEBUG, "%s Rx Response Body: \n", __func__);
		fdo_log_block(&fdor->b);

		/*
		 * When a REST error message(type 255) is sent over network,
		 * the received response may have an empty body.
		 */
		if (msglen == 0 && fdow->msg_type == FDO_TYPE_ERROR) {
			ret = -1;
			break;
		}
		 /* ERROR case ? */
		if (fdor->msg_type == FDO_TYPE_ERROR) {
			ret = -1;
			break;
		}

		/*
		 * Now that we have the received buffer, initialize the parser for next FDOR read
		 * operation and set the have_block flag.
		 */
		if (!fdor_parser_init(fdor)) {
			LOG(LOG_ERROR, "Failed to initilize FDOR parser\n");
			ret = -1;
			break;
		}
		if (!fdor_is_valid_cbor(fdor)) {
			LOG(LOG_ERROR, "Received an invalid CBOR stream\n");
			fdo_block_reset(&fdor->b);
			ret = -1;
			break;
		}
		fdor->have_block = true;
	}

	fdo_con_teardown();
	return ret;
}
