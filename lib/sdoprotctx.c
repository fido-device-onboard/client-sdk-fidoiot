/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of SDO Protocols (DI/TO1/TO2) contexts.
 *
 * This includes:
 *      1. Allocation of protocol contexts.
 *      2. Send/Receive protocol messages to/from MFG/RV/OWNER server.
 *      3. De-allocation of protocol contexts on completion.
 */

#include "util.h"
#include "sdoprot.h"
#include "network_al.h"
#include "sdoprotctx.h"
#include "sdonet.h"
#include <stdlib.h>
#include "load_credentials.h"
#include "safe_lib.h"
#include "snprintf_s.h"

#define CONNECTION_RETRY 2

/**
 * sdo_prot_ctx_alloc responsible for allocation of required protocol context.
 * @param protrun - pointer to function for intended protocol (DI/TO1/TO2).
 * @param protdata - pointer of type sdo_prot_t, hold protocol related data.
 * @param host_ip, - Pointer to intended HOST's IP address (null if DNS is
 * present).
 * @param host_dns - Pointer to intended HOST's DNS (null if IP is present).
 * @param host_port - port no of intended HOST.
 * @param tls - boolean denoting if transport level security is applicable.
 * @return pointer to required protocol context on success, NULL if any error
 * occured.
 */
sdo_prot_ctx_t *sdo_prot_ctx_alloc(bool (*protrun)(sdo_prot_t *ps),
				   sdo_prot_t *protdata,
				   sdo_ip_address_t *host_ip,
				   const char *host_dns, uint16_t host_port,
				   bool tls)
{
	if (NULL == host_ip && NULL == host_dns) {
		LOG(LOG_ERROR, "IP and DNS, both are found NULL!!\n please set "
			       "Server's IP/DNS and then proceed.\n");
		return NULL;
	}

	sdo_prot_ctx_t *prot_ctx = sdo_alloc(sizeof(sdo_prot_ctx_t));

	if (prot_ctx == NULL)
		return NULL;

	if (host_ip)
		prot_ctx->host_ip = host_ip;
	if (host_dns)
		prot_ctx->host_dns = host_dns;

	prot_ctx->protdata = protdata;
	prot_ctx->protrun = protrun;

	prot_ctx->host_port = host_port;
	prot_ctx->tls = tls;
	return prot_ctx;
}

/**
 * Internal API
 */
void sdo_prot_ctx_free(sdo_prot_ctx_t *prot_ctx)
{
	if (prot_ctx) {
		if (prot_ctx->host_dns)
			sdo_free(prot_ctx->resolved_ip);
		sdo_free(prot_ctx);
	}
}

/**
 * Internal API
 */
static bool sdo_prot_ctx_connect(sdo_prot_ctx_t *prot_ctx)
{
	bool ret = false;
	static int prevstate;

	if (prot_ctx->protdata->state == SDO_STATE_ERROR)
		prot_ctx->protdata->state = prevstate;

	switch (prot_ctx->protdata->state) {
	case SDO_STATE_DI_APP_START: /* type 10 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_DI_SET_CREDENTIALS: /* type 11 */
		if (prot_ctx->host_dns) {
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port, NULL,
					is_mfg_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_DI_SET_HMAC: /* type 12 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_DI_DONE: /* type 13 */
		ret = connect_to_manufacturer(prot_ctx->host_ip,
					      prot_ctx->host_port,
					      &prot_ctx->sock_hdl, NULL);
		break;
	case SDO_STATE_T01_SND_HELLO_SDO: /* type 30 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO1_RCV_HELLO_SDOACK: /* type 31 */
		if (prot_ctx->host_dns) {
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port,
					(prot_ctx->tls ? &prot_ctx->ssl : NULL),
					is_rv_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO1_SND_PROVE_TO_SDO: /* type 32 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO1_RCV_SDO_REDIRECT: /* type 33 */
		ret = connect_to_rendezvous(
		    prot_ctx->host_ip, prot_ctx->host_port, &prot_ctx->sock_hdl,
		    (prot_ctx->tls ? &prot_ctx->ssl : NULL));
		break;
	case SDO_STATE_T02_SND_HELLO_DEVICE: /* type 40 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_RCV_PROVE_OVHDR: /* type 41 */
		if (prot_ctx->host_dns) {
			if (!resolve_dn(prot_ctx->host_dns,
					&prot_ctx->resolved_ip,
					prot_ctx->host_port, NULL,
					is_owner_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY: /* type 42 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_T02_RCV_OP_NEXT_ENTRY: /* type 43 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_SND_PROVE_DEVICE: /* type 44 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO: /* type 45 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO: /* type 46 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_RCV_SETUP_DEVICE: /* type 47 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO: /* type 48 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO: /* type 49 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_SND_DONE: /* type 50 */
		ATTRIBUTE_FALLTHROUGH;
	case SDO_STATE_TO2_RCV_DONE_2: /* type 51 */
		ret = connect_to_owner(prot_ctx->host_ip, prot_ctx->host_port,
				       &prot_ctx->sock_hdl, NULL);
		break;
	default:
		LOG(LOG_ERROR, "%s reached unknown state\n", __func__);
		break;
	}
	prevstate = prot_ctx->protdata->state;
	return ret;
}

/**
 * sdo_prot_ctx_run responsible for running/maintaining DI, T01, T02 protocol
 * contexts and respond according to the state specified.
 * Managing the JSON packet to/from device to server is taken care.
 * Managing the ip/dns-to-ip resolution is taken care.
 * @param prot_ctx - Pointer of type sdo_prot_ctx_t, holds the all the
 * information,
 * @return 0 on success, -1 on error.
 */

int sdo_prot_ctx_run(sdo_prot_ctx_t *prot_ctx)
{
	int ret = 0;
	int n, size;
	int retries = 0;
	sdor_t *sdor = NULL;
	sdow_t *sdow = NULL;

	if (!prot_ctx || !prot_ctx->protdata)
		return -1;
	sdor = &prot_ctx->protdata->sdor;
	sdow = &prot_ctx->protdata->sdow;

	// init connection set-up for send/receive packets
	if (sdo_con_setup(NULL, NULL, 0)) {
		LOG(LOG_ERROR, "Connection setup failed!\n");
		return -1;
	}

	for (;;) {

		// initialize the encoder before every write operation
		if (!sdow_encoder_init(sdow)) {
			LOG(LOG_ERROR, "Failed to initilize SDOW encoder\n");
			return -1;
		}

		if (prot_ctx->protrun)
			(*prot_ctx->protrun)(prot_ctx->protdata);
		else {
			ret = -1;
			break;
		}
		
		/* ========================================================== */
		/*  Transmit outbound packet */


		/*  Protocol sets State as SDO_STATE_DONE at the end of the*/
		/*  protocol(DI/T01/TO2) */
		/*  Hence, when state = SDO_STATE_DONE, we have nothing more*/
		/*  left to */
		/*  send. Exit!! */
		if (prot_ctx->protdata->state == SDO_STATE_DONE) {
			ret = 0;
			break;
		}

		if ((sdow->msg_type < SDO_DI_APP_START) ||
		    (sdow->msg_type > SDO_TYPE_ERROR)) {
			ret = -1;
			break;
		}

		// update the final encoded length in the SDOW block after every successfull write.
		if (!sdow_encoded_length(sdow, &sdow->b.block_size)) {
			LOG(LOG_ERROR, "Failed to get encoded length in SDOW\n");
			ret = -1;
			break;
		}
		LOG(LOG_DEBUG, "%s Tx Request Body length: %zu\n", __func__, sdow->b.block_size);
		LOG(LOG_DEBUG, "%s Tx Request Body:\n", __func__);
		sdo_log_block(&sdow->b);

		if (!sdo_prot_ctx_connect(prot_ctx)) {
			/* Giving up, we tried enough to
			 * re-establish
			 */
			ret = -1;
			break;
		}

		size = sdow->b.block_size;

		sdow->b.block[size] = 0;
		retries = CONNECTION_RETRY;
		do {
			n = sdo_con_send_message(
			    prot_ctx->sock_hdl, SDO_PROT_SPEC_VERSION,
			    sdow->msg_type, &sdow->b.block[0], size,
			    prot_ctx->ssl);

			if (n <= 0) {
				if (sdo_con_disconnect(prot_ctx->sock_hdl,
						       prot_ctx->ssl)) {
					LOG(LOG_ERROR,
					    "Error during socket close()\n");
					ret = -1;
					break;
				}

				if (sdo_connection_restablish(prot_ctx)) {
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

		// clear the block contents in preparation for the next SDOW write operation
		sdo_block_reset(&sdow->b);
		sdow->b.block_size = CBOR_BUFFER_LENGTH;

		/* ========================================================== */
		/*  Receive response */

		uint32_t msglen = 0;
		uint32_t protver = 0;

		ret = sdo_con_recv_msg_header(prot_ctx->sock_hdl, &protver,
					      (uint32_t *)&sdor->msg_type,
					      &msglen, prot_ctx->ssl);
		if (ret == -1) {
			LOG(LOG_ERROR, "sdo_con_recv_msg_header() Failed!\n");
			ret = -1;
			break;
		}

		// clear the block contents in preparation for the next SDOR read operation
		sdo_block_reset(&sdor->b);
		// set the received msg length in the block
		sdor->b.block_size = msglen;

		if (msglen > 0) {
			retries = CONNECTION_RETRY;
			n = 0;
			do {
				n = sdo_con_recv_msg_body(
				    prot_ctx->sock_hdl, &sdor->b.block[0], msglen,
				    prot_ctx->ssl);
				if (n < 0) {
					if (sdo_con_disconnect(
						prot_ctx->sock_hdl,
						prot_ctx->ssl)) {
						LOG(LOG_ERROR, "Error during "
							       "socket "
							       "close()\n");
						ret = -1;
						break;
					}

					if (sdo_connection_restablish(
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
				sdor_flush(sdor);
				ret = -1;
				break;
			}
		}

		if (sdo_con_disconnect(prot_ctx->sock_hdl, prot_ctx->ssl)) {
			LOG(LOG_ERROR, "Error during socket close()\n");
			ret = -1;
			break;
		}

		LOG(LOG_DEBUG, "%s Rx Response Body: \n", __func__);
		sdo_log_block(&sdor->b);
		/*
		 * Now that we have the received buffer, initialize the parser for next SDOR read
		 * operation and set the have_block flag.
		 */
		if (!sdor_parser_init(sdor)) {
			LOG(LOG_ERROR, "Failed to initilize SDOR parser\n");
			return -1;
		}
		sdor->have_block = true;

		/*
		 * When a REST error message(type 255) is sent over network,
		 * the received response may have an empty body.
		 */
		if (msglen == 0 && sdow->msg_type == SDO_TYPE_ERROR) {
			ret = -1;
			break;
		}
		 /* ERROR case ? */
		if (sdor->msg_type == SDO_TYPE_ERROR) {
			ret = -1;
			break;
		}
	}

	sdo_con_teardown();
	return ret;
}
