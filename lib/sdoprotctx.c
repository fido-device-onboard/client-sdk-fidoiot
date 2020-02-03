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
#include "sdoprotctx.h"
#include "sdonet.h"
#include "network_al.h"
#include <stdlib.h>
#include "load_credentials.h"
#include "safe_lib.h"
#include "snprintf_s.h"

#define CONNECTION_RETRY 2

/**
 * sdoProtCtxAlloc responsible for allocation of required protocol context.
 * @param protrun - pointer to function for intended protocol (DI/TO1/TO2).
 * @param protdata - pointer of type SDOProt_t, hold protocol related data.
 * @param host_ip, - Pointer to intended HOST's IP address (null if DNS is
 * present).
 * @param host_dns - Pointer to intended HOST's DNS (null if IP is present).
 * @param host_port - port no of intended HOST.
 * @param tls - boolean denoting if transport level security is applicable.
 * @return pointer to required protocol context on success, NULL if any error
 * occured.
 */
SDOProtCtx_t *sdoProtCtxAlloc(bool (*protrun)(), SDOProt_t *protdata,
			      SDOIPAddress_t *host_ip, char *host_dns,
			      uint16_t host_port, bool tls)
{
	if (NULL == host_ip && NULL == host_dns) {
		LOG(LOG_ERROR, "IP and DNS, both are found NULL!!\nPlease set "
			       "Server's IP/DNS and then proceed.\n");
		return NULL;
	}

	SDOProtCtx_t *prot_ctx = sdoAlloc(sizeof(SDOProtCtx_t));
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
void sdoProtCtxFree(SDOProtCtx_t *prot_ctx)
{
	if (prot_ctx) {
		if (prot_ctx->host_dns)
			sdoFree(prot_ctx->resolved_ip);
		sdoFree(prot_ctx);
	}
}

/**
 * Internal API
 */
bool sdoProtCtxConnect(SDOProtCtx_t *prot_ctx)
{
	bool ret = false;
	static int prevstate = 0;

	if (prot_ctx->protdata->state == SDO_STATE_ERROR)
		prot_ctx->protdata->state = prevstate;

	switch (prot_ctx->protdata->state) {
	case SDO_STATE_DI_APP_START:       /* type 10 */
	case SDO_STATE_DI_SET_CREDENTIALS: /* type 11 */
		if (prot_ctx->host_dns) {
			if (!ResolveDn(prot_ctx->host_dns,
				       &prot_ctx->resolved_ip,
				       prot_ctx->host_port, NULL,
				       is_mfg_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
	case SDO_STATE_DI_SET_HMAC: /* type 12 */
	case SDO_STATE_DI_DONE:     /* type 13 */
		ret = ConnectToManufacturer(prot_ctx->host_ip,
					    prot_ctx->host_port,
					    &prot_ctx->sock, NULL);
		break;
	case SDO_STATE_T01_SND_HELLO_SDO:    /* type 30 */
	case SDO_STATE_TO1_RCV_HELLO_SDOACK: /* type 31 */
		if (prot_ctx->host_dns) {
			if (!ResolveDn(prot_ctx->host_dns,
				       &prot_ctx->resolved_ip,
				       prot_ctx->host_port,
				       (prot_ctx->tls ? &prot_ctx->ssl : NULL),
				       is_rv_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
	case SDO_STATE_TO1_SND_PROVE_TO_SDO: /* type 32 */
	case SDO_STATE_TO1_RCV_SDO_REDIRECT: /* type 33 */
		ret = ConnectToRendezvous(
		    prot_ctx->host_ip, prot_ctx->host_port, &prot_ctx->sock,
		    (prot_ctx->tls ? &prot_ctx->ssl : NULL));
		break;
	case SDO_STATE_T02_SND_HELLO_DEVICE: /* type 40 */
	case SDO_STATE_TO2_RCV_PROVE_OVHDR:  /* type 41 */
		if (prot_ctx->host_dns) {
			if (!ResolveDn(prot_ctx->host_dns,
				       &prot_ctx->resolved_ip,
				       prot_ctx->host_port, NULL,
				       is_owner_proxy_defined())) {
				ret = false;
				break;
			}
			prot_ctx->host_ip = prot_ctx->resolved_ip;
		}
	case SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY:	    /* type 42 */
	case SDO_STATE_T02_RCV_OP_NEXT_ENTRY:		     /* type 43 */
	case SDO_STATE_TO2_SND_PROVE_DEVICE:		     /* type 44 */
	case SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO: /* type 45 */
	case SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO:     /* type 46 */
	case SDO_STATE_TO2_RCV_SETUP_DEVICE:		     /* type 47 */
	case SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO:  /* type 48 */
	case SDO_STATE_T02_RCV_NEXT_OWNER_SERVICE_INFO:      /* type 49 */
	case SDO_STATE_TO2_SND_DONE:			     /* type 50 */
	case SDO_STATE_TO2_RCV_DONE_2:			     /* type 51 */
		ret = ConnectToOwner(prot_ctx->host_ip, prot_ctx->host_port,
				     &prot_ctx->sock, NULL);
		break;
	default:
		LOG(LOG_ERROR, "sdoProtCtxConnect reached unknown state \n");
		break;
	}
	prevstate = prot_ctx->protdata->state;
	return ret;
}

/**
 * sdoProtCtxRun responsible for running/maintaining DI, T01, T02 protocol
 * contexts and respond according to the state specified.
 * Managing the JSON packet to/from device to server is taken care.
 * Managing the ip/dns-to-ip resolution is taken care.
 * @param prot_ctx - Pointer of type SDOProtCtx_t, holds the all the
 * information,
 * @return 0 on success, -1 on error.
 */

int sdoProtCtxRun(SDOProtCtx_t *prot_ctx)
{
	int ret = 0;
	int n, size;
	int retries = 0;
	SDOBlock_t *sdob = NULL;
	SDOR_t *sdor = NULL;
	SDOW_t *sdow = NULL;

	if (!prot_ctx || !prot_ctx->protdata)
		return -1;
	sdor = &prot_ctx->protdata->sdor;
	sdow = &prot_ctx->protdata->sdow;

	// init connection set-up for send/receive packets
	if (sdoConSetup(NULL, NULL, 0)) {
		LOG(LOG_ERROR, "Connection setup failed!\n");
		return -1;
	}

	for (;;) {

		if (prot_ctx->protrun)
			(*prot_ctx->protrun)(prot_ctx->protdata);
		else {
			ret = -1;
			break;
		}

		//=====================================================================
		// Transmit outbound packet
		//

		// Protocol sets State as SDO_STATE_DONE at the end of the
		// protocol(DI/T01/TO2)
		// Hence, when state = SDO_STATE_DONE, we have nothing more left
		// to
		// send. Exit!!
		if (prot_ctx->protdata->state == SDO_STATE_DONE) {
			ret = 0;
			break;
		}

		if ((sdow->msgType < SDO_DI_APP_START) ||
		    (sdow->msgType > SDO_TYPE_ERROR)) {
			ret = -1;
			break;
		}

		if (!sdoProtCtxConnect(prot_ctx)) {
			/* Giving up, we tried enough to
			 * re-establish */
			ret = -1;
			break;
		}

		size = sdow->b.blockSize;

		sdow->b.block[size] = 0;
		retries = CONNECTION_RETRY;
		do {
			n = sdoConSendMessage(prot_ctx->sock,
					      SDO_PROT_SPEC_VERSION,
					      sdow->msgType, &sdow->b.block[0],
					      size, prot_ctx->ssl);

			if (n <= 0) {
				if (sdoConDisconnect(prot_ctx->sock,
						     prot_ctx->ssl)) {
					LOG(LOG_ERROR,
					    "Error during socket close()\n");
					ret = -1;
					break;
				}

				if (sdoConnectionRestablish(prot_ctx)) {
					/* Giving up, we tried enough to
					 * re-establish */
					ret = -1;
					break;
				}
			}
		} while (n < 0 && retries--);

		if (n < 0) {
			ret = -1;
			break;
		}

		LOG(LOG_DEBUG, "Tx sdoProtCtxRun:body:%s\n\n",
		    &sdow->b.block[0]);

		//=====================================================================
		// Receive response
		//
		sdob = &sdor->b;

		uint32_t msglen = 0;
		uint32_t protver = 0;

		if ((ret = sdoConRecvMsgHeader(prot_ctx->sock, &protver,
					       (uint32_t *)&sdor->msgType,
					       &msglen, prot_ctx->ssl)) == -1) {
			LOG(LOG_ERROR, "sdoConRecvMsgHeader() Failed!\n");
			ret = -1;
			break;
		}

		sdoRFlush(sdor);
		sdob = &sdor->b;
		sdoResizeBlock(sdob, msglen + 4);

		if (memset_s(sdob->block, msglen + 4, 0) != 0) {
			LOG(LOG_ERROR, "Memset Failed\n");
			ret = -1;
			break;
		}

		sdob->blockSize = msglen;

		if (msglen > 0) {
			retries = CONNECTION_RETRY;
			n = 0;
			do {
				n = sdoConRecvMsgBody(prot_ctx->sock,
						      &sdob->block[0], msglen,
						      prot_ctx->ssl);
				if (n < 0) {
					if (sdoConDisconnect(prot_ctx->sock,
							     prot_ctx->ssl)) {
						LOG(LOG_ERROR, "Error during "
							       "socket "
							       "close()\n");
						ret = -1;
						break;
					}

					if (sdoConnectionRestablish(prot_ctx)) {
						/* Giving up, we tried enough to
						 * re-establish */
						ret = -1;
						break;
					}
				}
			} while (n < 0 && retries--);

			if (n <= 0) {
				LOG(LOG_ERROR, "Socket read not successful "
					       "after retries!\n");
				sdoRFlush(sdor);
				ret = -1;
				break;
			}
		}

		if (sdoConDisconnect(prot_ctx->sock, prot_ctx->ssl)) {
			LOG(LOG_ERROR, "Error during socket close()\n");
			ret = -1;
			break;
		}

		LOG(LOG_DEBUG, "Rx sdoProtCtxRun:body:%s\n\n",
		    &sdor->b.block[0]);

		sdoRSetHaveBlock(sdor);

		/*
		 * When a REST error message(type 255) is sent over network,
		 * the received response may have an empty body.
		 */
		if (msglen == 0 && sdow->msgType == SDO_TYPE_ERROR) {
			ret = -1;
			break;
		}
		// ERROR case ?
		if (sdor->msgType == SDO_TYPE_ERROR) {
			ret = -1;
			break;
		}
	}

	sdoConTeardown();

	if (sdob && sdob->block) {
		sdob->blockMax = 0;
		sdob->blockSize = 0;
		sdob->cursor = 0;
		sdoFree(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}
