/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg46 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg46() - TO2.NextDeviceServiceInfo
 * --- Message Format Begins ---
 * {
 *   "nn" : UInt8,      # index of this message, from zero upwards.
 *   "dsi": ServiceInfo # service info entries to add or
 *                      # append to previous ones.
 * }
 * --- Message Format Ends ---
 */
int32_t msg46(SDOProt_t *ps)
{
	int ret = -1;

	/* Send all the key value sets in the Service Info list */
	sdoWNextBlock(&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO);
	sdoWBeginObject(&ps->sdow);

	/* Write the index of this message ("nn") */
	sdoWriteTag(&ps->sdow, "nn");
	sdoWriteUInt(&ps->sdow, ps->servReqInfoNum);

	/* Write the Device Service Info ("dsi") */
	sdoWriteTag(&ps->sdow, "dsi");
	sdoWBeginObject(&ps->sdow);

	if (!ps->serviceInfo)
		goto err;

	/*
	 * DSI's that need to be sent:
	 * 1. Platform DSI's (1st iteration, when nn=0)
	 * 2. SvInfo external module(s) DSI's (remaining iterations)
	 */

	if (ps->servReqInfoNum == 0) {
		/* Construct and write platform DSI's into a single json msg */
		if (!sdoCombinePlatformDSIs(&ps->sdow, ps->serviceInfo)) {
			LOG(LOG_ERROR, "Error in combining platform DSI's!\n");
			goto err;
		}
	} else {
		int modRetVal = 0;

		/* SvInfo external module(s) DSI's */
		sdoSdkSiKeyValue *sv_kv = sdoAlloc(sizeof(sdoSdkSiKeyValue));
		if (!sv_kv)
			goto err;

		if (!sdoConstructModuleDSI(ps->dsiInfo, sv_kv, &modRetVal)) {
			LOG(LOG_DEBUG, "SvInfo: module DSI "
				       "Construction Failed\n");
			sdoSVKeyValueFree(sv_kv);
			goto err;
		}

		if (!sdoModKVWrite(&ps->sdow, sv_kv)) {
			sdoSVKeyValueFree(sv_kv);
			goto err;
		}
		/* Free allocated memory */
		sdoSVKeyValueFree(sv_kv);
	}

	sdoWEndObject(&ps->sdow);
	sdoWEndObject(&ps->sdow);

	/* Encrypt the packet */
	if (!sdoEncryptedPacketWindup(
		&ps->sdow, SDO_TO2_NEXT_DEVICE_SERVICE_INFO, ps->iv)) {
		goto err;
	}

	/* Check for DSI rounds */
	if (ps->servReqInfoNum < ps->totalDsiRounds - 1) {
		/* Back to msg45 */
		ps->state = SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO;
	} else {
		/* Move to msg47 */
		ps->state = SDO_STATE_TO2_RCV_SETUP_DEVICE;
	}

	ret = 0; /* Mark as success */

err:
	return ret;
}
