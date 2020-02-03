/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg45 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg45() - TO2.GetNextDeviceServiceInfo
 * So, the owner has verified that it is talking to right device and
 * sending in the service info data
 * --- Message Format Begins ---
 * {
 *   "nn": UInt8,  #Index of device service info message expected
 *   "psi": String # extra for this version of protocol only
 * }
 * --- Message Format Ends ---
 */

int32_t msg45(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	SDOString_t *psi = NULL;
	uint32_t mtype = 0;
	SDOEncryptedPacket_t *pkt = NULL;

	if (!sdoCheckTO2RoundTrips(ps)) {
		goto err;
	}

	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	/* If the packet is encrypted, decrypt it */
	pkt = sdoEncryptedPacketRead(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdoEncryptedPacketUnwind(&ps->sdor, pkt, ps->iv)) {
		LOG(LOG_ERROR, "Failed to decrypt packet!\n");
		goto err;
	}

	/* Get past any header */
	if (!sdoRNextBlock(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to have next block !!\n");
		goto err;
	}

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* The device needs to send the Service Info corresponding to "nn" */
	if (!sdoReadExpectedTag(&ps->sdor, "nn")) {
		goto err;
	}
	ps->servReqInfoNum = sdoReadUInt(&ps->sdor);

	/*
	 * It is optional and can only contain value if "nn" = 0. For non-NULL
	 * "psi", it is indicating to device, to prepare itself for Service
	 * Info. (PSI: Pre Service Info
	 */
	if (!sdoReadExpectedTag(&ps->sdor, "psi")) {
		goto err;
	}

	psi = sdoStringAlloc();
	if (psi == NULL) {
		goto err;
	}
	if (!sdoStringRead(&ps->sdor, psi)) {
		LOG(LOG_ERROR, "Parsing psi String\n");
		goto err;
	}

	/*
	 * TODO:Support for preference module message, it is not needed for now
	 * as we have defined modules, but may be require at later point of
	 * time when  modules are completely dynamic.
	 */
	LOG(LOG_DEBUG, "psi string: %s, nn = %d\n\n", psi->bytes,
	    ps->servReqInfoNum);

	/* For "nn" == 0 */
	if (ps->servReqInfoNum == 0) {
		/* Parse PSI only when psi->bytes is not an empty string */
		if (psi->byteSz > EMPTY_STRING_LEN) {
			int modRetVal = 0;
			if (!sdoPsiParsing(ps->SvInfoModListHead, psi->bytes,
					   psi->byteSz, &modRetVal)) {
				LOG(LOG_ERROR, "SvInfo: PSI did not "
					       "finished gracefully!\n");

				/*
				 * TODO: See if there's benefit to handle
				 * multiple SI errors.
				 */
				goto err;
			}
		} else {
			LOG(LOG_INFO, "SvInfo: Empty PSI string for nn=0\n");
		}
	} else if (ps->servReqInfoNum > 0 &&
		   (ps->servReqInfoNum < ps->totalDsiRounds)) {
		if (psi->byteSz != EMPTY_STRING_LEN) {
			LOG(LOG_ERROR, "SvInfo: For non-zero nn, "
				       "psi string must be empty!\n");
			goto err;
		}
	} else {
		LOG(LOG_ERROR, "SvInfo: nn value is out of range!");
		goto err;
	}

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	sdoRFlush(&ps->sdor);
	ps->state = SDO_STATE_TO2_SND_NEXT_DEVICE_SERVICE_INFO;
	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_GET_NEXT_DEVICE_SERVICE_INFO "
		       ": 45 Completed\n");
	ret = 0; /* Marks as success */

err:
	if (psi) {
		sdoStringFree(psi);
	}
	return ret;
}
