/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg49 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg49() - TO2.OwnerServiceInfo
 * --- Message Format Begins ---
 * {
 *    "nn": UInt8, # index of this message, from zero upwards
 *    "sv": ServiceInfo
 * }
 * --- Message Format Ends ---
 */
int32_t msg49(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
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
		LOG(LOG_ERROR, "Trouble reading "
			       "encrypted packet\n");
		goto err;
	}
	if (!sdoEncryptedPacketUnwind(&ps->sdor, pkt, ps->iv)) {
		goto err;
	}
	/* Get past any header */
	if (!sdoRNextBlock(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to "
			       "have "
			       "next block !!\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	/* Print the service information received from the owner
	 * in plain text. */
	LOG(LOG_DEBUG, "Owner service info: ");
	print_buffer(LOG_DEBUG, ps->sdor.b.block, ps->sdor.b.blockSize);
#endif

	if (!sdoRBeginObject(&ps->sdor)) {
		goto err;
	}

	/* Read the index of the Owner service info */
	if (!sdoReadExpectedTag(&ps->sdor, "nn")) {
		goto err;
	}
	ps->ownerSuppliedServiceInfoRcv = sdoReadUInt(&ps->sdor);

	if (ps->ownerSuppliedServiceInfoNum ==
	    ps->ownerSuppliedServiceInfoRcv) {
		int modRetVal = 0;

		if (!sdoReadExpectedTag(&ps->sdor, "sv")) {
			goto err;
		}

		if (!sdoRBeginObject(&ps->sdor)) {
			goto err;
		}

		/*
		 * ===============OSI=================
		 * 1. Fill OSI KV data structure
		 * 2. Make appropriate module callback's
		 */
		sdoSdkSiKeyValue osiKV;

		if (!sdoOsiParsing(&ps->sdor, ps->SvInfoModListHead, &osiKV,
				   &modRetVal)) {
			LOG(LOG_ERROR, "SvInfo: OSI did not "
				       "finished "
				       "gracefully!\n");
			goto err;
		}
		/*===============OSI=================*/

		if (!sdoREndObject(&ps->sdor)) {
			goto err;
		}
	}

	if (!sdoREndObject(&ps->sdor)) {
		goto err;
	}

	sdoRFlush(&ps->sdor);

	/* Loop until all have been requested */
	ps->ownerSuppliedServiceInfoNum++;
	if (ps->ownerSuppliedServiceInfoNum >=
	    ps->ownerSuppliedServiceInfoCount) {
		ps->state = SDO_STATE_TO2_SND_DONE;
	} else {
		ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	}

	ret = 0; /*Mark as success */

err:
	return ret;
}
