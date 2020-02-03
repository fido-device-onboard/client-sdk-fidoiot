/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 30.
 */

#include "sdoprot.h"

/**
 * msg30() - TO1.HelloSDO
 * The device is powered ON again in customer premises and the process of
 * finding rightful owner begins with this message. The device will
 * prepare itself to talk to Rendezvous(RV) Server and establish the trust
 * to get the credentials of next owner
 *
 * --- Message Format Begins ---
 *  {
 *      "g2": GUID,   # Device GUID, received and stored during DI
 *      "eA": SigInfo # eA: Device Signature information
 *  }
 * --- Message Format Ends ---
 *
 * --- eA for EPID ---
 * Value = 92 (EPID2.0): 128bit number
 *
 * --- eA format for ECDSA ---
 * Value = 13 (ECDSA256): 128bit number
 * Value = 14 (ECDSA384): 128bit number
 */
int32_t msg30(SDOProt_t *ps)
{
	sdoWNextBlock(&ps->sdow, SDO_TO1_TYPE_HELLO_SDO);
	sdoWBeginObject(&ps->sdow);

	/* Write GUID received during DI */
	sdoWriteTag(&ps->sdow, "g2");
	sdoByteArrayWriteChars(&ps->sdow, ps->devCred->ownerBlk->guid);

	/* Write the siginfo for RV to use and prepare next msg */
	sdoWriteTag(&ps->sdow, "eA");
	sdoGidWrite(&ps->sdow);

	sdoWEndObject(&ps->sdow);

	/* Move to next state (msg31) */
	ps->state = SDO_STATE_TO1_RCV_HELLO_SDOACK;

	return 0;
}
