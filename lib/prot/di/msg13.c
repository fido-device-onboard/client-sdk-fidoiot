/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 13.
 */

#include "load_credentials.h"
#include "util.h"

/**
 * msg13() - DI.Done
 *
 * The device receives message once the manufacturer has storedall the relevant
 * information, and is ready with the Ownership Voucher.
 *
 * -no-body-
 */
int32_t msg13(SDOProt_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtDI";
	SDODevCred_t *devCred = app_get_credentials();

	/* Check if we are able to read the device credentials from storage */
	if (devCred == NULL) {
		LOG(LOG_ERROR, "Device credentials missing\n");
		goto err;
	}

	/* Read from the internal buffer to see if the data is there */
	if (!sdoProtRcvMsg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Try again */
		goto err;
	}

	/* Generate hash of the public key received in msg11 */
	sdoRFlush(&ps->sdor);
	devCred->ownerBlk->pkh = sdoPubKeyHash(devCred->ownerBlk->pk);
	if (!devCred->ownerBlk->pkh) {
		LOG(LOG_ERROR, "Hash creation of manufacturer pk failed\n");
		goto err;
	}

	/* Update the state of device to be ready for TO1 */
	ps->devCred->ST = SDO_DEVICE_STATE_READY1;
	if (store_credential(ps->devCred) != 0) {
		LOG(LOG_ERROR, "Failed to store updated device state\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Device credentials successfully written!!\n");

	/* Mark as success, and DI done */
	ret = 0;
	ps->state = SDO_STATE_DONE;

err:
	return ret;
}
