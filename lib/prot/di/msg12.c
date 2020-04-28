/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of msg number 12. The device ingested msg 11 contents
 * and prepares msg 12
 */

#include "util.h"
#include "sdoprot.h"

/**
 * msg12() - DI.SetHMAC
 *
 * The device has already calculated HMAC over the Ownership Header
 * received in msg11, so, fill in that information send it back to
 * manfacturer. Manufacturer uses this information to prepare the
 * fist empty Ownership Voucher
 *
 * {
 *    "hmac": Hash
 * }
 */
int32_t msg12(sdo_prot_t *ps)
{
	int ret = -1;

	/* Prepare the block for msg12 */
	sdow_next_block(&ps->sdow, SDO_DI_SET_HMAC);
	sdow_begin_object(&ps->sdow);

	sdo_write_tag(&ps->sdow, "hmac");
	if (!ps->new_ov_hdr_hmac) {
		LOG(LOG_ERROR, "OVHdrHMAC is NULL MSG#12\n");
		goto err;
	}

	/* Write the HMAC and send it to manufacturer */
	sdo_hash_write(&ps->sdow, ps->new_ov_hdr_hmac);
	sdo_hash_free(ps->new_ov_hdr_hmac);
	sdow_end_object(&ps->sdow);

	/* Mark as success and goto msg13 */
	ps->state = SDO_STATE_DI_DONE;
	ret = 0;

err:
	return ret;
}
