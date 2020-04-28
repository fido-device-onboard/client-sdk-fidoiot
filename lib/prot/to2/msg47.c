/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg47 of TO2 state machine.
 */

#include "sdoprot.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg47() - TO2.Setup_device
 * This will overwrite the device credentials received during DI
 * --- Message Format Begins ---
 * {
 *     "osinn":UInt8,  # number of service info messages to come
 *     "noh":{         # update to ownership proxyvoucher header for resale.
 *         "bo":{
 *             "r3": Rendezvous, # replaces stored Rendevous
 *              "g3": GUID,      # replaces stored GUID
 *              "n7": Nonce      # proves freshness of signature
 *         },
 *         "pk": Public_key,      # Owner2 key (replaces Manufacturer’s key).
 *         "sg": Signature       # Proof of Owner2 key.
 *     }
 * }
 * --- Message Format Ends ---
 */
int32_t msg47(sdo_prot_t *ps)
{
	int ret = -1;
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	sdo_sig_t sig = {0};
	uint32_t mtype = 0;
	sdo_encrypted_packet_t *pkt = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_SETUP_DEVICE: Starting\n");

	if (!sdo_check_to2_round_trips(ps)) {
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	pkt = sdo_encrypted_packet_read(&ps->sdor);
	if (pkt == NULL) {
		LOG(LOG_ERROR, "Trouble reading encrypted packet\n");
		goto err;
	}

	if (!sdo_encrypted_packet_unwind(&ps->sdor, pkt, ps->iv)) {
		goto err;
	}

	/* Get past any header */
	if (!sdor_next_block(&ps->sdor, &mtype)) {
		LOG(LOG_DEBUG, "SDOR doesn't seems to "
			       "have next block !!\n");
		goto err;
	}

	/* Create the destination of this final data */
	ps->osc = sdo_owner_supplied_credentials_alloc();
	if (ps->osc == NULL) {
		goto err;
	}

	ps->osc->rvlst = sdo_rendezvous_list_alloc();
	if (ps->osc->rvlst == NULL) {
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Read "osinn" - Owner Service Info Total count */
	if (!sdo_read_expected_tag(&ps->sdor, "osinn")) {
		goto err;
	}
	ps->owner_supplied_service_info_count = sdo_read_uint(&ps->sdor);

	/* Read "noh" - New Ownership Header */
	if (!sdo_read_expected_tag(&ps->sdor, "noh")) {
		goto err;
	}

	/* Store the "bo" tag "{" pointer */
	if (!sdo_begin_read_signature(&ps->sdor, &sig)) {
		goto err;
	}

	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* Store the new rendezvous entry */
	if (!sdo_read_expected_tag(&ps->sdor, "r3")) {
		goto err;
	}
	sdo_rendezvous_list_read(&ps->sdor, ps->osc->rvlst);
	LOG(LOG_DEBUG, "Rendezvous read, entries = %d\n",
	    ps->osc->rvlst->num_entries);

	/* Store the new GUID */
	if (!sdo_read_expected_tag(&ps->sdor, "g3")) {
		goto err;
	}
	ps->osc->guid = sdo_byte_array_alloc(0);
	if (ps->osc->guid == NULL) {
		goto err;
	}

	if (!sdo_byte_array_read_chars(&ps->sdor, ps->osc->guid)) {
		LOG(LOG_ERROR, "Error parsing new GUID\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	LOG(LOG_DEBUG, "New guid is \"%s\"\n",
	    sdo_guid_to_string(ps->osc->guid, buf, sizeof buf) ? buf : "");
#endif
	/* "n7" (nonce) was sent to owner in msg44 */
	if (!sdo_read_expected_tag(&ps->sdor, "n7")) {
		goto err;
	}
	ps->n7r = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n7r || !sdo_byte_array_read_chars(&ps->sdor, ps->n7r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Receiving n7: %s\n",
	    sdo_nonce_to_string(ps->n7r->bytes, buf, sizeof buf) ? buf : "");

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/*
	 * "bo" ends. Let's verify signature */
	if (!sdo_end_read_signature_full(&ps->sdor, &sig, &ps->new_pk)) {
		goto err;
	}

	/* FIXME: Is it not an error */
	if (!ps->new_pk) {
		LOG(LOG_ERROR, "No new owner public key returned\n");
		goto err;
	}

#if LOG_LEVEL == LOG_MAX_LEVEL /* LOG_DEBUG */
	{
		char *temp_buf;

		LOG(LOG_DEBUG,
		    "New Public Key : key1 "
		    ": %zu, key2 : %zu\n",
		    ps->new_pk->key1 == NULL ? 0 : ps->new_pk->key1->byte_sz,
		    ps->new_pk->key2 == NULL ? 0 : ps->new_pk->key2->byte_sz);
		temp_buf = sdo_alloc(2048);
		if (temp_buf == NULL) {
			sdo_byte_array_free(sig.sg);
			goto err;
		}
		sdo_public_key_to_string(ps->new_pk, temp_buf, 2048);
		LOG(LOG_DEBUG, "New Public Key: %s\n", temp_buf);
		sdo_free(temp_buf);
	}
#endif

	sdo_byte_array_free(sig.sg);

	sdor_flush(&ps->sdor);

	if (ps->owner_supplied_service_info_count > 0) {
		ps->owner_supplied_service_info_num = 0;
		ps->osc->si = sdo_service_info_alloc();
		if (!ps->osc->si) {
			LOG(LOG_ERROR, "Out for memory for SI\n");
			goto err;
		}
		/* Move to msg48 */
		ps->state = SDO_STATE_T02_SND_GET_NEXT_OWNER_SERVICE_INFO;
	} else {
		ps->state = SDO_STATE_TO2_SND_DONE; /* Move to msg50*/
	}
	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_SETUP_DEVICE: Complete\n");
	LOG(LOG_DEBUG, "Owner Service Info Messages to come: %d\n",
	    ps->owner_supplied_service_info_count);
	ret = 0; /* Mark as success */

err:
	return ret;
}
