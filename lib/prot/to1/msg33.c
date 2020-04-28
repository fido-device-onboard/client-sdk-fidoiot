/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Implementation of TO1 protocol message 33.
 */

#include "safe_lib.h"
#include "util.h"
#include "sdoprot.h"

/**
 * msg33() - TO1.sdo_redirect
 * This is the last message of TO1. The device receives the owner info from RV.
 *
 * --- Message Format Begins ---
 * {
 *     "bo": {
 *         "i1": IPAddress, # Owner IP address
 *         "dns1": String,  # DNS if owner is registered with DNS service
 *         "port1": UInt16, # TCP/UDP port to connect to
 *         "to0dh": Hash    # See TO0, msg22: Hash(to0d object, brace to brace)
 *     },
 *     "pk": PKNull,
 *     "sg": Signature      # Signed with “Owner key” that Device will get in
 * TO2
 * }
 * --- Message Format Begins ---
 *
 */
int32_t msg33(sdo_prot_t *ps)
{
	int ret = -1;
	sdo_sig_t sig = {0};
	int sig_block_sz = -1;
	int sig_block_end = -1;
	sdo_hash_t *ob_hash = NULL;
	char buf[DEBUGBUFSZ] = {0};
	uint8_t *plain_text = NULL;
	sdo_public_key_t *temp_pk = NULL;
	char prot[] = "SDOProtTO1";

	LOG(LOG_DEBUG, "\n_starting SDO_STATE_TO1_RCV_SDO_REDIRECT\n");

	/* Try to read from internal buffer */
	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /*Mark for retry */
		goto err;
	}

	/*
	 * Mark the beginning of "bo". The signature is calculated over
	 * braces to braces, so, saving the offset of starting "bo"
	 */
	if (!sdo_begin_read_signature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not read begin of signature\n");
		goto err;
	}

	/* Start parsing the "bo" (body) data now */
	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/* TODO: In 0.8 these are i1 fields, check what is the
	 * difference */

	/* Read "i1" tag/value: IP address of owner */
	if (!sdo_read_expected_tag(&ps->sdor, "i1")) {
		goto err;
	}
	if (sdo_read_ipaddress(&ps->sdor, &ps->i1) != true) {
		LOG(LOG_ERROR, "Read IP Address Failed\n");
		goto err;
	}

	/* Read "dns1" tag/value: URL of owner */
	if (!sdo_read_expected_tag(&ps->sdor, "dns1")) {
		goto err;
	}
	ps->dns1 = sdo_read_dns(&ps->sdor);

	/* Read "port1" tag/value: Port of owner machine */
	if (!sdo_read_expected_tag(&ps->sdor, "port1")) {
		goto err;
	}
	ps->port1 = sdo_read_uint(&ps->sdor);

	/* Read "to0dh" tag/value: Owner hash sent to RV */
	if (!sdo_read_expected_tag(&ps->sdor, "to0dh")) {
		goto err;
	}

	/*
	 * TODO: Check if the hash is just parsed to be discared.
	 * Do we have an API, where we just increased the cursor
	 * and not read the data at all?
	 */
	ob_hash = sdo_hash_alloc_empty();
	if (!ob_hash || !sdo_hash_read(&ps->sdor, ob_hash)) {
		goto err;
	}

	/* Mark the end of "bo" tag */
	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/* Save the "bo" start and size. The signature is over this */
	sig_block_end = ps->sdor.b.cursor;
	sig_block_sz = sig_block_end - sig.sig_block_start;

	/* Copy the full "bo" to ps */
	plain_text = sdor_get_block_ptr(&ps->sdor, sig.sig_block_start);
	if (plain_text == NULL) {
		ps->state = SDO_STATE_DONE;
		goto err;
	}

	ps->sdo_redirect.plain_text = sdo_byte_array_alloc(sig_block_sz);
	if (!ps->sdo_redirect.plain_text) {
		goto err;
	}
	if (memcpy_s(ps->sdo_redirect.plain_text->bytes, sig_block_sz,
		     plain_text, sig_block_sz) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		goto err;
	}

	ps->sdo_redirect.plain_text->byte_sz = sig_block_sz;

	/* Read the public key */
	if (!sdo_read_expected_tag(&ps->sdor, "pk")) {
		goto err;
	}

	/*
	 * FIXME: Reading public key and freeing it. Why are we returning
	 * a pointer to be freed
	 */
	temp_pk = sdo_public_key_read(&ps->sdor);
	if (temp_pk) {
		sdo_public_key_free(temp_pk);
	}

	/* Read the "sg" tag/value */
	if (!sdo_read_expected_tag(&ps->sdor, "sg")) {
		goto err;
	}

	if (!sdor_begin_sequence(&ps->sdor)) {
		LOG(LOG_ERROR, "Not at beginning of sequence\n");
		goto err;
	}

	/* These bytes will be thrown away, some issue with zero length */
	ps->sdo_redirect.obsig = sdo_byte_array_alloc(16);
	if (!ps->sdo_redirect.obsig) {
		goto err;
	}

	/* Read the signature to the signature object */
	if (!sdo_byte_array_read(&ps->sdor, ps->sdo_redirect.obsig)) {
		LOG(LOG_ERROR, "obsig read error\n");
		goto err;
	}

	if (!sdor_end_sequence(&ps->sdor)) {
		goto err;
	}

	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/* TODO: Add support for signing message defined in spec
	 * 0.8 */

	sdor_flush(&ps->sdor);

	LOG(LOG_DEBUG, "Received redirect: %s\n",
	    sdo_ipaddress_to_string(&ps->i1, buf, sizeof buf) ? buf : "");

	/* Mark as success and ready for TO2 */
	ps->state = SDO_STATE_DONE;
	ret = 0;
	LOG(LOG_DEBUG, "Complete SDO_STATE_TO1_RCV_SDO_REDIRECT\n");

err:
	if (ps->sdo_redirect.obsig && ret) {
		sdo_byte_array_free(ps->sdo_redirect.obsig);
		ps->sdo_redirect.obsig = NULL;
	}
	if (ob_hash) {
		sdo_hash_free(ob_hash);
	}
	return ret;
}
