/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements msg41 of TO2 state machine.
 */

#include "sdoprot.h"
#include "safe_lib.h"
#include "sdokeyexchange.h"
#include "util.h"

/**
 * msg41 - TO2.ProveOPHdr
 * The owner responds to the device with the Ownership Header. The body("bo")
 * is signed with owner Private key to start establishing that it is the
 * rightful owner of the Ownership Voucher and thus the device
 *
 * --- Message Format Begins ---
 * {
 *     bo: {
 *         "sz": UInt8,         # Number of Ownership Voucher entries
 *         "oh": {              # Ownership Voucher Header
 *             "pv": UInt16,    # Protocol Version
 *             "pe": UInt8,     # Public Key Encoding (RSA, ECDSA)
 *             "r": Rendezvous, # Whom to connect to next in customer
 *                              # premises (Rendezvous Server)
 *             "g": GUID,       # Securely generated random number
 *             "d": String,     # Device info
 *             "pk": Public_key, # Manufacturer Public Key (First owner)
 *             "hdc": Hash      # Absent if EPID
 *         },
 *         "hmac":Hash,         # HMAC over "oh" tag above created during DI
 *         "n5": Nonce,         # n5 from TO2.Hello_device
 *         "n6": Nonce,         # used below in TO2.Prove_device.
 *         "eB": Sig_info,       # Device attestation signature info
 *         "xA": Key_exchange    # Key exchange first step
 *     },
 *     "pk": Public_key,         # owner public key, may not be PKNull
 *     "sg": Signature          # Signature over "bo"
 * }
 * --- Message Format Ends ---
 */
int32_t msg41(sdo_prot_t *ps)
{
	char prot[] = "SDOProtTO2";
	char buf[DEBUGBUFSZ] = {0};
	int ret = -1;
	uint16_t ov_entries = 0;
	int result_memcmp = 0;
	sdo_sig_t sig = {0};
	sdo_byte_array_t *xA = NULL;

	LOG(LOG_DEBUG, "SDO_STATE_TO2_RCV_PROVE_OVHDR: Starting\n");

	/*
	 * Check that we don't exceed Round Trip Times requirements. The reason
	 * for checking here is that sdo_prot_rcv_msg() fails the first time.
	 * So, the parent loop send the contents of previous message and
	 * receives for this message, thus, housing the Round Trip Times.
	 */
	if (!sdo_check_to2_round_trips(ps)) {
		LOG(LOG_ERROR, "Max round trips reached\n");
		goto err;
	}

	if (!sdo_prot_rcv_msg(&ps->sdor, &ps->sdow, prot, &ps->state)) {
		ret = 0; /* Get the data, and come back */
		goto err;
	}

	/* Save the start of ownership header. The signature is brace to brace
	 */
	if (!sdo_begin_read_signature(&ps->sdor, &sig)) {
		LOG(LOG_ERROR, "Could not read begin of signature\n");
		goto err;
	}

	/* Start reading the JSON object */
	if (!sdor_begin_object(&ps->sdor)) {
		goto err;
	}

	/*
	 * Read the number of Ownership Vouchers present. The device does not
	 * know without "sz" tag, how many hops it has taken from Manufacturer
	 * to the real owner (end-user)
	 */
	if (!sdo_read_expected_tag(&ps->sdor, "sz")) {
		goto err;
	}
	ov_entries = sdo_read_uint(&ps->sdor);

	/* Read the ownership header */
	ps->ovoucher = sdo_ov_hdr_read(&ps->sdor, &ps->new_ov_hdr_hmac, true);
	if (!ps->ovoucher) {
		LOG(LOG_ERROR, "Invalid Ownership Header\n");
		goto err;
	}
	ps->ovoucher->num_ov_entries = ov_entries;

	LOG(LOG_DEBUG, "Total number of Ownership Vouchers: %d\n", ov_entries);

	/*
	 * Compare the HMAC sent by owner with HMAC calculated by us. The key is
	 * the one used by the device in DI. The owner gets the HMAC from
	 * manufacturer ps->ovoucher->ovoucher_hdr_hash->hash->bytes: owner sent
	 * HMAC ps->new_ov_hdr_hmac->hash->byte_sz            : Fresh HMAC
	 * calculated
	 */
	ret = memcmp_s(ps->ovoucher->ovoucher_hdr_hash->hash->bytes,
		       ps->ovoucher->ovoucher_hdr_hash->hash->byte_sz,
		       ps->new_ov_hdr_hmac->hash->bytes,
		       ps->new_ov_hdr_hmac->hash->byte_sz, &result_memcmp);
	if (ret || result_memcmp != 0) {
		LOG(LOG_ERROR, "Wrong HMAC received over Ownership header\n");
		ret = -1;
		goto err;
	}
	ret = -1; /* Reset to error */

	LOG(LOG_DEBUG, "Valid Ownership Header received\n");

	/* Read "n5". This must be same from msg40 (TO2.Hello_device) */
	if (!sdo_read_expected_tag(&ps->sdor, "n5")) {
		goto err;
	}
	ps->n5r = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n5r || !sdo_byte_array_read_chars(&ps->sdor, ps->n5r)) {
		goto err;
	}
	LOG(LOG_DEBUG, "Received n5r: %s\n",
	    sdo_nonce_to_string(ps->n5r->bytes, buf, sizeof buf) ? buf : "");

	/* Read "n6" value. It will be used in msg44 (TO2.Prove_device) */
	if (!sdo_read_expected_tag(&ps->sdor, "n6")) {
		goto err;
	}
	ps->n6 = sdo_byte_array_alloc(SDO_NONCE_BYTES);
	if (!ps->n6 || !sdo_byte_array_read_chars(&ps->sdor, ps->n6)) {
		goto err;
	}

	LOG(LOG_DEBUG, "Received n6: %s\n",
	    sdo_nonce_to_string(ps->n6->bytes, buf, sizeof buf) ? buf : "");

	/* Read Device Attestation key Info */
	if (!sdo_read_expected_tag(&ps->sdor, "eB")) {
		goto err;
	}

	/* Handle ECDSA */
	if (0 != sdo_eb_read(&ps->sdor)) {
		LOG(LOG_ERROR, "EB read in message 41 failed\n");
		goto err;
	}

	/*
	 * Read the key exchange info. This is the first part of key exchange of
	 * info. xA is used based on KEX selected (asym, RSA, DH)
	 */
	if (!sdo_read_expected_tag(&ps->sdor, "xA")) {
		goto err;
	}

	xA = sdo_byte_array_alloc(8);
	if (!xA) {
		LOG(LOG_ERROR, "Out of memory for key exchange info (xA)\n");
		goto err;
	}

	if (!sdor_begin_sequence(&ps->sdor)) {
		LOG(LOG_ERROR, "ERROR :Not at beginning of sequence\n");
		goto err;
	}
	sdo_byte_array_read(&ps->sdor, xA);

	LOG(LOG_DEBUG, "Key Exchange xA is %zu bytes\n", xA->byte_sz);

	if (!sdor_end_sequence(&ps->sdor)) {
		goto err;
	}

	/* TO2.ProveOPHdr.bo ends here */
	if (!sdor_end_object(&ps->sdor)) {
		goto err;
	}

	/* Here we will save a copy of the owner pk (TO2.ProveOVHdr bo.pk) */
	if (!sdo_end_read_signature_full(&ps->sdor, &sig,
					 &ps->owner_public_key)) {
		goto err;
	}

	if (!ps->owner_public_key) {
		goto err;
	}
#if LOG_LEVEL == LOG_MAX_LEVEL /* LOG_DEBUG */
	{
		char *temp_buf;

		LOG(LOG_DEBUG, "Owner Public Key returned\n");
		LOG(LOG_DEBUG,
		    "Owner Public Key : key1 : %zu, "
		    "key2 : %zu\n",
		    ps->owner_public_key->key1->byte_sz,
		    ps->owner_public_key->key2 == NULL
			? 0
			: ps->owner_public_key->key2->byte_sz);

		temp_buf = sdo_alloc(2048);
		if (!temp_buf) {
			goto err;
		}
		sdo_public_key_to_string(ps->owner_public_key, temp_buf, 2048);
		LOG(LOG_DEBUG, "Owner Public Key : %s\n", temp_buf);
		sdo_free(temp_buf);
	}
#endif

	/* The nonces "n5" (msg40) and "n6" here must match */
	if (!sdo_nonce_equal(ps->n5r, ps->n5)) {
		LOG(LOG_ERROR, "Invalid Nonce send by owner\n");
		goto err;
	}

	/* The signature verification over TO2.ProveOPHdr.bo must verify */
	if (!sdo_signature_verification(ps->sdo_redirect.plain_text,
					ps->sdo_redirect.obsig,
					ps->owner_public_key)) {
		LOG(LOG_ERROR, "sdo_redirect verification Failed.\n");
		goto err;
	}
	LOG(LOG_DEBUG, "sdo_redirect verification Successful \n");

	sdor_flush(&ps->sdor);

	/* Save TO2.ProveOPHdr.pk for Asymmetric Key Exchange algorithm */

	if (sdo_set_kex_paramA(xA, ps->owner_public_key)) {
		goto err;
	}

	/*
	 * If the TO2.ProveOPHdr.bo.sz > 0, get next Ownership Voucher (msg42),
	 * else jump to msg44
	 */
	if (ps->ovoucher->num_ov_entries) {
		ps->ov_entry_num = 0;
		ps->state = SDO_STATE_TO2_SND_GET_OP_NEXT_ENTRY;
	} else {
		LOG(LOG_INFO, "No Ownership Vouchers, jumping to msg44\n");
		ps->state = SDO_STATE_TO2_SND_PROVE_DEVICE;
	}

	LOG(LOG_DEBUG,
	    "SDO_STATE_TO2_RCV_PROVE_OVHDR: Complete, %d "
	    "ov_entries to follow\n",
	    ps->ovoucher->num_ov_entries);
	ret = 0; /* Mark as success */

err:
	/* sdo_public_key_free(ps->owner_public_key); */
	if (xA) {
		sdo_byte_array_free(xA);
	}
	if (sig.sg) {
		sdo_byte_array_free(sig.sg);
		sig.sg = NULL;
	}
	return ret;
}
