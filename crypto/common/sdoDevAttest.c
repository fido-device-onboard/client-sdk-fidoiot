/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "safe_lib.h"
#include "load_credentials.h"
#include "storage_al.h"
#include <unistd.h>
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "sdoCrypto.h"
#ifdef EPID_DA
#include "epid.h"
#define EPIDKEYLEN 144 // Value will change as per EPID version

/**
 * Load EPID data from credentials data store.
 *
 * @return ret
 *        return 0 on success. -1 on failure.
 */
int32_t dev_attestation_init(void)
{
	uint8_t *private_key = NULL;
	size_t private_key_len = EPIDKEYLEN;
	size_t raw_blob_size = 0;
	int ret = -1;
	sdor_t sdoreader = {0};
	sdor_t *sdor = NULL;
	sdo_block_t *sdob = NULL;

	sdor = &sdoreader;
	sdob = &(sdor->b);
	sdo_byte_array_t *cacert_data = sdo_byte_array_alloc(0);
	sdo_byte_array_t *signed_sig_rl = sdo_byte_array_alloc(0);
	sdo_byte_array_t *signed_group_public_key = sdo_byte_array_alloc(0);

	if (!cacert_data || !signed_sig_rl || !signed_group_public_key) {
		LOG(LOG_ERROR,
		    "Allocation for storing Raw block content failed\n");
		goto end;
	}

	if (!sdor_init(sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		goto end;
	}

	/*
	 * Read in the EPID group public key, private key, Sig_rl, and cacert.
	 * In a real product the private key and cacert data would be in the
	 * TEE, the Public key would come from the OProxy and the sigrl we
	 * would load it from a network resource for our group.
	 */

	// Raw Blob
	raw_blob_size = sdo_blob_size((char *)RAW_BLOB, SDO_SDK_RAW_DATA);
	if (raw_blob_size > 0) {
		sdo_resize_block(sdob, raw_blob_size);
	} else {
		LOG(LOG_DEBUG, "%s cacert!\n",
		    raw_blob_size ? "Error reading" : "Missing");
		goto end;
	}

	if (sdo_blob_read((char *)RAW_BLOB, SDO_SDK_RAW_DATA, sdob->block,
			  raw_blob_size) == -1) {
		LOG(LOG_ERROR, "Could not read the cacert blob\n");
		goto end;
	}

	sdor->b.block_size = raw_blob_size;
	sdor->have_block = true;

	LOG(LOG_DEBUG, "Raw blob has been processed\n");

	if (!sdor_begin_object(sdor)) {
		LOG(LOG_ERROR, "Begin object not found\n");
		goto end;
	}

	if (!sdo_read_expected_tag(sdor, "cacert")) {
		LOG(LOG_ERROR, "tag=cacert not found\n");
		goto end;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that CA certificate doesn't have any data */
	if (!sdo_byte_array_read_chars(sdor, cacert_data)) {
		LOG(LOG_DEBUG, "cacert not available.\n");
	}

#if LOG_LEVEL == LOG_MAX_LEVEL
	if (cacert_data->byte_sz) {
		hexdump("cacert", cacert_data->bytes, cacert_data->byte_sz);
	}
#endif

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* Sig_rl */
	if (!sdo_read_expected_tag(sdor, "sigrl")) {
		LOG(LOG_ERROR, "tag=sigrl not found\n");
		goto end;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that sig revocation list is not available */
	if (!sdo_byte_array_read_chars(sdor, signed_sig_rl)) {
		LOG(LOG_DEBUG, "Sigrl not available.\n");
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* Group public key blob */
	if (!sdo_read_expected_tag(sdor, "pubkey")) {
		LOG(LOG_ERROR, "tag=pubkey not found\n");
		goto end;
	}

	if (!sdor_begin_sequence(sdor)) {
		LOG(LOG_ERROR, "Beginning sequence not found.\n");
		goto end;
	}

	/* It may be possible that public key is not available */
	if (!sdo_byte_array_read_chars(sdor, signed_group_public_key)) {
		LOG(LOG_DEBUG, "pubkey not available.\n");
	}

	if (!sdor_end_sequence(sdor)) {
		LOG(LOG_ERROR, "No End Sequence\n");
		goto end;
	}

	/* Member private key */
	private_key = sdo_alloc(private_key_len);
	if (!private_key) {
		LOG(LOG_ERROR, "Malloc Failed for private_key!\n");
		goto end;
	}

	// When EPID is read from platform, error code will be introduced
	if (sdo_read_epid_key(private_key, (uint32_t *)&private_key_len) ==
	    -1) {
		LOG(LOG_DEBUG, "Readprivate_key Failed!\n");
		goto end;
	}

	if (sdo_set_device_sig_infoeA(private_key, &private_key_len) != 0) {
		LOG(LOG_ERROR, "Memcpy failed\n");
		goto end;
	}

	ret =
	    epid_init(signed_group_public_key->bytes,
		      signed_group_public_key->byte_sz, private_key,
		      private_key_len, cacert_data->bytes, cacert_data->byte_sz,
		      signed_sig_rl->bytes, signed_sig_rl->byte_sz, NULL, 0);
	if (ret != 0) {
		LOG(LOG_ERROR, "EPID Could not be initialized !!\n");
		goto end;
	}

	ret = 0; /* Mark as success */

end:
	if (private_key) {
		if (memset_s(private_key, private_key_len, 0)) {
			LOG(LOG_ERROR, "Failed to clear private key\n");
			ret = -1;
		}
		sdo_free(private_key);
	}
	if (signed_sig_rl) {
		sdo_byte_array_free(signed_sig_rl);
		signed_sig_rl = NULL;
	}
	if (signed_group_public_key) {
		sdo_byte_array_free(signed_group_public_key);
		signed_group_public_key = NULL;
	}
	if (cacert_data) {
		sdo_byte_array_free(cacert_data);
		cacert_data = NULL;
	}
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}
	return ret;
}

/* Calls EPID close.
 */
void dev_attestation_close(void)
{
	epid_close();
}

#else

/* Do nothing for ECDSA based attestation */
int32_t dev_attestation_init(void)
{
	return 0;
}

void dev_attestation_close(void)
{
	return;
}
#endif
