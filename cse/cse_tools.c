/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "cse_utils.h"
#include "cse_tools.h"
#include <inttypes.h>

/**
 * Interface to get device certificate from CSE
 * @return pointer to a byte_array holding a valid device CSE Cert.
 */
int32_t cse_get_cert_chain(fdo_byte_array_t **cse_cert)
{
	if (!cse_cert) {
		return -1;
	}

	FDO_STATUS fdo_status;
	int ret = -1;
	uint16_t lengths_of_certificates[FDO_ODCA_CHAIN_LEN];
	uint8_t certificate_chain[FDO_MAX_CERT_CHAIN_SIZE];
	uint8_t *cert_chain = (uint8_t*)&certificate_chain;
	uint16_t *len_cert = (uint16_t*)&lengths_of_certificates;
	uint16_t total_cert_len = 0;
	uint16_t total_cert_size = 0;
	uint8_t *formatted_cert_chain = NULL;

	if (TEE_SUCCESS != fdo_heci_get_cert_chain(&fdo_cse_handle, cert_chain,
				len_cert, &fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO GET CERT CHAIN failed!! %u\n", fdo_status);
		goto err;
	}
	LOG(LOG_DEBUG, "FDO GET CERT CHAIN SUCCESS %u\n", fdo_status);

	for (int i = 0; i < FDO_ODCA_CHAIN_LEN; i++) {
		total_cert_len += lengths_of_certificates[i];
	}

	total_cert_size = total_cert_len + 2 + sizeof(lengths_of_certificates);
	formatted_cert_chain = calloc(total_cert_size, 1);
	if (formatted_cert_chain == NULL) {
		LOG(LOG_ERROR,"calloc(%u) failed\n", (unsigned)total_cert_size);
		goto err;
	}

	uint16_t *tmp_formatted_cert_chain = (uint16_t *)formatted_cert_chain;
	// memset(formatted_cert_chain, 0, total_cert_size);

	*tmp_formatted_cert_chain = __builtin_bswap16(FDO_ODCA_CHAIN_LEN);
	tmp_formatted_cert_chain++;

	for (int it = 1; it <= FDO_ODCA_CHAIN_LEN; it++) {

		*tmp_formatted_cert_chain = __builtin_bswap16(lengths_of_certificates
				[it - 1]);
		tmp_formatted_cert_chain++;
	}

	if (memcpy_s(tmp_formatted_cert_chain, total_cert_len, certificate_chain,
				total_cert_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto err;
	}

	if (memcpy_s((*cse_cert)->bytes, (*cse_cert)->byte_sz,
				formatted_cert_chain, total_cert_size) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto err;
	}
	(*cse_cert)->byte_sz = total_cert_size;

	ret = 0;
err:

	if (formatted_cert_chain) {
		fdo_free(formatted_cert_chain);
	}

	return ret;
}

/**
 * Interface to get COSE signature structure
 * @param cose_sig_structure - In Pointer to the COSE signature structure.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type uint32_t.
 * @return pointer to a byte_array holding a cose signature structure.
 */
int32_t cse_get_cose_sig_structure(fdo_byte_array_t **cose_sig_structure, uint8_t
		*data, size_t data_len)
{
	if (!data || !data_len) {
		return -1;
	}

	int ret = -1;
	fdo_byte_array_t *cose_sig_byte_arr = NULL;
	fdo_cose_t *cose = NULL;

	cose = fdo_alloc(sizeof(fdo_cose_t));
	if (!cose) {
		LOG(LOG_ERROR, "Failed to alloc COSE\n");
		goto err;
	}

	cose->cose_ph = fdo_alloc(sizeof(fdo_cose_protected_header_t));
	if (!cose->cose_ph) {
		LOG(LOG_ERROR, "Failed to alloc Protected Header\n");
		goto err;
	}

	cose->cose_payload = fdo_byte_array_alloc(data_len);
	if (!cose->cose_payload) {
		LOG(LOG_ERROR, "Failed to alloc EATPayload\n");
		goto err;
	}

	cose->cose_ph->ph_sig_alg = FDO_CRYPTO_SIG_TYPE_ECSDAp384;
	if (memcpy_s(cose->cose_payload->bytes, cose->cose_payload->byte_sz,
				data, data_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto err;
	}

	if (!fdo_cose_write_sigstructure(cose->cose_ph, cose->cose_payload, NULL,
				&cose_sig_byte_arr) || !cose_sig_byte_arr) {
		LOG(LOG_ERROR, "Failed to write COSE Sig_structure\n");
		goto err;
	}
	ret = 0;

err:
	if (cose_sig_byte_arr && ret) {
		fdo_byte_array_free(cose_sig_byte_arr);
		cose_sig_byte_arr = NULL;
	}

	if (cose) {
		fdo_cose_free(cose);
		cose = NULL;
	}

	*cose_sig_structure = cose_sig_byte_arr;
	return ret;
}

/**
 * Interface to get test signature from CSE
 * @param cse_signature - In Pointer to the CSE signature.
 * @param cse_maroeprefix - In Pointer to the CSE maroeprefix.
 * @param cose_sig_structure - In Pointer to the COSE signature structure.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type uint32_t.
 * @return pointer to a byte_array holding a valid device CSE test signature.
 */
int32_t cse_get_test_sig(fdo_byte_array_t **cse_signature, fdo_byte_array_t
		**cse_maroeprefix, fdo_byte_array_t *cose_sig_structure, uint8_t
		*data, size_t data_len)
{
	if (!cse_signature || !cse_maroeprefix || !cose_sig_structure ||
			!data || !data_len) {
		return -1;
	}

	FDO_STATUS fdo_status;
	int ret = -1;
	uint32_t mp_len;

	if (TEE_SUCCESS != fdo_heci_load_file(&fdo_cse_handle, OVH_FILE_ID,
				&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI LOAD failed!! %u\n", fdo_status);
		goto err;
	}

	if (TEE_SUCCESS != fdo_heci_update_file(&fdo_cse_handle, OVH_FILE_ID,
				data, (uint32_t)data_len, NULL, 0, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI UPDATE failed!! %u\n", fdo_status);
		goto err;
	}
	LOG(LOG_DEBUG, "FDO HECI UPDATE succeeded %u\n", fdo_status);

	if (TEE_SUCCESS != fdo_heci_commit_file(&fdo_cse_handle, OVH_FILE_ID,
				&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO OVH COMMIT failed!! %u\n", fdo_status);
		goto err;
	}
	LOG(LOG_DEBUG, "FDO OVH COMMIT succeeded %u\n", fdo_status);

	/** Note : For CSE implementation, Maroe prefix derivation have a
	 * dependency with OVH HMAC. During DI phase, We populate it with some
	 * sample data (Here Device serial) to enable test signature generation
	 */

	if (TEE_SUCCESS != fdo_heci_ecdsa_device_sign_challenge(&fdo_cse_handle,
				cose_sig_structure->bytes, cose_sig_structure->byte_sz,
				(*cse_signature)->bytes, (*cse_signature)->byte_sz,
				(*cse_maroeprefix)->bytes, &mp_len, &fdo_status) ||
			FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI ECDSA DEVICE SIGN failed!! %u\n", fdo_status);
		goto err;
	}
	(*cse_maroeprefix)->byte_sz = mp_len;

	ret = 0;
err:
	return ret;

}

/**
 * Loads the data from CSE storage
 * @param file_id - file id type Device status or OVH
 * @param data_ptr - pointer of type uint8_t, holds the plaintext message.
 * @param data_length - size of message, type uint32_t.
 * @param hmac_ptr - pointer of type uint8_t, which will be
 * by filled with HMAC.
 * @param hmac_size - size of the HMAC
 * @return status for API function
 */
int32_t cse_load_file(uint32_t file_id, uint8_t *data_ptr, uint32_t
		*data_length, uint8_t *hmac_ptr, size_t hmac_sz)
{
	if (!data_ptr || !data_length) {
		return -1;
	}

	FDO_STATUS fdo_status;
	int ret = -1;

	if (TEE_SUCCESS != fdo_heci_load_file(&fdo_cse_handle, file_id,
				&fdo_status) || FDO_STATUS_SUCCESS != fdo_status) {
		LOG(LOG_ERROR, "FDO HECI LOAD failed!! %u\n", fdo_status);
		goto err;
	}

	if (TEE_SUCCESS != fdo_heci_read_file(&fdo_cse_handle, file_id, data_ptr,
				data_length, hmac_ptr, hmac_sz, &fdo_status) || FDO_STATUS_SUCCESS !=
			fdo_status) {
		LOG(LOG_ERROR, "FDO HECI READ FILE failed!! %u\n", fdo_status);
		goto err;
	}
	LOG(LOG_DEBUG, "FDO HECI READ FILE SUCCESS %u\n", fdo_status);

	ret = 0;
err:
	return ret;

}
