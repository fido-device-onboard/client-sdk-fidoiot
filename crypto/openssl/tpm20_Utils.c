/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for TPM Operations using
 * \ tpm2.0(tpm-tools & tpm-tss-engine) and openssl library.
 */
#include "util.h"
#include "safe_lib.h"
#include "tpm20_Utils.h"
#include "fdoCryptoHal.h"
#include "storage_al.h"

static int32_t fdoTPMEsys_context_init(ESYS_CONTEXT **esys_context);
static int32_t fdoTPMEsys_auth_session_init(ESYS_CONTEXT *esys_context,
					    ESYS_TR *session_handle);
static int32_t fdoTPMTSSContext_clean_up(ESYS_CONTEXT **esys_context,
					 ESYS_TR *auth_session_handle,
					 ESYS_TR *primary_handle);
static int32_t fdoTPMGenerate_primary_key_context(ESYS_CONTEXT **esys_context,
						  ESYS_TR *primary_handle,
						  ESYS_TR *auth_session_handle);

/**
 * Generates HMAC using TPM
 *
 * @param data: pointer to the input data
 * @param data_length: length of the input data
 * @param hmac: output buffer to save the HMAC
 * @param hmac_length: length of the output HMAC buffer
 *hash length
 * @param tpmHMACPub_key: File name of the TPM HMAC public key
 * @param tpmHMACPriv_key: File name of the TPM HMAC private key
 * @return
 *	0, on success
 *	-1, on failure
 */
int32_t fdo_tpm_get_hmac(const uint8_t *data, size_t data_length, uint8_t *hmac,
			 size_t hmac_length, char *tpmHMACPub_key,
			 char *tpmHMACPriv_key)
{
	int32_t ret = -1, ret_val = -1, file_size = 0;
	size_t hashed_length = 0;
	size_t offset = 0;
	uint8_t bufferTPMHMACPriv_key[TPM_HMAC_PRIV_KEY_CONTEXT_SIZE] = {0};
	uint8_t bufferTPMHMACPub_key[TPM_HMAC_PUB_KEY_CONTEXT_SIZE] = {0};
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primary_key_handle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	ESYS_TR hmac_key_handle = ESYS_TR_NONE;
	ESYS_TR sequence_handle = ESYS_TR_NONE;
	TPMT_TK_HASHCHECK *validation = NULL;
	TPM2B_PUBLIC unmarshalHMACPub_key = {0};
	TPM2B_PRIVATE unmarshalHMACPriv_key = {0};
	TPM2B_DIGEST *outHMAC = NULL;
	TPM2B_MAX_BUFFER block = {0};
	TPM2B_AUTH null_auth = {0};

	LOG(LOG_DEBUG, "HMAC generation from TPM function called.\n");

	/* Validating all input parameters are passed in the function call*/

	if (!data || !data_length || !tpmHMACPub_key || !tpmHMACPriv_key ||
	    !hmac || (hmac_length != PLATFORM_HMAC_SIZE)) {
		LOG(LOG_ERROR,
		    "Failed to generate HMAC from TPM, invalid parameter"
		    " received.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "All required function parameters available.\n");

	/*Creating TPM Primary Key Context*/

	if (0 != fdoTPMGenerate_primary_key_context(&esys_context,
						    &primary_key_handle,
						    &auth_session_handle)) {
		LOG(LOG_ERROR,
		    "Failed to create primary key context from TPM.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM Primary Key Context created successfully.\n");

	/* Unmarshalling the HMAC Private key from the HMAC Private key file*/

	file_size = get_file_size(tpmHMACPriv_key);

	if (file_size != TPM_HMAC_PRIV_KEY_CONTEXT_SIZE_128 &&
	    file_size != TPM_HMAC_PRIV_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Private Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Private Key file size retreived successfully.\n");

	ret_val = read_buffer_from_file(tpmHMACPriv_key, bufferTPMHMACPriv_key,
					file_size);

	if (ret_val != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Private Key into buffer.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Private Key file content copied successfully"
		       " to buffer.\n");

	ret_val = Tss2_MU_TPM2B_PRIVATE_Unmarshal(
	    bufferTPMHMACPriv_key, file_size, &offset, &unmarshalHMACPriv_key);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to unmarshal TPM HMAC Private Key.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Private Key Unmarshal complete successfully.\n");

	/* Unmarshalling the HMAC Public key from the HMAC public key file*/

	file_size = get_file_size(tpmHMACPub_key);

	if (file_size != TPM_HMAC_PUB_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Private Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Public Key file size retreived successfully.\n");

	ret_val = read_buffer_from_file(tpmHMACPub_key, bufferTPMHMACPub_key,
					file_size);

	if (ret_val != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Public key into buffer.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Public Key file content copied successfully"
		       " to buffer.\n");

	offset = 0;

	ret_val = Tss2_MU_TPM2B_PUBLIC_Unmarshal(
	    bufferTPMHMACPub_key, file_size, &offset, &unmarshalHMACPub_key);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to unmarshal TPM HMAC Public Key.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Public Key Unmarshal complete successfully.\n");

	/* Loading the TPM Primary key, HMAC public key and HMAC Private Key to
	 * generate the HMAC Key Context */

	ret_val =
	    Esys_Load(esys_context, primary_key_handle, auth_session_handle,
		      ESYS_TR_NONE, ESYS_TR_NONE, &unmarshalHMACPriv_key,
		      &unmarshalHMACPub_key, &hmac_key_handle);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to load HMAC Key Context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Key Context generated successfully.\n");

	/* Generating HMAC for input data, blockwise*/

	if (data_length <= TPM2_MAX_DIGEST_BUFFER) {

		block.size = data_length;
		ret_val = memcpy_s(block.buffer, sizeof(block.buffer), data,
				   data_length);

		if (ret_val != 0) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG, "Data copied from input buffer to TPM data"
			       " structure.\n");

		ret_val =
		    Esys_HMAC(esys_context, hmac_key_handle,
			      auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
			      &block, FDO_TPM2_ALG_SHA, &outHMAC);

		if (ret_val != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG, "HMAC created successfully.\n");

	} else {

		ret_val = Esys_HMAC_Start(esys_context, hmac_key_handle,
					  auth_session_handle, ESYS_TR_NONE,
					  ESYS_TR_NONE, &null_auth,
					  FDO_TPM2_ALG_SHA, &sequence_handle);

		if (ret_val != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG,
		    "HMAC generation initiated for data sequence.\n");

		while (hashed_length != data_length) {

			if ((data_length - hashed_length) <=
			    TPM2_MAX_DIGEST_BUFFER) {

				block.size = (data_length - hashed_length);
				ret_val =
				    memcpy_s(block.buffer, sizeof(block.buffer),
					     data + hashed_length,
					     (data_length - hashed_length));

				if (ret_val != 0) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG, "Data copied from input buffer "
					       "sequence to TPM"
					       " data structure.\n");

				ret_val = Esys_SequenceComplete(
				    esys_context, sequence_handle,
				    auth_session_handle, ESYS_TR_NONE,
				    ESYS_TR_NONE, &block, TPM2_RH_NULL,
				    &outHMAC, &validation);

				if (ret_val != TSS2_RC_SUCCESS) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG, "HMAC generation for data "
					       "sequence completed"
					       " successfully.\n");
				hashed_length = data_length;

			} else {

				block.size = TPM2_MAX_DIGEST_BUFFER;
				ret_val =
				    memcpy_s(block.buffer, sizeof(block.buffer),
					     data + hashed_length,
					     TPM2_MAX_DIGEST_BUFFER);

				if (ret_val != 0) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG,
				    "Data copied from input buffer sequence"
				    " to TPM data structure.\n");

				ret_val = Esys_SequenceUpdate(
				    esys_context, sequence_handle,
				    auth_session_handle, ESYS_TR_NONE,
				    ESYS_TR_NONE, &block);

				if (ret_val != TSS2_RC_SUCCESS) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG,
				    "Sequence handle updated successfully.\n");

				hashed_length =
				    hashed_length + TPM2_MAX_DIGEST_BUFFER;
			}
		}
	}

	if (!outHMAC || (hmac_length != outHMAC->size)) {
		LOG(LOG_ERROR, "Incorrect HMAC Generated\n");
		goto err;
	}

	ret_val = memcpy_s(hmac, hmac_length, outHMAC->buffer, outHMAC->size);

	if (ret_val != 0) {
		LOG(LOG_ERROR, "Failed to copy HMAC.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "HMAC generation for data sequence completed successfully."
	    "\n");

	ret = 0;

err:
	if (esys_context) {
		if (hmac_key_handle != ESYS_TR_NONE) {
			if (Esys_FlushContext(esys_context, hmac_key_handle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush HMAC key handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG,
				    "HMAC key handle flushed successfully.\n");
				hmac_key_handle = ESYS_TR_NONE;
			}
		}
		if (0 != fdoTPMTSSContext_clean_up(&esys_context,
						   &auth_session_handle,
						   &primary_key_handle)) {
			LOG(LOG_ERROR,
			    "Failed to tear down all the TSS context.\n");
			ret = -1;
		} else {
			LOG(LOG_DEBUG, "TSS context flushed successfully.\n");
		}
	}
	TPM2_ZEROISE_FREE(validation);
	TPM2_ZEROISE_FREE(outHMAC);
	memset_s(&unmarshalHMACPriv_key, sizeof(unmarshalHMACPriv_key), 0);
	memset_s(&unmarshalHMACPub_key, sizeof(unmarshalHMACPub_key), 0);
	memset_s(bufferTPMHMACPriv_key, sizeof(bufferTPMHMACPriv_key), 0);
	memset_s(bufferTPMHMACPub_key, sizeof(bufferTPMHMACPub_key), 0);

	return ret;
}

/**
 * Generates HMAC Key inside TPM
 *
 * @param tpmHMACPub_key: File name of the TPM HMAC public key
 * @param tpmHMACPriv_key: File name of the TPM HMAC private key
 * @return
 *		0, on success
 *		-1, on failure
 */
int32_t fdo_tpm_generate_hmac_key(char *tpmHMACPub_key, char *tpmHMACPriv_key)
{
	int32_t ret = -1;
	TSS2_RC ret_val = TPM2_RC_FAILURE;
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primary_key_handle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_PRIVATE *out_private = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	TPM2B_PUBLIC in_public = in_publicHMACKey_template;
	TPM2B_SENSITIVE_CREATE in_sensitive_primary = {0};
	TPM2B_DATA outside_info = {0};
	TPML_PCR_SELECTION creationPCR = {0};
	/* Using same buffer for both public and private context,
	   private context size > public context size */
	uint8_t buffer[TPM_HMAC_PRIV_KEY_CONTEXT_SIZE] = {0};
	size_t offset = 0;

	if (!tpmHMACPub_key || !tpmHMACPriv_key) {
		LOG(LOG_ERROR, "Failed to generate HMAC Key,"
			       "invalid parameters received.\n");
		goto err;
	}

	if ((file_exists(tpmHMACPub_key) && !remove(tpmHMACPub_key)) &&
	    (file_exists(tpmHMACPriv_key) && !remove(tpmHMACPriv_key))) {
		LOG(LOG_DEBUG, "Successfully deleted old HMAC key.\n");
	} else if (file_exists(tpmHMACPub_key) ||
		   file_exists(tpmHMACPriv_key)) {
		LOG(LOG_DEBUG, "HMAC key generation failed,"
			       "failed to delete the old HMAC key.\n");
		goto err;
	}

	if (0 != fdoTPMGenerate_primary_key_context(&esys_context,
						    &primary_key_handle,
						    &auth_session_handle)) {
		LOG(LOG_ERROR,
		    "Failed to create primary key context from TPM.\n");
		goto err;
	}

	ret_val = Esys_Create(esys_context, primary_key_handle,
			      auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
			      &in_sensitive_primary, &in_public, &outside_info,
			      &creationPCR, &out_private, &out_public,
			      &creation_data, &creation_hash, &creation_ticket);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create HMAC Key.\n");
		goto err;
	}

	ret_val = Tss2_MU_TPM2B_PUBLIC_Marshal(out_public, buffer,
					       sizeof(buffer), &offset);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR,
		    "Failed to serialize the public HMAC key context.\n");
		goto err;
	}

	if ((int32_t)offset !=
	    fdo_blob_write(tpmHMACPub_key, FDO_SDK_RAW_DATA, buffer, offset)) {
		LOG(LOG_ERROR, "Failed to save the public HMAC key context.\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Saved HMAC public key context of size %zu.\n", offset);

	offset = 0;
	ret_val = Tss2_MU_TPM2B_PRIVATE_Marshal(out_private, buffer,
						sizeof(buffer), &offset);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR,
		    "Failed to serialize the private HMAC key context.\n");
		goto err;
	}

	if ((int32_t)offset !=
	    fdo_blob_write(tpmHMACPriv_key, FDO_SDK_RAW_DATA, buffer, offset)) {
		LOG(LOG_ERROR,
		    "Failed to save the private HMAC key context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Saved HMAC private key context of size %zu.\n", offset);
	LOG(LOG_DEBUG, "HMAC Key generated successfully!.\n");

	ret = 0;

err:
	TPM2_ZEROISE_FREE(out_public);
	TPM2_ZEROISE_FREE(out_private);
	TPM2_ZEROISE_FREE(creation_data);
	TPM2_ZEROISE_FREE(creation_hash);
	TPM2_ZEROISE_FREE(creation_ticket);

	if (esys_context &&
	    (0 != fdoTPMTSSContext_clean_up(&esys_context, &auth_session_handle,
					    &primary_key_handle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
	}

	return ret;
}

/**
 * Generate TPM Primary key Context from endorsement Hierarchy
 *
 * @param esys_context : output Esys Context
 * @param primary_key_handle : output primary key handle
 * @param auth_session_handle : output auth sesson handle for Esys API
 * @return
 *		0, on success
 *		-1, on failure
 */
static int32_t fdoTPMGenerate_primary_key_context(ESYS_CONTEXT **esys_context,
						  ESYS_TR *primary_key_handle,
						  ESYS_TR *auth_session_handle)
{
	int ret = -1;
	TSS2_RC ret_val = TPM2_RC_FAILURE;
	TPM2B_SENSITIVE_CREATE in_sensitive_primary = {0};
	TPM2B_DATA outside_info = {0};
	TPML_PCR_SELECTION creationPCR = {0};
	TPM2B_PUBLIC *out_public = NULL;
	TPM2B_CREATION_DATA *creation_data = NULL;
	TPM2B_DIGEST *creation_hash = NULL;
	TPMT_TK_CREATION *creation_ticket = NULL;
	TPM2B_PUBLIC in_public = in_public_primary_key_template;

	if (!esys_context || !primary_key_handle || !auth_session_handle) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Generate Primary key context.\n");

	if (0 != fdoTPMEsys_context_init(esys_context) || (!*esys_context)) {
		LOG(LOG_ERROR, "Failed to Create Esys Context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Esys Context created succesfully!!\n");

	if (0 !=
	    fdoTPMEsys_auth_session_init(*esys_context, auth_session_handle)) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	ret_val = Esys_CreatePrimary(
	    *esys_context, ESYS_TR_RH_ENDORSEMENT, *auth_session_handle,
	    ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive_primary, &in_public,
	    &outside_info, &creationPCR, primary_key_handle, &out_public,
	    &creation_data, &creation_hash, &creation_ticket);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create primary key.\n");
		goto err;
	}

	ret = 0;
	goto out;

err:
	if (esys_context && *esys_context) {
		fdoTPMTSSContext_clean_up(esys_context, auth_session_handle,
					  primary_key_handle);
	}

out:
	TPM2_ZEROISE_FREE(out_public);
	TPM2_ZEROISE_FREE(creation_data);
	TPM2_ZEROISE_FREE(creation_hash);
	TPM2_ZEROISE_FREE(creation_ticket);

	return ret;
}

/**
 * Initialize Esys context.
 *
 * @param esys_context : output Esys Context
 *
 * @return
 *		0, on success
 *		-1, on failure
 */
static int32_t fdoTPMEsys_context_init(ESYS_CONTEXT **esys_context)
{
	int ret = -1;
	TSS2_TCTI_CONTEXT *tcti_context = NULL;

	if (!esys_context) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		goto err;
	}

	if ((TSS2_RC_SUCCESS !=
	     Tss2_TctiLdr_Initialize(TPM2_TCTI_TYPE, &tcti_context)) ||
	    (!tcti_context)) {
		LOG(LOG_ERROR, "TCTI Context initialization failed.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TCTI Initialized succesfully!!\n");

	if (Esys_Initialize(esys_context, tcti_context, NULL) !=
	    TPM2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	return 0;

err:
	if (tcti_context) {
		Tss2_TctiLdr_Finalize(&tcti_context);
	}
	return ret;
}

/**
 * Create HMAC based auth session for Esys Context
 *
 * @param esys_context : input Esys Context
 * @param session_handle : output authentication session Handle
 *
 * @return
 *	0, on success
 *	-1, on failure
 */
static int32_t fdoTPMEsys_auth_session_init(ESYS_CONTEXT *esys_context,
					    ESYS_TR *session_handle)
{
	int ret = -1;
	TPMT_SYM_DEF symmetric = {0};
	symmetric.algorithm = TPM2_ALG_NULL;

	TSS2_RC rval = Esys_StartAuthSession(
	    esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
	    ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmetric,
	    FDO_TPM2_ALG_SHA, session_handle);

	if (rval != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start the auth session.\n");
		return ret;
	}

	return 0;
}

/**
 * Clear Esys, TCTI, contexts and Auth Session, Primary Key handles.
 *
 * @param esys_context : Esys Context to be cleared
 * @param auth_session_handle : Auth session Handle to be flushed
 * @param primary_handle : Primary key handle to be cleared
 * @return
 *	0, on success
 *	-1, on failure
 */
static int32_t fdoTPMTSSContext_clean_up(ESYS_CONTEXT **esys_context,
					 ESYS_TR *auth_session_handle,
					 ESYS_TR *primary_handle)
{
	int ret = -1, is_failed = 0;
	TSS2_TCTI_CONTEXT *tcti_context = NULL;
	TSS2_RC rc = TPM2_RC_FAILURE;

	if (!esys_context || !*esys_context) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		return ret;
	}

	if (auth_session_handle && (*auth_session_handle != ESYS_TR_NONE)) {
		if (Esys_FlushContext(*esys_context, *auth_session_handle) !=
		    TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR,
			    "Failed to flush auth session handle.\n");
			is_failed = 1;
		} else {
			LOG(LOG_DEBUG,
			    "Auth session handle flushed successfully.\n");
			*auth_session_handle = ESYS_TR_NONE;
		}
	}

	if (primary_handle && (*primary_handle != ESYS_TR_NONE)) {
		if (Esys_FlushContext(*esys_context, *primary_handle) !=
		    TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to flush primary key handle.\n");
			is_failed = 1;
		} else {
			LOG(LOG_DEBUG,
			    "Primary key handle flushed successfully.\n");
			*primary_handle = ESYS_TR_NONE;
		}
	}

	rc = Esys_GetTcti(*esys_context, &tcti_context);
	if (rc != TPM2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to cleanup TCTI.\n");
		is_failed = 1;
	}
	Esys_Finalize(esys_context);

	if (tcti_context) {
		Tss2_TctiLdr_Finalize(&tcti_context);
		if (tcti_context) {
			LOG(LOG_ERROR, "Failed to finalize context.\n");
			is_failed = 1;
		}
	}

	if (is_failed) {
		return ret;
	}

	return 0;
}

/**
 * Replace the TPM_HMAC_PRIV_KEY with TPM_HMAC_REPLACEMENT_PRIV_KEY and
 * TPM_HMAC_PUB_KEY with TPM_HMAC_REPLACEMENT_PUB_KEY.
 *
 * @return
 *		-1, error
 *		0, success
 */
int32_t fdo_tpm_commit_replacement_hmac_key(void)
{
	size_t file_size = 0;
	// internal return value
	int32_t ret_val = -1;
	// function return value
	int32_t ret = -1;
	uint8_t bufferTPMHMACPriv_key[TPM_HMAC_PRIV_KEY_CONTEXT_SIZE] = {0};
	uint8_t bufferTPMHMACPub_key[TPM_HMAC_PUB_KEY_CONTEXT_SIZE] = {0};

	if (!file_exists(TPM_HMAC_PRIV_KEY) ||
		!file_exists(TPM_HMAC_PUB_KEY) ||
		!file_exists(TPM_HMAC_REPLACEMENT_PRIV_KEY) ||
		!file_exists(TPM_HMAC_REPLACEMENT_PUB_KEY)) {
		LOG(LOG_ERROR, "One or more HMAC objects are missing.\n");
		goto err;
	}

	// read TPM_HMAC_REPLACEMENT_PRIV_KEY contents and write it into TPM_HMAC_PRIV_KEY
	file_size = get_file_size(TPM_HMAC_REPLACEMENT_PRIV_KEY);

	if (file_size != TPM_HMAC_PRIV_KEY_CONTEXT_SIZE_128 &&
	    file_size != TPM_HMAC_PRIV_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Replacement Private Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Replacement Private Key file size retreived successfully.\n");

	ret_val = read_buffer_from_file(TPM_HMAC_REPLACEMENT_PRIV_KEY, bufferTPMHMACPriv_key,
					file_size);

	if (ret_val != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Replacement Private Key into buffer.\n");
		goto err;
	}

	if ((int32_t)file_size !=
	    fdo_blob_write(TPM_HMAC_PRIV_KEY, FDO_SDK_RAW_DATA,
			bufferTPMHMACPriv_key, file_size)) {
		LOG(LOG_ERROR, "Failed to save the private HMAC key context.\n");
		goto err;
	}

	// now, read TPM_HMAC_REPLACEMENT_PUB_KEY contents and write it into TPM_HMAC_PUB_KEY
	file_size = get_file_size(TPM_HMAC_REPLACEMENT_PUB_KEY);

	if (file_size != TPM_HMAC_PUB_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Replacement Public Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Replacement Public Key file size retreived successfully.\n");

	ret_val = read_buffer_from_file(TPM_HMAC_REPLACEMENT_PUB_KEY, bufferTPMHMACPub_key,
					file_size);

	if (ret_val != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Replacement Public key into buffer.\n");
		goto err;
	}

	if ((int32_t)file_size !=
	    fdo_blob_write(TPM_HMAC_PUB_KEY, FDO_SDK_RAW_DATA,
			bufferTPMHMACPub_key, file_size)) {
		LOG(LOG_ERROR, "Failed to save the public HMAC key context.\n");
		goto err;
	}
	ret = 0;
err:
	return ret;
}

/**
 * Clear the Replacement TPM HMAC key objects, if they exist.
 *
 */
void fdo_tpm_clear_replacement_hmac_key(void) {
	// remove the files if they exist, else return
	if (file_exists(TPM_HMAC_REPLACEMENT_PRIV_KEY)) {
		if (0 != remove(TPM_HMAC_REPLACEMENT_PRIV_KEY)) {
			LOG(LOG_ERROR, "Failed to cleanup private object\n");
		}
	}
	if (file_exists(TPM_HMAC_REPLACEMENT_PUB_KEY)) {
		if (0 != remove(TPM_HMAC_REPLACEMENT_PUB_KEY)) {
			LOG(LOG_ERROR, "Failed to cleanup public object\n");
		}
	}
}

/**
 * Check whether valid data integrity protection HMAC key is present or not.
 *
 * @return
 *		1, present
 *		0, not present
 */
int32_t is_valid_tpm_data_protection_key_present(void)
{
	return (file_exists(TPM_HMAC_DATA_PUB_KEY) &&
		(TPM_HMAC_PUB_KEY_CONTEXT_SIZE ==
		 get_file_size(TPM_HMAC_DATA_PUB_KEY)) &&
		file_exists(TPM_HMAC_DATA_PRIV_KEY) &&
		(TPM_HMAC_PRIV_KEY_CONTEXT_SIZE_128 ==
		 get_file_size(TPM_HMAC_DATA_PRIV_KEY) ||
		TPM_HMAC_PRIV_KEY_CONTEXT_SIZE ==
		 get_file_size(TPM_HMAC_DATA_PRIV_KEY)));
}
