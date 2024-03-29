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
#include "tpm2_nv_storage.h"
#include "tpm20_Utils.h"
#include "fdo_crypto_hal.h"
#include "storage_al.h"

/**
 * Generates HMAC using TPM
 *
 * @param data: pointer to the input data
 * @param data_length: length of the input data
 * @param hmac: output buffer to save the HMAC
 * @param hmac_length: length of the output HMAC buffer
 *hash length
 * @param persistent_handle: Persistent handle of the TPM HMAC public key
 * @return
 *	0, on success
 *	-1, on failure
 */
int32_t fdo_tpm_get_hmac(const uint8_t *data, size_t data_length, uint8_t *hmac,
			 size_t hmac_length,
			 TPMI_DH_PERSISTENT persistent_handle)
{
	int32_t ret = -1, ret_val = -1;
	size_t hashed_length = 0;
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primary_key_handle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	ESYS_TR hmac_key_handle = ESYS_TR_NONE;
	ESYS_TR sequence_handle = ESYS_TR_NONE;
	TPMT_TK_HASHCHECK *validation = NULL;
	TPM2B_DIGEST *outHMAC = NULL;
	TPM2B_MAX_BUFFER block = {0};
	TPM2B_AUTH null_auth = {0};

	LOG(LOG_DEBUG, "HMAC generation from TPM function called.\n");

	/* Validating all input parameters are passed in the function call*/

	if (!data || !data_length || !persistent_handle || !hmac ||
	    (hmac_length != PLATFORM_HMAC_SIZE)) {
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

	/* Loading the TPM Primary key, HMAC public key and HMAC Private Key to
	 * generate the HMAC Key Context */

	ret_val =
	    Esys_TR_FromTPMPublic(esys_context, persistent_handle, ESYS_TR_NONE,
				  ESYS_TR_NONE, ESYS_TR_NONE, &hmac_key_handle);

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
			if (Esys_TR_Close(esys_context, &hmac_key_handle) !=
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

	return ret;
}

/**
 * Generates HMAC Key inside TPM
 *
 * @param persistent_handle: Persistent handle of the TPM HMAC key
 * @return
 *		0, on success
 *		-1, on failure
 */
int32_t fdo_tpm_generate_hmac_key(TPMI_DH_PERSISTENT persistent_handle)
{
	int32_t ret = -1;
	TSS2_RC ret_val = TPM2_RC_FAILURE;
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primary_key_handle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	ESYS_TR object_handle = ESYS_TR_NONE;
	ESYS_TR pub_object_handle = ESYS_TR_NONE;
	ESYS_TR persistentHandle = ESYS_TR_NONE;
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

	if (!persistent_handle) {
		LOG(LOG_ERROR, "Failed to generate HMAC Key,"
			       "invalid parameters received.\n");
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

	ret_val = Esys_Load(esys_context, primary_key_handle,
			    auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
			    out_private, out_public, &object_handle);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_Load failed: 0x%x\n", ret_val);
		Esys_Finalize(&esys_context);
		goto err;
	}

	// Search the persistent Handle
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	ret_val = Esys_GetCapability(
	    esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
	    TPM2_CAP_HANDLES, persistent_handle, 1, NULL, &capability_data);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_GetCapability failed!\n");
		goto err;
	}

	int exists =
	    (capability_data->data.handles.count > 0 &&
	     capability_data->data.handles.handle[0] == persistent_handle);
	if (exists == 1) {
		ret_val = Esys_TR_FromTPMPublic(
		    esys_context, persistent_handle, ESYS_TR_NONE, ESYS_TR_NONE,
		    ESYS_TR_NONE, &persistentHandle);

		if (ret_val != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to load HMAC Key Context.\n");
			goto err;
		}

		ret_val = Esys_EvictControl(
		    esys_context, ESYS_TR_RH_OWNER, persistentHandle,
		    auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE, 0,
		    &pub_object_handle);
		if (ret_val != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Esys_EvictControl failed: 0x%x\n",
			    ret_val);
			Esys_Finalize(&esys_context);
			goto err;
		}
	}

	ret_val = Esys_EvictControl(
	    esys_context, ESYS_TR_RH_OWNER, object_handle, auth_session_handle,
	    ESYS_TR_NONE, ESYS_TR_NONE, persistent_handle, &pub_object_handle);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_EvictControl failed: 0x%x\n", ret_val);
		goto err;
	}

	LOG(LOG_DEBUG,
	    "Saved HMAC private key context inside persistance memory at  "
	    "%d.\n",
	    persistent_handle);
	LOG(LOG_DEBUG, "HMAC Key generated successfully!.\n");

	ret = 0;

err:
	TPM2_ZEROISE_FREE(out_public);
	TPM2_ZEROISE_FREE(out_private);
	TPM2_ZEROISE_FREE(creation_data);
	TPM2_ZEROISE_FREE(creation_hash);
	TPM2_ZEROISE_FREE(creation_ticket);

	if (esys_context) {
		if (object_handle != ESYS_TR_NONE) {
			if (Esys_TR_Close(esys_context, &object_handle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush object_handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG,
				    "object_handle flushed successfully.\n");
				object_handle = ESYS_TR_NONE;
			}
		}

		if (pub_object_handle != ESYS_TR_NONE) {
			if (Esys_TR_Close(esys_context, &pub_object_handle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush pub_object_handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG, "pub_object_handle flushed "
					       "successfully.\n");
				pub_object_handle = ESYS_TR_NONE;
			}
		}

		if (persistentHandle != ESYS_TR_NONE) {
			if (Esys_TR_Close(esys_context, &persistentHandle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush persistent handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG, "persistent handle flushed "
					       "successfully.\n");
				persistentHandle = ESYS_TR_NONE;
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
int32_t fdoTPMGenerate_primary_key_context(ESYS_CONTEXT **esys_context,
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
int32_t fdoTPMEsys_context_init(ESYS_CONTEXT **esys_context)
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
int32_t fdoTPMEsys_auth_session_init(ESYS_CONTEXT *esys_context,
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
int32_t fdoTPMTSSContext_clean_up(ESYS_CONTEXT **esys_context,
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
