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
#include "sdoCryptoHal.h"
#include "storage_al.h"

static int32_t sdoTPMEsysContextInit(ESYS_CONTEXT **esysContext);
static int32_t sdoTPMEsysAuthSessionInit(ESYS_CONTEXT *esysContext,
					 ESYS_TR *sessionHandle);
static int32_t sdoTPMTSSContextCleanUp(ESYS_CONTEXT **esysContext,
				       ESYS_TR *authSessionHandle,
				       ESYS_TR *primaryHandle);
static int32_t sdoTPMGeneratePrimaryKeyContext(ESYS_CONTEXT **esysContext,
					       ESYS_TR *primaryHandle,
					       ESYS_TR *authSessionHandle);

/**
 * Generates HMAC using TPM
 *
 * @param data: pointer to the input data
 * @param dataLength: length of the input data
 * @param hmac: output buffer to save the HMAC
 * @param hmacLength: length of the output HMAC buffer, equal to the SHA256 hash
 *length
 * @param tpmHMACPubKey: File name of the TPM HMAC public key
 * @param tpmHMACPrivKey: File name of the TPM HMAC private key
 * @return
 *	0, on success
 *	-1, on failure
 */
int32_t sdoTPMGetHMAC(const uint8_t *data, size_t dataLength, uint8_t *hmac,
		      size_t hmacLength, char *tpmHMACPubKey,
		      char *tpmHMACPrivKey)
{
	int32_t ret = -1, retVal = -1, fileSize = 0;
	size_t hashedLength = 0;
	size_t offset = 0;
	uint8_t bufferTPMHMACPrivKey[TPM_HMAC_PRIV_KEY_CONTEXT_SIZE] = {0};
	uint8_t bufferTPMHMACPubKey[TPM_HMAC_PUB_KEY_CONTEXT_SIZE] = {0};
	ESYS_CONTEXT *esysContext = NULL;
	ESYS_TR primaryKeyHandle = ESYS_TR_NONE;
	ESYS_TR authSessionHandle = ESYS_TR_NONE;
	ESYS_TR hmacKeyHandle = ESYS_TR_NONE;
	ESYS_TR sequenceHandle = ESYS_TR_NONE;
	TPMT_TK_HASHCHECK *validation = NULL;
	TPM2B_PUBLIC unmarshalHMACPubKey = {0};
	TPM2B_PRIVATE unmarshalHMACPrivKey = {0};
	TPM2B_DIGEST *outHMAC = NULL;
	TPM2B_MAX_BUFFER block = {0};
	TPM2B_AUTH nullAuth = {0};

	LOG(LOG_DEBUG, "HMAC generation from TPM function called.\n");

	/* Validating all input parameters are passed in the function call*/

	if (!data || !dataLength || !tpmHMACPubKey || !tpmHMACPrivKey ||
	    !hmac || (hmacLength != SHA256_DIGEST_SIZE)) {
		LOG(LOG_ERROR,
		    "Failed to generate HMAC from TPM, invalid parameter"
		    " received.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "All required function parameters available.\n");

	/*Creating TPM Primary Key Context*/

	if (0 != sdoTPMGeneratePrimaryKeyContext(
		     &esysContext, &primaryKeyHandle, &authSessionHandle)) {
		LOG(LOG_ERROR,
		    "Failed to create primary key context from TPM.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM Primary Key Context created successfully.\n");

	/* Unmarshalling the HMAC Private key from the HMAC Private key file*/

	fileSize = get_file_size(tpmHMACPrivKey);

	if (fileSize != TPM_HMAC_PRIV_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Private Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Private Key file size retreived successfully.\n");

	retVal = read_buffer_from_file(tpmHMACPrivKey, bufferTPMHMACPrivKey,
				       fileSize);

	if (retVal != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Private Key into buffer.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Private Key file content copied successfully"
		       " to buffer.\n");

	retVal = Tss2_MU_TPM2B_PRIVATE_Unmarshal(
	    bufferTPMHMACPrivKey, fileSize, &offset, &unmarshalHMACPrivKey);

	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to unmarshal TPM HMAC Private Key.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Private Key Unmarshal complete successfully.\n");

	/* Unmarshalling the HMAC Public key from the HMAC public key file*/

	fileSize = get_file_size(tpmHMACPubKey);

	if (fileSize != TPM_HMAC_PUB_KEY_CONTEXT_SIZE) {
		LOG(LOG_ERROR, "TPM HMAC Private Key file size incorrect.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Public Key file size retreived successfully.\n");

	retVal =
	    read_buffer_from_file(tpmHMACPubKey, bufferTPMHMACPubKey, fileSize);

	if (retVal != 0) {
		LOG(LOG_ERROR,
		    "Failed to load TPM HMAC Public key into buffer.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Public Key file content copied successfully"
		       " to buffer.\n");

	offset = 0;

	retVal = Tss2_MU_TPM2B_PUBLIC_Unmarshal(bufferTPMHMACPubKey, fileSize,
						&offset, &unmarshalHMACPubKey);

	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to unmarshal TPM HMAC Public Key.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "TPM HMAC Public Key Unmarshal complete successfully.\n");

	/* Loading the TPM Primary key, HMAC public key and HMAC Private Key to
	 * generate the HMAC Key Context */

	retVal = Esys_Load(esysContext, primaryKeyHandle, authSessionHandle,
			   ESYS_TR_NONE, ESYS_TR_NONE, &unmarshalHMACPrivKey,
			   &unmarshalHMACPubKey, &hmacKeyHandle);

	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to load HMAC Key Context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TPM HMAC Key Context generated successfully.\n");

	/* Generating HMAC for input data, blockwise*/

	if (dataLength <= TPM2_MAX_DIGEST_BUFFER) {

		block.size = dataLength;
		retVal = memcpy_s(block.buffer, sizeof(block.buffer), data,
				  dataLength);

		if (retVal != 0) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG, "Data copied from input buffer to TPM data"
			       " structure.\n");

		retVal = Esys_HMAC(
		    esysContext, hmacKeyHandle, authSessionHandle, ESYS_TR_NONE,
		    ESYS_TR_NONE, &block, TPM2_ALG_SHA256, &outHMAC);

		if (retVal != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG, "HMAC created successfully.\n");

	} else {

		retVal = Esys_HMAC_Start(
		    esysContext, hmacKeyHandle, authSessionHandle, ESYS_TR_NONE,
		    ESYS_TR_NONE, &nullAuth, TPM2_ALG_SHA256, &sequenceHandle);

		if (retVal != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to create HMAC.\n");
			goto err;
		}

		LOG(LOG_DEBUG,
		    "HMAC generation initiated for data sequence.\n");

		while (hashedLength != dataLength) {

			if ((dataLength - hashedLength) <=
			    TPM2_MAX_DIGEST_BUFFER) {

				block.size = (dataLength - hashedLength);
				retVal =
				    memcpy_s(block.buffer, sizeof(block.buffer),
					     data + hashedLength,
					     (dataLength - hashedLength));

				if (retVal != 0) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG, "Data copied from input buffer "
					       "sequence to TPM"
					       " data structure.\n");

				retVal = Esys_SequenceComplete(
				    esysContext, sequenceHandle,
				    authSessionHandle, ESYS_TR_NONE,
				    ESYS_TR_NONE, &block, TPM2_RH_NULL,
				    &outHMAC, &validation);

				if (retVal != TSS2_RC_SUCCESS) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG, "HMAC generation for data "
					       "sequence completed"
					       " successfully.\n");
				hashedLength = dataLength;

			} else {

				block.size = TPM2_MAX_DIGEST_BUFFER;
				retVal =
				    memcpy_s(block.buffer, sizeof(block.buffer),
					     data + hashedLength,
					     TPM2_MAX_DIGEST_BUFFER);

				if (retVal != 0) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG,
				    "Data copied from input buffer sequence"
				    " to TPM data structure.\n");

				retVal = Esys_SequenceUpdate(
				    esysContext, sequenceHandle,
				    authSessionHandle, ESYS_TR_NONE,
				    ESYS_TR_NONE, &block);

				if (retVal != TSS2_RC_SUCCESS) {
					LOG(LOG_ERROR,
					    "Failed to create HMAC.\n");
					goto err;
				}

				LOG(LOG_DEBUG,
				    "Sequence handle updated successfully.\n");

				hashedLength =
				    hashedLength + TPM2_MAX_DIGEST_BUFFER;
			}
		}
	}

	if (!outHMAC || (hmacLength != outHMAC->size)) {
		LOG(LOG_ERROR, "Incorrect HMAC Generated\n");
		goto err;
	}

	retVal = memcpy_s(hmac, hmacLength, outHMAC->buffer, outHMAC->size);

	if (retVal != 0) {
		LOG(LOG_ERROR, "Failed to copy HMAC.\n");
		goto err;
	}

	LOG(LOG_DEBUG,
	    "HMAC generation for data sequence completed successfully."
	    "\n");

	ret = 0;

err:
	if (esysContext) {
		if (hmacKeyHandle != ESYS_TR_NONE) {
			if (Esys_FlushContext(esysContext, hmacKeyHandle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush HMAC key handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG,
				    "HMAC key handle flushed successfully.\n");
				hmacKeyHandle = ESYS_TR_NONE;
			}
		}
		if (0 != sdoTPMTSSContextCleanUp(&esysContext,
						 &authSessionHandle,
						 &primaryKeyHandle)) {
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
 * @param tpmHMACPubKey: File name of the TPM HMAC public key
 * @param tpmHMACPrivKey: File name of the TPM HMAC private key
 * @return
 *		0, on success
 *		-1, on failure
 */
int32_t sdoTPMGenerateHMACKey(char *tpmHMACPubKey, char *tpmHMACPrivKey)
{
	int32_t ret = -1;
	TSS2_RC retVal = TPM2_RC_FAILURE;
	ESYS_CONTEXT *esysContext = NULL;
	ESYS_TR primaryKeyHandle = ESYS_TR_NONE;
	ESYS_TR authSessionHandle = ESYS_TR_NONE;
	TPM2B_PUBLIC *outPublic = NULL;
	TPM2B_PRIVATE *outPrivate = NULL;
	TPM2B_CREATION_DATA *creationData = NULL;
	TPM2B_DIGEST *creationHash = NULL;
	TPMT_TK_CREATION *creationTicket = NULL;
	TPM2B_PUBLIC inPublic = inPublicHMACKeyTemplate;
	TPM2B_SENSITIVE_CREATE inSensitivePrimary = {0};
	TPM2B_DATA outsideInfo = {0};
	TPML_PCR_SELECTION creationPCR = {0};
	/* Using same buffer for both public and private context,
	   private context size > public context size */
	uint8_t buffer[TPM_HMAC_PRIV_KEY_CONTEXT_SIZE] = {0};
	size_t offset = 0;

	if (!tpmHMACPubKey || !tpmHMACPrivKey) {
		LOG(LOG_ERROR, "Failed to generate HMAC Key,"
			       "invalid parameters received.\n");
		goto err;
	}

	if ((file_exists(tpmHMACPubKey) && !remove(tpmHMACPubKey)) &&
	    (file_exists(tpmHMACPrivKey) && !remove(tpmHMACPrivKey))) {
		LOG(LOG_DEBUG, "Successfully deleted old HMAC key.\n");
	} else if (file_exists(tpmHMACPubKey) || file_exists(tpmHMACPrivKey)) {
		LOG(LOG_DEBUG, "HMAC key generation failed,"
			       "failed to delete the old HMAC key.\n");
		goto err;
	}

	if (0 != sdoTPMGeneratePrimaryKeyContext(
		     &esysContext, &primaryKeyHandle, &authSessionHandle)) {
		LOG(LOG_ERROR,
		    "Failed to create primary key context from TPM.\n");
		goto err;
	}

	retVal = Esys_Create(esysContext, primaryKeyHandle, authSessionHandle,
			     ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
			     &inPublic, &outsideInfo, &creationPCR, &outPrivate,
			     &outPublic, &creationData, &creationHash,
			     &creationTicket);

	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create HMAC Key.\n");
		goto err;
	}

	retVal = Tss2_MU_TPM2B_PUBLIC_Marshal(outPublic, buffer, sizeof(buffer),
					      &offset);
	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR,
		    "Failed to serialize the public HMAC key context.\n");
		goto err;
	}
	if (offset !=
	    sdoBlobWrite(tpmHMACPubKey, SDO_SDK_RAW_DATA, buffer, offset)) {
		LOG(LOG_ERROR, "Failed to save the public HMAC key context.\n");
		goto err;
	}
	LOG(LOG_DEBUG, "Saved HMAC public key context of size %zu.\n", offset);

	offset = 0;
	retVal = Tss2_MU_TPM2B_PRIVATE_Marshal(outPrivate, buffer,
					       sizeof(buffer), &offset);
	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR,
		    "Failed to serialize the private HMAC key context.\n");
		goto err;
	}

	if (offset !=
	    sdoBlobWrite(tpmHMACPrivKey, SDO_SDK_RAW_DATA, buffer, offset)) {
		LOG(LOG_ERROR,
		    "Failed to save the private HMAC key context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Saved HMAC private key context of size %zu.\n", offset);
	LOG(LOG_DEBUG, "HMAC Key generated successfully!.\n");

	ret = 0;

err:
	TPM2_ZEROISE_FREE(outPublic);
	TPM2_ZEROISE_FREE(outPrivate);
	TPM2_ZEROISE_FREE(creationData);
	TPM2_ZEROISE_FREE(creationHash);
	TPM2_ZEROISE_FREE(creationTicket);

	if (esysContext &&
	    (0 != sdoTPMTSSContextCleanUp(&esysContext, &authSessionHandle,
					  &primaryKeyHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
	}

	return ret;
}

/**
 * Generate TPM Primary key Context from endorsement Hierarchy
 *
 * @param esysContext : output Esys Context
 * @param primaryKeyHandle : output primary key handle
 * @param authSessionHandle : output auth sesson handle for Esys API
 * @return
 *		0, on success
 *		-1, on failure
 */
static int32_t sdoTPMGeneratePrimaryKeyContext(ESYS_CONTEXT **esysContext,
					       ESYS_TR *primaryKeyHandle,
					       ESYS_TR *authSessionHandle)
{
	int ret = -1;
	TSS2_RC retVal = TPM2_RC_FAILURE;
	TPM2B_SENSITIVE_CREATE inSensitivePrimary = {0};
	TPM2B_DATA outsideInfo = {0};
	TPML_PCR_SELECTION creationPCR = {0};
	TPM2B_PUBLIC *outPublic = NULL;
	TPM2B_CREATION_DATA *creationData = NULL;
	TPM2B_DIGEST *creationHash = NULL;
	TPMT_TK_CREATION *creationTicket = NULL;
	TPM2B_PUBLIC inPublic = inPublicPrimaryKeyTemplate;

	if (!esysContext || !primaryKeyHandle || !authSessionHandle) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Generate Primary key context.\n");

	if (0 != sdoTPMEsysContextInit(esysContext) || (!*esysContext)) {
		LOG(LOG_ERROR, "Failed to Create Esys Context.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "Esys Context created succesfully!!\n");

	if (0 != sdoTPMEsysAuthSessionInit(*esysContext, authSessionHandle)) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	retVal = Esys_CreatePrimary(
	    *esysContext, ESYS_TR_RH_ENDORSEMENT, *authSessionHandle,
	    ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary, &inPublic,
	    &outsideInfo, &creationPCR, primaryKeyHandle, &outPublic,
	    &creationData, &creationHash, &creationTicket);

	if (retVal != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create primary key.\n");
		goto err;
	}

	ret = 0;
	goto out;

err:
	if (esysContext && *esysContext) {
		sdoTPMTSSContextCleanUp(esysContext, authSessionHandle,
					primaryKeyHandle);
	}

out:
	TPM2_ZEROISE_FREE(outPublic);
	TPM2_ZEROISE_FREE(creationData);
	TPM2_ZEROISE_FREE(creationHash);
	TPM2_ZEROISE_FREE(creationTicket);

	return ret;
}

/**
 * Initialize Esys context.
 *
 * @param esysContext : output Esys Context
 *
 * @return
 *		0, on success
 *		-1, on failure
 */
static int32_t sdoTPMEsysContextInit(ESYS_CONTEXT **esysContext)
{
	int ret = -1;
	TSS2_TCTI_CONTEXT *tctiContext = NULL;

	if (!esysContext) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		goto err;
	}

	if ((TSS2_RC_SUCCESS !=
	     Tss2_TctiLdr_Initialize(TPM2_TCTI_TYPE, &tctiContext)) ||
	    (!tctiContext)) {
		LOG(LOG_ERROR, "TCTI Context initialization failed.\n");
		goto err;
	}

	LOG(LOG_DEBUG, "TCTI Initialized succesfully!!\n");

	if (Esys_Initialize(esysContext, tctiContext, NULL) !=
	    TPM2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	return 0;

err:
	if (tctiContext) {
		Tss2_TctiLdr_Finalize(&tctiContext);
	}
	return ret;
}

/**
 * Create HMAC based auth session for Esys Context
 *
 * @param esysContext : input Esys Context
 * @param sessionHandle : output authentication session Handle
 *
 * @return
 *	0, on success
 *	-1, on failure
 */
static int32_t sdoTPMEsysAuthSessionInit(ESYS_CONTEXT *esysContext,
					 ESYS_TR *sessionHandle)
{
	int ret = -1;
	TPMT_SYM_DEF symmetric = {0};
	symmetric.algorithm = TPM2_ALG_NULL;

	TSS2_RC rval = Esys_StartAuthSession(
	    esysContext, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
	    ESYS_TR_NONE, NULL, TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA256,
	    sessionHandle);
	if (rval != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start the auth session.\n");
		return ret;
	}

	return 0;
}

/**
 * Clear Esys, TCTI, contexts and Auth Session, Primary Key handles.
 *
 * @param esysContext : Esys Context to be cleared
 * @param authSessionHandle : Auth session Handle to be flushed
 * @param primaryHandle : Primary key handle to be cleared
 * @return
 *	0, on success
 *	-1, on failure
 */
static int32_t sdoTPMTSSContextCleanUp(ESYS_CONTEXT **esysContext,
				       ESYS_TR *authSessionHandle,
				       ESYS_TR *primaryHandle)
{
	int ret = -1, isFailed = 0;
	TSS2_TCTI_CONTEXT *tctiContext = NULL;

	if (!esysContext || !*esysContext) {
		LOG(LOG_ERROR, "Invalid parameter received.\n");
		return ret;
	}

	if (authSessionHandle && (*authSessionHandle != ESYS_TR_NONE)) {
		if (Esys_FlushContext(*esysContext, *authSessionHandle) !=
		    TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR,
			    "Failed to flush auth session handle.\n");
			isFailed = 1;
		} else {
			LOG(LOG_DEBUG,
			    "Auth session handle flushed successfully.\n");
			*authSessionHandle = ESYS_TR_NONE;
		}
	}

	if (primaryHandle && (*primaryHandle != ESYS_TR_NONE)) {
		if (Esys_FlushContext(*esysContext, *primaryHandle) !=
		    TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to flush primary key handle.\n");
			isFailed = 1;
		} else {
			LOG(LOG_DEBUG,
			    "Primary key handle flushed successfully.\n");
			*primaryHandle = ESYS_TR_NONE;
		}
	}

	Esys_GetTcti(*esysContext, &tctiContext);
	Esys_Finalize(esysContext);

	if (tctiContext) {
		Tss2_TctiLdr_Finalize(&tctiContext);
	}

	if (isFailed) {
		return ret;
	}

	return 0;
}

/**
 * Check whether valid data integrity protection HMAC key is present or not.
 *
 * @return
 *		1, present
 *		0, not present
 */
int32_t isValidTPMDataProtectionKeyPresent(void)
{
	return (file_exists(TPM_HMAC_DATA_PUB_KEY) &&
		(TPM_HMAC_PUB_KEY_CONTEXT_SIZE ==
		 get_file_size(TPM_HMAC_DATA_PUB_KEY)) &&
		file_exists(TPM_HMAC_DATA_PRIV_KEY) &&
		(TPM_HMAC_PRIV_KEY_CONTEXT_SIZE ==
		 get_file_size(TPM_HMAC_DATA_PRIV_KEY)));
}
