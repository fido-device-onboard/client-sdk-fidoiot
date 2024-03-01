/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \ brief Abstraction layer for ECDSA signing routine using
 * \ tpm2.0(tpm-tss & tpm-tss-engine) and openssl library.
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/store.h>
#include <openssl/bio.h>
#include "safe_lib.h"
#include "util.h"
#include "fdo_crypto_hal.h"
#include "tpm20_Utils.h"
#include "tpm2_nv_storage.h"

/**
 * Sign a message using provided ECDSA Private Keys.
 * @param data - pointer of type uint8_t, holds the plaintext message.
 * @param data_len - size of message, type size_t.
 * @param message_signature - pointer of type unsigned char, which will be
 * by filled with signature.
 * @param signature_length - size of signature, pointer of type size_t.
 * @return 0 if success, else -1.
 */
int32_t crypto_hal_ecdsa_sign(const uint8_t *data, size_t data_len,
			      unsigned char *message_signature,
			      size_t *signature_length)
{

	int32_t ret = -1;
	TSS2_RC ret_val = TPM2_RC_FAILURE;
	ESYS_CONTEXT *esys_context = NULL;
	ESYS_TR primary_key_handle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	ESYS_TR tpm_ec_key_handle = ESYS_TR_NONE;
	int sig_r_len = 0;
	int sig_s_len = 0;
	TPM2B_DIGEST *digest = NULL;
	TPMT_TK_HASHCHECK *validation = NULL;
	TPMT_SIGNATURE *signature = NULL;
	TPM2B_MAX_BUFFER input_data;
	// Set the signature scheme to ECDSA with SHA256
	TPMT_SIG_SCHEME inScheme = {
	    .scheme = TPM2_ALG_ECDSA,
	    .details = {.rsapss = {.hashAlg = FDO_TPM2_ALG_SHA}}};

	if (!data || !data_len || !message_signature || !signature_length) {
		LOG(LOG_ERROR, "Invalid Parameters received.");
		goto error;
	}

	input_data.size = data_len;
	if (memcpy_s(input_data.buffer, input_data.size, (char *)data,
		     (size_t)data_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}

	if (0 != fdoTPMGenerate_primary_key_context(&esys_context,
						    &primary_key_handle,
						    &auth_session_handle)) {
		LOG(LOG_ERROR,
		    "Failed to create primary key context from TPM.\n");
		goto error;
	}

	ret_val = Esys_TR_FromTPMPublic(
	    esys_context, TPM_DEVICE_KEY_PERSISTANT_HANDLE, ESYS_TR_NONE,
	    ESYS_TR_NONE, ESYS_TR_NONE, &tpm_ec_key_handle);

	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to load EC Key Context.\n");
		goto error;
	}

	ret_val = Esys_Hash(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
			    ESYS_TR_NONE, &input_data, FDO_TPM2_ALG_SHA,
			    ESYS_TR_RH_OWNER, &digest, &validation);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create hash.\n");
		goto error;
	}
	ret_val = Esys_Sign(esys_context, tpm_ec_key_handle,
			    auth_session_handle, ESYS_TR_NONE, ESYS_TR_NONE,
			    digest, &inScheme, validation, &signature);
	if (ret_val != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to create Sign Key.\n");
		goto error;
	}

	sig_r_len = signature->signature.ecdsa.signatureR.size;
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig r len invalid\n");
		goto error;
	}

	sig_s_len = signature->signature.ecdsa.signatureS.size;
	if (sig_r_len <= 0) {
		LOG(LOG_ERROR, "Sig s len invalid\n");
		goto error;
	}

	*signature_length = sig_r_len + sig_s_len;
	if (memcpy_s(message_signature, *signature_length,
		     (char *)signature->signature.ecdsa.signatureR.buffer,
		     (size_t)sig_r_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}
	if (memcpy_s(message_signature + sig_r_len, *signature_length,
		     (char *)signature->signature.ecdsa.signatureS.buffer,
		     (size_t)sig_s_len) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		goto error;
	}
	ret = 0;

error:
	if (esys_context) {
		if (tpm_ec_key_handle != ESYS_TR_NONE) {
			if (Esys_TR_Close(esys_context, &tpm_ec_key_handle) !=
			    TSS2_RC_SUCCESS) {
				LOG(LOG_ERROR,
				    "Failed to flush HMAC key handle.\n");
				ret = -1;
			} else {
				LOG(LOG_DEBUG,
				    "HMAC key handle flushed successfully.\n");
				tpm_ec_key_handle = ESYS_TR_NONE;
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

	TPM2_ZEROISE_FREE(digest);
	TPM2_ZEROISE_FREE(validation);
	TPM2_ZEROISE_FREE(signature);

	return ret;
}