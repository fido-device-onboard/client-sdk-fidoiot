#include "util.h"
#include "tpm2_nv_storage.h"
#include "safe_lib.h"

/**
 * Initialize Esys context.
 *
 * @param esys_context : output Esys Context
 *
 * @return
 *		TPM2_RC_SUCCESS, on success
 *		-1, on failure
 */
static int32_t fdo_tpm_esys_context_init(ESYS_CONTEXT **esys_context)
{
	int ret = -1;
	TSS2_TCTI_CONTEXT *tcti_context = NULL;

	if ((TSS2_RC_SUCCESS !=
	     Tss2_TctiLdr_Initialize(TPM2_TCTI_TYPE, &tcti_context)) ||
	    (!tcti_context)) {
		LOG(LOG_ERROR, "TCTI Context initialization failed.\n");
		goto err;
	}

	if (Esys_Initialize(esys_context, tcti_context, NULL) !=
	    TPM2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	return TPM2_RC_SUCCESS;

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
 *	TPM2_RC_SUCCESS, on success
 *	-1, on failure
 */
static int32_t fdo_tpm_esys_auth_session_init(ESYS_CONTEXT *esys_context,
					      ESYS_TR *session_handle)
{
	int ret = -1;
	TSS2_RC rval;
	TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
				  .keyBits = {.aes = 128},
				  .mode = {.aes = TPM2_ALG_CFB}};

	rval = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
				     ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				     NULL, TPM2_SE_HMAC, &symmetric,
				     FDO_TPM2_ALG_SHA, session_handle);

	if (rval != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start the auth session.\n");
		return ret;
	}

	rval = Esys_TRSess_SetAttributes(esys_context, *session_handle,
					 TPMA_SESSION_DECRYPT |
					     TPMA_SESSION_ENCRYPT |
					     TPMA_SESSION_CONTINUESESSION,
					 0xff);
	if (rval != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to Set session attributes.\n");
		return ret;
	}

	return rval;
}

/**
 * Clear Esys, TCTI, contexts and Auth Session, Primary Key handles.
 *
 * @param esys_context : Esys Context to be cleared
 * @param auth_session_handle : Auth session Handle to be flushed
 * @param nv_handle : NV handle to be cleared
 * @return
 *	0, on success
 *	-1, on failure
 */
static int32_t fdo_tpm_context_clean_up(ESYS_CONTEXT **esys_context,
					ESYS_TR *auth_session_handle,
					ESYS_TR *nv_handle)
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

	if (nv_handle && (*nv_handle != ESYS_TR_NONE)) {
		if (Esys_TR_Close(*esys_context, nv_handle) !=
		    TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to flush primary key handle.\n");
			is_failed = 1;
		} else {
			LOG(LOG_DEBUG,
			    "Primary key handle flushed successfully.\n");
			*nv_handle = ESYS_TR_NONE;
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

/** Define space at NV index.
 *
 * @param[in] nv NV index to delete.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvdefine(TPMI_RH_NV_INDEX nv, size_t data_size)
{

	if (!nv) {
		return -1;
	}

	int ret = -1;
	TSS2_RC rc;
	ESYS_CONTEXT *ctx;
	ESYS_TR nvHandle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	TPM2B_AUTH emptyAuth = {
	    .size = 0,
	};

	TPM2B_NV_PUBLIC publicInfo = {
	    .size = 0,
	    .nvPublic = {
		.nvIndex = nv,
		.nameAlg = FDO_TPM2_ALG_SHA,
		.attributes =
		    (TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD |
		     TPMA_NV_OWNERREAD | TPMA_NV_NO_DA),
		.authPolicy =
		    {
			.size = 0,
			.buffer = {0},
		    },
		.dataSize = data_size,
	    }};

	rc = fdo_tpm_esys_context_init(&ctx);
	if (rc != TSS2_RC_SUCCESS || !ctx) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	rc = fdo_tpm_esys_auth_session_init(ctx, &auth_session_handle);
	if (rc != TSS2_RC_SUCCESS || !auth_session_handle) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start Esys context.\n");
		goto err;
	}

	// Search the NV index
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	rc =
	    Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, nv, 1, NULL, &capability_data);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_GetCapability failed!\n");
		goto err;
	}

	int exists = (capability_data->data.handles.count > 0 &&
		      capability_data->data.handles.handle[0] == nv);
	if (exists == 1) {
		LOG(LOG_DEBUG, "NV index already exist.\n");
		ret = 0;
		goto err;
	}

	rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, auth_session_handle,
				 ESYS_TR_NONE, ESYS_TR_NONE, &emptyAuth,
				 &publicInfo, &nvHandle);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to define Esys NV space.\n");
		goto err;
	}

	ret = 0;

err:

	if (ctx && (0 != fdo_tpm_context_clean_up(&ctx, &auth_session_handle,
						  &nvHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
		ret = -1;
	}

	return ret;
}

/** Store a data in a NV index.
 *
 * @param[in] data Key to store to NVRAM.
 * @param[in] data_size Size of the data.
 * @param[in] nv NV index to store the data.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvwrite(const uint8_t *data, size_t data_size, TPMI_RH_NV_INDEX nv)
{
	if (!data || !nv) {
		return -1;
	}

	int ret = -1;
	TSS2_RC rc;
	ESYS_CONTEXT *ctx;
	ESYS_TR nvHandle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	TPM2B_AUTH emptyAuth = {
	    .size = 0,
	};

	TPM2B_NV_PUBLIC publicInfo = {
	    .size = 0,
	    .nvPublic = {
		.nvIndex = nv,
		.nameAlg = FDO_TPM2_ALG_SHA,
		.attributes =
		    (TPMA_NV_OWNERWRITE | TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD |
		     TPMA_NV_OWNERREAD | TPMA_NV_NO_DA),
		.authPolicy =
		    {
			.size = 0,
			.buffer = {0},
		    },
		.dataSize = data_size,
	    }};

	TPM2B_MAX_NV_BUFFER blob = {.size = data_size};
	if (blob.size > sizeof(blob.buffer)) {
		LOG(LOG_ERROR, "Data too large.\n");
		return -1;
	}

	if (memcpy_s(&blob.buffer[0], blob.size, data, data_size) != 0) {
		LOG(LOG_ERROR, "Failed to copy data to blob!\n");
		goto err;
	}

	rc = fdo_tpm_esys_context_init(&ctx);
	if (rc != TSS2_RC_SUCCESS || !ctx) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	rc = fdo_tpm_esys_auth_session_init(ctx, &auth_session_handle);
	if (rc != TSS2_RC_SUCCESS || !auth_session_handle) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start Esys context.\n");
		goto err;
	}

	// Search the NV index
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	rc =
	    Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, nv, 1, NULL, &capability_data);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_GetCapability failed!\n");
		goto err;
	}

	int exists = (capability_data->data.handles.count > 0 &&
		      capability_data->data.handles.handle[0] == nv);
	if (exists == 1) {
		LOG(LOG_DEBUG, "NV index already exist. Deleting it.\n");
		rc = Esys_TR_FromTPMPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE,
					   ESYS_TR_NONE, &nvHandle);
		if (rc != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR,
			    "Failed to constructs an ESYS_TR object.\n");
			goto err;
		}
		rc = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvHandle,
					   auth_session_handle, ESYS_TR_NONE,
					   ESYS_TR_NONE);
		if (rc != TSS2_RC_SUCCESS) {
			LOG(LOG_ERROR, "Failed to undefine Esys NV space.\n");
			goto err;
		}
	}

	rc = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, auth_session_handle,
				 ESYS_TR_NONE, ESYS_TR_NONE, &emptyAuth,
				 &publicInfo, &nvHandle);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to define Esys NV space.\n");
		goto err;
	}

	rc = Esys_NV_Write(ctx, nvHandle, nvHandle, auth_session_handle,
			   ESYS_TR_NONE, ESYS_TR_NONE, &blob, 0 /*=offset*/);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to write in Esys NV space.\n");
		goto err;
	}

	ret = 0;

err:

	if (ctx && (0 != fdo_tpm_context_clean_up(&ctx, &auth_session_handle,
						  &nvHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
		ret = -1;
	}
	return ret;
}

/** Load data size from a NV index.
 *
 * @param[in] nv NV index of the data.
 * @retval data size on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
size_t fdo_tpm_nvread_size(TPMI_RH_NV_INDEX nv)
{
	int ret = -1;
	TSS2_RC rc;
	ESYS_CONTEXT *ctx;
	ESYS_TR nvHandle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	TPM2B_NV_PUBLIC *publicInfo = NULL;
	size_t data_size;

	if (!nv) {
		return -1;
	}

	rc = fdo_tpm_esys_context_init(&ctx);
	if (rc != TSS2_RC_SUCCESS || !ctx) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	rc = fdo_tpm_esys_auth_session_init(ctx, &auth_session_handle);
	if (rc != TSS2_RC_SUCCESS || !auth_session_handle) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start Esys API.\n");
		goto err;
	}

	// Search the NV index
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	rc =
	    Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, nv, 1, NULL, &capability_data);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_GetCapability failed!\n");
		goto err;
	}

	int exists = (capability_data->data.handles.count > 0 &&
		      capability_data->data.handles.handle[0] == nv);
	if (exists != 1) {
		LOG(LOG_DEBUG, "NV index doesn't exist.\n");
		ret = 0;
		goto err;
	}

	rc = Esys_TR_FromTPMPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, &nvHandle);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to constructs an ESYS_TR object.\n");
		goto err;
	}

	rc = Esys_NV_ReadPublic(ctx, nvHandle, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &publicInfo, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to read publicinfo from NV.\n");
		goto err;
	}

	data_size = publicInfo->nvPublic.dataSize;

	ret = data_size;

err:

	if (publicInfo) {
		free(publicInfo);
	}

	if (ctx && (0 != fdo_tpm_context_clean_up(&ctx, &auth_session_handle,
						  &nvHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
		ret = -1;
	}
	return ret;
}

/** Load data from a NV index.
 *
 * @param[in] nv NV index of the data.
 * @param[in] data_size Size of the data.
 * @param[out] data Loaded data.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvread(TPMI_RH_NV_INDEX nv, size_t data_size, uint8_t **data)
{
	int ret = -1;
	TSS2_RC rc;
	ESYS_CONTEXT *ctx;
	ESYS_TR nvHandle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;
	TPM2B_MAX_NV_BUFFER *blob;
	TPM2B_NV_PUBLIC *publicInfo;

	if (!nv) {
		return -1;
	}

	rc = fdo_tpm_esys_context_init(&ctx);
	if (rc != TSS2_RC_SUCCESS || !ctx) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	rc = fdo_tpm_esys_auth_session_init(ctx, &auth_session_handle);
	if (rc != TSS2_RC_SUCCESS || !auth_session_handle) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start Esys API.\n");
		goto err;
	}

	rc = Esys_TR_FromTPMPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, &nvHandle);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to constructs an ESYS_TR object.\n");
		goto err;
	}

	rc = Esys_NV_ReadPublic(ctx, nvHandle, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, &publicInfo, NULL);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to read publicinfo from NV.\n");
		goto err;
	}

	rc = Esys_NV_Read(ctx, ESYS_TR_RH_OWNER, nvHandle, auth_session_handle,
			  ESYS_TR_NONE, ESYS_TR_NONE, data_size, 0 /*=offset*/,
			  &blob);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to read data from NV storage.\n");
		goto err;
	}

	if (memcpy_s(*data, data_size, &blob->buffer[0], blob->size) != 0) {
		LOG(LOG_ERROR, "Failed to copy data to blob!\n");
		goto err;
	}

	ret = 0;

err:

	if (publicInfo) {
		free(publicInfo);
	}

	if (ctx && (0 != fdo_tpm_context_clean_up(&ctx, &auth_session_handle,
						  &nvHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
		ret = -1;
	}
	return ret;
}

/** Delete data from a NV index.
 *
 * @param[in] nv NV index to delete.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvdel(TPMI_RH_NV_INDEX nv)
{
	int ret = -1;
	TSS2_RC rc;
	ESYS_CONTEXT *ctx;
	ESYS_TR nvHandle = ESYS_TR_NONE;
	ESYS_TR auth_session_handle = ESYS_TR_NONE;

	if (!nv) {
		return -1;
	}

	rc = fdo_tpm_esys_context_init(&ctx);
	if (rc != TSS2_RC_SUCCESS || !ctx) {
		LOG(LOG_ERROR, "Failed to intitialize Esys context.\n");
		goto err;
	}

	rc = fdo_tpm_esys_auth_session_init(ctx, &auth_session_handle);
	if (rc != TSS2_RC_SUCCESS || !auth_session_handle) {
		LOG(LOG_ERROR, "Failed to create Auth Session for Esys API.\n");
		goto err;
	}

	rc = Esys_Startup(ctx, TPM2_SU_CLEAR);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to start Esys API.\n");
		goto err;
	}

	// Search the NV index
	TPMS_CAPABILITY_DATA *capability_data = NULL;
	rc =
	    Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, nv, 1, NULL, &capability_data);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Esys_GetCapability failed!\n");
		goto err;
	}

	int exists = (capability_data->data.handles.count > 0 &&
		      capability_data->data.handles.handle[0] == nv);
	if (exists != 1) {
		LOG(LOG_DEBUG, "NV index doesn't exist.\n");
		ret = 0;
		goto err;
	}

	rc = Esys_TR_FromTPMPublic(ctx, nv, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, &nvHandle);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to constructs an ESYS_TR object.\n");
		goto err;
	}

	rc = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvHandle,
				   auth_session_handle, ESYS_TR_NONE,
				   ESYS_TR_NONE);
	if (rc != TSS2_RC_SUCCESS) {
		LOG(LOG_ERROR, "Failed to undefine Esys NV space.\n");
		goto err;
	}
	nvHandle = ESYS_TR_NONE;

	ret = 0;

err:

	if (ctx && (0 != fdo_tpm_context_clean_up(&ctx, &auth_session_handle,
						  &nvHandle))) {
		LOG(LOG_ERROR, "Failed to tear down all the TSS context.\n");
		ret = -1;
	}

	return ret;
}
