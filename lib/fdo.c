/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements state machine of FDO library. Also contains entry
 * point to FDO library.
 */

#include "cli.h"
#include "fdokeyexchange.h"
#include "network_al.h"
#include "fdoprotctx.h"
#include "fdonet.h"
#include "fdoprot.h"
#include "load_credentials.h"
#include "network_al.h"
#include "fdoCrypto.h"
#include "util.h"
#include <stdlib.h>
#include <unistd.h>
#include "safe_lib.h"
#include "fdodeviceinfo.h"
#include <ctype.h>

typedef struct app_data_s {
	bool error_recovery;
	bool recovery_enabled;
	bool (*state_fn)(void);
	fdo_dev_cred_t *devcred;
	fdo_prot_t prot;
	int err;
	fdo_service_info_t *service_info;
	/* Temp, use the value in the configured rendezvous */
	fdo_ip_address_t *rendezvousIPAddr;
	char *rendezvousdns;
	uint64_t delaysec;
	/* Error handling callback */
	fdo_sdk_errorCB error_callback;
	/* Global Sv_info Module_list head pointer */
	fdo_sdk_service_info_module_list_t *module_list;
	fdo_rendezvous_directive_t *current_rvdirective;
	fdo_rvto2addr_entry_t *current_rvto2addrentry;
} app_data_t;

/* Globals */
static app_data_t *g_fdo_data = NULL;
extern int g_argc;
extern char **g_argv;

#if defined(SELF_SIGNED_CERTS_SUPPORTED)
bool useSelfSignedCerts = false;
#endif

#ifdef RETRY_FALSE
#define ERROR_RETRY_COUNT 1
#else
#define ERROR_RETRY_COUNT 5
#endif

static const uint64_t default_delay = 3;
static const uint64_t default_delay_rvinfo_retries = 120;
static const uint64_t max_delay = 3600;

static unsigned int error_count;
static bool rvbypass;

static bool _STATE_DI(void);
static bool _STATE_TO1(void);
static bool _STATE_TO2(void);
static bool _STATE_Error(void);
static bool _STATE_Shutdown(void);
static bool _STATE_Shutdown_Error(void);

static fdo_sdk_status app_initialize(void);
static void app_close(void);
bool parse_manufacturer_address(char *buffer, size_t buffer_sz, bool *tls,
	fdo_ip_address_t **mfg_ip, char *mfg_dns, size_t mfg_dns_sz, int *mfg_port);

#define ERROR()                                                                \
	{                                                                      \
		g_fdo_data->err = __LINE__;                                    \
		g_fdo_data->state_fn = &_STATE_Error;                          \
	}

/**
 * fdo_sdk_run is user API call to start device ownership
 * transfer
 * fdo_sdk_init should be called before calling this function
 * If device supports Device Initialization (DI) protocol,
 * then the first time invoking of this call completes DI
 * and for the next invoke completes transfer ownership protocols
 * (TO1 and TO2). If device does not support DI, then device is expected
 * to have credentials programmed in the factory and first time
 * invoking of this function will complete transfer ownership protocols.
 *
 * @return
 *        return FDO_SUCCESS on success. non-zero value from fdo_sdk_status
 * enum.
 */
fdo_sdk_status fdo_sdk_run(void)
{
	fdo_sdk_status ret = FDO_ERROR;

	if (!g_fdo_data) {
		LOG(LOG_ERROR,
		    "fdo_sdk not initialized. Call fdo_sdk_init first\n");
		goto end;
	}

	if (FDO_SUCCESS != app_initialize()) {
		goto end;
	}

	/* Loop until last state has been reached */
	while (1) {
		/* Nothing left to perform in state machine */
		if (!g_fdo_data->state_fn) {
			break;
		}

		/* Start the state machine */
		if (true == g_fdo_data->state_fn()) {
			ret = FDO_SUCCESS;
		} else {
			ret = FDO_ERROR;
			++error_count;
			if (error_count == ERROR_RETRY_COUNT) {
				LOG(LOG_INFO, "*********Retry(s) done*********\n");
				g_fdo_data->state_fn = &_STATE_Shutdown_Error;
			} else if (error_count > ERROR_RETRY_COUNT) {
				// reach here when all retries have been completed
				goto end;
			} else {
				LOG(LOG_INFO, "*********Retry count : %u*********\n", error_count);
			}
		}
	}

end:
	app_close();
	/* This should be moved to fdo_sdk_exit when its available */
	fdo_free(g_fdo_data);
	return ret;
}

/**
 * Deallocate allocated  memories in DI protocol and exit from DI.
 *
 * @param app_data
 *        Pointer to the database containtain all fdo state variables.
 * @return ret
 *         None.
 */
static void fdo_protDIExit(app_data_t *app_data)
{
	fdo_prot_t *ps = &app_data->prot;

	// clear FDOR, FDOW and reset state to start of DI
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	ps->fdor.b.block_size = ps->prot_buff_sz;
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	ps->state = FDO_STATE_DI_APP_START;
	return;
}

/**
 * Release memory allocated as a part of TO1 protocol.
 *
 * @param app_data
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void fdo_protTO1Exit(app_data_t *app_data)
{
	fdo_prot_t *ps = &app_data->prot;

	if (ps->nonce_to1proof) {
		fdo_byte_array_free(ps->nonce_to1proof);
		ps->nonce_to1proof = NULL;
	}
	// clear FDOR, FDOW and reset state to start of TO1
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	ps->fdor.b.block_size = ps->prot_buff_sz;
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	ps->state = FDO_TO1_TYPE_HELLO_FDO;
}

/**
 * Release memory allocated as a part of TO2 protocol and exit.
 *
 * @param app_data
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void fdo_protTO2Exit(app_data_t *app_data)
{
	fdo_prot_t *ps = &app_data->prot;

	if (ps->tls_key != NULL) {
		fdo_public_key_free(ps->tls_key);
		ps->tls_key = NULL;
	}
	if (ps->ovoucher != NULL) {
		fdo_ov_free(ps->ovoucher);
		ps->ovoucher = NULL;
	}
	if (ps->osc != NULL) {
		if (ps->osc->guid) {
			fdo_byte_array_free(ps->osc->guid);
			ps->osc->guid = NULL;
		}
		if (ps->osc->rvlst) {
			fdo_rendezvous_list_free(ps->osc->rvlst);
			ps->osc->rvlst = NULL;
		}
		if (ps->osc->pubkey) {
			fdo_public_key_free(ps->osc->pubkey);
			ps->osc->pubkey = NULL;
		}
		fdo_free(ps->osc);
		ps->osc = NULL;
	}
	if (ps->owner_public_key) {
		fdo_public_key_free(ps->owner_public_key);
		ps->owner_public_key = NULL;
	}
	if (ps->nonce_to2proveov != NULL) {
		fdo_byte_array_free(ps->nonce_to2proveov);
		ps->nonce_to2proveov = NULL;
	}
	if (ps->nonce_to2provedv != NULL) {
		fdo_byte_array_free(ps->nonce_to2provedv);
		ps->nonce_to2provedv = NULL;
	}
	if (ps->nonce_to2setupdv != NULL) {
		fdo_byte_array_free(ps->nonce_to2setupdv);
		ps->nonce_to2setupdv = NULL;
	}
	if (ps->nonce_to2setupdv_rcv != NULL) {
		fdo_byte_array_free(ps->nonce_to2setupdv_rcv);
		ps->nonce_to2setupdv_rcv = NULL;
	}
	if (ps->new_ov_hdr_hmac) {
		fdo_hash_free(ps->new_ov_hdr_hmac);
		ps->new_ov_hdr_hmac = NULL;
	}
	if (ps->hello_device_hash) {
		fdo_hash_free(ps->hello_device_hash);
		ps->hello_device_hash = NULL;
	}
	ps->max_owner_message_size = 0;

	/* clear Sv_info PSI/DSI/OSI related data */
	fdo_sv_info_clear_module_psi_osi_index(ps->sv_info_mod_list_head);
	ps->total_dsi_rounds = 0;
	if (ps->dsi_info) {
		ps->dsi_info->list_dsi = ps->sv_info_mod_list_head;
		ps->dsi_info->module_dsi_index = 0;
		fdo_free(ps->dsi_info);
		ps->dsi_info = NULL;
	}

	if (ps->service_info) {
		fdo_service_info_free(ps->service_info);
		ps->service_info = NULL;
	}

	if (ps->ext_service_info) {
		fdo_byte_array_free(ps->ext_service_info);
		ps->ext_service_info = NULL;
	}

	if (ps->serviceinfo_invalid_modnames) {
		fdo_serviceinfo_invalid_modname_free(ps->serviceinfo_invalid_modnames);
		fdo_free(ps->serviceinfo_invalid_modnames);
	}

	// clear FDOR, FDOW and reset state to start of TO2
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	ps->fdor.b.block_size = ps->prot_buff_sz;
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	ps->state = FDO_STATE_T02_SND_HELLO_DEVICE;
	fdo_kex_close();
}

/**
 * Allocate memory to hold device credentials which includes owner credentials
 * and manufacturer credentials.
 *
 * @return ret
 *        return pointer to memory holding device credentials on success, NULL
 * on failure.
 */
fdo_dev_cred_t *app_alloc_credentials(void)
{
	if (!g_fdo_data) {
		return NULL;
	}
	if (g_fdo_data->devcred) {
		fdo_dev_cred_free(g_fdo_data->devcred);
		fdo_free(g_fdo_data->devcred);
	}
	g_fdo_data->devcred = fdo_dev_cred_alloc();

	if (!g_fdo_data->devcred) {
		LOG(LOG_ERROR, "Device Credentials allocation failed !!");
	}

	return g_fdo_data->devcred;
}

/**
 * Get pointer to memory holding device credentials which includes owner
 * credentials and manufacturer credentials.
 *
 * @return ret
 *        return pointer to memory holding device credentials on success, NULL
 * if memory not allocated yet.
 */
fdo_dev_cred_t *app_get_credentials(void)
{
	return g_fdo_data->devcred;
}

/**
 * Internal API
 */
static fdo_sdk_status app_initialize(void)
{
	int ret = FDO_ERROR;
	size_t fsize;
	int max_serviceinfo_sz = 0;
	long buffer_as_long = 0;
	char *buffer = NULL;
	char *eptr = NULL;

	if (!g_fdo_data) {
		return FDO_ERROR;
	}

	g_fdo_data->delaysec = 0;
	/* Initialize service_info to NULL in case of early error. */
	g_fdo_data->service_info = NULL;

/* Enable/Disable Error Recovery */
#ifdef RETRY_FALSE
	g_fdo_data->error_recovery = false;
#else
	g_fdo_data->error_recovery = true;
#endif
	g_fdo_data->recovery_enabled = false;
	g_fdo_data->state_fn = &_STATE_TO1;
	if (memset_s(&g_fdo_data->prot, sizeof(fdo_prot_t), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return FDO_ERROR;
	}

	g_fdo_data->err = 0;

#ifdef CLI
	/* Process command line input. */
	ret = input_parameters(g_argc, g_argv);
	if (0 != ret) {
		return FDO_ERROR;
	}
#endif

	// Read the file at path MAX_SERVICEINFO_SZ_FILE to get the maximum
	// ServiceInfo size that will be supported for both Owner and Device
	// ServiceInfo.
	//
	// Default to MIN_SERVICEINFO_SZ if the file is non-existent, or if the file
	// content is not a valid number between MIN_SERVICEINFO_SZ and
	// MAX_SERVICEINFO_SZ
	fsize = fdo_blob_size((char *)MAX_SERVICEINFO_SZ_FILE, FDO_SDK_RAW_DATA);
	if (fsize == 0) {
		g_fdo_data->prot.maxDeviceServiceInfoSz = MIN_SERVICEINFO_SZ;
		g_fdo_data->prot.maxOwnerServiceInfoSz = MIN_SERVICEINFO_SZ;
		g_fdo_data->prot.prot_buff_sz = MSG_BUFFER_SZ + MSG_METADATA_SIZE;
	} else {
		buffer = fdo_alloc(fsize + 1);
		if (!buffer) {
			LOG(LOG_ERROR, "malloc failed\n");
		} else {
			if (fdo_blob_read((char *)MAX_SERVICEINFO_SZ_FILE, FDO_SDK_RAW_DATA,
					(uint8_t *)buffer, fsize) == -1) {
				LOG(LOG_ERROR, "Failed to read Manufacture DN\n");
			}
			// set to 0 explicitly
			errno = 0;
			buffer_as_long = strtol(buffer, &eptr, 10);
			if (!eptr || eptr == buffer || errno != 0) {
				LOG(LOG_INFO, "Invalid maximum ServiceInfo size, "
					"defaulting to %d\n", MIN_SERVICEINFO_SZ);
				max_serviceinfo_sz = MIN_SERVICEINFO_SZ;
			}

			if (buffer_as_long <= MIN_SERVICEINFO_SZ) {
				max_serviceinfo_sz = MIN_SERVICEINFO_SZ;
			} else if (buffer_as_long >= MAX_SERVICEINFO_SZ) {
				max_serviceinfo_sz = MAX_SERVICEINFO_SZ;
			} else {
				max_serviceinfo_sz = buffer_as_long;
			}
			if (max_serviceinfo_sz > MSG_BUFFER_SZ) {
				g_fdo_data->prot.prot_buff_sz = max_serviceinfo_sz + MSG_METADATA_SIZE;
			} else {
				g_fdo_data->prot.prot_buff_sz = MSG_BUFFER_SZ + MSG_METADATA_SIZE;
			}
			g_fdo_data->prot.maxDeviceServiceInfoSz = max_serviceinfo_sz;
			g_fdo_data->prot.maxOwnerServiceInfoSz = max_serviceinfo_sz;
		}
	}
	// maxDeviceMessageSize that is to be sent during msg/60
	g_fdo_data->prot.max_device_message_size = g_fdo_data->prot.prot_buff_sz;
	if (buffer != NULL) {
		fdo_free(buffer);
	}

	LOG(LOG_INFO, "Maximum supported DeviceServiceInfo size: %"PRIu64" bytes\n",
		g_fdo_data->prot.maxDeviceServiceInfoSz);
	LOG(LOG_INFO, "Maximum supported OwnerServiceInfo size: %"PRIu64" bytes\n",
		g_fdo_data->prot.maxOwnerServiceInfoSz);

	/*
	* Initialize and allocate memory for the FDOW/FDOR blocks before starting the spec's
	* protocol execution. Reuse the allocated memory by emptying the contents.
	*/
	if (!fdow_init(&g_fdo_data->prot.fdow) ||
		!fdo_block_alloc_with_size(&g_fdo_data->prot.fdow.b,
			g_fdo_data->prot.prot_buff_sz)) {
		LOG(LOG_ERROR, "fdow_init() failed!\n");
		return FDO_ERROR;
	}
	if (!fdor_init(&g_fdo_data->prot.fdor) ||
		!fdo_block_alloc_with_size(&g_fdo_data->prot.fdor.b,
			g_fdo_data->prot.prot_buff_sz)) {
		LOG(LOG_ERROR, "fdor_init() failed!\n");
		return FDO_ERROR;
	}

	if ((g_fdo_data->devcred->ST == FDO_DEVICE_STATE_READY1) ||
			(g_fdo_data->devcred->ST == FDO_DEVICE_STATE_READYN)) {
		ret = load_device_secret();
		if (ret == -1) {
			LOG(LOG_ERROR, "Load HMAC Secret failed\n");
			return FDO_ERROR;
		}
	}

	// Read HMAC & MFG only if it is T01/T02.
	if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_PC) {
		g_fdo_data->state_fn = &_STATE_DI;
#ifndef NO_PERSISTENT_STORAGE
		return 0;
#endif
	}

	if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_IDLE) {
		LOG(LOG_INFO,
		    "FDO in Idle State. Device Onboarding already complete\n");
		g_fdo_data->state_fn = &_STATE_Shutdown;
		return FDO_SUCCESS;
	}

	if (reuse_supported) {
		LOG(LOG_INFO, "Reuse support is enabled\n");
	} else {
		LOG(LOG_INFO, "Reuse support is disabled\n");
	}

	if (resale_supported) {
		LOG(LOG_INFO, "Resale support is enabled\n");
	} else {
		LOG(LOG_INFO, "Resale support is disabled\n");
	}

	return FDO_SUCCESS;
}
/**
 * Get FDO device state
 * fdo_sdk_init should be called before calling this function
 *
 * @return fdo_sdk_device_state type
 *	FDO_STATE_PRE_DI  : Device is ready for DI
 *	FDO_STATE_PRE_TO1 : Device is ready for Ownership transfer
 *	FDO_STATE_IDLE    : Device's ownership transfer done
 *	FDO_STATE_RESALE  : Device is ready for ownership transfer
 *	FDO_STATE_ERROR   : Error in getting device status
 *
 */
fdo_sdk_device_state fdo_sdk_get_status(void)
{
	fdo_sdk_device_state status = FDO_STATE_ERROR;

	if (g_fdo_data == NULL) {
		return FDO_STATE_ERROR;
	}

	g_fdo_data->err = 0;

	if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_PC) {
		status = FDO_STATE_PRE_DI;
	} else if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_READY1) {
		status = FDO_STATE_PRE_TO1;
	} else if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_IDLE) {
		status = FDO_STATE_IDLE;
	} else if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_READYN) {
		status = FDO_STATE_RESALE;
	}

	return status;
}

/**
 * API to register Service_info modules, for later communicaton with Owner
 * server.
 * This API is exposed to all the FDO Service_info modules, modules must call
 * this
 * API for registering themselves to FDO.
 *
 * @param
 *        module: pointer to a 'FDO service_info Module struct'
 *
 * @return none
 */

void fdo_sdk_service_info_register_module(fdo_sdk_service_info_module *module)
{
	if (module == NULL) {
		return;
	}

	fdo_sdk_service_info_module_list_t *new =
	    fdo_alloc(sizeof(fdo_sdk_service_info_module_list_t));

	if (new == NULL) {
		LOG(LOG_ERROR, "malloc failed\n");
		return;
	}

	if (memcpy_s(&new->module, sizeof(fdo_sdk_service_info_module), module,
		     sizeof(fdo_sdk_service_info_module)) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		fdo_free(new);
		return;
	}

	if (g_fdo_data->module_list == NULL) {
		// 1st module to register
		g_fdo_data->module_list = new;
	} else {
		fdo_sdk_service_info_module_list_t *list =
		    g_fdo_data->module_list;

		while (list->next != NULL) {
			list = list->next;
		}

		list->next = new;
	}
}

/**
 * Create 'devmod' module and initialize it with the key-value pairs.
 */
static bool add_module_devmod(void) {
	// Build up default 'devmod' ServiceInfo list
	g_fdo_data->service_info = fdo_service_info_alloc();

	if (!g_fdo_data->service_info) {
		LOG(LOG_ERROR, "Service_info List allocation failed!\n");
		return false;
	}

	if (!fdo_service_info_add_kv_bool(g_fdo_data->service_info, "devmod:active",
				    true)) {
		LOG(LOG_ERROR, "Failed to add devmod:active\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:os",
				    OS_NAME)) {
		LOG(LOG_ERROR, "Failed to add devmod:os\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:arch",
				    ARCH)) {
		LOG(LOG_ERROR, "Failed to add devmod:arch\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:version",
				    OS_VERSION)) {
		LOG(LOG_ERROR, "Failed to add devmod:version\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:device",
				    (char *)get_device_model())) {
		LOG(LOG_ERROR, "Failed to add devmod:device\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:sn",
				    (char *)get_device_serial_number())) {
		LOG(LOG_ERROR, "Failed to add devmod:sn\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:pathsep",
				    PATH_SEPARATOR)) {
		LOG(LOG_ERROR, "Failed to add devmod:pathsep\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:sep",
				    SEPARATOR)) {
		LOG(LOG_ERROR, "Failed to add devmod:sep\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:nl",
				    NEWLINE)) {
		LOG(LOG_ERROR, "Failed to add devmod:nl\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:tmp",
				    "")) {
		LOG(LOG_ERROR, "Failed to add devmod:tmp\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:dir",
				    "")) {
		LOG(LOG_ERROR, "Failed to add devmod:dir\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:progenv",
				    PROGENV)) {
		LOG(LOG_ERROR, "Failed to add devmod:progenv\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:bin",
				    BIN_TYPE)) {
		LOG(LOG_ERROR, "Failed to add devmod:bin\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:mudurl",
				    "")) {
		LOG(LOG_ERROR, "Failed to add devmod:mudurl\n");
		return false;
	}

	// should ideally contain supported ServiceInfo module list and its count.
	// for now, set this to 1, since we've only 1 module 'fdo_sys'
	// TO-DO : Move this to fdotypes later when multiple Device ServiceInfo module
	// support is added.
	if (!fdo_service_info_add_kv_int(g_fdo_data->service_info, "devmod:nummodules",
					1)) {
		LOG(LOG_ERROR, "Failed to add devmod:nummodules\n");
		return false;
	}
	if (!fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:modules",
				    g_fdo_data->module_list->module.module_name)) {
		LOG(LOG_ERROR, "Failed to add devmod:modules\n");
		return false;
	}

	g_fdo_data->service_info->sv_index_begin = 0;
	g_fdo_data->service_info->sv_index_end = 0;
	g_fdo_data->service_info->sv_val_index = 0;
	return true;
}

static fdo_sdk_service_info_module_list_t *
clear_modules_list(fdo_sdk_service_info_module_list_t *head)
{
	if (head->next != NULL) {
		head->next = clear_modules_list(head->next);
	}
	fdo_free(head);
	head = NULL;
	return head;
}

/**
 * API to de register Service_info modules, for later communicaton with Owner
 * server.
 * This API is exposed to all the FDO Service_info modules, modules must call
 * this
 * API for de- registering themselves after FDO complete.
 *
 * @param none
 *
 * @return none
 */

void fdo_sdk_service_info_deregister_module(void)
{
	fdo_sdk_service_info_module_list_t *list = g_fdo_data->module_list;
	if (list) {
		g_fdo_data->module_list = clear_modules_list(list);
	}
}

void fdo_sdk_deinit(void)
{
	(void)fdo_crypto_close();

	app_close();
	if (g_fdo_data) {
		fdo_free(g_fdo_data);
	}
}

/**
 * fdo_sdk_init is the first function should be called before calling
 * any API function
 * @param error_handling_callback
 * This is the Application’s error handling function and will be called by the
 * SDK when an error is encountered. This value can be NULL in which case,
 * errors will not be reported to the Application and the SDK will take the
 * appropriate recovery and/or restart action as required.
 * @param num_modules - Number of Service Information modules contained in the
 * following module_information list parameter. If no Application specific
 * modules are available, this value should be zero.
 * @param module_information - if no Application specific modules are available,
 * this value should be NULL.
 * @return FDO_SUCCESS for true, else FDO_ERROR
 */

fdo_sdk_status fdo_sdk_init(fdo_sdk_errorCB error_handling_callback,
			    uint32_t num_modules,
			    fdo_sdk_service_info_module *module_information)
{
	int ret;
	fdo_sdk_device_status state = FDO_DEVICE_STATE_D;

	/* fdo Global data initialization */
	g_fdo_data = fdo_alloc(sizeof(app_data_t));

	if (!g_fdo_data) {
		LOG(LOG_ERROR, "malloc failed to alloc app_data_t\n");
		return FDO_ERROR;
	}

	g_fdo_data->err = 0;

	/* Initialize Crypto services */
	if (0 != fdo_crypto_init()) {
		LOG(LOG_ERROR, "fdo_crypto_init failed!!\n");
		return FDO_ERROR;
	}

	fdo_net_init();

	if (!fdow_init(&g_fdo_data->prot.fdow)) {
		LOG(LOG_ERROR, "fdow_init() failed!\n");
		return FDO_ERROR;
	}
	if (!fdor_init(&g_fdo_data->prot.fdor)) {
		LOG(LOG_ERROR, "fdor_init() failed!\n");
		return FDO_ERROR;
	}

	/* Load credentials */
	if (NULL == app_alloc_credentials()) {
		LOG(LOG_ERROR, "Alloc credential failed.\n");
		return FDO_ERROR;
	}
	fdo_dev_cred_init(g_fdo_data->devcred);

	if (!load_device_status(&state)) {
		LOG(LOG_ERROR, "Load device status failed.\n");
		return FDO_ERROR;
	}
	g_fdo_data->devcred->ST = state;

	// Load Device Credentials ONLY if there is one
	if (g_fdo_data->devcred->ST != FDO_DEVICE_STATE_PC) {
		ret = load_credential(g_fdo_data->devcred);
		if (ret == -1) {
			LOG(LOG_ERROR, "Load credential failed.\n");
			return FDO_ERROR;
		}
	}

	if ((num_modules == 0) || (num_modules > FDO_MAX_MODULES) ||
	    (module_information == NULL) ||
	    (module_information->service_info_callback == NULL)) {
		return FDO_ERROR;
	    }

	/* register service-info modules */
	for (uint32_t i = 0; i < num_modules; i++) {
		if (module_information != NULL) {
			fdo_sdk_service_info_register_module(
			    &module_information[i]);
		}
	}

	/* Get the callback from user */
	g_fdo_data->error_callback = error_handling_callback;

	return FDO_SUCCESS;
}

/**
 * Parse the manufacturer network address in the given buffer, and extract and save
 * the TLS/IP/DNS/Port values.
 *
 * @param buffer Buffer containing the network address
 * @param buffer_sz Size of the above buffer
 * @param tls Output flag describing whether HTTP (false) or HTTPS (true) is used
 * @param mfg_ip
 * Output structure to store IP. Memory allocation is done in this method.
 * If IP address is found while parsing, this allocated structure is returned that must
 * be freed by the caller after use. Otherwise, a NULL object is returned.
 * @param mfg_dns Output pre-allocated buffer to store DNS
 * @param mfg_dns_sz Size of the DNS buffer (minimum 100)
 * @param mfg_port Output variable to store port
 *
 * Return true if parse was successful, false otherwise.
 */
bool parse_manufacturer_address(char *buffer, size_t buffer_sz, bool *tls,
	fdo_ip_address_t **mfg_ip, char *mfg_dns, size_t mfg_dns_sz,
	int *mfg_port) {

	char transport_prot[6] = {0};
	char port[6] = {0};
	size_t index = 0;
	size_t dns_index = 0;
	size_t port_index = 0;
	int count_dns_alphabets = 0;
	int result = 0;
	char *eptr = NULL;
	const char transport_http[5] = "http";
	const char transport_https[6] = "https";

	if (!buffer || buffer_sz == 0 || !tls || !mfg_ip || !mfg_dns ||
	mfg_dns_sz == 0 || !mfg_port) {
		LOG(LOG_ERROR, "Invalid params\n");
		return false;
	}

	// the expected format is '{http/https}://{IP/DNS}:port'

	// parse transport protocol until ':'
	while (buffer[index] != ':' && index < sizeof(transport_prot) - 1 && index < buffer_sz) {
		if (!isalpha(buffer[index])) {
			LOG(LOG_ERROR, "Invalid Transport protocol or missing separator"
				" in Manufacturer address\n");
			goto end;
		} else {
			transport_prot[index] = buffer[index];
		}
		index++;
	}

	// parse separator "://"
	if (buffer[index] != ':' || buffer[index + 1] != '/' || buffer[index + 2] != '/') {
		LOG(LOG_ERROR, "Invalid/missing DNS/IP separator in Manufacturer address\n");
		goto end;
	} else {
		index += 3;
	}

	// parse DNS/IP until ':'
	if (0 != memset_s(mfg_dns, mfg_dns_sz, 0)) {
		LOG(LOG_ERROR, "memset failed\n");
		goto end;
	}
	while (buffer[index] != ':' && (dns_index < mfg_dns_sz - 1) && index < buffer_sz) {
		if (!isalnum(buffer[index]) && buffer[index] != '-' && buffer[index] != '.') {
			LOG(LOG_ERROR, "Invalid DNS/IP or missing separator in Manufacturer address\n");
			goto end;
		} else {
			mfg_dns[dns_index] = buffer[index];
			if (isalpha(buffer[index])) {
				count_dns_alphabets++;
			}
		}
		index++;
		dns_index++;
	}

	if (!isalnum(mfg_dns[0]) || !isalnum(mfg_dns[dns_index - 1])) {
		LOG(LOG_ERROR, "Invalid DNS/IP in Manufacturer address\n");
		goto end;
	}

	// parse separator ':'
	if (buffer[index] != ':') {
		LOG(LOG_ERROR, "Missing port separator in Manufacturer address\n");
		goto end;
	} else {
		index += 1;
	}

	// parse port for atmost 5 characters
	while (port_index < sizeof(port) -1 && index < buffer_sz && isdigit(buffer[index])) {
		port[port_index] = buffer[index];
		index++;
		port_index++;
	}
	if (port_index == 0) {
		LOG(LOG_ERROR, "No port specified in Manufacturer address\n");
		goto end;
	}
	port[port_index] = '\0';

	// check for trailing '/'
	if (index < buffer_sz && buffer[index] == '/') {
		index++;
	}
	// check for new-line or EOF or null-character
	if (index < buffer_sz && (buffer[index] == EOF || buffer[index] == '\n' ||
		buffer[index] == '\0')) {
		index++;
	}

	if (buffer_sz != index) {
		LOG(LOG_ERROR, "Invalid data in Manufacturer address\n");
		goto end;
	}

	// validate transport protocol. check for 'http' first, then 'https'
	*tls = false;
	if (memcmp_s(transport_prot, sizeof(transport_prot), transport_http,
			sizeof(transport_http), &result) != 0) {
		LOG(LOG_ERROR, "Failed to compare transport protocol\n");
		goto end;
	}
	if (0 != result) {
		if (memcmp_s(transport_prot, sizeof(transport_prot), transport_https,
			sizeof(transport_https), &result) != 0) {
			LOG(LOG_ERROR, "Failed to compare transport protocol\n");
			goto end;
		}
		if (0 == result) {
			*tls = true;
			LOG(LOG_DEBUG, "Manufacturer Transport protocol: HTTPS\n");
		} else {
			LOG(LOG_ERROR, "Invalid Manufacturer Transport protocol specified.\n");
			goto end;
		}
	} else {
		LOG(LOG_DEBUG, "Manufacturer Transport protocol: HTTP\n");
	}

	// validate IP/DNS, check for IP first, if it fails, treat it as DNS
	// allocate IP structure here
	// if a valid IP is found, return the IP structure conatining IP, that must be freed by caller
	// if a valid IP is not found, free the IP structure immediately and return NULL IP structure
	*mfg_ip = fdo_ipaddress_alloc();
	if (!*mfg_ip) {
		LOG(LOG_ERROR, "Failed to alloc memory\n");
		ERROR();
		goto end;
	}
	result = fdo_printable_to_net(mfg_dns, (*mfg_ip)->addr);
	if (result > 0) {
		// valid IP address
		(*mfg_ip)->length = IPV4_ADDR_LEN;
		LOG(LOG_DEBUG, "Manufacturer IP will be used\n");
	} else if (result == 0) {
		// not an IP address, so treat it as DNS address
		LOG(LOG_DEBUG, "Manufacturer DNS will be used\n");
		fdo_free(*mfg_ip);
		// DNS contains atleast 1 alphabet
		if (count_dns_alphabets <= 0) {
			LOG(LOG_DEBUG, "Invalid Manufacturer DNS\n");
			goto end;
		}
	}

	// validate port
	// set to 0 explicitly
	errno = 0;
	*mfg_port = strtol(port, &eptr, 10);
	if (!eptr || eptr == port || errno != 0) {
		LOG(LOG_ERROR, "Manufacturer port is not a number.\n");
		goto end;
	} else if (!((*mfg_port >= FDO_PORT_MIN_VALUE) &&
	      (*mfg_port <= FDO_PORT_MAX_VALUE))) {
		LOG(LOG_ERROR,
		    "Manufacturer port value should be between "
		    "[%d-%d].\n",
		    FDO_PORT_MIN_VALUE, FDO_PORT_MAX_VALUE);
		goto end;
	}
	LOG(LOG_DEBUG, "Manufacturer Port: %d\n", *mfg_port);
	return true;
end:
	return false;
}

/**
 * Internal API
 */
void print_service_info_module_list(void)
{
	fdo_sdk_service_info_module_list_t *list = g_fdo_data->module_list;

	if (list) {
		while (list != NULL) {
			LOG(LOG_DEBUG, "Service_info module-name: %s\n",
			    list->module.module_name);
			list = list->next;
		}
	}
}

/**
 * Sets device state to Resale if all conditions are met.
 * fdo_sdk_init should be called before calling this function
 *
 * @return ret
 *        FDO_RESALE_NOT_SUPPORTED: Device doesnt support resale
 *        FDO_ERROR: Error encountered while setting the state.
 *        FDO_RESALE_NOT_READY: Device is not in right state to initiate
 * resale.
 *        FDO_SUCCESS: Device set to resale state.
 */
fdo_sdk_status fdo_sdk_resale(void)
{
	int ret;
	fdo_sdk_status r = FDO_ERROR;

#ifdef DISABLE_RESALE
	return FDO_RESALE_NOT_SUPPORTED;
#endif

	if (!g_fdo_data) {
		return FDO_ERROR;
	}

	if (!g_fdo_data->devcred) {
		return FDO_ERROR;
	}

	if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_IDLE) {
		g_fdo_data->devcred->ST = FDO_DEVICE_STATE_READYN;

		if (load_device_secret()) {
			LOG(LOG_ERROR, "Reading {Mfg|Secret} blob failied!\n");
			return FDO_ERROR;
		}

		ret = store_credential(g_fdo_data->devcred);
		if (!ret) {
			LOG(LOG_INFO, "Set Resale complete\n");
			r = FDO_SUCCESS;
		}
	} else {
		r = FDO_RESALE_NOT_READY;
	}

	if (r == FDO_ERROR) {
		LOG(LOG_ERROR, "Failed to set Resale\n");
	} else if (r == FDO_RESALE_NOT_READY) {
		LOG(LOG_DEBUG, "Device is not ready for Resale\n");
	}
	if (g_fdo_data->devcred) {
		fdo_dev_cred_free(g_fdo_data->devcred);
		fdo_free(g_fdo_data->devcred);
		g_fdo_data->devcred = NULL;
	}

	fdo_free(g_fdo_data);
	g_fdo_data = NULL;
	return r;
}

/**
 * Undo what app_initialize do
 */
static void app_close(void)
{
	fdo_block_t *fdob = NULL;

	if (!g_fdo_data) {
		return;
	}

	if (g_fdo_data->prot.service_info && g_fdo_data->service_info) {
		fdo_service_info_free(g_fdo_data->service_info);
		g_fdo_data->service_info = NULL;
	}

	fdo_sdk_service_info_deregister_module();

	fdob = &g_fdo_data->prot.fdor.b;
	if (fdob->block) {
		fdo_free(fdob->block);
		fdob->block = NULL;
	}
	fdor_flush(&g_fdo_data->prot.fdor);

	fdob = &g_fdo_data->prot.fdow.b;
	if (fdob->block) {
		fdo_free(fdob->block);
		fdob->block = NULL;
	}
	fdow_flush(&g_fdo_data->prot.fdow);

	if (g_fdo_data->devcred) {
		fdo_dev_cred_free(g_fdo_data->devcred);
		fdo_free(g_fdo_data->devcred);
		g_fdo_data->devcred = NULL;
	}
}

/**
 * Handles DI state of device. Initializes protocol context engine,
 * initializse state variables and runs the DI protocol.
 *
 * @return ret
 *         true if DI completes successfully. false in case of error.
 */
static bool _STATE_DI(void)
{
	bool ret = false;
	fdo_prot_ctx_t *prot_ctx = NULL;

	fdo_ip_address_t *mfg_ip = NULL;
	char mfg_dns[100] = {0};
	int mfg_port = 0;

	bool tls = false;
	int32_t fsize = 0;
	char *buffer = NULL;

	LOG(LOG_DEBUG, "\n-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n"
		       "                                           "
		       "                                  Starting DI\n"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n");

	fdo_prot_di_init(&g_fdo_data->prot, g_fdo_data->devcred);

	fsize = fdo_blob_size((char *)MANUFACTURER_ADDR, FDO_SDK_RAW_DATA);
	if (fsize > 0) {
		buffer = fdo_alloc(fsize + 1);
		if (buffer == NULL) {
			LOG(LOG_ERROR, "malloc failed\n");
			goto end;
		}

		if (fdo_blob_read((char *)MANUFACTURER_ADDR, FDO_SDK_RAW_DATA,
				  (uint8_t *)buffer, fsize) == -1) {
			LOG(LOG_ERROR, "Failed to read Manufacturer address\n");
			goto end;
		}

		buffer[fsize] = '\0';

		if (!parse_manufacturer_address(buffer, fsize, &tls, &mfg_ip,
			mfg_dns, sizeof(mfg_dns), &mfg_port)) {
			LOG(LOG_ERROR, "Failed to parse Manufacturer Network address.\n");
			goto end;
		}
	} else {
		LOG(LOG_ERROR, "Manufacturer Network address file is empty.\n");
		goto end;
	}

	g_fdo_data->delaysec = default_delay;

	prot_ctx = fdo_prot_ctx_alloc(fdo_process_states, &g_fdo_data->prot,
				      mfg_ip, mfg_ip ? NULL : mfg_dns, mfg_port, tls);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (fdo_prot_ctx_run(prot_ctx) != 0) {
		LOG(LOG_ERROR, "DI failed.\n");
		if (g_fdo_data->error_recovery) {
			g_fdo_data->state_fn = &_STATE_DI;
			LOG(LOG_INFO, "\nDelaying for %"PRIu64" seconds\n\n", g_fdo_data->delaysec);
			fdo_sleep(g_fdo_data->delaysec);
			LOG(LOG_INFO, "Retrying.....\n");
			goto end;
		} else {
			ERROR()
			fdo_sleep(g_fdo_data->delaysec);
			goto end;
		}
	}
	LOG(LOG_DEBUG, "\n------------------------------------ DI Successful "
		       "--------------------------------------\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	LOG(LOG_INFO, "@FIDO Device Initialization Complete@\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

#ifdef NO_PERSISTENT_STORAGE
	g_fdo_data->state_fn = &_STATE_TO1;
	fdo_sleep(5);
#else
	g_fdo_data->state_fn = &_STATE_Shutdown;
#endif
	ret = true;
end:
	fdo_protDIExit(g_fdo_data);
	if (prot_ctx) {
		fdo_prot_ctx_free(prot_ctx);
		fdo_free(prot_ctx);
	}
	if (buffer) {
		fdo_free(buffer);
	}
	if (mfg_ip) {
		fdo_free(mfg_ip);
	}
	return ret;
}

/**
 * Handles TO1 state of device. Initializes protocol context engine,
 * initializse state variables and runs the TO1 protocol.
 *
 * @return ret
 *         true if TO1 completes successfully, or if RVBypass was encountered in RendezvousInfo
 *         false if all RendezvousDirectives have been tried and TO1 resulted in failure.
 */
static bool _STATE_TO1(void)
{
	bool ret = false;
	bool tls = true;
	bool skip_rv = false;
	fdo_prot_ctx_t *prot_ctx = NULL;

	LOG(LOG_DEBUG, "\n-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n"
		       "                                             "
		       "                                  Starting TO1\n"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n");

	if (fdo_prot_to1_init(&g_fdo_data->prot, g_fdo_data->devcred)) {
		goto end;
	}

	// check for rendezvous list
	if (!g_fdo_data->devcred->owner_blk->rvlst ||
	    g_fdo_data->devcred->owner_blk->rvlst->num_rv_directives == 0) {
		LOG(LOG_ERROR, "Stored Rendezvous_list is empty!!\n");
		ERROR();
		goto end;
	}

	// Try TO1 for all available RVDirectives.
	// Only checking for RVIP/RVDNS/RVPort/RVBypass/RVOwnerOnly flags.
	// Depending on the requirement, check for more flags should be added here.
	// If we encounter RVBYPASS, skip directly to TO2.
	// TO-DO: Integrate TO2 flow into this and fix it to start from the
	// next directive always in case of failure (ex: RVBypass)
	int port = 0;
	fdo_ip_address_t *ip = NULL;
	fdo_string_t *dns = NULL;

	if (g_fdo_data->current_rvdirective == NULL) {
		// keep track of current directive in use with the help of stored RendezvousInfo from DI.
		// it is NULL at 2 points: during 1st TO1 run, and,
		// when all RVDirectives have been used and we're re-trying
		g_fdo_data->current_rvdirective = g_fdo_data->devcred->owner_blk->rvlst->rv_directives;
	}

	// delay if we came back from RVBypass or re-try RVInfo with some value,
	// otherwise, delaysec will be 0
	fdo_sleep(g_fdo_data->delaysec);

	while (!ret && g_fdo_data->current_rvdirective) {
		fdo_rendezvous_t *rv = g_fdo_data->current_rvdirective->rv_entries;
		// reset for next use.
		port = 0;
		ip = NULL;
		dns = NULL;
		rvbypass = false;
		tls = true;
		skip_rv = false;
		g_fdo_data->delaysec = 0;

		while (rv) {

			if (rv->bypass && *rv->bypass == true) {
				rvbypass = true;
				break;
			} else if (rv->owner_only && *rv->owner_only) {
				LOG(LOG_DEBUG, "Found RVOwnerOnly. Skipping the directive...\n");
				skip_rv = true;
				break;
			} else if (rv->ip) {
				ip = rv->ip;
			} else if (rv->dn) {
				dns = rv->dn;
			} else if (rv->po) {
				port = *rv->po;
			} else if (rv->pr) {
				if (*rv->pr == RVPROTHTTP) {
					tls = false;
				} else if (*rv->pr == RVPROTHTTPS || *rv->pr == RVPROTTLS) {
					// nothing to do. TLS is already set
				} else {
					LOG(LOG_ERROR, "Unsupported/Invalid value found for RVProtocolValue. "
						"Skipping the directive...\n");
					skip_rv = true;
					break;
				}
			} else if (rv->delaysec) {
				g_fdo_data->delaysec = *rv->delaysec;
				LOG(LOG_INFO, "DelaySec set, Delay: %"PRIu64"s\n", g_fdo_data->delaysec);
			}
			// ignore the other RendezvousInstr as they are not used for making requests
			rv = rv->next;
		}

		if (rvbypass) {
			ret = true;
			LOG(LOG_DEBUG, "Found RVBYPASS in the RendezvousDirective. Skipping TO1...\n");
			g_fdo_data->state_fn = &_STATE_TO2;
			goto end;
		}

		// Found the  needed entries of the current directive. Prepare to move to next.
		g_fdo_data->current_rvdirective = g_fdo_data->current_rvdirective->next;

		if (skip_rv || (!ip && !dns) || port == 0) {
			// If any of the IP/DNS/Port values are missing, or
			// if RVOwnerOnly is present in the current directive, or
			// if unsupported/invalid RVProtocolValue was found
			// skip the current directive and check for the same in the next directives.
			continue;
		}

		prot_ctx =
	    	fdo_prot_ctx_alloc(fdo_process_states, &g_fdo_data->prot, ip,
		       dns ? dns->bytes : NULL, port, tls);
		if (prot_ctx == NULL) {
			ERROR();
			goto end;
		}

		if (fdo_prot_ctx_run(prot_ctx) != 0) {
			LOG(LOG_ERROR, "TO1 failed.\n");

			// clear contents for a fresh start.
			fdo_protTO1Exit(g_fdo_data);
			fdo_prot_ctx_free(prot_ctx);
			fdo_free(prot_ctx);

			// check if there is another RV location to try. if yes, try it
			// the delay interval is conditional
			if (g_fdo_data->current_rvdirective) {
				if (g_fdo_data->delaysec == 0 || g_fdo_data->delaysec > max_delay) {
					g_fdo_data->delaysec = default_delay;
				}
				LOG(LOG_INFO, "\nDelaying for %"PRIu64" seconds\n\n", g_fdo_data->delaysec);
				fdo_sleep(g_fdo_data->delaysec);
				continue;
			}

			// there are no more RV locations left, so check if retry is enabled.
			// if yes, proceed with retrying all the RV locations
			// if not, return immediately since there is nothing else left to do.
			if (g_fdo_data->error_recovery) {
				if (g_fdo_data->delaysec == 0 || g_fdo_data->delaysec > max_delay) {
					g_fdo_data->delaysec = default_delay_rvinfo_retries;
				}
				LOG(LOG_INFO, "\nDelaying for %"PRIu64" seconds\n\n", g_fdo_data->delaysec);
				g_fdo_data->state_fn = &_STATE_TO1;
				LOG(LOG_INFO, "Retrying.....\n");
				return ret;
			} else {
				LOG(LOG_INFO, "Retry is disabled. Aborting.....\n");
				return ret;
			}
		} else {
			LOG(LOG_DEBUG, "\n------------------------------------ TO1 Successful "
		       "--------------------------------------\n");
			ret = true;
			g_fdo_data->state_fn = &_STATE_TO2;
			goto end;
		}
	}

end:
	fdo_protTO1Exit(g_fdo_data);
	if (prot_ctx) {
		fdo_prot_ctx_free(prot_ctx);
		fdo_free(prot_ctx);
	}
	return ret;
}

/**
 * Handles TO2 state of device. Initializes protocol context engine,
 * initializse state variables and runs the TO2 protocol.
 *
 * @return ret
 *         true if TO2 completes successfully, or if there are more RendezvousDirectives that
 *         need to be processed,
 *         false if all RendezvousDirectives have been tried and TO2 resulted in failure.
 */
static bool _STATE_TO2(void)
{
	fdo_prot_ctx_t *prot_ctx = NULL;
	bool ret = false;

	LOG(LOG_DEBUG, "\n-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n"
		       "                                             "
		       "                                  Starting TO2\n"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------"
		       "-------------------------------------------\n");
	/* Initialize the key exchange mechanism */
	ret = fdo_kex_init();
	if (ret) {
		LOG(LOG_ERROR, "Failed to initialize key exchange algorithm\n");
		return FDO_ERROR;
	}

	if (!add_module_devmod()) {
		LOG(LOG_ERROR, "Failed to create devmod module\n");
		return FDO_ERROR;
	}

	if (!fdo_prot_to2_init(&g_fdo_data->prot, g_fdo_data->service_info,
			       g_fdo_data->devcred, g_fdo_data->module_list)) {
		LOG(LOG_ERROR, "TO2_Init() failed!\n");
		return FDO_ERROR;
	}

	if (!rvbypass && !g_fdo_data->current_rvto2addrentry) {
		// preset RVTO2Addr if we're going to run TO2 using it.
		fdo_rvto2addr_t *rvto2addr = g_fdo_data->prot.rvto2addr;
		if (!rvto2addr) {
			LOG(LOG_ERROR, "RVTO2Addr list is empty!\n");
			return FDO_ERROR;
		}
		g_fdo_data->current_rvto2addrentry = rvto2addr->rv_to2addr_entry;
	}

	int port = 0;
	fdo_ip_address_t *ip = NULL;
	fdo_string_t *dns = NULL;
	bool tls = true;
	bool skip_rv = false;

	// if thers is RVBYPASS enabled, we set 'rvbypass' flag to false
	// otherwise, there'll be RVTO2AddrEntry(s), and we iterate through it.
	// Only one of the conditions will satisfy, which is ensured by resetting of the 'rvbypass' flag,
	// and, eventual Nulling of the 'g_fdo_data->current_rvto2addrentry'
	// because we keep on moving to next.
	// Run the TO2 protocol regardless.
	if (rvbypass || g_fdo_data->current_rvto2addrentry) {

		tls = true;
		skip_rv = false;
		g_fdo_data->delaysec = 0;
		// if rvbypass is set by TO1, then pick the Owner's address from RendezvousInfo.
		// otherwise, pick the address from RVTO2AddrEntry.
		if (rvbypass) {
			fdo_rendezvous_t *rv = g_fdo_data->current_rvdirective->rv_entries;
			while (rv) {
				if (rv->ip) {
					ip = rv->ip;
				} else if (rv->dn) {
					dns = rv->dn;
				} else if (rv->po) {
					port = *rv->po;
				} else if (rv->pr) {
					if (*rv->pr == RVPROTHTTP) {
						tls = false;
					} else if (*rv->pr == RVPROTHTTPS || *rv->pr == RVPROTTLS) {
						// nothing to do. TLS is already set
					} else {
						LOG(LOG_ERROR, "Unsupported/Invalid value found for RVProtocolValue. "
							"Skipping the directive...\n");
						skip_rv = true;
						break;
					}
				} else if (rv->delaysec) {
					g_fdo_data->delaysec = *rv->delaysec;
					LOG(LOG_INFO, "DelaySec set, Delay: %"PRIu64"s\n", g_fdo_data->delaysec);
				}
				// no need to check for RVBYPASS here again, since we used it
				// to get here in the first place
				// ignore the other RendezvousInstr as they are not used for making requests
				rv = rv->next;
			}

			// Found the  needed entries of the current directive.
			// Prepare to move to next in case of failure
			g_fdo_data->current_rvdirective = g_fdo_data->current_rvdirective->next;

			// clear to1d, if present.
			// if this is null at 'TO2.ProveOVHdr, Type 61',then to1d COSE Signature
			// verification is avoided.
			// Else, COSE Signature verification is done.
			if (g_fdo_data->prot.to1d_cose != NULL) {
				fdo_cose_free(g_fdo_data->prot.to1d_cose);
			}

		} else {

			ip = fdo_ipaddress_alloc();
			if (g_fdo_data->current_rvto2addrentry->rvip && !fdo_convert_to_ipaddress(g_fdo_data->current_rvto2addrentry->rvip, ip)) {
				LOG(LOG_ERROR, "Failed to convert IP from RVTO2Addr into IPAddress!\n");
			}
			dns = g_fdo_data->current_rvto2addrentry->rvdns;
			port = g_fdo_data->current_rvto2addrentry->rvport;
			if (g_fdo_data->current_rvto2addrentry->rvprotocol == PROTHTTP) {
				tls = false;
			} else if (g_fdo_data->current_rvto2addrentry->rvprotocol == PROTHTTPS ||
				g_fdo_data->current_rvto2addrentry->rvprotocol == PROTTLS) {
				// nothing to do. TLS is already set
			} else {
				LOG(LOG_ERROR, "Unsupported/Invalid value found for RVProtocol. "
					"Skipping the RVTO2AddrEntry...\n");
				skip_rv = true;
			}
			// prepare for next iteration beforehand
			g_fdo_data->current_rvto2addrentry = g_fdo_data->current_rvto2addrentry->next;

		}

		if (skip_rv || (!ip && !dns && !port)) {
			// If all of the IP/DNS/Port values are missing, or
			// if RVOwnerOnly is present in the current directive, or
			// if unsupported/invalid RVProtocolValue/RVProtocol was found
			// for rvbypass, goto TO1
			// else, skip the directive
			if (!rvbypass) {
				// free only when rvbypass is false, since the allocation was done then.
				// Note: This may be unreachable.
				if (ip) {
					fdo_free(ip);
				}
				ip = NULL;
			} else {
				// set the global rvbypass flag to false so that we don't continue the loop
				// because of rvbypass
				rvbypass = false;
				g_fdo_data->state_fn = &_STATE_TO1;
				// return true so that TO1 is processed with the remaining directives
				ret = true;
				return ret;
			}
			g_fdo_data->state_fn = &_STATE_TO2;
			// return true so that TO2 is processed with the remaining directives
			ret = true;
			return ret;
		}

		prot_ctx = fdo_prot_ctx_alloc(
			fdo_process_states, &g_fdo_data->prot, ip, dns ? dns->bytes : NULL, port, tls);
		if (prot_ctx == NULL) {
			ERROR();
			return FDO_ABORT;
		}

		if (fdo_prot_ctx_run(prot_ctx) != 0 || g_fdo_data->prot.success == false) {
			LOG(LOG_ERROR, "TO2 failed.\n");
			/* Execute Sv_info type=FAILURE */
			if (!fdo_mod_exec_sv_infotype(
				g_fdo_data->prot.sv_info_mod_list_head,
				FDO_SI_FAILURE)) {
				LOG(LOG_ERROR, "Sv_info: One or more module's FAILURE "
						"CB failed\n");
			}
			fdo_protTO2Exit(g_fdo_data);
			fdo_prot_ctx_free(prot_ctx);
			fdo_free(prot_ctx);

			// Repeat some of the same operations as the failure case above
			// when processing RendezvousInfo/RVTO2Addr and they need to be skipped
			if (!rvbypass) {
				if (ip) {
					fdo_free(ip);
				}
				ip = NULL;
				LOG(LOG_INFO, "\nDelaying for %"PRIu64" seconds\n\n", default_delay);
				fdo_sleep(default_delay);
				// if there is another Owner location present, try it
				// the execution reaches here only if rvbypass was never set
				if (g_fdo_data->current_rvto2addrentry) {
					LOG(LOG_ERROR, "Retrying TO2 using the next RVTO2AddrEntry\n");
					g_fdo_data->state_fn = &_STATE_TO2;
					// return true so that TO2 is processed with the remaining directives
					ret = true;
					return ret;
				}
				// there's no more owner locations left to try,
				// so start retrying with TO1, if retry is enabled.
				if (g_fdo_data->error_recovery) {
					g_fdo_data->state_fn = &_STATE_TO1;
					LOG(LOG_ERROR, "All RVTO2AddreEntry(s) exhausted. "
						"Retrying TO1 using the next RendezvousDirective\n");
				}
			} else {
				rvbypass = false;
				g_fdo_data->state_fn = &_STATE_TO1;
				if (g_fdo_data->delaysec == 0 || g_fdo_data->delaysec > max_delay) {
					if (!g_fdo_data->current_rvdirective) {
						g_fdo_data->delaysec = default_delay_rvinfo_retries;
					} else {
						g_fdo_data->delaysec = default_delay;
					}
				}
				LOG(LOG_INFO, "\nDelaying for %"PRIu64" seconds\n\n", g_fdo_data->delaysec);
			}
			// if this is last directive (NULL), return false to mark end of 1 retry
			// else if there are more directives left, return true for trying those
			if (!g_fdo_data->current_rvdirective) {
				ret = false;
			} else {
				ret = true;
			}
			return ret;
		}

		// if we reach here no failures occurred and TO2 has completed.
		// So proceed for shutdown and break.
		g_fdo_data->state_fn = &_STATE_Shutdown;
		fdo_protTO2Exit(g_fdo_data);
		fdo_prot_ctx_free(prot_ctx);
		fdo_free(prot_ctx);

		if (!rvbypass) {
			// free only when rvbypass is false, since the allocation was done then.
			if (ip) {
				fdo_free(ip);
			}
			ip = NULL;
		} else {
			// set the global rvbypass flag to false so that we don't continue the loop
			// because of rvbypass
			rvbypass = false;
		}

		LOG(LOG_DEBUG, "\n------------------------------------ TO2 Successful "
				"--------------------------------------\n\n");
		LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		LOG(LOG_INFO, "@FIDO Device Onboard Complete@\n");
		LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
		ret = true;
	} else {
		LOG(LOG_ERROR, "Invalid State\n");
	}
	return ret;
}

/**
 * Sets state varilable to error and notifies the same to user.
 *
 * @return ret
 *         Returns true always.
 */
static bool _STATE_Error(void)
{
	LOG(LOG_ERROR, "err %d\n", g_fdo_data->err);
	LOG(LOG_INFO, "FIDO Device Onboard Failed.\n");
	g_fdo_data->state_fn = &_STATE_Shutdown_Error;

	return true;
}

/**
 * Sets device state to shutdown and fdo_frees all resources.
 *
 * @return ret
 *         Returns true always.
 */
static bool _STATE_Shutdown(void)
{
	if (g_fdo_data->prot.service_info && g_fdo_data->service_info) {
		fdo_service_info_free(g_fdo_data->service_info);
		g_fdo_data->service_info = NULL;
	}
	if (g_fdo_data->devcred) {
		fdo_dev_cred_free(g_fdo_data->devcred);
		fdo_free(g_fdo_data->devcred);
		g_fdo_data->devcred = NULL;
	}

	g_fdo_data->state_fn = NULL;

	if (g_fdo_data->prot.rvto2addr) {
		fdo_rvto2addr_free(g_fdo_data->prot.rvto2addr);
		g_fdo_data->prot.rvto2addr = NULL;
	}
	if (g_fdo_data->prot.to1d_cose) {
		fdo_cose_free(g_fdo_data->prot.to1d_cose);
		g_fdo_data->prot.to1d_cose = NULL;
	}

	/* Closing all crypto related functions.*/
	(void)fdo_crypto_close();
	fdo_kex_close();

	return true;
}

/**
 * Sets device state to shutdown and fdo_frees all resources.
 * This function is only called when an Error occurs.
 *
 * @return ret
 *         Returns false always.
 */
static bool _STATE_Shutdown_Error(void)
{

	/* Call the regular shutdown function.*/
	(void)_STATE_Shutdown();

	/* Return false becuase there has been a failure. */
	return false;
}
