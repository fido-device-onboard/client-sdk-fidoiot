/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements state machine of FDO library. Also contains entry
 * point to FDO library.
 */

#include "base64.h"
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

int TO2_done;
typedef struct app_data_s {
	bool error_recovery;
	bool recovery_enabled;
	bool (*state_fn)(void);
	fdo_dev_cred_t *devcred;
	void *ssl;
	fdo_prot_t prot;
	int err;
	fdo_service_info_t *service_info;
	/* Temp, use the value in the configured rendezvous */
	fdo_ip_address_t *rendezvousIPAddr;
	char *rendezvousdns;
	uint32_t delaysec;
	/* Error handling callback */
	fdo_sdk_errorCB error_callback;
	/* Global Sv_info Module_list head pointer */
	fdo_sdk_service_info_module_list_t *module_list;
	fdo_rendezvous_directive_t *current_rvdirective;
	fdo_rvto2addr_entry_t *current_rvto2addrentry;
} app_data_t;

/* Globals */
static app_data_t *g_fdo_data;
extern int g_argc;
extern char **g_argv;

#ifdef RETRY_FALSE
#define ERROR_RETRY_COUNT 1
#else
#define ERROR_RETRY_COUNT 5
#endif

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
	if (ps->local_key_pair != NULL) {
		fdo_public_key_free(ps->local_key_pair);
		ps->local_key_pair = NULL;
	}
	if (ps->ovoucher != NULL) {
		fdo_ov_free(ps->ovoucher);
		ps->ovoucher = NULL;
	}
	if (ps->rv != NULL) {
		fdo_rendezvous_free(ps->rv);
		ps->rv = NULL;
	}
	if (ps->osc != NULL) {
		if (ps->osc->si != NULL) {
			fdo_service_info_free(ps->osc->si);
			ps->osc->si = NULL;
		}
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
	if (ps->new_pk != NULL) {
		fdo_public_key_free(ps->new_pk);
		ps->new_pk = NULL;
	}
	if (ps->dns1 != NULL) {
		fdo_free(ps->dns1);
		ps->dns1 = NULL;
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

	/* clear Sv_info PSI/DSI/OSI related data */
	if (ps->dsi_info) {
		ps->dsi_info->list_dsi = ps->sv_info_mod_list_head;
		ps->dsi_info->module_dsi_index = 0;
	}
	fdo_sv_info_clear_module_psi_osi_index(ps->sv_info_mod_list_head);
	ps->total_dsi_rounds = 0;

	// clear FDOR, FDOW and reset state to start of TO2
	fdo_block_reset(&ps->fdor.b);
	ps->fdor.have_block = false;
	ps->fdor.b.block_size = ps->prot_buff_sz;
	fdo_block_reset(&ps->fdow.b);
	ps->fdow.b.block_size = ps->prot_buff_sz;
	ps->state = FDO_STATE_T02_SND_HELLO_DEVICE;
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

	if (!g_fdo_data->devcred)
		LOG(LOG_ERROR, "Device Credentials allocation failed !!");

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
	int32_t fsize;
	int max_serviceinfo_sz;
	char *buffer = NULL;
	char *eptr = NULL;

	if (!g_fdo_data)
		return FDO_ERROR;

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

	// read the file at path MAX_SERVICEINFO_SZ_FILE to get the maximum ServiceInfo size
	// that will be supported for both Owner and Device ServiceInfo
	// default to MIN_SERVICEINFO_SZ if the file is empty/non-existent
	// file of size 1 is also considered an empty file containing new-line character
	fsize = fdo_blob_size((char *)MAX_SERVICEINFO_SZ_FILE, FDO_SDK_RAW_DATA);
	if (fsize == 0 || fsize == 1) {
		g_fdo_data->prot.maxDeviceServiceInfoSz = MIN_SERVICEINFO_SZ;
		g_fdo_data->prot.maxOwnerServiceInfoSz = MIN_SERVICEINFO_SZ;
		g_fdo_data->prot.prot_buff_sz = MIN_SERVICEINFO_SZ + MSG_METADATA_SIZE;
	} else if (fsize > 0) {
		buffer = fdo_alloc(fsize + 1);
		if (buffer == NULL) {
			LOG(LOG_ERROR, "malloc failed\n");
		} else {
			if (fdo_blob_read((char *)MAX_SERVICEINFO_SZ_FILE, FDO_SDK_RAW_DATA,
					(uint8_t *)buffer, fsize) == -1) {
				LOG(LOG_ERROR, "Failed to read Manufacture DN\n");
			}
			// set to 0 explicitly
			errno = 0;
			max_serviceinfo_sz = strtol(buffer, &eptr, 10);
			if (!eptr || eptr == buffer || errno != 0) {
				LOG(LOG_ERROR, "Invalid value read for maximum ServiceInfo size.\n");
			}
			if (max_serviceinfo_sz <= MIN_SERVICEINFO_SZ) {
				max_serviceinfo_sz = MIN_SERVICEINFO_SZ;
			}
			else if (max_serviceinfo_sz >= MAX_SERVICEINFO_SZ) {
				max_serviceinfo_sz = MAX_SERVICEINFO_SZ;
			}
			g_fdo_data->prot.prot_buff_sz = max_serviceinfo_sz + MSG_METADATA_SIZE;
			g_fdo_data->prot.maxDeviceServiceInfoSz = max_serviceinfo_sz;
			g_fdo_data->prot.maxOwnerServiceInfoSz = max_serviceinfo_sz;
		}
	}
	if (buffer != NULL) {
		fdo_free(buffer);
	}

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
		ret = load_mfg_secret();
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

	// Build up default 'devmod' ServiceInfo list
	g_fdo_data->service_info = fdo_service_info_alloc();

	if (!g_fdo_data->service_info) {
		LOG(LOG_ERROR, "Service_info List allocation failed!\n");
		return FDO_ERROR;
	}

	fdo_service_info_add_kv_bool(g_fdo_data->service_info, "devmod:active",
				    true);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:os",
				    OS_NAME);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:arch",
				    ARCH);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:version",
				    OS_VERSION);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:device",
				    (char *)get_device_model());
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:sn",
				    (char *)get_device_serial_number());
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:pathsep",
				    PATH_SEPARATOR);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:sep",
				    SEPARATOR);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:nl",
				    NEWLINE);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:tmp",
				    "");
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:dir",
				    "");
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:progenv",
				    PROGENV);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:bin",
				    BIN_TYPE);
	fdo_service_info_add_kv_str(g_fdo_data->service_info, "devmod:mudurl",
				    "");

	// should ideally contain supported ServiceInfo module list and its count.
	// for now, set this to 1, since we've only 1 module 'fdo_sys'
	// TO-DO : Move this to fdotypes later when multiple Device ServiceInfo module
	// support is added.
	fdo_service_info_add_kv_int(g_fdo_data->service_info, "devmod:nummodules",
			    	1);

	if (fdo_null_ipaddress(&g_fdo_data->prot.i1) == false) {
		return FDO_ERROR;
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

	if (g_fdo_data == NULL)
		return FDO_STATE_ERROR;

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
	if (module == NULL)
		return;

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

		while (list->next != NULL)
			list = list->next;

		list->next = new;
	}
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
	ret = load_credential();
	if (ret == -1) {
		LOG(LOG_ERROR, "Load credential failed.\n");
		return FDO_ERROR;
	}

#ifdef MODULES_ENABLED
	if ((num_modules == 0) || (num_modules > FDO_MAX_MODULES) ||
	    (module_information == NULL) ||
	    (module_information->service_info_callback == NULL))
		return FDO_ERROR;

	/* register service-info modules */
	for (uint32_t i = 0; i < num_modules; i++) {
		if (module_information != NULL) {
			fdo_sdk_service_info_register_module(
			    &module_information[i]);
		}
	}
#else
	(void)num_modules;
	(void)module_information;
#endif

	/* Get the callback from user */
	g_fdo_data->error_callback = error_handling_callback;

	return FDO_SUCCESS;
}

#ifdef MODULES_ENABLED
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
#endif
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

	if (!g_fdo_data)
		return FDO_ERROR;

	if (!g_fdo_data->devcred)
		return FDO_ERROR;

	if (g_fdo_data->devcred->ST == FDO_DEVICE_STATE_IDLE) {
		g_fdo_data->devcred->ST = FDO_DEVICE_STATE_READYN;

		if (load_mfg_secret()) {
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
	fdo_block_t *fdob;

	if (!g_fdo_data)
		return;

	if (g_fdo_data->service_info) {
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

	if (g_fdo_data->prot.iv != NULL) {
		fdo_iv_free(g_fdo_data->prot.iv);
		g_fdo_data->prot.iv = NULL;
	}
}

static const uint16_t g_DI_PORT = 8039;

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
	uint16_t di_port = g_DI_PORT;

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

	fdo_ip_address_t *manIPAddr = NULL;

#if defined(TARGET_OS_LINUX) || defined(TARGET_OS_MBEDOS) ||                   \
    defined(TARGET_OS_OPTEE)
	char *mfg_dns = NULL;
	int32_t fsize = 0;
	char *buffer = NULL;
	bool is_mfg_addr = false;

	fsize = fdo_blob_size((char *)MANUFACTURER_IP, FDO_SDK_RAW_DATA);
	if (fsize > 0) {
		buffer = fdo_alloc(fsize + 1);
		if (buffer == NULL) {
			LOG(LOG_ERROR, "malloc failed\n");
			goto end;
		}

		if (fdo_blob_read((char *)MANUFACTURER_IP, FDO_SDK_RAW_DATA,
				  (uint8_t *)buffer, fsize) == -1) {
			LOG(LOG_ERROR, "Failed to read Manufacture DN\n");
			fdo_free(buffer);
			goto end;
		}

		buffer[fsize] = '\0';
		manIPAddr = fdo_ipaddress_alloc();

		if (!manIPAddr) {
			LOG(LOG_ERROR, "Failed to alloc memory\n");
			ERROR()
			fdo_free(buffer);
			goto end;
		}
		int result = fdo_printable_to_net(buffer, manIPAddr->addr);

		if (result <= 0) {
			LOG(LOG_ERROR, "Failed to convert Mfg address\n");
			ERROR()
			fdo_free(buffer);
			goto end;
		}
		manIPAddr->length = IPV4_ADDR_LEN;
		fdo_free(buffer);
		is_mfg_addr = true;
	} else {
		fsize =
		    fdo_blob_size((char *)MANUFACTURER_DN, FDO_SDK_RAW_DATA);
		if (fsize > 0) {
			buffer = fdo_alloc(fsize + 1);
			if (buffer == NULL) {
				LOG(LOG_ERROR, "malloc failed\n");
				ERROR()
				goto end;
			}
			if (fdo_blob_read((char *)MANUFACTURER_DN,
					  FDO_SDK_RAW_DATA, (uint8_t *)buffer,
					  fsize) == -1) {
				LOG(LOG_ERROR,
				    "Failed to real Manufacture DN\n");
				fdo_free(buffer);
				goto end;
			}
			buffer[fsize] = '\0';
			mfg_dns = buffer;
			is_mfg_addr = true;
		}
	}
	if (is_mfg_addr == false) {
		LOG(LOG_ERROR, "Failed to get neither ip/dn mfg address\n");
		ERROR()
		goto end;
	}
#else
#ifdef MANUFACTURER_IP
	manIPAddr = fdo_ipaddress_alloc();
	if (!manIPAddr) {
		LOG(LOG_ERROR, "Failed to alloc memory\n");
		ERROR()
		goto end;
	}
	int result = fdo_printable_to_net(MANUFACTURER_IP, manIPAddr->addr);

	if (result <= 0) {
		LOG(LOG_ERROR, "Failed to convert Mfg address\n");
		ERROR()
		goto end;
	}
	manIPAddr->length = IPV4_ADDR_LEN;
#endif

	const char *mfg_dns = NULL;
#ifdef MANUFACTURER_DN
	mfg_dns = MANUFACTURER_DN;
#endif
#endif

	/* If MANUFACTURER_PORT file does not exists or is a blank file then,
	 *  use existing global DI port(8039) else use configured value as DI
	 *  port
	 */

	fsize = fdo_blob_size((char *)MANUFACTURER_PORT, FDO_SDK_RAW_DATA);

	if ((fsize > 0) && (fsize <= FDO_PORT_MAX_LEN)) {
		char port_buffer[FDO_PORT_MAX_LEN + 1] = {0};
		char *extra_string = NULL;
		unsigned long configured_port = 0;

		if (fdo_blob_read((char *)MANUFACTURER_PORT, FDO_SDK_RAW_DATA,
				  (uint8_t *)port_buffer, fsize) == -1) {
			LOG(LOG_ERROR, "Failed to read manufacturer port\n");
			goto end;
		}

		configured_port = strtoul(port_buffer, &extra_string, 10);

		if (strnlen_s(extra_string, 1)) {
			LOG(LOG_ERROR, "Invalid character encounered in the "
				       "given port.\n");
			goto end;
		}

		if (!((configured_port >= FDO_PORT_MIN_VALUE) &&
		      (configured_port <= FDO_PORT_MAX_VALUE))) {
			LOG(LOG_ERROR,
			    "Manufacturer port value should be between "
			    "[%d-%d].\n",
			    FDO_PORT_MIN_VALUE, FDO_PORT_MAX_VALUE);
			goto end;
		}

		di_port = (uint16_t)configured_port;

	} else if (fsize > 0) {
		LOG(LOG_ERROR,
		    "Manufacturer port value should be between "
		    "[%d-%d]. "
		    "It should not be zero prepended.\n",
		    FDO_PORT_MIN_VALUE, FDO_PORT_MAX_VALUE);
		goto end;
	}

	LOG(LOG_DEBUG, "Manufacturer Port = %d.\n", di_port);

	prot_ctx = fdo_prot_ctx_alloc(fdo_process_states, &g_fdo_data->prot,
				      manIPAddr, mfg_dns, di_port, false);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (fdo_prot_ctx_run(prot_ctx) != 0) {
		LOG(LOG_ERROR, "DI failed.\n");
		if (g_fdo_data->error_recovery) {
			LOG(LOG_INFO, "Retrying.....\n");
			g_fdo_data->state_fn = &_STATE_DI;
			fdo_sleep(3);
			goto end;
		} else {
			ERROR()
			fdo_sleep(g_fdo_data->delaysec + fdo_random() % 25);
			goto end;
		}
	}

	LOG(LOG_DEBUG, "\n------------------------------------ DI Successful "
		       "--------------------------------------\n");

#ifdef NO_PERSISTENT_STORAGE
	g_fdo_data->state_fn = &_STATE_TO1;
	fdo_sleep(5);
#else
	g_fdo_data->state_fn = &_STATE_Shutdown;
#endif
	ret = true;
end:
	fdo_protDIExit(g_fdo_data);
	fdo_prot_ctx_free(prot_ctx);
	fdo_free(manIPAddr);
	fdo_free(mfg_dns);
	return ret;
}

/**
 * Handles TO1 state of device. Initializes protocol context engine,
 * initializse state variables and runs the TO1 protocol.
 *
 * @return ret
 *         true if DI completes successfully. false in case of error.
 */
static bool _STATE_TO1(void)
{
	bool ret = false;
	bool tls = false;
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
	bool rvowner_only = false;

	if (g_fdo_data->current_rvdirective == NULL) {
		// keep track of current directive in use with the help of stored RendezvousInfo from DI.
		// it is NULL at 2 points: during 1st TO1 run, and,
		// when all RVDirectives have been used and we're re-trying
		g_fdo_data->current_rvdirective = g_fdo_data->devcred->owner_blk->rvlst->rv_directives;
	}

	while (!ret && g_fdo_data->current_rvdirective) {
		fdo_rendezvous_t *rv = g_fdo_data->current_rvdirective->rv_entries;
		// reset for next use.
		port = 0;
		ip = NULL;
		dns = NULL;
		rvbypass = false;
		rvowner_only = false;
		tls = false;
		while (rv) {

			if (rv->bypass && *rv->bypass == true) {
				rvbypass = true;
				break;
			}
			if (rv->owner_only && *rv->owner_only == true) {
				rvowner_only = true;
				break;
			}

			if (rv->ip) {
				ip = rv->ip;
				rv = rv->next;
				continue;
			}
			if (rv->dn) {
				dns = rv->dn;
				rv = rv->next;
				continue;
			}
			if (rv->po) {
				port = *rv->po;
				rv = rv->next;
				continue;
			}
			if (rv->pr && (*rv->pr == RVPROTHTTPS || *rv->pr == RVPROTTLS)) {
				tls = true;
			}
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

		if (rvowner_only || (!ip && !dns) || port == 0) {
			// If any of the IP/DNS/Port values are missing, or
			// if RVOwnerOnly is prsent in the current directive,
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
			fdo_sleep(3);

			// check if there is another RV location to try. if yes, try it
			if (g_fdo_data->current_rvdirective) {
				continue;
			}
			// there are no more RV locations left, so check if retry is enabled.
			// if yes, proceed with retrying all the RV locations
			// if not, return immediately since there is nothing else left to do.
			if (g_fdo_data->error_recovery) {
				LOG(LOG_INFO, "Retrying.....\n");
				g_fdo_data->state_fn = &_STATE_TO1;
				return ret;
			} else {
				LOG(LOG_INFO, "Retry is diabled. Aborting.....\n");
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
	fdo_prot_ctx_free(prot_ctx);
	return ret;
}

/**
 * Handles TO2 state of device. Initializes protocol context engine,
 * initializse state variables and runs the TO2 protocol.
 *
 * @return ret
 *         true if DI completes successfully. false in case of error.
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

	if (!fdo_prot_to2_init(&g_fdo_data->prot, g_fdo_data->service_info,
			       g_fdo_data->devcred, g_fdo_data->module_list)) {
		LOG(LOG_ERROR, "TO2_Init() failed!\n");
		return FDO_ERROR;
	}

	if (!rvbypass) {
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
	bool tls = false;

	// if thers is RVBYPASS enabled, we enter the loop and set 'rvbypass' flag to false
	// otherwise, there'll be RVTO2AddrEntry(s), and we iterate through it.
	// Only one of the conditions will satisfy, which is ensured by resetting of the 'rvbypass' flag,
	// and, eventual Nulling of the 'g_fdo_data->current_rvto2addrentry'
	// because we keep on moving to next.
	// Run the TO2 protocol regardless.
	while (rvbypass || g_fdo_data->current_rvto2addrentry) {

		tls = false;
		// if rvbypass is set by TO1, then pick the Owner's address from RendezvousInfo.
		// otherwise, pick the address from RVTO2AddrEntry.
		if (rvbypass) {
			fdo_rendezvous_t *rv = g_fdo_data->current_rvdirective->rv_entries;
			if (rv->ip) {
				ip = rv->ip;
				rv = rv->next;
			}
			if (rv->dn) {
				dns = rv->dn;
				rv = rv->next;
			}
			if (rv->po) {
				port = *rv->po;
				rv = rv->next;
			}
			if (rv->pr && (*rv->pr == RVPROTHTTPS || *rv->pr == RVPROTTLS)) {
				tls = true;
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
			if (!fdo_convert_to_ipaddress(g_fdo_data->current_rvto2addrentry->rvip, ip)) {
				LOG(LOG_ERROR, "Failed to convert IP from RVTO2Addr into IPAddress!\n");
			}
			dns = g_fdo_data->current_rvto2addrentry->rvdns;
			port = g_fdo_data->current_rvto2addrentry->rvport;
			if (g_fdo_data->current_rvto2addrentry->rvprotocol == PROTHTTPS ||
				g_fdo_data->current_rvto2addrentry->rvprotocol == PROTTLS) {
				tls = true;
			}
			// prepare for next iteration beforehand
			g_fdo_data->current_rvto2addrentry = g_fdo_data->current_rvto2addrentry->next;

		}

		prot_ctx = fdo_prot_ctx_alloc(
			fdo_process_states, &g_fdo_data->prot, ip, dns ? dns->bytes : NULL, port, tls);
		if (prot_ctx == NULL) {
			ERROR();
			fdo_prot_ctx_free(prot_ctx);
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

			fdo_sleep(3);

			if (!rvbypass) {
				// free only when rvbypass is false, since the allocation was done then.
				fdo_free(ip);
				ip = NULL;
			} else {
				// set the global rvbypass flag to false so that we don't continue the loop
				// because of rvbypass
				rvbypass = false;
				g_fdo_data->state_fn = &_STATE_TO1;
				return ret;
			}
			
			// if there is another Owner location present, try it
			// the execution reaches here only if rvbypass was never set
			if (g_fdo_data->current_rvto2addrentry) {
				LOG(LOG_ERROR, "Retrying TO2 using the next RVTO2AddrEntry\n");
				continue;
			}
			// there's no more owner locations left to try,
			// so start retrying with TO1, if retry is enabled.
			if (g_fdo_data->error_recovery) {
				g_fdo_data->state_fn = &_STATE_TO1;
				LOG(LOG_ERROR, "All RVTO2AddreEntry(s) exhausted. "
					"Retrying TO1 using the next RendezvousDirective\n");
				return ret;
			}
		}

		// if we reach here no failures occurred and TO2 has completed.
		// So proceed for shutdown and break.
		g_fdo_data->state_fn = &_STATE_Shutdown;
		fdo_protTO2Exit(g_fdo_data);
		fdo_prot_ctx_free(prot_ctx);

		if (!rvbypass) {
			// free only when rvbypass is false, since the allocation was done then.
			fdo_free(ip);
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
		TO2_done = 1;
		ret = true;
		break;
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
	if (g_fdo_data->service_info) {
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
