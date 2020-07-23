/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements state machine of SDO library. Also contains entry
 * point to SDO library.
 */

#include "base64.h"
#include "cli.h"
#include "sdokeyexchange.h"
#include "network_al.h"
#include "sdoprotctx.h"
#include "sdonet.h"
#include "sdoprot.h"
#include "load_credentials.h"
#include "network_al.h"
#include "sdoCrypto.h"
#include "util.h"
#include <stdlib.h>
#include <unistd.h>
#include "safe_lib.h"
#include "sdodeviceinfo.h"

#define HTTPS_TAG "https"

int TO2_done;
typedef struct app_data_s {
	bool error_recovery;
	bool recovery_enabled;
	bool (*state_fn)(void);
	sdo_dev_cred_t *devcred;
	void *ssl;
	sdo_prot_t prot;
	int err;
	sdo_service_info_t *service_info;
	/* Temp, use the value in the configured rendezvous */
	sdo_ip_address_t *rendezvousIPAddr;
	char *rendezvousdns;
	uint32_t delaysec;
	/* Error handling callback */
	sdo_sdk_errorCB error_callback;
	/* Global Sv_info Module_list head pointer */
	sdo_sdk_service_info_module_list_t *module_list;
} app_data_t;

/* Globals */
static app_data_t *g_sdo_data;
extern int g_argc;
extern char **g_argv;

static bool _STATE_DI(void);
static bool _STATE_TO1(void);
static bool _STATE_TO2(void);
static bool _STATE_Error(void);
static bool _STATE_Shutdown(void);
static bool _STATE_Shutdown_Error(void);

static sdo_sdk_status app_initialize(void);
static void app_close(void);

#define ERROR()                                                                \
	{                                                                      \
		g_sdo_data->err = __LINE__;                                    \
		g_sdo_data->state_fn = &_STATE_Error;                          \
	}

/**
 * sdo_sdk_run is user API call to start device ownership
 * transfer
 * sdo_sdk_init should be called before calling this function
 * If device supports Device Initialization (DI) protocol,
 * then the first time invoking of this call completes DI
 * and for the next invoke completes transfer ownership protocols
 * (TO1 and TO2). If device does not support DI, then device is expected
 * to have credentials programmed in the factory and first time
 * invoking of this function will complete transfer ownership protocols.
 *
 * @return
 *        return SDO_SUCCESS on success. non-zero value from sdo_sdk_status
 * enum.
 */
sdo_sdk_status sdo_sdk_run(void)
{
	sdo_sdk_status ret = SDO_ERROR;

	if (!g_sdo_data) {
		LOG(LOG_ERROR,
		    "sdo_sdk not initialized. Call sdo_sdk_init first\n");
		goto end;
	}

	if (SDO_SUCCESS != app_initialize()) {
		goto end;
	}

	/* Loop until last state has been reached */
	while (1) {
		/* Nothing left to perform in state machine */
		if (!g_sdo_data->state_fn) {
			break;
		}

		/* Start the state machine */
		if (true == g_sdo_data->state_fn()) {
			ret = SDO_SUCCESS;
		} else {
			ret = SDO_ERROR;
		}
	}

end:
	app_close();
	/* This should be moved to sdo_sdk_exit when its available */
	sdo_free(g_sdo_data);
	return ret;
}

/**
 * Deallocate allocated  memories in DI protocol and exit from DI.
 *
 * @param app_data
 *        Pointer to the database containtain all sdo state variables.
 * @return ret
 *         None.
 */
static void sdo_protDIExit(app_data_t *app_data)
{
	sdo_prot_t *ps = &app_data->prot;

	sdor_flush(&ps->sdor);
	return;
}

/**
 * Release memory allocated as a part of DI protocol.
 *
 * @param app_data
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void sdo_protTO1Exit(app_data_t *app_data)
{
	sdo_prot_t *ps = &app_data->prot;

	if (ps->n4) {
		sdo_byte_array_free(ps->n4);
		ps->n4 = NULL;
	}
	sdor_flush(&ps->sdor);
}

/**
 * Release memory allocated as a part of TO2 protocol and exit.
 *
 * @param app_data
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void sdo_protTO2Exit(app_data_t *app_data)
{
	sdo_prot_t *ps = &app_data->prot;

	if (ps->tls_key != NULL) {
		sdo_public_key_free(ps->tls_key);
		ps->tls_key = NULL;
	}
	if (ps->local_key_pair != NULL) {
		sdo_public_key_free(ps->local_key_pair);
		ps->local_key_pair = NULL;
	}
	if (ps->ovoucher != NULL) {
		sdo_ov_free(ps->ovoucher);
		ps->ovoucher = NULL;
	}
	if (ps->rv != NULL) {
		sdo_rendezvous_free(ps->rv);
		ps->rv = NULL;
	}
	if (ps->osc != NULL) {
		if (ps->osc->si != NULL) {
			sdo_service_info_free(ps->osc->si);
			ps->osc->si = NULL;
		}
		sdo_free(ps->osc);
		ps->osc = NULL;
	}
	if (ps->iv != NULL) {
		sdo_iv_free(ps->iv);
		ps->iv = NULL;
	}
	if (ps->new_pk != NULL) {
		sdo_public_key_free(ps->new_pk);
		ps->new_pk = NULL;
	}
	if (ps->dns1 != NULL) {
		sdo_free(ps->dns1);
		ps->dns1 = NULL;
	}
	if (ps->n7 != NULL) {
		sdo_byte_array_free(ps->n7);
		ps->n7 = NULL;
	}
	if (ps->n7r != NULL) {
		sdo_byte_array_free(ps->n7r);
		ps->n7r = NULL;
	}

	/* clear Sv_info PSI/DSI/OSI related data */
	if (ps->dsi_info) {
		ps->dsi_info->list_dsi = ps->sv_info_mod_list_head;
		ps->dsi_info->module_dsi_index = 0;
	}
	sdo_sv_info_clear_module_psi_osi_index(ps->sv_info_mod_list_head);
	ps->total_dsi_rounds = 0;
	sdor_flush(&ps->sdor);
}
/**
 * Allocate memory to hold device credentials which includes owner credentials
 * and manufacturer credentials.
 *
 * @return ret
 *        return pointer to memory holding device credentials on success, NULL
 * on failure.
 */
sdo_dev_cred_t *app_alloc_credentials(void)
{
	if (!g_sdo_data) {
		return NULL;
	}
	if (g_sdo_data->devcred) {
		sdo_dev_cred_free(g_sdo_data->devcred);
		sdo_free(g_sdo_data->devcred);
	}
	g_sdo_data->devcred = sdo_dev_cred_alloc();

	if (!g_sdo_data->devcred)
		LOG(LOG_ERROR, "Device Credentials allocation failed !!");

	return g_sdo_data->devcred;
}

/**
 * Get pointer to memory holding device credentials which includes owner
 * credentials and manufacturer credentials.
 *
 * @return ret
 *        return pointer to memory holding device credentials on success, NULL
 * if memory not allocated yet.
 */
sdo_dev_cred_t *app_get_credentials(void)
{
	return g_sdo_data->devcred;
}

/**
 * Internal API
 */
static sdo_sdk_status app_initialize(void)
{
	int ret = SDO_ERROR;

	if (!g_sdo_data)
		return SDO_ERROR;

	/* Initialize service_info to NULL in case of early error. */
	g_sdo_data->service_info = NULL;

/* Enable/Disable Error Recovery */
#ifdef RETRY_FALSE
	g_sdo_data->error_recovery = false;
#else
	g_sdo_data->error_recovery = true;
#endif
	g_sdo_data->recovery_enabled = false;
	g_sdo_data->state_fn = &_STATE_TO1;
	if (memset_s(&g_sdo_data->prot, sizeof(sdo_prot_t), 0) != 0) {
		LOG(LOG_ERROR, "Memset Failed\n");
		return SDO_ERROR;
	}

	g_sdo_data->err = 0;

#ifdef CLI
	/* Process command line input. */
	ret = input_parameters(g_argc, g_argv);
	if (0 != ret) {
		return SDO_ERROR;
	}
#endif

	if (!sdow_init(&g_sdo_data->prot.sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return SDO_ERROR;
	}
	if (!sdor_init(&g_sdo_data->prot.sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		return SDO_ERROR;
	}

	if ((g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READY1) ||
	    (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READYN)) {
		ret = load_mfg_secret();
		if (ret)
			return SDO_ERROR;
	}

	// Read HMAC & MFG only if it is T01/T02.
	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_PC) {
		g_sdo_data->state_fn = &_STATE_DI;
#ifndef NO_PERSISTENT_STORAGE
		return 0;
#endif
	}

	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_IDLE) {
		LOG(LOG_INFO,
		    "SDO in Idle State. Device Onboarding already complete\n");
		g_sdo_data->state_fn = &_STATE_Shutdown;
		return SDO_SUCCESS;
	}

	/* Build up a test service info list */
	char *get_modules = NULL;

	g_sdo_data->service_info = sdo_service_info_alloc();

	if (!g_sdo_data->service_info) {
		LOG(LOG_ERROR, "Service_info List allocation failed!\n");
		return SDO_ERROR;
	}

	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:os",
				    OS_NAME);
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:arch",
				    ARCH);
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:version",
				    OS_VERSION);
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:device",
				    (char *)get_device_model());
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:sn",
				    (char *)get_device_serial_number());
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:sep",
				    SEPARATOR);
	sdo_service_info_add_kv_str(g_sdo_data->service_info, "sdodev:bin",
				    BIN_TYPE);
	if (g_sdo_data->devcred->mfg_blk && g_sdo_data->devcred->mfg_blk->cu &&
	    g_sdo_data->devcred->mfg_blk->cu->byte_sz)
		sdo_service_info_add_kv_str(
		    g_sdo_data->service_info, "sdodev:cu",
		    g_sdo_data->devcred->mfg_blk->cu->bytes);
	else
		sdo_service_info_add_kv_str(g_sdo_data->service_info,
					    "sdodev:cu", "");

	if (g_sdo_data->devcred->mfg_blk && g_sdo_data->devcred->mfg_blk->ch &&
	    g_sdo_data->devcred->mfg_blk->ch->hash->byte_sz)
		sdo_service_info_add_kv(
		    g_sdo_data->service_info,
		    sdo_kv_alloc_with_array(
			"sdodev:ch", g_sdo_data->devcred->mfg_blk->ch->hash));
	else
		sdo_service_info_add_kv_str(g_sdo_data->service_info,
					    "sdodev:ch", "");

	if (sdo_construct_module_list(g_sdo_data->module_list, &get_modules)) {
		sdo_service_info_add_kv_str(g_sdo_data->service_info,
					    "sdodev:modules", get_modules);
		sdo_free(get_modules);
	}

	if (sdo_null_ipaddress(&g_sdo_data->prot.i1) == false) {
		return SDO_ERROR;
	}

	return SDO_SUCCESS;
}

/**
 * Get SDO device state
 * sdo_sdk_init should be called before calling this function
 *
 * @return sdo_sdk_device_state type
 *	SDO_STATE_PRE_DI  : Device is ready for DI
 *	SDO_STATE_PRE_TO1 : Device is ready for Ownership transfer
 *	SDO_STATE_IDLE    : Device's ownership transfer done
 *	SDO_STATE_RESALE  : Device is ready for ownership transfer
 *	SDO_STATE_ERROR   : Error in getting device status
 *
 */
sdo_sdk_device_state sdo_sdk_get_status(void)
{
	sdo_sdk_device_state status = SDO_STATE_ERROR;

	if (g_sdo_data == NULL)
		return SDO_STATE_ERROR;

	g_sdo_data->err = 0;

	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_PC) {
		status = SDO_STATE_PRE_DI;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READY1) {
		status = SDO_STATE_PRE_TO1;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_IDLE) {
		status = SDO_STATE_IDLE;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READYN) {
		status = SDO_STATE_RESALE;
	}

	return status;
}

/**
 * API to register Service_info modules, for later communicaton with Owner
 * server.
 * This API is exposed to all the SDO Service_info modules, modules must call
 * this
 * API for registering themselves to SDO.
 *
 * @param
 *        module: pointer to a 'SDO service_info Module struct'
 *
 * @return none
 */

void sdo_sdk_service_info_register_module(sdo_sdk_service_info_module *module)
{
	if (module == NULL)
		return;

	sdo_sdk_service_info_module_list_t *new =
	    sdo_alloc(sizeof(sdo_sdk_service_info_module_list_t));

	if (new == NULL) {
		LOG(LOG_ERROR, "malloc failed\n");
		return;
	}

	if (memcpy_s(&new->module, sizeof(sdo_sdk_service_info_module), module,
		     sizeof(sdo_sdk_service_info_module)) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdo_free(new);
		return;
	}

	if (g_sdo_data->module_list == NULL) {
		// 1st module to register
		g_sdo_data->module_list = new;
	} else {
		sdo_sdk_service_info_module_list_t *list =
		    g_sdo_data->module_list;

		while (list->next != NULL)
			list = list->next;

		list->next = new;
	}
}

static sdo_sdk_service_info_module_list_t *
clear_modules_list(sdo_sdk_service_info_module_list_t *head)
{
	if (head->next != NULL) {
		head->next = clear_modules_list(head->next);
	}
	sdo_free(head);
	head = NULL;
	return head;
}

/**
 * API to de register Service_info modules, for later communicaton with Owner
 * server.
 * This API is exposed to all the SDO Service_info modules, modules must call
 * this
 * API for de- registering themselves after SDO complete.
 *
 * @param none
 *
 * @return none
 */

void sdo_sdk_service_info_deregister_module(void)
{
	sdo_sdk_service_info_module_list_t *list = g_sdo_data->module_list;
	if (list) {
		g_sdo_data->module_list = clear_modules_list(list);
	}
}

void sdo_sdk_deinit(void)
{
	(void)sdo_crypto_close();

	app_close();
	if (g_sdo_data) {
		sdo_free(g_sdo_data);
	}
}

/**
 * sdo_sdk_init is the first function should be called before calling
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
 * @return SDO_SUCCESS for true, else SDO_ERROR
 */

sdo_sdk_status sdo_sdk_init(sdo_sdk_errorCB error_handling_callback,
			    uint32_t num_modules,
			    sdo_sdk_service_info_module *module_information)
{
	int ret;

	/* sdo Global data initialization */
	g_sdo_data = sdo_alloc(sizeof(app_data_t));

	if (!g_sdo_data) {
		LOG(LOG_ERROR, "malloc failed to alloc app_data_t\n");
		return SDO_ERROR;
	}

	g_sdo_data->err = 0;

	/* Initialize Crypto services */
	if (0 != sdo_crypto_init()) {
		LOG(LOG_ERROR, "sdo_crypto_init failed!!\n");
		return SDO_ERROR;
	}

	sdo_net_init();

	if (!sdow_init(&g_sdo_data->prot.sdow)) {
		LOG(LOG_ERROR, "sdow_init() failed!\n");
		return SDO_ERROR;
	}
	if (!sdor_init(&g_sdo_data->prot.sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdor_init() failed!\n");
		return SDO_ERROR;
	}

	/* Load credentials */
	ret = load_credential();
	if (ret) {
		printf("load fail -----------------\n");
		return SDO_ERROR;
	}

#ifdef MODULES_ENABLED
	if ((num_modules == 0) || (num_modules > SDO_MAX_MODULES) ||
	    (module_information == NULL) ||
	    (module_information->service_info_callback == NULL))
		return SDO_ERROR;

	/* register service-info modules */
	for (uint32_t i = 0; i < num_modules; i++) {
		if (module_information != NULL)
			sdo_sdk_service_info_register_module(
			    &module_information[i]);
	}
#else
	(void)num_modules;
	(void)module_information;
#endif

	/* Get the callback from user */
	g_sdo_data->error_callback = error_handling_callback;

	return SDO_SUCCESS;
}

#ifdef MODULES_ENABLED
/**
 * Internal API
 */
void print_service_info_module_list(void)
{
	sdo_sdk_service_info_module_list_t *list = g_sdo_data->module_list;

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
 * sdo_sdk_init should be called before calling this function
 *
 * @return ret
 *        SDO_RESALE_NOT_SUPPORTED: Device doesnt support resale
 *        SDO_ERROR: Error encountered while setting the state.
 *        SDO_RESALE_NOT_READY: Device is not in right state to initiate
 * resale.
 *        SDO_SUCCESS: Device set to resale state.
 */
sdo_sdk_status sdo_sdk_resale(void)
{
	int ret;
	sdo_sdk_status r = SDO_ERROR;

#ifdef DISABLE_RESALE
	return SDO_RESALE_NOT_SUPPORTED;
#endif

	if (!g_sdo_data)
		return SDO_ERROR;

	if (!g_sdo_data->devcred)
		return SDO_ERROR;

	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_IDLE) {
		g_sdo_data->devcred->ST = SDO_DEVICE_STATE_READYN;

		if (load_mfg_secret()) {
			LOG(LOG_ERROR, "Reading {Mfg|Secret} blob failied!\n");
			return SDO_ERROR;
		}

		ret = store_credential(g_sdo_data->devcred);
		if (!ret) {
			LOG(LOG_INFO, "Set Resale complete\n");
			r = SDO_SUCCESS;
		}
	} else {
		r = SDO_RESALE_NOT_READY;
	}

	if (r == SDO_ERROR) {
		LOG(LOG_ERROR, "Failed to set Resale\n");
	} else if (r == SDO_RESALE_NOT_READY) {
		LOG(LOG_DEBUG, "Device is not ready for Resale\n");
	}
	if (g_sdo_data->devcred) {
		sdo_dev_cred_free(g_sdo_data->devcred);
		sdo_free(g_sdo_data->devcred);
		g_sdo_data->devcred = NULL;
	}

	sdo_free(g_sdo_data);
	g_sdo_data = NULL;
	return r;
}

/**
 * Undo what app_initialize do
 */
static void app_close(void)
{
	sdo_block_t *sdob;

	if (!g_sdo_data)
		return;

	sdo_kex_close();

	if (g_sdo_data->service_info) {
		sdo_service_info_free(g_sdo_data->service_info);
		g_sdo_data->service_info = NULL;
	}

	sdo_sdk_service_info_deregister_module();

	sdob = &g_sdo_data->prot.sdor.b;
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}

	sdob = &g_sdo_data->prot.sdow.b;
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}

	if (g_sdo_data->devcred) {
		sdo_dev_cred_free(g_sdo_data->devcred);
		sdo_free(g_sdo_data->devcred);
		g_sdo_data->devcred = NULL;
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
	sdo_prot_ctx_t *prot_ctx = NULL;
	sdo_sdk_status status = SDO_SUCCESS;
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

	sdo_prot_di_init(&g_sdo_data->prot, g_sdo_data->devcred);

	sdo_ip_address_t *manIPAddr = NULL;

#if defined(TARGET_OS_LINUX) || defined(TARGET_OS_MBEDOS) ||                   \
    defined(TARGET_OS_OPTEE)
	char *mfg_dns = NULL;
	int32_t fsize = 0;
	char *buffer = NULL;
	bool is_mfg_addr = false;

	fsize = sdo_blob_size((char *)MANUFACTURER_IP, SDO_SDK_RAW_DATA);
	if (fsize > 0) {
		buffer = sdo_alloc(fsize + 1);
		if (buffer == NULL) {
			LOG(LOG_ERROR, "malloc failed\n");
			goto end;
		}

		if (sdo_blob_read((char *)MANUFACTURER_IP, SDO_SDK_RAW_DATA,
				  (uint8_t *)buffer, fsize) == -1) {
			LOG(LOG_ERROR, "Failed to read Manufacture DN\n");
			sdo_free(buffer);
			goto end;
		}

		buffer[fsize] = '\0';
		manIPAddr = sdo_ipaddress_alloc();

		if (!manIPAddr) {
			LOG(LOG_ERROR, "Failed to alloc memory\n");
			ERROR()
			sdo_free(buffer);
			goto end;
		}
		int result = sdo_printable_to_net(buffer, manIPAddr->addr);

		if (result <= 0) {
			LOG(LOG_ERROR, "Failed to convert Mfg address\n");
			ERROR()
			sdo_free(buffer);
			goto end;
		}
		manIPAddr->length = IPV4_ADDR_LEN;
		sdo_free(buffer);
		is_mfg_addr = true;
	} else {
		fsize =
		    sdo_blob_size((char *)MANUFACTURER_DN, SDO_SDK_RAW_DATA);
		if (fsize > 0) {
			buffer = sdo_alloc(fsize + 1);
			if (buffer == NULL) {
				LOG(LOG_ERROR, "malloc failed\n");
				ERROR()
				goto end;
			}
			if (sdo_blob_read((char *)MANUFACTURER_DN,
					  SDO_SDK_RAW_DATA, (uint8_t *)buffer,
					  fsize) == -1) {
				LOG(LOG_ERROR,
				    "Failed to real Manufacture DN\n");
				sdo_free(buffer);
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
	manIPAddr = sdo_ipaddress_alloc();
	if (!manIPAddr) {
		LOG(LOG_ERROR, "Failed to alloc memory\n");
		ERROR()
		goto end;
	}
	int result = sdo_printable_to_net(MANUFACTURER_IP, manIPAddr->addr);

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

	fsize = sdo_blob_size((char *)MANUFACTURER_PORT, SDO_SDK_RAW_DATA);

	if ((fsize > 0) && (fsize <= SDO_PORT_MAX_LEN)) {
		char port_buffer[SDO_PORT_MAX_LEN + 1] = {0};
		char *extra_string = NULL;
		unsigned long configured_port = 0;

		if (sdo_blob_read((char *)MANUFACTURER_PORT, SDO_SDK_RAW_DATA,
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

		if (!((configured_port >= SDO_PORT_MIN_VALUE) &&
		      (configured_port <= SDO_PORT_MAX_VALUE))) {
			LOG(LOG_ERROR,
			    "Manufacturer port value should be between "
			    "[%d-%d].\n",
			    SDO_PORT_MIN_VALUE, SDO_PORT_MAX_VALUE);
			goto end;
		}

		di_port = (uint16_t)configured_port;

	} else if (fsize > 0) {
		LOG(LOG_ERROR,
		    "Manufacturer port value should be between "
		    "[%d-%d]. "
		    "It should not be zero prepended.\n",
		    SDO_PORT_MIN_VALUE, SDO_PORT_MAX_VALUE);
		goto end;
	}

	LOG(LOG_DEBUG, "Manufacturer Port = %d.\n", di_port);

	prot_ctx = sdo_prot_ctx_alloc(sdo_process_states, &g_sdo_data->prot,
				      manIPAddr, mfg_dns, di_port, false);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (sdo_prot_ctx_run(prot_ctx) != 0) {
		LOG(LOG_ERROR, "DI failed.\n");
		if (g_sdo_data->error_recovery) {
			LOG(LOG_INFO, "Retrying,.....\n");
			g_sdo_data->state_fn = &_STATE_DI;
			if (g_sdo_data->error_callback) {
				status = g_sdo_data->error_callback(
				    SDO_WARNING, SDO_DI_ERROR);

				if (status == SDO_ABORT) {
					g_sdo_data->error_recovery = false;
					g_sdo_data->recovery_enabled = false;
					ERROR();
					/* Aborting the state machine */
					goto end;
				}
			}
			sdo_sleep(3); /* Sleep and retry */
			goto end;
		} else {
			ERROR()
			sdo_sleep(g_sdo_data->delaysec + sdo_random() % 25);
			if (g_sdo_data->error_callback)
				status = g_sdo_data->error_callback(
				    SDO_ERROR, SDO_DI_ERROR);
			goto end;
		}
	}

	LOG(LOG_DEBUG, "\n------------------------------------ DI Successful "
		       "--------------------------------------\n");

#ifdef NO_PERSISTENT_STORAGE
	g_sdo_data->state_fn = &_STATE_TO1;
	sdo_sleep(5);
#else
	g_sdo_data->state_fn = &_STATE_Shutdown;
#endif
	ret = true;
end:
	sdo_protDIExit(g_sdo_data);
	sdo_prot_ctx_free(prot_ctx);
	sdo_free(manIPAddr);
	sdo_free(mfg_dns);
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
	sdo_prot_ctx_t *prot_ctx = NULL;
	sdo_sdk_status status = SDO_SUCCESS;

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

	if (sdo_prot_to1_init(&g_sdo_data->prot, g_sdo_data->devcred)) {
		goto end;
	}

	sdo_prot_t *ps = &g_sdo_data->prot;

	// check for rendezvous list
	if (!g_sdo_data->devcred->owner_blk->rvlst ||
	    g_sdo_data->devcred->owner_blk->rvlst->num_entries == 0) {
		LOG(LOG_ERROR, "Stored Rendezvous_list is empty!!\n");
		ERROR();
		goto end;
	}

	ps->rv_index = ps->rv_index + 1;
	if (ps->rv_index > g_sdo_data->devcred->owner_blk->rvlst->num_entries)
		ps->rv_index =
		    ps->rv_index %
		    g_sdo_data->devcred->owner_blk->rvlst->num_entries;
	sdo_rendezvous_t *rv =
	    g_sdo_data->devcred->owner_blk->rvlst->rv_entries;
	for (int i = 1; i < ps->rv_index; i++)
		rv = rv->next;

	if (rv == NULL) {
		ERROR();
		goto end;
	} else {
		/* use the rendevous address from credential file ... pick
		 * first/only entry in the list
		 */
		if (!rv->ip && !rv->dn) {
			/* TODO put error cb	ERROR(); */
			ret = true;
			goto end;
		}

		/*if delay not specified in Rendezvous then 120s is default*/
		int strcmp_result = -1;

		if (rv->pr)
			strcmp_s(HTTPS_TAG, sizeof(HTTPS_TAG), rv->pr->bytes,
				 &strcmp_result);
		if (0 == strcmp_result)
			tls = true;
	}

	prot_ctx =
	    sdo_prot_ctx_alloc(sdo_process_states, &g_sdo_data->prot, rv->ip,
			       rv->dn ? rv->dn->bytes : NULL, *rv->po, tls);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (sdo_prot_ctx_run(prot_ctx) != 0) {
		LOG(LOG_ERROR, "TO1 failed.\n");
		if (g_sdo_data->error_recovery) {
			LOG(LOG_INFO, "Retrying,.....\n");
			g_sdo_data->state_fn = &_STATE_TO1;
			if (g_sdo_data->error_callback) {
				status = g_sdo_data->error_callback(
				    SDO_WARNING, SDO_TO1_ERROR);

				if (status == SDO_ABORT) {
					g_sdo_data->error_recovery = false;
					g_sdo_data->recovery_enabled = false;
					ERROR();
					goto end;
				}
			}
			sdo_sleep(3);
			/* Error recovery is enabled, so, it's not the final
			 * status
			 */
			goto end;
		} else {
			ERROR()
			sdo_sleep(g_sdo_data->delaysec + sdo_random() % 25);
			if (g_sdo_data->error_callback)
				status = g_sdo_data->error_callback(
				    SDO_ERROR, SDO_TO1_ERROR);
			goto end;
		}
	}

	LOG(LOG_DEBUG, "\n------------------------------------ TO1 Successful "
		       "--------------------------------------\n");

	g_sdo_data->state_fn = &_STATE_TO2;
	ret = true;
end:
	sdo_protTO1Exit(g_sdo_data);
	sdo_prot_ctx_free(prot_ctx);
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
	sdo_prot_ctx_t *prot_ctx = NULL;
	sdo_block_t *sdob;
	bool ret = false;
	sdo_sdk_status status = SDO_SUCCESS;

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
	ret = sdo_kex_init();
	if (ret) {
		LOG(LOG_ERROR, "Failed to initialize key exchange algorithm\n");
		return SDO_ERROR;
	}

	if (!sdo_prot_to2_init(&g_sdo_data->prot, g_sdo_data->service_info,

			       g_sdo_data->devcred, g_sdo_data->module_list)) {
		LOG(LOG_ERROR, "TO2_Init() failed!\n");
		goto err;
	}

	prot_ctx = sdo_prot_ctx_alloc(
	    sdo_process_states, &g_sdo_data->prot, &g_sdo_data->prot.i1,
	    g_sdo_data->prot.dns1, (uint16_t)g_sdo_data->prot.port1, false);
	if (prot_ctx == NULL) {
		ERROR();
		goto err;
	}

	if (sdo_prot_ctx_run(prot_ctx) != 0) {
		ERROR();
		goto err;
	}

	if (g_sdo_data->prot.success == false) {
		ERROR();
		LOG(LOG_ERROR, "TO2 failed.\n");

		/* Execute Sv_info type=FAILURE */
		if (!sdo_mod_exec_sv_infotype(
			g_sdo_data->prot.sv_info_mod_list_head,
			SDO_SI_FAILURE)) {
			LOG(LOG_ERROR, "Sv_info: One or more module's FAILURE "
				       "CB failed\n");
		}

		goto err;
	}

	g_sdo_data->state_fn = &_STATE_Shutdown;

	sdo_protTO2Exit(g_sdo_data);

	LOG(LOG_DEBUG, "\n------------------------------------ TO2 Successful "
		       "--------------------------------------\n\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	LOG(LOG_INFO, "@Secure Device Onboarding Complete@\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	TO2_done = 1;

	sdor_t *sdor = &prot_ctx->protdata->sdor;
	sdow_t *sdow = &prot_ctx->protdata->sdow;

	sdob = &sdor->b;
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}

	sdob = &sdow->b;
	if (sdob->block) {
		sdo_free(sdob->block);
		sdob->block = NULL;
	}

	ret = true;
err:
	sdo_prot_ctx_free(prot_ctx);
	if (g_sdo_data->prot.success == false) {
		if (g_sdo_data->error_recovery) {
			LOG(LOG_INFO, "Retrying TO2,.....\n");
			g_sdo_data->recovery_enabled = true;
			g_sdo_data->state_fn = &_STATE_TO1;
			sdo_protTO2Exit(g_sdo_data);
			if (g_sdo_data->error_callback)
				status = g_sdo_data->error_callback(
				    SDO_WARNING, SDO_TO2_ERROR);

			sdo_sleep(3);
		} else {
			if (g_sdo_data->error_callback)
				status = g_sdo_data->error_callback(
				    SDO_ERROR, SDO_TO2_ERROR);
		}

		if (status == SDO_ABORT) {
			g_sdo_data->error_recovery = false;
			g_sdo_data->recovery_enabled = false;
			ERROR();
			ret = false;
		}
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
	LOG(LOG_ERROR, "err %d\n", g_sdo_data->err);
	LOG(LOG_INFO, "Secure Device Onboarding Failed.\n");
	g_sdo_data->state_fn = &_STATE_Shutdown_Error;

	return true;
}

/**
 * Sets device state to shutdown and sdo_frees all resources.
 *
 * @return ret
 *         Returns true always.
 */
static bool _STATE_Shutdown(void)
{
	if (g_sdo_data->service_info) {
		sdo_service_info_free(g_sdo_data->service_info);
		g_sdo_data->service_info = NULL;
	}
	if (g_sdo_data->devcred) {
		sdo_dev_cred_free(g_sdo_data->devcred);
		sdo_free(g_sdo_data->devcred);
		g_sdo_data->devcred = NULL;
	}

	g_sdo_data->state_fn = NULL;

	/* Closing all crypto related functions.*/
	(void)sdo_crypto_close();

	return true;
}

/**
 * Sets device state to shutdown and sdo_frees all resources.
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
