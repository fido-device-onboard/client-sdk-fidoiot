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
#include "sdoprotctx.h"
#include "sdonet.h"
#include "sdoprot.h"
#include "load_credentials.h"
#include "network_al.h"
#include "sdoCryptoApi.h"
#include "util.h"
#include <stdlib.h>
#include <unistd.h>
#include "safe_lib.h"
#include "sdodeviceinfo.h"

#define HTTPS_TAG "https"

int TO2_done = 0;
typedef struct app_data_s {
	bool error_recovery;
	bool recovery_enabled;
	bool (*state_fn)(void);
	SDODevCred_t *devcred;
	void *ssl;
	SDOProt_t prot;
	int err;
	SDOServiceInfo_t *service_info;
	/* Temp, use the value in the configured rendezvous */
	SDOIPAddress_t *rendezvousIPAddr;
	char *rendezvousdns;
	uint32_t delaysec;
	/* Error handling callback */
	sdoSdkErrorCB error_callback;
	/* Global SvInfo ModuleList head pointer */
	sdoSdkServiceInfoModuleList_t *moduleList;
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

static sdoSdkStatus app_initialize(void);
static void app_close(void);

#define ERROR()                                                                \
	{                                                                      \
		g_sdo_data->err = __LINE__;                                    \
		g_sdo_data->state_fn = &_STATE_Error;                          \
	}

/**
 * sdoSdkRun is user API call to start device ownership
 * transfer
 * sdoSdkInit should be called before calling this function
 * If device supports Device Initialization (DI) protocol,
 * then the first time invoking of this call completes DI
 * and for the next invoke completes transfer ownership protocols
 * (TO1 and TO2). If device does not support DI, then device is expected
 * to have credentials programmed in the factory and first time
 * invoking of this function will complete transfer ownership protocols.
 *
 * @return
 *        return SDO_SUCCESS on success. non-zero value from sdoSdkStatus enum.
 */
sdoSdkStatus sdoSdkRun(void)
{
	sdoSdkStatus ret = SDO_ERROR;

	if (!g_sdo_data) {
		LOG(LOG_ERROR,
		    "sdoSdk not initialized. Call sdoSdkInit first\n");
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
	/* This should be moved to sdoSdkExit when its available */
	sdoFree(g_sdo_data);
	return ret;
}

/**
 * Deallocate allocated  memories in DI protocol and exit from DI.
 *
 * @param appData
 *        Pointer to the database containtain all sdo state variables.
 * @return ret
 *         None.
 */
static void sdoProtDIExit(app_data_t *appData)
{
	SDOProt_t *ps = &appData->prot;
	sdoRFlush(&ps->sdor);
	return;
}

/**
 * Release memory allocated as a part of DI protocol.
 *
 * @param appData
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void sdoProtTO1Exit(app_data_t *appData)
{
	SDOProt_t *ps = &appData->prot;

	if (ps->n4) {
		sdoByteArrayFree(ps->n4);
		ps->n4 = NULL;
	}
	sdoRFlush(&ps->sdor);
}

/**
 * Release memory allocated as a part of TO2 protocol and exit.
 *
 * @param appData
 *        Pointer to the database holds all protocol state variables.
 * @return ret
 *         None.
 */
static void sdoProtTO2Exit(app_data_t *appData)
{
	SDOProt_t *ps = &appData->prot;

	if (ps->tlsKey != NULL) {
		sdoPublicKeyFree(ps->tlsKey);
		ps->tlsKey = NULL;
	}
	if (ps->localKeyPair != NULL) {
		sdoPublicKeyFree(ps->localKeyPair);
		ps->localKeyPair = NULL;
	}
	if (ps->ovoucher != NULL) {
		sdoOvFree(ps->ovoucher);
		ps->ovoucher = NULL;
	}
	if (ps->rv != NULL) {
		sdoRendezvousFree(ps->rv);
		ps->rv = NULL;
	}
	if (ps->osc != NULL) {
		if (ps->osc->si != NULL) {
			sdoServiceInfoFree(ps->osc->si);
			ps->osc->si = NULL;
		}
		sdoFree(ps->osc);
		ps->osc = NULL;
	}
	if (ps->iv != NULL) {
		sdoIVFree(ps->iv);
		ps->iv = NULL;
	}
	if (ps->new_pk != NULL) {
		sdoPublicKeyFree(ps->new_pk);
		ps->new_pk = NULL;
	}
	if (ps->dns1 != NULL) {
		sdoFree(ps->dns1);
		ps->dns1 = NULL;
	}
	if (ps->n7 != NULL) {
		sdoByteArrayFree(ps->n7);
		ps->n7 = NULL;
	}
	if (ps->n7r != NULL) {
		sdoByteArrayFree(ps->n7r);
		ps->n7r = NULL;
	}

	/* clear SvInfo PSI/DSI/OSI related data */
	if (ps->dsiInfo) {
		ps->dsiInfo->list_dsi = ps->SvInfoModListHead;
		ps->dsiInfo->moduleDsiIndex = 0;
	}
	sdoSvInfoClearModulePsiOsiIndex(ps->SvInfoModListHead);
	ps->totalDsiRounds = 0;
	sdoRFlush(&ps->sdor);
}
/**
 * Allocate memory to hold device credentials which includes owner credentials
 * and manufacturer credentials.
 *
 * @return ret
 *        return pointer to memory holding device credentials on success, NULL
 * on failure.
 */
SDODevCred_t *app_alloc_credentials(void)
{
	g_sdo_data->devcred = sdoDevCredAlloc();

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
SDODevCred_t *app_get_credentials(void)
{
	return g_sdo_data->devcred;
}

/**
 * Internal API
 */
static sdoSdkStatus app_initialize(void)
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
	if (memset_s(&g_sdo_data->prot, sizeof(SDOProt_t), 0) != 0) {
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

	if (!sdoWInit(&g_sdo_data->prot.sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return SDO_ERROR;
	}
	if (!sdoRInit(&g_sdo_data->prot.sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		return SDO_ERROR;
	}

	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READY1) {
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
	g_sdo_data->service_info = sdoServiceInfoAlloc();

	if (!g_sdo_data->service_info) {
		LOG(LOG_ERROR, "ServiceInfo List allocation failed!\n");
		return SDO_ERROR;
	}

	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:os", OS_NAME);
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:arch", ARCH);
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:version",
			       OS_VERSION);
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:device",
			       (char *)get_device_model());
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:sn",
			       (char *)get_device_serial_number());
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:sep",
			       SEPARATOR);
	sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:bin",
			       BIN_TYPE);
	if (g_sdo_data->devcred->mfgBlk && g_sdo_data->devcred->mfgBlk->cu &&
	    g_sdo_data->devcred->mfgBlk->cu->byteSz)
		sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:cu",
				       g_sdo_data->devcred->mfgBlk->cu->bytes);
	else
		sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:cu",
				       "");

	if (g_sdo_data->devcred->mfgBlk && g_sdo_data->devcred->mfgBlk->ch &&
	    g_sdo_data->devcred->mfgBlk->ch->hash->byteSz)
		sdoServiceInfoAddKV(
		    g_sdo_data->service_info,
		    sdoKVAllocWithArray("sdodev:ch",
					g_sdo_data->devcred->mfgBlk->ch->hash));
	else
		sdoServiceInfoAddKVStr(g_sdo_data->service_info, "sdodev:ch",
				       "");

	if (sdoConstructModuleList(g_sdo_data->moduleList, &get_modules)) {
		sdoServiceInfoAddKVStr(g_sdo_data->service_info,
				       "sdodev:modules", get_modules);
		sdoFree(get_modules);
	}

	if (sdoNullIPAddress(&g_sdo_data->prot.i1) == false) {
		return SDO_ERROR;
	}

	return SDO_SUCCESS;
}

/**
 * Get SDO device state
 * sdoSdkInit should be called before calling this function
 *
 * @return sdoSdkDeviceState type
 *	SDO_STATE_PRE_DI  : Device is ready for DI
 *	SDO_STATE_PRE_TO1 : Device is ready for Ownership transfer
 *	SDO_STATE_IDLE    : Device's ownership transfer done
 *	SDO_STATE_RESALE  : Device is ready for ownership transfer
 *	SDO_STATE_ERROR   : Error in getting device status
 *
 */
sdoSdkDeviceState sdoSdkGetStatus(void)
{
	sdoSdkDeviceState status = SDO_STATE_ERROR;

	if (g_sdo_data == NULL)
		return SDO_STATE_ERROR;

	g_sdo_data->err = 0;

	if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_PC) {
		status = SDO_STATE_PRE_DI;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READY1) {
		status = SDO_STATE_PRE_TO1;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_IDLE) {
		status = SDO_STATE_IDLE;
		;
	} else if (g_sdo_data->devcred->ST == SDO_DEVICE_STATE_READYN) {
		status = SDO_STATE_RESALE;
	}

	return status;
}

/**
 * API to register ServiceInfo modules, for later communicaton with Owner
 * server.
 * This API is exposed to all the SDO ServiceInfo modules, modules must call
 * this
 * API for registering themselves to SDO.
 *
 * @param
 *        module: pointer to a 'SDO serviceInfo Module struct'
 *
 * @return none
 */

void sdoSdkServiceInfoRegisterModule(sdoSdkServiceInfoModule *module)
{
	if (module == NULL)
		return;

	sdoSdkServiceInfoModuleList_t *new =
	    sdoAlloc(sizeof(sdoSdkServiceInfoModuleList_t));

	if (new == NULL) {
		LOG(LOG_ERROR, "malloc failed\n");
		return;
	}

	if (memcpy_s(&new->module, sizeof(sdoSdkServiceInfoModule), module,
		     sizeof(sdoSdkServiceInfoModule)) != 0) {
		LOG(LOG_ERROR, "Memcpy Failed\n");
		sdoFree(new);
		return;
	}

	if (g_sdo_data->moduleList == NULL) {
		// 1st module to register
		g_sdo_data->moduleList = new;
	} else {
		sdoSdkServiceInfoModuleList_t *list = g_sdo_data->moduleList;

		while (list->next != NULL)
			list = list->next;

		list->next = new;
	}
}

/**
 * sdoSdkInit is the first function should be called before calling
 * any API function
 * @param errorHandlingCallback
 * This is the Application’s error handling function and will be called by the
 * SDK when an error is encountered. This value can be NULL in which case,
 * errors will not be reported to the Application and the SDK will take the
 * appropriate recovery and/or restart action as required.
 * @param numModules - Number of Service Information modules contained in the
 * following moduleInformation list parameter. If no Application specific
 * modules are available, this value should be zero.
 * @param moduleInformation - if no Application specific modules are available,
 * this value should be NULL.
 * @return SDO_SUCCESS for true, else SDO_ERROR
 */

sdoSdkStatus sdoSdkInit(sdoSdkErrorCB errorHandlingCallback,
			uint32_t numModules,
			sdoSdkServiceInfoModule *moduleInformation)
{
	int ret;

	/* sdo Global data initialization */
	g_sdo_data = sdoAlloc(sizeof(app_data_t));

	if (!g_sdo_data) {
		LOG(LOG_ERROR, "malloc failed to alloc app_data_t\n");
		return SDO_ERROR;
	}

	g_sdo_data->err = 0;

	/* Initialize Crypto services */
	if (0 != sdoCryptoInit()) {
		LOG(LOG_ERROR, "sdoCryptoInit failed!!\n");
		return SDO_ERROR;
	}

	sdoNetInit();

	if (!sdoWInit(&g_sdo_data->prot.sdow)) {
		LOG(LOG_ERROR, "sdoWInit() failed!\n");
		return SDO_ERROR;
	}
	if (!sdoRInit(&g_sdo_data->prot.sdor, NULL, NULL)) {
		LOG(LOG_ERROR, "sdoRInit() failed!\n");
		return SDO_ERROR;
	}

	/* Load credentials */
	ret = load_credential();
	if (ret) {
		printf("load fail -----------------\n");
		return SDO_ERROR;
	}

#ifdef MODULES_ENABLED
	if ((numModules == 0) || (numModules > SDO_MAX_MODULES) ||
	    (moduleInformation == NULL) ||
	    (moduleInformation->serviceInfoCallback == NULL))
		return SDO_ERROR;

	/* register service-info modules */
	for (int i = 0; i < numModules; i++) {
		if (moduleInformation != NULL)
			sdoSdkServiceInfoRegisterModule(&moduleInformation[i]);
	}
#endif

	/* Get the callback from user */
	g_sdo_data->error_callback = errorHandlingCallback;

	return SDO_SUCCESS;
}

#ifdef MODULES_ENABLED
/**
 * Internal API
 */
void printServiceInfoModuleList(void)
{
	sdoSdkServiceInfoModuleList_t *list = g_sdo_data->moduleList;
	if (list) {
		while (list != NULL) {
			LOG(LOG_DEBUG, "ServiceInfo module-name: %s\n",
			    list->module.moduleName);
			list = list->next;
		}
	}
}
#endif
/**
 * Sets device state to Resale if all conditions are met.
 * sdoSdkInit should be called before calling this function
 *
 * @return ret
 *        SDO_RESALE_NOT_SUPPORTED: Device doesnt support resale
 *        SDO_ERROR: Error encountered while setting the state.
 *        SDO_RESALE_NOT_READY: Device is not in right state to initiate
 * resale.
 *        SDO_SUCCESS: Device set to resale state.
 */
sdoSdkStatus sdoSdkResale(void)
{
	int ret;
	sdoSdkStatus r = SDO_ERROR;

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
		sdoDevCredFree(g_sdo_data->devcred);
		sdoFree(g_sdo_data->devcred);
		g_sdo_data->devcred = NULL;
	}

	sdoFree(g_sdo_data);
	g_sdo_data = NULL;
	return r;
}

/**
 * Undo what app_initialize do
 */
static void app_close(void)
{
	SDOBlock_t *sdob;

	if (!g_sdo_data)
		return;

	sdoKexClose();

	if (g_sdo_data->service_info) {
		sdoServiceInfoFree(g_sdo_data->service_info);
		g_sdo_data->service_info = NULL;
	}

	sdob = &g_sdo_data->prot.sdor.b;
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}

	sdob = &g_sdo_data->prot.sdow.b;
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
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
	SDOProtCtx_t *prot_ctx = NULL;
	sdoSdkStatus status = SDO_SUCCESS;
	uint16_t diPort = g_DI_PORT;

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

	sdoProtDIInit(&g_sdo_data->prot, g_sdo_data->devcred);

	SDOIPAddress_t *manIPAddr = NULL;

#if defined(TARGET_OS_LINUX) || defined(TARGET_OS_MBEDOS)
	char *mfg_dns = NULL;
	int32_t fsize = 0;
	char *buffer = NULL;
	bool isMfgAddr = false;

	fsize = sdoBlobSize((char *)MANUFACTURER_IP, SDO_SDK_RAW_DATA);
	if (fsize > 0) {
		buffer = sdoAlloc(fsize + 1);
		if (buffer == NULL) {
			LOG(LOG_ERROR, "malloc failed\n");
			goto end;
		}

		if (sdoBlobRead((char *)MANUFACTURER_IP, SDO_SDK_RAW_DATA,
				(uint8_t *)buffer, fsize) == -1) {
			LOG(LOG_ERROR, "Failed to read Manufacture DN\n");
			sdoFree(buffer);
			goto end;
		}

		buffer[fsize] = '\0';
		manIPAddr = sdoIPAddressAlloc();

		if (!manIPAddr) {
			LOG(LOG_ERROR, "Failed to alloc memory\n");
			ERROR()
			sdoFree(buffer);
			goto end;
		}
		int result = sdoPrintableToNet(buffer, manIPAddr->addr);
		if (result <= 0) {
			LOG(LOG_ERROR, "Failed to convert Mfg address\n");
			ERROR()
			sdoFree(buffer);
			goto end;
		}
		manIPAddr->length = IPV4_ADDR_LEN;
		sdoFree(buffer);
		isMfgAddr = true;
	} else {
		fsize = sdoBlobSize((char *)MANUFACTURER_DN, SDO_SDK_RAW_DATA);
		if (fsize > 0) {
			buffer = sdoAlloc(fsize + 1);
			if (buffer == NULL) {
				LOG(LOG_ERROR, "malloc failed\n");
				ERROR()
				goto end;
			}
			if (sdoBlobRead((char *)MANUFACTURER_DN,
					SDO_SDK_RAW_DATA, (uint8_t *)buffer,
					fsize) == -1) {
				LOG(LOG_ERROR,
				    "Failed to real Manufacture DN\n");
				sdoFree(buffer);
				goto end;
			}
			buffer[fsize] = '\0';
			mfg_dns = buffer;
			isMfgAddr = true;
		}
	}
	if (isMfgAddr == false) {
		LOG(LOG_ERROR, "Failed to get neither ip/dn mfg address\n");
		ERROR()
		goto end;
	}
#else
#ifdef MANUFACTURER_IP
	manIPAddr = sdoIPAddressAlloc();
	if (!manIPAddr) {
		LOG(LOG_ERROR, "Failed to alloc memory\n");
		ERROR()
		goto end;
	}
	int result = sdoPrintableToNet(MANUFACTURER_IP, manIPAddr->addr);
	if (result <= 0) {
		LOG(LOG_ERROR, "Failed to convert Mfg address\n");
		ERROR()
		goto end;
	}
	manIPAddr->length = IPV4_ADDR_LEN;
#endif

	char *mfg_dns = NULL;
#ifdef MANUFACTURER_DN
	mfg_dns = MANUFACTURER_DN;
#endif
#endif

	/* If MANUFACTURER_PORT file does not exists or is a blank file then,
	   use existing global DI port(8039) else use configured value as DI
	   port */
	if (file_exists(MANUFACTURER_PORT)) {
		fsize =
		    sdoBlobSize((char *)MANUFACTURER_PORT, SDO_SDK_RAW_DATA);

		if ((fsize > 0) && (fsize <= SDO_PORT_MAX_LEN)) {
			char portBuffer[SDO_PORT_MAX_LEN + 1] = {0};
			char *extraString = NULL;
			long configuredPort = 0;

			if (sdoBlobRead((char *)MANUFACTURER_PORT,
					SDO_SDK_RAW_DATA, (uint8_t *)portBuffer,
					fsize) == -1) {
				LOG(LOG_ERROR,
				    "Failed to read manufacturer port\n");
				goto end;
			}

			configuredPort = strtol(portBuffer, &extraString, 10);

			if (strnlen_s(extraString, 1)) {
				LOG(LOG_ERROR,
				    "Invalid character encounered in the "
				    "given port.\n");
				goto end;
			}

			if (!((configuredPort >= SDO_PORT_MIN_VALUE) &&
			      (configuredPort <= SDO_PORT_MAX_VALUE))) {
				LOG(LOG_ERROR,
				    "Manufacturer port value should be between "
				    "[%d-%d].\n",
				    SDO_PORT_MIN_VALUE, SDO_PORT_MAX_VALUE);
				goto end;
			}

			diPort = (uint16_t)configuredPort;

		} else if (fsize > 0) {
			LOG(LOG_ERROR,
			    "Manufacturer port value should be between "
			    "[%d-%d]. "
			    "It should not be zero prepended.\n",
			    SDO_PORT_MIN_VALUE, SDO_PORT_MAX_VALUE);
			goto end;
		}
	}

	LOG(LOG_DEBUG, "Manufacturer Port = %d.\n", diPort);

	prot_ctx = sdoProtCtxAlloc(sdo_process_states, &g_sdo_data->prot,
				   manIPAddr, mfg_dns, diPort, false);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (sdoProtCtxRun(prot_ctx) != 0) {
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
			sdoSleep(3); /* Sleep and retry */
			goto end;
		} else {
			ERROR()
			sdoSleep(g_sdo_data->delaysec + sdoRandom() % 25);
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
	sdoSleep(5);
#else
	g_sdo_data->state_fn = &_STATE_Shutdown;
#endif
	ret = true;
end:
	sdoProtDIExit(g_sdo_data);
	sdoProtCtxFree(prot_ctx);
	sdoFree(manIPAddr);
#ifndef TARGET_OS_OPTEE
	sdoFree(mfg_dns);
#endif
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
	SDOProtCtx_t *prot_ctx = NULL;
	sdoSdkStatus status = SDO_SUCCESS;

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

	if (sdoProtTO1Init(&g_sdo_data->prot, g_sdo_data->devcred)) {
		goto end;
	}

	SDOProt_t *ps = &g_sdo_data->prot;

	// check for rendezvous list
	if (!g_sdo_data->devcred->ownerBlk->rvlst ||
	    g_sdo_data->devcred->ownerBlk->rvlst->numEntries == 0) {
		LOG(LOG_ERROR, "Stored RendezvousList is empty!!\n");
		ERROR();
		goto end;
	}

	ps->rvIndex = ps->rvIndex + 1;
	if (ps->rvIndex > g_sdo_data->devcred->ownerBlk->rvlst->numEntries)
		ps->rvIndex = ps->rvIndex %
			      g_sdo_data->devcred->ownerBlk->rvlst->numEntries;
	SDORendezvous_t *rv = g_sdo_data->devcred->ownerBlk->rvlst->rvEntries;
	for (int i = 1; i < ps->rvIndex; i++)
		rv = rv->next;

	if (rv == NULL) {
		ERROR();
		goto end;
	} else {
		/* use the rendevous address from credential file ... pick
		 * first/only entry in the list */
		if (!rv->ip && !rv->dn) {
			// TODO put error cb	ERROR();
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
	    sdoProtCtxAlloc(sdo_process_states, &g_sdo_data->prot, rv->ip,
			    rv->dn ? rv->dn->bytes : NULL, *rv->po, tls);
	if (prot_ctx == NULL) {
		ERROR();
		goto end;
	}

	if (sdoProtCtxRun(prot_ctx) != 0) {
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
			sdoSleep(3);
			/* Error recovery is enabled, so, it's not the final
			 * status */
			goto end;
		} else {
			ERROR()
			sdoSleep(g_sdo_data->delaysec + sdoRandom() % 25);
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
	sdoProtTO1Exit(g_sdo_data);
	sdoProtCtxFree(prot_ctx);
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
	SDOProtCtx_t *prot_ctx = NULL;
	SDOBlock_t *sdob;
	bool ret = false;
	sdoSdkStatus status = SDO_SUCCESS;

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
	ret = sdoKexInit();
	if (ret) {
		LOG(LOG_ERROR, "Failed to initialize key exchange algorithm\n");
		return SDO_ERROR;
	}

	if (!sdoProtTO2Init(&g_sdo_data->prot, g_sdo_data->service_info,

			    g_sdo_data->devcred, g_sdo_data->moduleList)) {
		LOG(LOG_ERROR, "TO2_Init() failed!\n");
		goto err;
	}

	prot_ctx = sdoProtCtxAlloc(sdo_process_states, &g_sdo_data->prot,
				   &g_sdo_data->prot.i1, g_sdo_data->prot.dns1,
				   (uint16_t)g_sdo_data->prot.port1, false);
	if (prot_ctx == NULL) {
		ERROR();
		goto err;
	}

	if (sdoProtCtxRun(prot_ctx) != 0) {
		ERROR();
		goto err;
	}

	if (g_sdo_data->prot.success == false) {
		ERROR();
		LOG(LOG_ERROR, "TO2 failed.\n");

		/* Execute SvInfo type=FAILURE */
		if (!sdoModExecSvInfotype(g_sdo_data->prot.SvInfoModListHead,
					  SDO_SI_FAILURE)) {
			LOG(LOG_ERROR,
			    "SvInfo: One or more module's FAILURE CB failed\n");
		}

		goto err;
	}

	g_sdo_data->state_fn = &_STATE_Shutdown;

	sdoProtTO2Exit(g_sdo_data);

	LOG(LOG_DEBUG, "\n------------------------------------ TO2 Successful "
		       "--------------------------------------\n\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	LOG(LOG_INFO, "@Secure Device Onboarding Complete@\n");
	LOG(LOG_INFO, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
	TO2_done = 1;

	SDOR_t *sdor = &prot_ctx->protdata->sdor;
	SDOW_t *sdow = &prot_ctx->protdata->sdow;

	sdob = &sdor->b;
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}

	sdob = &sdow->b;
	if (sdob->block) {
		sdoFree(sdob->block);
		sdob->block = NULL;
	}

	ret = true;
err:
	sdoProtCtxFree(prot_ctx);
	if (g_sdo_data->prot.success == false) {
		if (g_sdo_data->error_recovery) {
			LOG(LOG_INFO, "Retrying TO2,.....\n");
			g_sdo_data->recovery_enabled = true;
			g_sdo_data->state_fn = &_STATE_TO1;
			sdoProtTO2Exit(g_sdo_data);
			if (g_sdo_data->error_callback)
				status = g_sdo_data->error_callback(
				    SDO_WARNING, SDO_TO2_ERROR);

			sdoSleep(3);
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
 * Sets device state to shutdown and sdoFrees all resources.
 *
 * @return ret
 *         Returns true always.
 */
static bool _STATE_Shutdown(void)
{
	if (g_sdo_data->service_info) {
		sdoServiceInfoFree(g_sdo_data->service_info);
		g_sdo_data->service_info = NULL;
	}
	if (g_sdo_data->devcred) {
		sdoDevCredFree(g_sdo_data->devcred);
		sdoFree(g_sdo_data->devcred);
		g_sdo_data->devcred = NULL;
	}

	g_sdo_data->state_fn = NULL;

	/* Closing all crypto related functions.*/
	(void)sdoCryptoClose();

	return true;
}

/**
 * Sets device state to shutdown and sdoFrees all resources.
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
