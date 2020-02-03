/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Main application. This file has implementation for entry point into
 * the platform and necessary things to initialize sdo, run it and exit
 * gracefully.
 */

#include "sdo.h"
#include "sdomodules.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "blob.h"
#include "safe_lib.h"
#ifdef SECURE_ELEMENT
#include "se_provisioning.h"
#endif

#ifdef TARGET_OS_FREERTOS
#include "wifi_init.h"
#include "nvs_flash.h"
#endif

#define STORAGE_NAMESPACE "storage"
#define OWNERSHIP_TRANSFER_FILE "owner_transfer"
#define ERROR_RETRY_COUNT 5

static bool is_ownership_transfer(void)
{
	FILE *fp = NULL;
	char state = 0;
	sdoSdkStatus ret;

#ifdef TARGET_OS_LINUX
	fp = fopen(OWNERSHIP_TRANSFER_FILE, "r");
	if (!fp)
		return false;

	if (fread(&state, 1, 1, fp) != 1) {
		if (fclose(fp) == EOF)
			LOG(LOG_INFO, "Fclose Failed");
		return false;
	}

	if (fclose(fp) == EOF)
		LOG(LOG_INFO, "Fclose Failed");
#endif

	if (state == '1') {
		ret = sdoSdkResale();
		if (ret == SDO_ERROR) {
			LOG(LOG_INFO,
			    "Failed to set Ownership transfer app exits\n");
			exit(-1);
		}
		if (ret == SDO_SUCCESS) {
			fp = fopen(OWNERSHIP_TRANSFER_FILE, "w");
			if (!fp)
				return false;
			state = '0';
			if (fwrite(&state, 1, 1, fp) != 1) {
				LOG(LOG_INFO, "Fwrite Failed");
				if (fclose(fp) == EOF)
					LOG(LOG_INFO, "Fclose Failed");
				return false;
			}
			ret = 0;
			if (fclose(fp) == EOF)
				LOG(LOG_INFO, "Fclose Failed");
			return true;
		} else if (ret == SDO_RESALE_NOT_READY) {
			/*Device is not yet ready for ownership transfer
			 * First do the initial configuration*/
			return false;
		} else if (ret == SDO_RESALE_NOT_SUPPORTED) {
			LOG(LOG_INFO, "Device doesn't support Resale\n");
			return false;
		}
	}
	return false;
}

/**
 * API to initialize service-info modules with their correspoding data. This
 * in-turn calls another API, which finally register them to SDO.
 *
 * @return
 *        pointer to array of SvInfo modules.
 */
static sdoSdkServiceInfoModule *sdoSvInfoModulesInit(void)
{
	sdoSdkServiceInfoModule *moduleInfo = NULL;

#ifdef MODULES_ENABLED
	moduleInfo = malloc(SDO_MAX_MODULES * (sizeof(*moduleInfo)));

	if (!moduleInfo) {
		LOG(LOG_ERROR, "Malloc failed!\n");
		return NULL;
	}

	/* module#1: sdo_sys */
	if (strncpy_s(moduleInfo[0].moduleName, SDO_MODULE_NAME_LEN, "sdo_sys",
		      SDO_MODULE_NAME_LEN) != 0) {
		LOG(LOG_ERROR, "Strcpy failed");
		free(moduleInfo);
		return NULL;
	}
	moduleInfo[0].serviceInfoCallback = sdo_sys;
#endif

	return moduleInfo;
}

static int error_cb(sdoSdkStatus type, sdoSdkError errorcode)
{
	static unsigned int rv_timeout = 0;
	static unsigned int conn_timeout = 0;
	static unsigned int di_err = 0;
	static unsigned int to1_err = 0;
	static unsigned int to2_err = 0;

	switch (errorcode) {
	case SDO_RV_TIMEOUT:
		rv_timeout++;
		if (rv_timeout > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT RV connection from app\n");
			return SDO_ABORT;
		}
		break;

	case SDO_CONN_TIMEOUT:
		conn_timeout++;
		if (conn_timeout > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT connection from app\n");
			return SDO_ABORT;
		}
		break;

	case SDO_DI_ERROR:
		di_err++;
		if (di_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT DI from app\n");
			return SDO_ABORT;
		}
		break;

	case SDO_TO1_ERROR:
		to1_err++;
		if (to1_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT T01 from app\n");
			return SDO_ABORT;
		}
		break;

	case SDO_TO2_ERROR:
		to2_err++;
		if (to2_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT T02 from app\n");
			return SDO_ABORT;
		}
		break;

	default:
		break;
	}

	LOG(LOG_INFO,
	    "rv_timeout: %u, conn_timeout: %u, di_err: %u, to1_err: "
	    "%u, to2_err: %u\n",
	    rv_timeout, conn_timeout, di_err, to1_err, to2_err);

	return SDO_SUCCESS;
}

static void print_device_status(void)
{
	sdoSdkDeviceState status = SDO_STATE_ERROR;

	status = sdoSdkGetStatus();
	if (status == SDO_STATE_PRE_DI)
		LOG(LOG_DEBUG, "Device is ready for DI \n");
	if (status == SDO_STATE_PRE_TO1)
		LOG(LOG_DEBUG, "Device is ready for Ownership transfer \n");
	if (status == SDO_STATE_IDLE)
		LOG(LOG_DEBUG, "Device Ownership transfer Done\n");
	if (status == SDO_STATE_RESALE)
		LOG(LOG_DEBUG, "Device is ready for Ownership transfer\n");
	if (status == SDO_STATE_ERROR)
		LOG(LOG_DEBUG, "Error in getting device status \n");
}

/**
 * This is the main entry point of the Platform.
 * @return
 *        0 if success, -ve if error.
 */
#ifdef TARGET_OS_LINUX
int main(void)
#elif defined TARGET_OS_FREERTOS
int app_main()
#else
int app_main()
#endif
{
	sdoSdkServiceInfoModule *moduleInfo;

	LOG(LOG_DEBUG, "Starting Secure Device Onboard\n");

#ifdef SECURE_ELEMENT
	if (-1 == se_provisioning()) {
		LOG(LOG_ERROR, "Provisioning Secure element failed!\n");
		return -1;
	}
#endif /* SECURE_ELEMENT */

	if (-1 == configureNormalBlob()) {
		LOG(LOG_ERROR,
		    "Provisioning Normal blob for the 1st time failed!\n");
		return -1;
	}

	/* List and Init all SvInfo modules */
	moduleInfo = sdoSvInfoModulesInit();

	if (!moduleInfo) {
		LOG(LOG_DEBUG, "SvInfo Modules not loaded!\n");
	}

	/* Init sdo sdk */
	if (SDO_SUCCESS != sdoSdkInit(error_cb, SDO_MAX_MODULES, moduleInfo)) {
		LOG(LOG_ERROR, "sdoSdkInit failed!!\n");
		return -1;
	}

	/* free the module related info
	 * SDO has created the required DB
	 * */
	free(moduleInfo);

#ifdef TARGET_OS_LINUX
	/* Change stdout to unbuffered mode, without this we don't get logs
	 * if app crashes */
	setbuf(stdout, NULL);
#endif

#if defined TARGET_OS_FREERTOS
	static nvs_handle storage = -1;
	int err = nvs_flash_init();
	if (err != ESP_OK) {
		LOG(LOG_ERROR, "esp32 NVS init Failed.\n");
		return -1;
	}

	err = nvs_open(STORAGE_NAMESPACE, NVS_READWRITE, &storage);
	if (err != ESP_OK) {
		LOG(LOG_ERROR, "esp32 NVS open Failed.\n");
		return -1;
	}

	sdoWifiInit();
#endif
#if defined TARGET_OS_MBEDOS
/* TODO: ad nvs and network */
#endif

	if (is_ownership_transfer())
		return 0;

	print_device_status();

	if (SDO_SUCCESS != sdoSdkRun()) {
		LOG(LOG_ERROR, "Secure device onboarding failed\n");
		return -1;
	}

#ifdef TARGET_OS_FREERTOS
	sdoWifiExit();
#endif
	// Return 0 on success
	return 0;
}
