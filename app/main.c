/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief Main application. This file has implementation for entry point into
 * the platform and necessary things to initialize fdo, run it and exit
 * gracefully.
 */

#include "fdo.h"
#include "fdomodules.h"
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

#define STORAGE_NAMESPACE "storage"
#define OWNERSHIP_TRANSFER_FILE "data/owner_transfer"
#define ERROR_RETRY_COUNT 5

static bool is_ownership_transfer(bool do_resale)
{
	FILE *fp = NULL;
	char state = 0;
	fdo_sdk_status ret;

	if (do_resale) {
		state = '1';
	} else {
		return false;
	}

#ifdef RASALE_BASED_ON_FILE
	fp = fopen(OWNERSHIP_TRANSFER_FILE, "r");
	if (!fp) {
		return false;
	}

	if (fread(&state, 1, 1, fp) != 1) {
		if (fclose(fp) == EOF) {
			LOG(LOG_INFO, "Fclose Failed");
		}
		return false;
	}

	if (fclose(fp) == EOF) {
		LOG(LOG_INFO, "Fclose Failed");
	}
#endif
	if (state == '1') {
		ret = fdo_sdk_resale();
		if (ret == FDO_ERROR) {
			LOG(LOG_INFO,
			    "Failed to set Ownership transfer app exits\n");
			exit(-1);
		}
		if (ret == FDO_SUCCESS) {
			fp = fopen(OWNERSHIP_TRANSFER_FILE, "w");
			if (!fp) {
				return false;
			}
			state = '0';
			if (fwrite(&state, 1, 1, fp) != 1) {
				LOG(LOG_INFO, "Fwrite Failed");
				if (fclose(fp) == EOF) {
					LOG(LOG_INFO, "Fclose Failed");
				}
				return false;
			}
			ret = 0;
			if (fclose(fp) == EOF) {
				LOG(LOG_INFO, "Fclose Failed");
			}
			return true;
		} else if (ret == FDO_RESALE_NOT_READY) {
			/*Device is not yet ready for ownership transfer
			 * First do the initial configuration
			 */
			return false;
		} else if (ret == FDO_RESALE_NOT_SUPPORTED) {
			LOG(LOG_INFO, "Device doesn't support Resale\n");
			return false;
		}
	}
	return false;
}

/**
 * API to initialize service-info modules with their correspoding data. This
 * in-turn calls another API, which finally register them to FDO.
 *
 * @return
 *        pointer to array of Sv_info modules.
 */
static fdo_sdk_service_info_module *fdo_sv_info_modules_init(void)
{
	fdo_sdk_service_info_module *module_info = NULL;

	module_info = fdo_alloc(FDO_MAX_MODULES * (sizeof(fdo_sdk_service_info_module)));

	if (!module_info) {
		LOG(LOG_ERROR, "Malloc failed!\n");
		return NULL;
	}

	/* module#1: fdo_sys */
	if (strncpy_s(module_info[0].module_name, FDO_MODULE_NAME_LEN,
		      "fdo_sys", FDO_MODULE_NAME_LEN) != 0) {
		LOG(LOG_ERROR, "Strcpy failed");
		fdo_free(module_info);
		return NULL;
	}
	module_info[0].service_info_callback = fdo_sys;

	return module_info;
}

static int error_cb(fdo_sdk_status type, fdo_sdk_error errorcode)
{
	static unsigned int rv_timeout;
	static unsigned int conn_timeout;
	static unsigned int di_err;
	static unsigned int to1_err;
	static unsigned int to2_err;

	(void)type;

	switch (errorcode) {
	case FDO_RV_TIMEOUT:
		rv_timeout++;
		if (rv_timeout > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT RV connection from app\n");
			return FDO_ABORT;
		}
		break;

	case FDO_CONN_TIMEOUT:
		conn_timeout++;
		if (conn_timeout > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT connection from app\n");
			return FDO_ABORT;
		}
		break;

	case FDO_DI_ERROR:
		di_err++;
		if (di_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT DI from app\n");
			return FDO_ABORT;
		}
		break;

	case FDO_TO1_ERROR:
		to1_err++;
		if (to1_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT T01 from app\n");
			return FDO_ABORT;
		}
		break;

	case FDO_TO2_ERROR:
		to2_err++;
		if (to2_err > ERROR_RETRY_COUNT) {
			LOG(LOG_INFO, "Sending ABORT T02 from app\n");
			return FDO_ABORT;
		}
		break;

	default:
		break;
	}

	LOG(LOG_INFO,
	    "rv_timeout: %u, conn_timeout: %u, di_err: %u, to1_err: "
	    "%u, to2_err: %u\n",
	    rv_timeout, conn_timeout, di_err, to1_err, to2_err);

	return FDO_SUCCESS;
}

static void print_device_status(void)
{
	fdo_sdk_device_state status = FDO_STATE_ERROR;

	status = fdo_sdk_get_status();
	if (status == FDO_STATE_PRE_DI) {
		LOG(LOG_DEBUG, "Device is ready for DI\n");
	}
	if (status == FDO_STATE_PRE_TO1) {
		LOG(LOG_DEBUG, "Device is ready for Ownership transfer\n");
	}
	if (status == FDO_STATE_IDLE) {
		LOG(LOG_DEBUG, "Device Ownership transfer Done\n");
	}
	if (status == FDO_STATE_RESALE) {
		LOG(LOG_DEBUG, "Device is ready for Ownership transfer\n");
	}
	if (status == FDO_STATE_ERROR) {
		LOG(LOG_DEBUG, "Error in getting device status\n");
	}
}

/**
 * This is the main entry point of the Platform.
 * @return
 *        0 if success, -ve if error.
 */
#ifdef TARGET_OS_LINUX
int main(int argc, char **argv)
#else
int app_main(bool is_resale)
#endif
{
	fdo_sdk_service_info_module *module_info = NULL;
	int ret = -1;

	bool do_resale = false;
	LOG(LOG_DEBUG, "Starting FIDO Device Onboard\n");

#ifdef SECURE_ELEMENT
	if (-1 == se_provisioning()) {
		LOG(LOG_ERROR, "Provisioning Secure element failed!\n");
		return -1;
	}
#endif /* SECURE_ELEMENT */

	if (-1 == configure_normal_blob()) {
		LOG(LOG_ERROR,
		    "Provisioning Normal blob for the 1st time failed!\n");
		ret = -1;
		goto end;
	}

	/* List and Init all Sv_info modules */
	module_info = fdo_sv_info_modules_init();

	if (!module_info) {
		LOG(LOG_DEBUG, "Sv_info Modules not loaded!\n");
	}

	/* Init fdo sdk */
	if (FDO_SUCCESS !=
	    fdo_sdk_init(error_cb, FDO_MAX_MODULES, module_info)) {
		LOG(LOG_ERROR, "fdo_sdk_init failed!!\n");
		fdo_free(module_info);
		ret = -1;
		goto end;
	}

#ifdef TARGET_OS_LINUX
	/* Change stdout to unbuffered mode, without this we don't get logs
	 * if app crashes
	 */
	setbuf(stdout, NULL);
#endif

#if defined TARGET_OS_MBEDOS
/* TODO: ad nvs and network */
#endif

#if defined TARGET_OS_LINUX
	if  (argc > 1 && *argv[1] == '1') {
		do_resale = true;
	}
#else
	if  (is_resale == true) {
		do_resale = true;
	}
#endif
#if defined SELF_SIGNED_CERTS_SUPPORTED
	int strcmp_ss = 1;
	int res = -1;

	res = (int)strcmp_s((char *)argv[1], DATA_CONTENT_SIZE, "-ss",
						&strcmp_ss);

	if  (argc > 1 && (!res && !strcmp_ss)) {
		useSelfSignedCerts = true;
	}
#endif
	if (is_ownership_transfer(do_resale)) {
		ret = 0;
		goto end;
	}

	print_device_status();

	if (FDO_SUCCESS != fdo_sdk_run()) {
		LOG(LOG_ERROR, "FIDO Device Onboard failed\n");
		ret = -1;
		goto end;
	}

	ret = 0;
end:
	/* free the module related info
	 * FDO has created the required DB
	 */
	if (module_info) {
		fdo_free(module_info);
	}

	fdo_sdk_deinit();
	// Return 0 on success
	return ret;
}
