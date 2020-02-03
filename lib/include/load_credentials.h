/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __LOAD_CREDENTIALS_H__
#define __LOAD_CREDENTIALS_H__

#include "sdo.h"
#include "sdocred.h"
#include "sdoprot.h"
#include "storage_al.h"
#include <stdbool.h>

#define DATA_FILES "./data/"
#define MAX_FILENAME_LEN 1024

bool ReadNormalDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
				 SDODevCred_t *ourDevCred);
bool ReadMfgDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
			      SDODevCred_t *ourDevCred);
bool ReadSecureDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
				 SDODevCred_t *ourDevCred);
bool WriteNormalDeviceCredentials(const char *devCredFile,
				  sdoSdkBlobFlags flags,
				  SDODevCred_t *ourDevCred);
bool WriteMfgDeviceCredentials(const char *devCredFile, sdoSdkBlobFlags flags,
			       SDODevCred_t *ourDevCred);
bool WriteSecureDeviceCredentials(const char *devCredFile,
				  sdoSdkBlobFlags flags,
				  SDODevCred_t *ourDevCred);
int load_credential(void);
int load_mfg_secret(void);
int store_credential(SDODevCred_t *ocred);
void load_default_data(void);
SDODevCred_t *app_get_credentials(void);
SDODevCred_t *app_alloc_credentials(void);

#endif /* __LOAD_CREDENTIALS_H__ */
