/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __LOAD_CREDENTIALS_H__
#define __LOAD_CREDENTIALS_H__

#include "fdo.h"
#include "fdocred.h"
#include "fdoprot.h"
#include "storage_al.h"
#include <stdbool.h>

#define DATA_FILES "./data/"
#define MAX_FILENAME_LEN 1024

bool read_normal_device_credentials(const char *dev_cred_file,
				    fdo_sdk_blob_flags flags,
				    fdo_dev_cred_t *our_dev_cred);
bool read_mfg_device_credentials(const char *dev_cred_file,
				 fdo_sdk_blob_flags flags,
				 fdo_dev_cred_t *our_dev_cred);
bool read_secure_device_credentials(const char *dev_cred_file,
				    fdo_sdk_blob_flags flags,
				    fdo_dev_cred_t *our_dev_cred);
bool write_normal_device_credentials(const char *dev_cred_file,
				     fdo_sdk_blob_flags flags,
				     fdo_dev_cred_t *our_dev_cred);
bool write_mfg_device_credentials(const char *dev_cred_file,
				  fdo_sdk_blob_flags flags,
				  fdo_dev_cred_t *our_dev_cred);
bool write_secure_device_credentials(const char *dev_cred_file,
				     fdo_sdk_blob_flags flags,
				     fdo_dev_cred_t *our_dev_cred);
int load_credential(void);
int load_mfg_secret(void);
int store_credential(fdo_dev_cred_t *ocred);
void load_default_data(void);
fdo_dev_cred_t *app_get_credentials(void);
fdo_dev_cred_t *app_alloc_credentials(void);

#endif /* __LOAD_CREDENTIALS_H__ */
