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

bool read_normal_device_credentials(const char *dev_cred_file,
				    fdo_sdk_blob_flags flags,
				    fdo_dev_cred_t *our_dev_cred);
bool read_secure_device_credentials(const char *dev_cred_file,
				    fdo_sdk_blob_flags flags,
				    fdo_dev_cred_t *our_dev_cred);
bool write_normal_device_credentials(const char *dev_cred_file,
				     fdo_sdk_blob_flags flags,
				     fdo_dev_cred_t *our_dev_cred);
bool write_secure_device_credentials(const char *dev_cred_file,
				     fdo_sdk_blob_flags flags,
				     fdo_dev_cred_t *our_dev_cred);
bool read_cse_device_credentials(fdo_dev_cred_t *our_dev_cred);
int load_credential(fdo_dev_cred_t *ocred);
int load_device_secret(void);
int store_credential(fdo_dev_cred_t *ocred);

bool load_device_status(fdo_sdk_device_status *state);
bool store_device_status(fdo_sdk_device_status *state);

#endif /* __LOAD_CREDENTIALS_H__ */
