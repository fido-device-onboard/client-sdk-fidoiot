/*
 * Copyright 2022 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * CSE Platform Utilities header file.
 *
 */

#ifndef __FDOCSE_H__
#define __FDOCSE_H__

#include "fdo.h"
#include "fdotypes.h"
#include "util.h"
#include "fdo_cse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <ctype.h>
#include <linux/mei.h>
#include <metee.h>

#define FDO_APP_ID 1
#define OVH_FILE_ID 0
#define DS_FILE_ID 1

TEESTATUS heci_init(TEEHANDLE *cl);
void heci_deinit(TEEHANDLE *cl);
TEESTATUS fdo_heci_get_version(TEEHANDLE *cl, uint16_t *major_v, uint16_t
                *minor_v, FDO_STATUS *fdo_status);
TEESTATUS fdo_heci_get_cert_chain(TEEHANDLE *cl, uint8_t *cert_chain, uint16_t
                *len_cert, FDO_STATUS *fdo_status);
TEESTATUS fdo_heci_ecdsa_device_sign_challenge(TEEHANDLE *cl, uint8_t *data,
                uint32_t data_length, uint8_t *sig_ptr, size_t sig_len, uint8_t
                *mp_ptr, uint32_t *mp_len, FDO_STATUS *fdo_status);
TEESTATUS fdo_heci_generate_random(TEEHANDLE *cl, uint8_t *random_bytes,
                uint32_t length, FDO_STATUS *fdo_status);
TEESTATUS fdo_heci_load_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
                *fdo_status);
TEESTATUS fdo_heci_update_file(TEEHANDLE *cl, uint32_t file_id, uint8_t *data,
                uint32_t data_length, uint8_t *hmac_ptr, size_t hmac_length, FDO_STATUS
                *fdo_status);
TEESTATUS fdo_heci_commit_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
                *fdo_status);
TEESTATUS fdo_heci_read_file(TEEHANDLE *cl, uint32_t file_id, uint8_t
                *data_ptr, uint32_t *data_length, uint8_t *hmac_ptr, size_t hmac_sz,
                FDO_STATUS *fdo_status);
TEESTATUS fdo_heci_clear_file(TEEHANDLE *cl, uint32_t file_id, FDO_STATUS
                *fdo_status);
TEESTATUS fdo_heci_close_interface(TEEHANDLE *cl, FDO_STATUS *fdo_status);

#endif /* __FDOCSE_H__ */