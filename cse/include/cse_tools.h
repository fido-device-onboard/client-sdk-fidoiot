/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __FDO_CSE_H__
#define __FDO_CSE_H__

#include "safe_lib.h"
#include "fdoCrypto.h"
#include "fdoCryptoHal.h"
#include "cse_utils.h"

int32_t cse_get_cert_chain(fdo_byte_array_t **cse_cert);
int32_t cse_get_cose_sig_structure(fdo_byte_array_t **cose_sig_structure,
                uint8_t *data, size_t data_len);
int32_t cse_get_test_sig(fdo_byte_array_t **cse_signature, fdo_byte_array_t
                **cse_maroeprefix, fdo_byte_array_t *cose_sig_structure,
                uint8_t *data, size_t data_len);
int32_t cse_load_file(uint32_t file_id, uint8_t *data_ptr, uint32_t
                *data_length, uint8_t *hmac_ptr, size_t hmac_sz);


#endif /* __FDO_CSE_H__ */