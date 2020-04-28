/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include "sdotypes.h"
#include <stdint.h>
#include <stddef.h>

int aes_encrypt_packet(sdo_encrypted_packet_t *cipher_txt, uint8_t *clear_txt,
		       size_t clear_txt_size);

int aes_decrypt_packet(sdo_encrypted_packet_t *cipher_txt,
		       sdo_string_t *clear_txt);

#endif /* __CRYPTO_UTILS_H__ */
