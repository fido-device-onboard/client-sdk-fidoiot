/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __CRYPTO_UTILS_H__
#define __CRYPTO_UTILS_H__

#include "fdotypes.h"
#include <stdint.h>
#include <stddef.h>

int aes_encrypt_packet(fdo_encrypted_packet_t *cipher_txt, uint8_t *clear_txt,
		       size_t clear_txt_size, const uint8_t *aad,
		       size_t aad_length);

int aes_decrypt_packet(fdo_encrypted_packet_t *cipher_txt,
		       fdo_byte_array_t *clear_txt, const uint8_t *aad,
		       size_t aad_length);

#endif /* __CRYPTO_UTILS_H__ */
