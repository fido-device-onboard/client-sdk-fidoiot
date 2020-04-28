/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __EPID_H__
#define __EPID_H__

#include "sdotypes.h"
#include <stdint.h>
#include <stddef.h>

sdo_bits_t *epid_sign(uint8_t *data, size_t data_len,
		      const uint8_t *b_group_public_key,
		      size_t Group_public_key_len, const uint8_t *b_sigrl,
		      size_t Sig_rl_size);

int epid_init(const uint8_t *signed_group_public_key,
	      size_t signed_group_public_key_len, const uint8_t *private_key,
	      size_t private_key_len, const uint8_t *cacert_buf,
	      size_t cacert_size, const uint8_t *signed_sig_rl,
	      size_t signed_sig_rl_size, const uint8_t *precomp_file,
	      size_t precomp_size);

void epid_close(void);

#endif /* __EPID_H__ */
