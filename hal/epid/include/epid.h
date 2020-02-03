/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#ifndef __EPID_H__
#define __EPID_H__

#include "sdotypes.h"
#include <stdint.h>
#include <stddef.h>

SDOBits_t *EPID_Sign(uint8_t *data, size_t data_len,
		     const uint8_t *bGroupPublicKey, size_t GroupPublicKeyLen,
		     const uint8_t *bSigrl, size_t SigRlSize);

int EPID_Init(const uint8_t *signedGroupPublicKey,
	      size_t signedGroupPublicKeyLen, const uint8_t *privateKey,
	      size_t privateKeyLen, const uint8_t *cacert_buf,
	      size_t cacert_size, const uint8_t *signed_sig_rl,
	      size_t signed_sig_rl_size, const uint8_t *precomp_file,
	      size_t precomp_size);

void EPID_Close(void);

#endif /* __EPID_H__ */
