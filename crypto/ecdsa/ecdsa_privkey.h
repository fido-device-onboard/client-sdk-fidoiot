/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * NOTE: Internal Header file. This is not exposing any standard abstraction
 * APIs
 */

#ifndef __ECDSA_PRIVKEY_H__
#define __ECDSA_PRIVKEY_H__

/**
 * Internal API
 * load_ecdsa_privkey() - convert the stored ecdsa privkey to buffer
 * @keybuf: valid pointer to receive the pointer to key buffer
 * @length: length of the key buffer
 */
int load_ecdsa_privkey(unsigned char **keybuf, size_t *length);

#endif
