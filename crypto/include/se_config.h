/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/* If there is a need to have a external key written to a slot when the
 * Data zone and configuration zones are locked we need a write key. This
 * write keys' main purpose is to create an encrypted write to the data slot.
 * Refer to the reference doc for more detailed description.
 *
 */
#define WRITE_KEY_ID (0x04)
#define WRITE_KEY                                                              \
	{                                                                      \
		0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5, 0xd8, 0x22,    \
		    0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84, 0x5d, 0x1b, 0x56,      \
		    0x9f, 0xe7, 0x05, 0xb6, 0x00, 0x06, 0xfe, 0xec, 0x14,      \
		    0x5a, 0x0d, 0xb1, 0xe3                                     \
	}

#define HMAC_KEY_SLOT (ATCA_TEMPKEY_KEYID)

#define ECDSA_SIGN_KEY_ID (0x0)

/* key slot used for AES GCM encrypt and decrypt operations. */
#define AES_KEY_ID (0x1)

/* using Block 0 out of the 4 blocks inside the Slot AES_KEY_ID
 * each block is of 16Bytes long because the AES key size is 128
 */
#define AES_KEY_BLOCK (0x0)

extern uint8_t ecdsa_public_key[64];
