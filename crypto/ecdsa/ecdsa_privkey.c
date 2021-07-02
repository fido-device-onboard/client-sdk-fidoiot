/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*!
 * \file
 * \brief This file implements generic utility functions for mbedTLS hal
 */

#include "fdotypes.h"
#include "storage_al.h"
#include "util.h"
#include "safe_lib.h"
#include "ecdsa_privkey.h"

/**
 * Convert the stored ecdsa privkey to buffer
 * @param keybuf: valid pointer to receive the pointer to key buffer
 * @param length: length of the key buffer
 * @return 0 on success, else error
 */
int load_ecdsa_privkey(unsigned char **keybuf, size_t *length)
{
	int ret = -1;
	bool is_pem = false;
	size_t privkeysize = 0;
	unsigned char *privkey = NULL;

	if (!keybuf || !length) {
		LOG(LOG_ERROR,
		    "Invalid parameters sent for receiving priv key\n");
		goto err;
	}

	/* Get the ECDSA private key size from storage */
	privkeysize = fdo_blob_size((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA);
	if (privkeysize == 0) {
		LOG(LOG_ERROR, "No ECDSA private key exists\n");
		goto err;
	}

	/* PEM keys are parsed with terminating NULL character */
#ifdef ECDSA_PEM
	is_pem = true;
#endif

	/* Read private key in buffer */
	privkey = fdo_alloc(privkeysize + (is_pem ? 1 : 0));
	if (!privkey) {
		LOG(LOG_ERROR, "Malloc Failed for ECDSA private key\n");
		goto err;
	}

	ret = fdo_blob_read((char *)ECDSA_PRIVKEY, FDO_SDK_RAW_DATA,
			    (uint8_t *)privkey, privkeysize);
	if (ret == -1) {
		LOG(LOG_ERROR, "Reading private key for ECDSA Failed\n");
		goto err;
	}

#ifdef ECDSA_PEM
	/*Insert NULL termination for PEM */
	privkey[privkeysize] = '\0';
#endif

	*keybuf = privkey;
	*length = privkeysize + (is_pem ? 1 : 0);

	return 0;

err:
	if (privkey) {
		if (memset_s(privkey, privkeysize, 0) != 0)
			LOG(LOG_ERROR, "Memset Failed\n");
		fdo_free(privkey);
	}
	return ret;
}
