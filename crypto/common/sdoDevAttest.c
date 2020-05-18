/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "safe_lib.h"
#include "load_credentials.h"
#include "storage_al.h"
#include <unistd.h>
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
#include "sdoCryptoHal.h"
#include "sdoCrypto.h"

/* Do nothing for ECDSA based attestation */
int32_t dev_attestation_init(void)
{
	return 0;
}

void dev_attestation_close(void)
{
	return;
}
