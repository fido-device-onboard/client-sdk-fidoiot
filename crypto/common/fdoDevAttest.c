/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "util.h"
#include "safe_lib.h"
#include "load_credentials.h"
#include "storage_al.h"
#ifndef WIN32
#include <unistd.h>
#endif // !WIN32
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
#include "fdoCryptoHal.h"
#include "fdoCrypto.h"

/* Do nothing for ECDSA based attestation */
int32_t dev_attestation_init(void)
{
	return 0;
}

void dev_attestation_close(void)
{
	return;
}
