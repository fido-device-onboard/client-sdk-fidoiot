/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include <stdbool.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include "sdoCrypto.h"
#include "sdoCryptoHal.h"
#include "safe_lib.h"
#include "util.h"
#include "mbedtls_random.h"
#include "mbedtls/entropy_poll.h"

#define SDO_PRO_SPEC_VERSION "112"
#define SDO_PERS "SDO_version_" SDO_PRO_SPEC_VERSION

static mbedtls_ctr_drbg_context g_prng_ctx;
static mbedtls_entropy_context g_entropy;
static bool g_random_initialised;

/*
 * Routines like ECDSA sign required random generator context,
 * so, this API returns that context
 */
void *get_mbedtls_random_ctx(void)
{
	return ((void *)&g_prng_ctx);
}

bool is_mbedtls_random_init(void)
{
	return g_random_initialised ? 1 : 0;
}

#if defined(TARGET_OS_LINUX) || defined(TARGET_OS_OPTEE)
static int entropy_source(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	FILE *fp = NULL;
	size_t result = 0;

	(void)data; /* Warning fix */

	if (!output || !olen)
		return -1;

	*olen = 0;

#if defined(TARGET_OS_LINUX)
	fp = fopen("/dev/random", "r");
	if (fp) {
		result = fread((char *)output, 1, len, fp);
		fclose(fp);
	}
	if (result <= 0 || len != result) {
		LOG(LOG_ERROR, "random dev read failed!\n");
		return -1;
	}
	*olen = result;
#elif defined(TARGET_OS_OPTEE)
	(void)fp;
	(void)result;

	if (sdo_crypto_random_bytes(output, len))
		return -1;
	*olen = len;
#endif

	return 0;
}
#endif

#ifndef SECURE_ELEMENT
/**
 * Initialize the random function by using RAND_poll function and
 * maintain the state of randomness by variable g_random_initialised.
 * @return 0 if succeeds,else -1.
 */

int random_init(void)
{
	const char pers[] = {SDO_PERS};
	entropy_src_funp funcptr = NULL;

	if (!g_random_initialised) {
		mbedtls_ctr_drbg_init(&g_prng_ctx);
		mbedtls_entropy_init(&g_entropy);

#if defined(TARGET_OS_MBEDOS)
		funcptr = mbedtls_hardware_poll;
#elif defined(TARGET_OS_LINUX) || defined(TARGET_OS_OPTEE)
#pragma message(                                                               \
    "WARNING: Using /dev/random for entropy source which is a slow source. Production builds must use a good entropy source from the platform")
		LOG(LOG_INFO,
		    "WARNING: Using /dev/random for entropy source"
		    "which is a slow source. Production builds must use a good"
		    "entropy source from the platform\n");

		funcptr = entropy_source; /* default */

#else // Non-linux & Non-mbedos
#error(                                                               \
    "CRITICAL WARNING: Using non-secure entropy source. In  production builds, the code in entropy_source() must be replaced to a good entropy source from the platform")
		LOG(LOG_ERROR,
		    "CRITICAL WARNING: Using non-secure entropy source. In \
		      production builds, the code in entropy_source() must be \
		      replaced to a good entropy source from the platform\n");

#endif

		if (0 !=
		    mbedtls_entropy_add_source(&g_entropy, funcptr, NULL,
					       MBEDTLS_ENTROPY_MAX_GATHER,
					       MBEDTLS_ENTROPY_SOURCE_STRONG)) {
			return -1;
		}

		if (0 != mbedtls_ctr_drbg_seed(
			     &g_prng_ctx, mbedtls_entropy_func, &g_entropy,
			     (const unsigned char *)pers, sizeof(pers) - 1)) {
			return -1;
		}

		g_random_initialised = true;
	}

	return 0;
}

/**
 * Free random engine resources and change state to false using
 * g_random_initialised variable.
 * @return 0 if succeeds,else -1.
 */

int random_close(void)
{
	if (!g_random_initialised) {
		return -1;
	}
	mbedtls_ctr_drbg_free(&g_prng_ctx);
	mbedtls_entropy_free(&g_entropy);
	g_random_initialised = false;
	return 0;
}
#endif /* SECURE_ELEMENT */
