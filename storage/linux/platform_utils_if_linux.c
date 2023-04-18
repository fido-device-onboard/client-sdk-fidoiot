/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

/*
 * Platform Utilities
 *
 * The file implements required platform utilities for FDO.
 */
#include <stdlib.h>
#include "util.h"
#include "safe_lib.h"
#include "fdoCryptoHal.h"
#include "platform_utils.h"
/**
 * Generate platform IV (if not already generated) else provide already
 * generated IV.
 *
 * @param iv - buffer of size len to output IV.
 * @param len - length(in bytes) of the IV to be generated.
 * @param datalen - length(in bytes) of data to be encrypted.
 * @retval true if IV is copied successfully, false otherwise.
 */
bool get_platform_iv(uint8_t *iv, size_t len, size_t datalen)
{
	bool retval = false;
	FILE *fp = NULL;
	size_t fsize = 0;
	uint8_t buf[PLATFORM_IV_DEFAULT_LEN * 2] = {0};
	uint8_t *p_iv = NULL;

	/*
	 * Platform iv file storage format
	 * [First_iv||latest_iv]
	 */
	if (!iv || len < PLATFORM_IV_DEFAULT_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (!file_exists((const char *)PLATFORM_IV)) {
		LOG(LOG_ERROR, "Plaform-IV file does not exists!\n");
		goto end;
	}

	fsize = get_file_size((const char *)PLATFORM_IV);

	if (fsize != PLATFORM_IV_DEFAULT_LEN * 2) {
		/* generate new IV and store into file */
		p_iv = fdo_alloc(PLATFORM_IV_DEFAULT_LEN);
		if (p_iv == NULL) {
			LOG(LOG_ERROR, "Allocation failed for plaform IV!\n");
			goto end;
		}

		LOG(LOG_DEBUG, "Generating platform IV of length: %zu\n",
		    (size_t)PLATFORM_IV_DEFAULT_LEN);

		if (crypto_hal_random_bytes(p_iv, PLATFORM_IV_DEFAULT_LEN)) {
			LOG(LOG_ERROR,
			    "Generating random platform IV failed!\n");
			goto end;
		}

		/* store the first iv */
		if (memcpy_s(buf, len, p_iv, PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR, "Copying platform IV failed!\n");
			goto end;
		}
		if (memcpy_s(buf + PLATFORM_IV_DEFAULT_LEN, len, p_iv,
			     PLATFORM_IV_DEFAULT_LEN) != 0) {
			LOG(LOG_ERROR, "Copying platform IV failed!\n");
			goto end;
		}

	} else {
		/* return the previously generated IV */
		if (0 != read_buffer_from_file((const char *)PLATFORM_IV, buf,
					       sizeof(buf))) {
			LOG(LOG_ERROR, "Failed to read platform IV file!\n");
			goto end;
		}
		// check_the_rollover_and_increment
		if (inc_rollover_ctr(buf, buf + PLATFORM_IV_DEFAULT_LEN,
				     PLATFORM_IV_DEFAULT_LEN,
				     datalen / PLATFORM_AES_BLOCK_LEN) == -1) {
			LOG(LOG_ERROR, "Roll over condition reached!\n");
			goto end;
		}
	}

	fp = fopen((const char *)PLATFORM_IV, "w");
	if (!fp) {
		LOG(LOG_ERROR, "Could not open platform IV file!\n");
		goto end;
	}

	if ((PLATFORM_IV_DEFAULT_LEN * 2) !=
	    fwrite(buf, sizeof(char), sizeof(buf), fp)) {
		LOG(LOG_ERROR, "Plaform IV file is not written properly!\n");
		goto end;
	}

	if (memcpy_s(iv, len, buf + PLATFORM_IV_DEFAULT_LEN,
		     PLATFORM_IV_DEFAULT_LEN) != 0) {
		LOG(LOG_ERROR, "Copying platform IV failed!\n");
		goto end;
	}
	retval = true;

end:
	if (fp) {
		if (fclose(fp) == EOF) {
			LOG(LOG_INFO, "Fclose Failed");
		}
	}
	if (p_iv) {
		fdo_free(p_iv);
	}
	return retval;
}

/**
 * Generate platform AES Key (if not already generated) else provide already
 * generated Key.
 *
 * @param key - buffer of size len to output KEY.
 * @param len - length(in bytes) of the KEY to be generated.
 * @retval true if Key is copied successfully, false otherwise.
 */
bool get_platform_aes_key(uint8_t *key, size_t len)
{
	bool retval = false;
	FILE *fp = NULL;
	size_t fsize = 0;

	if (!key || len < PLATFORM_AES_KEY_DEFAULT_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (!file_exists((const char *)PLATFORM_AES_KEY)) {
		LOG(LOG_ERROR, "Plaform-AES-Key file does not exists!\n");
		goto end;
	}

	fsize = get_file_size((const char *)PLATFORM_AES_KEY);

	if (fsize != PLATFORM_AES_KEY_DEFAULT_LEN) {
		/* generate new AES Key and store into file */

		LOG(LOG_DEBUG, "Generating platform AES Key of length: %zu\n",
		    len);

		if (crypto_hal_random_bytes(key,
					     PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR,
			    "Generating random platform AES Key failed!\n");
			goto end;
		}

		fp = fopen((const char *)PLATFORM_AES_KEY, "w");
		if (!fp) {
			LOG(LOG_ERROR,
			    "Could not open platform AES Key file!\n");
			goto end;
		}

		if (len != fwrite(key, sizeof(char),
				  PLATFORM_AES_KEY_DEFAULT_LEN, fp)) {
			LOG(LOG_ERROR,
			    "Plaform AES Key file is not written properly!\n");
			goto end;
		}
	} else {
		/* return the previously generated AES Key */
		if (0 != read_buffer_from_file((const char *)PLATFORM_AES_KEY,
					       key,
					       PLATFORM_AES_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR,
			    "Failed to read platform AES Key file!\n");
			goto end;
		}
	}
	retval = true;

end:
	if (fp) {
		if (fclose(fp) == EOF) {
			LOG(LOG_INFO, "Fclose Failed");
		}
	}
	return retval;
}
/**
 * Generate HMAC Key (if not already generated) else provide already
 * generated Key.
 *
 * @param key - buffer of size len to output key.
 * @param len - length(in bytes) of the key to be generated.
 * @retval true if key is copied successfully, false otherwise.
 */

bool get_platform_hmac_key(uint8_t *key, size_t len)
{
	bool retval = false;
	FILE *fp = NULL;
	size_t fsize = 0;

	if (!key || len < PLATFORM_HMAC_KEY_DEFAULT_LEN) {
		LOG(LOG_ERROR, "Invalid parameters!\n");
		goto end;
	}

	if (!file_exists((const char *)PLATFORM_HMAC_KEY)) {
		LOG(LOG_ERROR, "Plaform-HMAC-Key file does not exists!\n");
		goto end;
	}

	fsize = get_file_size((const char *)PLATFORM_HMAC_KEY);

	if (fsize == 0 || fsize != len) {
		/* generate new HMAC Key and store into file */
		LOG(LOG_DEBUG, "Generating platform HMAC Key of length: %zu\n",
		    len);

		if (crypto_hal_random_bytes(key,
					     PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR,
			    "Generating random platform HMAC Key failed!\n");
			goto end;
		}

		fp = fopen((const char *)PLATFORM_HMAC_KEY, "w");
		if (!fp) {
			LOG(LOG_ERROR,
			    "Could not open platform HMAC Key file!\n");
			goto end;
		}

		if (len != fwrite(key, sizeof(char),
				  PLATFORM_HMAC_KEY_DEFAULT_LEN, fp)) {
			LOG(LOG_ERROR,
			    "Plaform HMAC Key file is not written properly!\n");
			goto end;
		}
	} else {
		/* return the previously generated HMAC Key */
		if (0 != read_buffer_from_file((const char *)PLATFORM_HMAC_KEY,
					       key,
					       PLATFORM_HMAC_KEY_DEFAULT_LEN)) {
			LOG(LOG_ERROR,
			    "Failed to read platform HMAC Key file!\n");
			goto end;
		}
	}
	retval = true;

end:
	if (fp) {
		if (fclose(fp) == EOF) {
			LOG(LOG_INFO, "Fclose Failed");
		}
	}
	return retval;
}
