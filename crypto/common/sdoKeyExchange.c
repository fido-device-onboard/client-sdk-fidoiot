/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include "sdokeyexchange.h"
#include "sdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#include "sdoCryptoCtx.h"
#include "sdoCrypto.h"
#include <math.h>

/* Static functions */
static int32_t remove_java_compatible_byte_array(sdo_byte_array_t *BArray);

/******************************************************************************/
/**
 * sdo_kex_init() - Initialize key exchange context
 * Initialize the key exchange context which can be done at init time
 * o Key Exchange algorithm (DH, AYSM, ECDH, ECDH384)
 * o Cipher Suite to be used (AESxxx/CTRorCBC/HMAC-SHAyyy)
 * o If it's ECDH, perform the 1st step of ECDH
 */
int32_t sdo_kex_init(void)
{
	char cs[32];
	int32_t ret = -1;
	sdo_kex_ctx_t *kex_ctx = getsdo_key_ctx();
	sdo_to2Sym_enc_ctx_t *to2sym_ctx = get_sdo_to2_ctx();
	size_t ofs = 0;

	/* Allocate kex string */
	kex_ctx->kx = sdo_string_alloc_with_str(KEX);
	if (!kex_ctx->kx) {
		LOG(LOG_ERROR, "Failed to allocate kex info\n");
		goto err;
	}

	LOG(LOG_DEBUG, "kex name (%s) used\n", KEX);
	/*
	 * Set the Cipher Suit(cs) as follows
	 *
	 * if KEX != ecdh384
	 *     AES = 128 bit
	 *     SHA = 256 bit
	 * else
	 *     AES = 256 bit
	 *     SHA = 384 bit
	 */

	/* Construct the cs string: AESxxx/CTRorCBC/HMAC-SHAyyy */
	snprintf_s_i(cs, sizeof(cs), "AES%u/", AES_BITS);
	ofs = strnlen_s(cs, sizeof(cs));
	snprintf_s_si(cs + ofs, sizeof(cs) - ofs, "%s/HMAC-SHA%u",
		      (char *)AES_MODE, HMAC_MODE);

	kex_ctx->cs = sdo_string_alloc_with_str(cs);
	if (!kex_ctx->cs) {
		LOG(LOG_ERROR, "Failed to allocate cs info\n");
		goto err;
	}

	/* Allocate buffer for Session Encryption Key (SEK) */
	to2sym_ctx->keyset.sek = sdo_byte_array_alloc(SEK_KEY_SIZE);
	if (!to2sym_ctx->keyset.sek)
		goto err;

	to2sym_ctx->keyset.svk = sdo_byte_array_alloc(SVK_KEY_SIZE);
	if (!to2sym_ctx->keyset.svk)
		goto err;

	if (crypto_hal_kex_init(&(kex_ctx->context))) {
		goto err;
	}

	/* Fill out the labels */
	kex_ctx->kdf_label = "FIDO-KDF";
	kex_ctx->context_label = "AutomaticOnboardTunnel";

	ret = 0; /* Mark as success */

err:
	if (ret) {
		sdo_kex_close();
	}
	return ret;
}

/**
 * sdo_kex_close() - release kex context
 */
int32_t sdo_kex_close(void)
{
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	sdo_to2Sym_enc_ctx_t *to2sym_ctx = get_sdo_to2_ctx();
	/* Free "KEX" string (Key Exchange) */
	if (kex_ctx->kx) {
		sdo_string_free(kex_ctx->kx);
		kex_ctx->kx = NULL;
	}

	/* Free "Cipher Suite" string */
	if (kex_ctx->cs) {
		sdo_string_free(kex_ctx->cs);
		kex_ctx->cs = NULL;
	}

	/* Free "Key Exchange" information sent from device */
	if (kex_ctx->xB) {
		sdo_byte_array_free(kex_ctx->xB);
		kex_ctx->xB = NULL;
	}

	/* TODO: Final initial secret */
	if (kex_ctx->initial_secret) {
		sdo_byte_array_free(kex_ctx->initial_secret);
		kex_ctx->initial_secret = NULL;
	}

	/* Cleanup sdo_to2Sym_enc_ctx_t */
	if (to2sym_ctx->keyset.sek) {
		sdo_byte_array_free(to2sym_ctx->keyset.sek);
		to2sym_ctx->keyset.sek = NULL;
	}
	if (to2sym_ctx->keyset.svk) {
		sdo_byte_array_free(to2sym_ctx->keyset.svk);
		to2sym_ctx->keyset.svk = NULL;
	}

	if (to2sym_ctx->initialization_vector) {
		sdo_free(to2sym_ctx->initialization_vector);
		to2sym_ctx->initialization_vector = NULL;
		to2sym_ctx->ctr_value = 0U;
	}

	if (kex_ctx->context) {
		crypto_hal_kex_close((void *)&kex_ctx->context);
		kex_ctx->context = NULL;
	}

	return 0;
}

/**
 * Internal API
 */
static int32_t set_encrypt_key(sdo_public_key_t *encrypt_key)
{
#ifdef KEX_ASYM_ENABLED
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();

	return set_encrypt_key_asym(kex_ctx->context, encrypt_key);
#endif
	(void)encrypt_key;
	return 0;
}

/**
 * Step 1 of key exchange algorithm. Allocate internal secrets and generate
 * public shared value B
 * This is then sent to the other side of the connection.
 * @param xB Byte array for Kex ParamB
 * @return B secret to be suared with other side of connection
 *	encrypted or clear based on encryption mode
 */
int32_t sdo_get_kex_paramB(sdo_byte_array_t **xB)
{
	int32_t ret = -1;
	sdo_kex_ctx_t *kex_ctx = getsdo_key_ctx();
	uint32_t bufsize = 0;
	sdo_byte_array_t *tmp_xB = NULL;

	if (!xB) {
		return -1;
	}
	if (*xB != NULL) {
		sdo_byte_array_free(*xB);
		*xB = NULL;
	}

	if (crypto_hal_get_device_random(kex_ctx->context, NULL, &bufsize)) {
		return -1;
	}

	tmp_xB = sdo_byte_array_alloc(bufsize);
	if (!tmp_xB) {
		goto err;
	}

	if (crypto_hal_get_device_random(kex_ctx->context, tmp_xB->bytes,
					 &bufsize)) {
		goto err;
	}
	/* if not clean clean it */
	if (kex_ctx->xB != NULL) {
		sdo_byte_array_free(kex_ctx->xB);
		kex_ctx->xB = NULL;
	}
	kex_ctx->xB = tmp_xB;
	*xB = kex_ctx->xB;
	ret = 0;
err:
	if (ret && tmp_xB) {
		sdo_byte_array_free(tmp_xB);
		*xB = NULL;
	}
	return ret;
}

static int32_t remove_java_compatible_byte_array(sdo_byte_array_t *BArray)
{
	if (BArray && BArray->bytes) {
		if (BArray->bytes[0] == 0x00) {
			if (!memmove_s(BArray->bytes, BArray->byte_sz - 1,
				       &BArray->bytes[1], BArray->byte_sz - 1))
				BArray->byte_sz--;
			else
				return -1;
		}
		return 0;
		// BArray->bytes[0] != 0x00 is also valid array
	}
	return -1;
}

/**
 * Internal API
 */

static int32_t prep_keymat(uint8_t *keymat, size_t keymat_size, const int index,
	const int bytes_length)
{
	int ret = -1;
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	size_t ofs = 0;
	uint8_t idx0_val;

	if (index == 1)
		idx0_val = 0x01;
	else if (index == 2)
		idx0_val = 0x02;
	else {
		// for now, we cannot go beyond 2
		LOG(LOG_ERROR, "Invalid i\n");
		goto err;
	}

	keymat[ofs++] = idx0_val;
	// Fill in the kdflabel
	if (strncpy_s((char *)&keymat[ofs], keymat_size - ofs,
		kex_ctx->kdf_label,
		strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE))) {
		LOG(LOG_ERROR, "Failed to fill kdf label in key Material\n");
		goto err;
	}
	ofs += strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE);
	keymat[ofs++] = 0x00;
	// Fill in the context
	if (strncpy_s((char *)&keymat[ofs], keymat_size - ofs,
		kex_ctx->context_label,
		strnlen_s(kex_ctx->context_label, SDO_MAX_STR_SIZE))) {
		LOG(LOG_ERROR, "Failed to fill svk label\n");
		goto err;
	}
	ofs += strnlen_s(kex_ctx->context_label, SDO_MAX_STR_SIZE);
	keymat[ofs++] = (bytes_length >> 8) & 0xff;
	keymat[ofs++] = bytes_length & 0xff;

	ret = 0;

err:
	return ret;
}

/* Get Shared Secret She_she */
static sdo_byte_array_t *get_secret(void)
{
	sdo_byte_array_t *b = NULL;
	uint8_t *shared_secret_buffer = NULL;
	uint32_t secret_size = 0;
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	sdo_kex_ctx_t *key_ex_data = (sdo_kex_ctx_t *)(getsdo_key_ctx());

	if (crypto_hal_get_secret(key_ex_data->context, NULL, &secret_size) !=
	    0) {
		LOG(LOG_ERROR, " crypto_hal_get_secret failed");
		return NULL;
	}

	shared_secret_buffer = sdo_alloc(secret_size);

	if (!shared_secret_buffer) {
		LOG(LOG_ERROR, " alloc of %d failed", (int)secret_size);
		return NULL;
	}

	if (crypto_hal_get_secret(key_ex_data->context, shared_secret_buffer,
				  &secret_size) != 0) {
		LOG(LOG_ERROR, " crypto_hal_get_secret failed");
		goto err;
	}

	b = sdo_byte_array_alloc_with_byte_array(shared_secret_buffer,
						 secret_size);

	if (memset_s(shared_secret_buffer, secret_size, 0)) {
		LOG(LOG_ERROR, "Failed to clear shared secret buffer\n");
		goto err;
	}

	sdo_free(shared_secret_buffer);

	/* remove extra byte from bigendian java */
	if (remove_java_compatible_byte_array(b)) {
		goto err;
	}

	if (kex_ctx->initial_secret) {
		sdo_bits_free(kex_ctx->initial_secret);
		kex_ctx->initial_secret = b;
	}
	return b;

err:
	sdo_free(shared_secret_buffer);
	sdo_byte_array_free(b);
	return NULL;
}

/**
 * Derive encryption and hashing key using the input shared secret for
 * DH key exchange mode.
 * NOTE: Currently, only works for AES-CTR and AES-CBC
 *
 * @return ret
 *        return true on success. false on failure.
 */
static int32_t kex_kdf(void)
{
	int ret = -1;
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	sdo_byte_array_t *shse = get_secret();
	sdo_aes_keyset_t *keyset = get_keyset();
	uint8_t *keymat = NULL;
	size_t keymat_size = 0;
	// number of key bytes to derive = SEK + SVK size for AES-CTR and AES-CBC modes
	// TO-DO : update when AES-GCM and AES-CCM are added
	size_t key_bytes_sz = SEK_KEY_SIZE + SVK_KEY_SIZE;
	uint8_t key_bytes[key_bytes_sz];
	size_t key_bytes_index = 0;
	size_t num_key_bytes_to_copy = 0;
	uint8_t *hmac = NULL;
	int num_rounds = 0, num_rounds_index = 0;

	if (!shse) {
		LOG(LOG_ERROR, "Failed to get the shared secret\n");
		goto err;
	}

	// total number of rounds to iterate for generating the total number of key bytes
	num_rounds = ceil((double)key_bytes_sz / SDO_SHA_DIGEST_SIZE_USED);

	// KeyMaterial size
	keymat_size = 1 + strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE) + 1 +
		    strnlen_s(kex_ctx->context_label, SDO_MAX_STR_SIZE) + 1 + 1;
	// Allocate memory for KeyMaterial
	keymat = sdo_alloc(keymat_size);
	if (!keymat) {
		LOG(LOG_ERROR, "Out of memory for key material 1\n");
		goto err;
	}

	// Allocate memory to store hmac
	hmac = sdo_alloc(SDO_SHA_DIGEST_SIZE_USED);
	if (!hmac) {
		LOG(LOG_ERROR, "Failed to allocate hmac buffer\n");
		goto err;
	}

	// iterate for the calculated number of rounds to generate key
	// once the iterations are done, key_bytes contains the generated key bytes
	for (num_rounds_index = 1; num_rounds_index <= num_rounds; num_rounds_index++) {

		// clear for new round usage
		if (0 != memset_s(keymat, keymat_size, 0)) {
			LOG(LOG_ERROR, "Failed to clear keymat\n");
			goto err;
		}
		// generate KeyMaterial
		ret = prep_keymat(keymat, keymat_size, num_rounds_index, key_bytes_sz);
		if (ret) {
			LOG(LOG_ERROR, "Failed to prepare keymat\n");
			goto err;
		}

		// clear for new round usage
		if (0 != memset_s(hmac, SDO_SHA_DIGEST_SIZE_USED, 0)) {
			LOG(LOG_ERROR, "Failed to clear hmac buffer\n");
			goto err;
		}
		// generate hmac that gives us the key (or a part of it)
		if (crypto_hal_hmac(SDO_CRYPTO_HMAC_TYPE_USED, keymat, keymat_size,
					hmac, SDO_SHA_DIGEST_SIZE_USED, shse->bytes,
					shse->byte_sz)) {
			LOG(LOG_ERROR, "Failed to derive key via HMAC\n");
			goto err;
		}

		if (key_bytes_index + SDO_SHA_DIGEST_SIZE_USED < key_bytes_sz)
			num_key_bytes_to_copy = SDO_SHA_DIGEST_SIZE_USED;
		else
			num_key_bytes_to_copy = key_bytes_sz - key_bytes_index;

		// copy the generated hmac (key/a part of the key) into generated key buffer
		if (memcpy_s(&key_bytes[key_bytes_index], key_bytes_sz, hmac,
		    num_key_bytes_to_copy)) {
			LOG(LOG_ERROR, "Failed to copy generated key bytes\n");
			goto err;
		}
		key_bytes_index += SDO_SHA_DIGEST_SIZE_USED;
	}

	// Get the sek
	if (memcpy_s(keyset->sek->bytes, keyset->sek->byte_sz, &key_bytes[0],
		      keyset->sek->byte_sz)) {
		LOG(LOG_ERROR, "Failed to copy sek key\n");
		goto err;
	}

	// Get the svk
	if (memcpy_s(keyset->svk->bytes, keyset->svk->byte_sz, &key_bytes[keyset->sek->byte_sz],
		     keyset->svk->byte_sz)) {
		LOG(LOG_ERROR, "Failed to copy svk key\n");
		goto err;
	}

	ret = 0;

err:
	if (hmac) {
		sdo_free(hmac);
	}
	if (keymat) {
		sdo_free(keymat);
	}
	sdo_byte_array_free(shse);

	return ret;
}

/**
 * This API shall set the parameter A that is received from peer and proceed
 * to generate key as per the SDO Protocol Spec. This generated key shall be
 * used for encryption/decryption in TO2 protocol.
 * @param xA In Pointer to the key exchange parameter xA
 * @param encrypt_key Encrypt key
 * @return 0 on success and -1 on failures
 */
int32_t sdo_set_kex_paramA(sdo_byte_array_t *xA, sdo_public_key_t *encrypt_key)

{
	int32_t ret = true;
	sdo_kex_ctx_t *key_ex_data = (sdo_kex_ctx_t *)(getsdo_key_ctx());

	if (!xA) {
		return -1;
	}

	if (set_encrypt_key(encrypt_key)) {
		LOG(LOG_ERROR, "Failed set encryption random\n");
		return -1;
	}

	if (0 != crypto_hal_set_peer_random(key_ex_data->context, xA->bytes,
					    xA->byte_sz)) {
		LOG(LOG_ERROR, "Failed set peer random\n");
		return -1;
	}

	ret = kex_kdf();
	return ret;
}
