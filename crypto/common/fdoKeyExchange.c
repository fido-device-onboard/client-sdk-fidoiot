/*
 * Copyright 2020 Intel Corporation
 * SPDX-License-Identifier: Apache 2.0
 */

#include <math.h>
#include "fdokeyexchange.h"
#include "fdoCryptoHal.h"
#include "util.h"
#include "safe_lib.h"
#include "snprintf_s.h"
#include "stdlib.h"
#include "fdoCryptoCtx.h"
#include "fdoCrypto.h"

/* Static functions */
static int32_t remove_java_compatible_byte_array(fdo_byte_array_t *BArray);

/******************************************************************************/
/**
 * fdo_kex_init() - Initialize key exchange context
 * Initialize the key exchange context which can be done at init time
 * o Key Exchange algorithm (ECDH, ECDH384)
 * o Cipher Suite to be used
 * o If it's ECDH, perform the 1st step of ECDH
 */
int32_t fdo_kex_init(void)
{
	char cs[32];
	int32_t ret = -1;
	fdo_kex_ctx_t *kex_ctx = getfdo_key_ctx();
	fdo_to2Sym_enc_ctx_t *to2sym_ctx = get_fdo_to2_ctx();
	size_t ofs = 0;

	/* Allocate kex string */
	kex_ctx->kx = fdo_string_alloc_with_str(KEX);
	if (!kex_ctx->kx) {
		LOG(LOG_ERROR, "Failed to allocate kex info\n");
		goto err;
	}

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

#ifdef AES_MODE_GCM_ENABLED
	// AES GCM mode
	snprintf_s_i(cs, sizeof(cs), "AES%uGCM", AES_BITS);
	(void)ofs;
#else
	// AES CCM mode
	snprintf_s_i(cs, sizeof(cs), "AES-CCM-64-128-%u", AES_BITS);
	(void)ofs;
#endif

	kex_ctx->cs = fdo_string_alloc_with_str(cs);
	if (!kex_ctx->cs) {
		LOG(LOG_ERROR, "Failed to allocate cs info\n");
		goto err;
	}

	/* Allocate buffer for Session Encryption Key (SEK) */
	to2sym_ctx->keyset.sek = fdo_byte_array_alloc(SEK_KEY_SIZE);
	if (!to2sym_ctx->keyset.sek) {
		goto err;
	}

	if (crypto_hal_kex_init(&(kex_ctx->context))) {
		goto err;
	}

	/* Fill out the labels */
	kex_ctx->kdf_label = "FIDO-KDF";
	kex_ctx->context_label = "AutomaticOnboardTunnel";

	ret = 0; /* Mark as success */

err:
	if (ret) {
		fdo_kex_close();
	}
	return ret;
}

/**
 * fdo_kex_close() - release kex context
 */
int32_t fdo_kex_close(void)
{
	struct fdo_kex_ctx *kex_ctx = getfdo_key_ctx();
	fdo_to2Sym_enc_ctx_t *to2sym_ctx = get_fdo_to2_ctx();
	/* Free "KEX" string (Key Exchange) */
	if (kex_ctx->kx) {
		fdo_string_free(kex_ctx->kx);
		kex_ctx->kx = NULL;
	}

	/* Free "Cipher Suite" string */
	if (kex_ctx->cs) {
		fdo_string_free(kex_ctx->cs);
		kex_ctx->cs = NULL;
	}

	/* Free "Key Exchange" information sent from device */
	if (kex_ctx->xB) {
		fdo_byte_array_free(kex_ctx->xB);
		kex_ctx->xB = NULL;
	}

	/* TODO: Final initial secret */
	if (kex_ctx->initial_secret) {
		fdo_byte_array_free(kex_ctx->initial_secret);
		kex_ctx->initial_secret = NULL;
	}

	/* Cleanup fdo_to2Sym_enc_ctx_t */
	if (to2sym_ctx->keyset.sek) {
		fdo_byte_array_free(to2sym_ctx->keyset.sek);
		to2sym_ctx->keyset.sek = NULL;
	}
	if (to2sym_ctx->keyset.svk) {
		fdo_byte_array_free(to2sym_ctx->keyset.svk);
		to2sym_ctx->keyset.svk = NULL;
	}

	if (to2sym_ctx->initialization_vector) {
		fdo_free(to2sym_ctx->initialization_vector);
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
static int32_t set_encrypt_key(fdo_public_key_t *encrypt_key)
{
#ifdef KEX_ASYM_ENABLED
	struct fdo_kex_ctx *kex_ctx = getfdo_key_ctx();

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
int32_t fdo_get_kex_paramB(fdo_byte_array_t **xB)
{
	int32_t ret = -1;
	fdo_kex_ctx_t *kex_ctx = getfdo_key_ctx();
	uint32_t bufsize = 0;
	fdo_byte_array_t *tmp_xB = NULL;

	if (!xB) {
		return -1;
	}
	if (*xB != NULL) {
		fdo_byte_array_free(*xB);
		*xB = NULL;
	}

	if (crypto_hal_get_device_random(kex_ctx->context, NULL, &bufsize)) {
		return -1;
	}

	tmp_xB = fdo_byte_array_alloc(bufsize);
	if (!tmp_xB) {
		goto err;
	}

	if (crypto_hal_get_device_random(kex_ctx->context, tmp_xB->bytes,
					 &bufsize)) {
		goto err;
	}
	/* if not clean clean it */
	if (kex_ctx->xB != NULL) {
		fdo_byte_array_free(kex_ctx->xB);
		kex_ctx->xB = NULL;
	}
	kex_ctx->xB = tmp_xB;
	*xB = kex_ctx->xB;
	ret = 0;
err:
	if (ret && tmp_xB) {
		fdo_byte_array_free(tmp_xB);
		*xB = NULL;
	}
	return ret;
}

static int32_t remove_java_compatible_byte_array(fdo_byte_array_t *BArray)
{
	if (BArray && BArray->bytes) {
		if (BArray->bytes[0] == 0x00) {
			if (!memmove_s(BArray->bytes, BArray->byte_sz - 1,
				       &BArray->bytes[1], BArray->byte_sz - 1)) {
				BArray->byte_sz--;
			} else {
				return -1;
			}
		}
		return 0;
		// BArray->bytes[0] != 0x00 is also valid array
	}
	return -1;
}

/**
 * Write the input to the KDF i.e KDFInput, of size kdf_input_len into kdf_input buffer.
 * Refer to Section 3.6.4 in FIDO Device Onboard (FDO) specification.
 *
 * KDFInput = (byte)i||"FIDO-KDF"||(byte)0||Context||Lstr,
 * where Context = "AutomaticOnboardTunnel"||ContextRand, and,
 * ContextRand = null for ECDH Key Exchange (Section 3.6.3)
 *
 * index is the counter (i), and cannot be more than 2.
 * keymat_bit_length is the total number of key-bits to generate, and is used to calculate Lstr.
 */
static int32_t prep_kdf_input(uint8_t *kdf_input, size_t kdf_input_len, const int index,
	const int keymat_bit_length)
{
	int ret = -1;
	struct fdo_kex_ctx *kex_ctx = getfdo_key_ctx();
	size_t ofs = 0;
	uint8_t idx0_val;
	size_t kdf_label_len = 0;
	size_t context_label_len = 0;

	if (!kex_ctx) {
		LOG(LOG_ERROR, "Key exchange context is not initialized.\n");
		goto err;
	}

	kdf_label_len = strnlen_s(kex_ctx->kdf_label, FDO_MAX_STR_SIZE);
	if (!kdf_label_len || kdf_label_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "KDF Label is not NULL terminated.\n");
		goto err;
	}

	context_label_len = strnlen_s(kex_ctx->context_label,
					FDO_MAX_STR_SIZE);
	if (!context_label_len || context_label_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "Context Label is not NULL terminated.\n");
		goto err;
	}

	if (index == 1) {
		idx0_val = 0x01;
	} else if (index == 2) {
		idx0_val = 0x02;
	} else {
		// for now, we cannot go beyond 2
		LOG(LOG_ERROR, "Invalid i\n");
		goto err;
	}

	kdf_input[ofs++] = idx0_val;
	// Fill in the kdflabel
	if (strncpy_s((char *)&kdf_input[ofs], kdf_input_len - ofs,
		kex_ctx->kdf_label, kdf_label_len)) {
		LOG(LOG_ERROR, "Failed to fill kdf label in key Material\n");
		goto err;
	}
	ofs += kdf_label_len;
	// Separation indicator
	kdf_input[ofs++] = 0x00;
	// Fill in the context
	if (strncpy_s((char *)&kdf_input[ofs], kdf_input_len - ofs,
		kex_ctx->context_label, context_label_len)) {
		LOG(LOG_ERROR, "Failed to fill svk label\n");
		goto err;
	}
	ofs += context_label_len;
	kdf_input[ofs++] = (keymat_bit_length >> 8) & 0xff;
	kdf_input[ofs++] = keymat_bit_length & 0xff;

	ret = 0;

err:
	return ret;
}

/* Get Shared Secret She_she */
static fdo_byte_array_t *get_secret(void)
{
	fdo_byte_array_t *b = NULL;
	uint8_t *shared_secret_buffer = NULL;
	uint32_t secret_size = 0;
	struct fdo_kex_ctx *kex_ctx = getfdo_key_ctx();
	fdo_kex_ctx_t *key_ex_data = (fdo_kex_ctx_t *)(getfdo_key_ctx());

	if (crypto_hal_get_secret(key_ex_data->context, NULL, &secret_size) !=
	    0) {
		LOG(LOG_ERROR, " crypto_hal_get_secret failed");
		return NULL;
	}

	shared_secret_buffer = fdo_alloc(secret_size);

	if (!shared_secret_buffer) {
		LOG(LOG_ERROR, " alloc of %d failed", (int)secret_size);
		return NULL;
	}

	if (crypto_hal_get_secret(key_ex_data->context, shared_secret_buffer,
				  &secret_size) != 0) {
		LOG(LOG_ERROR, " crypto_hal_get_secret failed");
		goto err;
	}

	b = fdo_byte_array_alloc_with_byte_array(shared_secret_buffer,
						 secret_size);

	if (memset_s(shared_secret_buffer, secret_size, 0)) {
		LOG(LOG_ERROR, "Failed to clear shared secret buffer\n");
		goto err;
	}

	fdo_free(shared_secret_buffer);

	/* remove extra byte from bigendian java */
	if (remove_java_compatible_byte_array(b)) {
		goto err;
	}

	if (kex_ctx->initial_secret) {
		fdo_bits_free(kex_ctx->initial_secret);
		kex_ctx->initial_secret = b;
	}
	return b;

err:
	fdo_free(shared_secret_buffer);
	fdo_byte_array_free(b);
	return NULL;
}

/**
 * Derive encryption and hashing key using the input shared secret for
 * the selected key exchange mode.
 *
 * @return ret
 *        return true on success. false on failure.
 */
static int32_t kex_kdf(void)
{
	int ret = -1;
	struct fdo_kex_ctx *kex_ctx = getfdo_key_ctx();
	fdo_byte_array_t *shse = get_secret();
	fdo_aes_keyset_t *keyset = get_keyset();
	// input data to the KDF
	uint8_t *kdf_input = NULL;
	size_t kdf_input_len = 0;
	// length of 1 byte in bits
	int byte_size = 8;
	// Length of Output Keying Material, in bytes = SEK size for AES-GCM and AES-CCM modes
	size_t keymat_bytes_sz = SEK_KEY_SIZE;
	// Output Keying Material
	uint8_t keymat[keymat_bytes_sz];
	// number of iterations of PRF
	int n = 0;
	// counter, that is an input to each iteration of PRF
	int i = 0;
	size_t keymat_bytes_index = 0;
	size_t keymat_bytes_to_copy = 0;
	uint8_t *hmac = NULL;
	size_t hmac_sha256_sz = BUFF_SIZE_32_BYTES;
	size_t kdf_label_len = 0;
	size_t context_label_len = 0;

	if (!kex_ctx) {
		LOG(LOG_ERROR, "Key exchange context is not initialized.\n");
		goto err;
	}

	kdf_label_len = strnlen_s(kex_ctx->kdf_label, FDO_MAX_STR_SIZE);
	if (!kdf_label_len || kdf_label_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "KDF Label is not NULL terminated.\n");
		goto err;
	}

	context_label_len = strnlen_s(kex_ctx->context_label,
					FDO_MAX_STR_SIZE);
	if (!context_label_len || context_label_len == FDO_MAX_STR_SIZE) {
		LOG(LOG_ERROR, "Context Label is not NULL terminated.\n");
		goto err;
	}

	if (!shse) {
		LOG(LOG_ERROR, "Failed to get the shared secret\n");
		goto err;
	}

	// total number of rounds (n) to iterate for generating the total number of key bits
	// n = ceil (L/h), where,
	// L = Keying Material length in bits, and
	// h = PRF output length in bits
	n = ceil((double)(keymat_bytes_sz * byte_size) / (hmac_sha256_sz * byte_size));

	// Input to the KDF, KDFInput = (byte)i||"FIDO-KDF"||(byte)0||Context||Lstr, where
	// Context = "AutomaticOnboardTunnel"||ContextRand, ContextRand is NULL for ECDH key-exchange,
	// Lstr = (byte)L1||(byte)L2, i.e, 16-bit number, depending on L=key-bits to generate
	// Therefore, KDFInput size = 1 for byte (i) + length of Label + 1 for byte (0) +
	// length of Context + 2 bytes for Lstr
	kdf_input_len = 1 + kdf_label_len + 1 + context_label_len + 2;
	// Allocate memory for KDFInput
	kdf_input = fdo_alloc(kdf_input_len);
	if (!kdf_input) {
		LOG(LOG_ERROR, "Out of memory for key material 1\n");
		goto err;
	}

	// Allocate memory to store hmac
	hmac = fdo_alloc(hmac_sha256_sz);
	if (!hmac) {
		LOG(LOG_ERROR, "Failed to allocate hmac buffer\n");
		goto err;
	}

	// iterate for the calculated number of iterations (n) to generate key bits
	// once the iterations are done, keymat contains the generated key
	for (i = 1; i <= n; i++) {

		// clear for new round usage
		if (0 != memset_s(kdf_input, kdf_input_len, 0)) {
			LOG(LOG_ERROR, "Failed to clear kdf_input\n");
			goto err;
		}
		// prepare KDFInput by passing the number of rounds (i) and length of key bits (L)
		ret = prep_kdf_input(kdf_input, kdf_input_len, i, keymat_bytes_sz * byte_size);
		if (ret) {
			LOG(LOG_ERROR, "Failed to prepare kdf_input\n");
			goto err;
		}

		// clear for new round usage
		if (0 != memset_s(hmac, hmac_sha256_sz, 0)) {
			LOG(LOG_ERROR, "Failed to clear hmac buffer\n");
			goto err;
		}
		// generate hmac that gives us the key (or a part of it)
		if (crypto_hal_hmac(FDO_CRYPTO_HMAC_TYPE_SHA_256, kdf_input, kdf_input_len,
					hmac, hmac_sha256_sz, shse->bytes,
					shse->byte_sz)) {
			LOG(LOG_ERROR, "Failed to derive key via HMAC\n");
			goto err;
		}

		if (keymat_bytes_index + hmac_sha256_sz <= keymat_bytes_sz) {
			keymat_bytes_to_copy = hmac_sha256_sz;
		}
		else {
			keymat_bytes_to_copy = keymat_bytes_sz - keymat_bytes_index;
		}

		// copy the generated hmac (key/a part of the key) into generated key buffer
		if (memcpy_s(&keymat[keymat_bytes_index], keymat_bytes_sz, hmac,
		    keymat_bytes_to_copy)) {
			LOG(LOG_ERROR, "Failed to copy generated key bytes\n");
			goto err;
		}
		keymat_bytes_index += keymat_bytes_to_copy;
	}

	if (keymat_bytes_index != keymat_bytes_sz) {
		LOG(LOG_ERROR, "Mismatch is generated key bytes length\n");
		goto err;
	}

	// Get the sevk
	if (memcpy_s(keyset->sek->bytes, keyset->sek->byte_sz, &keymat[0],
		      keyset->sek->byte_sz)) {
		LOG(LOG_ERROR, "Failed to copy sek key\n");
		goto err;
	}

	ret = 0;

err:
	if (hmac) {
		fdo_free(hmac);
	}
	if (kdf_input) {
		fdo_free(kdf_input);
	}
	fdo_byte_array_free(shse);

	return ret;
}

/**
 * This API shall set the parameter A that is received from peer and proceed
 * to generate key as per the FDO Protocol Spec. This generated key shall be
 * used for encryption/decryption in TO2 protocol.
 * @param xA In Pointer to the key exchange parameter xA
 * @param encrypt_key Encrypt key
 * @return 0 on success and -1 on failures
 */
int32_t fdo_set_kex_paramA(fdo_byte_array_t *xA, fdo_public_key_t *encrypt_key)

{
	int32_t ret = true;
	fdo_kex_ctx_t *key_ex_data = (fdo_kex_ctx_t *)(getfdo_key_ctx());

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
