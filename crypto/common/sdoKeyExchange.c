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
	kex_ctx->kdf_label = "MarshalPointKDF";
	kex_ctx->sek_label = "AutomaticProvisioning-cipher";
	kex_ctx->svk_label = "AutomaticProvisioning-hmac";

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

static int32_t prep_keymat(uint8_t *keymat, size_t keymat_size,
			   sdo_byte_array_t *shse, bool svk, bool svk384)
{
	int ret = -1;
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	const char *label = kex_ctx->sek_label;
	size_t ofs = 0;
	uint8_t idx0_val = 0x1; /* for keymat1 */

	/* Decide what to fill in idx = 0 of key material */
	if (svk) {
		if (svk384 == 0) {
			idx0_val = 0x2;
		} else {
			idx0_val = 0x3;
		}
		label = kex_ctx->svk_label;
	}
	keymat[ofs] = idx0_val;
	ofs += 1;

	/* Fill in the kdflabel */
	if (strncpy_s((char *)&keymat[ofs], keymat_size - ofs,
		      kex_ctx->kdf_label,
		      strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE))) {
		LOG(LOG_ERROR, "Failed to fill kdf label in key Material 1\n");
		goto err;
	}
	ofs += strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE);

	/* Follow the kdf_label by 0 */
	keymat[ofs] = 0x00;
	ofs += 1;

	/* Fill in the sek/svk label */
	if (strncpy_s((char *)&keymat[ofs], keymat_size - ofs, label,
		      strnlen_s(label, SDO_MAX_STR_SIZE))) {
		LOG(LOG_ERROR, "Failed to fill svk label\n");
		goto err;
	}
	ofs += strnlen_s(label, SDO_MAX_STR_SIZE);

	/* Fill in the shared secret */
	if (memcpy_s(&keymat[ofs], keymat_size - ofs, shse->bytes,
		     shse->byte_sz)) {
		LOG(LOG_ERROR, "Failed to copy shared secret\n");
		goto err;
	}

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
 *
 * @return ret
 *        return true on success. false on failure.
 */
static int32_t kex_kdf(void)
{
	int ret = -1;
	size_t keymat1_size = 0;
	size_t keymat2_size = 0;
	struct sdo_kex_ctx *kex_ctx = getsdo_key_ctx();
	sdo_byte_array_t *shse = get_secret();
	sdo_aes_keyset_t *keyset = get_keyset();
	uint8_t *keymat1 = NULL;
	uint8_t *keymat2a = NULL;
	uint8_t *keymat2b = NULL;
	uint8_t *hmac_buf = NULL;
	uint8_t hmac_key[SHA256_DIGEST_SIZE] = {0};

	/*
	 * kdf_label = "Marshal_pointKDF"
	 * sek_label = "Automatic_provisioning-cipher"
	 * svk_label = "Automatic_provisioning-hmac"
	 *
	 * For DH/ECDH/ASYM
	 * ----------------
	 * key_material1 = HMAC-SHA-256[0,
	 * (byte)1||kdf_label||(byte)0||sek_label||Sh_se] key_material2 =
	 * HMAC-SHA-256[0, (byte)2||kdf_label||(byte)0||svk_label||Sh_se]
	 *
	 * sek = Key_material1[0..15] (128 bits, to feed AES128)
	 * svk = Key_material2[0..31] (256 bits, to feed SHA256)
	 *
	 * For ECDH384
	 * -----------
	 * key_material1  = HMAC-SHA-384[0,
	 * (byte)1||kdf_label||(byte)0||sek_label||Sh_se] key_material2a =
	 * HMAC-SHA-384[0, (byte)2||kdf_label||(byte)0||svk_label||Sh_se]
	 * key_material2b = HMAC-SHA-384[0,
	 * (byte)3||kdf_label||(byte)0||svk_label||Sh_se]
	 *
	 * sek = Key_material1[0..31]
	 * svk = Key_material2a[0..47] || Key_material2b[0..15]
	 *
	 */

	if (!shse) {
		LOG(LOG_ERROR, "Failed to get the shared secret\n");
		goto err;
	}

	keymat1_size = 1 + strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE) + 1 +
		       strnlen_s(kex_ctx->sek_label, SDO_MAX_STR_SIZE) +
		       shse->byte_sz;
	keymat2_size = 1 + strnlen_s(kex_ctx->kdf_label, SDO_MAX_STR_SIZE) + 1 +
		       strnlen_s(kex_ctx->svk_label, SDO_MAX_STR_SIZE) +
		       shse->byte_sz;

	/* Allocate memory for key materials */
	keymat1 = sdo_alloc(keymat1_size);
	if (!keymat1) {
		LOG(LOG_ERROR, "Out of memory for key material 1\n");
		goto err;
	}

	keymat2a = sdo_alloc(keymat2_size);
	if (!keymat2a) {
		LOG(LOG_ERROR, "Out of memory for key material 2a\n");
		goto err;
	}

#ifdef KEX_ECDH384_ENABLED
	keymat2b = sdo_alloc(keymat2_size);
	if (!keymat2b) {
		LOG(LOG_ERROR, "Out of memory for key material 2b\n");
		goto err;
	}
#endif

	/*
	 * Prepare keymaterial for key derivation
	 *  -----------------------------------------------------
	 * | param1 (svk)| param2 (svk384) | Comments            |
	 * | false       | Don't care      | Derive sek          |
	 * | true        | false           | Derive svk          |
	 * | true        | true            | Derive svk (ecdh384)|
	 *  -----------------------------------------------------
	 */
	ret = prep_keymat(keymat1, keymat1_size, shse, false, false);
	if (ret) {
		LOG(LOG_ERROR, "Failed to prepare keymat1\n");
		goto err;
	}

	ret = prep_keymat(keymat2a, keymat2_size, shse, true, false);
	if (ret) {
		LOG(LOG_ERROR, "Failed to prepare keymat2a\n");
		goto err;
	}

#ifdef KEX_ECDH384_ENABLED
	ret = prep_keymat(keymat2b, keymat2_size, shse, true, true);
	if (ret) {
		LOG(LOG_ERROR, "Failed to prepare keymat2b\n");
		goto err;
	}
#endif

	/* Generate the final key materials. Keys will be subpart of it */

	/*
	 * Allocate a transient buffer to store hmac.
	 * AES key is either 128 bit or 256 bit, so, in any case it
	 * cannot be directly used to hold the HMAC output
	 */
	hmac_buf = sdo_alloc(SDO_SHA_DIGEST_SIZE_USED);
	if (!hmac_buf) {
		LOG(LOG_ERROR, "Failed to allocate hmac buffer\n");
		goto err;
	}

	if (crypto_hal_hmac(SDO_CRYPTO_HMAC_TYPE_USED, keymat1, keymat1_size,
			    hmac_buf, SDO_SHA_DIGEST_SIZE_USED, hmac_key,
			    sizeof(hmac_key))) {
		LOG(LOG_ERROR, "Failed to derive key via HMAC\n");
		goto err;
	}

	/* Get the sek. (keyset->sek->byte_sz <= SDO_SHA_DIGEST_SIZE_USED) */
	if (memcpy_s(keyset->sek->bytes, keyset->sek->byte_sz, hmac_buf,
		     keyset->sek->byte_sz)) {
		LOG(LOG_ERROR, "Failed to copy sek key\n");
		goto err;
	}

	/*
	 * Get the svk key. It can directly hold the hmac output as it
	 * is either 256 bits (32 bytes) or 512 bits (64 bytes)
	 */
	if (crypto_hal_hmac(SDO_CRYPTO_HMAC_TYPE_USED, keymat2a, keymat2_size,
			    keyset->svk->bytes, keyset->svk->byte_sz, hmac_key,
			    sizeof(hmac_key))) {
		LOG(LOG_ERROR, "Failed to derive key via HMAC\n");
		goto err;
	}

/*
 * If the kex selected is ecdh384, then calculate hmac over
 * keymat2b. In this case, hmac buffer will not be able to
 * directly hold next 48 bytes more, so, using the above
 * allocated transient buffer
 */
#ifdef KEX_ECDH384_ENABLED
	if (crypto_hal_hmac(SDO_CRYPTO_HMAC_TYPE_USED, keymat2b, keymat2_size,
			    hmac_buf, SDO_SHA_DIGEST_SIZE_USED, hmac_key,
			    sizeof(hmac_key))) {
		LOG(LOG_ERROR, "Failed to derive key via HMAC\n");
		goto err;
	}

	/* Copy 16 bytes more to complete 64 bytes of svk */
	if (memcpy_s(keyset->svk->bytes + SDO_SHA_DIGEST_SIZE_USED,
		     keyset->svk->byte_sz - SDO_SHA_DIGEST_SIZE_USED, hmac_buf,
		     16)) {
		LOG(LOG_ERROR, "Failed to fill svk\n");
		goto err;
	}
#endif

	ret = 0;

err:
	if (hmac_buf) {
		sdo_free(hmac_buf);
	}
	if (keymat1) {
		sdo_free(keymat1);
	}
	if (keymat2a) {
		sdo_free(keymat2a);
	}
	if (keymat2b) {
		sdo_free(keymat2b);
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
