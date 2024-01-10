#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#define FDO_CRED_NV_IDX 0x1000001

#define TPM_HMAC_PUB_KEY_NV_IDX 0x1000002
#define TPM_HMAC_PRIV_KEY_NV_IDX 0x1000003

#define TPM_HMAC_DATA_PUB_KEY_NV_IDX 0x1000004
#define TPM_HMAC_DATA_PRIV_KEY_NV_IDX 0x1000005

#define TPM_HMAC_REPLACEMENT_PUB_KEY_NV_IDX 0x1000006
#define TPM_HMAC_REPLACEMENT_PRIV_KEY_NV_IDX 0x1000007

#define TPM_ECDSA_DEVICE_KEY_NV_IDX 0x1000008
#define TPM_DEVICE_CSR_NV_IDX 0x1000009

#if defined(ECDSA256_DA)
#define FDO_TPM2_ALG_SHA TPM2_ALG_SHA256
#else
#define FDO_TPM2_ALG_SHA TPM2_ALG_SHA384
#endif

/** Define space at NV index.
 *
 * @param[in] nv NV index to delete.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvdefine(uint32_t nv, size_t data_size);

/** Store a data in a NV index.
 *
 * @param[in] data Key to store to NVRAM.
 * @param[in] data_size Size of the data.
 * @param[in] nv NV index to store the data.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvwrite(const uint8_t *data, size_t data_size, uint32_t nv);

/** Load data size from a NV index.
 *
 * @param[in] nv NV index of the data.
 * @retval data size on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
size_t fdo_tpm_nvread_size(uint32_t nv);

/** Load a data from a NV index.
 *
 * @param[in] nv NV index of the data.
 * @param[out] data Loaded data.
 * @param[out] data_size Size of the data.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvread(uint32_t nv, size_t data_size, uint8_t **data);

/** Delete data from a NV index.
 *
 * @param[in] nv NV index to delete.
 * @retval 0 on success.
 * @retval -1 on undefined/general failure.
 * @retval TSS2_RC response code for failures relayed from the TSS library.
 */
int fdo_tpm_nvdel(uint32_t nv);