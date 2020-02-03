#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
include crypto/conf.mk

### Common crypto
common-srcs-y += sdoOvVerify.c sdoKeyExchange.c sdoAes.c sdoHmac.c sdoDevSign.c sdoCryptoCommon.c sdoDevAttest.c

ifeq ($(KEX), asym)
        common-srcs-y += sdokeyexchange_asym.c
endif

### OpenSSL
ifeq ($(TLS), openssl)
    crypto-srcs-y += openssl_AESRoutines.c openssl_cryptoSupport.c openssl_SSLRoutines.c openssl_base64.c

    ifeq ($(CRYPTO_HW), false)
        crypto-srcs-y += openssl_AESGCMRoutines.c
    endif

    ### DH key exchange
    ifeq ($(KEX), dh)
        crypto-srcs-y += openssl_key_exchange_dh.c
    endif
    ### ECDH key exchange
    ifeq ($(KEX),$(filter $(KEX),ecdh ecdh384))
        crypto-srcs-y += openssl_key_exchange_ecdh.c
    endif

    ### Signature verifications types
    ifeq ($(PK_ENC), ecdsa)
        ifeq ($(CRYPTO_HW), false)
            crypto-srcs-y += openssl_ECDSAVerifyRoutines.c
        endif
    endif
    ifeq ($(PK_ENC), rsa)
        crypto-srcs-y += openssl_RSAVerifyRoutines.c
    endif

    crypto-srcs-y += openssl_RSAEncryptRoutines.c

    ifeq ($(DA),$(filter $(DA),ecdsa256 ecdsa384))
        ifeq ($(CRYPTO_HW), false)
            crypto-srcs-y += openssl_ECDSASignRoutines.c
            crypto-srcs-y += openssl_csr.c ec_key.c
            ecdsa-srcs-y  += ecdsa_privkey.c
        endif

    else ifeq ($(DA),$(filter $(DA),tpm20_ecdsa256 tpm20_ecdsa384))
        crypto-srcs-y += tpm20_ECDSASignRoutines.c
        crypto-srcs-y += tpm20_Utils.c
        crypto-srcs-y += openssl_csr.c ec_key.c
        ecdsa-srcs-y  += ecdsa_privkey.c
    endif

    crypto-srcs-y += BN_support.c
    ifeq ($(CRYPTO_HW), true)
        crypto-srcs-y += openssl_DERRoutines.c
    endif
endif

### mbedTLS
ifeq ($(TLS), mbedtls)
    crypto-srcs-y += mbedtls_AESRoutines.c mbedtls_cryptoSupport.c mbedtls_SSLRoutines.c mbedtls_random.c mbedtls_base64.c

    ifeq ($(CRYPTO_HW), false)
        crypto-srcs-y += mbedtls_AESGCMRoutines.c
    endif

    ### Signature verifications types
    ifeq ($(PK_ENC), ecdsa)
        ifeq ($(CRYPTO_HW), false)
            crypto-srcs-y += mbedtls_ECDSAVerifyRoutines.c
        endif
    endif
    ifeq ($(PK_ENC), rsa)
        crypto-srcs-y += mbedtls_RSAVerifyRoutines.c
    endif

    crypto-srcs-y += mbedtls_RSAEncryptRoutines.c

    ifeq ($(DA),$(filter $(DA),ecdsa256 ecdsa384))
        ifeq ($(CRYPTO_HW), false)
            crypto-srcs-y += mbedtls_ECDSASignRoutines.c
            crypto-srcs-y += mbedtls_ec_csr.c
        endif
        ecdsa-srcs-y  += ecdsa_privkey.c
    endif

    ### DH key exchange
    ifeq ($(KEX), dh)
        crypto-srcs-y += mbedtls_key_exchange_dh.c
    endif
    ### ECDH key exchange
    ifeq ($(KEX),$(filter $(KEX),ecdh ecdh384))
        crypto-srcs-y += mbedtls_key_exchange_ecdh.c
    endif
    ifeq ($(CRYPTO_HW), true)
        crypto-srcs-y += mbedtls_DERRoutines.c
    endif
endif

ifeq ($(CRYPTO_HW), true)
        se-srcs-y = se_AESGCMRoutines.c  se_cryptoSupport.c se_csr.c
        ifeq ($(PK_ENC), ecdsa)
            se-srcs-y += se_ECDSAVerifyRoutines.c
        endif
        ifeq ($(DA),$(filter $(DA),ecdsa256 ))
            se-srcs-y += se_ECDSASignRoutines.c
        endif
        srcs-y += $(addprefix crypto/se/, $(se-srcs-y))
endif

srcs-y += $(addprefix crypto/common/, $(common-srcs-y))
srcs-y += $(addprefix crypto/$(TLS)/, $(crypto-srcs-y))
ifeq ($(DA),$(filter $(DA),ecdsa256 ecdsa384 tpm20_ecdsa256 tpm20_ecdsa384))
    srcs-y += $(addprefix crypto/ecdsa/, $(ecdsa-srcs-y))
endif
