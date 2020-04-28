#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

### TLS Library validation
SUPPORTED_TLS = openssl mbedtls
$(info TLS = $(TLS))
ifeq ($(filter $(TLS),$(SUPPORTED_TLS)),)
    $(error Supported values for TLS are: $(SUPPORTED_TLS))
endif
ifeq ($(TLS), openssl)
    CRYPTO_CFLAGS := -DUSE_OPENSSL
else
    CRYPTO_CFLAGS := -DUSE_MBEDTLS
endif

### KEX (key exchange) validation
SUPPORTED_KEX = dh asym ecdh ecdh384 none

### Device Attestation validation
SUPPORTED_DA = epid ecdsa256 ecdsa384 tpm20_ecdsa256
$(info DA = $(DA))
ifeq ($(filter $(DA),$(SUPPORTED_DA)),)
    $(error Supported values for DA are: $(SUPPORTED_DA))
endif

# enforce to use higher crypto
ifeq ($(DA), ecdsa384)
    $(info "enforcing to use ecdh384 for ecdsa384")
    KEX = ecdh384
endif


ifeq ($(DA), epid)
    ifeq ($(EPID_SDK_R6_ROOT),)
        $(error EPID_SDK path is not set, please export EPID_SDK_R6_ROOT=/path/to/epid-sdk)
    endif

    SUPPORTED_EPID = epid_sdk epid_r6
    $(info EPID = $(EPID))
    ifeq ($(filter $(EPID),$(SUPPORTED_EPID)),)
        $(error Supported values for EPID are: $(SUPPORTED_EPID))
    endif
    ifeq ($(EPID), epid_sdk)
        CRYPTO_CFLAGS += -DEPID_SDK
    endif
    ifeq ($(EPID),epid_r6)
        CRYPTO_CFLAGS += -DEPID_R6
    endif
    CRYPTO_CFLAGS += -DEPID_DA
endif
ifeq ($(DA), $(filter $(DA), ecdsa256 tpm20_ecdsa256))
    CRYPTO_CFLAGS += -DECDSA256_DA
endif
ifeq ($(DA), $(filter $(DA), ecdsa384 tpm20_ecdsa384))
    CRYPTO_CFLAGS += -DECDSA384_DA
endif
ifeq ($(DA_FILE), pem)
    CRYPTO_CFLAGS += -DECDSA_PEM
endif

### Public Key Exchange validation
$(info PK_ENC = $(PK_ENC))
SUPPORTED_PK_ENC = rsa ecdsa
ifeq ($(filter $(PK_ENC),$(SUPPORTED_PK_ENC)),)
    $(error supported values for PK_ENC are: $(SUPPORTED_PK_ENC))
endif


ifeq ($(PK_ENC), rsa)
    ifeq ($(DA), $(filter $(DA), ecdsa256 tpm20_ecdsa256 ecdsa384 tpm20_ecdsa384))
        $(error PK_ENC: $(PK_ENC) not supported for DA : $(DA))
    endif
    CRYPTO_CFLAGS += -DPK_ENC_RSA
endif

ifeq ($(PK_ENC), ecdsa)
    ifeq ($(DA), epid)
        $(error PK_ENC: $(PK_ENC) not supported for DA : $(DA))
    endif
    CRYPTO_CFLAGS += -DPK_ENC_ECDSA
endif

$(info KEX = $(KEX))
ifeq ($(filter $(KEX),$(SUPPORTED_KEX)),)
    $(error supported values for kex are: $(SUPPORTED_KEX))
endif

ifeq ($(DA), epid)
    ifneq ($(KEX), $(filter $(KEX), dh asym))
        $(error $(KEX) not supported supported DA : $(DA))
    endif
endif

ifeq ($(DA), $(filter $(DA), ecdsa256 tpm20_ecdsa256 ecdsa384 tpm20_ecdsa384))
    ifneq ($(KEX), $(filter $(KEX), ecdh ecdh384))
        $(error $(KEX) not supported supported DA : $(DA))
    endif
endif

ifeq ($(KEX), dh)
    CRYPTO_CFLAGS += -DKEX=\"DHKEXid14\" -DKEX_DH_ENABLED
endif
ifeq ($(KEX), asym)
    CRYPTO_CFLAGS += -DKEX=\"ASYMKEX\" -DKEX_ASYM_ENABLED
endif

ifeq ($(KEX), ecdh)
    ifneq ($(DA), $(filter $(DA), ecdsa256 tpm20_ecdsa256))
	    $(error $(KEX) not supported supported DA : $(DA))
    endif
    CRYPTO_CFLAGS += -DKEX=\"ECDH\" -DKEX_ECDH_ENABLED
    CRYPTO_CFLAGS += -DAES_128_BIT
endif
ifeq ($(KEX), ecdh384)
    ifneq ($(DA), $(filter $(DA), ecdsa384 tpm20_ecdsa384))
        $(error $(KEX) not supported supported DA : $(DA))
    endif
    CRYPTO_CFLAGS += -DKEX=\"ECDH384\" -DKEX_ECDH384_ENABLED
    CRYPTO_CFLAGS += -DAES_256_BIT
endif

### Encryption mode validation
SUPPORTED_AES_MODE = cbc ctr
$(info AES_MODE = $(AES_MODE))
ifeq ($(filter $(AES_MODE),$(SUPPORTED_AES_MODE)),)
    $(error Supported values for AES_MODE are: $(SUPPORTED_AES_MODE))
endif
ifeq ($(AES_MODE), ctr)
    CRYPTO_CFLAGS += -DAES_MODE_CTR_ENABLED
endif
ifeq ($(AES_MODE), cbc)
    CRYPTO_CFLAGS += -DAES_MODE_CBC_ENABLED
endif
AES := `echo $(AES_MODE) | tr a-z A-Z`
CRYPTO_CFLAGS += -DAES_MD=\"$(AES)\"

### Invalid combinations
ifeq ($(PK_ENC), ecdsa)
    ifeq ($(KEX), asym)
        $(error ecdsa public-key-encoding and asym key-exchange are not supported together)
    endif
endif
