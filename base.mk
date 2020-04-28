#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

### Environment checks
ifeq ($(BASE_DIR),)
$(error BASE_DIR is not defined)
endif

ifeq ($(EPID), epid_sdk)
ifeq ($(EPID_SDK_ROOT),)
$(error EPID_SDK_ROOT is undefined, see README.rst)
endif
endif

### Variables
TARGET_OS ?= linux
BUILD ?= debug
ARCH ?= x86
CSTD ?= c99
V ?= 0
CLI ?= false
DA ?= ecdsa256
KEX ?= ecdh
PK_ENC ?= ecdsa
AES_MODE ?= ctr
HTTPPROXY ?= true
PROXY_DISCOVERY ?= false
RESALE ?= true
REUSE ?= true
MODULES ?= false
STORAGE ?= true
RETRY ?= true
CRYPTO_HW ?= false
OPTIMIZE ?= 0

ifneq ($(OPENSSL_BIN_ROOT),)
CFLAGS += -I$(OPENSSL_BIN_ROOT)/include
endif

ifeq ($(MODULES), true)
DFLAGS += -DMODULES_ENABLED
endif

ifeq ($(TARGET_OS), linux)
EPID ?= epid_r6
TLS ?= openssl
# Enable following compiler flags, so, that sdo compilation
# works for optee out of the box
CFLAGS += -Wold-style-declaration -Wold-style-definition
CFLAGS += -fstack-protector -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -fPIE -fPIC
endif
ifeq ($(TARGET_OS), freertos)
EPID ?= epid_r6
TLS ?= mbedtls
BOARD ?= esp32
endif
ifeq ($(TARGET_OS), optee)
EPID ?= epid_r6
TLS ?= tomcrypt
CFG_ARM64_ta_arm64=y
BOARD ?= rpi3
endif
ifeq ($(TARGET_OS), mbedos)
EPID ?= epid_r6
TLS ?= mbedtls
BOARD ?= NUCLEO_F429ZI
endif

ifeq ($(CRYPTO_HW), true)
DFLAGS += -DSECURE_ELEMENT
CFLAGS += -I${CRYPTOAUTHLIB_ROOT}/lib/basic -I${CRYPTOAUTHLIB_ROOT}/lib
endif

ifneq ($(TARGET_OS),$(filter $(TARGET_OS),linux mbedos))
ifneq ($(MANUFACTURER_IP), )
DFLAGS += -DMANUFACTURER_IP=\"$(MANUFACTURER_IP)\"
endif

ifneq ($(MANUFACTURER_DN), )
DFLAGS += -DMANUFACTURER_DN=\"$(MANUFACTURER_DN)\"
endif
endif

# Manufacturer toolkit
MANUFACTURER_TOOLKIT ?= false

### Supported values
SUPPORTED_BUILD = debug release
SUPPORTED_QEMU_BOARD = qemu_x86 qemu_cortex_m3
SUPPORTED_BOARD = $(SUPPORTED_QEMU_BOARD) esp32 rpi3  NUCLEO_F429ZI NUCLEO_F767ZI
SUPPORTED_CSTD = c90 c99
SUPPORTED_CREDENTIALS = hard-coded file
SUPPORTED_CLI = true false
SUPPORTED_HTTPPROXY = true false
SUPPORTED_PROXY_DISCOVERY = true false
SUPPORTED_MODULES = true false

### Parameter list
ifneq ($(TARGET_OS), linux)
PARAM_LST += BOARD=$(BOARD)
endif

export PARAM_LST +=             \
	V=$(V)                 \
	TARGET_OS=$(TARGET_OS) \
	BUILD=$(BUILD)         \
	ARCH=$(ARCH)           \
	EPID=$(EPID)           \
	TLS=$(TLS) \
	CLI=$(CLI) \
	KEX=$(KEX) \
	DA=$(DA) \
	PK_ENC=$(PK_ENC) \
	AES_MODE=$(AES_MODE) \
	HTTPPROXY=$(HTTPPROXY) \
	PROXY_DISCOVERY=$(PROXY_DISCOVERY) \
	MODULES=$(MODULES) \
	MANUFACTURER_TOOLKIT=$(MANUFACTURER_TOOLKIT) \
	RESALE=$(RESALE) \
	REUSE=$(REUSE)

### Include paths
CFLAGS += -I$(BASE_DIR)/include -I$(BASE_DIR)/lib/include
CFLAGS += -I$(BASE_DIR)/crypto/common

$(info EPID = $(EPID))

CFLAGS += -Wall

### Board definition
ifneq ($(TARGET_OS), linux)
$(info BOARD = $(BOARD))
ifeq ($(filter $(BOARD), $(SUPPORTED_BOARD)),)
$(error Supported values are: $(SUPPORTED_BOARD))
endif
endif

### Debug/release build
$(info BUILD = $(BUILD))
ifeq ($(BUILD), debug)
    CFLAGS += -O$(OPTIMIZE) -g
    ifeq ($(TARGET_OS), linux)
        ifeq ($(UNIT_TEST), true)
            DFLAGS += -ULOG_LEVEL -DLOG_LEVEL=-1
        else
            DFLAGS += -DDEBUG -DLOG_LEVEL=2
        endif
    else
        DFLAGS += -DLOG_LEVEL=3
    endif
else
    ifeq ($(BUILD), release)
        CFLAGS += -Os -fomit-frame-pointer -s -Wl,-strip-debug
        ifeq ($(UNIT_TEST), true)
            DFLAGS += -DLOG_LEVEL=-1
        else
            DFLAGS += -DLOG_LEVEL=1
        endif
    else
        $(error Supported BUILD values are 'release' and 'debug')
    endif
endif

# Blob path defines for SDO over Linux
ifeq ($(TARGET_OS), linux)
    DFLAGS += -DPLATFORM_IV=\"$(PRJ_DIR)/data/platform_iv.bin\"
    DFLAGS += -DPLATFORM_HMAC_KEY=\"$(PRJ_DIR)/data/platform_hmac_key.bin\"
    DFLAGS += -DPLATFORM_AES_KEY=\"$(PRJ_DIR)/data/platform_aes_key.bin\"
    DFLAGS += -DEPID_PRIVKEY=\"$(PRJ_DIR)/data/epidprivkey.dat\"
    DFLAGS += -DSDO_CRED=\"$(PRJ_DIR)/data/PMDeviceCredentials.bin\"
    DFLAGS += -DMANUFACTURER_IP=\"$(PRJ_DIR)/data/manufacturer_ip.bin\"
    DFLAGS += -DMANUFACTURER_DN=\"$(PRJ_DIR)/data/manufacturer_dn.bin\"
    DFLAGS += -DMANUFACTURER_PORT=\"$(PRJ_DIR)/data/manufacturer_port.bin\"
    ifeq ($(DA), $(filter $(DA),tpm20_ecdsa256 tpm20_ecdsa384))
        DFLAGS += -DDEVICE_TPM20_ENABLED
        DFLAGS += -DDEVICE_MSTRING=\"$(PRJ_DIR)/data/device_mstring\"
        DFLAGS += -DTPM_ECDSA_DEVICE_KEY=\"$(PRJ_DIR)/data/tpm_ecdsa_priv_pub_blob.key\"
        DFLAGS += -DTPM_INPUT_DATA_TEMP_FILE=\"$(PRJ_DIR)/data/tpm_input_data_temp_file\"
        DFLAGS += -DTPM_OUTPUT_DATA_TEMP_FILE=\"$(PRJ_DIR)/data/tpm_output_data_temp_file\"
        DFLAGS += -DTPM_HMAC_PUB_KEY=\"$(PRJ_DIR)/data/tpm_hmac_pub.key\"
        DFLAGS += -DTPM_HMAC_PRIV_KEY=\"$(PRJ_DIR)/data/tpm_hmac_priv.key\"
        DFLAGS += -DTPM_HMAC_DATA_PUB_KEY=\"$(PRJ_DIR)/data/tpm_hmac_data_pub.key\"
        DFLAGS += -DTPM_HMAC_DATA_PRIV_KEY=\"$(PRJ_DIR)/data/tpm_hmac_data_priv.key\"
        DFLAGS += -DTPM2_TSS_ENGINE_SO_PATH=\"/usr/local/lib/engines-1.1/libtpm2tss.so\"
        DFLAGS += -DTPM2_TCTI_TYPE=\"tabrmd\"
    endif
ifeq ($(UNIT_TEST), true)
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/test_ecdsaprivkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/test_ecdsaprivkey.pem\"
endif
    DFLAGS += -DSDO_CACERT=\"$(PRJ_DIR)/data/test_cacert.bin\"
    DFLAGS += -DSDO_PUBKEY=\"$(PRJ_DIR)/data/test_pubkey.dat\"
    DFLAGS += -DSDO_SIGRL=\"$(PRJ_DIR)/data/test_sigrl.dat\"
    DFLAGS += -DSDO_CRED_SECURE=\"$(PRJ_DIR)/data/Secure.blob\"
    DFLAGS += -DSDO_CRED_MFG=\"$(PRJ_DIR)/data/Mfg.blob\"
    DFLAGS += -DSDO_CRED_NORMAL=\"$(PRJ_DIR)/data/Normal.blob\"
    DFLAGS += -DRAW_BLOB=\"$(PRJ_DIR)/data/raw.blob\"
else
ifeq ($(DA), ecdsa256)
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/ecdsa256privkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/ecdsa256privkey.pem\"
endif
else
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/ecdsa384privkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"$(PRJ_DIR)/data/ecdsa384privkey.pem\"
endif
endif
    DFLAGS += -DSDO_CACERT=\"$(PRJ_DIR)/data/cacert.bin\"
    DFLAGS += -DSDO_PUBKEY=\"$(PRJ_DIR)/data/pubkey.dat\"
    DFLAGS += -DSDO_SIGRL=\"$(PRJ_DIR)/data/sigrl.dat\"
    DFLAGS += -DSDO_CRED_SECURE=\"$(PRJ_DIR)/data/Secure.blob\"
    DFLAGS += -DSDO_CRED_MFG=\"$(PRJ_DIR)/data/Mfg.blob\"
    DFLAGS += -DSDO_CRED_NORMAL=\"$(PRJ_DIR)/data/Normal.blob\"
    DFLAGS += -DRAW_BLOB=\"$(PRJ_DIR)/data/raw.blob\"
endif
ifneq ("$(HTTPPROXY)", "")
    DFLAGS += -DMFG_PROXY=\"$(PRJ_DIR)/data/mfg_proxy.dat\"
    DFLAGS += -DRV_PROXY=\"$(PRJ_DIR)/data/rv_proxy.dat\"
    DFLAGS += -DOWNER_PROXY=\"$(PRJ_DIR)/data/owner_proxy.dat\"
endif
endif

ifeq ($(TARGET_OS), mbedos)
    DFLAGS += -DPLATFORM_IV=\"data/platform_iv.bin\"
    DFLAGS += -DPLATFORM_HMAC_KEY=\"data/platform_hmac_key.bin\"
    DFLAGS += -DPLATFORM_AES_KEY=\"data/platform_aes_key.bin\"
    DFLAGS += -DEPID_PRIVKEY=\"data/epidprivkey.dat\"
    DFLAGS += -DSDO_CRED=\"data/PMDeviceCredentials.bin\"
    DFLAGS += -DMANUFACTURER_IP=\"data/manufacturer_ip.bin\"
    DFLAGS += -DMANUFACTURER_DN=\"data/manufacturer_dn.bin\"
    DFLAGS += -DMANUFACTURER_PORT=\"data/manufacturer_port.bin\"
ifeq ($(UNIT_TEST), true)
    DFLAGS += -DSDO_CACERT=\"data/test_cacert.bin\"
    DFLAGS += -DSDO_PUBKEY=\"data/test_pubkey.dat\"
    DFLAGS += -DSDO_SIGRL=\"data/test_sigrl.dat\"
    DFLAGS += -DSDO_CRED_SECURE=\"data/Secure.blob\"
    DFLAGS += -DSDO_CRED_MFG=\"data/Mfg.blob\"
    DFLAGS += -DSDO_CRED_NORMAL=\"data/Normal.blob\"
    DFLAGS += -DRAW_BLOB=\"data/raw.blob\"
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"data/test_ecdsaprivkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"data/test_ecdsaprivkey.pem\"
endif
else
    DFLAGS += -DSDO_CACERT=\"data/cacert.bin\"
    DFLAGS += -DSDO_PUBKEY=\"data/pubkey.dat\"
    DFLAGS += -DSDO_SIGRL=\"data/sigrl.dat\"
    DFLAGS += -DSDO_CRED_SECURE=\"data/Secure.blob\"
    DFLAGS += -DSDO_CRED_MFG=\"data/Mfg.blob\"
    DFLAGS += -DSDO_CRED_NORMAL=\"data/Normal.blob\"
    DFLAGS += -DRAW_BLOB=\"data/raw.blob\"
ifeq ($(DA), ecdsa256)
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"data/ecdsa256privkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"data/ecdsa256privkey.pem\"
endif
else
ifneq ($(DA_FILE), pem)
    DFLAGS += -DECDSA_PRIVKEY=\"data/ecdsa384privkey.dat\"
else
    DFLAGS += -DECDSA_PRIVKEY=\"data/ecdsa256privkey.pem\"
endif

endif
endif
ifneq ("$(HTTPPROXY)", "")
    DFLAGS += -DMFG_PROXY=\"data/mfg_proxy.dat\"
    DFLAGS += -DRV_PROXY=\"data/rv_proxy.dat\"
    DFLAGS += -DOWNER_PROXY=\"data/owner_proxy.dat\"
endif
endif

### We don't want any logs when running unit tests

### TARGET_OS validation
#OS HAL include
CFLAGS += -I$(BASE_DIR)/network/include
CFLAGS += -I$(BASE_DIR)/storage/include

$(info TARGET_OS = $(TARGET_OS))
ifeq ($(TARGET_OS), linux)
DFLAGS += -DTARGET_OS_LINUX
else ifeq ($(TARGET_OS), freertos)
DFLAGS += -DTARGET_OS_FREERTOS
else ifeq ($(TARGET_OS), mbedos)
DFLAGS += -DTARGET_OS_MBEDOS
else ifeq ($(TARGET_OS), optee)
DFLAGS += -DTARGET_OS_OPTEE
endif

ifeq ($(STORAGE), false)
DFLAGS += -DNO_PERSISTENT_STORAGE
endif

ifeq ($(RETRY), false)
DFLAGS += -DRETRY_FALSE
endif

CFLAGS +=-I$(SAFESTRING_ROOT)/include

### CSTD validation
$(info CSTD = $(CSTD))
ifeq ($(filter $(CSTD),$(SUPPORTED_CSTD)),)
$(error Supported values for CSTD are: $(SUPPORTED_CSTD))
endif

### HTTPPROXY validation
$(info HTTPPROXY = $(HTTPPROXY))
ifeq ($(filter $(HTTPPROXY),$(SUPPORTED_HTTPPROXY)),)
$(error Supported values for HTTPPROXY are: $(SUPPORTED_HTTPPROXY))
endif
### PROXY_DISCOVERY validation
$(info PROXY_DISCOVERY = $(PROXY_DISCOVERY))
ifeq ($(filter $(PROXY_DISCOVERY),$(SUPPORTED_PROXY_DISCOVERY)),)
$(error Supported values for HTTPPROXY are: $(PROXY_DISCOVERY))
endif

### MODULES validation
$(info MODULES = $(MODULES))
ifeq ($(filter $(MODULES),$(SUPPORTED_MODULES)),)
$(error Supported values for MODULES are: $(SUPPORTED_MODULES))
endif
CFLAGS += $(DFLAGS)
