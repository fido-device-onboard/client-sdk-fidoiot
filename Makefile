#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

# Following make rules are specific to sdo code being built with
# optee_examples. The intent is to clone the sdo inside optee_examples
# and it will be built and placed in filesystem of the target platform
-include $(TA_DEV_KIT_DIR)/mk/conf.mk
ifeq "$(CFG_ARM64_ta_arm64)" "y"
export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

.PHONY: all
all:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" #--no-builtin-variables
	$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" #LDFLAGS=""

.PHONY: clean
clean:
	$(MAKE) -C host clean
	$(MAKE) -C ta clean
else
BASE_DIR := .
ifeq ($(PRJ_DIR),)
	PRJ_DIR := .
endif

export PRJ_DIR
export CRYPTO_CFLAGS
include $(BASE_DIR)/base.mk
O = build/$(TARGET_OS)/$(BUILD)/$(BOARD)
ifeq "$(TARGET_OS)" "linux"
    export OBJ_DIR_TLS = $(O)/crypto
    export OBJ_DIR_OS = $(O)/network
    export OBJ_DIR_STORAGE = $(O)/storage/linux
    export OBJ_DIR_STORAGE_COMMON = $(O)/storage/
    export OBJ_DIR_MODULES =  $(O)/modules/
endif
ifeq ($(CRYPTO_HW), true)
    export OBJ_DIR_SE = $(O)/crypto/se
endif

include $(BASE_DIR)/crypto/build.mk
CFLAGS += $(CRYPTO_CFLAGS)
CFLAGS += -I$(BASE_DIR)/crypto/epid/include
CFLAGS += -I$(BASE_DIR)/crypto/include -I$(BASE_DIR)/crypto/ecdsa/

# Enable restrictive C-flags
CFLAGS += -Wswitch-default -Wunused-parameter -Wsign-compare #-Wdeclaration-after-statement
CFLAGS += -Wpedantic -Werror -Wimplicit-function-declaration -Wnested-externs -Wmissing-prototypes
CFLAGS += -Wmissing-declarations -Wdiscarded-qualifiers -Wundef -Wincompatible-pointer-types
CFLAGS += -Wunused-function -Wunused-variable -Wstrict-prototypes -Wshadow

# Exceptions for now
CFLAGS += -Wno-declaration-after-statement

# Include storage into the build
include $(BASE_DIR)/storage/build.mk
CFLAGS += -I$(BASE_DIR)/storage/include

ifeq "$(CFG_ARM64_ta_arm64)" "y"
export V?=0

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

ifneq "$(OPTEE_ROOT)" ""
export EPID_SDK_R6_ROOT = $(OPTEE_ROOT)/epid-sdk-optee
export SAFESTRING_ROOT = $(OPTEE_ROOT)/safestring-optee

OPTEE_COMPILER_PATH = $(OPTEE_ROOT)/toolchains/aarch64/bin
OPTEE_COMPILER = $(OPTEE_COMPILER_PATH)/aarch64-linux-gnu-

HOST_CROSS_COMPILE=$(OPTEE_COMPILER_PATH)/aarch64-linux-gnu-
TA_CROSS_COMPILE=$(OPTEE_COMPILER_PATH)/aarch64-linux-gnu-
export TEEC_EXPORT=$(OPTEE_ROOT)/optee_client/out/export
export TA_DEV_KIT_DIR=$(OPTEE_ROOT)/optee_os/out/arm/export-ta_arm64
endif

export RPI_NFS_ROOT ?= /nfs

export HOST_CROSS_COMPILE
export TA_CROSS_COMPILE
export MANUFACTURER_IP
export MANUFACTURER_DN
export TARGET_OS
export HTTPPROXY
export BUILD
export EPID
export TLS

.PHONY: all build flashsd flashnfs

all: build

flashsd: build
	$(BASE_DIR)/flash_rpi.sh ${SD_ROOT} "sd_rootfs" ${BASE_DIR}

flashnfs: build
	${BASE_DIR}/flash_rpi.sh ${RPI_NFS_ROOT} "nfs_rootfs" ${BASE_DIR}

build:
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)"
	$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)"

.PHONY: clean

clean:
	$(MAKE) -C host clean
	$(MAKE) -C ta clean

else # Non OPTEE systems

APPNAME = $(O)/linux-client


ifeq ($(TARGET_OS), mbedos)
export OBJ_DIR_EPID = $(O)/epid
export OBJ_DIR_APP = $(O)/app
export MBEDOS_ROOT = $(BASE_DIR)/mbedos
else
export OBJ_DIR_EPID = $(O)/crypto/epid
export OBJ_DIR_APP = $(O)/app
export LIB_DIR = $(O)/lib/libsdo
export ESP32_ROOT = $(BASE_DIR)/esp32
endif
export MANUFACTURER_IP
export MANUFACTURER_DN
export TARGET_OS
export HTTPPROXY
export BUILD
export EPID
export TLS

UNIT_TESTS_DIR = tests/unit

SRC = main.c blob.c
ifeq ($(CRYPTO_HW), true)
SRC += se_provisioning.c
endif
OBJS = $(addprefix $(OBJ_DIR_APP)/,$(notdir $(SRC:.c=.o)))


.PHONY: all lib app hal help epid os hal clean pristine esp32-unity-clean

ifeq ($(TARGET_OS), mbedos)

.PHONY: mbed-clean flash
all:
	make -C $(MBEDOS_ROOT) all
flash:
	make -C $(MBEDOS_ROOT) flash
mbed-clean:
	make -C $(MBEDOS_ROOT) clean

endif

ifeq ($(TARGET_OS), freertos)
ESP32_UNITY_PATH = $(ESP32_ROOT)/components/tools/unit-test-app
all:
	python utils/partition_esp32.py
	make -C $(ESP32_ROOT)

flash:
	python utils/partition_esp32.py
	make -C $(ESP32_ROOT) flash
	python utils/partition_esp32.py --flash-epid-partition

monitor:
	make -C $(ESP32_ROOT) monitor

esp32-unity-prepare:
	$(shell [ ! -e $(ESP32_ROOT)/components/tools ] && cp -rf ${IDF_PATH}/tools $(ESP32_ROOT)/components/)
	$(shell cp ${ESP32_ROOT}/sdkconfig ${ESP32_UNITY_PATH}/)
	$(shell [ ! -L ${ESP32_UNITY_PATH}/components/sdo ] && [ ! -e ${ESP32_UNITY_PATH}/components/sdo ] && ln -s ../../../sdo ${ESP32_UNITY_PATH}/components/sdo)
	$(shell [ ! -L ${ESP32_UNITY_PATH}/components/epid ] && [ ! -e ${ESP32_UNITY_PATH}/components/epid ] && ln -s ../../../epid ${ESP32_UNITY_PATH}/components/epid)
	# Use test/unit directory for unit tests
	$(shell cp $(BASE_DIR)/tests/unit/*.c $(ESP32_ROOT)/components/sdo/test/)
	$(shell cp $(BASE_DIR)/tests/unit/*.h $(ESP32_ROOT)/components/sdo/test/)
	$(shell sed -i 's/CRITICAL_LEAK_THRESHOLD \= 4096\;/CRITICAL_LEAK_THRESHOLD \= 12288\;/g' $(ESP32_ROOT)/components/tools/unit-test-app/components/unity/unity_platform.c)


esp32-unity: esp32-unity-prepare
	python utils/partition_esp32.py --unity
	cp $(ESP32_ROOT)/partitions.csv ${ESP32_UNITY_PATH}
	make -C $(ESP32_UNITY_PATH) EXTRA_COMPONENT_DIRS=$(ESP32_ROOT)/components/ TEST_COMPONENTS=sdo

esp32-unity-flash:
	python utils/partition_esp32.py --unity
	cp esp32/partitions.csv $(ESP32_UNITY_PATH)/partition_table_unit_test_app.csv
	make -C $(ESP32_UNITY_PATH) flash
	python utils/partition_esp32.py --flash-epid-partition

esp32-unity-clean: clean
	rm $(ESP32_ROOT)/components/sdo/test/*.c
	rm $(ESP32_ROOT)/components/sdo/test/*.h
	$(shell [ -L ${ESP32_UNITY_PATH}/components/sdo/test ] && rm $(ESP32_ROOT)/components/sdo/test/component.mk)
	$(shell [ -L ${ESP32_UNITY_PATH}/components/sdo/test ] && unlink $(ESP32_ROOT)/components/sdo/test)
	$(shell mv $(ESP32_ROOT)/components/sdo/test_old $(ESP32_ROOT)/components/sdo/test)

esp32-unity-monitor:
	make -C $(ESP32_UNITY_PATH) monitor

gen_epid_blob:
	$(shell ./gen_epid_blob.sh $(PWD) > /dev/null)

unit-test: gen_epid_blob esp32-unity esp32-unity-flash esp32-unity-monitor esp32-unity-clean

endif
#end of freertos

ifeq ($(TARGET_OS), linux)

LDFLAGS += -L$(LIB_DIR)
LDFLAGS += -z noexecstack -z relro -z now
LDLIBS += -Wl,--whole-archive -lsdo

ifneq ($(OPENSSL_BIN_ROOT),)
LDFLAGS += -L$(OPENSSL_BIN_ROOT)/lib
endif

#Include Safe String library
LDFLAGS +=-L$(SAFESTRING_ROOT)/
LDLIBS +=-l:libsafestring.a

ifeq ($(PROXY_DISCOVERY), true)
LDLIBS += -lproxy
endif

ifeq ($(MODULES), true)
#Include Module libraries
SERVICE_INFO_DEVICE_MODULE_ROOT = device_modules
LDFLAGS += -L$(SERVICE_INFO_DEVICE_MODULE_ROOT)/utils
LDLIBS += -l:libutil.a
LDFLAGS += -L$(SERVICE_INFO_DEVICE_MODULE_ROOT)/sdo_sys
LDLIBS += -l:libsdo_sys.a
endif

ifeq ($(TLS), openssl)
LDLIBS += -Wl,--no-whole-archive -lssl -lcrypto -ldl
endif

ifeq ($(TLS), mbedtls)
LDLIBS +=-Wl,--no-whole-archive -lmbedcrypto \
	-Wl,--no-whole-archive -lmbedtls -lmbedx509
endif

ifeq ($(CRYPTO_HW), true)
LDFLAGS += -L${CRYPTOAUTHLIB_ROOT}/lib/
LDLIBS += -l:libcryptoauth.so
endif

ifeq ($(TARGET_OS), linux)
ifeq ($(DA),epid)
ifeq ($(EPID), epid_r6)
ifeq ($(ARCH), arm)
LDFLAGS +=-L$(EPID_SDK_R6_ROOT)/_install/epid-sdk/lib/posix-arm
else
LDFLAGS +=-L$(EPID_SDK_R6_ROOT)/_install/epid-sdk/lib/posix-x86_64
endif
LDLIBS +=-l:libmember.a -l:libcommon.a  -l:libippcp.a
endif
endif #ifeq ($(DA),epid)
ifeq ($(DA),$(filter $(DA),tpm20_ecdsa256 tpm20_ecdsa384))
LDLIBS +=-ltss2-esys -ltss2-mu -ltss2-tctildr
endif
endif

all: clean lib app
ifeq ($(V), 1)
	$(CC) -o $(APPNAME) $(OBJS) $(LDFLAGS) $(LDLIBS) $(CFLAGS)
else
	@$(CC) -o $(APPNAME) $(OBJS) $(LDFLAGS) $(LDLIBS) $(CFLAGS)
endif

flash:
	$(info make flash is applicable only for esp32. Please run TARGET_OS=freertos)

monitor:
	$(info make monitor is applicable only for esp32. Please run TARGET_OS=freertos)
endif
#end of linux

ifeq ($(DA),epid)
lib: obj_mkdir epid os gen_epid_blob hal srvc_mods
else #skip epid build in case DA=ecdsaXXX
lib: obj_mkdir os gen_epid_blob hal srvc_mods
endif
	$(MAKE) -C $(BASE_DIR)/lib -f lib.mk O=$(O) $(PARAM_LST)

srvc_mods:
ifeq ($(MODULES),true)
	$(MAKE) -C $(SERVICE_INFO_DEVICE_MODULE_ROOT) O=$(O) $(PARAM_LST)
else
	$(info  service modules not used)
endif

epid:
	$(MAKE) -C $(BASE_DIR)/crypto/epid -f epid.mk O=$(O) $(PARAM_LST)

os:
	$(MAKE) -C $(BASE_DIR)/network -f network.mk O=$(O) $(PARAM_LST)

gen_epid_blob:
	$(BASE_DIR)/gen_epid_blob.sh ./

obj_mkdir:
	mkdir -p $(O)/crypto/common/
	mkdir -p $(O)/crypto/$(TLS)
ifeq ($(CRYPTO_HW), true)
	mkdir -p $(O)/crypto/se
endif
ifeq ($(DA),$(filter $(DA),ecdsa256 ecdsa384 tpm20_ecdsa256 tpm20_ecdsa384))
	mkdir -p $(O)/crypto/ecdsa/
endif
	mkdir -p $(O)/storage/$(TARGET_OS)


lib-obj-y += $(srcs-y:.c=.o)
$(lib-obj-y): %.o: %.c
	@echo "  CC    $<"
ifeq ($(V), 1)
	$(CC) $(CFLAGS) -c $< -o $(O)/$@
else
	@$(CC) $(CFLAGS) -c $< -o $(O)/$@
endif

hal: $(lib-obj-y)

app:
	$(MAKE) -C $(BASE_DIR)/app -f app.mk O=$(O) $(PARAM_LST)

clean:
	rm -rf $(BASE_DIR)/$(O)
	echo -n > ./data/platform_iv.bin
	echo -n > ./data/platform_hmac_key.bin
	echo -n > ./data/platform_aes_key.bin
	echo -n > ./data/Mfg.blob
	echo '{"ST":1}' > ./data/Normal.blob
	echo -n > ./data/Secure.blob
	echo -n > ./data/raw.blob
ifeq ($(MODULES),true)
	$(MAKE) -C $(SERVICE_INFO_DEVICE_MODULE_ROOT) clean
endif

pristine: clean local-pristine

local-pristine:
	rm -rf $(BASE_DIR)/build

ifeq ($(TARGET_OS), freertos)
	make -C $(ESP32_ROOT) clean
endif
ifeq ($(TARGET_OS), mbedos)
	make -C $(MBEDOS_ROOT) clean
endif
ifeq ($(TARGET_OS), linux)
unit-test: clean
	$(MAKE) -C $(UNIT_TESTS_DIR) $(PARAM_LST)
endif

functional-test:

help: local-help

local-help:
	$(info )
	$(info ===================== SDO c-code-sdk HELP =====================)
	$(info List of build modes:)
	$(info BUILD=debug           # Debug mode (default))
	$(info BUILD=release         # Release mode)
	$(info )
	$(info List of supported TARGET_OS:)
	$(info TARGET_OS=linux       # (Default))
	$(info TARGET_OS=mbedos      # (Mbed OS v5.9.14))
	$(info )
	$(info List of supported boards (valid only when TARGET_OS=mbedos):)
	$(info BOARD=NUCLEO_F767ZI   # (When building for STM32F767ZI MCU))
	$(info BOARD=NUCLEO_F429ZI   # (When building for STM32F429ZI MCU))
	$(info )
	$(info List of key exchange options:)
	$(info KEX=dh                # use Diffie-Hellman key exchange mechanism during TO2)
	$(info KEX=asym              # use Asymmetric key exchange mechanism during TO2)
	$(info KEX=ecdh              # use Elliptic-curve Diffie–Hellman key exchange mechanism during TO2 (default))
	$(info KEX=ecdh384           # use Elliptic-curve Diffie–Hellman 384 bit key exchange mechanism during TO2)
	$(info )
	$(info List of AES encryption modes:)
	$(info AES_MODE=ctr          # use Counter mode encryption during TO2 (default))
	$(info AES_MODE=cbc          # use Code-Block-Chaining mode encryption during TO2)
	$(info )
	$(info List of Device Attestation options:)
	$(info DA=ecdsa256           # Use ECDSA P256 based device attestation(default))
	$(info DA=epid               # Use EPID based device attestation)
	$(info DA=ecdsa384           # Use ECDSA-P384 based device attestation)
	$(info DA=tpm20_ecdsa256     # Use ECDSA-P256 based device attestation with TPM2.0 support)
	$(info MANUFACTURER_TOOLKIT=true # Use ECDSA with supply chain tool)
	$(info DA_FILE=pem           # only Use if ECDSA private keys are PEM encoded)
	$(info )
	$(info List of Public Key encoding/owner-attestation options:)
	$(info PK_ENC=rsa            # Use RSAMODEXP-RSA2048RESTR public key encoding)
	$(info PK_ENC=ecdsa          # Use ECDSA-X.509 based public key encoding (default))
	$(info )
	$(info Underlying crypto library to be used:)
	$(info TLS=openssl           # (Linux default, not supported for other TARGET_OS))
	$(info TLS=mbedtls           # (Mbed OS default, not supported for other TARGET_OS))
	$(info CRYPTO_HW=true        # Use Secure element for some of the crypto operations)
	$(info )
	$(info Option to enable network-proxy:)
	$(info HTTPPROXY=true        # http-proxy enabled (default))
	$(info HTTPPROXY=false       # http-proxy disabled)
	$(info PROXY_DISCOVERY=true  # network discovery enabled)
	$(info )
	$(info Option to enable SDO service-info functionality:)
	$(info MODULES=false         # Service info modules are not present (default))
	$(info MODULES=true          # Service info modules are present)
	$(info )
	$(info Option to enable/disable Device credential resue and resale feature:)
	$(info REUSE=true            # Reuse feature enabled (default))
	$(info REUSE=false           # Reuse feature disabled)
	$(info RESALE=false          # Resale feature disabled (default))
	$(info RESALE=true           # Resale feature enabled)
	$(info )
	$(info List of options to clean targets(use with respective TARGET_OS and BOARD flags):)
	$(info pristine              # make clean, remove generated files, remove labs)
	$(info clean                 # Clean application and all libraries)
	$(info )
	$(info Supported values for C standerd are: C90 and C99)
	$(info )
	$(info ===================== SDO c-code-sdk HELP =====================)
endif
endif
