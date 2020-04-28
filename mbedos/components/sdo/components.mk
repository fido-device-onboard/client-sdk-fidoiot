#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

BASE_DIR := .

include ./connection_settings.mk
include ../../base.mk
include ../../../crypto/conf.mk

    $(shell ln -sfn $(SAFESTRING_ROOT) $(BASE_DIR)/safestring)
    $(shell ln -sfn ../../../lib lib)
    $(shell ln -sfn ../../../network network)
    $(shell ln -sfn ../../../crypto crypto)
    $(shell ln -sfn ../../../storage storage)
    $(shell ln -sfn ../../../../app/main.c sdo/app_main.c)
    $(shell ln -sfn ../../../../app/blob.c sdo/blob.c)
    $(shell ln -sfn ../../../../app/include/blob.h sdo/blob.h)
    $(shell ln -sfn ../../../include include)
    $(shell ln -sfn ../../../data data)
ifeq ($(MODULES), true)
    $(shell ln -sfn $(SDO_SYS_ROOT) $(BASE_DIR)/sdo_sys)
    $(shell ln -sfn $(DEVCONFIG_ROOT) $(BASE_DIR)/devconfig)
    $(shell ln -sfn $(KEYPAIR_ROOT) $(BASE_DIR)/keypair)
    $(shell ln -sfn $(UTILS_ROOT) $(BASE_DIR)/utils)
endif

DATASTORE ?= sd
CFLAGS += -Wno-error=format -Wno-error=maybe-uninitialized
DFLAGS += -DSTDC_HEADERS $(CRYPTO_CFLAGS)

ifeq ($(HTTPPROXY), true)
DFLAGS += -DMBEDOS_ADAPTATION
endif

ifeq ($(STORAGE), false)
DFLAGS += -DNO_PERSISTENT_STORAGE
endif

# Manufacturer toolkit
ifeq ($(MANUFACTURER_TOOLKIT), true)
DFLAGS += -DMANUFACTURER_TOOLKIT
endif

ifneq ($(DA), epid)
EPID_IGNORE ='*\n'
else
EPID_IGNORE =''
endif

#DATASTORE Macro used to define blob store location
ifeq ($(DATASTORE), sd)
DFLAGS += -DMBEDOS_SD_DATA
MBEDOS_STORAGE_IGNORE_LIST +='storage_if_mbedFlash.cpp\n'
else
MBEDOS_STORAGE_IGNORE_LIST +='storage_if_mbedSD.cpp\n'
endif

ifeq ($(KEX), dh)
MBEDTLS_IGNORE_LST +='mbedtls_key_exchange_ecdh.c\n'
COMMON_IGNORE_LST +='sdokeyexchange_asym.c\n'
endif
ifeq ($(KEX),$(filter $(KEX), ecdh ecdh384))
MBEDTLS_IGNORE_LST +='mbedtls_key_exchange_dh.c\n'
MBEDTLS_IGNORE_LST +='mbedtls_RSARoutines.c\n'
COMMON_IGNORE_LST +='sdokeyexchange_asym.c\n'
endif

ifeq ($(KEX), asym)
MBEDTLS_IGNORE_LST +='mbedtls_key_exchange_dh.c\n'
MBEDTLS_IGNORE_LST +='mbedtls_ECDSARoutines.c\n'
MBEDTLS_IGNORE_LST +='mbedtls_key_exchange_ecdh.c\n'
endif

ifeq ($(PK_ENC), rsa)
MBEDTLS_IGNORE_LST +='mbedtls_ECDSAVerifyRoutines.c\n'
endif
ifeq ($(PK_ENC), ecdsa)
MBEDTLS_IGNORE_LST +='mbedtls_RSAVerifyRoutines.c\n'
endif

ifeq ($(CRYPTO_HW), false)
MBEDTLS_IGNORE_LST +='mbedtls_DERRoutines.c\n'
endif

ifeq ($(DA),epid)
MBEDTLS_IGNORE_LST +='mbedtls_ECDSASignRoutines.c\n'
endif

CFLAGS += $(DFLAGS)
#include epid_sign_verify_setting.mk
include proxy_settings.mk
