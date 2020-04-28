#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.

ECHOTST=$(shell echo "hello\n" | grep "\n")
ifeq (${ECHOTST},)
export ECHOM=echo
else
export ECHOM=echo -e
endif

include ./components.mk
PROJECT_NAME := SDO
#SHELL := /bin/bash


SAFESTRING_IGNORE +='unittests/*\n'
SAFESTRING_IGNORE +='safestringlib/*\n'
SAFESTRING_IGNORE +='obj/*\n'
SAFESTRING_IGNORE +='Debug/*\n'
SAFESTRING_IGNORE +='objtest/*\n'

GP_IGNORE_LST +='*.c\n'
SE_IGNORE_LST +='se_*.c\n'
OS_IGNORE_LST += '*_esp.c\n'
OS_IGNORE_LST  += '*_linux.c\n'
OS_IGNORE_LST += '*_optee.c\n'
OS_IGNORE_LST += '*wifi_init.c\n'
OPENSSL_IGNORE_LST +='*.c\n'

LINUX_STORAGE_IGNORE_LIST += '*_linux.c\n'
GP_STORAGE_IGNORE_LIST += '*_optee.c\n'
FREERTOS_STORAGE_IGNORE_LIST += '*_esp.c\n'

#DFLAGS +=-DLOG_LEVEL=1
ifeq ($(DA),epid)
EPID_DFLAGS := -D_IPP_v50_ -D_IPP_DEBUG -D_DISABLE_ALG_MD5_ -D_DISABLE_ALG_SM3_
endif

.PHONY: all clean flash

all: gen_epid_blob creat_data
ifeq ($(DA),epid)
	make -C epid
endif
	mbed deploy -v --insecure
	$(ECHOM) $(SAFESTRING_IGNORE) > ./safestring/.mbedignore
	$(ECHOM) $(MBEDTLS_IGNORE_LST) > ./crypto/mbedtls/.mbedignore
	$(ECHOM) $(COMMON_IGNORE_LST) > ./crypto/common/.mbedignore
	$(ECHOM) $(OPENSSL_IGNORE_LST) > ./crypto/openssl/.mbedignore
	$(ECHOM) $(SE_IGNORE_LST) > ./crypto/se/.mbedignore
	$(ECHOM) $(OS_IGNORE_LST) > ./network/.mbedignore
	$(ECHOM) $(EPID_IGNORE) > ./crypto/epid/.mbedignore
	$(ECHOM) $(LINUX_STORAGE_IGNORE_LIST) > ./storage/linux/.mbedignore
	$(ECHOM) $(MBEDOS_STORAGE_IGNORE_LIST) > ./storage/mbedos/.mbedignore

ifeq ($(DA),epid)
	#compile the epid sdk
	mbed-cli compile -m $(BOARD) -t GCC_ARM --library --no-archive --source=epid/epid-sdk-v601 --build=../$(OBJ_DIR_EPID) $(EPID_DFLAGS)
endif
ifneq ($(DATASTORE), sd)
ifeq (,$(wildcard ../$(OBJ_DIR_APP)/nverase.bin))
	# compile flash erase code and generate binary
	mbed-cli compile -m $(BOARD) -t GCC_ARM --source=nverase --source=mbed-os $(DFLAGS) --build=../$(OBJ_DIR_APP)
endif
endif

	# compile the sdo
ifeq ($(MODULES), true)
	cp sdo/mbed_app.json_pelion sdo/mbed_app.json
ifneq ($(DA),epid)
	mbed-cli compile -m $(BOARD) -t GCC_ARM  --source=sdo --source=dms-agent/pelion --source=data --source=network --source=crypto --source=storage --source=lib --source=include --source=keypair --source=devconfig --source=utils --source=sdo_sys  --source=safestring --source=mbed-os --source=simple-mbed-cloud-client -DCLOUD_CLIENT $(DFLAGS) --build=../$(OBJ_DIR_APP)
else
	mbed-cli compile -m $(BOARD) -t GCC_ARM  --source=sdo --source=dms-agent/pelion --source=data --source=network --source=crypto --source=storage --source=lib --source=include --source=../$(OBJ_DIR_EPID)  --source=keypair --source=devconfig --source=utils --source=sdo_sys  --source=safestring --source=mbed-os --source=simple-mbed-cloud-client -DCLOUD_CLIENT $(DFLAGS) --build=../$(OBJ_DIR_APP)
endif

else
	cp sdo/mbed_app.json_sdo_only sdo/mbed_app.json
ifneq ($(DA),epid)
	mbed-cli compile -m $(BOARD) -t GCC_ARM --source=sdo --source=data --source=network --source=crypto --source=storage --source=lib --source=include --source=safestring --source=mbed-os $(DFLAGS) --build=../$(OBJ_DIR_APP)
else #ifeq ($(DA),epid)
	mbed-cli compile -m $(BOARD) -t GCC_ARM --source=sdo --source=data --source=network --source=crypto --source=storage --source=lib --source=include --source=../$(OBJ_DIR_EPID) --source=safestring --source=mbed-os $(DFLAGS) --build=../$(OBJ_DIR_APP)
endif
endif

gen_epid_blob:
	echo -n > data/platform_iv.bin
	echo -n > data/platform_hmac_key.bin
	echo -n > data/platform_aes_key.bin
	echo -n > ./data/Mfg.blob
	echo '{"ST":1}' > ./data/Normal.blob
	echo -n > ./data/Secure.blob
	echo -n > ./data/raw.blob
	../../../gen_epid_blob.sh  ../../../

creat_data:
	rm -rf data/*.h
ifneq ($(DATASTORE), sd)
	xxd -i data/epidprivkey.dat > data/epidprivkey.dat.h
	xxd -i data/mfg_proxy.dat > data/mfg_proxy.dat.h
ifeq ($(DA), ecdsa256)
ifneq ($(DA_FILE), pem)
	cp -f data/ecdsa256privkey.dat data/ecdsaprivkey
else
	cp -f data/ecdsa256privkey.pem data/ecdsaprivkey
endif
else
ifneq ($(DA_FILE), pem)
	cp -f data/ecdsa384privkey.dat data/ecdsaprivkey
else
	cp -f data/ecdsa384privkey.pem data/ecdsaprivkey
endif
endif
	xxd -i data/ecdsaprivkey > data/ecdsaprivkey.h
	rm -rf data/ecdsaprivkey
	xxd -i data/owner_proxy.dat > data/owner_proxy.dat.h
	xxd -i data/rv_proxy.dat > data/rv_proxy.dat.h
	xxd -i data/Normal.blob > data/Normal.blob.h
	xxd -i data/Secure.blob > data/Secure.blob.h
	xxd -i data/Mfg.blob > data/Mfg.blob.h
	xxd -i data/raw.blob > data/raw.blob.h
endif

flash: erase_flash
	../../../utils/flash_mbed.sh "../$(OBJ_DIR_APP)/sdo.bin" $(BOARD)

	# used to corrupt previously written flash data
erase_flash:
ifneq ($(DATASTORE), sd)
	../../../utils/flash_mbed.sh "../$(OBJ_DIR_APP)/nverase.bin" $(BOARD)
endif

clean:
	rm -rf data/*.h
	rm -rf data/platform*.bin
	rm -rf data/ecdsaprivkey
	rm -rf ../$(OBJ_DIR_EPID)
	rm -rf ../$(OBJ_DIR_APP)
	rm -rf sdo/mbed_app.json
	rm -rf ./mbed-os
	make -C epid clean
	unlink data
	unlink network
	unlink crypto
	unlink storage
	unlink include
	unlink lib
	unlink safestring
	unlink sdo/app_main.c 
	unlink sdo/blob.c
	unlink sdo/blob.h
