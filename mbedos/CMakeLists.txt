#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


set (MBED_OS_DIR ${BASE_DIR}/mbedos/components/sdo)

if (${HTTPPROXY} STREQUAL true)
  list (APPEND MBED_FLAGS -DHTTPPROXY="\"10.223.4.20\"" -DHTTPPROXYPORT=911)
endif()
  
if (NOT(${WIFI_SSID} STREQUAL " " ))
  list (APPEND MBED_FLAGS -DWIFI_SSID=\"${WIFI_SSID}\")
endif()

if (NOT(${WIFI_PASS} STREQUAL " "))
  list (APPEND MBED_FLAGS -DWIFI_PASS=\"${WIFI_PASS}\")
endif()

if (NOT(${MANUFACTURER_IP} STREQUAL " " ))
  list (APPEND MBED_FLAGS -DMANUFACTURER_IP=\"${MANUFACTURER_IP}\")
endif()

if (NOT(${MANUFACTURER_DN}  STREQUAL " " ))
    list (APPEND MBED_FLAGS -DMANUFACTURER_DN=\"${MANUFACTURER_DN}\")
endif()
  
# Create links

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  $ENV{SAFESTRING_ROOT} ${MBED_OS_DIR}/safestring)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/lib ${MBED_OS_DIR}/lib)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/network ${MBED_OS_DIR}/network)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/crypto ${MBED_OS_DIR}/crypto)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/storage ${MBED_OS_DIR}/storage)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/app/main.c ${MBED_OS_DIR}/sdo/app_main.c)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/app/blob.c ${MBED_OS_DIR}/sdo/blob.c)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/app/include/blob.h ${MBED_OS_DIR}/sdo/blob.h)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/include ${MBED_OS_DIR}/include)

execute_process(COMMAND
  ${CMAKE_COMMAND} -E create_symlink
  ${BASE_DIR}/data ${MBED_OS_DIR}/data)

if (${MODULES} STREQUAL true)
  execute_process(COMMAND
    ${CMAKE_COMMAND} -E create_symlink
    ${BASE_DIR}/device_modules/sdo_sys/ ${MBED_OS_DIR}/sdo_sys)
endif()

list (APPEND MBED_FLAGS -DSTDC_HEADERS)


if (${HTTPPROXY} STREQUAL true)
  list (APPEND MBED_FLAGS -DMBEDOS_ADAPTATION)
endif()

if (${STORAGE} STREQUAL false)
  list (APPEND MBED_FLAGS -DNO_PERSISTENT_STORAGE)
endif()

# Manufacturer toolkit
if (${MANUFACTURER_TOOLKIT} STREQUAL true)
  list (APPEND MBED_FLAGS -DMANUFACTURER_TOOLKIT)
endif()



set( SAFESTRING_IGNORE "unittests/*
safestringlib/*
obj/*
Debug/*
objtest/*")

if (${DATASTORE} STREQUAL sd)
  list (APPEND MBED_FLAGS  -DMBEDOS_SD_DATA)
  list (APPEND MBEDOS_STORAGE_IGNORE "storage_if_mbedFlash.cpp\n")
else()
  list (APPEND MBEDOS_STORAGE_IGNORE "storage_if_mbedSD.cpp\n")
endif()

if (${KEX} STREQUAL dh)
  list (APPEND MBEDTLS_IGNORE "mbedtls_key_exchange_ecdh.c\n")
  list (APPEND COMMON_IGNORE "sdokeyexchange_asym.c\n")
endif()

if (${KEX} MATCHES ecdh)
  list (APPEND MBEDTLS_IGNORE "mbedtls_key_exchange_dh.c\n")
  list (APPEND MBEDTLS_IGNORE "mbedtls_RSARoutines.c\n")
  list (APPEND COMMON_IGNORE "sdokeyexchange_asym.c\n")
endif()

if (${KEX} STREQUAL asym)
  list (APPEND MBEDTLS_IGNORE "mbedtls_key_exchange_dh.c\n")
  list (APPEND MBEDTLS_IGNORE "mbedtls_ECDSARoutines.c\n")
  list (APPEND MBEDTLS_IGNORE "mbedtls_key_exchange_ecdh.c\n")
endif()

if (${PK_ENC} STREQUAL rsa)
  list (APPEND MBEDTLS_IGNORE "mbedtls_ECDSAVerifyRoutines.c\n")
endif()
if (${PK_ENC} STREQUAL ecdsa)
  list (APPEND MBEDTLS_IGNORE "mbedtls_RSAVerifyRoutines.c\n")
endif()

if (${CRYPTO_HW} STREQUAL false)
  list (APPEND MBEDTLS_IGNORE "mbedtls_DERRoutines.c\n")
endif()

if (${DA} STREQUAL epid)
  list (APPEND MBEDTLS_IGNORE "mbedtls_ECDSASignRoutines.c\n")
endif()


set( NETWORK_IGNORE "*_esp.c
*_linux.c
*_optee.c
*wifi_init.c\n")

set(LINUX_STORAGE_IGNORE "*_linux.c\n")
set(GP_STORAGE_IGNORE "*_optee.c\n")
set(FREERTOS_STORAGE_IGNORE "*_esp.c\n")

file(WRITE ${MBED_OS_DIR}/safestring/.mbedignore ${SAFESTRING_IGNORE})
file(WRITE ${MBED_OS_DIR}/crypto/mbedtls/.mbedignore ${MBEDTLS_IGNORE})
file(WRITE ${MBED_OS_DIR}/crypto/common/.mbedignore ${COMMON_IGNORE})

file(WRITE ${MBED_OS_DIR}/crypto/openssl/.mbedignore "*.c\n")
file(WRITE ${MBED_OS_DIR}/crypto/gp/.mbedignore "*.c\n")
file(WRITE ${MBED_OS_DIR}/crypto/se/.mbedignore "*.c\n")
file(WRITE ${MBED_OS_DIR}/crypto/epid/.mbedignore "*.c\n")

file(WRITE ${MBED_OS_DIR}/network/.mbedignore ${NETWORK_IGNORE})
file(WRITE ${MBED_OS_DIR}/storage/linux/.mbedignore ${LINUX_STORAGE_IGNORE})
file(WRITE ${MBED_OS_DIR}/storage/gp/.mbedignore ${GP_STORAGE_IGNORE})

file(WRITE ${MBED_OS_DIR}/storage/mbedos/.mbedignore ${MBEDOS_STORAGE_IGNORE})
file(WRITE ${MBED_OS_DIR}/storage/freertos/.mbedignore ${FREERTOS_STORAGE_IGNORE})



if (${MODULES} MATCHES true)
  add_custom_command(
    OUTPUT mbed_json_update
    COMMAND
    ${CMAKE_COMMAND} -E copy
    ${MBED_OS_DIR}/sdo/mbed_app.json_pelion
    ${MBED_OS_DIR}/sdo/mbed_app.json
    )

list (APPEND MBED_FLAGS  --source=sdo_sys --source=simple-mbed-cloud-client -DCLOUD_CLIENT)

else()
  add_custom_command(
    OUTPUT mbed_json_update
    COMMAND
    ${CMAKE_COMMAND} -E copy
    ${MBED_OS_DIR}/sdo/mbed_app.json_sdo_only
    ${MBED_OS_DIR}/sdo/mbed_app.json
    )
endif()


add_custom_command(
  OUTPUT sdo_deploy
  COMMAND
  mbed deploy -v --insecure
  WORKING_DIRECTORY ${MBED_OS_DIR}/
  DEPENDS mbed_json_update
  VERBATIM
  )

client_sdk_get_compile_definitions(c_defines "-D")

 

add_custom_command(
  OUTPUT sdo_bin
  COMMAND
  mbed-cli compile -m ${BOARD} -t GCC_ARM --source=sdo --source=data --source=network --source=crypto --source=storage --source=lib --source=include --source=safestring --source=mbed-os ${MBED_FLAGS} ${c_defines} --build=${BASE_DIR}/build
  WORKING_DIRECTORY ${MBED_OS_DIR}
  DEPENDS sdo_deploy
  VERBATIM
  )

add_custom_target(mbedos_build ALL DEPENDS sdo_bin)

# Set for nv ram
if (NOT(${DATASTORE} STREQUAL sd))
  add_custom_command(OUTPUT epid_key
    COMMAND
    xxd -i data/epidprivkey.dat > data/epidprivkey.dat.h
    )
  add_custom_command(OUTPUT mfg_proxy
    COMMAND
    xxd -i data/mfg_proxy.dat > data/mfg_proxy.dat.h
    )
  if (${DA} STREQUAL ecdsa256)
    if (NOT(${DA_FILE} STREQUAL pem))
      add_custom_command(OUTPUT ecdsa_key
	COMMAND
	${CMAKE_COMMAND} -E copy
	data/ecdsa256privkey.dat data/ecdsaprivkey
	)
    else()
      add_custom_command(OUTPUT ecdsa_key
	COMMAND
	${CMAKE_COMMAND} -E copy      
	data/ecdsa256privkey.pem data/ecdsaprivkey
	)
    endif()
  else()
    if (NOT(${DA_FILE} STREQUAL pem))
      add_custom_command(OUTPUT ecdsa_key
	COMMAND
	${CMAKE_COMMAND} -E copy
	data/ecdsa384privkey.dat data/ecdsaprivkey
	)
    else()
      add_custom_command(OUTPUT ecdsa_key
	COMMAND
	${CMAKE_COMMAND} -E copy
	data/ecdsa384privkey.pem data/ecdsaprivkey
	)
    endif()
  endif()
    add_custom_command(OUTPUT set_data
      COMMAND
      xxd -i data/ecdsaprivkey > data/ecdsaprivkey.h
      xxd -i data/owner_proxy.dat > data/owner_proxy.dat.h
      xxd -i data/rv_proxy.dat > data/rv_proxy.dat.h
      xxd -i data/Normal.blob > data/Normal.blob.h
      xxd -i data/Secure.blob > data/Secure.blob.h
      xxd -i data/Mfg.blob > data/Mfg.blob.h
      xxd -i data/raw.blob > data/raw.blob.h
      )
    add_custom_target(mbedos_nvram ALL DEPENDS set_data ecdsa_key epid_key)
endif()
