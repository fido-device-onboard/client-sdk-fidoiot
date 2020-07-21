#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


############################################################
# cmake given defaults
set (TARGET_OS linux)
set (CSTD c99)
set (TLS openssl)
set (DA ecdsa256)
set (PK_ENC ecdsa)
set (KEX ecdh)
set (AES_MODE ctr)
set (EPID epid_r6)
set (BUILD debug)
set (TARGET_OS linux)
set (HTTPPROXY true)
set (PROXY_DISCOVERY false)
set (OPTIMIZE 1)
set (MODULES false)
set (DA_FILE der)
set (CRYPTO_HW false)
set (ARCH x86)
set (RETRY true)
set (unit-test false)
set (MANUFACTURER_TOOLKIT false)
set (STORAGE true)
set (BOARD NUCLEO_F767ZI)
set (BLOB_PATH .)
set (TPM2_TCTI_TYPE tabrmd)

#following are specific to only mbedos
set (DATASTORE sd)
set (WIFI_SSID " ")
set (WIFI_PASS " ")
set (MANUFACTURER_IP " ")
set (MANUFACTURER_DN " ")

# Following piece of code is needed to configure the SDO
# Command line inputs are given higher prority than cached/defaults
# note to change the variable values subsequent runs,
# make pristine must be executed to update these values.

###########################################
# FOR TLS
get_property(cached_tls_value CACHE TLS PROPERTY VALUE)

set(tls_cli_arg ${cached_tls_value})
if(tls_cli_arg STREQUAL CACHED_TLS)
  unset(tls_cli_arg)
endif()

set(tls_app_cmake_lists ${TLS})
if(cached_tls_value STREQUAL TLS)
  unset(tls_app_cmake_lists)
endif()

if(CACHED_TLS)
  if ((tls_cli_arg) AND (NOT(CACHED_TLS STREQUAL tls_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(TLS ${CACHED_TLS})
elseif(tls_cli_arg)
  set(TLS ${tls_cli_arg})
elseif(tls_app_cmake_lists)
  set(TLS ${tls_app_cmake_lists})
endif()

set(CACHED_TLS ${TLS} CACHE STRING "Selected TLS")
message("Selected TLS ${TLS}")


###########################################
# FOR DA
get_property(cached_da_value CACHE DA PROPERTY VALUE)

set(da_cli_arg ${cached_da_value})
if(da_cli_arg STREQUAL CACHED_DA)
  unset(da_cli_arg)
endif()

set(da_app_cmake_lists ${DA})
if(cached_da_value STREQUAL DA)
  unset(da_app_cmake_lists)
endif()

if(CACHED_DA)
  if ((da_cli_arg) AND (NOT(CACHED_DA STREQUAL da_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(DA ${CACHED_DA})
elseif(da_cli_arg)
  set(DA ${da_cli_arg})
elseif(da_app_cmake_lists)
  set(DA ${da_app_cmake_lists})
endif()

set(CACHED_DA ${DA} CACHE STRING "Selected DA")
message("Selected DA ${DA}")

###########################################
# FOR PK_ENC
get_property(cached_pk_enc_value CACHE PK_ENC PROPERTY VALUE)

set(pk_enc_cli_arg ${cached_pk_enc_value})
if(pk_enc_cli_arg STREQUAL CACHED_PK_ENC)
  unset(pk_enc_cli_arg)
endif()

set(pk_enc_app_cmake_lists ${PK_ENC})
if(cached_pk_enc_value STREQUAL PK_ENC)
  unset(pk_enc_app_cmake_lists)
endif()

if(CACHED_PK_ENC)
  if ((pk_enc_cli_arg) AND (NOT(CACHED_PK_ENC STREQUAL pk_enc_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(PK_ENC ${CACHED_PK_ENC})
elseif(pk_enc_cli_arg)
  set(PK_ENC ${pk_enc_cli_arg})
elseif(pk_enc_app_cmake_lists)
  set(PK_ENC ${pk_enc_app_cmake_lists})
endif()

set(CACHED_PK_ENC ${PK_ENC} CACHE STRING "Selected PK_ENC")
message("Selected PK_ENC ${PK_ENC}")

###########################################
# FOR KEX
get_property(cached_kex_value CACHE KEX PROPERTY VALUE)

set(kex_cli_arg ${cached_kex_value})
if(kex_cli_arg STREQUAL CACHED_KEX)
  unset(kex_cli_arg)
endif()

set(kex_app_cmake_lists ${KEX})
if(cached_kex_value STREQUAL KEX)
  unset(kex_app_cmake_lists)
endif()

if(CACHED_KEX)
  if ((kex_cli_arg) AND (NOT(CACHED_KEX STREQUAL kex_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(KEX ${CACHED_KEX})
elseif(kex_cli_arg)
  set(KEX ${kex_cli_arg})
elseif(kex_app_cmake_lists)
  set(KEX ${kex_app_cmake_lists})
endif()

set(CACHED_KEX ${KEX} CACHE STRING "Selected KEX")
message("Selected KEX ${KEX}")

###########################################
# FOR AES_MODE
get_property(cached_aes_mode_value CACHE AES_MODE PROPERTY VALUE)

set(aes_mode_cli_arg ${cached_aes_mode_value})
if(aes_mode_cli_arg STREQUAL CACHED_AES_MODE)
  unset(aes_mode_cli_arg)
endif()

set(aes_mode_app_cmake_lists ${AES_MODE})
if(cached_aes_mode_value STREQUAL AES_MODE)
  unset(aes_mode_app_cmake_lists)
endif()

if(CACHED_AES_MODE)
  if ((aes_mode_cli_arg) AND (NOT(CACHED_AES_MODE STREQUAL aes_mode_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(AES_MODE ${CACHED_AES_MODE})
elseif(aes_mode_cli_arg)
  set(AES_MODE ${aes_mode_cli_arg})
elseif(aes_mode_app_cmake_lists)
  set(AES_MODE ${aes_mode_app_cmake_lists})
endif()

set(CACHED_AES_MODE ${AES_MODE} CACHE STRING "Selected AES_MODE")
message("Selected AES_MODE ${AES_MODE}")

###########################################
# FOR TARGET_OS
get_property(cached_target_os_value CACHE TARGET_OS PROPERTY VALUE)

set(target_os_cli_arg ${cached_target_os_value})
if(target_os_cli_arg STREQUAL CACHED_TARGET_OS)
  unset(target_os_cli_arg)
endif()

set(target_os_app_cmake_lists ${TARGET_OS})
if(cached_target_os_value STREQUAL TARGET_OS)
  unset(target_os_app_cmake_lists)
endif()

if(CACHED_TARGET_OS)
  if ((target_os_cli_arg) AND (NOT(CACHED_TARGET_OS STREQUAL target_os_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(TARGET_OS ${CACHED_TARGET_OS})
elseif(target_os_cli_arg)
  set(TARGET_OS ${target_os_cli_arg})
elseif(target_os_app_cmake_lists)
  set(TARGET_OS ${target_os_app_cmake_lists})
endif()

set(CACHED_TARGET_OS ${TARGET_OS} CACHE STRING "Selected TARGET_OS")
message("Selected TARGET_OS ${TARGET_OS}")

###########################################
# FOR HTTPPROXY
get_property(cached_httpproxy_value CACHE HTTPPROXY PROPERTY VALUE)

set(httpproxy_cli_arg ${cached_httpproxy_value})
if(httpproxy_cli_arg STREQUAL CACHED_HTTPPROXY)
  unset(httpproxy_cli_arg)
endif()

set(httpproxy_app_cmake_lists ${HTTPPROXY})
if(cached_httpproxy_value STREQUAL HTTPPROXY)
  unset(httpproxy_app_cmake_lists)
endif()

if(CACHED_HTTPPROXY)
  if ((httpproxy_cli_arg) AND (NOT(CACHED_HTTPPROXY STREQUAL httpproxy_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(HTTPPROXY ${CACHED_HTTPPROXY})
elseif(httpproxy_cli_arg)
  set(HTTPPROXY ${httpproxy_cli_arg})
elseif(httpproxy_app_cmake_lists)
  set(HTTPPROXY ${httpproxy_app_cmake_lists})
endif()

set(CACHED_HTTPPROXY ${HTTPPROXY} CACHE STRING "Selected HTTPPROXY")
message("Selected HTTPPROXY ${HTTPPROXY}")

###########################################
# FOR PROXY_DISCOVERY
get_property(cached_proxy_discovery_value CACHE PROXY_DISCOVERY PROPERTY VALUE)

set(proxy_discovery_cli_arg ${cached_proxy_discovery_value})
if(proxy_discovery_cli_arg STREQUAL CACHED_PROXY_DISCOVERY)
  unset(proxy_discovery_cli_arg)
endif()

set(proxy_discovery_app_cmake_lists ${PROXY_DISCOVERY})
if(cached_proxy_discovery_value STREQUAL PROXY_DISCOVERY)
  unset(proxy_discovery_app_cmake_lists)
endif()

if(CACHED_PROXY_DISCOVERY)
  if ((proxy_discovery_cli_arg) AND (NOT(CACHED_PROXY_DISCOVERY STREQUAL proxy_discovery_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(PROXY_DISCOVERY ${CACHED_PROXY_DISCOVERY})
elseif(proxy_discovery_cli_arg)
  set(PROXY_DISCOVERY ${proxy_discovery_cli_arg})
elseif(proxy_discovery_app_cmake_lists)
  set(PROXY_DISCOVERY ${proxy_discovery_app_cmake_lists})
endif()

set(CACHED_PROXY_DISCOVERY ${PROXY_DISCOVERY} CACHE STRING "Selected PROXY_DISCOVERY")
message("Selected PROXY_DISCOVERY ${PROXY_DISCOVERY}")

###########################################
# FOR MODULES
get_property(cached_modules_value CACHE MODULES PROPERTY VALUE)

set(modules_cli_arg ${cached_modules_value})
if(modules_cli_arg STREQUAL CACHED_MODULES)
  unset(modules_cli_arg)
endif()

set(modules_app_cmake_lists ${MODULES})
if(cached_modules_value STREQUAL MODULES)
  unset(modules_app_cmake_lists)
endif()

if(CACHED_MODULES)
  if ((modules_cli_arg) AND (NOT(CACHED_MODULES STREQUAL modules_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(MODULES ${CACHED_MODULES})
elseif(modules_cli_arg)
  set(MODULES ${modules_cli_arg})
elseif(modules_app_cmake_lists)
  set(MODULES ${modules_app_cmake_lists})
endif()

set(CACHED_MODULES ${MODULES} CACHE STRING "Selected MODULES")
message("Selected MODULES ${MODULES}")


###########################################
# FOR DA_FILE
get_property(cached_da_file_value CACHE DA_FILE PROPERTY VALUE)

set(da_file_cli_arg ${cached_da_file_value})
if(da_file_cli_arg STREQUAL CACHED_DA_FILE)
  unset(da_file_cli_arg)
endif()

set(da_file_app_cmake_lists ${DA_FILE})
if(cached_da_file_value STREQUAL DA_FILE)
  unset(da_file_app_cmake_lists)
endif()

if(CACHED_DA_FILE)
  if ((da_file_cli_arg) AND (NOT(CACHED_DA_FILE STREQUAL da_file_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(DA_FILE ${CACHED_DA_FILE})
elseif(da_file_cli_arg)
  set(DA_FILE ${da_file_cli_arg})
elseif(da_file_app_cmake_lists)
  set(DA_FILE ${da_file_app_cmake_lists})
endif()

set(CACHED_DA_FILE ${DA_FILE} CACHE STRING "Selected DA_FILE")
message("Selected DA_FILE ${DA_FILE}")

###########################################
# FOR CRYPTO_HW
get_property(cached_crypto_hw_value CACHE CRYPTO_HW PROPERTY VALUE)

set(crypto_hw_cli_arg ${cached_crypto_hw_value})
if(crypto_hw_cli_arg STREQUAL CACHED_CRYPTO_HW)
  unset(crypto_hw_cli_arg)
endif()

set(crypto_hw_app_cmake_lists ${CRYPTO_HW})
if(cached_crypto_hw_value STREQUAL CRYPTO_HW)
  unset(crypto_hw_app_cmake_lists)
endif()

if(CACHED_CRYPTO_HW)
  if ((crypto_hw_cli_arg) AND (NOT(CACHED_CRYPTO_HW STREQUAL crypto_hw_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(CRYPTO_HW ${CACHED_CRYPTO_HW})
elseif(crypto_hw_cli_arg)
  set(CRYPTO_HW ${crypto_hw_cli_arg})
elseif(crypto_hw_app_cmake_lists)
  set(CRYPTO_HW ${crypto_hw_app_cmake_lists})
endif()

set(CACHED_CRYPTO_HW ${CRYPTO_HW} CACHE STRING "Selected CRYPTO_HW")
message("Selected CRYPTO_HW ${CRYPTO_HW}")

###########################################
# FOR ARCH
get_property(cached_arch_value CACHE ARCH PROPERTY VALUE)

set(arch_cli_arg ${cached_arch_value})
if(arch_cli_arg STREQUAL CACHED_ARCH)
  unset(arch_cli_arg)
endif()

set(arch_app_cmake_lists ${ARCH})
if(cached_arch_value STREQUAL ARCH)
  unset(arch_app_cmake_lists)
endif()

if(CACHED_ARCH)
  if ((arch_cli_arg) AND (NOT(CACHED_ARCH STREQUAL arch_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(ARCH ${CACHED_ARCH})
elseif(arch_cli_arg)
  set(ARCH ${arch_cli_arg})
elseif(arch_app_cmake_lists)
  set(ARCH ${arch_app_cmake_lists})
endif()

set(CACHED_ARCH ${ARCH} CACHE STRING "Selected ARCH")
message("Selected ARCH ${ARCH}")

###########################################
# FOR UNIT-TEST
get_property(cached_unit-test_value CACHE unit-test PROPERTY VALUE)

set(unit-test_cli_arg ${cached_unit-test_value})
if(unit-test_cli_arg STREQUAL CACHED_UNIT-TEST)
  unset(unit-test_cli_arg)
endif()

set(unit-test_app_cmake_lists ${unit-test})
if(cached_unit-test_value STREQUAL unit-test)
  unset(unit-test_app_cmake_lists)
endif()

if(CACHED_UNIT-TEST)
  if ((unit-test_cli_arg) AND (NOT(CACHED_UNIT-TEST STREQUAL unit-test_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(unit-test ${CACHED_UNIT-TEST})
elseif(unit-test_cli_arg)
  set(unit-test ${unit-test_cli_arg})
elseif(unit-test_app_cmake_lists)
  set(unit-test ${unit-test_app_cmake_lists})
endif()

set(CACHED_UNIT-TEST ${unit-test} CACHE STRING "Selected unit-test")
if (${unit-test} STREQUAL true)  
  message("Selected UNIT-TEST ${unit-test}")
endif()

###########################################
# FOR MANUFACTURER_TOOLKIT
get_property(cached_manufacturer_toolkit_value CACHE MANUFACTURER_TOOLKIT PROPERTY VALUE)

set(manufacturer_toolkit_cli_arg ${cached_manufacturer_toolkit_value})
if(manufacturer_toolkit_cli_arg STREQUAL CACHED_MANUFACTURER_TOOLKIT)
  unset(manufacturer_toolkit_cli_arg)
endif()

set(manufacturer_toolkit_app_cmake_lists ${MANUFACTURER_TOOLKIT})
if(cached_manufacturer_toolkit_value STREQUAL MANUFACTURER_TOOLKIT)
  unset(manufacturer_toolkit_app_cmake_lists)
endif()

if(CACHED_MANUFACTURER_TOOLKIT)
  if ((manufacturer_toolkit_cli_arg) AND (NOT(CACHED_MANUFACTURER_TOOLKIT STREQUAL manufacturer_toolkit_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(MANUFACTURER_TOOLKIT ${CACHED_MANUFACTURER_TOOLKIT})
elseif(manufacturer_toolkit_cli_arg)
  set(MANUFACTURER_TOOLKIT ${manufacturer_toolkit_cli_arg})
elseif(manufacturer_toolkit_app_cmake_lists)
  set(MANUFACTURER_TOOLKIT ${manufacturer_toolkit_app_cmake_lists})
endif()

set(CACHED_MANUFACTURER_TOOLKIT ${MANUFACTURER_TOOLKIT} CACHE STRING
  "Selected MANUFACTURER_TOOLKIT")
message("Selected MANUFACTURER_TOOLKIT ${MANUFACTURER_TOOLKIT}")

###########################################
# FOR BUILD
get_property(cached_build_value CACHE BUILD PROPERTY VALUE)

set(build_cli_arg ${cached_build_value})
if(build_cli_arg STREQUAL CACHED_BUILD)
  unset(build_cli_arg)
endif()

set(build_app_cmake_lists ${BUILD})
if(cached_build_value STREQUAL BUILD)
  unset(build_app_cmake_lists)
endif()

if(CACHED_BUILD)
  if ((build_cli_arg) AND (NOT(CACHED_BUILD STREQUAL build_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(BUILD ${CACHED_BUILD})
elseif(build_cli_arg)
  set(BUILD ${build_cli_arg})
elseif(build_app_cmake_lists)
  set(BUILD ${build_app_cmake_lists})
endif()

set(CACHED_BUILD ${BUILD} CACHE STRING "Selected BUILD")
message("Selected BUILD ${BUILD}")

###########################################
# FOR OPTIMIZE
get_property(cached_optimize_value CACHE OPTIMIZE PROPERTY VALUE)

set(optimize_cli_arg ${cached_optimize_value})
if(optimize_cli_arg STREQUAL CACHED_OPTIMIZE)
  unset(optimize_cli_arg)
endif()

set(optimize_app_cmake_lists ${OPTIMIZE})
if(cached_optimize_value STREQUAL OPTIMIZE)
  unset(optimize_app_cmake_lists)
endif()

if(CACHED_OPTIMIZE)
  if ((optimize_cli_arg) AND (NOT(CACHED_OPTIMIZE STREQUAL optimize_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(OPTIMIZE ${CACHED_OPTIMIZE})
elseif(optimize_cli_arg)
  set(OPTIMIZE ${optimize_cli_arg})
elseif(optimize_app_cmake_lists)
  set(OPTIMIZE ${optimize_app_cmake_lists})
endif()

set(CACHED_OPTIMIZE ${OPTIMIZE} CACHE STRING "Selected OPTIMIZE")
message("Selected OPTIMIZE ${OPTIMIZE}")

###########################################
# FOR RETRY
get_property(cached_retry_value CACHE RETRY PROPERTY VALUE)

set(retry_cli_arg ${cached_retry_value})
if(retry_cli_arg STREQUAL CACHED_RETRY)
  unset(retry_cli_arg)
endif()

set(retry_app_cmake_lists ${RETRY})
if(cached_retry_value STREQUAL RETRY)
  unset(retry_app_cmake_lists)
endif()

if(CACHED_RETRY)
  if ((retry_cli_arg) AND (NOT(CACHED_RETRY STREQUAL retry_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(RETRY ${CACHED_RETRY})
elseif(retry_cli_arg)
  set(RETRY ${retry_cli_arg})
elseif(retry_app_cmake_lists)
  set(RETRY ${retry_app_cmake_lists})
endif()

set(CACHED_RETRY ${RETRY} CACHE STRING "Selected RETRY")
message("Selected RETRY ${RETRY}")


###########################################
# FOR BOARD
get_property(cached_board_value CACHE BOARD PROPERTY VALUE)

set(board_cli_arg ${cached_board_value})
if(board_cli_arg STREQUAL CACHED_BOARD)
  unset(board_cli_arg)
endif()

set(board_app_cmake_lists ${BOARD})
if(cached_board_value STREQUAL BOARD)
  unset(board_app_cmake_lists)
endif()

if(CACHED_BOARD)
  if ((board_cli_arg) AND (NOT(CACHED_BOARD STREQUAL board_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(BOARD ${CACHED_BOARD})
elseif(board_cli_arg)
  set(BOARD ${board_cli_arg})
elseif(board_app_cmake_lists)
  set(BOARD ${board_app_cmake_lists})
endif()

set(CACHED_BOARD ${BOARD} CACHE STRING "Selected BOARD")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected BOARD ${BOARD}")
endif()

###########################################
# FOR DATASTORE
get_property(cached_datastore_value CACHE DATASTORE PROPERTY VALUE)

set(datastore_cli_arg ${cached_datastore_value})
if(datastore_cli_arg STREQUAL CACHED_DATASTORE)
  unset(datastore_cli_arg)
endif()

set(datastore_app_cmake_lists ${DATASTORE})
if(cached_datastore_value STREQUAL DATASTORE)
  unset(datastore_app_cmake_lists)
endif()

if(CACHED_DATASTORE)
  if ((datastore_cli_arg) AND (NOT(CACHED_DATASTORE STREQUAL datastore_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(DATASTORE ${CACHED_DATASTORE})
elseif(datastore_cli_arg)
  set(DATASTORE ${datastore_cli_arg})
elseif(datastore_app_cmake_lists)
  set(DATASTORE ${datastore_app_cmake_lists})
endif()

set(CACHED_DATASTORE ${DATASTORE} CACHE STRING "Selected DATASTORE")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected DATASTORE ${DATASTORE}")
endif()

###########################################
# FOR BLOB_PATH
get_property(cached_blob_path_value CACHE BLOB_PATH PROPERTY VALUE)

set(blob_path_cli_arg ${cached_blob_path_value})
if(blob_path_cli_arg STREQUAL CACHED_BLOB_PATH)
  unset(blob_path_cli_arg)
endif()

set(blob_path_app_cmake_lists ${BLOB_PATH})
if(cached_blob_path_value STREQUAL BLOB_PATH)
  unset(blob_path_app_cmake_lists)
endif()

if(CACHED_BLOB_PATH)
  if ((blob_path_cli_arg) AND (NOT(CACHED_BLOB_PATH STREQUAL blob_path_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(BLOB_PATH ${CACHED_BLOB_PATH})
elseif(blob_path_cli_arg)
  set(BLOB_PATH ${blob_path_cli_arg})
elseif(DEFINED ENV{BLOB_PATH})
  set(BLOB_PATH $ENV{BLOB_PATH})
elseif(blob_path_app_cmake_lists)
  set(BLOB_PATH ${blob_path_app_cmake_lists})
endif()

set(CACHED_BLOB_PATH ${BLOB_PATH} CACHE STRING "Selected BLOB_PATH")
message("Selected BLOB_PATH ${BLOB_PATH}")

###########################################
# FOR WIFI_SSID
get_property(cached_wifi_ssid_value CACHE WIFI_SSID PROPERTY VALUE)

set(wifi_ssid_cli_arg ${cached_wifi_ssid_value})
if(wifi_ssid_cli_arg STREQUAL CACHED_WIFI_SSID)
  unset(wifi_ssid_cli_arg)
endif()

set(wifi_ssid_app_cmake_lists ${WIFI_SSID})
if(cached_wifi_ssid_value STREQUAL WIFI_SSID)
  unset(wifi_ssid_app_cmake_lists)
endif()

if(CACHED_WIFI_SSID)
  if ((wifi_ssid_cli_arg) AND (NOT(CACHED_WIFI_SSID STREQUAL wifi_ssid_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(WIFI_SSID ${CACHED_WIFI_SSID})
elseif(wifi_ssid_cli_arg)
  set(WIFI_SSID ${wifi_ssid_cli_arg})
elseif(wifi_ssid_app_cmake_lists)
  set(WIFI_SSID ${wifi_ssid_app_cmake_lists})
endif()

set(CACHED_WIFI_SSID ${WIFI_SSID} CACHE STRING "Selected WIFI_SSID")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected WIFI_SSID ${WIFI_SSID}")
endif()


###########################################
# FOR WIFI_PASS
get_property(cached_wifi_pass_value CACHE WIFI_PASS PROPERTY VALUE)

set(wifi_pass_cli_arg ${cached_wifi_pass_value})
if(wifi_pass_cli_arg STREQUAL CACHED_WIFI_PASS)
  unset(wifi_pass_cli_arg)
endif()

set(wifi_pass_app_cmake_lists ${WIFI_PASS})
if(cached_wifi_pass_value STREQUAL WIFI_PASS)
  unset(wifi_pass_app_cmake_lists)
endif()

if(CACHED_WIFI_PASS)
  if ((wifi_pass_cli_arg) AND (NOT(CACHED_WIFI_PASS STREQUAL wifi_pass_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(WIFI_PASS ${CACHED_WIFI_PASS})
elseif(wifi_pass_cli_arg)
  set(WIFI_PASS ${wifi_pass_cli_arg})
elseif(wifi_pass_app_cmake_lists)
  set(WIFI_PASS ${wifi_pass_app_cmake_lists})
endif()

set(CACHED_WIFI_PASS ${WIFI_PASS} CACHE STRING "Selected WIFI_PASS")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected WIFI_PASS ${WIFI_PASS}")
endif()

###########################################
# FOR MANUFACTURER_IP
get_property(cached_manufacturer_ip_value CACHE MANUFACTURER_IP PROPERTY VALUE)

set(manufacturer_ip_cli_arg ${cached_manufacturer_ip_value})
if(manufacturer_ip_cli_arg STREQUAL CACHED_MANUFACTURER_IP)
  unset(manufacturer_ip_cli_arg)
endif()

set(manufacturer_ip_app_cmake_lists ${MANUFACTURER_IP})
if(cached_manufacturer_ip_value STREQUAL MANUFACTURER_IP)
  unset(manufacturer_ip_app_cmake_lists)
endif()

if(CACHED_MANUFACTURER_IP)
if ((manufacturer_ip_cli_arg) AND (NOT(CACHED_MANUFACTURER_IP STREQUAL manufacturer_ip_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(MANUFACTURER_IP ${CACHED_MANUFACTURER_IP})
elseif(manufacturer_ip_cli_arg)
  set(MANUFACTURER_IP ${manufacturer_ip_cli_arg})
elseif(manufacturer_ip_app_cmake_lists)
  set(MANUFACTURER_IP ${manufacturer_ip_app_cmake_lists})
endif()

set(CACHED_MANUFACTURER_IP ${MANUFACTURER_IP} CACHE STRING "Selected MANUFACTURER_IP")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected MANUFACTURER_IP ${MANUFACTURER_IP}")
endif()

###########################################
# FOR MANUFACTURER_DN
get_property(cached_manufacturer_dn_value CACHE MANUFACTURER_DN PROPERTY VALUE)

set(manufacturer_dn_cli_arg ${cached_manufacturer_dn_value})
if(manufacturer_dn_cli_arg STREQUAL CACHED_MANUFACTURER_DN)
  unset(manufacturer_dn_cli_arg)
endif()

set(manufacturer_dn_app_cmake_lists ${MANUFACTURER_DN})
if(cached_manufacturer_dn_value STREQUAL MANUFACTURER_DN)
  unset(manufacturer_dn_app_cmake_lists)
endif()

if(CACHED_MANUFACTURER_DN)
  if ((manufacturer_dn_cli_arg) AND (NOT(CACHED_MANUFACTURER_DN STREQUAL manufacturer_dn_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(MANUFACTURER_DN ${CACHED_MANUFACTURER_DN})
elseif(manufacturer_dn_cli_arg)
  set(MANUFACTURER_DN ${manufacturer_dn_cli_arg})
elseif(manufacturer_dn_app_cmake_lists)
  set(MANUFACTURER_DN ${manufacturer_dn_app_cmake_lists})
endif()

set(CACHED_MANUFACTURER_DN ${MANUFACTURER_DN} CACHE STRING "Selected MANUFACTURER_DN")
if(${TARGET_OS} STREQUAL mbedos)
  message("Selected MANUFACTURER_DN ${MANUFACTURER_DN}")
endif()

###########################################
# FOR SPECIFYING TPM RESOURCE MANAGER
get_property(cached_tpm2_tcti_type_value CACHE TPM2_TCTI_TYPE PROPERTY VALUE)

set(tpm2_tcti_type_cli_arg ${cached_tpm2_tcti_type_value})
if(tpm2_tcti_type_cli_arg STREQUAL CACHED_TPM2_TCTI_TYPE)
  unset(tpm2_tcti_type_cli_arg)
endif()

set(tpm2_tcti_type_app_cmake_lists ${TPM2_TCTI_TYPE})
if(cached_tpm2_tcti_type_value STREQUAL TPM2_TCTI_TYPE)
  unset(tpm2_tcti_type_app_cmake_lists)
endif()

if(CACHED_TPM2_TCTI_TYPE)
  if ((tpm2_tcti_type_cli_arg) AND (NOT(CACHED_TPM2_TCTI_TYPE STREQUAL tpm2_tcti_type_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(TPM2_TCTI_TYPE ${CACHED_TPM2_TCTI_TYPE})
elseif(tpm2_tcti_type_cli_arg)
  set(TPM2_TCTI_TYPE ${tpm2_tcti_type_cli_arg})
elseif(tpm2_tcti_type_app_cmake_lists)
  set(TPM2_TCTI_TYPE ${tpm2_tcti_type_app_cmake_lists})
endif()

set(CACHED_TPM2_TCTI_TYPE ${TPM2_TCTI_TYPE} CACHE STRING "Selected TPM2_TCTI_TYPE")
message("Selected TPM2_TCTI_TYPE ${TPM2_TCTI_TYPE}")

###########################################
