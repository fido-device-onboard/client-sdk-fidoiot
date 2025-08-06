#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


############################################################
# cmake given defaults
set (TARGET_OS linux)
set (CSTD c99)
set (TLS openssl)
set (DA ecdsa384)
set (AES_MODE gcm)
set (BUILD release)
set (TARGET_OS linux)
set (HTTPPROXY true)
set (PROXY_DISCOVERY false)
set (SELF_SIGNED_CERTS true)
set (SNI true)
set (OPTIMIZE 1)
set (DA_FILE der)
set (CRYPTO_HW false)
set (ARCH x86)
set (RETRY true)
set (unit-test false)
set (STORAGE true)
set (BOARD NUCLEO_F767ZI)
set (BLOB_PATH .)
set (TPM2_TCTI_TYPE tabrmd)
set (RESALE true)
set (REUSE true)
set (MTLS false)
set (CA false)
set (GET_DEV_SERIAL false)
set (LOCK_TPM true)

#Mfg toolkit specific
set (BUILD_MFG_TOOLKIT false)

#for CSE
set (CSE_SHUTDOWN true)
set (CSE_CLEAR false)

#following are specific to only mbedos
set (DATASTORE sd)
set (WIFI_SSID " ")
set (WIFI_PASS " ")
# TO-DO : This flag is no longer being used in the source.
# Explore use of the alternative MANUFACTURER_ADDR instead.
set (MANUFACTURER_IP " ")
set (MANUFACTURER_DN " ")

# Following piece of code is needed to configure the FDO
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

if(DEFINED CACHED_HTTPPROXY)
  if ((DEFINED httpproxy_cli_arg) AND (NOT(CACHED_HTTPPROXY STREQUAL httpproxy_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(HTTPPROXY ${CACHED_HTTPPROXY})
elseif(DEFINED httpproxy_cli_arg)
  set(HTTPPROXY ${httpproxy_cli_arg})
elseif(DEFINED httpproxy_app_cmake_lists)
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

if(DEFINED CACHED_PROXY_DISCOVERY)
  if ((DEFINED proxy_discovery_cli_arg) AND (NOT(CACHED_PROXY_DISCOVERY STREQUAL proxy_discovery_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(PROXY_DISCOVERY ${CACHED_PROXY_DISCOVERY})
elseif(DEFINED proxy_discovery_cli_arg)
  set(PROXY_DISCOVERY ${proxy_discovery_cli_arg})
elseif(DEFINED proxy_discovery_app_cmake_lists)
  set(PROXY_DISCOVERY ${proxy_discovery_app_cmake_lists})
endif()

set(CACHED_PROXY_DISCOVERY ${PROXY_DISCOVERY} CACHE STRING "Selected PROXY_DISCOVERY")
message("Selected PROXY_DISCOVERY ${PROXY_DISCOVERY}")

###########################################
# FOR SELF_SIGNED_CERTS
get_property(cached_self_signed_certs_value CACHE SELF_SIGNED_CERTS PROPERTY VALUE)

set(self_signed_certs_cli_arg ${cached_self_signed_certs_value})
if(self_signed_certs_cli_arg STREQUAL CACHED_SELF_SIGNED_CERTS)
  unset(self_signed_certs_cli_arg)
endif()

set(self_signed_certs_app_cmake_lists ${SELF_SIGNED_CERTS})
if(cached_self_signed_certs_value STREQUAL SELF_SIGNED_CERTS)
  unset(self_signed_certs_app_cmake_lists)
endif()

if(DEFINED CACHED_SELF_SIGNED_CERTS)
  if ((DEFINED self_signed_certs_cli_arg) AND (NOT(CACHED_SELF_SIGNED_CERTS STREQUAL self_signed_certs_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(SELF_SIGNED_CERTS ${CACHED_SELF_SIGNED_CERTS})
elseif(DEFINED self_signed_certs_cli_arg)
  set(SELF_SIGNED_CERTS ${self_signed_certs_cli_arg})
elseif(DEFINED self_signed_certs_app_cmake_lists)
  set(SELF_SIGNED_CERTS ${self_signed_certs_app_cmake_lists})
endif()

set(CACHED_SELF_SIGNED_CERTS ${SELF_SIGNED_CERTS} CACHE STRING "Selected SELF_SIGNED_CERTS")
message("Selected SELF_SIGNED_CERTS ${SELF_SIGNED_CERTS}")

###########################################
# FOR SNI
get_property(cached_server_name_indication_value CACHE SNI PROPERTY VALUE)

set(server_name_indication_cli_arg ${cached_server_name_indication_value})
if(server_name_indication_cli_arg STREQUAL CACHED_SNI)
  unset(server_name_indication_cli_arg)
endif()

set(server_name_indication_app_cmake_lists ${SNI})
if(cached_server_name_indication_value STREQUAL SNI)
  unset(server_name_indication_app_cmake_lists)
endif()

if(DEFINED CACHED_SNI)
  if ((DEFINED server_name_indication_cli_arg) AND (NOT(CACHED_SNI STREQUAL server_name_indication_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(SNI ${CACHED_SNI})
elseif(DEFINED server_name_indication_cli_arg)
  set(SNI ${server_name_indication_cli_arg})
elseif(DEFINED server_name_indication_app_cmake_lists)
  set(SNI ${server_name_indication_app_cmake_lists})
endif()

set(CACHED_SNI ${SNI} CACHE STRING "Selected SNI")
message("Selected SNI ${SNI}")

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

if(DEFINED CACHED_CRYPTO_HW)
  if ((DEFINED crypto_hw_cli_arg) AND (NOT(CACHED_CRYPTO_HW STREQUAL crypto_hw_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(CRYPTO_HW ${CACHED_CRYPTO_HW})
elseif(DEFINED crypto_hw_cli_arg)
  set(CRYPTO_HW ${crypto_hw_cli_arg})
elseif(DEFINED crypto_hw_app_cmake_lists)
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

if(DEFINED CACHED_UNIT-TEST)
  if ((DEFINED unit-test_cli_arg) AND (NOT(CACHED_UNIT-TEST STREQUAL unit-test_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(unit-test ${CACHED_UNIT-TEST})
elseif(DEFINED unit-test_cli_arg)
  set(unit-test ${unit-test_cli_arg})
elseif(DEFINED unit-test_app_cmake_lists)
  set(unit-test ${unit-test_app_cmake_lists})
endif()

set(CACHED_UNIT-TEST ${unit-test} CACHE STRING "Selected unit-test")
if (${unit-test} STREQUAL true)
  message("Selected UNIT-TEST ${unit-test}")
endif()

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

if(DEFINED CACHED_RETRY)
  if ((DEFINED retry_cli_arg) AND (NOT(CACHED_RETRY STREQUAL retry_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(RETRY ${CACHED_RETRY})
elseif(DEFINED retry_cli_arg)
  set(RETRY ${retry_cli_arg})
elseif(DEFINED retry_app_cmake_lists)
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

# FOR RESALE
get_property(cached_resale_value CACHE RESALE PROPERTY VALUE)

set(resale_cli_arg ${cached_resale_value})
if(resale_cli_arg STREQUAL CACHED_RESALE)
  unset(resale_cli_arg)
endif()

set(resale_app_cmake_lists ${RESALE})
if(cached_resale_value STREQUAL RESALE)
  unset(resale_app_cmake_lists)
endif()

if(DEFINED CACHED_RESALE)
  if ((DEFINED resale_cli_arg) AND (NOT(CACHED_RESALE STREQUAL resale_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(RESALE ${CACHED_RESALE})
elseif(DEFINED resale_cli_arg)
  set(RESALE ${resale_cli_arg})
elseif(DEFINED resale_app_cmake_lists)
  set(RESALE ${resale_app_cmake_lists})
endif()

set(CACHED_RESALE ${RESALE} CACHE STRING "Selected RESALE")
message("Selected RESALE ${RESALE}")

###########################################
# FOR REUSE
get_property(cached_reuse_value CACHE REUSE PROPERTY VALUE)

set(reuse_cli_arg ${cached_reuse_value})
if(reuse_cli_arg STREQUAL CACHED_REUSE)
  unset(reuse_cli_arg)
endif()

set(reuse_app_cmake_lists ${REUSE})
if(cached_reuse_value STREQUAL REUSE)
  unset(reuse_app_cmake_lists)
endif()

if(DEFINED CACHED_REUSE)
  if ((DEFINED reuse_cli_arg) AND (NOT(CACHED_REUSE STREQUAL reuse_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(REUSE ${CACHED_REUSE})
elseif(DEFINED reuse_cli_arg)
  set(REUSE ${reuse_cli_arg})
elseif(DEFINED reuse_app_cmake_lists)
  set(REUSE ${reuse_app_cmake_lists})
endif()

set(CACHED_REUSE ${REUSE} CACHE STRING "Selected REUSE")
message("Selected REUSE ${REUSE}")

###########################################
# FOR CSE SHUTDOWN
if (${DA} MATCHES cse)
  get_property(cached_shutdown_value CACHE CSE_SHUTDOWN PROPERTY VALUE)

  set(shutdown_cli_arg ${cached_shutdown_value})
  if(shutdown_cli_arg STREQUAL CACHED_CSE_SHUTDOWN)
    unset(shutdown_cli_arg)
  endif()

  set(shutdown_app_cmake_lists ${CSE_SHUTDOWN})
  if(cached_shutdown_value STREQUAL CSE_SHUTDOWN)
    unset(shutdown_app_cmake_lists)
  endif()

  if(DEFINED CACHED_CSE_SHUTDOWN)
    if ((DEFINED shutdown_cli_arg) AND (NOT(CACHED_CSE_SHUTDOWN STREQUAL shutdown_cli_arg)))
      message(WARNING "Need to do make pristine before cmake args can change.")
    endif()
    set(CSE_SHUTDOWN ${CACHED_CSE_SHUTDOWN})
  elseif(DEFINED shutdown_cli_arg)
    set(CSE_SHUTDOWN ${shutdown_cli_arg})
  elseif(DEFINED shutdown_app_cmake_lists)
    set(CSE_SHUTDOWN ${shutdown_app_cmake_lists})
  endif()

  set(CACHED_CSE_SHUTDOWN ${CSE_SHUTDOWN} CACHE STRING "Selected CSE_SHUTDOWN")
  message("Selected CSE_SHUTDOWN ${CSE_SHUTDOWN}")

  ###########################################
  # FOR CSE CLEAR CRED
  get_property(cached_clear_value CACHE CSE_CLEAR PROPERTY VALUE)

  set(clear_cli_arg ${cached_clear_value})
  if(clear_cli_arg STREQUAL CACHED_CSE_CLEAR)
    unset(clear_cli_arg)
  endif()

  set(clear_app_cmake_lists ${CSE_CLEAR})
  if(cached_clear_value STREQUAL CSE_CLEAR)
    unset(clear_app_cmake_lists)
  endif()

  if(DEFINED CACHED_CSE_CLEAR)
    if ((DEFINED clear_cli_arg) AND (NOT(CACHED_CSE_CLEAR STREQUAL clear_cli_arg)))
      message(WARNING "Need to do make pristine before cmake args can change.")
    endif()
    set(CSE_CLEAR ${CACHED_CSE_CLEAR})
  elseif(DEFINED clear_cli_arg)
    set(CSE_CLEAR ${clear_cli_arg})
  elseif(DEFINED clear_app_cmake_lists)
    set(CSE_CLEAR ${clear_app_cmake_lists})
  endif()

  set(CACHED_CSE_CLEAR ${CSE_CLEAR} CACHE STRING "Selected CSE_CLEAR")
  message("Selected CSE_CLEAR ${CSE_CLEAR}")
endif()
###########################################
# FOR MTLS
get_property(cached_mtls_value CACHE MTLS PROPERTY VALUE)

set(mtls_cli_arg ${cached_mtls_value})
if(mtls_cli_arg STREQUAL CACHED_MTLS)
  unset(mtls_cli_arg)
endif()

set(mtls_app_cmake_lists ${MTLS})
if(cached_mtls_value STREQUAL MTLS)
  unset(mtls_app_cmake_lists)
endif()

if(DEFINED CACHED_MTLS)
  if ((DEFINED mtls_cli_arg) AND (NOT(CACHED_MTLS STREQUAL mtls_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(MTLS ${CACHED_MTLS})
elseif(DEFINED mtls_cli_arg)
  set(MTLS ${mtls_cli_arg})
elseif(DEFINED mtls_app_cmake_lists)
  set(MTLS ${mtls_app_cmake_lists})
endif()

set(CACHED_MTLS ${MTLS} CACHE STRING "Selected MTLS")
message("Selected MTLS ${MTLS}")
###########################################
# FOR CA RETRIEVAL
get_property(cached_CA_value CACHE CA PROPERTY VALUE)

set(CA_cli_arg ${cached_CA_value})
if(CA_cli_arg STREQUAL CACHED_CA)
  unset(CA_cli_arg)
endif()

set(CA_app_cmake_lists ${CA})
if(cached_CA_value STREQUAL CA)
  unset(CA_app_cmake_lists)
endif()

if(DEFINED CACHED_CA)
  if ((DEFINED CA_cli_arg) AND (NOT(CACHED_CA STREQUAL CA_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(CA ${CACHED_CA})
elseif(DEFINED CA_cli_arg)
  set(CA ${CA_cli_arg})
elseif(DEFINED CA_app_cmake_lists)
  set(CA ${CA_app_cmake_lists})
endif()

set(CACHED_CA ${CA} CACHE STRING "Selected CA")
message("Selected CA ${CA}")
###########################################
# FOR GET_DEV_SERIAL
get_property(cached_get_dev_serial_value CACHE GET_DEV_SERIAL PROPERTY VALUE)

set(get_dev_serial_cli_arg ${cached_get_dev_serial_value})
if(get_dev_serial_cli_arg STREQUAL CACHED_GET_DEV_SERIAL)
  unset(get_dev_serial_cli_arg)
endif()

set(get_dev_serial_app_cmake_lists ${GET_DEV_SERIAL})
if(cached_get_dev_serial_value STREQUAL GET_DEV_SERIAL)
  unset(get_dev_serial_app_cmake_lists)
endif()

if(DEFINED CACHED_GET_DEV_SERIAL)
  if ((DEFINED get_dev_serial_cli_arg) AND (NOT(CACHED_GET_DEV_SERIAL STREQUAL get_dev_serial_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(GET_DEV_SERIAL ${CACHED_GET_DEV_SERIAL})
elseif(DEFINED get_dev_serial_cli_arg)
  set(GET_DEV_SERIAL ${get_dev_serial_cli_arg})
elseif(DEFINED get_dev_serial_app_cmake_lists)
  set(GET_DEV_SERIAL ${get_dev_serial_app_cmake_lists})
endif()

set(CACHED_GET_DEV_SERIAL ${GET_DEV_SERIAL} CACHE STRING "Selected GET_DEV_SERIAL")
message("Selected GET_DEV_SERIAL ${GET_DEV_SERIAL}")
###########################################
# FOR LOCK TPM
if (${DA} MATCHES tpm)
  get_property(cached_lock_tpm_value CACHE LOCK_TPM PROPERTY VALUE)

  set(lock_tpm_cli_arg ${cached_lock_tpm_value})
  if(lock_tpm_cli_arg STREQUAL CACHED_LOCK_TPM)
    unset(lock_tpm_cli_arg)
  endif()

  set(lock_tpm_app_cmake_lists ${LOCK_TPM})
  if(cached_lock_tpm_value STREQUAL LOCK_TPM)
    unset(lock_tpm_app_cmake_lists)
  endif()

  if(DEFINED CACHED_LOCK_TPM)
    if ((DEFINED lock_tpm_cli_arg) AND (NOT(CACHED_LOCK_TPM STREQUAL lock_tpm_cli_arg)))
      message(WARNING "Need to do make pristine before cmake args can change.")
    endif()
    set(LOCK_TPM ${CACHED_LOCK_TPM})
  elseif(DEFINED lock_tpm_cli_arg)
    set(LOCK_TPM ${lock_tpm_cli_arg})
  elseif(DEFINED lock_tpm_app_cmake_lists)
    set(LOCK_TPM ${lock_tpm_app_cmake_lists})
  endif()

  set(CACHED_LOCK_TPM ${LOCK_TPM} CACHE STRING "Selected LOCK_TPM")
  message("Selected LOCK_TPM ${LOCK_TPM}")
endif()
###########################################
# FOR BUILD MFG TOOLKIT
get_property(cached_build_mfg_toolkit_value CACHE BUILD_MFG_TOOLKIT PROPERTY VALUE)
set(build_mfg_toolkit_cli_arg ${cached_build_mfg_toolkit_value})
if(build_mfg_toolkit_cli_arg STREQUAL CACHED_BUILD_MFG_TOOLKIT)
  unset(build_mfg_toolkit_cli_arg)
endif()

set(build_mfg_toolkit_app_cmake_lists ${BUILD_MFG_TOOLKIT})
if(cached_build_mfg_toolkit_value STREQUAL BUILD_MFG_TOOLKIT)
  unset(build_mfg_toolkit_app_cmake_lists)
endif()

if(DEFINED CACHED_BUILD_MFG_TOOLKIT)
  if ((DEFINED build_mfg_toolkit_cli_arg) AND (NOT(CACHED_BUILD_MFG_TOOLKIT STREQUAL build_mfg_toolkit_cli_arg)))
    message(WARNING "Need to do make pristine before cmake args can change.")
  endif()
  set(BUILD_MFG_TOOLKIT ${CACHED_BUILD_MFG_TOOLKIT})
elseif(DEFINED build_mfg_toolkit_cli_arg)
  set(BUILD_MFG_TOOLKIT ${build_mfg_toolkit_cli_arg})
elseif(DEFINED build_mfg_toolkit_app_cmake_lists)
  set(BUILD_MFG_TOOLKIT ${build_mfg_toolkit_app_cmake_lists})
endif()

set(CACHED_BUILD_MFG_TOOLKIT ${BUILD_MFG_TOOLKIT} CACHE STRING "Selected BUILD_MFG_TOOLKIT")
message("Selected BUILD_MFG_TOOLKIT ${BUILD_MFG_TOOLKIT}")
