#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


# This File provides various functions that can be used with client-sdk build system.
# Also this provides compile definitions for various CLI options.


add_library(client_sdk_interface INTERFACE)
if(${TARGET_OS} MATCHES linux)
  add_library(client_sdk STATIC "")
endif()


#############################################################
#functions for ease of use

function(client_sdk_sources)
  foreach(arg ${ARGV})
    if(IS_ABSOLUTE ${arg})
      set(path ${arg})
    else()
      set(path ${CMAKE_CURRENT_SOURCE_DIR}/${arg})
    endif()

    if(IS_DIRECTORY ${path})
      message(FATAL_ERROR "client_sdk_sources() was called on a directory")
    endif()

    target_sources(client_sdk PRIVATE ${path})
  endforeach()
endfunction()

function(client_sdk_include_directories)
  foreach(arg ${ARGV})
    if(IS_ABSOLUTE ${arg})
      set(path ${arg})
    else()
      set(path ${CMAKE_CURRENT_SOURCE_DIR}/${arg})
    endif()
    target_include_directories(client_sdk_interface INTERFACE ${path})
  endforeach()
endfunction()


function(client_sdk_compile_definitions)
  target_compile_definitions(client_sdk_interface INTERFACE ${ARGV})
endfunction()


function(client_sdk_compile_options)
  target_compile_options(client_sdk_interface INTERFACE ${ARGV})
endfunction()


function(client_sdk_link_libraries)
  target_link_libraries(client_sdk_interface INTERFACE ${ARGV})
endfunction()


function(client_sdk_cc_option)
  foreach(arg ${ARGV})
    target_cc_option(client_sdk_interface INTERFACE ${arg})
  endforeach()
endfunction()


function(client_sdk_ld_options)
  foreach(arg ${ARGV})
    target_link_libraries(client_sdk_interface INTERFACE ${arg})
  endforeach()
endfunction()


function(client_sdk_sources_if setting value)
  if(${${setting}} MATCHES ${value})
    client_sdk_sources(${ARGN})
  endif()
endfunction()

function(client_sdk_get_include_directories i)
  get_property(flags TARGET client_sdk_interface PROPERTY INTERFACE_INCLUDE_DIRECTORIES)

  set(prefix "")
  foreach(x ${flags})
    list(APPEND temp_list ${prefix}${x})
  endforeach()

  set(${i} ${temp_list} PARENT_SCOPE)
endfunction()

function(client_sdk_get_compile_definitions i prefix)
  get_property(flags TARGET client_sdk_interface PROPERTY INTERFACE_COMPILE_DEFINITIONS)

  # set(prefix "-D")
  foreach(x ${flags})
    list(APPEND temp_list ${prefix}${x})
  endforeach()

  set(${i} ${temp_list} PARENT_SCOPE)
endfunction()

function(client_sdk_get_compile_options i)
  get_property(flags TARGET client_sdk_interface PROPERTY INTERFACE_COMPILE_OPTIONS)

  set(prefix "")
  foreach(x ${flags})
    list(APPEND temp_list ${prefix}${x})
  endforeach()

  set(${i} ${temp_list} PARENT_SCOPE)
endfunction()

# first agrument needs to be the lib name then the rest should be the
# paths to the files.
function(client_sdk_sources_with_lib lib)
  foreach(arg ${ARGN})
    if(IS_ABSOLUTE ${arg})
      set(path ${arg})
    else()
      set(path ${CMAKE_CURRENT_SOURCE_DIR}/${arg})
    endif()

    if(IS_DIRECTORY ${path})
      message(FATAL_ERROR "client_sdk_sources() was called on a directory")
    endif()

    target_sources(${lib} PRIVATE ${path})
  endforeach()
endfunction()

############################################################
# macros needed from compile based on CLI.
if(TARGET_OS MATCHES linux)
  client_sdk_compile_definitions(
    -DTARGET_OS_LINUX)
elseif (${TARGET_OS} STREQUAL mbedos)
  client_sdk_compile_definitions(
    -DTARGET_OS_MBEDOS)
  set(TLS mbedtls)
endif()

if(DA STREQUAL ecdsa256)
  client_sdk_compile_definitions(-DECDSA256_DA)
elseif(DA STREQUAL ecdsa384)
  client_sdk_compile_definitions(-DECDSA384_DA)
elseif(DA STREQUAL tpm20_ecdsa256)
  client_sdk_compile_definitions(-DECDSA256_DA)
  if(${TPM2_TCTI_TYPE} MATCHES tpmrm0)
    client_sdk_compile_definitions(-DTPM2_TCTI_TYPE=\"device:/dev/tpmrm0\")
  elseif(${TPM2_TCTI_TYPE} MATCHES tabrmd)
    client_sdk_compile_definitions(-DTPM2_TCTI_TYPE=\"tabrmd\")
  else()
    message(WARNING "Incorrect TPM2_TCTI_TYPE selected. Supported values are 'tabrmd' and 'tpmrm0'. \
    Defaulting to 'tabrmd'")
    set (TPM2_TCTI_TYPE tabrmd)
    client_sdk_compile_definitions(-DTPM2_TCTI_TYPE=\"tabrmd\")
  endif()
else()
  message(WARNING "Incorrect DA selected. Supported values are 'ecdsa256', 'ecdsa384' and 'tpm20_ecdsa256'. \
  Defaulting to 'ecdsa384'")
  set (DA ecdsa384)
  client_sdk_compile_definitions(-DECDSA384_DA)
endif()

if(TLS MATCHES openssl)
  client_sdk_compile_definitions(
    -DUSE_OPENSSL)
  if (DEFINED ENV{OPENSSL_BIN_ROOT})
    client_sdk_ld_options(-L$ENV{OPENSSL_BIN_ROOT}/lib)
    client_sdk_compile_options(-I$ENV{OPENSSL_BIN_ROOT}/include)
  endif()
elseif(TLS MATCHES mbedtls)
  client_sdk_compile_definitions(
    -DUSE_MBEDTLS)
endif()

if(${AES_MODE} STREQUAL gcm)
  client_sdk_compile_definitions(
    -DAES_MODE_GCM_ENABLED)
elseif(${AES_MODE} STREQUAL ccm)
  client_sdk_compile_definitions(
    -DAES_MODE_CCM_ENABLED)
else()
  message(WARNING "Incorrect AES_MODE selected. Supported values are: 'gcm' and 'ccm'. \
  Defaulting to 'gcm'")
  set (AES_MODE gcm)
  client_sdk_compile_definitions(
    -DAES_MODE_GCM_ENABLED)
endif()


if(${CRYPTO_HW} MATCHES true)
  client_sdk_compile_options(
    -I$ENV{CRYPTOAUTHLIB_ROOT}/lib/basic -I$ENV{CRYPTOAUTHLIB_ROOT}/lib
    )
  client_sdk_compile_definitions(-DSECURE_ELEMENT)
endif()

if (${BUILD} STREQUAL debug)
  client_sdk_compile_definitions(-DDEBUG_LOGS)
  if (${TARGET_OS} STREQUAL linux)
    if (${unit-test} STREQUAL true)
      client_sdk_compile_definitions(-DLOG_LEVEL=-1)
      client_sdk_compile_options (-O0 -g)
    else()
      client_sdk_compile_definitions(-DDEBUG -DLOG_LEVEL=3)
      client_sdk_compile_options (-O${OPTIMIZE} -g)
    endif()
  else()
    client_sdk_compile_definitions(-DLOG_LEVEL=3)
  endif()
elseif (${BUILD} STREQUAL release)
  client_sdk_compile_options(-Os -fomit-frame-pointer -s -Wl,-strip-debug)
  if (${unit-test} STREQUAL true)
    client_sdk_compile_definitions(-DLOG_LEVEL=-1)
  else()
    client_sdk_compile_definitions(-DLOG_LEVEL=1)
  endif()
else()
  message(WARNING "Supported BUILD values are 'release' and 'debug'")
endif()

if (${RETRY} MATCHES false)
  client_sdk_compile_definitions(-DRETRY_FALSE)
endif()

if(${HTTPPROXY} STREQUAL true)
  client_sdk_compile_definitions(-DHTTPPROXY)
  if(${PROXY_DISCOVERY} STREQUAL true)
    client_sdk_compile_definitions(-DPROXY_DISCOVERY)
  endif()
endif()

if(${SELF_SIGNED_CERTS} STREQUAL true)
  client_sdk_compile_definitions(-DSELF_SIGNED_CERTS_SUPPORTED)
endif()

if(${RESALE} STREQUAL true)
  client_sdk_compile_definitions(-DRESALE_SUPPORTED)
endif()

if(${REUSE} STREQUAL true)
  client_sdk_compile_definitions(-DREUSE_SUPPORTED)
endif()

############################################################
