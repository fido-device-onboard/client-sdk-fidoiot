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

if(PK_ENC MATCHES ecdsa)
  client_sdk_compile_definitions(
    -DPK_ENC_ECDSA)
elseif(PK_ENC MATCHES rsa)
  client_sdk_compile_definitions(
    -DPK_ENC_RSA)
else()
  message(WARNING "Supported PK_ENC are ecdsa and rsa'")  
endif()

if(DA MATCHES ecdsa256)
  client_sdk_compile_definitions(
    -DECDSA256_DA)
elseif(DA MATCHES ecdsa384)
    client_sdk_compile_definitions(
      -DECDSA384_DA)
    #Move KEX to higher crypto
    if (NOT(${KEX} STREQUAL ecdh384))
      set(KEX ecdh384)
      message("KEX moved to higher crypto")
    endif()
elseif(DA MATCHES epid)
    client_sdk_compile_definitions(
      -DEPID_DA -DEPID_R6)
    client_sdk_compile_options(-I$ENV{EPID_SDK_R6_ROOT})
    if( ${ARCH} STREQUAL arm)
      client_sdk_ld_options(-L$ENV{EPID_SDK_R6_ROOT}/_install/epid-sdk/lib/posix-arm)
    else()
      client_sdk_ld_options(-L$ENV{EPID_SDK_R6_ROOT}/_install/epid-sdk/lib/posix-x86_64)
    endif()
    client_sdk_ld_options(-l:libmember.a -l:libcommon.a  -l:libippcp.a)
  if ((${KEX} MATCHES ecdh) OR (${PK_ENC} STREQUAL ecdsa))
    message(WARNING "EPID supports only KEX=dh/asym and PK_ENC=rsa")    
  endif()
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

if(${AES_MODE} MATCHES ctr)
  client_sdk_compile_definitions(
    -DAES_MODE_CTR_ENABLED)
elseif(${AES_MODE} MATCHES cbc)
  client_sdk_compile_definitions(
    -DAES_MODE_CBC_ENABLED)
else()
  message(WARNING "Incorrect AES_MODE selected")
endif()


if(${CRYPTO_HW} MATCHES true)
  client_sdk_compile_options(
    -I$ENV{CRYPTOAUTHLIB_ROOT}/lib/basic -I$ENV{CRYPTOAUTHLIB_ROOT}/lib
    )
  client_sdk_compile_definitions(-DSECURE_ELEMENT)
endif()

if(KEX STREQUAL dh)
  client_sdk_compile_definitions(
    -DKEX=\"DHKEXid14\" -DKEX_DH_ENABLED)
elseif(KEX STREQUAL asym)
    client_sdk_compile_definitions(
      -DKEX=\"ASYMKEX\" -DKEX_ASYM_ENABLED)
  elseif(KEX STREQUAL ecdh)
    client_sdk_compile_definitions(
      -DKEX=\"ECDH\" -DKEX_ECDH_ENABLED -DAES_128_BIT)
  elseif(KEX STREQUAL ecdh384)
  client_sdk_compile_definitions(
    -DKEX=\"ECDH384\" -DKEX_ECDH384_ENABLED -DAES_256_BIT)
else()
    message(WARNING "Incorrect KEX selected")
endif()


if (${BUILD} STREQUAL debug)
  if (${TARGET_OS} STREQUAL linux)
    if (${unit-test} STREQUAL true)
      client_sdk_compile_definitions(-DLOG_LEVEL=-1)
      client_sdk_compile_options (-O0 -g)
    else()
      client_sdk_compile_definitions(-DDEBUG -DLOG_LEVEL=2)
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


if(${MANUFACTURER_TOOLKIT} STREQUAL true)
  client_sdk_compile_definitions(-DMANUFACTURER_TOOLKIT)
endif()

if(${MODULES} STREQUAL true)
  client_sdk_compile_definitions(-DMODULES_ENABLED)
endif()

if(${HTTPPROXY} STREQUAL true)
  client_sdk_compile_definitions(-DHTTPPROXY)
endif()

############################################################
