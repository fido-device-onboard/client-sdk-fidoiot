#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

###################################################
#common build

#unity build
add_library(unity STATIC
    unity/src/unity.c
)
 
target_include_directories(unity PUBLIC
  unity/include
  )

#get includes, options, defines for the test files
client_sdk_get_include_directories(c_inc_lists)
client_sdk_get_compile_definitions(c_defines "")
client_sdk_get_compile_options(c_ops)



###########################################################
# rules for per test file
# note sequence needs to be maintained for proper execution.
set (UNIT_TEST_SOURCES
  test_ECDSAVerifyRoutines.c
  test_sample.c
  test_hal_os.c
  test_sdoprot.c
  test_base64.c
  test_sdotypes.c
  test_sdonet.c
  test_RSARoutines.c
  test_sdo.c
  test_credentials.c
  test_cryptoSupport.c
  test_bn_support.c
  test_utils.c
  test_cryptoUtils.c
  test_AESRoutines.c
  test_protctx.c
  test_SSLRoutines.c
  test_ECDSASignRoutines.c
)

set (test_sample_flags -Wl,-wrap,sdo_read_string_sz)

set (test_cryptosupport_flags -Wl,-wrap,crypto_init -Wl,-wrap,crypto_close
  -Wl,-wrap,sdo_alloc -Wl,-wrap,sdo_string_alloc_with_str
  -Wl,-wrap,crypto_hal_get_device_random -Wl,-wrap,crypto_init
  -Wl,-wrap,crypto_close -Wl,-wrap,sdo_string_alloc_with_str
  -Wl,-wrap,crypto_hal_set_peer_random -Wl,-wrap,sdo_byte_array_alloc
  -Wl,-wrap,sdo_alloc -Wl,-wrap,strcmp_s -Wl,-wrap,memset_s
  -Wl,-wrap,sdo_blob_read -Wl,-wrap,sdo_blob_size
  -Wl,-wrap,crypto_hal_sig_verify -Wl,-wrap,sdo_crypto_ecdsa_sign
  -Wl,-wrap,get_ec_key -Wl,-wrap,ECDSA_size -Wl,-wrap,memcpy_s
  -Wl,-wrap,convert2pkey)
      
set (test_hal_os_flags -Wl,-wrap,close -Wl,-wrap,recv -Wl,-wrap,send
  -Wl,-wrap,socket -Wl,-wrap,connect)

set (test_utils_flags -Wl,-wrap,fopen -Wl,-wrap,fread -Wl,-wrap,fclose
  -Wl,-wrap,ftell -Wl,-wrap,sdo_alloc)

set (test_sdokeyexchangedh_flags -Wl,-wrap,sdo_crypto_init)

set (test_protctx_flags -Wl,-wrap,snprintf_s_si -Wl,-wrap,sdo_alloc
  -Wl,-wrap,socket -Wl,-wrap,sdo_socket_read -Wl,-wrap,snprintf_s_i
  -Wl,-wrap,strncpy_s -Wl,-wrap,strcat_s)

set (test_credentials_flags -Wl,-wrap,sdoDeviceCredentialRead
  -Wl,-wrap,sdo_device_credential_write
  -Wl,-wrap,new_buffer_from_file
  -Wl,-wrap,sdo_alloc)

set (test_sslroutines_flags -Wl,-wrap,TLS_method
  -Wl,-wrap,SSL_CTX_new -Wl,-wrap,SSL_new
  -Wl,-wrap,SSL_connect -Wl,-wrap,SSL_shutdown
  -Wl,-wrap,SSL_CTX_set_cipher_list
  -Wl,-wrap,SSL_read -Wl,-wrap,SSL_write -Wl,-wrap,SSL_free)

set (test_cryptoutils_flags -Wl,-wrap,malloc -Wl,-wrap,memset_s
  -Wl,-wrap,memcpy_s -Wl,-wrap,crypto_hal_hmac
  -Wl,-wrap,sdo_hash_alloc
  -Wl,-wrap,sdo_hash_free)

set (test_sdo_flags -Wl,-wrap,sdo_crypto_init -Wl,-wrap,sdor_init -Wl,-wrap,sdow_init 
  -Wl,-wrap,app_alloc_credentials -Wl,-wrap,key_exchange_init
  -Wl,-wrap,sdo_null_ipaddress
  -Wl,-wrap,store_credential -Wl,-wrap,sdo_socket_connect
  -Wl,-wrap,memset_s -Wl,-wrap,sdo_alloc)

set (test_sdoprot_flags -Wl,-wrap,sdo_send_error_message -Wl,-wrap,sdo_prot_rcv_msg 
  -Wl,-wrap,sdo_cred_mfg_alloc -Wl,-wrap,app_get_credentials
  -Wl,-wrap,sdo_begin_write_signature 
  -Wl,-wrap,sdo_byte_array_write_chars -Wl,-wrap,sdo_service_info_get)

set (test_sdonet_flags -Wl,-wrap,cacheHostIP -Wl,-wrap,cacheHostDns
  -Wl,-wrap,sdo_byte_array_alloc -Wl,-wrap,sdor_init -Wl,-wrap,cacheHostPort 
  -Wl,-wrap,sdo_con_dns_lookup -Wl,-wrap,sdo_con_connect)

if (${TLS} MATCHES mbedtls)
  set (test_bn_support_flags -Wl,-wrap,sdo_byte_array_alloc -Wl,-wrap,crypto_hal_random_bytes
    -Wl,-wrap,mbedtls_mpi_write_binary
    -Wl,-wrap,mbedtls_mpi_size -Wl,-wrap,mbedtls_mpi_read_binary
    -Wl,-wrap,mbedtls_mpi_exp_mod -Wl,-wrap,mbedtls_mpi_grow
    -Wl,-wrap,mbedtls_mpi_exp_mod)
elseif (${TLS} MATCHES openssl)
  set (test_bn_support_flags -Wl,-wrap,sdo_byte_array_alloc -Wl,-wrap,crypto_hal_random_bytes
    -Wl,-wrap,BN_num_bits -Wl,-wrap,BN_bin2bn
    -Wl,-wrap,BN_bn2bin -Wl,-wrap,BN_mod_exp -Wl,-wrap,BN_rand)
endif()

###############
#need to check the need for this.
#epid
      

foreach(unit_test ${UNIT_TEST_SOURCES})


  STRING(REPLACE ".c" "" unit_test_match ${unit_test})
  STRING(TOLOWER ${unit_test_match} unit_test_lower)
  STRING(REGEX MATCH "test_.*" unit_test_exe ${unit_test_lower})
  
  add_library(${unit_test_exe}_lib STATIC
    ${unit_test}
    )

  target_include_directories(${unit_test_exe}_lib PUBLIC
    ${c_inc_lists}
    unity/include
    ${CMAKE_CURRENT_BINARY_DIR}
    )


  target_compile_definitions(${unit_test_exe}_lib PUBLIC ${c_defines} "-DUNIT_TEST")
  
  target_compile_options(${unit_test_exe}_lib PUBLIC
    ${c_ops}
    ${${unit_test_exe}_flags}
    -I$ENV{EPID_SDK_R6_ROOT}
    -std=c99
    )
  
  set (unity_runner ${EXECUTABLE_OUTPUT_PATH}/${unit_test_exe}_runner.c)
  # add_custom_target(unit_runner_target DEPENDS ${unity_runner})
  add_custom_command( OUTPUT  ${unity_runner}
    COMMAND
    ruby
    ${BASE_DIR}/tests/unit/unity/auto/generate_test_runner.rb ${unit_test} ${unity_runner}
    )


  add_executable(${unit_test_exe}
    ${unit_test}
    ${unity_runner}
    )

  target_link_libraries(${unit_test_exe}
    -Wl,--start-group
    ${unit_test_exe}_lib
    unity
    client_sdk
    network storage crypto
    ${${unit_test_exe}_flags}
    -Wl,--gc-sections
    -Wl,--end-group
    )


  set (execute_${unit_test_exe} ${unit_test_exe}.log)
  add_custom_command(
    OUTPUT ${execute_${unit_test_exe}}
    COMMAND
    #    ${EXECUTABLE_OUTPUT_PATH}/${unit_test_exe} > ${EXECUTABLE_OUTPUT_PATH}/${execute_${unit_test_exe}}
    ${EXECUTABLE_OUTPUT_PATH}/${unit_test_exe} >> ${EXECUTABLE_OUTPUT_PATH}/report.log || exit 0
    WORKING_DIRECTORY ${BASE_DIR}/
    DEPENDS ${unit_test_exe} ${test_case_lists}
    COMMENT "Executing test file ${unit_test_exe}"
    VERBATIM
    )

  # add_custom_target(test_case_exe ALL DEPENDS ${execute_test_sample})  



  list(APPEND test_case_lists ${execute_${unit_test_exe}})
endforeach()

#add_custom_target(test_case_exe ALL DEPENDS ${test_sample_report})
add_custom_target(test_case_exe ALL DEPENDS ${test_case_lists})   #working


# set (${unit_test_exe}_report ${unit_test_exe}_report.log)
add_custom_command(
  OUTPUT unit_test_exe_report.xml
  COMMAND
  ruby tests/unit/unity/auto/parse_output.rb -xml ${EXECUTABLE_OUTPUT_PATH}/report.log
  DEPENDS  test_case_exe
  WORKING_DIRECTORY ${BASE_DIR}
  COMMENT "report generate"
  VERBATIM
  )

add_custom_target(test_case_reporing ALL DEPENDS unit_test_exe_report.xml)
