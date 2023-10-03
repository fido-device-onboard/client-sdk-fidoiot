#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


file(GLOB FDO_CRYPTO_COMMON_SOURCES common/*.c)
file(GLOB FDO_CRYPTO_OPENSSL_SOURCES openssl/openssl*.c)
file(GLOB FDO_CRYPTO_MBEDTLS_SOURCES mbedtls/mbedtls*.c)

client_sdk_include_directories(
  include
  ecdsa
  )

add_library(crypto "")

client_sdk_sources_with_lib(
  crypto
  common/fdo_ov_verify.c
  common/fdo_key_exchange.c
  common/fdo_aes.c
  common/fdo_hmac.c
  common/fdo_dev_sign.c
  common/fdo_crypto_common.c
  common/fdo_dev_attest.c
  )


#################################################################
#openssl build
if (${TLS} STREQUAL openssl)
  client_sdk_sources_with_lib( crypto
    openssl/openssl_AES_routines.c
    openssl/openssl_crypto_support.c
    openssl/openssl_SSL_routines.c
    openssl/BN_support.c
    openssl/openssl_key_exchange_ecdh.c)

    ### Signature verifications types
    if (${CRYPTO_HW} STREQUAL false)
          client_sdk_sources_with_lib( crypto openssl/openssl_ECDSA_verify_routines.c)
    endif()

    if (${DA} STREQUAL cse_ecdsa384)
    client_sdk_sources_with_lib ( crypto
    openssl/cse_crypto_support.c
    )
    endif()


    if (${DA} MATCHES tpm)
	  client_sdk_sources_with_lib ( crypto
	    openssl/tpm20_ECDSA_sign_routines.c
	    openssl/tpm20_Utils.c
	    openssl/openssl_csr.c
	    openssl/ec_key.c
	    ecdsa/ecdsa_privkey.c)

    elseif (${DA} MATCHES ecdsa)
      if (${CRYPTO_HW} MATCHES false)
	  client_sdk_sources_with_lib ( crypto
	    openssl/openssl_ECDSA_sign_routines.c
	    openssl/openssl_csr.c
	    openssl/ec_key.c
            ecdsa/ecdsa_privkey.c)
        endif()
    endif()

    if (${CRYPTO_HW} MATCHES true)
	  client_sdk_sources_with_lib( crypto openssl/openssl_DER_routines.c)
    endif()
endif()



#################################################################
#mbedtls build
if (${TLS} STREQUAL mbedtls)
  client_sdk_sources_with_lib ( crypto
    mbedtls/mbedtls_AESRoutines.c
    mbedtls/mbedtls_cryptoSupport.c
    mbedtls/mbedtls_SSLRoutines.c
    mbedtls/mbedtls_RSAEncryptRoutines.c
    mbedtls/mbedtls_random.c
    mbedtls/mbedtls_key_exchange_ecdh.c)

    if (${CRYPTO_HW} MATCHES false)
        client_sdk_sources_with_lib( crypto mbedtls/mbedtls_AESGCMRoutines.c)
    endif()

    ### Signature verifications types

    if (${CRYPTO_HW} STREQUAL false)
          client_sdk_sources_with_lib( crypto mbedtls/mbedtls_ECDSAVerifyRoutines.c)
    endif()


    if (${DA} MATCHES ecdsa)
      if (${CRYPTO_HW} MATCHES false)
	  client_sdk_sources_with_lib ( crypto
	    mbedtls/mbedtls_ECDSASignRoutines.c
	    mbedtls/mbedtls_ec_csr.c
            ecdsa/ecdsa_privkey.c)
        endif()
      endif()

    if (${CRYPTO_HW} MATCHES true)
	  client_sdk_sources_with_lib( crypto mbedtls/mbedtls_DERRoutines.c)
    endif()
endif()

#################################################################
#SE build

if (${CRYPTO_HW} MATCHES true)
  client_sdk_sources_with_lib( crypto
    se/se_AES_GCM_routines.c
    se/se_crypto_support.c
    se/se_csr.c
    se/se_ECDSA_verify_routines.c)

  if (${DA} STREQUAL ecdsa256 )
    client_sdk_sources_with_lib( crypto se/se_ECDSA_sign_routines.c)
    endif()
  endif()



target_link_libraries(crypto PUBLIC client_sdk_interface)
