#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


# Note all blobs and data will be made relative.
# if absoulte is needed declare BLOB_PATH on CLI
# or export BLOB_PATH=<path>

if(TARGET_OS MATCHES linux)

  client_sdk_compile_definitions(
    -DSERIAL_FILE=\"${BLOB_PATH}/data/manufacturer_sn.bin\"
    -DMODEL_FILE=\"${BLOB_PATH}/data/manufacturer_mod.bin\"
    -DPLATFORM_IV=\"${BLOB_PATH}/data/platform_iv.bin\"
    -DPLATFORM_HMAC_KEY=\"${BLOB_PATH}/data/platform_hmac_key.bin\"
    -DPLATFORM_AES_KEY=\"${BLOB_PATH}/data/platform_aes_key.bin\"
    -DMANUFACTURER_ADDR=\"${BLOB_PATH}/data/manufacturer_addr.bin\"
    -DMAX_SERVICEINFO_SZ_FILE=\"${BLOB_PATH}/data/max_serviceinfo_sz.bin\"
    )
  if (${DA} MATCHES cse)
    client_sdk_compile_definitions(
      -DDEVICE_CSE_ENABLED
    )
    endif()

  if (${MTLS} MATCHES true)
    client_sdk_compile_definitions(
      -DSSL_CERT=\"${BLOB_PATH}/data/apiUser.pem\"
      -DSSL_KEY=\"${BLOB_PATH}/data/clientKey.pem\"
    )
    endif()

  if (${BUILD_MFG_TOOLKIT} MATCHES true)
    client_sdk_compile_definitions(
      -DMAC_ADDRESSES=\"${BLOB_PATH}/data/mac_addresses.bin\"
    )
    endif()

  if (${DA} MATCHES tpm)
    client_sdk_compile_definitions(
       -DDEVICE_TPM20_ENABLED
	)
    endif()

    if (${unit-test} MATCHES true)
      if (${DA_FILE} MATCHES pem)
	client_sdk_compile_definitions(
          -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.pem\"
          )
      else()
	client_sdk_compile_definitions(
          -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.dat\"
          )
      endif()
      client_sdk_compile_definitions(
        -DFDO_CACERT=\"${BLOB_PATH}/data/test_cacert.bin\"
        -DFDO_PUBKEY=\"${BLOB_PATH}/data/test_pubkey.dat\"
        -DFDO_SIGRL=\"${BLOB_PATH}/data/test_sigrl.dat\"
        -DFDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
        -DFDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
        -DFDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
        -DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\"
        )
    else() 				#Not unit tests
      if (${DA} MATCHES ecdsa256)	#ecdsa 256 selected
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.dat\")
	endif()
      else() 				# ecdsa 384 selected
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa384privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa384privkey.dat\")
	endif()
      endif()
      client_sdk_compile_definitions(
	-DFDO_CACERT=\"${BLOB_PATH}/data/cacert.bin\"
	-DFDO_PUBKEY=\"${BLOB_PATH}/data/pubkey.dat\"
	-DFDO_SIGRL=\"${BLOB_PATH}/data/sigrl.dat\"
	-DFDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DFDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DFDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
	-DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\"
	)
    endif()
    if (NOT(${HTTPPROXY} STREQUAL ""))
      client_sdk_compile_definitions(
	-DMFG_PROXY=\"${BLOB_PATH}/data/mfg_proxy.dat\"
	-DRV_PROXY=\"${BLOB_PATH}/data/rv_proxy.dat\"
	-DOWNER_PROXY=\"${BLOB_PATH}/data/owner_proxy.dat\"
	)
    endif()
  endif()

  if (${TARGET_OS} MATCHES mbedos)
    client_sdk_compile_definitions(
      -DSERIAL_FILE=\"${BLOB_PATH}/data/manufacturer_sn.bin\"
      -DMODEL_FILE=\"${BLOB_PATH}/data/manufacturer_mod.bin\"
      -DPLATFORM_IV=\"${BLOB_PATH}/data/platform_iv.bin\"
      -DPLATFORM_HMAC_KEY=\"${BLOB_PATH}/data/platform_hmac_key.bin\"
      -DPLATFORM_AES_KEY=\"${BLOB_PATH}/data/platform_aes_key.bin\"
      -DMANUFACTURER_ADDR=\"${BLOB_PATH}/data/manufacturer_addr.bin\"
      -DMAX_SERVICEINFO_SZ_FILE=\"${BLOB_PATH}/data/max_serviceinfo_sz.bin\"
      )
    if (${unit-test} MATCHES true)
      client_sdk_compile_definitions(
	-DFDO_CACERT=\"${BLOB_PATH}/data/test_cacert.bin\"
	-DFDO_PUBKEY=\"${BLOB_PATH}/data/test_pubkey.dat\"
	-DFDO_SIGRL=\"${BLOB_PATH}/data/test_sigrl.dat\"
	-DFDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DFDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DFDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
	-DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\"
	)
      if (${DA_FILE} MATCHES pem)
	client_sdk_compile_definitions(
	  -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.pem\")
      else()
	client_sdk_compile_definitions(
	  -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.dat\")
      endif()

    else()
      client_sdk_compile_definitions(
	-DFDO_CACERT=\"${BLOB_PATH}/data/cacert.bin\"
	-DFDO_PUBKEY=\"${BLOB_PATH}/data/pubkey.dat\"
	-DFDO_SIGRL=\"${BLOB_PATH}/data/sigrl.dat\"
	-DFDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DFDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DFDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
	-DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\")

      if (${DA} MATCHES ecdsa256)
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.dat\")
	endif()
      else()
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PEM -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa384privkey.dat\")
	endif()

      endif()
    endif()
    if (NOT(${HTTPPROXY} STREQUAL ""))
	client_sdk_compile_definitions(
          -DMFG_PROXY=\"${BLOB_PATH}/data/mfg_proxy.dat\"
          -DRV_PROXY=\"${BLOB_PATH}/data/rv_proxy.dat\"
          -DOWNER_PROXY=\"${BLOB_PATH}/data/owner_proxy.dat\"
	  )
    endif()
  endif()

###################################################################
# setup the various blobs/ data files

# Configure if needed at a later point
# configure_file(${BLOB_PATH}/data/Normal.blob NEWLINE_STYLE DOS)

if (NOT ${DA} MATCHES tpm)
  file(WRITE ${BLOB_PATH}/data/platform_iv.bin "")
  file(WRITE ${BLOB_PATH}/data/platform_hmac_key.bin "")
  file(WRITE ${BLOB_PATH}/data/platform_aes_key.bin "")
  file(WRITE ${BLOB_PATH}/data/Normal.blob "")
  file(WRITE ${BLOB_PATH}/data/Secure.blob "")
  file(WRITE ${BLOB_PATH}/data/raw.blob "")
endif()
