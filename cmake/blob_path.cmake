#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


# Note all blobs and data will be made relative.
# if absoulte is needed uncomment the following line
#set(BLOB_PATH ${BASE_DIR})

if(NOT (DEFINED BLOB_PATH))
set(BLOB_PATH .)
endif()

if(TARGET_OS MATCHES linux)
  
  Client_sdk_compile_definitions(
    -DPLATFORM_IV=\"${BLOB_PATH}/data/platform_iv.bin\"
    -DPLATFORM_HMAC_KEY=\"${BLOB_PATH}/data/platform_hmac_key.bin\"
    -DPLATFORM_AES_KEY=\"${BLOB_PATH}/data/platform_aes_key.bin\"
    -DEPID_PRIVKEY=\"${BLOB_PATH}/data/epidprivkey.dat\"
    -DSDO_CRED=\"${BLOB_PATH}/data/PMDeviceCredentials.bin\"
    -DMANUFACTURER_IP=\"${BLOB_PATH}/data/manufacturer_ip.bin\"
    -DMANUFACTURER_DN=\"${BLOB_PATH}/data/manufacturer_dn.bin\"
    -DMANUFACTURER_PORT=\"${BLOB_PATH}/data/manufacturer_port.bin\"
    )
  if (${DA} MATCHES tpm20)
    Client_sdk_compile_definitions(
       -DDEVICE_TPM20_ENABLED
       -DDEVICE_MSTRING=\"${BLOB_PATH}/data/device_mstring\"
       -DTPM_ECDSA_DEVICE_KEY=\"${BLOB_PATH}/data/tpm_ecdsa_priv_pub_blob.key\"
       -DTPM_INPUT_DATA_TEMP_FILE=\"${BLOB_PATH}/data/tpm_input_data_temp_file\"
       -DTPM_OUTPUT_DATA_TEMP_FILE=\"${BLOB_PATH}/data/tpm_output_data_temp_file\"
       -DTPM_HMAC_PUB_KEY=\"${BLOB_PATH}/data/tpm_hmac_pub.key\"
       -DTPM_HMAC_PRIV_KEY=\"${BLOB_PATH}/data/tpm_hmac_priv.key\"
       -DTPM_HMAC_DATA_PUB_KEY=\"${BLOB_PATH}/data/tpm_hmac_data_pub.key\"
       -DTPM_HMAC_DATA_PRIV_KEY=\"${BLOB_PATH}/data/tpm_hmac_data_priv.key\"
       -DTPM2_TSS_ENGINE_SO_PATH=\"/usr/local/lib/engines-1.1/libtpm2tss.so\"
       -DTPM2_TCTI_TYPE=\"tabrmd\"
	)
    endif()
  
    if (${unit-test} MATCHES true)
      if (${DA_FILE} MATCHES pem)
	client_sdk_compile_definitions(
          -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.pem\"
          )
      else()
	client_sdk_compile_definitions(
          -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.dat\"
          )
      endif()
      client_sdk_compile_definitions(
        -DSDO_CACERT=\"${BLOB_PATH}/data/test_cacert.bin\"
        -DSDO_PUBKEY=\"${BLOB_PATH}/data/test_pubkey.dat\"
        -DSDO_SIGRL=\"${BLOB_PATH}/data/test_sigrl.dat\"
        -DSDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
        -DSDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
        -DSDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
        -DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\"
        )
    else() 				#Not unit tests
      if (${DA} MATCHES ecdsa256)	#ecdsa 256 selected
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.dat\")
	endif()
      else() 				# ecdsa 384 selected
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa384privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa384privkey.dat\")
	endif()
      endif()
      client_sdk_compile_definitions(
	-DSDO_CACERT=\"${BLOB_PATH}/data/cacert.bin\"
	-DSDO_PUBKEY=\"${BLOB_PATH}/data/pubkey.dat\"
	-DSDO_SIGRL=\"${BLOB_PATH}/data/sigrl.dat\"
	-DSDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DSDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DSDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
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
      -DPLATFORM_IV=\"${BLOB_PATH}/data/platform_iv.bin\"
      -DPLATFORM_HMAC_KEY=\"${BLOB_PATH}/data/platform_hmac_key.bin\"
      -DPLATFORM_AES_KEY=\"${BLOB_PATH}/data/platform_aes_key.bin\"
      -DEPID_PRIVKEY=\"${BLOB_PATH}/data/epidprivkey.dat\"
      -DSDO_CRED=\"${BLOB_PATH}/data/PMDeviceCredentials.bin\"
      -DMANUFACTURER_IP=\"${BLOB_PATH}/data/manufacturer_ip.bin\"
      -DMANUFACTURER_DN=\"${BLOB_PATH}/data/manufacturer_dn.bin\"
      -DMANUFACTURER_PORT=\"${BLOB_PATH}/data/manufacturer_port.bin\"
      )
    if (${unit-test} MATCHES true)
      client_sdk_compile_definitions(
	-DSDO_CACERT=\"${BLOB_PATH}/data/test_cacert.bin\"
	-DSDO_PUBKEY=\"${BLOB_PATH}/data/test_pubkey.dat\"
	-DSDO_SIGRL=\"${BLOB_PATH}/data/test_sigrl.dat\"
	-DSDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DSDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DSDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
	-DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\"
	)
      if (${DA_FILE} MATCHES pem)
	client_sdk_compile_definitions(
	  -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.pem\")
      else()
	client_sdk_compile_definitions(
	  -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/test_ecdsaprivkey.dat\")
      endif()
  
    else()
      client_sdk_compile_definitions(
	-DSDO_CACERT=\"${BLOB_PATH}/data/cacert.bin\"
	-DSDO_PUBKEY=\"${BLOB_PATH}/data/pubkey.dat\"
	-DSDO_SIGRL=\"${BLOB_PATH}/data/sigrl.dat\"
	-DSDO_CRED_SECURE=\"${BLOB_PATH}/data/Secure.blob\"
	-DSDO_CRED_MFG=\"${BLOB_PATH}/data/Mfg.blob\"
	-DSDO_CRED_NORMAL=\"${BLOB_PATH}/data/Normal.blob\"
	-DRAW_BLOB=\"${BLOB_PATH}/data/raw.blob\")

      if (${DA} MATCHES ecdsa256)
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
	else()
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.dat\")
	endif()
      else()
	if (${DA_FILE} MATCHES pem)
	  client_sdk_compile_definitions(
	    -DECDSA_PRIVKEY=\"${BLOB_PATH}/data/ecdsa256privkey.pem\")
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

file(WRITE ${BLOB_PATH}/data/platform_iv.bin "")
file(WRITE ${BLOB_PATH}/data/platform_hmac_key.bin "")
file(WRITE ${BLOB_PATH}/data/platform_aes_key.bin "")
file(WRITE ${BLOB_PATH}/data/Mfg.blob "")
file(WRITE ${BLOB_PATH}/data/Normal.blob "{\"ST\":1}")
file(WRITE ${BLOB_PATH}/data/Secure.blob "")
file(WRITE ${BLOB_PATH}/data/raw.blob "")

#####
if (${DA} STREQUAL epid)
  execute_process(COMMAND /bin/bash ./gen_epid_blob.sh .)  
endif()
