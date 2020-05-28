#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


client_sdk_include_directories(
  include
  )

client_sdk_sources(
  main.c
  blob.c
  )

client_sdk_sources_if(
  CRYPTO_HW true
  se_provisioning.c
  )
