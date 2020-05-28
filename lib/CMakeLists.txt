#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#


file(GLOB LIB_SOURCES *.c)
file(GLOB LIB_DI_SOURCES prot/di/*.c)
file(GLOB LIB_TO1_SOURCES prot/to1/*.c)
file(GLOB LIB_TO2_SOURCES prot/to2/*.c)

client_sdk_include_directories(
  include
  )

client_sdk_sources(
  ${LIB_SOURCES}
  ${LIB_DI_SOURCES}
  ${LIB_TO1_SOURCES}
  ${LIB_TO2_SOURCES}
  )


