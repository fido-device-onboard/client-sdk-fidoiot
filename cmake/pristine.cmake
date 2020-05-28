#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

set(all_generated ${CMAKE_BINARY_DIR}/CMakeCache.txt
  ${CMAKE_BINARY_DIR}/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/Makefile
  ${CMAKE_BINARY_DIR}/build
  ${CMAKE_BINARY_DIR}/CMakeFiles
  ${CMAKE_BINARY_DIR}/tests/unit/CMakeFiles/
  ${CMAKE_BINARY_DIR}/network/CMakeFiles/
  ${CMAKE_BINARY_DIR}/storage/CMakeFiles/
  ${CMAKE_BINARY_DIR}/lib/CMakeFiles/
  ${CMAKE_BINARY_DIR}/app/CMakeFiles/
  ${CMAKE_BINARY_DIR}/mbedos/CMakeFiles/
  ${CMAKE_BINARY_DIR}/device_modules/CMakeFiles/
  ${CMAKE_BINARY_DIR}/crypto/CMakeFiles/
  ${CMAKE_BINARY_DIR}/storage/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/network/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/tests/unit/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/crypto/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/lib/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/mbedos/cmake_install.cmake
  ${CMAKE_BINARY_DIR}/tests/unit/CMakeCache.txt
  )
  

message("Cleaning Old files if present.")
foreach(file ${all_generated} )
  if (EXISTS ${file})
    message("${file}")
    file(REMOVE_RECURSE ${file})
  endif()
endforeach(file)
