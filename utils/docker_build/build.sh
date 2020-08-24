#!/bin/bash

# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

REMOTE_URL=https://github.com/secure-device-onboard/client-sdk.git
REMOTE_BRANCH=master

git clone http://github.com/intel/safestringlib.git
cd safestringlib/ && make
cd .. && rm -f CMakeCache.txt
export SAFESTRING_ROOT=/home/sdouser/client-sdk/safestringlib

if [ "$use_remote" = "1" ]; then
  echo "Building $REMOTE_URL : $REMOTE_BRANCH"
  cd /tmp/
  git clone $REMOTE_URL
  cd /tmp/client-sdk/
  git checkout $REMOTE_BRANCH

  ./cDevice_Build.sh
  ./cDevice_Build_tpm.sh

  # Copying Binaries back to the mounted volume.
  cp -r /tmp/client-sdk/ecdsa256_c_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/ecdsa256_c_sct_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/ecdsa384_c_sct_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/tpm_ecdsa_c_device_bin/ /home/sdouser/client-sdk/

else
  ./cDevice_Build.sh
  ./cDevice_Build_tpm.sh
fi

# Changing the ownership of files from root user to sdouser.
chown -R sdouser:sdouser *
