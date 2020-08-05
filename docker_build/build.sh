#!/bin/bash

# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

REMOTE_URL=https://github.com/secure-device-onboard/client-sdk.git
REMOTE_BRANCH=master

export DEBIAN_FRONTEND=noninteractive

apt-get install -y build-essential
apt-get install -y cmake
apt-get install -y libssl-dev
apt-get install -y ruby
apt-get install -y wget
apt-get install -y tar
apt-get install -y unzip
apt-get install -y python
apt-get install -y python-pip

git clone https://github.com/intel/safestringlib.git
cd safestringlib/
make
export SAFESTRING_ROOT=/home/sdouser/client-sdk/safestringlib
cd ..
rm CMakeCache.txt

if [ "$use_remote" = "1" ]; then
  echo "Building $REMOTE_URL : $REMOTE_BRANCH"
  cd /tmp/
  git clone $REMOTE_URL
  cd /tmp/client-sdk/
  git checkout $REMOTE_BRANCH
  ./cDevice_Build.sh
  cd utils/
  sed 's/sudo//g' install_tpm_libs.sh > script.sh
  chmod 777 script.sh
  unset DEBIAN_FRONTEND
  yes | ./script.sh -i
  yes | ./script.sh -t
  cd ..
  ./cDevice_Build_tpm.sh
  # Copying Binaries back to the mounted volume.
  cp -r /tmp/client-sdk/ecdsa256_c_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/ecdsa256_c_sct_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/ecdsa384_c_sct_device_bin/ /home/sdouser/client-sdk/
  cp -r /tmp/client-sdk/tpm_ecdsa_c_device_bin/ /home/sdouser/client-sdk/

else
  ./cDevice_Build.sh
  cd utils/
  sed 's/sudo//g' install_tpm_libs.sh > script.sh
  chmod 777 script.sh
  unset DEBIAN_FRONTEND
  yes | ./script.sh -i
  yes | ./script.sh -t
  cd ..
  ./cDevice_Build_tpm.sh
fi

# Changing the ownership of files from root user to sdouser.
chown -R sdouser:sdouser *
