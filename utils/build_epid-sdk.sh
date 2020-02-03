#!/bin/bash

echo "Building epid-sdk for ARM architecture"

git clone  https://github.com/Intel-EPID-SDK/epid-sdk.git epid-sdk
cd epid-sdk
git checkout 29965f89eab7b8591564d4dde05b0b3c00ade4cd
chmod +x configure

./configure --prefix=${PWD}/_install --host=arm-linux-gnueabi CFLAGS=-mfloat-abi=hard LDFLAGS=-mfloat-abi=hard
make all

sed -i '/cp $(MEMBER_TPM2_UTEST_EXE)/d' epid/member/Makefile
mkdir _install 
make install
cd ..
