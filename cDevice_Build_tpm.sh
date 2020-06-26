#!/bin/bash -x
set -e -x
export WORKSPACE=`pwd`

BUILDTYPE="release"

if [ -z $1 ]
        then
        echo "No argument supplied"
else
        BUILDTYPE=$1
fi

# Build To Archive into Artifactory

echo "For ecdsa_c_device (TPM) *******"
mkdir -p tpm_ecdsa_c_device_bin
mkdir -p tpm_ecdsa_c_device_bin/blob_backup
make pristine || true
cmake -DBUILD=${BUILDTYPE} -DPK_ENC=ecdsa -DDA=tpm20_ecdsa256 .
make -j4

cp -a ${WORKSPACE}/build/linux-client    ${WORKSPACE}/tpm_ecdsa_c_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/tpm_ecdsa_c_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/tpm_ecdsa_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/tpm_ecdsa_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/tpm_ecdsa_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/tpm_ecdsa_c_device_bin/blob_backup
