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


echo "For ecdsa_c_device *******"
mkdir -p ecdsa256_c_device_bin
mkdir -p ecdsa256_c_device_bin/blob_backup
make DA=ecdsa256 pristine
make BUILD=${BUILDTYPE} PK_ENC=ecdsa DA=ecdsa256 KEX=ecdh

cp -a ${WORKSPACE}/build/linux/${BUILDTYPE}/linux-client    ${WORKSPACE}/ecdsa256_c_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa256_c_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup

echo "For ecdsa_c_device for Supply chain tool*******"
mkdir -p ecdsa256_c_sct_device_bin
mkdir -p ecdsa256_c_sct_device_bin/blob_backup
make DA=ecdsa256 pristine
make BUILD=${BUILDTYPE} PK_ENC=ecdsa DA=ecdsa256 MANUFACTURER_TOOLKIT=true KEX=ecdh

cp -a ${WORKSPACE}/build/linux/${BUILDTYPE}/linux-client    ${WORKSPACE}/ecdsa256_c_sct_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa256_c_sct_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup

mkdir -p ecdsa384_c_sct_device_bin
mkdir -p ecdsa384_c_sct_device_bin/blob_backup
make DA=ecdsa384 pristine
make BUILD=${BUILDTYPE} PK_ENC=ecdsa DA=ecdsa384 MANUFACTURER_TOOLKIT=true KEX=ecdh384

cp -a ${WORKSPACE}/build/linux/${BUILDTYPE}/linux-client    ${WORKSPACE}/ecdsa384_c_sct_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa384_c_sct_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup

echo "For epid_c_device *******"
mkdir -p epid_c_device_bin
mkdir -p epid_c_device_bin/blob_backup
make DA=epid pristine
make BUILD=${BUILDTYPE} HTTPPROXY=true DA=epid PK_ENC=rsa KEX=asym

cp -a ${WORKSPACE}/build/linux/${BUILDTYPE}/linux-client    ${WORKSPACE}/epid_c_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/epid_c_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/epid_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/epid_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/epid_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/epid_c_device_bin/blob_backup

echo "For epid_c_device for Supply chain tool*******"
mkdir -p epid_c_sct_device_bin
mkdir -p epid_c_sct_device_bin/blob_backup
make DA=epid pristine
make BUILD=${BUILDTYPE} PK_ENC=rsa DA=epid MANUFACTURER_TOOLKIT=true KEX=dh

cp -a ${WORKSPACE}/build/linux/${BUILDTYPE}/linux-client    ${WORKSPACE}/epid_c_sct_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/epid_c_sct_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/epid_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/epid_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/epid_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/epid_c_sct_device_bin/blob_backup


