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
make pristine || true
cmake -DBUILD=${BUILDTYPE} -DPK_ENC=ecdsa -DDA=ecdsa256 -DKEX=ecdh
make -j$(nproc)

cp -a ${WORKSPACE}/build/linux-client    ${WORKSPACE}/ecdsa256_c_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa256_c_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa256_c_device_bin/blob_backup

echo "For ecdsa_c_device for Supply chain tool*******"
mkdir -p ecdsa256_c_sct_device_bin
mkdir -p ecdsa256_c_sct_device_bin/blob_backup
make pristine || true
cmake -DBUILD=${BUILDTYPE} -DPK_ENC=ecdsa -DDA=ecdsa256 -DMANUFACTURER_TOOLKIT=true -DKEX=ecdh
make -j$(nproc)

cp -a ${WORKSPACE}/build/linux-client    ${WORKSPACE}/ecdsa256_c_sct_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa256_c_sct_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa256_c_sct_device_bin/blob_backup

mkdir -p ecdsa384_c_sct_device_bin
mkdir -p ecdsa384_c_sct_device_bin/blob_backup
make pristine || true
cmake -DBUILD=${BUILDTYPE} -DPK_ENC=ecdsa -DDA=ecdsa384 -DMANUFACTURER_TOOLKIT=true -DKEX=ecdh384
make -j$(nproc)

cp -a ${WORKSPACE}/build/linux-client    ${WORKSPACE}/ecdsa384_c_sct_device_bin
cp -a ${WORKSPACE}/data   ${WORKSPACE}/ecdsa384_c_sct_device_bin
cp -a ${WORKSPACE}/data/*.blob ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_aes_key.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_hmac_key.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup
cp -a ${WORKSPACE}/data/platform_iv.bin ${WORKSPACE}/ecdsa384_c_sct_device_bin/blob_backup

echo " *****Running Unit Tests*********" 
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=ctr -DDA=ecdsa256 -DPK_ENC=ecdsa ; make -j$(nproc)
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=cbc -DDA=ecdsa256 -DPK_ENC=ecdsa ; make -j$(nproc)
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh384 -DAES_MODE=ctr -DDA=ecdsa384 -DPK_ENC=ecdsa ; make -j$(nproc)
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh384 -DAES_MODE=cbc -DDA=ecdsa384 -DPK_ENC=ecdsa ; make -j$(nproc)
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=ctr -DDA=ecdsa256 -DPK_ENC=ecdsa -DDA_FILE=pem ; make -j$(nproc)
