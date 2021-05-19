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

############################
### Build Configurations ###
############################

# Helper function for copying build artifacts to target folder
function copy_build_artifacts()
{
  # Arg1: Target build directory
  BUILDDIR=$1

  # Create the target directory, cleanup if it already exists
  rm -rf ${BUILDDIR}
  mkdir -p ${BUILDDIR}
  mkdir -p ${BUILDDIR}/blob_backup

  # Copy the build artifacts
  cp -a build/linux-client ${BUILDDIR}
  cp -a data ${BUILDDIR}
  cp -a data/*.blob ${BUILDDIR}/blob_backup
  cp -a data/platform_aes_key.bin ${BUILDDIR}/blob_backup
  cp -a data/platform_hmac_key.bin ${BUILDDIR}/blob_backup
  cp -a data/platform_iv.bin ${BUILDDIR}/blob_backup
}

## Common build configurations
DEFAULT_CONFIG="-DBUILD=${BUILDTYPE} -DMANUFACTURER_TOOLKIT=true -DMODULES=true -DPK_ENC=ecdsa"

## ECDSA256 build configurations
echo "***** Building with ECDSA256 support *****"
make pristine || true
cmake ${DEFAULT_CONFIG} -DDA=ecdsa256 -DKEX=ecdh .
make -j$(nproc)
copy_build_artifacts x86_ecdsa256_bin

# Build configurations for ECDSA384
echo "***** Building with ECDSA384 support *****"
make pristine || true
cmake ${DEFAULT_CONFIG} -DDA=ecdsa384 -DKEX=ecdh384 .
make -j$(nproc)
copy_build_artifacts x86_ecdsa384_bin

# Build configurations for TPM based devices
echo "***** Building with TPM (ECDSA256) support *****"
make pristine || true
cmake ${DEFAULT_CONFIG} -DDA=tpm20_ecdsa256 -DPK_ENC=ecdsa .
make -j$(nproc)
copy_build_artifacts tpm_ecdsa256_bin

######################
### Run Unit Tests ###
######################

echo " ***** Running Unit Tests *****"
TEST_OUTPUT="build/unit-test-output.txt"
rm -f $TEST_OUTPUT
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=ctr -DDA=ecdsa256 -DPK_ENC=ecdsa ; make -j$(nproc) | tee -a $TEST_OUTPUT
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=cbc -DDA=ecdsa256 -DPK_ENC=ecdsa ; make -j$(nproc) | tee -a $TEST_OUTPUT
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh384 -DAES_MODE=ctr -DDA=ecdsa384 -DPK_ENC=ecdsa ; make -j$(nproc) | tee -a $TEST_OUTPUT
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh384 -DAES_MODE=cbc -DDA=ecdsa384 -DPK_ENC=ecdsa ; make -j$(nproc) | tee -a $TEST_OUTPUT
make pristine || true; cmake -Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DKEX=ecdh -DAES_MODE=ctr -DDA=ecdsa256 -DPK_ENC=ecdsa -DDA_FILE=pem ; make -j$(nproc) | tee -a $TEST_OUTPUT

fail_count=$(awk '/Tests Failed  :/ {split($0,a,": "); count+=a[2]} END{print count}' $TEST_OUTPUT)
echo "Found $fail_count unit-test failure(s)."
exit $fail_count
