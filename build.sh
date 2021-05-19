#!/bin/bash -x
set -e -x
export WORKSPACE=`pwd`

BUILDTYPE="release"
SKIP_UNIT_TEST=0

# Parse command line arguments
function usage()
{
 echo -e "Usage:
         $0 <OPTION>\n
        OPTION:
           [-d: Build in Debug mode]
           [-s: Skip unit test execution]
           [-h: Print help message]"
}

function parse_args()
{
  arg_count=0
  for opt in $@; do
    case $opt in
      -d)
        BUILDTYPE="debug"
        ;;
      -s)
        SKIP_UNIT_TEST=1
        ;;
      -h|*)
        usage;
        exit 1
        ;;
      esac
  done
}

parse_args "$@"

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
nproc=$(cat /proc/cpuinfo | grep processor | wc -l)
COMMON_BUILD_CONFIG="-DBUILD=${BUILDTYPE} -DMANUFACTURER_TOOLKIT=true -DMODULES=true -DPK_ENC=ecdsa"

## ECDSA256 build configurations
echo "***** Building with ECDSA256 support *****"
make pristine || true
cmake ${COMMON_BUILD_CONFIG} -DDA=ecdsa256 -DKEX=ecdh .
make -j$(nproc)
copy_build_artifacts x86_ecdsa256_bin

# Build configurations for ECDSA384
echo "***** Building with ECDSA384 support *****"
make pristine || true
cmake ${COMMON_BUILD_CONFIG} -DDA=ecdsa384 -DKEX=ecdh384 .
make -j$(nproc)
copy_build_artifacts x86_ecdsa384_bin

# Build configurations for TPM based devices
echo "***** Building with TPM (ECDSA256) support *****"
make pristine || true
cmake ${COMMON_BUILD_CONFIG} -DDA=tpm20_ecdsa256 -DPK_ENC=ecdsa .
make -j$(nproc)
copy_build_artifacts tpm_ecdsa256_bin

######################
### Run Unit Tests ###
######################

# Skip unit test if requested through command-line
if [ $SKIP_UNIT_TEST -eq 1 ]; then
  exit 0
fi

echo " ***** Running Unit Tests *****"
TEST_OUTPUT="build/unit-test-output.txt"
rm -f $TEST_OUTPUT
COMMON_TEST_CONFIG="-Dunit-test=true -DHTTPPROXY=true -DBUILD=release -DPK_ENC=ecdsa"

# Run unit-test with given test configuration
function run_unit_test
{
  make pristine || true
  cmake ${COMMON_TEST_CONFIG} $@
  make -j$(nproc) | tee -a $TEST_OUTPUT
}

run_unit_test -DDA=ecdsa256 -DKEX=ecdh -DAES_MODE=ctr
run_unit_test -DDA=ecdsa256 -DKEX=ecdh -DAES_MODE=cbc
run_unit_test -DDA=ecdsa384 -DKEX=ecdh384 -DAES_MODE=ctr
run_unit_test -DDA=ecdsa384 -DKEX=ecdh384 -DAES_MODE=cbc
run_unit_test -DDA=ecdsa256 -DKEX=ecdh -DAES_MODE=ctr -DDA_FILE=pem

# DO NOT change the AWK search string, the spaces has been kept deliberately.
fail_count=$(awk '/Tests Failed  :/ {split($0,a,": "); count+=a[2]} END{print count}' $TEST_OUTPUT)
echo "Found $fail_count unit-test failure(s)."

exit $fail_count
