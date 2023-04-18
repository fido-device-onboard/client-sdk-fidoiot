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
  
  if [ ${BUILDDIR} == "cse_ecdsa384_gcm_bin" ] || [ ${BUILDDIR} == "cse_ecdsa384_ccm_bin" ]
  then
    cp -a build/cse-clear ${BUILDDIR}
  fi
}

## Common build configurations
nproc=$(cat /proc/cpuinfo | grep processor | wc -l)
COMMON_BUILD_CONFIG="-DBUILD=${BUILDTYPE}"

# Generic build function
function build_bin()
{
  target_dir=$1
  build_flag=${@:2}

  echo "***** Building configuration: $build_flag"
  make pristine || true
  cmake ${COMMON_BUILD_CONFIG} $build_flag .
  make -j$(nproc)
  copy_build_artifacts $target_dir
}

build_bin x86_ecdsa256_gcm_bin -DAES_MODE=gcm -DDA=ecdsa256
build_bin x86_ecdsa256_ccm_bin -DAES_MODE=ccm -DDA=ecdsa256
build_bin x86_ecdsa384_gcm_bin -DAES_MODE=gcm -DDA=ecdsa384
build_bin x86_ecdsa384_ccm_bin -DAES_MODE=ccm -DDA=ecdsa384
build_bin tpm_ecdsa256_gcm_bin -DAES_MODE=gcm -DDA=tpm20_ecdsa256
build_bin tpm_ecdsa256_ccm_bin -DAES_MODE=ccm -DDA=tpm20_ecdsa256
build_bin tpm_ecdsa384_gcm_bin -DAES_MODE=gcm -DDA=tpm20_ecdsa384
build_bin tpm_ecdsa384_ccm_bin -DAES_MODE=ccm -DDA=tpm20_ecdsa384
build_bin cse_ecdsa384_gcm_bin -DAES_MODE=gcm -DDA=cse_ecdsa384 -DCSE_CLEAR=true
build_bin cse_ecdsa384_ccm_bin -DAES_MODE=ccm -DDA=cse_ecdsa384 -DCSE_CLEAR=true

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
COMMON_TEST_CONFIG="-Dunit-test=true -DHTTPPROXY=true -DBUILD=release"

# Run unit-test with given test configuration
function run_unit_test
{
  make pristine || true
  cmake ${COMMON_TEST_CONFIG} $@
  make -j$(nproc) | tee -a $TEST_OUTPUT
}

run_unit_test -DDA=ecdsa256 -DAES_MODE=gcm
run_unit_test -DDA=ecdsa256 -DAES_MODE=ccm
run_unit_test -DDA=ecdsa384 -DAES_MODE=gcm
run_unit_test -DDA=ecdsa384 -DAES_MODE=ccm
run_unit_test -DDA=ecdsa256 -DAES_MODE=gcm -DDA_FILE=pem

# DO NOT change the AWK search string, the spaces has been kept deliberately.
fail_count=$(awk '/Tests Failed  :/ {split($0,a,": "); count+=a[2]} END{print count}' $TEST_OUTPUT)
echo "Found $fail_count unit-test failure(s)."

exit $fail_count