#!/bin/bash

CSDK_REPO=$1
CSDK_DATA=$CSDK_REPO/data

EC256_DAT=$CSDK_DATA/ecdsa256privkey.dat
EC256_PEM=$CSDK_DATA/ecdsa256privkey.pem
EC384_DAT=$CSDK_DATA/ecdsa384privkey.dat
EC384_PEM=$CSDK_DATA/ecdsa384privkey.pem

usage()
{
  echo -e "Usage:
    $0 <absolute_path_of_CSDK_repo>\n"
}

gen_csdk_keys()
{
  # Generation of ECDSA 256 and 384 .pem files and .dat files
  openssl ecparam -name prime256v1 -genkey -noout -out $EC256_PEM
  echo "Generated $EC256_PEM"

  echo `openssl asn1parse < $EC256_PEM | grep "HEX DUMP" |\
    cut -d ":" -f 4` | xxd -r -p > $EC256_DAT
  echo "Generated $EC256_DAT"

  openssl ecparam -name secp384r1 -genkey -noout -out $EC384_PEM
  echo "Generated $EC384_PEM"

  echo `openssl asn1parse < $EC384_PEM | grep "HEX DUMP" |\
    cut -d ":" -f 4` | xxd -r -p > $EC384_DAT
  echo "Generated $EC384_DAT"
}

if [[ $# == 1 ]]; then
  gen_csdk_keys
else
  usage; exit 1;
fi
