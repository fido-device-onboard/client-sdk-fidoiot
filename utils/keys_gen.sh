#!/bin/bash
#
# Copyright 2021 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# Summary:
#   keys_gen.sh script creates a new ECDSA256 and ECDSA384 PEM files and DAT files
#   to onboard the CLIENT-SDK-FIDO device with the fresh key-pairs.
#
# List of output files:
#   /path/to/client-sdk-fidoiot/data/ecdsaxxxprivkey.pem -> Private key file
#   /path/to/client-sdk-fidoiot/data/ecdsaxxxprivkey.dat -> Encrypted hex-dump file
#
# Command used to generate pem and dat files:
#   ./keys_gen.sh /path/to/client-sdk-fidoiot
#
# Note:
#   Ensure that data folder exists in the path /path/to/client-sdk-fidoiot
#   with the new ecdsa256 or ecdsa384 private keys inside
#

# Usage message to be displayed whenever we provide wrong inputs
usage()
{
  echo -e "\nUsage:
    $0 /path/to/client-sdk-fidoiot"
}

# Environmental variables
CLIENTSDK_REPO=$1
if ! [[ -d ${CLIENTSDK_REPO}/data ]]; then
  echo -e "Data folder doesn't exist.......\n\
Please do verify the data path in /path/to/client-sdk-fidoiot"
  usage
  exit 1
else
  CLIENTSDK_DATA=$CLIENTSDK_REPO/data
fi
EC256_PEM=$CLIENTSDK_DATA/ecdsa256privkey.pem
EC256_DAT=$CLIENTSDK_DATA/ecdsa256privkey.dat
EC384_PEM=$CLIENTSDK_DATA/ecdsa384privkey.pem
EC384_DAT=$CLIENTSDK_DATA/ecdsa384privkey.dat

# Generate the private key for ecdsa256 or ecdsa384
# Extracts the hex-dump from PEM file and generates a encrypted DAT file out of it
keys_gen()
{
  openssl ecparam -name $1 -genkey -noout -out $2
  echo "Generated $2"
  echo `openssl asn1parse < $2 | grep "HEX DUMP" | cut -d ":" -f 4` | xxd -r -p > $3
  echo "Generated $3"
}

# Generation of ECDSA 256 and 384 .pem files and .dat files
if [[ $# == 1 ]]; then
  keys_gen prime256v1 $EC256_PEM $EC256_DAT
  keys_gen secp384r1 $EC384_PEM $EC384_DAT
else
  usage; exit 1;
fi
