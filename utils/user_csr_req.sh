#!/bin/bash
#
# Copyright 2023 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# ***WARNING***: The script generates the credentials using default system
# configurations and might not provide necessary security strength for a
# production deployment. Care must be taken to maintain necessary cryptographic
# strength while generating keys for production deployment.

# Summary:
# user_csr_req.sh creates a certificate signing request for mTLS user/client credentials
# the client.conf contains the subject name of the certificate.
# the csr will be outputed to client.req file.
# the private key will be outputed to client.key
#
# Usage message to be displayed whenever we provide wrong inputs
usage()
{
  echo -e "\nUsage:
    $0 /path/to/client-sdk-fidoiot"
}

CLIENTSDK_REPO=$1
if ! [[ -d ${CLIENTSDK_REPO}/data ]]; then
  echo -e "Data folder doesn't exist.......\n\
Please do verify the data path in /path/to/client-sdk-fidoiot"
  usage
  exit 1
else
  CLIENTSDK_DATA=$CLIENTSDK_REPO/data
fi

if [[ $# == 1 ]]; then
  openssl req -x509 -newkey rsa:2048 -keyout $CLIENTSDK_DATA/clientKey.pem -out $CLIENTSDK_DATA/clientUser.pem -sha256 -days 12775 -nodes -config $CLIENTSDK_DATA/client.conf
  openssl x509 -x509toreq -in $CLIENTSDK_DATA/clientUser.pem -out $CLIENTSDK_DATA/client.req -signkey $CLIENTSDK_DATA/clientKey.pem

  #comment out following line if signing with external CA
  openssl x509 -req -days 12775 -in $CLIENTSDK_DATA/client.req -CA $CLIENTSDK_DATA/ca-cert.pem -CAkey $CLIENTSDK_DATA/caKey.pem -CAcreateserial -out $CLIENTSDK_DATA/apiUser.pem -extfile $CLIENTSDK_DATA/client.conf -extensions v3_req
else
  usage; exit 1;
fi
