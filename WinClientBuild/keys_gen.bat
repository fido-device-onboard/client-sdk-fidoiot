@echo off
REM #
REM # Copyright 2023 Intel Corporation
REM # SPDX-License-Identifier: Apache 2.0
REM #
REM # Summary:
REM #   keys_gen.bat script creates a new ECDSA256 and ECDSA384 PEM files
REM #   to onboard the CLIENT-SDK-FIDO device with the fresh key-pairs.
REM #
REM # List of output files:
REM #   /path/to/client-sdk-fidoiot/data/ecdsaxxxprivkey.pem -> Private key file
REM #
REM # Open command prompt to generate pem files:
REM #   keys_gen.bat /path/to/client-sdk-fidoiot
REM #
REM # Note:
REM #   Ensure that data folder exists in the path /path/to/client-sdk-fidoiot
REM #   with the new ecdsa256 or ecdsa384 private keys inside
REM #

REM # Usage message to be displayed whenever we provide wrong inputs

SET CLIENTSDK_REPO=%~1

IF exist %CLIENTSDK_REPO%\data (
 SET CLIENTSDK_DATA=%CLIENTSDK_REPO%\data
) ELSE (
  echo Data folder doesn't exist....... 
  echo Please do verify the data path in \path\to\client-sdk-fidoiot
  CALL :usage
  EXIT /B %ERRORLEVEL%
)

SET EC256_PEM=%CLIENTSDK_DATA%\ecdsa256privkey.pem
SET EC384_PEM=%CLIENTSDK_DATA%\ecdsa384privkey.pem

IF not [%1]==[] (
  CALL :keys_gen prime256v1 , %EC256_PEM%
  CALL :keys_gen secp384r1 , %EC384_PEM%
) ELSE (
  CALL :usage
)
EXIT /B %ERRORLEVEL%

:usage
echo Usage: %0 /path/to/client-sdk-fidoiot
EXIT /B 0

:keys_gen
openssl ecparam -name %~1 -genkey -noout -out %~2
echo "Generated %~2"
EXIT /B 0