# Build Configuration
Following are some of the options to choose when building the device:
- BUILD: Release or debug mode
- DA: Device Attestation Algorithm
- AES_MODE: Advanced Encryption Standard (AES) encryption mode
- TLS: Underlying cryptography library to use

> ***NOTE***: The currently supported AES operations are: A128GCM, A256GCM, AES-CCM-64-128-128 and AES-CCM-64-128-256. Refer to Section 4.4 of [FIDO Device Onboard (FDO) specification](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-RD-v1.1-20211214/) for more information.

## Default Configuration

```shell
  BUILD = debug #build mode
  TARGET_OS = linux #target OS. (`linux` denotes the Linux* OS.)
  AES_MODE = gcm #AES encryption type
  DA = ecdsa384 #device attestation method
  TLS = openssl #underlying cryptography library to use. (`openssl` denotes the OpenSSL* toolkit.)
```
The default configuration can be overridden by using more options in `cmake`.<br>

> ***NOTE***: The Owner attestation supported is conversely based on the specified `DA`. Additionally, only `X509 (COSE EC2)` Public Key encoding is supported.

## Custom Build
The default configuration can be overridden by using more options in `cmake`.<br>
For example, to build the `STM32F429ZI` device:
- BUILD: Debug mode
- DA: ECDSA-256
- AES_MODE: GCM
```shell
$ cmake -DTARGET_OS=mbedos -DBOARD=NUCLEO_F429ZI -DBUILD=debug -DAES_MODE=gcm -DDA=ecdsa256 .
$ make -j4
```

For available build options:
```shell
List of build modes:
BUILD=debug           # Debug mode (default)
BUILD=release         # Release mode

List of supported TARGET_OS:
TARGET_OS=linux       # (Default)
TARGET_OS=mbedos      # (Mbed OS v5.9.14)

List of supported boards (valid only when TARGET_OS=mbedos):
BOARD=NUCLEO_F767ZI   # (When building for STM32F767ZI MCU)
BOARD=NUCLEO_F429ZI   # (When building for STM32F429ZI MCU)

List of AES encryption modes:
AES_MODE=gcm          # use Galois/Counter Mode encryption during TO2 (default)
AES_MODE=ccm          # use Counter with CBC-MAC encryption during TO2

List of Device Attestation options:
DA=ecdsa256           # Use ECDSA P256 based device attestation
DA=ecdsa384           # Use ECDSA-P384 based device attestation(default)
DA=tpm20_ecdsa256     # Use ECDSA-P256 based device attestation with TPM2.0 support
DA_FILE=pem           # only Use if ECDSA private keys are PEM encoded

Underlying crypto library to be used:
TLS=openssl           # (Linux default, not supported for other TARGET_OS)
TLS=mbedtls           # (Mbed OS default, not supported for other TARGET_OS)
CRYPTO_HW=true        # Use Secure element for some of the crypto operations(default = false)

Option to enable network-proxy:
HTTPPROXY=true        # http-proxy enabled (default)
HTTPPROXY=false       # http-proxy disabled
PROXY_DISCOVERY=true  # network discovery enabled (default = false)

Option to enable self signed certs:
SELF_SIGNED_CERTS=true # self signed certs check enabled for HTTPS connection. (default)
SELF_SIGNED_CERTS=false # self signed certs check disabled for HTTPS connection.
```
> ***Note***: For accepting self-signed certs, additional runtime argument '-ss' is required.
```shell
$ ./build/linux-client -ss
```
> ***WARN***: Accepting Self Signed Certificates is not recommended. If compromised, self-signed certificates can pose serious security risks.

```
Option to enable/disable Device credential resue and resale feature:
REUSE=true            # Reuse feature enabled (default)
REUSE=false           # Reuse feature disabled
RESALE=false          # Resale feature disabled
RESALE=true           # Resale feature enabled (default)

List of options to clean targets:
pristine              # cleanup by remove generated files

Supported values for C standard are: C90 and C99
```

## Crypto Library Support
a. TARGET_OS=linux supports
   - openssl
(`linux` denotes the Linux* OS.)

b. TARGET_OS=mbedos supports
   - mbedTLS
(`mbedos` denotes the Arm* Mbed* OS.
`mbedTLS` denotes the Arm Mbed TLS.)

> ***NOTE***: Currently, only `TARGET_OS=linux` and its configurations is supported. The source will be updated to add support for `TARGET_OS=mbedos` in a future release.
