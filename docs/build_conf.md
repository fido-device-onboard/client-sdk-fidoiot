# Build configuration
There following are some of the options to choose when building the device:
- BUILD: Release or debug mode
- DA: Device Attestation Algorithm
- AES_MODE: Advanced Encryption Standard (AES) encryption mode
- KEX: Key Exchange method
- PK_ENC: Owner Attestation Algorithm
- TLS: SSL support

## Default configuration

```shell
  BUILD = debug #build mode
  TARGET_OS = linux #target OS. (`linux` denotes the Linux* OS.)
  KEX = dh #key-exchange method
  AES_MODE = ctr #AES encryption type
  DA = ecdsa256 #device attestation method
  PK_ENC = rsa #public key encoding (for owner attestation)
  TLS = openssl #underlying cryptography library to use. (`openssl` denotes the OpenSSL* toolkit.)
  MODULE = false #whether to use Secure Device Onboard (SDO) service-info functionality
```
The default configuration can be overridden by using more options in `cmake`.<br>

## Custom build
The default configuration can be overridden by using more options in `cmake`.<br>
For example, to build the `STM32F429ZI` device:
- BUILD: Debug mode
- DA: ECDSA-256
- AES_MODE: CBC
- KEX: Diffie-Hellman
- PK_ENC: rsa (Default)
```shell
$ cmake -DTARGET_OS=mbedos -DBOARD=NUCLEO_F429ZI -DBUILD=debug -DAES_MODE=cbc -DKEX=dh -DDA=ecdsa256 .
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

List of key exchange options:
KEX=dh                # use Diffie-Hellman key exchange mechanism during TO2
KEX=asym              # use Asymmetric key exchange mechanism during TO2
KEX=ecdh              # use Elliptic-curve Diffie–Hellman key exchange mechanism during TO2 (default)
KEX=ecdh384           # use Elliptic-curve Diffie–Hellman 384 bit key exchange mechanism during TO2

List of AES encryption modes:
AES_MODE=ctr          # use Counter mode encryption during TO2 (default)
AES_MODE=cbc          # use Code-Block-Chaining mode encryption during TO2

List of Device Attestation options:
DA=ecdsa256           # Use ECDSA P256 based device attestation(default)
DA=ecdsa384           # Use ECDSA-P384 based device attestation
DA=tpm20_ecdsa256     # Use ECDSA-P256 based device attestation with TPM2.0 support
DA_FILE=pem           # only Use if ECDSA private keys are PEM encoded

List of Public Key encoding/owner-attestation options:
PK_ENC=ecdsa          # Use ECDSA-X.509 based public key encoding (default)

Underlying crypto library to be used:
TLS=openssl           # (Linux default, not supported for other TARGET_OS)
TLS=mbedtls           # (Mbed OS default, not supported for other TARGET_OS)
CRYPTO_HW=true        # Use Secure element for some of the crypto operations(default = false)

Option to enable network-proxy:
HTTPPROXY=true        # http-proxy enabled (default)
HTTPPROXY=false       # http-proxy disabled
PROXY_DISCOVERY=true  # network discovery enabled (default = false)

Option to enable SDO service-info functionality:
MODULES=false         # Service info modules are not present (default)
MODULES=true          # Service info modules are present

Option to enable/disable Device credential resue and resale feature:
REUSE=true            # Reuse feature enabled (default)
REUSE=false           # Reuse feature disabled
RESALE=false          # Resale feature disabled (default)
RESALE=true           # Resale feature enabled

List of options to clean targets:
pristine              # cleanup by remove generated files

Supported values for C standerd are: C90 and C99
```

## Crypto library support
a. TARGET_OS=linux supports
   - openssl
(`linux` denotes the Linux* OS.)

b. TARGET_OS=mbedos supports
   - mbedTLS
(`mbedos` denotes the Arm* Mbed* OS.
`mbedTLS` denotes the Arm Mbed TLS.)


