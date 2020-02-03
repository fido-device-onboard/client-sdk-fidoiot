# Build Configuration
There following are some of the options to choose when building the device:
- BUILD: Release of debug mode
- DA: Device Attestation Algorithm
- AES_MODE: Advanced Encryption Standard (AES) encryption mode
- KEX: Key Exchange method
- PK_ENC: Owner Attestation Algorithm
- TLS: SSL support

## Default Configuration

```shell
  BUILD = debug #build mode
  TARGET_OS = linux #target OS. “linux” denotes the Linux* OS.
  KEX = dh #key-exchange method
  AES_MODE = ctr #AES encryption type
  DA = ecdsa256 #device attestation method
  PK_ENC = rsa #Public key encoding (for owner attestation)
  TLS = openssl #underlying cryptography library to use. “openssl” denotes the OpenSSL* toolkit.
  MODULE = false #whether to use Secure Device Onboard (SDO) service-info functionality
```
The default configuration can be overridden by providing more options with the `make` options.<br>

## Custom Build
The default configuration can be overridden by providing more options with the `make` options.<br>
For example, to build the `STM32F429ZI` device:
- BUILD: Debug mode
- DA: ECDSA-256
- AES_MODE: CBC
- KEX: Diffie-Hellman
- PK_ENC: rsa (Default)
```shell
$ make TARGET_OS=mbedos BOARD=NUCLEO_F429ZI BUILD=debug AES_MODE=cbc KEX=dh DA=ecdsa256
```

For more available build options:
```shell
make help
```

## Crypto Library Support
a. TARGET_OS=linux supports
   - openssl
“linux” denotes the Linux* OS

b. TARGET_OS=mbedos supports
   - mbedTLS
“mbedos” denotes the Arm* Mbed* OS


