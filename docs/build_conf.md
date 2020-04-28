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
The default configuration can be overridden by using more options in `make`.<br>

## Custom build
The default configuration can be overridden by using more options in `make`.<br>
For example, to build the `STM32F429ZI` device:
- BUILD: Debug mode
- DA: ECDSA-256
- AES_MODE: CBC
- KEX: Diffie-Hellman
- PK_ENC: rsa (Default)
```shell
$ make TARGET_OS=mbedos BOARD=NUCLEO_F429ZI BUILD=debug AES_MODE=cbc KEX=dh DA=ecdsa256
```

For available build options:
```shell
make help
```

## Crypto library support
a. TARGET_OS=linux supports
   - openssl
(`linux` denotes the Linux* OS.)

b. TARGET_OS=mbedos supports
   - mbedTLS
(`mbedos` denotes the Arm* Mbed* OS.
`mbedTLS` denotes the Arm Mbed TLS.)


