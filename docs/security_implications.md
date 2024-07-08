# Security Implications
The following are security implications to be
addressed before using the reference solution as is, because of the nature of the reference platform.

## AES Counter with CBC-MAC (CCM) mode trade-offs
The Nonce length 'N' for CCM mode is dependent on the maximum message length 'L' value
and should be equal to '15-L' octets.
Refer to [RFC3610](https://datatracker.ietf.org/doc/html/rfc3610) for more information on
trade-offs between 'L' and 'N' value.
The current implementation supports L=8 with the following configurations:
   - `AES-CCM-64-128-128` (L=64 (8 octets, maximum 2^64 bytes message length), Tag = 128 bits, Key = 128 bits)
   - `AES-CCM-64-128-256` (L=64 (8 octets, maximum 2^64 bytes message length), Tag = 128 bits, Key = 256 bits)

The Nonce length 'N' is thus fixed at 7 octets (i.e 15-8).

As per FDO and COSE [RFC8152](https://datatracker.ietf.org/doc/html/rfc8152) specifications,
L=2 could also be used. N=13 MUST be used in this case.
   Affected file(s):
   - `crypto/openssl/openssl_AES_routines.c`
   - `lib/fdotypes.h`

## Linux* OS (OpenSSL* toolkit as the cryptography library)
1. The random number needs to be seeded with an entropy source.
   Affected file(s):
   - `crypto/openssl/openssl_crypto_support.c`
   - `crypto/mbedtls/mbedtls_cryptoSupport.c` (Not supported)
   - `crypto/se/se_crypto_support.c` (Not supported)

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the FIDO Device Onboard (FDO) data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as a Secure Engine that can be a third-party application, library, or hardware.
   - `PLATFORM_HMAC_KEY`: The key is stored in the `data/platform_hmac_key.bin` file
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the `data/platform_aes_key.bin` file
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the `data/ecdsa256privkey.dat` file or
                      `data/ecdsa256privkey.pem` file in the reference
                      implementation. <br>
   Affected file(s): <br>
   - `base.mk`

***NOTE***: The configurations mentioned for below platforms are not supported yet. They will be updated in a future release.

## NUCLEO-F429ZI board: Arm Cortex* -M4/Arm Mbed* OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the True Random Number Generator (TRNG) hardware for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls-hardware-entropy-source) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the FDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the `data/platform_hmac_key.bin` file
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the `data/platform_aes_key.bin` file
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the `data/ecdsa256privkey.dat` file or the
                      `data/ecdsa256privkey.pem` file in the reference
                      implementation. <br>
   Affected file(s): <br>
   - `base.mk`

3. FDO recommends to switch on the following compilation options for mbedTLS:
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

## NUCLEO-F767ZI board: Arm Cortex-M7/Arm Mbed OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the TRNG hardware for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls-hardware-entropy-source) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the FDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the `data/platform_hmac_key.bin` file
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the `data/platform_aes_key.bin` file
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the `data/ecdsa256privkey.dat` file or the
                      `data/ecdsa256privkey.pem` file in the reference
                      implementation. <br>
   Affected file(s): <br>

   - `cmake/blob_path.cmake`

3. FDO recommends to switch on the following compilation options for mbedTLS:
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

## WaRP7 board: Arm Cortex-A7/Linux OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the True Random Number Generator (TRNG) hardware for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls-hardware-entropy-source) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the  FDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the `data/platform_hmac_key.bin` file
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the `data/platform_aes_key.bin` file
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the `data/ecdsa256privkey.dat` file or
                      the`data/ecdsa256privkey.pem` file in the reference
                      implementation. <br>
   Affected file(s): <br>
   - `cmake/blob_path.cmake`

3.  FDO data must be protected by appropriate file system permissions as a defense
   in depth. Read/write permissions must be provided only to the user running the
   FDO application. The list of files is as follows:
   - data/Normal.blob: The integrity of this file is protected using
                       `PLATFORM_HMAC_KEY`, with read/write permissions provided
                       only to the  FDO user.
   - data/Secure.blob: This file is encrypted using `PLATFORM_AES_KEY`, with
                       read/write permissions provided only to the FDO user.
   - data/raw.blob: This file is not protected using cryptography but must have
                    read/write permissions provided only to the FDO user.
   - data: This directory must be read or written only by the FDO user. <br>
   Affected file(s): <br>
   - `cmake/blob_path.cmake`

4. FDO recommends to switch on the following compilation options for mbedTLS:
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

<a name="mbedtls_entropy"></a>
## mbedTLS Hardware Entropy Source
To enable the TRNG hardware as the entropy source, the
`MBEDTLS_ENTROPY_HARDWARE_ALT` macro must be uncommented in
`include/mbedtls/config.h` in the mbedTLS source code. The
` mbedtls_hardware_poll()` function, with prototype declared in
`entropy_poll.h`, must be implemented to collect entropy from the
hardware source.

In addition, the Arm Mbed OS must support the TRNG hardware using the appropriate
drivers. For this, the `device_has` array for the target platform in the
`targets/targets.json` file must have TRNG as one of the attributes.
The functions declared in `hal/trng_api.h` from the Arm Mbed OS source code
must be implemented to access the hardware entropy source.
