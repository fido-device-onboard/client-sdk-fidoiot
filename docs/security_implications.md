# Security Implications
The following are security implications to be
addressed before using the reference solution as is, because of the nature of the reference platform.

## Linux* OS (OpenSSL* toolkit as the cryptography library)
1. The random number needs to be seeded with an entropy source.
   Affected File(s):
   - `hal/tls/openssl_cryptoSupport.c`

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the Secure Device Onboard (SDO) data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as a Secure Engine that can be a third party application, library, or hardware where the keys are stored.
   - `PLATFORM_HMAC_KEY`: The key is stored in the file `data/platform_hmac_key.bin`
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the file `data/platform_aes_key.bin`
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the file `data/ecdsa256privkey.dat` or
                      `data/ecdsa256privkey.pem` in the reference
                      implementation. <br>
   Affected File(s): <br>
   - `base.mk`

## NUCLEO-F429ZI board: Arm* Cortex*-M4/Arm* Mbed* OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the hardware True Random Number Generator (TRNG) for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls_entropy) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the SDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the file `data/platform_hmac_key.bin`
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the file `data/platform_aes_key.bin`
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the file `data/ecdsa256privkey.dat` or
                      `data/ecdsa256privkey.pem` in the reference
                      implementation. <br>
   Affected File(s): <br>
   - `base.mk`

3. SDO recommends to switch on the following compilation options for mbedTLS:
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

## NUCLEO-F767ZI board: Arm Cortex-M7/Arm Mbed OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the hardware TRNG for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls_entropy) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the SDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the file `data/platform_hmac_key.bin`
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the file `data/platform_aes_key.bin`
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the file `data/ecdsa256privkey.dat` or
                      `data/ecdsa256privkey.pem` in the reference
                      implementation. <br>
   Affected File(s): <br>

   - `base.mk`

3. SDO recommends to switch on the following compilation options for mbedTLS:
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

## WaRP7 board: Arm Cortex-A7/Linux OS (mbedTLS as the cryptography library)
1. The mbedTLS library must use the hardware True Random Number Generator (TRNG) for
   the entropy source. Refer to
   [mbedTLS Hardware Entropy Source](#mbedtls_entropy) for more information.

2. In the reference implementation, the device key and the keys that encrypt
   or protect the integrity of the  SDO data are stored in clear text on the file system.
   In production systems, these keys must be stored in a secure storage such
   as the Secure Engine.
   - `PLATFORM_HMAC_KEY`: The key is stored in the file `data/platform_hmac_key.bin`
                          in the reference implementation.
   - `PLATFORM_AES_KEY`: The key is stored in the file `data/platform_aes_key.bin`
                         in the reference implementation.
   - `ECDSA_PRIVKEY`: The key is stored in the file `data/ecdsa256privkey.dat` or
                      `data/ecdsa256privkey.pem` in the reference
                      implementation. <br>
   Affected File(s): <br>
   - `base.mk`

3.  SDO data must be protected by the appropriate file system permissions for defense
   in depth. Read/write permissions must be provided only to the user running the
    SDO application. The list of the files is as follows:
   - data/Normal.blob: This file’s integrity is protected using
                       `PLATFORM_HMAC_KEY`, with read/write permissions provided
                       only to the  SDO user.
   - data/Secure.blob: This file is encrypted using `PLATFORM_AES_KEY`, with
                       read/write permissions provided only to the  SDO user
   - data/raw.blob: This file is not protected using cryptography but must have
                    read/write permissions provided only to the  SDO user.
   - data: This directory must be read or written only by the  SDO user. <br>
   Affected File(s): <br>
   - `base.mk`

4. SDO recommends to switch on the following compilation options for mbedTLS.
   ```
   MBEDTLS_SSL_ENCRYPT_THEN_MAC
   MBEDTLS_SSL_EXTENDED_MASTER_SECRET
   ```

<a name="mbedtls_entropy"></a>
## mbedTLS Hardware Entropy Source
To enable hardware TRNG as the entropy source, the
`MBEDTLS_ENTROPY_HARDWARE_ALT` macro must be uncommented in
`include/mbedtls/config.h` in the mbedTLS source code. The function
` mbedtls_hardware_poll()`, with prototype declared in
`entropy_poll.h` must be implemented to collect entropy from the
hardware source.

In addition, the Mbed OS must support the hardware TRNG using the appropriate
drivers. For this, the `device_has` array for the target platform in the
`targets/targets.json` file must have TRNG as one of the attributes.
The functions declared in `hal/trng_api.h` from the Mbed OS source code
must be implemented to access the hardware entropy source.
