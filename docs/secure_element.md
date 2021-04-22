# For Secure Element Based Implementation

The Secure Element(SE) is a trusted platform module which helps in secure
authentication using ECDSA. This Secure Element in FDO is used to ensure that
the Elliptical Curve keys and AES keys are kept in a secure non volatile
memory. This ensures secure access for any ECDSA or AES GCM related operations.
Any operations that involve the ECDSA or AES key will have to be passed as a
secure command. These Secure element commands will use the private key from
inside the SE and gives us the sign or verify results.

The Secure Element provides us with various other cryptographic operations.
Among which Random number generator is a key crypto operation. The Secure element provides us
with a truly random 32 byte number that is used as an iv or seed for many crypto operations inside FDO.

FDO implementation for ARM devices uses Microchip AT608A as the secure element.

***NOTE***: The configurations mentioned in the document are not supported yet. This document will be updated in a future release when the source code implementation is updated to support the same.

## Setting up the SE for Execution
1. Pin Connections has to be set as shown below.
>                            ----------------------------                 ----------------------------
>                           |         RPI Board         |                |      Microchip AT608A      |
>                            ----------------------------                 ----------------------------
>                           | Signal   | RPI board pin  |                | XPRO Extension Header pin  |
>                            ----------------------------                 ----------------------------
>                           | SCL      |       5        |<-------------->|     SCK       |       12   |
>                            ----------------------------                 ----------------------------
>                           | SDA      |       3        |<-------------->|     SDA       |       11   |
>                            ----------------------------                 ----------------------------
>                           | VCC      |       2        |<-------------->|     VCC       |       20   |
>                            ----------------------------                 ----------------------------
>                           | GND      |       39       |<-------------->|     GND       |       2    |
>                            ----------------------------                 ----------------------------

2. Get CryptoAuthlib source code.
   ``` bash
   $ cd ~
   $ git clone https://github.com/MicrochipTech/cryptoauthlib.git cryptoauthlib
   ```

3. Install the shared binary object. Prerequisite for this step is cmake should be available.
   And note this has to be build for Raspberry Pi(RPI) which is an ARM platform. Cross compile or native build
   on RPI is users choice. The following steps show how it is done on RPI.
   ``` bash
   $ cd ~/cryptoauthlib
   $ cmake .
   $ make
   $ make install
   ```

4. Enable the I2C driver on the RPI. Uncomment 'dtparam=i2c_arm=on` in boot config. 
   ```bash
   $ sudo vi /boot/config.txt
   # uncomment i2c
   $ sudo reboot
   ```

5. Check if the device is up and running.
   ```bash
   $ sudo i2cdetect -y 1
   ```
   ***NOTE***: i2cdetect is run on i2c bus 1. Therefore "-y 1", there maybe devices in which this
   might not be true. Refer to the hardware spec for the correct bus number.

6. Setting up the build Environment for SE.
   ``` bash
   $ sudo chmod +666 /dev/i2c-1
   $ export CRYPTOAUTHLIB_ROOT=~/cryptoauthlib
   ```

7. Do a [regular build](./linux.md) of FDO with an additional parameter CRYPTO_HW=true.
   ***NOTE***: Only ECDSA is supported from SE.
   ```bash
   $ cd <client-sdk folder>
   $ cmake -DCRYPTO_HW=true -DPK_ENC=ecdsa -DKEX=ecdh .
   $ make
   $ ./build/linux/debug/linux-client
   ```

8. Note that the first time the provisioning takes place, it will create a device.csr.pem file
   in the current working directory which can be used to create a certificate if needed.
   Also during the first run, AES key and ECDSA public key are shown. The subsequent runs can
   not access the AES/ECDSA key related information.
