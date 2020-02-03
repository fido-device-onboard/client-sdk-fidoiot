# Supply Chain Toolkit for Secure Device Onboard (SDO)
The Supply Chain Toolkit generates a device certificate based in the Elliptic Curve Digital Signature Algorithm (ECDSA) as part of the Device Initialization (DI) protocol, enabling a seamless Ownership Transfer of the device to the new owner.

## DI.AppStart
- This is the first message sent by the device to start the Ownership Transfer.

- The message is sent to the Supply Chain Toolkit in the manufacturer’s premises with a Certificate Signing Request (CSR).

- The Supply Chain Toolkit uses this CSR to generate the Device Certificate and passes the Device Certificate on as an
  authentication mechanism for the device using the ECDSA public/private key cryptography.

## Enabling Supply Chain Toolkit for  SDO-Client-SDK
```shell
export MANUFACTURER_TOOLKIT=true # Build with usual configuration
```

## Supported Configuration
```
make PK_ENC=ecdsa DA=ecdsa256
```

## Known Limitations
1. DI.AppStart specifies a particular format of the message in which the CSR is one of the components.
   Another component is the `serial_number`. SDO expects the device user to write their own mechanism
   to generate this `serial_number`.
   As a reference:
   ```
   FILE: lib/m-string.c
   MSG Format: <key type id>\0<serial number>\0<model number>[\0<CSR>]
   key type id  : RSA = 1, ECDSA256 = 13, and ECDSA384 = 14
   serial number: To be filled
   model number : Can be an empty string
   csr          : Only for ECC

   ```

2. The ECDSA key is read from the filesystem. Refer to [Security Implications](security_implications.md)

3. Currently, the Device Attestation (DA) mechanism is independent of the Owner Attestation (OA) mechanism as
   shown in the following table:
   ```
    ---------------------------------------
   |Device Attestation | Owner Attestation |
   |---------------------------------------|
   | EPID              | RSA2048RESTR      |
   | ECDSA NIST P-256  | RSA2048RESTR      | <--
   | ECDSA NIST P-384  | RSA2048RESTR      | <--
   | EPID              | RSA 3072-bit key  |
   | ECDSA NIST P-256  | RSA 3072-bit key  | <--
   | ECDSA NIST P-384  | RSA 3072-bit key  | <--
   | EPID              | ECDSA NIST P-256  |
   | ECDSA NIST P-256  | ECDSA NIST P-256  |
   | ECDSA NIST P-384  | ECDSA NIST P-256  |
   | EPID              | ECDSA NIST P-384  |
   | ECDSA NIST P-256  | ECDSA NIST P-384  |
   | ECDSA NIST P-384  | ECDSA NIST P-384  |
    ---------------------------------------
   ```
   With the introduction of the Supply Chain Toolkit, and referring to point 1, the CSR data will be filled
   conditionally as part of `DI.AppStart` because the CSR data is selected based on Owner Attestation.
   So, essentially, it is only filled for
   ```
   Owner Attestation = ECDSA
   ```
   Marked combinations in the preceding table will not work.

