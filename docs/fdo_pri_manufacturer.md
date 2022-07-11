
# FIDO Device Onboard (FDO) Protocol Reference Implementation (PRI) Manufacturer
The FDO PRI Manufacturer generates a device certificate based on the Elliptic Curve Digital Signature Algorithm (ECDSA) as part of the Device Initialization (DI) protocol, enabling a seamless Ownership Transfer of the device to the new owner.

## DI.AppStart
- This is the first message sent by the device to start the Ownership Transfer.

- The message is sent to the FDO PRI Manufacturer in the manufacturer's premises with a Certificate Signing Request (CSR).

- The FDO PRI Manufacturer uses this CSR to generate the Device Certificate and passes the Device Certificate on as an
  authentication mechanism for the device using the ECDSA public/private key cryptography.

## Supported Configuration
```
make DA=ecdsa256
```

## Known Limitations
1. DI.AppStart specifies a particular format of the message in which the CSR is one of the components.
   Another component is the `serial_number`. FDO expects the device user to write their own mechanism
   to generate this `serial_number`.
   As a reference:
   ```
   FILE: lib/m-string.c
   DeviceMfgInfo Format: [<key type id>, <serial number>, <model number>, <csr>]
   key type id  : ECDSA256 = 10 and ECDSA384 = 11
   serial number: To be filled
   model number : Can be an empty string
   csr          : ECC-based Certificate Signing Request

   ```

2. The ECDSA key is read from the filesystem. Refer to [Security Implications](security_implications.md)

3. Currently, the Device Attestation (DA) mechanism is independent of the Owner Attestation (OA) mechanism as
   shown in the following table:
   ```
    ---------------------------------------
   |Device Attestation | Owner Attestation |
   |---------------------------------------|
   | EPID              | RSA2048RESTR      |
   | ECDSA NIST P-256  | RSA2048RESTR      |
   | ECDSA NIST P-384  | RSA2048RESTR      |
   | EPID              | RSA 3072-bit key  |
   | ECDSA NIST P-256  | RSA 3072-bit key  |
   | ECDSA NIST P-384  | RSA 3072-bit key  |
   | EPID              | ECDSA NIST P-256  |
   | ECDSA NIST P-256  | ECDSA NIST P-256  | <--
   | ECDSA NIST P-384  | ECDSA NIST P-256  |
   | EPID              | ECDSA NIST P-384  |
   | ECDSA NIST P-256  | ECDSA NIST P-384  |
   | ECDSA NIST P-384  | ECDSA NIST P-384  | <--
    ---------------------------------------
   ```
   The CSR data is filled as part of `DI.AppStart` based on Owner Attestation.
   So, essentially, it is only filled for
   ```
   Owner Attestation = ECDSA
   ```
   Marked combinations in the preceding table are supported.

4. If the onboarding fails during TO2, any artifacts created by the fdosys module may not be deleted. Delete these files from clients if the ServiceInfo fails halfway through.
