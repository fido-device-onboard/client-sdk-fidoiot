# FIDO Device Onboard (FDO) Client SDK

This is a production-ready implementation of the Device component defined in
[FIDO Device Onboard Spec](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/)
published by the FIDO Alliance. Appropriate security measures should be taken for storing the device
credentials while porting this to different platforms.

[ Introduction ](docs/introduction.md) <br>
[  FDO Compilation Setup ](docs/setup.md)
- [ Safestring ](docs/setup.md#safestring) <br>
- [ TinyCBOR ](docs/setup.md#tinycbor) <br>
- [ Manufacturer Network Address ](docs/setup.md#manuf_addr)
- [ ECDSA Private Key Generation ](docs/setup.md#ecdsa_priv)
- [ Setting the Maximum ServiceInfo Size](docs/setup.md#serviceinfo_mtu)
- [ Setting the Manufacturer Device Serial Number](docs/setup.md#device_serial)
- [ Configure Credential REUSE](docs/setup.md#cred_reuse)
- [ HTTP_PROXY ](docs/setup.md#http_proxy)

[ Linux* TPM* Reference Implementation ](docs/tpm.md) <br>
[ Linux* CSE* Reference Implementation ](docs/cse.md) <br>
[ Linux* Reference Implementation ](docs/linux.md) <br>
[Security Implications](docs/security_implications.md)

***Note***: The implementation hasn't yet been updated for Arm* based platforms. This will be updated in a future release.

[ Arm* Mbed* OS Reference Implementation ](docs/mbedos.md) <br>
[ Arm* Mbed* Linux* Reference Implementation ](docs/mbed_linux.md) <br>
