**NOTE**: This is a preliminary implementation of the [FIDO Device Onboard Spec](https://fidoalliance.org/specs/FDO/fido-device-onboard-v1.0-ps-20210323/) published by the FIDO Alliance. The implementation is experimental and incomplete, and is not ready for use in any production capacity. Some cryptographic algorithms and encoding formats have not been implemented, and any aspect of this implementation is subject to change.

# FIDO Device Onboard (FDO) Client SDK

[ Introduction ](docs/introduction.md) <br>
[  FDO Compilation Setup ](docs/setup.md)
- [ Safestring ](docs/setup.md#safestring) <br>
- [ TinyCBOR ](docs/setup.md#tinycbor) <br>
- [ Manufacturer Network Address ](docs/setup.md#manuf_addr)
- [ ECDSA Private Key Generation ](docs/setup.md#ecdsa_priv)
- [ Setting the Maximum ServiceInfo Size](docs/setup.md#serviceinfo_mtu)
- [ Configure Credential Reuse](docs/setup.md#cred_reuse)
- [ HTTP_PROXY ](docs/setup.md#http_proxy)

[ Linux* TPM* Reference Implementation ](docs/tpm.md) <br>
[ Linux* Reference Implementation ](docs/linux.md) <br>
[Security Implications](docs/security_implications.md)

***Note***: The implementation hasn't yet been updated for Arm* based implementations. This will be updated in a future release.

[ Arm* Mbed* OS Reference Implementation ](docs/mbedos.md) <br>
[ Arm* Mbed* Linux* Reference Implementation ](docs/mbed_linux.md) <br>
