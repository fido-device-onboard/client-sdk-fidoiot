# Device Initialization(DI) SCT Setup
The process where the device obtains Secure Device Onboard (SDO) credentials from the supply chain toolkit(SCT) is known as Device Initialization (DI).

Open a terminal and start the SCT. After this step, an ownership voucher
is generated so that the new owner can initiate the TO0 protocol.

Detailed steps and configuration needed to start SDO supply chain toolkit are in the `<release-package-dir>/SupplyChainTools/README.md` document.

# Device Initialization Device Setup

During this time, the device does not have SDO credentials and therefore will obtain the SDO credentials from the SCT.

> **Note:** If you are not running the default SDO Client-SDK binaries from the release package and have your own EC keys and certs, do the following:
>
>   - If the device attestation method is Elliptic Curve Digital Signature Algorithm (ECDSA), place the ECDSA private key in the `data/` directory and name it `ecdsaXXXprivkey.dat`(`ecdsa256privkey.dat` for curve type `P-256` and `ecdsa384privkey.dat` for curve type `P-384`). For the Privacy-Enhanced Mail (PEM)-formatted private key, use `ecdsaXXXprivkey.pem` in a similar way (`ecdsa256privkey.pem` or `ecdsa384privkey.pem`).
