# Device Initialization Customer Reference Implementation (CRI) Setup
The process where the device obtains Secure Device Onboard (SDO) credentials from the manufacturer’s CRI is known as Device Initialization (DI).

Open a terminal and start the  SDO manufacturer CRI server. After this step, an ownership proxy
is generated so that the new owner can initiate the TO0 protocol.

> **Note:** To run  SDO Client-SDK binaries from the release package,use the following configuration when launching  SDO CRIs (required before running the DI protocol):
>
>       - org.sdo.pm.ownershipproxy.dc=%device-cert-file-name% #An example of the device’s elliptic curve (EC) public-certificate, used for verification of the device’s EC signature.
>       - org.sdo.pkix.trust-anchors=%cert-chain-file-name% #An example of the certificate-chain, used to issue the device’s EC public-certificate.
>
> All required certs and cert chains are present under the `<path-to-sdo-client-sdk>/data` directory.

Detailed steps and configuration needed to start SDO manufacturer are in the `<release-package-dir>/cri/README.md` document.

# Device Initialization Device Setup

During this time, the device does not have SDO credentials and therefore will obtain the SDO credentials from the manufacturer CRI.

> **Note:** If you are not running the default SDO Client-SDK binaries from the release package and have your own EC keys and certs, do the following:
>
>   - If the device attestation method is Elliptic Curve Digital Signature Algorithm (ECDSA), place the ECDSA private key in the `data/` directory and name it `ecdsaXXXprivkey.dat`(`ecdsa256privkey.dat` for curve type `P-256` and `ecdsa384privkey.dat` for curve type `P-384`). For the Privacy-Enhanced Mail (PEM)-formatted private key, use `ecdsaXXXprivkey.pem` in a similar way (`ecdsa256privkey.pem` or `ecdsa384privkey.pem`).

