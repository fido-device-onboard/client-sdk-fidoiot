# Device Initialization(DI) FDO PRI Manufacturer Setup
The process where the device obtains FIDO Device Onboard (FDO) credentials from the FDO Manufacturer is known as Device Initialization (DI).

Open a terminal and start the FDO PRI Manufacturer. After this step, an ownership voucher
is generated so that the new owner can initiate the TO0 protocol.

Detailed steps and configuration needed to start FDO PRI Manufacturer are in
[README](https://github.com/fido-device-onboard/pri-fidoiot/blob/master/component-samples/demo/manufacturer/README.md) document.

# Device Initialization Device Setup

During this time, the device does not have FDO Device Credentials and therefore will obtain the same from the FDO PRI Manufacturer.

> ***NOTE***: If you are not running the default FDO Client SDK binaries and have your own EC keys and certs, do the following:
>
>   - Place the ECDSA private key in the `data/` directory and name it `ecdsaXXXprivkey.dat`(`ecdsa256privkey.dat` for curve type `P-256` and `ecdsa384privkey.dat` for curve type `P-384`). For the Privacy-Enhanced Mail (PEM)-formatted private key, use `ecdsaXXXprivkey.pem` in a similar way (`ecdsa256privkey.pem` or `ecdsa384privkey.pem`).
