

# FIDO Device Onboard (FDO) Compilation Setup
<a name="safestring"></a>
## 1. Intel safestringlib
FDO Client SDK uses safestringlib for string and memory operations to prevent serious security vulnerabilities (For example, buffer overflows).

* For Linux*/ Arm Mbed* OS/ Arm Mbed* Linux* OS builds, download safestring from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>.

<a name="tinycbor"></a>
## 2. Intel TinyCBOR
FDO Client SDK uses TinyCBOR library for Concise Binary Object Representation (CBOR) encoding and decoding.

* For Linux* OS builds, download TinyCBOR from <a href="https://github.com/intel/tinycbor">tinycbor</a>.

<a name="manuf_addr"></a>
## 3. Setting the Manufacturer Network Address
To set the manufacturer network address(transport protocol, DNS/IP and/or port) that FDO Client SDK Linux device uses during Device Initialization (DI) protocol:

```shell
# To set the complete manufacturer address
$ cd <path-to-client-sdk-fidoiot>
$ echo -n <{http,https}://{DNS,IP}:port> > data/manufacturer_addr.bin
```

The following rules apply while setting the value and all of these are mandatory:
 a) The transport protocol value must be either `http` or `https` (case-sensitive). Any other value will result in an error.
 b) Either one of DNS or IP Address can be provided. The maximum value of DNS is 100 characters and must only contain alphanumeric characters (0-9A-za-z), hyphens (-) and dot (.).
 c) The port should be an integer between (1-65535).
 d) The URL separators `://` and `:` should be present at appropriate indices as per the indices of the above values.

```shell
# For example, to set the manufacturer address as "https://127.0.0.1:12345"
$ cd <path-to-client-sdk-fidoiot>
$ echo -n https://127.0.0.1:12345 > data/manufacturer_addr.bin
```

> ***NOTE***: By default, `manufacturer_addr.bin` is configured with "http://host.docker.internal:8039".

<a name="ecdsa_priv"></a>
## 4. Elliptic Curve Digital Signature Algorithm (ECDSA) Private Key File Generation
The following are steps to generate the private key file for ECDSA-based devices, only EC Curve `P-256` and `P-384` are supported.

*  Generate EC private key (optional, if not already generated):
   ```shell
   $ openssl ecparam -name prime256v1 -genkey -noout -out key.pem #For P-256
   ```
   or
   ```shell
   $ openssl ecparam -name secp384r1 -genkey -noout -out key.pem #For P-384
   ```

*   **Option1 (default):** To generate the binary private key data file

1. To parse the Privacy-Enhanced Mail (PEM)-formatted EC private key to generate the private key in binary format:
   ```shell
   $ openssl asn1parse < key.pem
   ```
   > ***NOTE***: An example of output from the preceding command: <br>
     ...... <br>
     ...... <br>
     .. [HEX DUMP]:A253014C61B6AEB5FA867B5417CD4A87D45BD6A505E81060D064529D0540CD36<br>
     ...... <br>
     ...... <br>

2. Use the `[HEX DUMP]` information from the above to generate the respective EC key (.dat) file (`ecdsa256privkey.dat` for EC curve P-256 and `ecdsa384privkey.dat` for EC curve P-384):
	For example,
   ```shell
   $ echo 'A253014C61B6AEB5FA867B5417CD4A87D45BD6A505E81060D064529D0540CD36' | xxd -r -p > ecdsaXXXprivkey.dat
   ```

   The respective ecdsaXXXprivkey.dat file will be used by the FDO target binary (Linux* or Arm* Mbed* OS) while ECDSA sign operation.
   

* **Option2:** To use the private key in PEM format, rename key.pem to ecdsaXXXprivkey.pem (`ecdsa256privkey.pem` for EC curve P-256 and `ecdsa384privkey.pem` for EC curve P-384). Use the compilation flag `DA_FILE=pem` during binary creation.

<a name="serviceinfo_mtu"></a>
## 5.  Setting the Maximum ServiceInfo Size

The maximum permissible ServiceInfo size (both Device and Owner) that FDO Client SDK can process should be set in the file `max_serviceinfo_sz.bin`. The value must lie between 256 and 8192 (both inclusive). If the set value is less than 256, the value would default to 256. Similarly, if the value is greater than 8192, the value would default to 8192.

This value is sent as TO2.DeviceServiceInfoReady.maxOwnerServiceInfoSz and is compared with the TO2.OwnerServiceInfoReady.maxDeviceServiceInfoSz.

```shell
# To set the maximum ServiceInfo Size
$ cd <path-to-client-sdk-fidoiot>
$ echo -n <integer size> > data/max_serviceinfo_sz.bin
```
<a  name="device_serial"></a>
## 6. Setting the Manufacturer Device Serial Number (Optional)

The manufacturer device serial number can be set in the file `manufacturer_sn.bin`. The character length should not be greater than 255. If the length is greater than 255, the value would default to "abcdef".

```shell
# To set the device serial number
$ cd <path-to-client-sdk-fidoiot>
$ echo -n <device serial> > data/manufacturer_sn.bin
```

>  ***NOTE***: By default, `manufacturer_sn.bin` is not there and the device serial is configured with "abcdef".

<a name="cred_reuse"></a>
## 7.  FDO Credentials REUSE Protocol

The FDO credentials REUSE feature allows FDO devices to reuse their ownership credentials across multiple device onboardings. This feature only gets enabled if the owner sends down the same rendezvous info, device GUID information, and public key at the end of the Transfer of Ownership, Step 2 (TO2) protocol.

Specifically, if `TO2.SetupDevice.TO2SetupDevicePayload.RendezvousInfo`, `TO2.SetupDevice.TO2SetupDevicePayload.Guid`, and `TO2.SetupDevice.TO2SetupDevicePayload.Owner2Key` match the corresponding values held by the device, the device will not generate a Hash-based Message Authentication Code (HMAC), which then allows the original ownership voucher (OV) to be used for another (and subsequent) onboarding(s) by reusing the same device credentials multiple times.

However, device client binary must be generated using -DREUSE=true flag. This flag simply enables/disables the support for REUSE feature for FDO Client SDK and it is upto the Owner to decide whether device is onboarded with the same credentials. For instance, if the REUSE flag is set to true at the device and the Owner decides to NOT perform REUSE, then the device will be continue with the new set of credentials (onboarding then depends on RESALE flag). Conversely, if REUSE flag is set to false, and the above mentioned conditions for credential REUSE are met by the Owner, an error message will be thrown. This can be useful for a scenario where the device credentials should never be reused, once saved.

```shell
$ cmake -DREUSE=true
```
Activating the device credentials will in turn, activate the FDO device and configure the FDO device to run multiple onboarding(s). This can be useful in several test and development environments, where multiple onboardings are common.

<a name="http_proxy"></a>
## 8. HTTP-proxy Configuration (Optional)
If the device is located behind a proxy server, the proxy server details must be provided to the device. For the same purpose, there are three files (each for the manufacturer, rendezvous, and owner servers) in which the proxy server details should be specified in the required format, before connecting to the respective server. These files can be created or removed as required.

Each proxy file is located in the `data/` directory and named as follows:

* `mfg_proxy.dat` - holds the proxy server network address between the device and manufacturer.
* `rv_proxy.dat` - holding the proxy server network address between the device and the rendezvous server.
* `owner_proxy.dat` - holds the proxy server network address between the device and owner.

The following is the format for proxy server network address:

    <Proxy Server IP>:<proxy Server Port>  e.g. 255.255.255.255:65535

> ***NOTE***: The files `rv_proxy.dat`,`mfg_proxy.dat`, and `owner_proxy.dat` must not contain any other information beyond the information mentioned above.

The proxy server network address is optional if the device connects to an access point that connects the device through the proxy server.

***NOTE***:  FDO clients that run on the Linux* OS also support network proxy discovery using the environment variable or the Web Proxy Auto-Discovery (WPAD) protocol based on the libproxy library. To use wpad protocol, use export http_proxy=’wpad:’.
