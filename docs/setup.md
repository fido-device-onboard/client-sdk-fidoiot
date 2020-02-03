# Secure Device Onboard (SDO) Compilation Setup
<a name="safestring"></a>
## 1. Intel safestringlib
SDO client-sdk uses safestringlib for string and memory operations to prevent serious security vulnerabilities (e.g. buffer overflows).
1. For OPTEE, download safestring from <a href="https://gitlab.devtools.intel.com/c-code-sdk/optee/safestring-optee">safestring-optee</a>

2. For non OPTEE builds, like Linux, Mbed OS, Mbed Linux, download safestring from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, checkout to the tag `v1.0.0`.

<a name="epid_sdk"></a>
## 2. Intel® Enhanced Privacy ID (Intel® EPID) SDK (optional)
To use Intel EPID for device attestation (DA), Intel EPID SDK must be installed. If any other DA method is used (e.g. ECDSA), this step can be skipped.
1. For OPTEE, epid port is not available for the moment.

2. For non-OPTEE builds, like Linux, Mbed OS, Mbed Linux, EPID SDK can be downloaded from <a href="https://intel-epid-sdk.github.io/">intel-epid-sdk</a>.

<a name="si_info_modules"></a>

## 3. Service-info device modules path (optional):
Provide the service-info device module path to use the  SDO service-info functionality:

<a name="manuf_addr"></a>
## 4. Setting the Manufacturer Customer Reference Implementation (CRI) network-address
Set the manufacturer CRI network (domain-name or IP) address, to which the device executing  SDO will connect during the Device Initialization (DI) protocol:

```shell
# For setting manufacturer DNS
$ cd <path-to-sdo-client-sdk>
$ echo -n <manufacturer domain-name> > data/manufacturer_dn.bin
```
or

```shell
# For setting manufacturer IP
$ cd <path-to-sdo-client-sdk>
$ echo -n <manufacturer server-ip> > data/manufacturer_ip.bin
```

The default manufacturer port is 8039. If required, it can be configured by following instructions:

```shell
# For setting manufacturer port
$ cd <path-to-sdo-client-sdk>
$ echo -n <manufacturer server-port> > data/manufacturer_port.bin
```

> **Note:** By default, `manufacturer_dn.bin` is configured with "localhost". If both IP and domain name are set, the IP takes precedence over domain name.

<a name="ecdsa_priv"></a>
## 5. Elliptic Curve Digital Signature Algorithm (ECDSA) private key file generation
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

1. Parse the Privacy-Enhanced Mail (PEM)-formatted EC private key to generate the private key in binary format:
   ```shell
   $ openssl asn1parse < key.pem
   ```
   > **Note**: An example of output from the preceding command: <br>
     ...... <br>
     ...... <br>
     .. [HEX DUMP]:A253014C61B6AEB5FA867B5417CD4A87D45BD6A505E81060D064529D0540CD36<br>
     ...... <br>
     ...... <br>

2. Use the `[HEX DUMP]` information from the above to generate the respective EC key(.dat) file (`ecdsa256privkey.dat` for EC curve P-256 and `ecdsa384privkey.dat` for EC curve P-384).
	E.g.
   ```shell
   $ echo 'A253014C61B6AEB5FA867B5417CD4A87D45BD6A505E81060D064529D0540CD36' | xxd -r -p > ecdsaXXXprivkey.dat
   ```

   The respective ecdsaXXXprivkey.dat file will be used by the  SDO target binary (Linux* or Arm* Mbed* OS) while ECDSA sign operation.
   

* **Option2:** To use the private key in PEM format, rename key.pem to ecdsaXXXprivkey.pem (`ecdsa256privkey.pem` for EC curve P-256 and `ecdsa384privkey.pem` for EC curve P-384). Use the compilation flag `DA_FILE=pem` during binary creation.

<a name="http_proxy"></a>

## 6.  SDO credentials REUSE protocol

 SDO credentials’ REUSE feature allows  SDO devices to reuse their ownership credentials across multiple device onboardings. This feature only gets enabled if the owner CRI sends down the same rendezvous info, device GUID information, and public key at the end of the Transfer of Ownership, Step 2 (TO2) protocol.

Specifically, if TO2.SetupDevice.r3, TO2.SetupDevice.g3, and TO2.SetupDevice.pk match the corresponding values held by the device, this will cause the device to not generate an Hash-based Message Authentication Code (HMAC), which then allows the original ownership proxy (OP) to be used for another (and subsequent) onboarding(s) by reusing the same device credentials multiple times.

However, the device will still deactivate  SDO after onboarding and it will need to be reactivated before  SDO can be run again. To activate the device credentials for an already onboarded  SDO device, run the `reuse_oc.sh` script from the root of the repository:

```shell
$ cd <path-to-sdo-client-sdk>
$ ./reuse_oc.sh
```

Activating the device credentials will in turn, activate the  SDO device and configure the  SDO device to run multiple onboarding(s). This can be useful in several test and development environments, where multiple onboardings are common.

> **Note:** To run  SDO Client-SDK binaries in REUSE mode, the following configuration need to be taken care of while launching  SDO CRIs:
> * Set owner CRI property `org.sdo.owner.reuse-enabled=true`.
> * Manufacturer and Owner CRI must share the same key-pair when the TO0 and TO2 protocols are run.
## 7. HTTP-proxy configuration (optional)
If the device is located behind a proxy server, the proxy server details must be provided to the device. For the same purpose, there are three files (each for the manufacturer, rendezvous, and owner servers) in which the proxy server details should be specified in the required format, while connecting to the respective server. These files can be created or removed as required.

Each of the proxy files are located in the `data/` directory and named as follows:

* `mfg_proxy.dat` - holds proxy server network address between the device and manufacturer.
* `rv_proxy.dat` - holding proxy server network address between the device and the rendezvous server.
* `owner_proxy.dat` - holds the proxy server network address between the device and owner.

The following is the format for the proxy server network address:

    <Proxy Server IP>:<proxy Server Port>  e.g. 255.255.255.255:65535

> **Note:** The files `rv_proxy.dat`,`mfg_proxy.dat`, and `owner_proxy.dat` shall not contain any other information beyond the information mentioned above.

The proxy server network address is optional if the device connects to an access point that connects the device through the proxy server.

**Note :**  SDO clients that run on the Linux* OS also support network proxy discovery using the environment variable or the Web Proxy Auto-Discovery (WPAD) protocol based on the libproxy library.
