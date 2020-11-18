# For Arm* Mbed* Linux* (Arm Cortex*-A7) OS-Based Implementation
## About

This document can be used as a quick guide to build and execute Secure Device Onboard (SDO) client-sdk on the Arm Cortex-A7 platform running the Arm Mbed* Linux* OS. To build and execute the SDO client-sdk on other target platforms (For example, Linux OS and Arm Mbed OS), refer to [this](setup.md) document.

## Hardware Requirements:
- WaRP7* development platform with an [i.MX 7Solo](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/i.mx-applications-processors/i.mx-7-processors/i.mx-7solo-processors-heterogeneous-processing-with-arm-cortex-a7-and-cortex-m4-cores:i.MX7S) processor.
- Two MICROUSB cables (one for power supply, another for serial communication).

***Note :*** WaRP7 is a deprecited hardware. Client-sdk tested on it. But client-sdk can work on any mbedlinux boards for A7.

## Software Requirements:
This implementation is built using Yocto Project* and provides facilities to run SDO client-sdk in the context of the Arm Mbed Linux software. The following are the requirements:

- Linux OS (Ubuntu* OS version 20.04 LTS) as the host machine.

> ***Note:*** Compilation steps are documented in the [ sdo-client-sdk for Arm Mbed Linux OS](mbed_linux.md) readme file.

## Building Arm Mbed Linux OS
Download and build the Arm Mbed Linux OS source code, after following the steps mentioned in [this](https://github.com/ARMmbed/mbl-docs/tree/v0.9/Docs) link. **Use 0.9 release brach for all repos.**

> ***Note:*** The current supported version of the Arm Mbed Linux OS is `mbl-os-0.9`.

On successful build completion, a new directory named `build-warp7` will be created.

## Building Required Dependencies
Place all required dependencies under the `build-warp7` directory for the final SDO client-sdk build.

## Building SDO client-sdk
The SDO client-sdk for Arm Cortex-A7 platform is built using the Yocto Project-based build system. Follow these instructions to generate the SDO client-sdk binaries:

1. Add the required SDO manifest layer after copying the `meta-intel-sdo` layer to the appropriate location under the `build-warp7` directory:
```shell
	$ mkdir -p build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/meta-intel-sdo/recipes-connectivity
	
	$ cp -rf <release-package-dir>/sdo-client-sdk/utils/meta-intel-sdo/conf build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/meta-intel-sdo/conf
	
	$ cp -rf <release-package-dir>/sdo-client-sdk/utils/meta-intel-sdo/recipes-connectivity/clientsdk-mbedtls build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/meta-intel-sdo/recipes-connectivity/clientsdk-mbedtls
```

3. Modify `clientsdk-mbedtls.bb` inside build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/meta-intel-sdo/recipes-connectivity/clientsdk-mbedtls folder to configure and build the client-sdk source code for configurations other than the default (optional).

>***Note:*** By default, `clientsdk-mbedtls.bb` is configured with the default build configuration for Mbed Linux. To see the SDO default configuration and other details, refer to the [Building  SDO client-sdk](build_conf.md) section of the `<release-package-dir>/client-sdk/README.md` document.

4. Add the `meta-intel-sdo` layer information by setting the `BBLAYERS` flag in the BitBake configuration file (the BitBake configuration file can be found at `build-warp7/machine-imx7s-warp-mbl/mbl-manifest/conf/bblayers.conf`):

```shell
    BBLAYERS = ${OEROOT}/layers/meta-intel-sdo
```

5. Specify to install SDO `clientsdk-mbedtls` packages into the image by setting the `IMAGE_INSTALL_APPEND` flag in the local configuration file (the local configuration file can be found at `build-warp7/machine-imx7s-warp-mbl/mbl-manifest/conf/local.conf`):

```shell
    IMAGE_INSTALL_APPEND = "clientsdk-mbedtls"
```

6. Re-run the build command as you did in the [Building Arm Mbed Linux OS](#building-mbed-linux) step.
> ***Note:*** If the `imx7s-warp.dtb` file is not generated during build, refer to [this](https://github.com/WaRP7/linux-fslc/) link to generate the file.

## Flashing and Preparing the Device

To flash the WaRP7 device with the build image, follow the steps in the [this](https://os.mbed.com/docs/mbed-linux-os/v0.6/first-image/warp7-devices.html) link.

After the device is flashed, use the [Setting up a WI-FI* connection](https://github.com/ARMmbed/mbl-docs/blob/v0.9/Docs/install_mbl_on_device/connect_network_and_pelion/connect_network.md) connect the device to the Wi-Fi* network for the first time.

## Running SDO
After a successful flash, the  SDO Cortex-A7 device executable can be found at `<device-root>/opt/sdo/linux-client`. Follow the steps in the [Execution](./linux.md#run_linux_sdo) section of [this](./linux.md) document to run the SDO Cortex-A7 application against the SDO Customer Reference Implementation (CRI) implementation.
