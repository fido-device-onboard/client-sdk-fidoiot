# For Arm* Mbed* Linux* (Arm Cortex*-A7) OS-based Implementation
## About

This document can be used as a quick guide to build and execute Secure Device Onboard (SDO) client-sdk on the Arm Cortex-A7 platform running the Arm Mbed* Linux* OS. To build and execute the SDO client-sdk on other platforms (e.g. Linux OS and Arm Mbed OS), refer to [this](setup.md) document.

## Hardware requirements:
- WaRP7* development platform with an [i.MX 7Solo](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/i.mx-applications-processors/i.mx-7-processors/i.mx-7solo-processors-heterogeneous-processing-with-arm-cortex-a7-and-cortex-m4-cores:i.MX7S) processor.
- Two MICROUSB cables (one for power supply, another for serial communication).

## Software requirements:

This implementation is built using Yocto Project* and provides facilities to run  SDO client-sdk in the context of the Arm Mbed Linux software. The following are the requirements:

- Linux OS (Ubuntu* OS version 16.04 LTS) as the host machine.
- Arm cross-compiler, can be installed using the command:
```shell
$ sudo apt-get install gcc-arm-linux-gnueabi gcc-multilib-arm-linux-gnueabi
```

> **Note:** Compilation steps are documented in the [ sdo-client-sdk for Arm Mbed Linux OS](mbed_linux.md) readme file.

## Building Arm Mbed Linux OS
Download and build the Arm Mbed Linux OS source code, after following the steps mentioned in [this](https://os.mbed.com/docs/mbed-linux-os/v0.9/getting-started/building-an-mbl-image.html) link. 

> **Note:** The current supported version of the Arm Mbed Linux OS is `mbl-os-0.9`.

On successful build completion, a new directory named `build-warp7` will be created.

## Building required dependencies
Place all required dependencies under the `build-warp7` directory for the final  SDO client-sdk build.

### Intel safestringlib
Download safestringlib from <a href="https://github.com/intel/safestringlib">intel-safestringlib</a>, and follow these instructions to build safestringlib with the Arm cross-compiler:

1. Clone `safestringlib` into the `build-warp7` directory and check out to tag `v1.0.0`:

```shell
$ cd build-warp7/
$ git clone git@github.com:intel/safestringlib.git
$ cd safestringlib/
$ git checkout -b v1.0.0
```

2. Adapt `safestringlib/makefile` to use the Arm cross-compiler by modifying `CC`, `CFLAGS`, and `LDFLAGS` variables to the values given as follows:

* `CC=arm-linux-gnueabi-gcc`
* `CFLAGS=-I$(IDIR) -fstack-protector-strong -fPIE -fPIC -O2 -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -march=armv7ve -marm -mfpu=neon-vfpv4 -mfloat-abi=hard -mcpu=cortex-a7`
* `LDFLAGS=-z noexecstack -z relo -z now -march=armv7ve -marm -mfpu=neon-vfpv4 -mfloat-abi=hard -mcpu=cortex-a7`

3. Build the `safestringlib` source:

```shell
$ mkdir obj
$ make libsafestring.a
```

After this step, the `libsafestring.a` library is created.

## Building  SDO client-sdk
The  SDO client-sdk for Arm Cortex-A7 platform is built using the Yocto Project-based build system. Follow these instructions to generate the  SDO client-sdk binaries:

1. Add the required  SDO manifest layer after copying the `meta-intel-sdo` layer to the appropriate location under the `build-warp7` directory:
```shell
$ cp <release-package-dir>/sdo-client-sdk/utils/meta-intel-sdo build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/
```

2. Create `sdo.tar.gz` by renaming the `c-device-sdk` directory to `sdo` and place it in an appropriate location under the `build-warp7` directory:
```shell
$ cd <release-package-dir>
$ mv sdo-client-sdk/ sdo/
$ tar -czvf sdo.tar.gz sdo/
$ cp sdo.tar.gz build-warp7/machine-imx7s-warp-mbl/mbl-manifest/layers/meta-intel-sdo/recipes-connectivity/
```

3. Modify `c-code-sdk.bb` to configure and build the c-code-sdk source code for configurations other than the default (optional).

>**Note:** By default, `c-code-sdk.bb` is configured with the default build configuration. To see the  SDO default configuration and other details, refer to the [Building  SDO c-code-sdk](build_conf.md) section of the `<release-package-dir>/c-code-sdk/README.md` document.

4. Add the `meta-intel-sdo` layer information by setting the `BBLAYERS` flag in the BitBake configuration file (the BitBake configuration file can be found at `build-warp7/machine-imx7s-warp-mbl/mbl-manifest/conf/bblayers.conf`):

```shell
    BBLAYERS = ${OEROOT}/layer/meta-intel-sdo
```

5. Specify to install  SDO `c-code-sdk` packages into the image by setting the `IMAGE_INSTALL_APPEND` flag in the local configuration file (the local configuration file can be found at `build-warp7/machine-imx7s-warp-mbl/mbl-manifest/conf/local.conf`):

```shell
    IMAGE_INSTALL_APPEND = "c-code-sdk"
```

6. Re-run the build command as you did in the [Building Arm Mbed Linux OS](#building-mbed-linux) step.
> **Note:** If the `imx7s-warp.dtb` file is not generated during build, refer to [this](https://github.com/WaRP7/linux-fslc/) link to generate the file.

## Flashing and preparing the device

To flash the WaRP7 device with the build image, follow the steps in the [this](https://os.mbed.com/docs/mbed-linux-os/v0.6/first-image/warp7-devices.html) link.

After the device is flashed, use the [Setting up a WI-FI* connection](https://os.mbed.com/docs/mbed-linux-os/v0.6/first-image/connecting-to-a-network-and-pelion-device-management.html#setting-up-a-wi-fi-connection) link to connect the device to the Wi-Fi* network for the first time.

## Running  SDO
After a successful flash, the  SDO Cortex-A7 device executable can be found at `<device-root>/opt/arm/linux-client`. Follow the steps in the [Execution](./linux.md#run_linux_sdo) section of [this](./linux.md) document to run the  SDO Cortex-A7 application against the  SDO Customer Reference Implementation (CRI) implementation.
