# A Guide to build Linux Image with SDO and mbed cloud client for Raspberry pi 3

# Table of Contents
1. [Software Requirement](#Software_Requirement)
2. [Repository Access](#Repository_Access)
3. [Building](#Building)
4. [Flashing](#Flashing)
5. [Running](#Running)



## 1. Software Requirements:<a name="Software_Requirement"></a>
1. Ubuntu Linux 16.04
2. mbed-cli (version 1.7.5). [mbed-cli](https://pypi.org/project/mbed-cli/)
3. ARM Cross compiler - install using below command.
```bash
sudo apt install gcc-arm-linux-gnueabi 
sudo apt-get install gcc-multilib-arm-linux-gnueabi
```
4. Following package needs to be installed.
```bash
sudo apt-get install mercurial
sudo apt-get install whois
sudo apt-get install libmbedtls-dev
sudo pip install click
sudo pip install requests
```
5. Configure proxy to clone - Follow [Yocto project setup start guide](https://www.intel.com/content/dam/www/public/us/en/documents/guides/atom-soc-for-yocto-getting-started-guide.pdf?asset=14077) - (In gitproxy file use IP as proxy.png.intel.com)
6. Please create github acount with Intel email and upload your mahine's ssh public key there.

## 2. Repository Access: <a name="Repository_Access"></a>
Send repository access request mail to jeshwanth.kumar.nk@intel.com and cc rohit.dhawan@intel.com for below repositories access.
1. https://github.intel.com/jkumarnk/mbed-cloud-client-yocto-setup_sdo
2. https://github.intel.com/jkumarnk/meta-sdo
3. https://github.intel.com/jkumarnk/safestring_arm
4. https://github.intel.com/jkumarnk/meta-mbed-cloud-client
5. https://github.intel.com/jkumarnk/meta-myhello

## 3. Building:<a name="Building"></a>

Ready for yocto build:
```bash
sudo mkdir /var/cache/bitbake
sudo chown <build-username>:<build-username> /var/cache/bitbake
```
Clone mbed-cloud-client-yocto-setup_sdo latest version and deploy the dependent repositories:

```bash
git clone git@github.intel.com:jkumarnk/mbed-cloud-client-yocto-setup_sdo.git

cd mbed-cloud-client-yocto-setup_sdo

mbed deploy #ignore WARNING

cd C-SDK-Device-Modules

./build_modules.sh

cd ..

```

Edit Variable MANUFACTURER_DN in file layers/meta-sdo/recipes-connectivity/C-Code-SDK/C-Code-SDK.bb which pointing to your Manufacturer IP.
Note: This will be changed in future to set with environment variable.


Build using below command to generate binary:
```bash
make -f Makefile.example EXTRA_CONF_FILE=1 all
```
Note: This will take sometime for first time build.

## 4. Flashing: <a name="Flashing"></a>
Flash the generated image to Micro SD card using card reader using below command:

```bash
sudo dd if=rpi-build/tmp/deploy/images/raspberrypi3/mbed-cloud-client-example-image-raspberrypi3.rpi-sdimg of=/dev/sdX bs=4M
```
sdX is the device name assigned by your operating system.

## 5. Running: <a name="Running"></a>

Insert the micro SD card into RPI3 micro SD card slot, and power it up.

open the serial terminal of your choice with baudrate 115200: (picocom recommended)

```bash
picocom /dev/ttyUSB0 -b 115200 -l
```
The RPI3 terminal is available.

The cloud client and SDO application binaries will be available in /opt/arm directory.

1. Run for DI:
```bash

cd /opt/arm

./linux-client
```

Output:
```bash

------------------------------------ DI Successful --------------------------------------
```

2. Run for Onboarding TO1 and TO2: (Please extend the proxy in CRI side before running below command)

```bash
./linux-client
```

Output:

```bash
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@Secure Device Onboarding Complete@
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

3. Run mbed cloud client example:

```bash
./mbedCloudClientExample.elf
```

Output:

```bash
Client registered
Endpoint Name: 01688416601000000000000100100224
Device Id: 01688416601000000000000100100224

```
