# A Guide on phase 1a and 1b demo

## Build rootfs
### Clone and sync the repositories:

```bash
repo init -u  ssh://<username>@git-gar-1.devtools.intel.com:29418/iotg_sdo-manifest -m rpi3.xml

repo sync

cd build

make toolchains

make
```
**Notes**: 
1. Change the username to yours.
2. TODO: The optee repositories file rpi3 needs to be updated, as there are some changes in upstream which makes the current version obsolete.
### Create REE extras:
1. REE extras are extra tools and libraries required in the default rootfs created as a part of optee master branch. For example: curl tool is not part of default rootfs, but to register with Mocana we need curl tool.
2. The developer should install the required tools and libraries in a directory which mirrors the actual rootfs directory structure and create a tar of that directory.
3. In [flash_rpi3.sh](https://github.intel.com/SDO/C-Code-SDK/blob/master/utils/flash_rpi3.sh) line 59, the current name is hardcoded to root_mbedCloud.tar, this means when the user executes flash_rpi3.sh it will consider the tar file root_mbedCloud.tar to patching on the default rootfs.

**TODO**: Change the code to take REE extra as an argument to the script.

### Setting up REE extras for 1a (Mocana) and 1b (mbed CloudClient):
1. The Mocana tools depends on curl tool, bash and java jdk.
2. Developer can use [optee_curl.sh](https://sharepoint.gar.ith.intel.com/sites/BoxCreek_MCU_SW/Shared%20Documents/SDO/jeshwanth-kt/optee_curl.sh) script to cross compile the curl.
3. bash needs to cross compiled and make the part of REE extras. (Recommended to use bash version 4.2 and statically linked binary).
4. Jdk source can be downloaded from this [link](http://hg.openjdk.java.net/aarch64-port/jdk8/file/9a781f9c1338) and follow below commands.


```bash
hg clone http://hg.openjdk.java.net/aarch64-port/jdk8/ jdk8

wget http://openjdk.linaro.org/sysroots/sysroots_140918.tar.xz

tar xf sysroots_140918.tar.xz

cd jdk8

bash get_source.sh

bash cross_configure

bash cross_compile
```
The results will be available in jdk8/build/linux-aarch64-normal-server-release/jdk directory, the entire jdk directory needs to be copied to rootfs (the developer needs to take care of this while building REE extras)

### Construct OSI Package for Mocana:
1. DMS agent transfers a tar file at the stage of OSI transfer, below is the directory structure of the tar file.  
sdej  
├── certificates  
├── DemoUtils.class  
├── device_registration.json  
├── device_registration.sh  
├── docs  
├── jars  
├── Keystore  
├── libs  
├── README-sdej.txt  
├── scripts  
├── SecureDeviceEnroll$1.class  
├── SecureDeviceEnroll.class  
├── setup.sh  
└── version.txt
2. Some directories are delivered by mocana and we have created some scripts to make the registration and enrollment automated for our demo.  
-> certificates directory shall have the certificates transfered from mocana after enroll the device.  
-> device_registration.json shall have the initial settings for provisioning (UUID is mandatory here)  
-> device_registration.sh shall register the device with the configuration mentioned in device_registration.json  
-> setup.sh shall export the environment variables required for Mocana Application, basically  JAVA_HOME.  
-> For more information on running Mocana application follow docs/README_sdec.txt.
3. To understand more about Mocana client enrollment - [Mocana Trust Point Enrollment Client Package](https://sharepoint.gar.ith.intel.com/sites/BoxCreek_MCU_SW/Shared%20Documents/SDO/jeshwanth-kt/Mocana%20TrustPoint%20Enrollment%20Client%20Package.pdf)

### Construct OSI Package for mbedcloud:
1. The OSI package for mbedcloud is a single elf file which is **mbedCloudClientExample.elf**  

**Note:** During the demo the cloud client was not running with 64 bit Optee's rootfs, because the compilation done straightaway on top on x86 configuration with cross compiler. It's recommended to build the binary mbedCloudClientExample.elf with yocto project as as mentioned [here](https://cloud.mbed.com/docs/v1.2/connecting/tutorial-connect-rpi3.html) and copy the same to OSI package tar.

### rc.init and run SDO scripts:

1. rc.init file for Mocana demo is available [here](https://github.intel.com/SDO/C-Code-SDK/blob/master/utils/rc.init_mocana)
2. run_sdo.sh for Mocana is available [here](https://github.intel.com/SDO/C-Code-SDK/blob/master/utils/run_sdo_mocana.sh)
3. rc.init filr for mbed Cloud is available [here](https://github.intel.com/SDO/C-Code-SDK/blob/master/utils/rc.init)
4. run_sdo.sh for mbed cloud is available [here](https://github.intel.com/SDO/C-Code-SDK/blob/master/utils/run_sdo.sh)
5. package.sh for Mocana is available [here](https://sharepoint.gar.ith.intel.com/sites/BoxCreek_MCU_SW/Shared%20Documents/SDO/jeshwanth-kt/package.sh_mocana)
6. package.sh for mbed cloud is available [here](https://sharepoint.gar.ith.intel.com/sites/BoxCreek_MCU_SW/Shared%20Documents/SDO/jeshwanth-kt/package.sh_mbed)

