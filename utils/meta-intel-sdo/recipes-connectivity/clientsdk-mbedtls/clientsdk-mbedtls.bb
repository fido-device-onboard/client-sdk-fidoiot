#SDO yocto project

DESCRIPTION="Recipe for SDO (client-sdk) on linux with mbedtls"
LICENSE = "Apache-2.0"
BB_STRICT_CHECKSUM = "0"

LIC_FILES_CHKSUM = "file://LICENSE;md5=fa818a259cbed7ce8bc2a22d35a464fc"

SRCREV = "d5cbe0a5c060bbedfa75c42fb802cc3abe6b5d68"
SRC_URI = "git://github.com/secure-device-onboard/client-sdk.git"
#SRC_URI[sha256sum] = "c821a9afa9f987ac829fb3a8dd72122c3c612b0c25c9c0fe03201f7e1081f183"

S = "${WORKDIR}/git"

TOOLCHAIN = "POKY-GLIBC"
APP_NAME = "c_code_sdk"
DEPENDS += "mbedtls"

inherit pkgconfig cmake

INSANE_SKIP_${PN} = "dev-elf"
INSANE_SKIP_${PN} = "ldflags"
INSANE_SKIP_${PN}-dev = "ldflags"
PACKAGES = "${PN}"
INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
INHIBIT_PACKAGE_STRIP = "1"
INHIBIT_SYSROOT_STRIP = "1"
FILES_${PN} += "/opt \
                /opt/sdo \
                /opt/sdo/linux-client"
# make command parameters
BUILD = "debug"
HTTPPROXY = "false"
MODULES = "true"
KEX = "ecdh384"
AES_MODE = "cbc"
DA = "ecdsa384"
PK_ENC = "ecdsa"

do_configure(){
}

do_compile(){
CUR_DIR=$(pwd)
cd "${WORKDIR}/git"

cd ${CUR_DIR}/../

if [ ! -d "safestringlib" ] ; then
	git clone git://github.com/intel/safestringlib.git
fi
export SAFESTRING_ROOT=${CUR_DIR}/../safestringlib
cd ${SAFESTRING_ROOT}
rm -rf makefile
sed -i '/mmitigate-rop/d' ./CMakeLists.txt
cmake .
make
cp libsafestring_static.a libsafestring.a

echo " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< "
echo "${S}":"${DA}":"${BUILD}":"${PK_ENC}":"${AES_MODE}":"${KEX}"
echo " >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< "
cd ${S}
cmake -DTLS=mbedtls -DHTTPPROXY=${HTTPPROXY} -DMODULES=${MODULES} -DBUILD=${BUILD} -DDA=${DA} -DPK_ENC=${PK_ENC} -DAES_MODE=${AES_MODE} -DKEX=${KEX} -DOPTIMIZE=1 . ;
make -j$(nproc)
}

do_install() {
    install -d "${D}/opt/sdo"
    install "${WORKDIR}/git/build/linux-client" "${D}/opt/sdo"
    install -d "${D}/opt/sdo/data"
    cp -r "${WORKDIR}/git/data/" "${D}/opt/sdo/"
    install -d "${D}/opt/sdo/data_bkp"
    cp -r "${WORKDIR}/git/data/" "${D}/opt/sdo/data_bkp"
}

do_package_qa[noexec] = "1"

INITSCRIPT_PACKAGES = "${PN}"
