#sdo tpm yocto project

DESCRIPTION = "Recipe for SDO (client-sdk) on  with tpm"
LICENSE = "Apache-2.0"
BB_STRICT_CHECKSUM = "0"

BB_STRICT_CHECKSUM = "0"
LIC_FILES_CHKSUM = "file://LICENSE;md5=fa818a259cbed7ce8bc2a22d35a464fc"

SRCREV = "e57e7ca325cbd41207561470dec786d947d2f4ca"
SRC_URI = "git://github.com/secure-device-onboard/client-sdk.git"
###SRC_URI[sha256sum] = "f21ab4d2f2ddf83feac2e6d98f79ae1ccf8fdff5ec03661d0a5240928c0d3d7f"

S = "${WORKDIR}/git"

TOOLCHAIN = "POKY-GLIBC"
APP_NAME = "c_code_sdk"
DEPENDS += "openssl"

inherit pkgconfig cmake

DEPENDS += "openssl"
DEPENDS += "tpm2-tss"
DEPENDS += "tpm2-abrmd"
DEPENDS += "tpm2-tools"
DEPENDS += "tpm2-tss-engine"

FILES_${PN} += "/opt \
                /opt/sdotpm \
                /opt/sdotpm/linux-client"
# make command parameters
BUILD = "debug"
HTTPPROXY = "false"
MODULES = "true"
KEX = "ecdh"
AES_MODE = "cbc"
DA = "tpm20_ecdsa256"
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
#patching for yocto
sed -i '1s/^/ln -s \/usr\/lib64\/engines-1.1\/libtpm2tss.so  \/usr\/lib64\/engines-1.1\/tpm2tss.so\n/' ./utils/tpm_make_ready_ecdsa.sh
sed -i 's/usr\/local\/lib\/engines-1.1/usr\/lib64\/engines-1.1/g' ./utils/tpm_make_ready_ecdsa.sh
sed -i 's/usr\/local\/lib\/engines-1.1/usr\/lib64\/engines-1.1/g' cmake/blob_path.cmake


cmake -DHTTPPROXY=${HTTPPROXY} -DMODULES=${MODULES} -DBUILD=${BUILD} -DDA=${DA} -DPK_ENC=${PK_ENC} -DAES_MODE=${AES_MODE} -DKEX=${KEX} -DOPTIMIZE=1 .
make -j$(nproc)
}

do_install() {
    install -d "${D}/opt/sdotpm"
    install "${WORKDIR}/git/build/linux-client" "${D}/opt/sdotpm"
    cp -r "${WORKDIR}/git/utils/tpm_make_ready_ecdsa.sh" "${D}/opt/sdotpm"
    install -d "${D}/opt/sdotpm/data"
    cp -r "${WORKDIR}/git/data/" "${D}/opt/sdotpm/"
    install -d "${D}/opt/sdotpm/data_bkp"
    cp -r "${WORKDIR}/git/data/" "${D}/opt/sdotpm/data_bkp"
}

do_package_qa[noexec] = "1"

INITSCRIPT_PACKAGES = "${PN}"
