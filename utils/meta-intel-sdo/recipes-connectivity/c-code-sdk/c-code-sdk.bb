DESCRIPTION="Recipe for sdo (c-code-sdk) on mbed-linux"
TOOLCHAIN = "POKY-GLIBC"
LICENSE = "CLOSED"
S = "${WORKDIR}"

DEPENDS += "mbedtls"

INSANE_SKIP_${PN} = "dev-elf"
INSANE_SKIP_${PN} = "ldflags"
INSANE_SKIP_${PN}-dev = "ldflags"  
PACKAGES = "${PN}"
INHIBIT_PACKAGE_DEBUG_SPLIT = "1"
INHIBIT_PACKAGE_STRIP = "1"
INHIBIT_SYSROOT_STRIP = "1"
FILES_${PN} += "/opt \
                /opt/arm \
                /opt/arm/linux-client" 


FILESEXTRAPATHS_prepend := "${THISDIR}:"
SRC_URI = "file://sdo.tar.gz"


do_configure(){
}

do_compile(){
CUR_DIR=$(pwd)
cd "${WORKDIR}/sdo"
export CFLAGS="-D_IPP_v50_ -D_IPP_DEBUG -D_DISABLE_ALG_MD5_ -mfloat-abi=hard -D_DISABLE_ALG_SM3_ -Wstrict-aliasing -g -D_FORTIFY_SOURCE=2 HTTPPROXY=false"
export SAFESTRING_ROOT=${TOPDIR}/../../../safestringlib
#export EPID_SDK_R6_ROOT=${TOPDIR}/../../../epid-sdk
export MODULES=false
export ARCH=arm
CFLAGS="${CFLAGS}" make TLS=mbedtls PK_ENC=rsa DA=ecdsa256 pristine 
CFLAGS="${CFLAGS}" make TLS=mbedtls PK_ENC=rsa DA=ecdsa256
cd ${CUR_DIR}
}

do_install() {
    install -d "${D}/opt/arm"
    install "${WORKDIR}/sdo/build/linux/debug/linux-client" "${D}/opt/arm"
    install -d "${D}/opt/arm/data"
    cp -r "${WORKDIR}/sdo/data/" "${D}/opt/arm/"
    install -d "${D}/opt/arm/data_bkp"
    cp -r "${WORKDIR}/sdo/data/" "${D}/opt/arm/data_bkp"
}

do_package_qa[noexec] = "1"

INITSCRIPT_PACKAGES = "${PN}"
