OPENSSL_ROOT=/opt/openssl
CURL_ROOT=/opt/curl
CURL_VER="8.4.0"
CURL_LINK="https://curl.se/download/curl-8.4.0.tar.gz --no-check-certificate"

PARENT_DIR=`pwd`
cd $PARENT_DIR



install() 
{  
    OPENSSL_LINK="https://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz --no-check-certificate"
    echo "Build & Install OpenSSL version : $OPENSSL_VER"
    cd $PARENT_DIR
    rm -f openssl-$OPENSSL_VER.tar.gz
    wget $OPENSSL_LINK
    tar -xvzf openssl-$OPENSSL_VER.tar.gz
    cd openssl-$OPENSSL_VER

    ./config --prefix=$OPENSSL_ROOT --openssldir=/usr/local/ssl
    make -j$(nproc)
    make install
    
    grep -qxF '$OPENSSL_ROOT/lib64/' /etc/ld.so.conf.d/libc.conf || echo $OPENSSL_ROOT/lib64/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
    ldconfig
	
    echo "Build & Install Curl version : $CURL_VER"
    cd $PARENT_DIR
    wget $CURL_LINK
    tar -xvzf curl-$CURL_VER.tar.gz
    cd curl-$CURL_VER

    ./configure --prefix=$CURL_ROOT --with-openssl=$OPENSSL_ROOT --with-nghttp2 --enable-versioned-symbols
    make -j$(nproc)
    make install
    
    $OPENSSL_ROOT/bin/openssl version
    $CURL_ROOT/bin/curl -V
}


uninstall()
{
    OPENSSL_LINK="https://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz --no-check-certificate"
    echo "Uninstall OpenSSL version : $OPENSSL_VER"
	
    cd $PARENT_DIR
    rm -f openssl-$OPENSSL_VER.tar.gz
    wget $OPENSSL_LINK
    tar -xvzf openssl-$OPENSSL_VER.tar.gz
    cd openssl-$OPENSSL_VER

    ./config
    make -j$(nproc)
    make uninstall
    rm /usr/bin/openssl
    rm -rf openssl-$OPENSSL_VER
    rm -f openssl-$OPENSSL_VER.tar.gz
    ldconfig
}

usage()
{
    echo -e "Usage:
        ./$0 <OPTION>\n
        OPTION:
            -i - Install OpenSSL.
	          -u - Uninstall OpenSSL. (e.g. -v 3.0.8)
            -v - OpenSSL Version
            -h - Help."
}


parse_args()
{
    #Modes
    INSTALL=1
    UNINSTALL=2

    mode=0

    while getopts "iuv:h" opt; do
        case $opt in
            (i) mode=$(($mode | $INSTALL));;
            (u) mode=$(($mode | $UNINSTALL));;
            (v) OPENSSL_VER=${OPTARG};;
            (h | *) usage;
                    exit;;
        esac
    done

    if [ $mode -eq $INSTALL ]; then
        install $OPENSSL_VER
    elif [ $mode -eq $UNINSTALL ]; then
        uninstall $OPENSSL_VER
    else
        echo -e "Invalid argument!\n"
        usage
    fi
}

parse_args "$@"
