CURL_VER="7.88.0"
CURL_LINK="https://github.com/curl/curl/releases/download/curl-7_88_0/curl-7.88.0.tar.gz --no-check-certificate"

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

    ./config --libdir=/usr/local/lib
    make -j$(nproc)
    mv /usr/bin/openssl ~/tmp
    make install
    
    ln -s /usr/local/bin/openssl /usr/bin/openssl
    grep -qxF '/usr/local/lib/' /etc/ld.so.conf.d/libc.conf || echo /usr/local/lib/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
    ldconfig
    openssl version
	
    echo "Build & Install Curl version : $CURL_VER"
    cd $PARENT_DIR
    wget $CURL_LINK
    tar -xvzf curl-$CURL_VER.tar.gz
    cd curl-$CURL_VER

    ./configure --with-openssl=$PARENT_DIR/openssl-$OPENSSL_VER --enable-versioned-symbols
    make -j$(nproc)
    make install
    
    ldconfig
    openssl version
    curl --version
	
	
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