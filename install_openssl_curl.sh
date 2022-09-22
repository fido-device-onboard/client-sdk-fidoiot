#OPENSSL_VER=""
CURL_VER="7.85.0"
CURL_LINK="https://github.com/curl/curl/releases/download/curl-7_85_0/curl-7.85.0.tar.gz --no-check-certificate"

PARENT_DIR=`pwd`
cd $PARENT_DIR



install() 
{  
	sudo apt remove curl libcurl4-openssl-dev
    #yum remove curl libcurl-devel openssl-devel
    OPENSSL_LINK="https://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz --no-check-certificate"
    echo "Build & Install OpenSSL version : $OPENSSL_VER"
    cd $PARENT_DIR
    rm -f openssl-$OPENSSL_VER.tar.gz
    wget $OPENSSL_LINK
    tar -xvzf openssl-$OPENSSL_VER.tar.gz
    cd openssl-$OPENSSL_VER

    ./config
    make -j$(nproc)
    mv /usr/bin/openssl ~/tmp
    make install
    
    ln -s /usr/local/bin/openssl /usr/bin/openssl
	cat /usr/local/lib64/ >> /etc/ld.so.conf.d/libc.conf
	grep -qxF '/usr/local/lib64/' /etc/ld.so.conf.d/libc.conf || echo /usr/local/lib64/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
    ldconfig
    openssl version
	
    echo "Build & Install Curl version : $CURL_VER"
    cd $PARENT_DIR
    wget $CURL_LINK
    tar -xvzf curl-$CURL_VER.tar.gz
    cd curl-$CURL_VER

    ./configure --with-openssl=$PARENT_DIR/openssl-$OPENSSL_VER
    make -j$(nproc)
    make install
    
	grep -qxF '/usr/local/lib64/' /etc/ld.so.conf.d/libc.conf || echo /usr/local/lib64/ | sudo tee -a /etc/ld.so.conf.d/libc.conf
    ldconfig
	openssl version
    curl --version
	ln -fs /usr/lib/libcurl.so.4 /usr/local/lib/
	ldconfig
	
	
}


uninstall()
{
	OPENSSL_LINK="https://www.openssl.org/source/openssl-$OPENSSL_VER.tar.gz --no-check-certificate"
    echo "Uninstall OpenSSL version : $OPENSSL_VER"
	apt remove curl libssl-dev libcurl4-openssl-dev
	#yum remove curl libcurl-devel openssl-devel
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
            -u - Uninstall OpenSSL.
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
