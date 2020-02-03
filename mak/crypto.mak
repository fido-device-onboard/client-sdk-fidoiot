ifeq ($(DA), ecdsa256)
    ifneq ($(DA_FILE), pem)
        CRYPTO_CFLAGS += -DECDSA_PRIVKEY=\"ecdsa256privkey.dat\"
    else
        CRYPTO_CFLAGS += -DECDSA_PRIVKEY=\"ecdsa256privkey.pem\"
    endif
else
    ifneq ($(DA_FILE), pem)
        CRYPTO_CFLAGS += -DECDSA_PRIVKEY=\"ecdsa384privkey.dat\"
    else
        CRYPTO_CFLAGS += -DECDSA_PRIVKEY=\"ecdsa384privkey.pem\"
    endif
endif
