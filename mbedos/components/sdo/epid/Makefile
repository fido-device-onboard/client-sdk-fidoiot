BASE_DIR :=.

include ../../../base.mk

$(shell ln -sfn $(EPID_SDK_R6_ROOT) epid-sdk-v601)

CFLAGS += -Wno-error=missing-braces -Wno-error=unknown-pragmas -Wno-error=comment

IGNORE_LIST +='epid/common-testhelper/*\n'
IGNORE_LIST +='epid/common/src/*.o\n'
IGNORE_LIST +='epid/common/src/*.d\n'
IGNORE_LIST +='epid/common/1.1/*.c\n'
IGNORE_LIST +='epid/common/1.1/src/*.c\n'
IGNORE_LIST +='epid/common/1.1/src/*.o\n'
IGNORE_LIST +='epid/common/1.1/src/*.d\n'
#IGNORE_LIST +='epid/common/1.1/src/unittests/*\n'
IGNORE_LIST +='epid/common/1.1/unittests/file_parser-test.cc\n'
IGNORE_LIST +='epid/common/unittests/*\n'
IGNORE_LIST +='epid/common/math/unittests/*\n'
IGNORE_LIST +='epid/common/math/src/*.o\n'
IGNORE_LIST +='epid/member/src/*.o\n'
IGNORE_LIST +='epid/member/src/*.d\n'
IGNORE_LIST +='epid/member/tiny/*\n'
IGNORE_LIST +='epid/member/tiny/*\n'
#IGNORE_LIST +='epid/member/tpm2/*\n'
IGNORE_LIST +='epid/member/tpm2/src/*.o\n'
IGNORE_LIST +='epid/member/tpm2/src/*.d\n'
IGNORE_LIST +='epid/member/tpm2/ibm_tss/*\n'
#IGNORE_LIST +='epid/member/tpm2/src/*\n'
IGNORE_LIST +='epid/member/tpm2/unittests/*\n'
IGNORE_LIST +='epid/member/unittests/*\n'
IGNORE_LIST +='epid/verifier/*\n'
IGNORE_LIST +='epid/verifier/1.1/*\n'
IGNORE_LIST +='epid/verifier/src/*\n'
IGNORE_LIST +='epid/verifier/unittests/*\n'
IGNORE_LIST +='example/*\n'
IGNORE_LIST +='ext/argtable3/*\n'
IGNORE_LIST +='ext/gtest/*\n'
IGNORE_LIST +='ext/ippcp/src/*.o\n'
IGNORE_LIST +='ext/ipp/sources/ippcp/src/*.d\n'
IGNORE_LIST +='ext/ipp/sources/ippcp/src/*.o\n'
IGNORE_LIST +='parts-site/*\n'
IGNORE_LIST +='tools/*\n'
IGNORE_LIST +='_install/*\n'

EPID_DFLAGS := -D_IPP_v50_ -D_IPP_DEBUG -D_DISABLE_ALG_MD5_ -D_DISABLE_ALG_SM3_

.PHONY: all clean

all:
	$(ECHOM) $(IGNORE_LIST) > ./epid-sdk-v601/.mbedignore
#	mbed-cli compile -m $(BOARD) -t GCC_ARM --library --no-archive --source=epid-sdk-v601 --build=../../$(OBJ_DIR_EPID) $(EPID_DFLAGS) -v
clean:
	rm -rf $(OBJ_DIR_EPID)
	unlink epid-sdk-v601
