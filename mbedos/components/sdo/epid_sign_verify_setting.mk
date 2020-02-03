#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# EPID specific defines for signing and verification
ifneq ("$(SDO_CACERT)", "")
    DFLAGS += -DSDO_CACERT=\"cacert\"
else
    $(error SDO_CACERT is not defined, export SDO_CACERT=<filename>)
endif
ifneq ("$(SDO_CRED_NORMAL)", "")
    DFLAGS += -DSDO_CRED_NORMAL=\"normal\"
else
    $(error SDO_CRED_NORMAL is not defined, export SDO_CRED_NORMAL=<filename>)
endif
ifneq ("$(SDO_CRED_SECURE)", "")
    DFLAGS += -DSDO_CRED_SECURE=\"secure\"
else
    $(error SDO_CRED_SECURE is not defined, export SDO_CRED_SECURE=<filename>)
endif
ifneq ("$(SDO_CRED_MFG)", "")
    DFLAGS += -DSDO_CRED_MFG=\"mfg\"
else
    $(error SDO_CRED_MFG is not defined, export SDO_CRED_MFG=<filename>)
endif
ifneq ("$(RAW_BLOB)", "")
    DFLAGS += -DRAW_BLOB=\"raw\"
else
    $(error RAW_BLOB is not defined, export RAW_BLOB=<filename>)
endif
ifneq ("$(EPID_PRIVKEY)", "")
    DFLAGS += -DEPID_PRIVKEY=\"privkey\"
else
    $(error EPID_PRIVKEY is not defined, export EPID_PRIVKEY=<filename>)
endif
ifneq ("$(SDO_PUBKEY)", "")
    DFLAGS += -DSDO_PUBKEY=\"pubkey\"
else
    $(error SDO_PUBKEY is not defined, export SDO_PUBKEY=<filename>)
endif
ifneq ("$(SDO_SIGRL)", "")
    DFLAGS += -DSDO_SIGRL=\"sigrl\"
else
    $(error SDO_SIGRL is not defined, export SDO_SIGRL=<filename>)
endif
