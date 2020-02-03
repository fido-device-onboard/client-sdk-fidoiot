#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#

ifneq ("$(HTTPPROXY)", "false")
ifneq ("$(MFG_PROXY)", "")
    DFLAGS += -DMFG_PROXY=\"mfg_proxy\"
endif
ifneq ("$(RV_PROXY)", "")
    DFLAGS += -DRV_PROXY=\"rv_proxy\"
endif
ifneq ("$(OWNER_PROXY)", "")
    DFLAGS += -DOWNER_PROXY=\"owner_proxy\"
endif
endif
