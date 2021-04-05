# Ownership Transfer: TO1, TO2 protocols:
During this time, FDO Client SDK assumes that the Ownership Voucher is already transferred from the Manufacturer to the Owner, and the Owner has registered itself to the Rendezvous
Server, i.e. TO0 is successful. FDO Client SDK, then connects to FDO PRI Rendezvous and PRI Owner subsequently.

If the RendezvousInfo in the Ownership Voucher contains RendezvousInstr `RVBYPASS`, then TO0 completion is not required. In such a scenario, FDO Client SDK connects directly to the FDO PRI Owner.

Refer to the [FDO PRI Rendezvous](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md) and
[FDO PRI Owner](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md) for details on setup and configuration.
