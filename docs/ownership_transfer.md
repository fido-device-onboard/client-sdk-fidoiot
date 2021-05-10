# Ownership Transfer: TO1, TO2 Protocols
During this time, FDO Client SDK assumes that the Ownership Voucher is already transferred from the Manufacturer to the Owner, and the Owner has registered itself to the Rendezvous
Server, that is, TO0 is successful. FDO Client SDK, then connects to FDO PRI Rendezvous during TO1 protocol and FDO PRI Owner subsequently during TO2 protocol.

If the RendezvousInfo in the Ownership Voucher contains RendezvousInstr `RVBYPASS`, then TO0 completion is not required. In such a scenario, FDO Client SDK skips TO1 protocol and connects directly to the FDO PRI Owner to execute TO2 protocol.

Refer to the [FDO PRI Rendezvous](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/rv/README.md) and
[FDO PRI Owner](https://github.com/secure-device-onboard/pri-fidoiot/blob/master/component-samples/demo/owner/README.md) for details on setup and configuration.
