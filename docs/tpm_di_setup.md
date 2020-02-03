# Device Intialization SCT Setup
Device obtains SDO credentials from manufacturer SCT and this process is known as Device
Initialization.

Open a terminal and start SDO manufacturer SCT server. Post this step an ownership proxy
is generated so, that the new owner can now initiate TO0 protocol.

Detailed steps and configuration needed to start SDO manufacturer can be found in 
`<release-package-dir>/SupplyChainTools/docker_manufacturer/README.md` document.

# Device Intialization Device Setup

During this time, device does not have SDO credentials and will obtain the same from manufacturer SCT.
