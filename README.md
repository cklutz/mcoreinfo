# mcoreinfo
An attempt to implement Sysinternals coreinfo tool in managed code (with loads of P/Invoke of course)

## Current status

Supports the following (in terms of "coreinfo.exe"):

* CPUID/Capabilities
* "Logical to Physical processor Map"
* "Logical Processor to Socket Map"
* "Logical Processor to NUMA Map"
* "Logical Processor to Cache Map"
* "Logical Processor to Group Map"

Open:

* "Approximate Cross-NUMA Node Access Cost (relative to fastest)" on NUMA sytems.
  * Currently, reading APIC SLIT and SRAT tables.

