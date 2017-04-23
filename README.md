# mcoreinfo
An attempt to implement Sysinternals coreinfo tool in managed code (with loads of P/Invoke of course)

## Current status
Current focus is to get the P/Invoke stuff right under 32- and 64-bit.

Only tested on an old quad core (hyperthreading) box under Windows 10.
Output:

        Logical to Physical Processor Map:
        **------ Core 0 (Hyperthreaded)
        --**---- Core 1 (Hyperthreaded)
        ----**-- Core 2 (Hyperthreaded)
        ------** Core 3 (Hyperthreaded)

        Logical Processor to Socket Map:
        ******** Socket 0

        Logical Processor to NUMA Node Map:
        ******** NUMA Node 0

        Logical Processor to Cache Map:
        **------ CacheData        0, Level 1,       32 KB, Assoc  8, LineSize 64
        **------ CacheInstruction 0, Level 1,       32 KB, Assoc  8, LineSize 64
        **------ CacheUnified     0, Level 2,      256 KB, Assoc  8, LineSize 64
        ******** CacheUnified     0, Level 3,    8.192 KB, Assoc 16, LineSize 64
        --**---- CacheData        0, Level 1,       32 KB, Assoc  8, LineSize 64
        --**---- CacheInstruction 0, Level 1,       32 KB, Assoc  8, LineSize 64
        --**---- CacheUnified     0, Level 2,      256 KB, Assoc  8, LineSize 64
        ----**-- CacheData        0, Level 1,       32 KB, Assoc  8, LineSize 64
        ----**-- CacheInstruction 0, Level 1,       32 KB, Assoc  8, LineSize 64
        ----**-- CacheUnified     0, Level 2,      256 KB, Assoc  8, LineSize 64
        ------** CacheData        0, Level 1,       32 KB, Assoc  8, LineSize 64
        ------** CacheInstruction 0, Level 1,       32 KB, Assoc  8, LineSize 64
        ------** CacheUnified     0, Level 2,      256 KB, Assoc  8, LineSize 64

        Logical Processor to Group Map:
        ******** Group 0