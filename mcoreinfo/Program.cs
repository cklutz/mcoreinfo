using System;
using System.Collections.Generic;
using SysInfo;

namespace mcoreinfo
{
    class Program
    {
        static int Main(string[] args)
        {
            try
            {
                Console.WriteLine("Processor capabilities:");
                CpuCapabilities.Dump();
                Console.WriteLine();

                Console.WriteLine("Logical to Physical Processor Map:");
                CpuCoreInfo.Dump();
                Console.WriteLine();
                Console.WriteLine("Logical Processor to Socket Map:");
                CpuSocketInfo.Dump();
                Console.WriteLine();
                Console.WriteLine("Logical Processor to NUMA Node Map:");
                CpuNumaNodeInfo.Dump();
                Console.WriteLine();
                Console.WriteLine("Logical Processor to Cache Map:");
                CpuCacheInfo.Dump();
                Console.WriteLine();
                Console.WriteLine("Logical Processor to Group Map:");
                CpuGroupInfo.Dump();
                Console.WriteLine();

                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex);
                return ex.HResult;
            }
        }
    }
}