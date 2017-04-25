using System;
using System.Collections.Generic;
using SysInfo;

namespace mcoreinfo
{
    class Program
    {
        static void Usage()
        {
            Console.WriteLine(@"
Usage: mcoreinfo [-c][-f][-g][-l][-n][-s][-m][-v]
  -c       Dump information on cores.
  -f       Dump core feature information.
  -g       Dump information on groups.
  -l       Dump information on caches.
  -n       Dump information on NUMA nodes.
  -s       Dump information on sockets.
  -m       Dump NUMA access cost.
");
        }

        static int Main(string[] args)
        {
            bool dumpCoreInfo = false;
            bool dumpCoreFeatures = false;
            bool dumpGroups = false;
            bool dumpCaches = false;
            bool dumpNuma = false;
            bool dumpSockets = false;
            bool dumpNumaCost = false;
            bool dumpVirt = false;

            if (args.Length == 0)
            {
                dumpCoreInfo = true;
                dumpCoreFeatures = true;
                dumpGroups = true;
                dumpCaches = true;
                dumpNuma = true;
                dumpSockets = true;
                dumpNumaCost = true;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "-c") dumpCoreInfo = true;
                else if (args[i] == "-f") dumpCoreFeatures = true;
                else if (args[i] == "-g") dumpGroups = true;
                else if (args[i] == "-l") dumpCaches = true;
                else if (args[i] == "-n") dumpNuma = true;
                else if (args[i] == "-s") dumpSockets = true;
                else if (args[i] == "-m") dumpNumaCost = true;
                else if (args[i] == "-v") dumpVirt = true;
                else
                {
                    Usage();
                    return 1;
                }
            }
            
            try
            {
                if (dumpCoreFeatures || dumpVirt)
                {
                    Console.WriteLine("Processor capabilities:");
                    CpuCapabilities.Dump(null, dumpVirt);
                    Console.WriteLine();
                }

                if (dumpCoreInfo)
                {
                    Console.WriteLine("Logical to Physical Processor Map:");
                    CpuCoreInfo.Dump();
                    Console.WriteLine();
                }

                if (dumpSockets)
                {
                    Console.WriteLine("Logical Processor to Socket Map:");
                    CpuSocketInfo.Dump();
                    Console.WriteLine();
                }

                if (dumpNuma)
                {
                    Console.WriteLine("Logical Processor to NUMA Node Map:");
                    CpuNumaNodeInfo.Dump();
                    Console.WriteLine();
                }

                if (dumpNumaCost)
                {
                    if (CpuNumaNodeInfo.NumberOfNumaNodes > 1)
                    {
                        CpuNumaNodeInfo.DumpCost();
                        Console.WriteLine();
                    }
                    else
                    {
                        Console.WriteLine("No NUMA configured.");
                        Console.WriteLine();
                    }
                }

                if (dumpCaches)
                {
                    Console.WriteLine("Logical Processor to Cache Map:");
                    CpuCacheInfo.Dump();
                    Console.WriteLine();
                }

                if (dumpGroups)
                {
                    Console.WriteLine("Logical Processor to Group Map:");
                    CpuGroupInfo.Dump();
                    Console.WriteLine();
                }

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