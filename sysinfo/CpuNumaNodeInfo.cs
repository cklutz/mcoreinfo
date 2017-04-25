using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Runtime.InteropServices;

namespace SysInfo
{
    public class CpuNumaNodeInfo
    {
        public static void Dump(TextWriter tw = null)
        {
            tw = tw ?? Console.Out;

            int maxMask = s_data.Value.NumaNodeRelationships.Select(x => x.GroupMask.Mask.ToInt64()).Max(n => Convert.ToString(n, 2).Length);

            for (var i = 0; i < s_data.Value.NumaNodeRelationships.Count; i++)
            {
                var entry = s_data.Value.NumaNodeRelationships[i];
                string map = new string(Convert.ToString(entry.GroupMask.Mask.ToInt64(), 2).Reverse().ToArray());
                tw.Write(map.Replace('1', '*').Replace('0', '-').PadRight(maxMask, '-'));
                tw.Write(" ");
                tw.Write("NUMA Node ");
                tw.Write(i);
                tw.WriteLine();
            }
        }

        public static void DumpCost(TextWriter tw = null)
        {
            tw = tw ?? Console.Out;
            
            var slit = s_data.Value.SlitTable;
            if (slit != null)
            {
                tw.WriteLine();
                tw.WriteLine("Locality Distance Information Table:");

                tw.Write("   ");
                for (int i = 0; i < slit.GetLength(1); i++)
                {
                    tw.Write(i.ToString().PadLeft(3));
                    tw.Write(" ");
                }
                tw.WriteLine();

                for (int i = 0; i < slit.GetLength(0); i++)
                {
                    tw.Write(i.ToString().PadLeft(3));
                    tw.Write(" ");

                    for (int j = 0; j < slit.GetLength(1); j++)
                    {
                        tw.Write(slit[i, j].ToString().PadRight(3));
                        if (j < slit.GetLength(1))
                            tw.Write(" ");
                    }
                    tw.WriteLine();
                }

                tw.WriteLine();
            }

            var srat = s_data.Value.SratTable;
            if (srat != null)
            {
                tw.WriteLine();
                tw.WriteLine("Resource Affinity Table:");

                if (srat.ProcessorApicAffinities.Any())
                {
                    tw.WriteLine("Processor Affinity:");
                    foreach (var proc in srat.ProcessorApicAffinities.OrderBy(p => p.ApicId))
                    {
                        tw.WriteLine(proc);
                    }
                    tw.WriteLine();
                }

                if (srat.ProcessorX2ApicAffinities.Any())
                {
                    tw.WriteLine("Processor Affinity (X2APIC):");
                    foreach (var proc in srat.ProcessorX2ApicAffinities.OrderBy(p => p.X2ApicId))
                    {
                        tw.WriteLine(proc);
                    }
                    tw.WriteLine();
                }

                if (srat.MemoryAffinities.Any())
                {
                    tw.WriteLine("Memory Affinity:");
                    foreach (var mem in srat.MemoryAffinities.OrderBy(m => m.BaseAddress))
                    {
                        tw.WriteLine(mem);
                    }
                    tw.WriteLine();
                }
            }
        }

        public static byte[,] SystemLocalityDistanceInformationTable => s_data.Value.SlitTable;

        public static int NumberOfNumaNodes => s_data.Value.NumaNodeRelationships.Count;

        private class Info
        {
            public byte[,] SlitTable;
            public List<NativeMethods.NUMA_NODE_RELATIONSHIP> NumaNodeRelationships;
            public NativeMethods.SystemResourceAffinityTable SratTable;
        }

        private static readonly Lazy<Info> s_data = new Lazy<Info>(() => GetNativeInfo());

        private static Info GetNativeInfo()
        {
            NativeMethods.GetSystemResourceAffinityTable();

            var result = new Info();
            result.NumaNodeRelationships = new List<NativeMethods.NUMA_NODE_RELATIONSHIP>();
            result.SlitTable = NativeMethods.GetSystemLocalityDistanceInformationTable();
            result.SratTable = NativeMethods.GetSystemResourceAffinityTable();

            NativeMethods.GetLogicalProcessorInformationEx<NativeMethods.SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_NUMA_NODE>(
                    NativeMethods.RelationNumaNode,
                    info =>
                    {
                        result.NumaNodeRelationships.Add(info.NumaNode);
                        return true;
                    });

            return result;
        }
    }
}