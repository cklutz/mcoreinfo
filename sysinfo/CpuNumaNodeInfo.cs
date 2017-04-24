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

            int maxMask = s_data.Value.Select(x => x.GroupMask.Mask.ToInt64()).Max(n => Convert.ToString(n, 2).Length);

            for (var i = 0; i < s_data.Value.Count; i++)
            {
                var entry = s_data.Value[i];
                string map = new string(Convert.ToString(entry.GroupMask.Mask.ToInt64(), 2).Reverse().ToArray());
                tw.Write(map.Replace('1', '*').Replace('0', '-').PadRight(maxMask, '-'));
                tw.Write(" ");
                tw.Write("NUMA Node ");
                tw.Write(i);
                tw.WriteLine();
            }

            //NativeMethods.EnumSystemFirmwareTables("RSMB");
            //NativeMethods.EnumSystemFirmwareTables("ACPI");

            //Console.WriteLine(NativeMethods.GetSystemFirmwareTable("RSMB", null).ToInt64().ToString());
            try
            {
                var ptr = NativeMethods.GetSystemFirmwareTable("ACPI", "SLIT");
                var slit = Marshal.PtrToStructure<NativeMethods.SLIT>(ptr);
                var matrix = slit.GetMatrix(ptr);

                for (int i = 0; i < matrix.Length; i++)
                {
                    Console.WriteLine(matrix[i]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        public static int NumberOfNumaNodes => s_data.Value.Count;

        private static readonly Lazy<List<NativeMethods.NUMA_NODE_RELATIONSHIP>> s_data =
            new Lazy<List<NativeMethods.NUMA_NODE_RELATIONSHIP>>(() => GetNativeInfo().ToList());

        private static IEnumerable<NativeMethods.NUMA_NODE_RELATIONSHIP> GetNativeInfo()
        {
            var result = new List<NativeMethods.NUMA_NODE_RELATIONSHIP>();
            NativeMethods
                .GetLogicalProcessorInformationEx<NativeMethods.SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_NUMA_NODE>(
                    NativeMethods.RelationNumaNode,
                    info =>
                    {
                        result.Add(info.NumaNode);
                        return true;
                    });

            return result;
        }
    }
}