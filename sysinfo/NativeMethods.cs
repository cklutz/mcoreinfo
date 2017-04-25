using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

// ReSharper disable InconsistentNaming

namespace SysInfo
{
    internal class NativeMethods
    {
        private const string KernelDll = "kernel32.dll";
        private const string NtDll = "ntdll.dll";

        // -----------------------------------------------------------------------------------
        // ACPI defitions (see http://www.acpi.info)
        // -----------------------------------------------------------------------------------

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct DESCRIPTION_HEADER
        {
            public int Signature;
            public int Length;
            public byte Revision;
            public byte Checksum;
            public byte OemId0;
            public byte OemId1;
            public byte OemId2;
            public byte OemId3;
            public byte OemId4;
            public byte OemId5;
            public long OemTableId;
            public int OemRevision;
            public int CreatorId;
            public int CreatorRevision;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SLIT
        {
            public DESCRIPTION_HEADER Header;
            public ulong NumberOfSytemLocalities;
            // Unused - Built up manually inside GetSystemLocalityDistanceInformationTable()
            //public IntPtr Entries;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SRAT
        {
            public DESCRIPTION_HEADER Header;
            public int Reserved;
            public long Reserverd;
        }

        internal class SystemResourceAffinityTable
        {
            public SystemResourceAffinityTable()
            {
                ProcessorApicAffinities = new List<ProcessorLocalApicAffinity>();
                ProcessorX2ApicAffinities = new List<ProcessorLocalx2ApicAffinity>();
                MemoryAffinities = new List<MemoryAffinity>();
            }

            public List<ProcessorLocalApicAffinity> ProcessorApicAffinities;
            public List<ProcessorLocalx2ApicAffinity> ProcessorX2ApicAffinities;
            public List<MemoryAffinity> MemoryAffinities;
        }

        internal class ProcessorLocalApicAffinity
        {
            public int ProximityDomain;
            public byte ApicId;
            public int Flags;
            public byte LocalSapicEid;
            public int ClockDomain;

            public override string ToString()
            {
                return $"PXM={ProximityDomain}, ApicId={ApicId}, Flags={Convert.ToString(Flags, 2)}, LocalSapicEid={LocalSapicEid}, ClockDomain={ClockDomain}";
            }
        }

        internal class ProcessorLocalx2ApicAffinity
        {
            public int ProximityDomain;
            public int X2ApicId;
            public int Flags;
            public int ClockDomain;

            public override string ToString()
            {
                return $"PXM={ProximityDomain}, Flags={Convert.ToString(Flags, 2)}, X2ApicId={X2ApicId}, ClockDomain={ClockDomain}";
            }
        }

        internal class MemoryAffinity
        {
            public int ProximityDomain;
            public long BaseAddress;
            public long Length;
            public int Flags;

            public override string ToString()
            {
                return $"PXM={ProximityDomain}, Flags={Convert.ToString(Flags, 2)}, BaseAddress={BaseAddress:X16}, Length={Length:X16}";
            }
        }

        // -----------------------------------------------------------------------------------

        internal static SystemResourceAffinityTable GetSystemResourceAffinityTable()
        {
            return GetSystemFirmwareTable("ACPI", "SRAT", raw =>
            {
                var result = new SystemResourceAffinityTable();

                var srat = Marshal.PtrToStructure<SRAT>(raw);
                IntPtr start = raw + Marshal.SizeOf(srat);

                int dataLen = srat.Header.Length - Marshal.SizeOf(srat);
                int pos = 0;
                while (pos < dataLen)
                {
                    // First two bytes of every sub table are type and size.
                    byte type = Marshal.ReadByte(start, pos);
                    byte len = Marshal.ReadByte(start, pos + sizeof(byte));

                    switch (type)
                    {
                        case 0: // Processor Local APIC/SAPIC Affinity Structure
                            {
                                int flags = Marshal.ReadInt32(start, pos + 4);
                                // Flags are not 1 (Enabled), than the entry is a static entry, that
                                // is not enabled and most likely only used as a placeholder.
                                if ((flags & 1) != 0)
                                {
                                    var table = new ProcessorLocalApicAffinity();

                                    byte[] pxm = new byte[4];
                                    pxm[0] = Marshal.ReadByte(start, pos + 2);
                                    pxm[1] = Marshal.ReadByte(start, pos + 9);
                                    pxm[2] = Marshal.ReadByte(start, pos + 10);
                                    pxm[3] = Marshal.ReadByte(start, pos + 11);

                                    table.ProximityDomain = BitConverter.ToInt32(pxm, 0);
                                    table.ApicId = Marshal.ReadByte(start, pos + 3);
                                    table.Flags = flags;
                                    table.LocalSapicEid = Marshal.ReadByte(start, pos + 8);
                                    table.ClockDomain = Marshal.ReadInt32(start, pos + 12);

                                    result.ProcessorApicAffinities.Add(table);
                                }
                            }
                            break;
                        case 1: // Memory Affinity Structure
                            {
                                int flags = Marshal.ReadInt32(start, pos + 28);
                                if ((flags & 1) != 0)
                                {
                                    var table = new MemoryAffinity();
                                    table.ProximityDomain = Marshal.ReadInt32(start, pos + 2);
                                    table.BaseAddress = Combine(Marshal.ReadInt32(start, pos + 8), Marshal.ReadInt32(start, pos + 12));
                                    table.Length = Combine(Marshal.ReadInt32(start, pos + 16), Marshal.ReadInt32(start, pos + 20));
                                    table.Flags = flags;

                                    result.MemoryAffinities.Add(table);
                                }
                            }
                            break;
                        case 2: // Processor Local x2APIC Affinity Structure
                            {
                                int flags = Marshal.ReadInt32(start, pos + 12);
                                if ((flags & 1) != 0)
                                {
                                    var table = new ProcessorLocalx2ApicAffinity();
                                    table.ProximityDomain = Marshal.ReadInt32(start, pos + 4);
                                    table.X2ApicId = Marshal.ReadInt32(start, pos + 8);
                                    table.Flags = flags;
                                    table.ClockDomain = Marshal.ReadInt32(start, pos + 16);

                                    result.ProcessorX2ApicAffinities.Add(table);
                                }
                            }
                            break;
                    }

                    pos += len;
                }

                return result;
            });
        }

        internal static long Combine(int low, int high)
        {
            unchecked
            {
                return (long)(((ulong)(uint)high) << 32) | (uint)low;
            }
        }

        internal static byte[,] GetSystemLocalityDistanceInformationTable()
        {
            return GetSystemFirmwareTable("ACPI", "SLIT", raw =>
            {
                var slit = Marshal.PtrToStructure<SLIT>(raw);
                int items = (int)(slit.NumberOfSytemLocalities * slit.NumberOfSytemLocalities);

                IntPtr start = raw + (slit.Header.Length - items);

                var result = new byte[slit.NumberOfSytemLocalities, slit.NumberOfSytemLocalities];

                int j = -1;
                int k = 0;
                for (int i = 0; i < items; i++)
                {
                    if ((i % (int)slit.NumberOfSytemLocalities) == 0)
                    {
                        j++;
                        k = 0;
                    }
                    result[j, k] = Marshal.ReadByte(start, i);
                    k++;
                }
                return result;
            });
        }

        internal static TResult GetSystemFirmwareTable<TResult>(string providerStr, string idStr, Func<IntPtr, TResult> converter)
        {
            int provider = providerStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(providerStr).Reverse().ToArray(), 0);
            int id = idStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(idStr).ToArray(), 0);
            var result = IntPtr.Zero;

            try
            {
                int size = GetSystemFirmwareTable(provider, id, result, 0);
                if (size == 0)
                {
                    int le = Marshal.GetLastWin32Error();
                    // ERROR_ELEMENT_NOT_FOUND - unknown/invalid id
                    // ERROR_INVALID_FUNCTION - unknown/invalid provider
                    if (le == ERROR_ELEMENT_NOT_FOUND || le == ERROR_INVALID_FUNCTION)
                    {
                        return default(TResult);
                    }

                    throw new Win32Exception(le,
                        $"GetSystemFirmwareTable('{providerStr}', '{idStr}') get size: {le:X}");
                }

                result = Marshal.AllocHGlobal(size);
                if (GetSystemFirmwareTable(provider, id, result, size) == 0)
                {
                    int le = Marshal.GetLastWin32Error();
                    throw new Win32Exception(le,
                        $"GetSystemFirmwareTable('{providerStr}', '{idStr}') get data: {le:X}");
                }

                return converter(result);
            }
            finally
            {
                if (result != IntPtr.Zero)
                    Marshal.FreeHGlobal(result);
            }
        }

        internal static int[] EnumSystemFirmwareTables(string providerStr)
        {
            int provider = providerStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(providerStr).Reverse().ToArray(), 0);
            var result = IntPtr.Zero;
            try
            {
                int size = EnumSystemFirmwareTables(provider, IntPtr.Zero, 0);
                if (size == 0)
                {
                    int le = Marshal.GetLastWin32Error();
                    // ERROR_INVALID_FUNCTION - unknown/invalid provider
                    if (le == ERROR_INVALID_FUNCTION)
                    {
                        return null;
                    }

                    throw new Win32Exception(le, $"EnumSystemFirmwareTables('{providerStr}') get size: {le:X}");
                }

                result = Marshal.AllocHGlobal(size);
                if (EnumSystemFirmwareTables(provider, result, size) == 0)
                {
                    int le = Marshal.GetLastWin32Error();
                    throw new Win32Exception(le, $"EnumSystemFirmwareTables('{providerStr}') get data: {le:X}");
                }

                int count = size / sizeof(int);
                int[] data = new int[count];
                Marshal.Copy(result, data, 0, data.Length);
                return data;
            }
            finally
            {
                if (result != IntPtr.Zero)
                    Marshal.FreeHGlobal(result);
            }
        }

        [DllImport(KernelDll, SetLastError = true, ExactSpelling = true)]
        private static extern int EnumSystemFirmwareTables(
            int FirmwareTableProviderSignature,
            IntPtr pFirmwareTableBuffer,
            int BufferSize);

        [DllImport(KernelDll, SetLastError = true, ExactSpelling = true)]
        private static extern int GetSystemFirmwareTable(
            int FirmwareTableProviderSignature,
            int FirmwareTableID,
            IntPtr pFirmwareTableBuffer,
            int BufferSize);

        // --------------------------------------------------------------------------------------

        internal static IntPtr GetCurrentProcessAffinityMask()
        {
            IntPtr pmask;
            IntPtr smask;
            if (!GetProcessAffinityMask(GetCurrentProcess(), out pmask, out smask))
                throw new Win32Exception();

            long mask = pmask.ToInt64();
            mask &= smask.ToInt64();
            return new IntPtr(mask);
        }

        [DllImport(KernelDll, SetLastError = true, ExactSpelling = true)]
        internal static extern IntPtr GetCurrentProcess();

        [DllImport(KernelDll, SetLastError = true, ExactSpelling = true)]
        internal static extern bool GetProcessAffinityMask(IntPtr hProcess, out IntPtr lpProcessAffinityMask,
            out IntPtr lpSystemAffinityMask);

        [StructLayout(LayoutKind.Sequential)]
        internal class SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
        {
            public LARGE_INTEGER IdleTime;
            public LARGE_INTEGER KernelTime;
            public LARGE_INTEGER UserTime;
            public LARGE_INTEGER DpcTime;
            public LARGE_INTEGER InterruptTime;
            public int InterruptCount;
        }

        [StructLayout(LayoutKind.Explicit, Size = 8)]
        internal struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public Int32 HighPart;
        }

        internal const int SystemProcessorPerformanceInformation = 0x08;

        [DllImport(NtDll, CharSet = CharSet.Auto)]
        internal static extern int NtQuerySystemInformation(int query, IntPtr dataPtr, int size, out int returnedSize);

        [DllImport(KernelDll, EntryPoint = "RtlZeroMemory", SetLastError = false)]
        internal static extern void ZeroMemory(IntPtr dest, int size);


        [StructLayout(LayoutKind.Sequential)]
        public struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [DllImport(KernelDll, SetLastError = true)]
        internal static extern bool GetSystemTimes(ref FILETIME lpIdleTime, ref FILETIME lpKernelTime,
            ref FILETIME lpUserTime);

        internal const int RelationProcessorCore = 0;
        internal const int RelationNumaNode = 1;
        internal const int RelationCache = 2;
        internal const int RelationProcessorPackage = 3;
        internal const int RelationGroup = 4;

        [DllImport(KernelDll, SetLastError = true)]
        internal static extern bool GetLogicalProcessorInformationEx(
            int RelationshipType,
            IntPtr Buffer,
            ref int ReturnedLength);

        internal interface ISystemLogicalProcessoInformation
        {
            int _RelationShip { get; }
            int _Size { get; }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_GROUP : ISystemLogicalProcessoInformation
        {
            public int Relationship;
            public int Size;
            public GROUP_RELATIONSHIP Groups;

            public int _RelationShip => Relationship;
            public int _Size => Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_CACHE : ISystemLogicalProcessoInformation
        {
            public int Relationship;
            public int Size;
            public CACHE_RELATIONSHIP Cache;

            public int _RelationShip => Relationship;
            public int _Size => Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_PROCESSOR : ISystemLogicalProcessoInformation
        {
            public int Relationship;
            public int Size;
            public PROCESSOR_RELATIONSHIP Processor;

            public int _RelationShip => Relationship;
            public int _Size => Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX_NUMA_NODE : ISystemLogicalProcessoInformation
        {
            public int Relationship;
            public int Size;
            public NUMA_NODE_RELATIONSHIP NumaNode;

            public int _RelationShip => Relationship;
            public int _Size => Size;
        }

        internal enum PROCESSOR_CACHE_TYPE
        {
            CacheUnified,
            CacheInstruction,
            CacheData,
            CacheTrace
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct NUMA_NODE_RELATIONSHIP
        {
            public uint NodeNumber;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Reserved;
            public GROUP_AFFINITY GroupMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESSOR_RELATIONSHIP
        {
            public byte Flags;

            //
            // NOTE: Apparently there is a error in the MSDN documentation (https://msdn.microsoft.com/en-us/library/windows/desktop/dd405506.aspx),
            // as of 2017/04/23. The PROCESSOR_RELATIONSHIP structure documented there,
            // has the following definition:
            //    typedef struct _PROCESSOR_RELATIONSHIP {
            //        BYTE Flags;
            //        BYTE EfficiencyClass;
            //        BYTE Reserved[21];
            //        WORD GroupCount;
            //        GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
            //    }
            //    PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;
            //
            // Whereas the "C:\Program Files (x86)\Windows Kits\10\Include\10.0.14393.0\um\winnt.h" file defines it as follows:
            //    typedef struct _PROCESSOR_RELATIONSHIP {
            //       BYTE Flags;
            //       BYTE EfficiencyClass;
            //       BYTE Reserved[20];
            //       WORD GroupCount;
            //       _Field_size_(GroupCount) GROUP_AFFINITY GroupMask[ANYSIZE_ARRAY];
            //    }
            //    PROCESSOR_RELATIONSHIP, *PPROCESSOR_RELATIONSHIP;
            //
            // Which makes sense. This EfficiencyClass member was introduced with Windows 10 (officially at least)
            // and the Reserved member would have to give one byte to it.
            //
            public byte EfficiencyClass;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Reserved;
            public ushort GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public GROUP_AFFINITY[] GroupMask;
        }

        /// <summary>
        /// Value of <see cref="PROCESSOR_RELATIONSHIP.Flags"/> if the <see cref="GetLogicalProcessorInformationEx"/>
        /// has been called with the <see cref="RelationProcessorCore"/> relation ship and the core has more
        /// than one logical processor.
        /// </summary>
        internal const byte LPT_PC_SMT = 0x1;

        [StructLayout(LayoutKind.Sequential)]
        internal struct CACHE_RELATIONSHIP
        {
            public byte Level;
            public byte Associativity;
            public ushort LineSize;
            public uint CacheSize;
            public PROCESSOR_CACHE_TYPE Type;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Reserved;
            public GROUP_AFFINITY GroupMask;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GROUP_AFFINITY
        {
            public IntPtr Mask;
            public ushort Group;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)] public ushort[] Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GROUP_RELATIONSHIP
        {
            public ushort MaximumGroupCount;
            public ushort ActiveGroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)] public byte[] Reserved;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public PROCESSOR_GROUP_INFO[] GroupInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESSOR_GROUP_INFO
        {
            public byte MaximumProcessorCount;
            public byte ActiveProcessorCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 38)] public byte[] Reserved;
            public IntPtr ActiveProcessorMask;
        }

        internal const int ERROR_INSUFFICIENT_BUFFER = 122;
        internal const int ERROR_ELEMENT_NOT_FOUND = 1168;
        internal const int ERROR_INVALID_FUNCTION = 1;

        internal static void GetLogicalProcessorInformationEx<T>(int relation, Func<T, bool> worker)
            where T : ISystemLogicalProcessoInformation
        {
            int len = 0;
            var buffer = IntPtr.Zero;
            if (!GetLogicalProcessorInformationEx(relation, buffer, ref len) &&
                Marshal.GetLastWin32Error() != ERROR_INSUFFICIENT_BUFFER)
            {
                throw new Win32Exception();
            }

            buffer = Marshal.AllocHGlobal(len);
            try
            {
                if (!GetLogicalProcessorInformationEx(relation, buffer, ref len))
                {
                    throw new Win32Exception();
                }

                int bytesRead = 0;
                var iter = buffer;
                while (bytesRead < len)
                {
                    var info = Marshal.PtrToStructure<T>(iter);
                    if (info._RelationShip == relation)
                    {
                        if (!worker(info))
                        {
                            break;
                        }
                    }

                    bytesRead += info._Size;
                    iter = iter + info._Size;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        /// <summary>
        /// Returns the number of processors that a process has been configured to run on.
        /// Note this is not equal to <see cref="Environment.ProcessorCount"/>.
        /// </summary>
        /// <returns></returns>
        internal static int GetCurrentProcessCpuCount()
        {
            IntPtr pmaskPtr, smaskPtr;
            if (!GetProcessAffinityMask(GetCurrentProcess(), out pmaskPtr, out smaskPtr))
                throw new Win32Exception();

            long pmask = pmaskPtr.ToInt64();
            long smask = smaskPtr.ToInt64();

            if (pmask == 1)
                return 1;

            pmask &= smask;

            int count = CountBitsSet(pmask);

            // GetProcessAffinityMask can return pmask=0 and smask=0 on systems with more
            // than 64 processors, which would leave us with a count of 0.  Since the GC
            // expects there to be at least one processor to run on (and thus at least one
            // heap), we'll return 64 here if count is 0, since there are likely a ton of
            // processors available in that case.  The GC also cannot (currently) handle
            // the case where there are more than 64 processors, so we will return a
            // maximum of 64 here.
            if (count == 0 || count > 64)
                count = 64;

            return count;
        }

        internal static int CountBitsSet(long mask)
        {
            if (mask == 1)
                return 1;

            int count = 0;
            while (mask > 0)
            {
                if ((mask & 1) != 0)
                    count++;
                mask >>= 1;
            }
            return count;
        }

        // --------------------------------------------------------------------------------

        [DllImport(KernelDll, SetLastError = true)]
        internal static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);

        internal const uint PF_FLOATING_POINT_PRECISION_ERRATA = 0;
        internal const uint PF_FLOATING_POINT_EMULATED = 1;
        internal const uint PF_COMPARE_EXCHANGE_DOUBLE = 2;
        internal const uint PF_MMX_INSTRUCTIONS_AVAILABLE = 3;
        internal const uint PF_PPC_MOVEMEM_64BIT_OK = 4;
        internal const uint PF_ALPHA_BYTE_INSTRUCTIONS = 5;
        internal const uint PF_XMMI_INSTRUCTIONS_AVAILABLE = 6;
        internal const uint PF_3DNOW_INSTRUCTIONS_AVAILABLE = 7;
        internal const uint PF_RDTSC_INSTRUCTION_AVAILABLE = 8;
        internal const uint PF_PAE_ENABLED = 9;
        internal const uint PF_XMMI64_INSTRUCTIONS_AVAILABLE = 10;
        internal const uint PF_SSE_DAZ_MODE_AVAILABLE = 11;
        internal const uint PF_NX_ENABLED = 12;
        internal const uint PF_SSE3_INSTRUCTIONS_AVAILABLE = 13;
        internal const uint PF_COMPARE_EXCHANGE128 = 14;
        internal const uint PF_COMPARE64_EXCHANGE128 = 15;
        internal const uint PF_CHANNELS_ENABLED = 16;
        internal const uint PF_XSAVE_ENABLED = 17;
        internal const uint PF_ARM_VFP_32_REGISTERS_AVAILABLE = 18;
        internal const uint PF_ARM_NEON_INSTRUCTIONS_AVAILABLE = 19;
        internal const uint PF_SECOND_LEVEL_ADDRESS_TRANSLATION = 20;
        internal const uint PF_VIRT_FIRMWARE_ENABLED = 21;
        internal const uint PF_RDWRFSGSBASE_AVAILABLE = 22;
        internal const uint PF_FASTFAIL_AVAILABLE = 23;
        internal const uint PF_ARM_DIVIDE_INSTRUCTION_AVAILABLE = 24;
        internal const uint PF_ARM_64BIT_LOADSTORE_ATOMIC = 25;
        internal const uint PF_ARM_EXTERNAL_CACHE_AVAILABLE = 26;
        internal const uint PF_ARM_FMAC_INSTRUCTIONS_AVAILABLE = 27;
        internal const uint PF_RDRAND_INSTRUCTION_AVAILABLE = 28;
        internal const uint PF_ARM_V8_INSTRUCTIONS_AVAILABLE = 29;
        internal const uint PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE = 30;
        internal const uint PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE = 31;
        internal const uint PF_RDTSCP_INSTRUCTION_AVAILABLE = 32;
    }
}