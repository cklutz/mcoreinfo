using System;
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

        //[StructLayout(LayoutKind.Explicit)]
        //internal class SLIT
        //{
        //    [FieldOffset(0)]
        //    public int Signature;
        //    [FieldOffset(4)]
        //    public int Length;
        //    [FieldOffset(8)]
        //    public byte Revision;
        //    [FieldOffset(9)]
        //    public byte Checksum;
        //    [FieldOffset(10)]
        //    public byte OemId0;
        //    [FieldOffset(11)]
        //    public byte OemId1;
        //    [FieldOffset(12)]
        //    public byte OemId2;
        //    [FieldOffset(13)]
        //    public byte OemId3;
        //    [FieldOffset(14)]
        //    public byte OemId4;
        //    [FieldOffset(15)]
        //    public byte OemId5;
        //    [FieldOffset(16)]
        //    public long OemTableId;
        //    [FieldOffset(24)]
        //    public int OemRevision;
        //    [FieldOffset(28)]
        //    public int CreatorId;
        //    [FieldOffset(32)]
        //    public int CreatorRevision;
        //    [FieldOffset(36)]
        //    public ulong NumberOfSytemLocalities;
        //    [FieldOffset(44)]
        //    public IntPtr Data;
        //    //[MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        //    //public byte[] Data;
        //}

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct SLIT
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
            public ulong NumberOfSytemLocalities;
            // Unused - use GetMatrix() instead.
            //public IntPtr Data;

            public byte[] GetMatrix(IntPtr slitPtr)
            {
                int items = (int)(NumberOfSytemLocalities * NumberOfSytemLocalities);
                var matrix = new byte[items];
                Marshal.Copy(slitPtr + (Length - items), matrix, 0, items);
                return matrix;
            }
        }

        internal static IntPtr GetSystemFirmwareTable(string providerStr, string idStr)
        {
            int provider = providerStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(providerStr).Reverse().ToArray(), 0);
            int id = idStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(idStr).ToArray(), 0);
            var result = IntPtr.Zero;

            try
            {
                int size = GetSystemFirmwareTable(provider, id, result, 0);
                if (size == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        string.Format("GetSystemFirmwareTable('{0}', '{1}') get size: {2:X}",
                        providerStr, idStr, Marshal.GetLastWin32Error()));
                }

                result = Marshal.AllocHGlobal(size);
                if (GetSystemFirmwareTable(provider, id, result, size) == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        string.Format("GetSystemFirmwareTable('{0}', '{1}') get data: {2:X}",
                        providerStr, idStr, Marshal.GetLastWin32Error()));
                }

                return result;
            }
            catch (Exception)
            {
                if (result != IntPtr.Zero)
                    Marshal.FreeHGlobal(result);
                throw;
            }
        }

        internal static void EnumSystemFirmwareTables(string providerStr)
        {
            Console.WriteLine(providerStr);

            int provider = providerStr == null ? 0 : BitConverter.ToInt32(Encoding.ASCII.GetBytes(providerStr).Reverse().ToArray(), 0);
            var result = IntPtr.Zero;
            try
            {
                int size = EnumSystemFirmwareTables(provider, IntPtr.Zero, 0);
                if (size == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        string.Format("EnumSystemFirmwareTables('{0}') get size: {1:X}",
                            providerStr, Marshal.GetLastWin32Error()));
                }

                result = Marshal.AllocHGlobal(size);
                if (EnumSystemFirmwareTables(provider, result, size) == 0)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        string.Format("EnumSystemFirmwareTables('{0}') get data: {1:X}",
                            providerStr, Marshal.GetLastWin32Error()));
                }

                Console.WriteLine("result: " + result.ToInt64().ToString("X") + " size " + size);
                int count = size / sizeof(int);
                Console.WriteLine("count: " + count);
                int[] data = new int[count];
                Marshal.Copy(result, data, 0, data.Length);
                for (int i = 0; i < count; i++)
                {
                    Console.WriteLine(i + " : " + data[i] + " : " + Encoding.ASCII.GetString(BitConverter.GetBytes(data[i])));
                }

                Marshal.FreeHGlobal(result);
            }
            catch (Exception)
            {
                if (result != IntPtr.Zero)
                    Marshal.FreeHGlobal(result);
                throw;
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

        [DllImport(KernelDll, SetLastError = true, ExactSpelling = true)]
        private static extern int GetSystemFirmwareTable(
            int FirmwareTableProviderSignature,
            int FirmwareTableID,
            ref SLIT pFirmwareTableBuffer,
            int BufferSize);

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