using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace SysInfo
{
    public class CpuCapabilities
    {
        public static void Dump(TextWriter tw = null, bool virtualizationOnly = false)
        {
            tw = tw ?? Console.Out;

            tw.WriteLine(ProcessorBrand);

            string manufacturer = "Unknown";
            if (IsIntelProcessor)
                manufacturer = "Intel";
            else if (IsAmdProcessor)
                manufacturer = "AMD";
            else if (s_features.Value.IsLikelyVirtualMachine)
                manufacturer = "Virtual Machine";

            if (X64)
            {
                manufacturer += "64";
            }

            tw.WriteLine("{0} Family {1} Model {2} Stepping {3}, {4}",
                manufacturer, ProcessorFamily, ProcessorModel, ProcessorStepping, ProcessorVendor);
            tw.WriteLine("Microcode signature: {0}", GetMicrocodeDisplayString(MicrocodeUpdateSignature));

            if (virtualizationOnly)
            {
                SupportMessage("HYPERVISOR", HYPERVISOR, tw);
                if (IsIntelProcessor)
                {
                    SupportMessage("VMX", VMX, tw);
                    //TODO: EPT: SupportMessage("EPT", EPT, tw);
                }
                else if (IsAmdProcessor)
                {
                    SupportMessage("SVM", SVM, tw);
                    SupportMessage("NP", NP, tw);
                }
            }
            else
            {
                SupportMessage("HTT", HTT, tw);
                SupportMessage("HYPERVISOR", HYPERVISOR, tw);
                SupportMessage("VMX", VMX, tw);
                SupportMessage("SVM", SVM, tw);
                SupportMessage("SMX", SMX, tw);
                SupportMessage("NX", NX, tw);
                SupportMessage("X64", X64, tw);
                SupportMessage("3DNOW", _3DNOW, tw);
                SupportMessage("3DNOWEXT", _3DNOWEXT, tw);
                SupportMessage("ABM", ABM, tw);
                SupportMessage("ADX", ADX, tw);
                SupportMessage("AES", AES, tw);
                SupportMessage("AVX", AVX, tw);
                SupportMessage("AVX2", AVX2, tw);
                SupportMessage("AVX512CD", AVX512CD, tw);
                SupportMessage("AVX512ER", AVX512ER, tw);
                SupportMessage("AVX512F", AVX512F, tw);
                SupportMessage("AVX512PF", AVX512PF, tw);
                SupportMessage("BMI1", BMI1, tw);
                SupportMessage("BMI2", BMI2, tw);
                SupportMessage("CLFSH", CLFSH, tw);
                SupportMessage("CMPXCHG16B", CMPXCHG16B, tw);
                SupportMessage("CX8", CX8, tw);
                SupportMessage("ERMS", ERMS, tw);
                SupportMessage("F16C", F16C, tw);
                SupportMessage("FMA", FMA, tw);
                SupportMessage("FSGSBASE", FSGSBASE, tw);
                SupportMessage("FXSR", FXSR, tw);
                SupportMessage("HLE", HLE, tw);
                SupportMessage("INVPCID", INVPCID, tw);
                SupportMessage("LAHF", LAHF, tw);
                SupportMessage("LZCNT", LZCNT, tw);
                SupportMessage("MMX", MMX, tw);
                SupportMessage("MMXEXT", MMXEXT, tw);
                SupportMessage("MONITOR", MONITOR, tw);
                SupportMessage("MOVBE", MOVBE, tw);
                SupportMessage("MSR", MSR, tw);
                SupportMessage("OSXSAVE", OSXSAVE, tw);
                SupportMessage("PCLMULQDQ", PCLMULQDQ, tw);
                SupportMessage("POPCNT", POPCNT, tw);
                SupportMessage("PREFETCHWT1", PREFETCHWT1, tw);
                SupportMessage("RDRAND", RDRAND, tw);
                SupportMessage("RDSEED", RDSEED, tw);
                SupportMessage("RDTSCP", RDTSCP, tw);
                SupportMessage("RTM", RTM, tw);
                SupportMessage("SEP", SEP, tw);
                SupportMessage("SHA", SHA, tw);
                SupportMessage("SSE", SSE, tw);
                SupportMessage("SSE2", SSE2, tw);
                SupportMessage("SSE3", SSE3, tw);
                SupportMessage("SSE4.1", SSE41, tw);
                SupportMessage("SSE4.2", SSE42, tw);
                SupportMessage("SSE4a", SSE4a, tw);
                SupportMessage("SSSE3", SSSE3, tw);
                SupportMessage("SYSCALL", SYSCALL, tw);
                SupportMessage("TBM", TBM, tw);
                SupportMessage("XOP", XOP, tw);
                SupportMessage("XSAVE", XSAVE, tw);

                tw.WriteLine();
                tw.Write("Maximum implemented CPUID leaves: {0:X8} (Basic)", MaxBasicLeave.ToInt64());
                if (MaxExtendedLeave != IntPtr.Zero)
                {
                    tw.Write(", {0:X8} (Extended).", MaxExtendedLeave.ToInt64());
                }
                else
                {
                    tw.Write(".");
                }
                tw.WriteLine();
            }
        }

        private static string GetMicrocodeDisplayString(byte[] data)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                if (i < 8)
                {
                    sb.AppendFormat("{0:X}", data[i]);
                }
                else if (data[i] > 0)
                {
                    sb.AppendFormat("{0:X}", data[i]);
                }
            }
            return sb.ToString();
        }

        private static readonly Dictionary<string, string> s_descriptions = new Dictionary<string, string>
        {
            {"HTT", "Hyperthreading enabled"},
            {"HYPERVISOR", "Hypervisor is present"},
            {"VMX", "Supports Intel hardwareassisted virtualization"},
            {"SVM", "Supports AMD hardwareassisted virtualization"},
            {"X64", "Supports 64bit mode"},
            {"SMX", "Supports Intel trusted execution"},
            {"SKINIT", "Supports AMD SKINIT"},
            {"NX", "Supports noexecute page protection"},
            {"SMEP", "Supports Supervisor Mode Execution Prevention"},
            {"SMAP", "Supports Supervisor Mode Access Prevention"},
            {"PAGE1GB", "Supports 1 GB large pages"},
            {"PAE", "Supports > 32bit physical addresses"},
            {"PAT", "Supports Page Attribute Table"},
            {"PSE", "Supports 4 MB pages"},
            {"PSE36", "Supports > 32bit address 4 MB pages"},
            {"PGE", "Supports global bit in page tables"},
            {"SS", "Supports bus snooping for cache operations"},
            {"VME", "Supports Virtual8086 mode"},
            {"FSGSBASE", "Supports direct GS/FS base access"},
            {"FPU", "Implements i387 floating point instructions"},
            {"MMX", "Supports MMX instruction set"},
            {"MMXEXT", "Implements AMD MMX extensions"},
            {"3DNOW", "Supports 3DNow! instructions"},
            {"3DNOWEXT", "Supports 3DNow! extension instructions"},
            {"SSE", "Supports Streaming SIMD Extensions"},
            {"SSE2", "Supports Streaming SIMD Extensions 2"},
            {"SSE3", "Supports Streaming SIMD Extensions 3"},
            {"SSSE3", "Supports Supplemental SIMD Extensions 3"},
            {"SSE4a", "Supports Streaming SIMDR Extensions 4a"},
            {"SSE4.1", "Supports Streaming SIMD Extensions 4.1"},
            {"SSE4.2", "Supports Streaming SIMD Extensions 4.2"},
            {"AES", "Supports AES extensions"},
            {"PREFETCHWT1", "Supports PREFETCHWT1 instruction"},
            {"ABM", "Supports advanced bit manipulation"},
            {"ERMS", "Enhanced REP MOVSB/STOSB"},
            {"AVX", "Supports AVX intruction extensions"},
            {"AVX2", "Supports AVX intruction extensions"},
            {"AVX512CD", "Supports AVX-512 Conflict Detection intructions"},
            {"AVX512ER", "Supports AVX-512 Exponential and Reciprocal instructions"},
            {"AVX512F", "Supports AVX-512 Foundation"},
            {"AVX512PF", "Supports AVX-512 Prefetch instructions"},
            {"FMA", "Supports FMA extensions using YMM state"},
            {"MSR", "Implements RDMSR/WRMSR instructions"},
            {"MTRR", "Supports Memory Type Range Registers"},
            {"XSAVE", "Supports XSAVE/XRSTOR instructions"},
            {"OSXSAVE", "Supports XSETBV/XGETBV instructions"},
            {"RDRAND", "Supports RDRAND instruction"},
            {"RDSEED", "Supports RDSEED instruction"},
            {"CMOV", "Supports CMOVcc instruction"},
            {"CLFSH", "Supports CLFLUSH instruction"},
            {"CX8", "Supports compare and exchange 8byte instructions"},
            {"CMPXCHG16B", "Supports CMPXCHG16B instruction"},
            {"BMI1", "Supports bit manipulation extensions 1"},
            {"BMI2", "Supports bit manipulation extensions 2"},
            {"ADX", "Supports ADCX/ADOX instructions"},
            {"DCA", "Supports prefetch from memorymapped device"},
            {"F16C", "Supports halfprecision instruction"},
            {"FXSR", "Supports FXSAVE/FXSTOR instructions"},
            {"FFXSR", "Supports optimized FXSAVE/FSRSTOR instruction"},
            {"MONITOR", "Supports MONITOR and MWAIT instructions"},
            {"MOVBE", "Supports MOVBE instruction"},
            {"ERMSB", "Supports Enhanced REP MOVSB/STOSB"},
            {"PCLMULQDQ", "Supports PCLMULQDQ instruction"},
            {"POPCNT", "Supports POPCNT instruction"},
            {"LZCNT", "Supports LZCNT instruction"},
            {"SEP", "Supports fast system call instructions"},
            {"LAHF", "Supports LAHF/SAHF instructions in 64bit mode"},
            {"HLE", "Supports Hardware Lock Elision instructions"},
            {"RTM", "Supports Restricted Transactional Memory instructions"},
            {"DE", "Supports I/O breakpoints including CR4.DE"},
            {"DTES64", "Can write history of 64bit branch addresses"},
            {"DS", "Implements memoryresident debug buffer"},
            {"DSCPL", "Supports Debug Store feature with CPL"},
            {"PCID", "Supports PCIDs and settable CR4.PCIDE"},
            {"INVPCID", "Supports INVPCID instruction"},
            {"PDCM", "Supports Performance Capabilities MSR"},
            {"RDTSCP", "Supports RDTSCP instruction"},
            {"TSC", "Supports RDTSC instruction"},
            {"TSCDEADLINE", "Local APIC supports oneshot deadline timer"},
            {"TSCINVARIANT", "TSC runs at constant rate"},
            {"xTPR", "Supports disabling task priority messages"},
            {"EIST", "Supports Enhanced Intel Speedstep"},
            {"ACPI", "Implements MSR for power management"},
            {"TM", "Implements thermal monitor circuitry"},
            {"TM2", "Implements Thermal Monitor 2 control"},
            {"APIC", "Implements softwareaccessible local APIC"},
            {"x2APIC", "Supports x2APIC"},
            {"CNXTID", "L1 data cache mode adaptive or BIOS"},
            {"MCE", "Supports Machine Check, INT18 and CR4.MCE"},
            {"MCA", "Implements Machine Check Architecture"},
            {"PBE", "Supports use of FERR#/PBE# pin"},
            {"PSN", "Implements 96bit processor serial number"},
            {"PREFETCHW", "Supports PREFETCHW instruction"},
            {"SYSCALL", "Supports SYSCALL/SYSRET instructions"},
            {"SHA", "Supports Intel SHA extensions"},
            {"TBM", "Supports trading bit manipulation"},
            {"XOP", "Supports XOP instruction set"},
            {"NP", "Supports AMD ntested page tables"},

            // TODO: EPT is not available via CPUID, but in the MSR IA32_VMX_PROCBASED_CTLS2.
            //
            // We would need to invoke the "rdmsr" instruction properly, like we already do
            // with "cpuid".
            //
            // Additional stuff:
            // - https://www.codeproject.com/Articles/215458/Virtualization-for-System-Programmers
            {"EPT", "Supports Intel extended page tables (SLAT)"}
        };

        private static readonly Lazy<int> s_maxFeatureName = new Lazy<int>(() => s_descriptions.Keys.Max(k => k.Length));

        private static void SupportMessage(string what, bool isSupported, TextWriter tw)
        {
            string description;
            if (s_descriptions.TryGetValue(what, out description))
            {
                tw.WriteLine("{0}\t{1}\t{2}", what.PadRight(s_maxFeatureName.Value), isSupported ? "*" : "-", description);
            }
            else
            {
                tw.WriteLine("{0}\t{1}\t{2}", what.PadRight(s_maxFeatureName.Value), isSupported ? "*" : "-", "XXXXXXXXXXXXXX");
            }
        }

        public static bool IsIntelProcessor => CpuFeatures.IsIntel;
        public static bool IsAmdProcessor => CpuFeatures.IsAmd;
        public static IntPtr MaxBasicLeave { get; private set; }
        public static IntPtr MaxExtendedLeave { get; private set; }
        public static byte[] MicrocodeUpdateSignature => Features.UpdateSignature.Value;

        public static int ProcessorStepping => CpuFeatures.Stepping;

        public static int ProcessorFamily
        {
            get
            {
                if (CpuFeatures.Family == 15)
                    return CpuFeatures.Family + CpuFeatures.ExtendedFamily;
                return CpuFeatures.Family;
            }
        }

        public static int ProcessorModel
        {
            get
            {
                if (CpuFeatures.Family == 15 || CpuFeatures.Family == 6)
                    return CpuFeatures.Model + (CpuFeatures.ExtendedModel << 4);
                return CpuFeatures.Model;
            }
        }

        public static string ProcessorVendor => CpuFeatures.CpuVendor;
        public static string ProcessorBrand => CpuFeatures.CpuBrand;

        // ReSharper disable InconsistentNaming
        public static bool SSE3 => CpuFeatures.Func1Ecx[0];

        public static bool PCLMULQDQ => CpuFeatures.Func1Ecx[1];
        public static bool MONITOR => CpuFeatures.Func1Ecx[3];
        public static bool SSSE3 => CpuFeatures.Func1Ecx[9];
        public static bool FMA => CpuFeatures.Func1Ecx[12];
        public static bool CMPXCHG16B => CpuFeatures.Func1Ecx[13];
        public static bool SSE41 => CpuFeatures.Func1Ecx[19];
        public static bool SSE42 => CpuFeatures.Func1Ecx[20];
        public static bool MOVBE => CpuFeatures.Func1Ecx[22];
        public static bool POPCNT => CpuFeatures.Func1Ecx[23];
        public static bool AES => CpuFeatures.Func1Ecx[25];
        public static bool XSAVE => CpuFeatures.Func1Ecx[26];
        public static bool OSXSAVE => CpuFeatures.Func1Ecx[27];
        public static bool AVX => CpuFeatures.Func1Ecx[28];
        public static bool F16C => CpuFeatures.Func1Ecx[29];
        public static bool RDRAND => CpuFeatures.Func1Ecx[30];
        public static bool HYPERVISOR => CpuFeatures.Func1Ecx[31];
        public static bool MSR => CpuFeatures.Func1Edx[5];
        public static bool CX8 => CpuFeatures.Func1Edx[8];
        public static bool SEP => CpuFeatures.Func1Edx[11];
        public static bool CMOV => CpuFeatures.Func1Edx[15];
        public static bool CLFSH => CpuFeatures.Func1Edx[19];
        public static bool MMX => CpuFeatures.Func1Edx[23];
        public static bool FXSR => CpuFeatures.Func1Edx[24];
        public static bool SSE => CpuFeatures.Func1Edx[25];
        public static bool SSE2 => CpuFeatures.Func1Edx[26];
        public static bool HTT => CpuFeatures.Func1Edx[28];
        public static bool FSGSBASE => CpuFeatures.Func7Ebx[0];
        public static bool BMI1 => CpuFeatures.Func7Ebx[3];
        public static bool HLE => CpuFeatures.IsIntel && CpuFeatures.Func7Ebx[4];
        public static bool AVX2 => CpuFeatures.Func7Ebx[5];
        public static bool BMI2 => CpuFeatures.Func7Ebx[8];
        public static bool ERMS => CpuFeatures.Func7Ebx[9];
        public static bool INVPCID => CpuFeatures.Func7Ebx[10];
        public static bool RTM => CpuFeatures.IsIntel && CpuFeatures.Func7Ebx[11];
        public static bool AVX512F => CpuFeatures.Func7Ebx[16];
        public static bool RDSEED => CpuFeatures.Func7Ebx[18];
        public static bool ADX => CpuFeatures.Func7Ebx[19];
        public static bool AVX512PF => CpuFeatures.Func7Ebx[26];
        public static bool AVX512ER => CpuFeatures.Func7Ebx[27];
        public static bool AVX512CD => CpuFeatures.Func7Ebx[28];
        public static bool SHA => CpuFeatures.Func7Ebx[29];
        public static bool PREFETCHWT1 => CpuFeatures.Func7Ecx[0];
        public static bool LAHF => CpuFeatures.Func81Ecx[0];
        public static bool LZCNT => CpuFeatures.IsIntel && CpuFeatures.Func81Ecx[5];
        public static bool ABM => CpuFeatures.IsAmd && CpuFeatures.Func81Ecx[5];
        public static bool SSE4a => CpuFeatures.IsAmd && CpuFeatures.Func81Ecx[6];
        public static bool XOP => CpuFeatures.IsAmd && CpuFeatures.Func81Ecx[11];
        public static bool TBM => CpuFeatures.IsAmd && CpuFeatures.Func81Ecx[21];
        public static bool SYSCALL => CpuFeatures.IsIntel && CpuFeatures.Func81Edx[11];
        public static bool MMXEXT => CpuFeatures.IsAmd && CpuFeatures.Func81Edx[22];
        public static bool RDTSCP => CpuFeatures.IsIntel && CpuFeatures.Func81Edx[27];
        public static bool _3DNOWEXT => CpuFeatures.IsAmd && CpuFeatures.Func81Edx[30];
        public static bool _3DNOW => CpuFeatures.IsAmd && CpuFeatures.Func81Edx[31];
        public static bool SVM => CpuFeatures.IsAmd && CpuFeatures.Func81Ecx[2];
        public static bool VMX => CpuFeatures.Func1Ecx[5];
        public static bool SMX => CpuFeatures.Func1Ecx[6];
        public static bool NX => CpuFeatures.Func81Edx[20];
        public static bool X64 => CpuFeatures.Func81Edx[29];

        public static bool NP => CpuFeatures.IsAmd && CpuFeatures.Func8AEdx[0];
        // ReSharper restore InconsistentNaming

        private static Features CpuFeatures => s_features.Value;

        private static readonly Lazy<Features> s_features = new Lazy<Features>(() => new Features());

        private class Features
        {
            private const string RegKey = @"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0";
            public static readonly Lazy<byte[]> UpdateSignature = new Lazy<byte[]>(() => (byte[])Registry.GetValue(RegKey, "Update Signature", new byte[8]));

            public Features()
            {
                using (var cpuid = new CpuIdHelper())
                {
                    const int eax = 0;
                    const int ebx = 1;
                    const int ecx = 2;
                    const int edx = 3;

                    var data = cpuid.GetCpuId(0);

                    // Calling __cpuid with 0x0 as the function_id argument  
                    // gets the number of the highest valid function ID.  
                    var nIds = (uint)data[eax];

                    for (int i = 0; i <= nIds; ++i)
                    {
                        data = cpuid.GetCpuId(i);
                        m_data.Add(data);
                    }

                    byte[] vendor = new byte[0x20];
                    Buffer.BlockCopy(m_data[0], 1 * sizeof(int), vendor, 0, sizeof(int));
                    Buffer.BlockCopy(m_data[0], 3 * sizeof(int), vendor, 4, sizeof(int));
                    Buffer.BlockCopy(m_data[0], 2 * sizeof(int), vendor, 8, sizeof(int));
                    CpuVendor = Encoding.ASCII.GetString(vendor).TrimEnd(' ', '\t', '\0');
                    if (CpuVendor == "GenuineIntel")
                    {
                        IsIntel = true;
                    }
                    else if (CpuVendor == "AuthenticAMD")
                    {
                        IsAmd = true;
                    }
                    else if (CpuVendor == "KVMKVMKVM" ||
                             CpuVendor == "Microsoft Hv" ||
                             CpuVendor == " lrpepyh vr" || // => "prl hyperv" (Parallels)
                             CpuVendor == "VMwareVMware" ||
                             CpuVendor == "XenVMMXenVMM")
                    {
                        IsLikelyVirtualMachine = true;
                    }

                    // load bitset with flags for function 0x00000001  
                    if (nIds >= 1)
                    {
                        int eaxValue = m_data[1][eax];
                        Stepping = (byte)((eaxValue >> 0) & ((1 << 4) - 1));
                        Model = (byte)((eaxValue >> 4) & ((1 << 4) - 1));
                        Family = (byte)((eaxValue >> 8) & ((1 << 4) - 1));
                        ProcessorType = (byte)((eaxValue >> 12) & ((1 << 2) - 1));
                        ExtendedModel = (byte)((eaxValue >> 16) & ((1 << 4) - 1));
                        ExtendedFamily = (byte)((eaxValue >> 20) & ((1 << 8) - 1));

                        Func1Ecx = Set(m_data[1][ecx]);
                        Func1Edx = Set(m_data[1][edx]);
                    }

                    // load bitset with flags for function 0x00000007  
                    if (nIds >= 7)
                    {
                        Func7Ebx = Set(m_data[7][ebx]);
                        Func7Ecx = Set(m_data[7][ecx]);
                    }

                    // Calling __cpuid with 0x80000000 as the function_id argument  
                    // gets the number of the highest valid extended ID.  
                    data = cpuid.GetCpuId(unchecked((int)0x80000000));
                    var nExIds = (uint)data[0];

                    for (uint i = 0x80000000; i <= nExIds; ++i)
                    {
                        data = cpuid.GetCpuId(unchecked((int)i));
                        m_extdata.Add(data);
                    }

                    // load bitset with flags for function 0x80000001  
                    if (nExIds >= 0x80000001)
                    {
                        Func81Ecx = Set(m_extdata[1][ecx]);
                        Func81Edx = Set(m_extdata[1][edx]);
                    }

                    // Interpret CPU brand string if reported  
                    if (nExIds >= 0x80000004)
                    {
                        byte[] brand = new byte[0x40];
                        Buffer.BlockCopy(m_extdata[2], 0, brand, 0, 16);
                        Buffer.BlockCopy(m_extdata[3], 0, brand, 16, 16);
                        Buffer.BlockCopy(m_extdata[4], 0, brand, 32, 16);
                        CpuBrand = Encoding.ASCII.GetString(brand).TrimEnd(' ', '\t', '\0');
                    }

                    if (nExIds >= 0x8000000A)
                    {
                        Func8AEdx = Set(m_extdata[10][edx]);
                    }

                    MaxBasicLeave = new IntPtr(nIds);
                    MaxExtendedLeave = new IntPtr(nExIds);

#if TRACE_CPUID
                    Console.WriteLine("Basic:");
                    for (var index = 0; index < m_data.Count; index++)
                    {
                        var x = m_data[index];
                        Console.WriteLine(index + " eax => " + x[eax].ToString("x"));
                        Console.WriteLine(index + " ebx => " + x[ebx].ToString("x"));
                        Console.WriteLine(index + " ecx => " + x[ecx].ToString("x"));
                        Console.WriteLine(index + " edx => " + x[edx].ToString("x"));
                    }
                    Console.WriteLine("Extended:");
                    for (var index = 0; index < m_extdata.Count; index++)
                    {
                        var x = m_extdata[index];
                        Console.WriteLine(index + " eax => " + x[eax].ToString("x"));
                        Console.WriteLine(index + " ebx => " + x[ebx].ToString("x"));
                        Console.WriteLine(index + " ecx => " + x[ecx].ToString("x"));
                        Console.WriteLine(index + " edx => " + x[edx].ToString("x"));
                    }
#endif
                }
            }

            public readonly byte Stepping;
            public readonly byte Model;
            public readonly byte Family;
            public readonly byte ProcessorType;
            public readonly byte ExtendedModel;
            public readonly byte ExtendedFamily;

            private readonly List<int[]> m_data = new List<int[]>();
            private readonly List<int[]> m_extdata = new List<int[]>();
            public readonly string CpuVendor;
            public readonly string CpuBrand;
            public readonly bool IsIntel;
            public readonly bool IsAmd;
            public readonly bool IsLikelyVirtualMachine;
            public readonly BitArray Func1Ecx;
            public readonly BitArray Func1Edx;
            public readonly BitArray Func7Ebx;
            public readonly BitArray Func7Ecx;
            public readonly BitArray Func81Ecx;
            public readonly BitArray Func81Edx;
            public readonly BitArray Func8AEdx;

            private static BitArray Set(int value)
            {
                return new BitArray(new[] { value });
            }
        }
    }
}