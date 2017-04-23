using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;

namespace SysInfo
{
    public class InstructionSet
    {
        public void Dump(TextWriter tw = null)
        {
            tw = tw ?? Console.Out;

            Console.WriteLine(Vendor());
            Console.WriteLine(Brand());

            support_message("3DNOW", InstructionSet._3DNOW(), tw);
            support_message("3DNOWEXT", InstructionSet._3DNOWEXT(), tw);
            support_message("ABM", InstructionSet.ABM(), tw);
            support_message("ADX", InstructionSet.ADX(), tw);
            support_message("AES", InstructionSet.AES(), tw);
            support_message("AVX", InstructionSet.AVX(), tw);
            support_message("AVX2", InstructionSet.AVX2(), tw);
            support_message("AVX512CD", InstructionSet.AVX512CD(), tw);
            support_message("AVX512ER", InstructionSet.AVX512ER(), tw);
            support_message("AVX512F", InstructionSet.AVX512F(), tw);
            support_message("AVX512PF", InstructionSet.AVX512PF(), tw);
            support_message("BMI1", InstructionSet.BMI1(), tw);
            support_message("BMI2", InstructionSet.BMI2(), tw);
            support_message("CLFSH", InstructionSet.CLFSH(), tw);
            support_message("CMPXCHG16B", InstructionSet.CMPXCHG16B(), tw);
            support_message("CX8", InstructionSet.CX8(), tw);
            support_message("ERMS", InstructionSet.ERMS(), tw);
            support_message("F16C", InstructionSet.F16C(), tw);
            support_message("FMA", InstructionSet.FMA(), tw);
            support_message("FSGSBASE", InstructionSet.FSGSBASE(), tw);
            support_message("FXSR", InstructionSet.FXSR(), tw);
            support_message("HLE", InstructionSet.HLE(), tw);
            support_message("INVPCID", InstructionSet.INVPCID(), tw);
            support_message("LAHF", InstructionSet.LAHF(), tw);
            support_message("LZCNT", InstructionSet.LZCNT(), tw);
            support_message("MMX", InstructionSet.MMX(), tw);
            support_message("MMXEXT", InstructionSet.MMXEXT(), tw);
            support_message("MONITOR", InstructionSet.MONITOR(), tw);
            support_message("MOVBE", InstructionSet.MOVBE(), tw);
            support_message("MSR", InstructionSet.MSR(), tw);
            support_message("OSXSAVE", InstructionSet.OSXSAVE(), tw);
            support_message("PCLMULQDQ", InstructionSet.PCLMULQDQ(), tw);
            support_message("POPCNT", InstructionSet.POPCNT(), tw);
            support_message("PREFETCHWT1", InstructionSet.PREFETCHWT1(), tw);
            support_message("RDRAND", InstructionSet.RDRAND(), tw);
            support_message("RDSEED", InstructionSet.RDSEED(), tw);
            support_message("RDTSCP", InstructionSet.RDTSCP(), tw);
            support_message("RTM", InstructionSet.RTM(), tw);
            support_message("SEP", InstructionSet.SEP(), tw);
            support_message("SHA", InstructionSet.SHA(), tw);
            support_message("SSE", InstructionSet.SSE(), tw);
            support_message("SSE2", InstructionSet.SSE2(), tw);
            support_message("SSE3", InstructionSet.SSE3(), tw);
            support_message("SSE4.1", InstructionSet.SSE41(), tw);
            support_message("SSE4.2", InstructionSet.SSE42(), tw);
            support_message("SSE4a", InstructionSet.SSE4a(), tw);
            support_message("SSSE3", InstructionSet.SSSE3(), tw);
            support_message("SYSCALL", InstructionSet.SYSCALL(), tw);
            support_message("TBM", InstructionSet.TBM(), tw);
            support_message("XOP", InstructionSet.XOP(), tw);
            support_message("XSAVE", InstructionSet.XSAVE(), tw);
        }

        private static void support_message(string what, bool value, TextWriter tw)
        {
            if (value)
            {
                tw.WriteLine($"{what} supported");
            }
            //else
            //{
            //    tw.WriteLine($"{what} not supported");
            //}
        }

        private static readonly InstructionSet_Internal CPU_Rep = new InstructionSet_Internal();

        public static string Vendor()
        {
            return CPU_Rep.vendor_;
        }

        public static string Brand()
        {
            return CPU_Rep.brand_;
        }

        public static bool SSE3()
        {
            return CPU_Rep.f_1_ECX_[0];
        }

        public static bool PCLMULQDQ()
        {
            return CPU_Rep.f_1_ECX_[1];
        }

        public static bool MONITOR()
        {
            return CPU_Rep.f_1_ECX_[3];
        }

        public static bool SSSE3()
        {
            return CPU_Rep.f_1_ECX_[9];
        }

        public static bool FMA()
        {
            return CPU_Rep.f_1_ECX_[12];
        }

        public static bool CMPXCHG16B()
        {
            return CPU_Rep.f_1_ECX_[13];
        }

        public static bool SSE41()
        {
            return CPU_Rep.f_1_ECX_[19];
        }

        public static bool SSE42()
        {
            return CPU_Rep.f_1_ECX_[20];
        }

        public static bool MOVBE()
        {
            return CPU_Rep.f_1_ECX_[22];
        }

        public static bool POPCNT()
        {
            return CPU_Rep.f_1_ECX_[23];
        }

        public static bool AES()
        {
            return CPU_Rep.f_1_ECX_[25];
        }

        public static bool XSAVE()
        {
            return CPU_Rep.f_1_ECX_[26];
        }

        public static bool OSXSAVE()
        {
            return CPU_Rep.f_1_ECX_[27];
        }

        public static bool AVX()
        {
            return CPU_Rep.f_1_ECX_[28];
        }

        public static bool F16C()
        {
            return CPU_Rep.f_1_ECX_[29];
        }

        public static bool RDRAND()
        {
            return CPU_Rep.f_1_ECX_[30];
        }

        public static bool MSR()
        {
            return CPU_Rep.f_1_EDX_[5];
        }

        public static bool CX8()
        {
            return CPU_Rep.f_1_EDX_[8];
        }

        public static bool SEP()
        {
            return CPU_Rep.f_1_EDX_[11];
        }

        public static bool CMOV()
        {
            return CPU_Rep.f_1_EDX_[15];
        }

        public static bool CLFSH()
        {
            return CPU_Rep.f_1_EDX_[19];
        }

        public static bool MMX()
        {
            return CPU_Rep.f_1_EDX_[23];
        }

        public static bool FXSR()
        {
            return CPU_Rep.f_1_EDX_[24];
        }

        public static bool SSE()
        {
            return CPU_Rep.f_1_EDX_[25];
        }

        public static bool SSE2()
        {
            return CPU_Rep.f_1_EDX_[26];
        }

        public static bool FSGSBASE()
        {
            return CPU_Rep.f_7_EBX_[0];
        }

        public static bool BMI1()
        {
            return CPU_Rep.f_7_EBX_[3];
        }

        public static bool HLE()
        {
            return CPU_Rep.isIntel_ && CPU_Rep.f_7_EBX_[4];
        }

        public static bool AVX2()
        {
            return CPU_Rep.f_7_EBX_[5];
        }

        public static bool BMI2()
        {
            return CPU_Rep.f_7_EBX_[8];
        }

        public static bool ERMS()
        {
            return CPU_Rep.f_7_EBX_[9];
        }

        public static bool INVPCID()
        {
            return CPU_Rep.f_7_EBX_[10];
        }

        public static bool RTM()
        {
            return CPU_Rep.isIntel_ && CPU_Rep.f_7_EBX_[11];
        }

        public static bool AVX512F()
        {
            return CPU_Rep.f_7_EBX_[16];
        }

        public static bool RDSEED()
        {
            return CPU_Rep.f_7_EBX_[18];
        }

        public static bool ADX()
        {
            return CPU_Rep.f_7_EBX_[19];
        }

        public static bool AVX512PF()
        {
            return CPU_Rep.f_7_EBX_[26];
        }

        public static bool AVX512ER()
        {
            return CPU_Rep.f_7_EBX_[27];
        }

        public static bool AVX512CD()
        {
            return CPU_Rep.f_7_EBX_[28];
        }

        public static bool SHA()
        {
            return CPU_Rep.f_7_EBX_[29];
        }

        public static bool PREFETCHWT1()
        {
            return CPU_Rep.f_7_ECX_[0];
        }

        public static bool LAHF()
        {
            return CPU_Rep.f_81_ECX_[0];
        }

        public static bool LZCNT()
        {
            return CPU_Rep.isIntel_ && CPU_Rep.f_81_ECX_[5];
        }

        public static bool ABM()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[5];
        }

        public static bool SSE4a()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[6];
        }

        public static bool XOP()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[11];
        }

        public static bool TBM()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_ECX_[21];
        }

        public static bool SYSCALL()
        {
            return CPU_Rep.isIntel_ && CPU_Rep.f_81_EDX_[11];
        }

        public static bool MMXEXT()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[22];
        }

        public static bool RDTSCP()
        {
            return CPU_Rep.isIntel_ && CPU_Rep.f_81_EDX_[27];
        }

        public static bool _3DNOWEXT()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[30];
        }

        public static bool _3DNOW()
        {
            return CPU_Rep.isAMD_ && CPU_Rep.f_81_EDX_[31];
        }

        class InstructionSet_Internal
        {
            public InstructionSet_Internal()
            {
                //int cpuInfo[4] = {-1};  
                var cpui = CpuId_Experimental.Invoke(0);

                // Calling __cpuid with 0x0 as the function_id argument  
                // gets the number of the highest valid function ID.  
                nIds_ = (uint) cpui[0];

                for (int i = 0; i <= nIds_; ++i)
                {
                    cpui = CpuId_Experimental.Invoke((uint) i);
                    data_.Add(cpui);
                }

                byte[] vendor = new byte[0x20];
                Buffer.BlockCopy(data_[0], 1 * sizeof(int), vendor, 0, sizeof(int));
                Buffer.BlockCopy(data_[0], 3 * sizeof(int), vendor, 4, sizeof(int));
                Buffer.BlockCopy(data_[0], 2 * sizeof(int), vendor, 8, sizeof(int));
                vendor_ = Encoding.ASCII.GetString(vendor);

                if (vendor_ == "GenuineIntel")
                {
                    isIntel_ = true;
                }
                else if (vendor_ == "AuthenticAMD")
                {
                    isAMD_ = true;
                }

                // load bitset with flags for function 0x00000001  
                if (nIds_ >= 1)
                {
                    f_1_ECX_ = Set(data_[1][2]);
                    f_1_EDX_ = Set(data_[1][3]);
                }

                // load bitset with flags for function 0x00000007  
                if (nIds_ >= 7)
                {
                    //f_7_EBX_ = Set((data_[7][1]));
                    f_7_EBX_ = Set(0x000023ab);
                    f_7_ECX_ = Set((data_[7][2]));
                }

                // Calling __cpuid with 0x80000000 as the function_id argument  
                // gets the number of the highest valid extended ID.  
                cpui = CpuId_Experimental.Invoke(0x80000000);
                nExIds_ = (uint) cpui[0];

                for (uint i = 0x80000000; i <= nExIds_; ++i)
                {
                    cpui = CpuId_Experimental.Invoke(i);
                    extdata_.Add(cpui);
                }

                // load bitset with flags for function 0x80000001  
                if (nExIds_ >= 0x80000001)
                {
                    f_81_ECX_ = Set((extdata_[1][2]));
                    f_81_EDX_ = Set((extdata_[1][3]));
                }

                // Interpret CPU brand string if reported  
                if (nExIds_ >= 0x80000004)
                {
                    byte[] brand = new byte[0x40];
                    Buffer.BlockCopy(extdata_[2], 0, brand, 0, 16);
                    Buffer.BlockCopy(extdata_[3], 0, brand, 16, 16);
                    Buffer.BlockCopy(extdata_[4], 0, brand, 32, 16);
                    brand_ = Encoding.ASCII.GetString(brand);
                }
            }


            public uint nIds_;
            public uint nExIds_;
            public string vendor_;
            public string brand_;
            public bool isIntel_;
            public bool isAMD_;
            public BitArray f_1_ECX_;
            public BitArray f_1_EDX_;
            public BitArray f_7_EBX_;
            public BitArray f_7_ECX_;
            public BitArray f_81_ECX_;
            public BitArray f_81_EDX_;
            public List<int[]> data_ = new List<int[]>();
            public List<int[]> extdata_ = new List<int[]>();

            private BitArray Set(int value)
            {
                Console.WriteLine("===> {0:x08}", value);
                return new BitArray(new [] { value });
            }

            public static int ReverseBits(int n)
            {
                uint v = (uint) n;

                unchecked
                {
                    // swap odd and even bits
                    v = ((v >> 1) & 0x55555555) | ((v & 0x55555555) << 1);
                    // swap consecutive pairs
                    v = ((v >> 2) & 0x33333333) | ((v & 0x33333333) << 2);
                    // swap nibbles ... 
                    v = ((v >> 4) & 0x0F0F0F0F) | ((v & 0x0F0F0F0F) << 4);
                    // swap bytes
                    v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) << 8);
                    // swap 2-byte long pairs
                    v = (v >> 16) | (v << 16);
                }

                return (int) v;
            }
        };
    }
}