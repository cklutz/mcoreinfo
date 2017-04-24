using System;
using System.Runtime.InteropServices;

namespace SysInfo
{
    public class CpuIdHelper : IDisposable
    {
        // Based on http://stackoverflow.com/questions/3216535/x86-x64-cpuid-in-c-sharp.

        private CpuIDDelegate m_cpuIdDelg;
        private CpuIDDelegate64 m_cpuIdDelg64;
        private IntPtr m_codePointer;

        public CpuIdHelper()
        {
            Prepare();
        }

        ~CpuIdHelper()
        {
            Dispose(false);
        }

        private void Prepare()
        {
            byte[] codeBytes;

            if (IntPtr.Size == 4)
            {
                codeBytes = s_x86CodeBytes;
            }
            else
            {
                codeBytes = s_x64CodeBytes;
            }

            m_codePointer = VirtualAlloc(
                IntPtr.Zero,
                new UIntPtr((uint)codeBytes.Length),
                AllocationType.COMMIT | AllocationType.RESERVE,
                MemoryProtection.EXECUTE_READWRITE
            );

            Marshal.Copy(codeBytes, 0, m_codePointer, codeBytes.Length);

            if (IntPtr.Size == 4)
            {
                m_cpuIdDelg = (CpuIDDelegate)Marshal.GetDelegateForFunctionPointer(m_codePointer, typeof(CpuIDDelegate));
            }
            else
            {
                m_cpuIdDelg64 = (CpuIDDelegate64)Marshal.GetDelegateForFunctionPointer(m_codePointer, typeof(CpuIDDelegate64));
            }
        }

        public int[] GetCpuId(int functionId)
        {
            var buffer = new int[4];
            GetCpuId(functionId, buffer);
            return buffer;
        }

        public void GetCpuId(int functionId, int[] buffer)
        {
            if (buffer.Length < 4)
                throw new ArgumentOutOfRangeException(nameof(buffer));

            var handle = default(GCHandle);
            try
            {
                handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
                if (IntPtr.Size == 4)
                    m_cpuIdDelg(functionId, buffer);
                else
                    m_cpuIdDelg64(0, functionId, buffer);
            }
            finally
            {
                if (handle != default(GCHandle))
                {
                    handle.Free();
                }
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        public void Dispose(bool disposing)
        {
            if (m_codePointer != IntPtr.Zero)
            {
                VirtualFree(m_codePointer, 0, 0x8000);
                m_codePointer = IntPtr.Zero;
            }
        }

        // void x86CpuId(int level, byte* buffer) 
        // {
        //    eax = level
        //    cpuid
        //    buffer[0] = eax
        //    buffer[4] = ebx
        //    buffer[8] = ecx
        //    buffer[12] = edx
        // }
        private static readonly byte[] s_x86CodeBytes =
        {
            0x55,                   // push        ebp  
            0x8B, 0xEC,             // mov         ebp,esp
            0x53,                   // push        ebx  
            0x57,                   // push        edi

            0x8B, 0x45, 0x08,       // mov         eax, dword ptr [ebp+8] (move level into eax)
            0x0F, 0xA2,              // cpuid

            0x8B, 0x7D, 0x0C,       // mov         edi, dword ptr [ebp+12] (move address of buffer into edi)
            0x89, 0x07,             // mov         dword ptr [edi+0], eax  (write eax, ... to buffer)
            0x89, 0x5F, 0x04,       // mov         dword ptr [edi+4], ebx 
            0x89, 0x4F, 0x08,       // mov         dword ptr [edi+8], ecx 
            0x89, 0x57, 0x0C,       // mov         dword ptr [edi+12],edx 

            0x5F,                   // pop         edi  
            0x5B,                   // pop         ebx  
            0x8B, 0xE5,             // mov         esp,ebp  
            0x5D,                   // pop         ebp 
            0xc3                    // ret
        };

        private static readonly byte[] s_x64CodeBytes = {
            0x53,                         // push rbx    this gets clobbered by cpuid
            0x89, 0xD0,
            0x0F, 0xA2,                   // cpuid 
            0x41, 0x89, 0x40, 0x00,       // mov    dword ptr [r8+0],  eax
            0x41, 0x89, 0x58, 0x04,       // mov    dword ptr [r8+4],  ebx
            0x41, 0x89, 0x48, 0x08,       // mov    dword ptr [r8+8],  ecx
            0x41, 0x89, 0x50, 0x0c,       // mov    dword ptr [r8+12], edx
            0x5b,                         // pop rbx
            0xc3                          // ret
        };

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CpuIDDelegate64(int ecx, int level, int[] buffer);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CpuIDDelegate(int level, int[] buffer);

        // ReSharper disable InconsistentNaming

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            UIntPtr dwSize,
            AllocationType flAllocationType,
            MemoryProtection flProtect
        );

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFree(
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 dwFreeType
        );

        [Flags()]
        public enum AllocationType : uint
        {
            COMMIT = 0x1000,
            RESERVE = 0x2000,
            RESET = 0x80000,
            LARGE_PAGES = 0x20000000,
            PHYSICAL = 0x400000,
            TOP_DOWN = 0x100000,
            WRITE_WATCH = 0x200000
        }

        [Flags()]
        public enum MemoryProtection : uint
        {
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            GUARD_Modifierflag = 0x100,
            NOCACHE_Modifierflag = 0x200,
            WRITECOMBINE_Modifierflag = 0x400
        }
        // ReSharper restore InconsistentNaming
    }
}