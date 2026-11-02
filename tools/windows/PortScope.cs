using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

public static class PortScope {
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimit {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcesses;
        public UIntPtr Affinity;
        public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters {
        public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimit {
        public BasicLimit Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimit limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")] private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    // Windows CRT quoting, including empty arguments, embedded quotes and trailing backslashes.
    internal static string Quote(string argument) {
        var result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char value in argument) {
            if (value == '\\') { slashes++; continue; }
            if (value == '"') result.Append('\\', slashes * 2 + 1).Append('"');
            else result.Append('\\', slashes).Append(value);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    private static int Main(string[] arguments) {
        Console.OutputEncoding = new UTF8Encoding(false);
        string root = AppDomain.CurrentDomain.BaseDirectory;
        string node = Path.Combine(root, "runtime", "node.exe");
        string entry = Path.Combine(root, "app", "server.js");
        if (!File.Exists(node) || !File.Exists(entry)) {
            Console.Error.WriteLine("PortScope: extract the complete portable ZIP before running PortScope.exe. Keep app/ and runtime/ beside it.");
            return 1;
        }
        bool open = arguments.Length == 0;
        var command = new StringBuilder(Quote(entry));
        foreach (string argument in arguments) {
            if (argument == "--open") { open = true; continue; }
            command.Append(' ').Append(Quote(argument));
        }
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) { Console.Error.WriteLine("PortScope: unable to create a private process job."); return 1; }
        var limits = new ExtendedLimit();
        limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: only this server and its workers.
        if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(ExtendedLimit)))) {
            CloseHandle(job); Console.Error.WriteLine("PortScope: unable to configure process cleanup."); return 1;
        }
        Timer shutdown = null;
        ConsoleCancelEventHandler cancel = delegate(object sender, ConsoleCancelEventArgs e) {
            e.Cancel = true; // The attached Node child receives the same Ctrl+C and shuts down gracefully.
            if (shutdown == null) shutdown = new Timer(delegate { TerminateJobObject(job, 1); }, null, 5000, Timeout.Infinite);
        };
        Console.CancelKeyPress += cancel;
        try {
            var start = new ProcessStartInfo(node, command.ToString());
            start.WorkingDirectory = Path.Combine(root, "app");
            start.UseShellExecute = false;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.StandardOutputEncoding = new UTF8Encoding(false);
            start.StandardErrorEncoding = new UTF8Encoding(false);
            // Do not let inherited development preload flags execute code in the portable runtime.
            start.EnvironmentVariables.Remove("NODE_OPTIONS");
            start.EnvironmentVariables.Remove("NODE_PATH");
            using (var child = new Process()) {
                child.StartInfo = start;
                int browserOpened = 0;
                child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                    if (e.Data == null) return;
                    Console.WriteLine(e.Data);
                    if (!open) return;
                    var match = Regex.Match(e.Data, @"-> http://127\.0\.0\.1:([0-9]{1,5})/");
                    int port;
                    if (!match.Success || !int.TryParse(match.Groups[1].Value, out port) || port < 1 || port > 65535 ||
                        Interlocked.Exchange(ref browserOpened, 1) != 0) return;
                    // Launch from outside the server job, so closing PortScope never terminates the browser.
                    try { Process.Start(new ProcessStartInfo("http://127.0.0.1:" + port + "/") { UseShellExecute = true }); }
                    catch { Console.Error.WriteLine("PortScope: browser could not open; use the local URL printed above."); }
                };
                child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                if (!child.Start()) throw new InvalidOperationException("Node could not start.");
                if (!AssignProcessToJobObject(job, child.Handle) && !child.HasExited) {
                    child.Kill(); throw new InvalidOperationException("Could not attach the server to its private cleanup job.");
                }
                child.BeginOutputReadLine(); child.BeginErrorReadLine();
                child.WaitForExit();
                return child.ExitCode;
            }
        } catch (Exception error) {
            Console.Error.WriteLine("PortScope: " + error.Message);
            return 1;
        } finally {
            Console.CancelKeyPress -= cancel;
            if (shutdown != null) shutdown.Dispose();
            CloseHandle(job);
        }
    }
}
