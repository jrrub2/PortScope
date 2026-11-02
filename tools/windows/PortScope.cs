using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using Microsoft.Win32.SafeHandles;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

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
    [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] private static extern bool FreeConsole();
    [DllImport("kernel32.dll")] private static extern bool AllocConsole();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll")] private static extern bool SetStdHandle(int standard, IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] private struct ProcessBasic { public IntPtr Reserved, Peb, Reserved2, Reserved3, Id, Parent; }
    [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr process, int kind, ref ProcessBasic data, int size, out int returned);

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


    private static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 65536 };
    private static readonly string[] Managed = { "app", "runtime", "PortScope.exe", "LICENSE", "START-HERE.txt" };
    private static readonly Regex NoncePattern = new Regex("^[a-f0-9]{32}$");
    private static readonly Regex VersionPattern = new Regex("^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$");
    private const long MiB = 1024 * 1024;

    private static string Canonical(string value) {
        string full = Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar);
        if (full.StartsWith(@"\\") || full.Length < 3 || full[1] != ':' || full.Substring(2).Contains(":")) throw new IOException("Only local Windows drive paths are supported.");
        return full;
    }
    private static void NoLinks(string value) {
        string current = Path.GetFullPath(value);
        while (!String.IsNullOrEmpty(current)) {
            if (!File.Exists(current) && !Directory.Exists(current)) throw new IOException("A required path is missing: " + current);
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) throw new IOException("Updates refuse linked or reparse-point paths: " + current);
            string parent = Path.GetDirectoryName(current);
            if (parent == current) break;
            current = parent;
        }
    }
    private static void NoLinkedTree(string directory) {
        NoLinks(directory);
        foreach (string entry in Directory.GetFileSystemEntries(directory)) {
            if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) throw new IOException("A managed directory contains a reparse point.");
            if (Directory.Exists(entry)) NoLinkedTree(entry);
        }
    }
    private static string PortableRoot(string value) {
        string root = Canonical(value); NoLinks(root);
        for (string current = root; !String.IsNullOrEmpty(current); current = Path.GetDirectoryName(current)) {
            if (File.Exists(Path.Combine(current, ".git")) || Directory.Exists(Path.Combine(current, ".git"))) throw new IOException("Automatic updates are disabled in or below a source checkout.");
        }
        NoLinks(Path.Combine(root, "app")); NoLinks(Path.Combine(root, "runtime"));
        foreach (string file in new [] { "PortScope.exe", "app/server.js", "app/package.json", "runtime/node.exe" }) NoLinks(Path.Combine(root, file));
        return root;
    }
    private static string StagePath(string root, string nonce) {
        if (!NoncePattern.IsMatch(nonce ?? "")) throw new IOException("Invalid update session.");
        string stage = Path.Combine(root, ".portscope-update", nonce); NoLinks(stage); return stage;
    }
    private static Dictionary<string, object> ReadJson(string file, params string[] keys) {
        NoLinks(file); var info = new FileInfo(file);
        if (info.Length > 65536) throw new IOException("Update metadata exceeds its limit.");
        var data = Json.DeserializeObject(File.ReadAllText(file, Encoding.UTF8)) as Dictionary<string, object>;
        if (data == null) throw new IOException("Invalid update metadata.");
        if (keys.Length != 0) {
            if (data.Count != keys.Length) throw new IOException("Unexpected update metadata fields.");
            foreach (string key in keys) if (!data.ContainsKey(key)) throw new IOException("Missing update metadata field.");
        }
        return data;
    }
    private static int Integer(object value, int min, int max) {
        if (!(value is int) && !(value is long)) throw new IOException("Expected an integer update field.");
        long number = Convert.ToInt64(value, CultureInfo.InvariantCulture);
        if (number < min || number > max) throw new IOException("Update field is outside its safe range.");
        return (int)number;
    }
    private static string Text(object value) { string text = value as string; if (text == null) throw new IOException("Expected an update text field."); return text; }
    private static void WriteExclusive(string file, object value) {
        byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(value));
        using (var stream = new FileStream(file, FileMode.CreateNew, FileAccess.Write, FileShare.Read)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    private static string Fingerprint(Stream stream) {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    private static string Fingerprint(string file) { using (var stream = File.OpenRead(file)) return Fingerprint(stream); }
    private static bool SameHash(string left, string right) { if (left.Length != right.Length) return false; int result = 0; for (int i = 0; i < left.Length; i++) result |= left[i] ^ right[i]; return result == 0; }

    private static string ZipPath(string raw) {
        string value = raw.Replace('\\', '/');
        if (value.Length > 220 || value.StartsWith("/") || value.Contains(":") || value.Contains("//")) throw new IOException("Unsafe ZIP path.");
        if (value.EndsWith("/")) value = value.Substring(0, value.Length - 1);
        foreach (string part in value.Split('/')) {
            if (part == "" || part.StartsWith(".") || part.EndsWith(".") || part.EndsWith(" ") ||
                !Regex.IsMatch(part, @"^[a-zA-Z0-9_@ .-]+$") ||
                Regex.IsMatch(part, @"^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])([.]|$)", RegexOptions.IgnoreCase)) throw new IOException("Unsafe ZIP component.");
        }
        return value;
    }
    private static bool AllowedFile(string file) {
        if (Array.IndexOf(new [] { "PortScope.exe", "LICENSE", "START-HERE.txt", "app/server.js", "app/package.json", "runtime/node.exe", "runtime/runtime.json", "runtime/NODE-LICENSE.txt" }, file) >= 0) return true;
        if (Regex.IsMatch(file, @"^app/lib/[a-zA-Z0-9_-]+[.](js|ps1)$")) return true;
        if (!file.StartsWith("app/web/", StringComparison.Ordinal)) return false;
        string extension = Path.GetExtension(file).ToLowerInvariant();
        return Array.IndexOf(new [] { ".html", ".js", ".css", ".svg", ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".json", ".txt" }, extension) >= 0 &&
            !Regex.IsMatch(file, @"(^|/)([.]|.*(credential|cookie|profile|secret|export|password|token|history|settings))", RegexOptions.IgnoreCase);
    }
    private static void CheckPe(string file, bool managed) {
        using (var stream = File.OpenRead(file)) using (var reader = new BinaryReader(stream)) {
            if (stream.Length < 256 || reader.ReadUInt16() != 0x5a4d) throw new IOException("Invalid Windows executable.");
            stream.Position = 0x3c; int offset = reader.ReadInt32();
            if (offset < 64 || offset > stream.Length - 256) throw new IOException("Invalid PE header.");
            stream.Position = offset;
            if (reader.ReadUInt32() != 0x4550 || reader.ReadUInt16() != 0x8664) throw new IOException("The update must contain x64 PE executables.");
            stream.Position = offset + 24;
            if (reader.ReadUInt16() != 0x20b) throw new IOException("Invalid x64 optional header.");
            if (managed) {
                stream.Position = offset + 24 + 112 + 14 * 8;
                if (reader.ReadUInt32() == 0 || reader.ReadUInt32() == 0) throw new IOException("The launcher must be a managed native executable.");
            }
        }
    }
    private static string ExtractPackage(string root, string stage, string version, string hash, int size) {
        string archive = Path.Combine(stage, "package.zip"); NoLinks(archive);
        if (!VersionPattern.IsMatch(version) || !Regex.IsMatch(hash, "^[a-f0-9]{64}$") || new FileInfo(archive).Length != size || size > 150 * MiB) throw new IOException("Invalid staged package metadata.");
        string unpacked = Path.Combine(stage, "unpacked");
        if (Directory.Exists(unpacked) || File.Exists(unpacked)) throw new IOException("This update was already unpacked; recover or use a new session.");
        string prefix = "PortScope-" + version + "-windows-x64";
        using (var stream = new FileStream(archive, FileMode.Open, FileAccess.Read, FileShare.Read)) {
            if (!SameHash(Fingerprint(stream), hash)) throw new IOException("Staged package SHA256 verification failed.");
            stream.Position = 0;
            using (var zip = new ZipArchive(stream, ZipArchiveMode.Read, true)) {
                if (zip.Entries.Count == 0 || zip.Entries.Count > 10000) throw new IOException("ZIP entry limit exceeded.");
                long total = 0; var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var files = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                var spellings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var entry in zip.Entries) {
                    string name = ZipPath(entry.FullName);
                    if (!names.Add(name)) throw new IOException("Duplicate or case-aliased ZIP entry.");
                    string componentPath = ""; foreach (string component in name.Split('/')) {
                        componentPath = componentPath == "" ? component : componentPath + "/" + component; string prior;
                        if (spellings.TryGetValue(componentPath, out prior) && prior != componentPath) throw new IOException("Case-aliased ZIP directory denied.");
                        spellings[componentPath] = componentPath;
                    }
                    bool directory = entry.FullName.EndsWith("/") || entry.FullName.EndsWith(@"\");
                    uint attributes = unchecked((uint)entry.ExternalAttributes); uint kind = (attributes >> 16) & 0xf000;
                    if ((attributes & 0x400) != 0 || (kind != 0 && kind != (directory ? 0x4000U : 0x8000U))) throw new IOException("Linked or special ZIP entry denied.");
                    if (name != prefix && !name.StartsWith(prefix + "/", StringComparison.Ordinal)) throw new IOException("The ZIP root does not match the requested release.");
                    string relative = name == prefix ? "" : name.Substring(prefix.Length + 1);
                    if (directory) {
                        if (entry.Length != 0 || !(relative == "" || relative == "app" || relative == "app/lib" || relative == "app/web" || relative.StartsWith("app/web/") || relative == "runtime")) throw new IOException("Unexpected ZIP directory.");
                    } else {
                        if (!AllowedFile(relative) || entry.Length > 120 * MiB || entry.Length < 0) throw new IOException("Unexpected or oversized ZIP file: " + relative);
                        total += entry.Length; if (total > 300 * MiB) throw new IOException("Expanded ZIP size exceeds 300 MiB.");
                        files.Add(name);
                    }
                }
                foreach (string name in names) {
                    for (string parent = Path.GetDirectoryName(name.Replace('/', Path.DirectorySeparatorChar)); !String.IsNullOrEmpty(parent); parent = Path.GetDirectoryName(parent))
                        if (files.Contains(parent.Replace(Path.DirectorySeparatorChar, '/'))) throw new IOException("ZIP file/directory alias denied.");
                }
                foreach (string required in new [] { "PortScope.exe", "LICENSE", "START-HERE.txt", "app/server.js", "app/package.json", "app/web/index.html", "app/web/THIRD-PARTY-NOTICES.txt", "runtime/node.exe", "runtime/runtime.json", "runtime/NODE-LICENSE.txt" })
                    if (!files.Contains(prefix + "/" + required)) throw new IOException("Required runtime file is missing: " + required);
                Directory.CreateDirectory(unpacked); NoLinks(unpacked);
                foreach (var entry in zip.Entries) {
                    string name = ZipPath(entry.FullName); string target = Path.Combine(unpacked, name.Replace('/', Path.DirectorySeparatorChar));
                    if (entry.FullName.EndsWith("/") || entry.FullName.EndsWith(@"\")) { Directory.CreateDirectory(target); continue; }
                    Directory.CreateDirectory(Path.GetDirectoryName(target));
                    using (var source = entry.Open()) using (var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                        byte[] buffer = new byte[65536]; long copied = 0; int count;
                        while ((count = source.Read(buffer, 0, buffer.Length)) != 0) { copied += count; if (copied > entry.Length || copied > 120 * MiB) throw new IOException("ZIP stream exceeds its declared size."); output.Write(buffer, 0, count); }
                        if (copied != entry.Length) throw new IOException("Incomplete ZIP entry.");
                    }
                }
            }
        }
        string payload = Path.Combine(unpacked, prefix);
        if (Text(ReadJson(Path.Combine(payload, "app/package.json"))["version"]) != version) throw new IOException("Package version differs from release metadata.");
        CheckPe(Path.Combine(payload, "PortScope.exe"), true); CheckPe(Path.Combine(payload, "runtime/node.exe"), false);
        var runtime = ReadJson(Path.Combine(payload, "runtime/runtime.json"));
        if (Text(runtime["architecture"]) != "x64" || !SameHash(Text(runtime["nodeSha256"]), Fingerprint(Path.Combine(payload, "runtime/node.exe")))) throw new IOException("Bundled runtime identity mismatch.");
        return payload;
    }


    private static void MoveManaged(string source, string target) {
        if (Directory.Exists(source)) Directory.Move(source, target); else File.Move(source, target);
    }
    private static void Journal(string file, object record, bool create) {
        if (!create) NoLinks(file);
        byte[] bytes = Encoding.UTF8.GetBytes(Json.Serialize(record) + "\n");
        using (var stream = new FileStream(file, create ? FileMode.CreateNew : FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough)) { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
    }
    private static void JournalMove(string journal, string source, string target, string phase, string item, List<string> completed, bool restoring = false) {
        try { Journal(journal, new { status = "moving", phase = phase, item = item, source = source, target = target, step = "before" }, false); } catch { if (!restoring) throw; }
        MoveManaged(source, target); completed.Add(item);
        try { Journal(journal, new { status = "moving", phase = phase, item = item, source = source, target = target, step = "after" }, false); } catch { if (!restoring) throw; }
    }
    private static void CheckPending(string root, string allowedNonce) {
        string updateBase = Path.Combine(root, ".portscope-update");
        if (!Directory.Exists(updateBase)) return;
        NoLinks(updateBase);
        foreach (string directory in Directory.GetDirectories(updateBase)) {
            string nonce = Path.GetFileName(directory); if (!NoncePattern.IsMatch(nonce)) continue;
            NoLinks(directory); string journal = Path.Combine(directory, "journal.jsonl");
            if (!File.Exists(journal)) continue;
            NoLinks(journal);
            if (nonce == allowedNonce) continue; // Only the helper's exact health restart may run inside its active transaction.
            bool complete = false;
            try {
                if (new FileInfo(journal).Length > MiB) throw new IOException();
                string[] lines = File.ReadAllLines(journal, Encoding.UTF8);
                if (lines.Length < 2 || lines.Length > 256) throw new IOException();
                var first = Json.DeserializeObject(lines[0]) as Dictionary<string, object>;
                var last = Json.DeserializeObject(lines[lines.Length - 1]) as Dictionary<string, object>;
                complete = first != null && last != null && Text(first["root"]) == Canonical(root) && Text(first["nonce"]) == nonce &&
                    (Text(last["status"]) == "updated" || Text(last["status"]) == "rolled-back");
            } catch { }
            if (!complete) throw new IOException("Incomplete update requires manual recovery. Do not launch partially swapped files. Journal: " + journal + "; original files: " + Path.Combine(directory, "backup") + ". Preserve this entire session, use journal before/after moves to restore only app, runtime, PortScope.exe, LICENSE and START-HERE.txt; then archive the session after recovery.");
        }
    }
    private static void Preflight(string root, string stage) {
        PortableRoot(root); NoLinks(stage); CheckPending(root, Path.GetFileName(stage)); NoLinkedTree(Path.Combine(root, "app")); NoLinkedTree(Path.Combine(root, "runtime"));
        foreach (string item in Managed) NoLinks(Path.Combine(root, item));
        string probe = Path.Combine(root, ".portscope-write-" + Guid.NewGuid().ToString("N"));
        using (new FileStream(probe, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1, FileOptions.DeleteOnClose)) { }
    }
    private static bool Healthy(int port, string version, string nonce, int pid) {
        try {
            var request = (HttpWebRequest)WebRequest.Create("http://127.0.0.1:" + port + "/api/health");
            request.Proxy = null; request.AllowAutoRedirect = false; request.Timeout = 1000; request.ReadWriteTimeout = 1000;
            using (var response = (HttpWebResponse)request.GetResponse()) {
                if (response.StatusCode != HttpStatusCode.OK || response.ContentLength > 16384) return false;
                using (var stream = response.GetResponseStream()) using (var memory = new MemoryStream()) {
                    byte[] bytes = new byte[4096]; int count;
                    while ((count = stream.Read(bytes, 0, bytes.Length)) != 0) { if (memory.Length + count > 16384) return false; memory.Write(bytes, 0, count); }
                    var data = Json.DeserializeObject(Encoding.UTF8.GetString(memory.ToArray())) as Dictionary<string, object>;
                    return data != null && Text(data["app"]) == "PortScope" && Text(data["version"]) == version &&
                        data["ok"] is bool && (bool)data["ok"] && data["ready"] is bool && (bool)data["ready"] &&
                        Integer(data["pid"], 1, Int32.MaxValue) == pid && Text(data["updateNonce"]) == nonce;
                }
            }
        } catch { return false; }
    }
    private static void StopTrial(Process trial, string stage, string marker) {
        string cancel = Path.Combine(stage, marker + ".cancel");
        if (!File.Exists(cancel)) WriteExclusive(cancel, new { cancel = true });
        if (!trial.WaitForExit(5000)) {
            // Process.Handle is already pinned by Start(), never kill a PID looked up from package metadata.
            trial.Kill(); if (!trial.WaitForExit(5000)) throw new IOException("Trial launcher could not be stopped safely; retain backup for manual recovery.");
        }
    }
    private static Process StartTrial(string root, string nonce, string marker) {
        var start = new ProcessStartInfo(Path.Combine(root, "PortScope.exe"), "--update-health " + Quote(nonce) + " " + Quote(marker));
        start.UseShellExecute = false; start.WorkingDirectory = root;
        return Process.Start(start);
    }
    private static bool WaitTrial(Process trial, string stage, string marker, int port, string version, string nonce) {
        DateTime until = DateTime.UtcNow.AddSeconds(25);
        string markerPath = Path.Combine(stage, marker + ".json");
        while (DateTime.UtcNow < until && !trial.HasExited) {
            if (File.Exists(markerPath)) {
                try {
                    var data = ReadJson(markerPath, "pid", "startedAt", "parentPid", "nonce");
                    if (Text(data["nonce"]) != nonce || Integer(data["parentPid"], 1, Int32.MaxValue) != trial.Id) throw new IOException("Trial identity mismatch.");
                    using (var server = Process.GetProcessById(Integer(data["pid"], 1, Int32.MaxValue))) {
                        IntPtr pinned = server.Handle; var basic = new ProcessBasic(); int returned;
                        if (NtQueryInformationProcess(pinned, 0, ref basic, Marshal.SizeOf(typeof(ProcessBasic)), out returned) != 0 || basic.Parent.ToInt64() != trial.Id) throw new IOException("Trial server is not owned by the pinned launcher.");
                        if (server.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture) != Text(data["startedAt"])) throw new IOException("Trial server identity changed.");
                        if (!server.HasExited && Healthy(port, version, nonce, server.Id)) return true;
                    }
                } catch (IOException) { throw; } catch { }
            }
            Thread.Sleep(100);
        }
        return false;
    }
    private static int ApplyUpdate(string rootArgument, string nonce) {
        string root = PortableRoot(rootArgument), stage = StagePath(root, nonce);
        string log = Path.Combine(stage, "update.log");
        Action<string> report = message => { File.AppendAllText(log, DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine, Encoding.UTF8); try { Console.WriteLine(message); } catch (IOException) { } };
        string backup = Path.Combine(stage, "backup");
        var backed = new List<string>(); var installed = new List<string>(); Process trial = null;
        string journal = Path.Combine(stage, "journal.jsonl"); bool journalStarted = false, finished = false, oldExited = false;
        int port = 0, interval = 0; string oldVersion = Text(ReadJson(Path.Combine(root, "app/package.json"))["version"]);
        try {
            var handoff = ReadJson(Path.Combine(stage, "handoff.json"), "port", "interval");
            port = Integer(handoff["port"], 1, 65535); interval = Integer(handoff["interval"], 1000, Int32.MaxValue);
            if (!Regex.IsMatch(Environment.GetEnvironmentVariable("PORTSCOPE_CONTROL_TOKEN") ?? "", "^[a-f0-9]{64}$")) throw new IOException("Missing private update restart authority.");
            var handles = Json.DeserializeObject(Console.ReadLine() ?? "") as Dictionary<string, object>;
            if (handles == null || handles.Count != 2) throw new IOException("Missing pinned old process handles.");
            IntPtr oldLauncher = new IntPtr(Convert.ToInt64(Text(handles["launcherHandle"]), CultureInfo.InvariantCulture));
            IntPtr oldServer = new IntPtr(Convert.ToInt64(Text(handles["serverHandle"]), CultureInfo.InvariantCulture));
            Console.WriteLine("READY"); Console.Out.Flush();
            try {
                if (WaitForSingleObject(oldServer, 10000) != 0 || WaitForSingleObject(oldLauncher, 10000) != 0) throw new IOException("The previous application did not exit safely.");
                oldExited = true;
            } finally { CloseHandle(oldServer); CloseHandle(oldLauncher); }
            // The handshake pipe belongs to the old launcher. Create an independent console before it disappears.
            FreeConsole(); AllocConsole();
            var consoleHandle = CreateFile("CONOUT$", 0x40000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero);
            if (consoleHandle.IsInvalid) throw new IOException("The updater could not open an independent console.");
            SetStdHandle(-11, consoleHandle.DangerousGetHandle()); SetStdHandle(-12, consoleHandle.DangerousGetHandle());
            var writer = new StreamWriter(new FileStream(consoleHandle, FileAccess.Write), new UTF8Encoding(false)) { AutoFlush = true };
            Console.SetOut(writer); Console.SetError(writer);
            Preflight(root, stage);
            var request = ReadJson(Path.Combine(stage, "request.json"), "version", "sha256", "size", "archive");
            string version = Text(request["version"]);
            if (Text(request["archive"]) != "package.zip") throw new IOException("Unexpected package archive name.");
            string payload = ExtractPackage(root, stage, version, Text(request["sha256"]), Integer(request["size"], 1, 150 * (int)MiB));
            Preflight(root, stage);
            if (Directory.Exists(backup) || File.Exists(backup)) throw new IOException("A backup already exists for this update session.");
            Journal(journal, new { status = "prepared", root = root, nonce = nonce, oldVersion = oldVersion, version = version, managed = Managed, recovery = "Retain all session files; before/after move paths describe exactly which original managed entries belong in root. Never delete root or backup recursively." }, true); journalStarted = true;
            Directory.CreateDirectory(backup); NoLinks(backup);
            foreach (string item in Managed) JournalMove(journal, Path.Combine(root, item), Path.Combine(backup, item), "backup", item, backed);
            foreach (string item in Managed) JournalMove(journal, Path.Combine(payload, item), Path.Combine(root, item), "install", item, installed);
            trial = StartTrial(root, nonce, "startup");
            if (!WaitTrial(trial, stage, "startup", port, version, nonce)) throw new IOException("Updated server did not become healthy on the original port within 25 seconds.");
            Journal(journal, new { status = "updated", version = version, port = port }, false); finished = true;
            WriteExclusive(Path.Combine(stage, "result.json"), new { ok = true, version = version, port = port, status = "updated" });
            report("UPDATE_SUCCESS " + version + "; previous managed files retained at " + backup);
            return 0;
        } catch (Exception error) {
            if (finished) { try { report("Updated server is healthy; post-commit reporting failed. Journal: " + journal); } catch { } return 0; }
            try { report("UPDATE_FAILED: " + error.Message); } catch { }
            if (!oldExited) return 1; // Never restart or move files while either pinned old process may still be alive.
            try {
                if (trial != null) StopTrial(trial, stage, "startup");
                if (installed.Count > 0) {
                    string failed = Path.Combine(stage, "failed-new"); if (Directory.Exists(failed)) throw new IOException("Failed payload recovery path already exists.");
                    Directory.CreateDirectory(failed);
                    for (int i = installed.Count - 1; i >= 0; i--) JournalMove(journal, Path.Combine(root, installed[i]), Path.Combine(failed, installed[i]), "remove-new", installed[i], new List<string>(), true);
                }
                for (int i = backed.Count - 1; i >= 0; i--) JournalMove(journal, Path.Combine(backup, backed[i]), Path.Combine(root, backed[i]), "restore-old", backed[i], new List<string>(), true);
                if (port != 0) {
                    var recovery = StartTrial(root, nonce, "recovery");
                    if (!WaitTrial(recovery, stage, "recovery", port, oldVersion, nonce)) { StopTrial(recovery, stage, "recovery"); throw new IOException("Old files restored, but the original-port restart was not confirmed."); }
                    report("ROLLBACK_SUCCESS: original version restored on the same port.");
                }
                if (journalStarted) Journal(journal, new { status = "rolled-back", version = oldVersion, port = port }, false);
                WriteExclusive(Path.Combine(stage, "result.json"), new { ok = false, status = "rolled-back", error = error.Message });
            } catch (Exception restoreError) { report("MANUAL_RECOVERY_REQUIRED: " + restoreError.Message + "; preserve " + stage); }
            return 1;
        } finally { if (trial != null) trial.Dispose(); }
    }
    private static int BeginUpdate(string root, string nonce, Process server, string controlToken) {
        string stage = StagePath(PortableRoot(root), nonce);
        string temp = Path.Combine(Path.GetTempPath(), "PortScope-updater-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp); NoLinks(temp);
        string helperPath = Path.Combine(temp, "PortScope.exe");
        File.Copy(Process.GetCurrentProcess().MainModule.FileName, helperPath, false);
        var start = new ProcessStartInfo(helperPath, "--apply-update " + Quote(root) + " " + Quote(nonce));
        start.UseShellExecute = false; start.RedirectStandardInput = true; start.RedirectStandardOutput = true; start.WorkingDirectory = temp;
        start.EnvironmentVariables["PORTSCOPE_CONTROL_TOKEN"] = controlToken;
        using (var helper = Process.Start(start)) {
            IntPtr parentHandle, serverHandle;
            using (var current = Process.GetCurrentProcess()) {
                if (!DuplicateHandle(GetCurrentProcess(), current.Handle, helper.Handle, out parentHandle, 0, false, 2) ||
                    !DuplicateHandle(GetCurrentProcess(), server.Handle, helper.Handle, out serverHandle, 0, false, 2)) { helper.Kill(); throw new IOException("Could not pin previous processes for update."); }
            }
            helper.StandardInput.WriteLine(Json.Serialize(new { launcherHandle = parentHandle.ToInt64().ToString(CultureInfo.InvariantCulture), serverHandle = serverHandle.ToInt64().ToString(CultureInfo.InvariantCulture) })); helper.StandardInput.Close();
            var ready = helper.StandardOutput.ReadLineAsync();
            if (!ready.Wait(15000) || ready.Result != "READY") { helper.Kill(); throw new IOException("Update helper could not acquire a safe handoff. See " + stage); }
            // Drain the one-line handshake only. The helper is outside the Node cleanup job and continues after this process exits.
            Console.WriteLine("PortScope: applying update; recovery log: " + Path.Combine(stage, "update.log"));
        }
        return 0;
    }

    private static int SelfCheck() {
        foreach (string bad in new [] { "../escape", "a/../b", "C:/file", "/root", "a//b", "a/NUL.txt", "a/file.", "a/file ", "a:ads", "a/CON" }) {
            bool refused = false; try { ZipPath(bad); } catch (IOException) { refused = true; }
            if (!refused) throw new IOException("ZIP self-check failed: " + bad);
        }
        if (ZipPath(@"PortScope-2.2.1-windows-x64\app\server.js") != "PortScope-2.2.1-windows-x64/app/server.js" || AllowedFile("app/web/secret.json") || AllowedFile("runtime/extra.exe")) throw new IOException("ZIP allowlist self-check failed.");
        // ponytail: interrupted installs stop with a durable journal; automatic crash recovery waits for a dedicated recovery command.
        Console.WriteLine("PortScope launcher self-check passed; no update applied."); return 0;
    }
    private static int Main(string[] arguments) {
        Console.OutputEncoding = new UTF8Encoding(false);
        try {
            if (arguments.Length == 1 && arguments[0] == "--self-check") return SelfCheck();
            if (arguments.Length == 3 && arguments[0] == "--apply-update") return ApplyUpdate(arguments[1], arguments[2]);
            if (arguments.Length == 3 && arguments[0] == "--validate-package") {
                string validateRoot = PortableRoot(arguments[1]), stage = StagePath(validateRoot, arguments[2]);
                var request = ReadJson(Path.Combine(stage, "request.json"), "version", "sha256", "size", "archive");
                if (Text(request["archive"]) != "package.zip") throw new IOException("Unexpected archive name.");
                ExtractPackage(validateRoot, stage, Text(request["version"]), Text(request["sha256"]), Integer(request["size"], 1, 150 * (int)MiB));
                Console.WriteLine("Package validated and unpacked; no application files changed or executed."); return 0;
            }
        } catch (Exception error) { Console.Error.WriteLine("PortScope update: " + error.Message); return 1; }
        string root = AppDomain.CurrentDomain.BaseDirectory;
        bool trial = arguments.Length == 3 && arguments[0] == "--update-health";
        string updateNonce = Guid.NewGuid().ToString("N"), sessionNonce = Guid.NewGuid().ToString("N"), trialStage = null, trialMarker = null;
        int trialPort = 0; string controlToken = Environment.GetEnvironmentVariable("PORTSCOPE_CONTROL_TOKEN");
        if (!Regex.IsMatch(controlToken ?? "", "^[a-f0-9]{64}$")) {
            byte[] secret = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(secret);
            controlToken = BitConverter.ToString(secret).Replace("-", "").ToLowerInvariant();
        }
        if (trial) {
            try {
                root = PortableRoot(root); trialStage = StagePath(root, arguments[1]); updateNonce = arguments[1]; trialMarker = arguments[2];
                if (trialMarker != "startup" && trialMarker != "recovery") throw new IOException("Invalid health handoff marker.");
                var handoff = ReadJson(Path.Combine(trialStage, "handoff.json"), "port", "interval");
                trialPort = Integer(handoff["port"], 1, 65535);
                arguments = new [] { "--port", trialPort.ToString(CultureInfo.InvariantCulture), "--interval", Integer(handoff["interval"], 1000, Int32.MaxValue).ToString(CultureInfo.InvariantCulture) };
            } catch (Exception error) { Console.Error.WriteLine("PortScope update restart: " + error.Message); return 1; }
        }
        try { CheckPending(root, trial ? updateNonce : null); }
        catch (Exception error) { Console.Error.WriteLine("PortScope: " + error.Message); return 1; }
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
            foreach (string name in new [] { "PORTSCOPE_UPDATE_PROTOCOL", "PORTSCOPE_PORTABLE_ROOT", "PORTSCOPE_UPDATE_DIR", "PORTSCOPE_UPDATE_RESTART", "PORTSCOPE_UPDATE_HEALTH_NONCE" }) start.EnvironmentVariables.Remove(name);
            bool portable = false;
            try {
                root = PortableRoot(root);
                string updateBase = Path.Combine(root, ".portscope-update");
                if (Directory.Exists(updateBase) || File.Exists(updateBase)) NoLinks(updateBase);
                start.EnvironmentVariables["PORTSCOPE_UPDATE_PROTOCOL"] = "1";
                start.EnvironmentVariables["PORTSCOPE_PORTABLE_ROOT"] = root;
                start.EnvironmentVariables["PORTSCOPE_UPDATE_DIR"] = Path.Combine(updateBase, sessionNonce);
                portable = true;
            } catch { /* Normal launching remains available; source or linked installs require manual updates. */ }
            start.EnvironmentVariables["PORTSCOPE_CONTROL_TOKEN"] = controlToken;
            if (trial) {
                if (!portable) throw new IOException("Update restart lost its verified portable layout.");
                start.EnvironmentVariables["PORTSCOPE_UPDATE_RESTART"] = "1";
                start.EnvironmentVariables["PORTSCOPE_UPDATE_HEALTH_NONCE"] = updateNonce;
            }
            using (var child = new Process()) {
                child.StartInfo = start;
                int browserOpened = 0;
                child.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e) {
                    if (e.Data == null) return;
                    Console.WriteLine(e.Data);
                    if (!open) return;
                    var match = Regex.Match(e.Data, @"^  Private control link [(]do not share[)]: (http://127[.]0[.]0[.]1:([0-9]{1,5})/#overview[?]control=[a-f0-9]{64})$");
                    int port;
                    if (!match.Success || !int.TryParse(match.Groups[2].Value, out port) || port < 1 || port > 65535 ||
                        Interlocked.Exchange(ref browserOpened, 1) != 0) return;
                    // Launch from outside the server job, so closing PortScope never terminates the browser.
                    try { Process.Start(new ProcessStartInfo(match.Groups[1].Value) { UseShellExecute = true }); }
                    catch { Console.Error.WriteLine("PortScope: browser could not open; use the local URL printed above."); }
                };
                child.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e) { if (e.Data != null) Console.Error.WriteLine(e.Data); };
                if (!child.Start()) throw new InvalidOperationException("Node could not start.");
                if (!AssignProcessToJobObject(job, child.Handle) && !child.HasExited) {
                    child.Kill(); throw new InvalidOperationException("Could not attach the server to its private cleanup job.");
                }
                child.BeginOutputReadLine(); child.BeginErrorReadLine();
                Timer trialGuard = null;
                if (trial) {
                    WriteExclusive(Path.Combine(trialStage, trialMarker + ".json"), new { pid = child.Id, startedAt = child.StartTime.ToUniversalTime().ToFileTimeUtc().ToString(CultureInfo.InvariantCulture), parentPid = Process.GetCurrentProcess().Id, nonce = updateNonce });
                    trialGuard = new Timer(delegate {
                        if (File.Exists(Path.Combine(trialStage, trialMarker + ".cancel"))) TerminateJobObject(job, 1);
                    }, null, 100, 100);
                }
                try { child.WaitForExit(); } finally { if (trialGuard != null) trialGuard.Dispose(); }
                if (child.ExitCode == 75 && portable) {
                    TerminateJobObject(job, 1); // Stop only this server's workers before the external helper swaps runtime files.
                    CloseHandle(job); job = IntPtr.Zero;
                    return BeginUpdate(root, sessionNonce, child, controlToken);
                }
                return child.ExitCode;
            }
        } catch (Exception error) {
            Console.Error.WriteLine("PortScope: " + error.Message);
            return 1;
        } finally {
            Console.CancelKeyPress -= cancel;
            if (shutdown != null) shutdown.Dispose();
            if (job != IntPtr.Zero) CloseHandle(job);
        }
    }
}
