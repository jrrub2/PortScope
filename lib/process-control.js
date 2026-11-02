'use strict';

const { spawn, execFile } = require('node:child_process');
const path = require('node:path');
const { parseWindowsNetstat } = require('./scanner');
const { isLoopbackReachable } = require('./classify');

const STOP_TIMEOUT_MS = 18000;
const STOP_COOLDOWN_MS = 2000;
const stopError = (status, code, message) => Object.assign(new Error(message), { status, code });

function validateStop(rawPort, input) {
  const fields = ['pid', 'startedAt', 'confirm'];
  if (typeof rawPort !== 'string' || !/^[1-9][0-9]{0,4}$/.test(rawPort) || Number(rawPort) > 65535 ||
      !input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== fields.length ||
      Object.keys(input).some(key => !fields.includes(key)) || input.confirm !== true ||
      !Number.isSafeInteger(input.pid) || input.pid <= 0 || input.pid > 2147483647 ||
      typeof input.startedAt !== 'string' || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{3}Z$/.test(input.startedAt) ||
      !Number.isFinite(Date.parse(input.startedAt)) || new Date(input.startedAt).toISOString() !== input.startedAt) {
    throw stopError(400, 'INVALID_STOP', 'Use a canonical port and exactly {pid, startedAt, confirm:true} from fresh process details.');
  }
  return { port: Number(rawPort), pid: input.pid, startedAt: input.startedAt };
}

function assertListenerOwner(rows, spec) {
  const owners = rows.filter(row => row.port === spec.port && isLoopbackReachable(row.address));
  if (!owners.length || owners.some(row => row.pid !== spec.pid)) {
    throw stopError(409, 'PORT_OWNER_CHANGED', 'The listener owner changed or the port has multiple owners. Refresh before confirming again.');
  }
}

// Hold one native process handle from validation through termination: never reopen an unpinned PID.
const NATIVE_SOURCE = `
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

public sealed class StopRefused : Exception {
    public readonly int Status;
    public readonly string Code;
    public StopRefused(int status, string code, string message) : base(message) { Status = status; Code = code; }
}
public sealed class PinnedStop : IDisposable {
    private IntPtr handle;
    private readonly int id;
    private readonly string startedAt;
    public DateTime CreatedAtUtc { get; private set; }
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint rights, bool inherit, int pid);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessTimes(IntPtr h, out long created, out long exited, out long kernel, out long user);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessCritical(IntPtr h, out bool critical);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetProcessInformation(IntPtr h, int kind, out uint protection, int size);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint milliseconds);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, uint rights, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token, int kind, out int session, int length, out int needed);
    [DllImport("iphlpapi.dll", SetLastError=true)] static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int family, int kind, uint reserved);
    public PinnedStop(int pid, string expectedStart) {
        id = pid; startedAt = expectedStart;
        handle = OpenProcess(0x101001, false, pid); // TERMINATE | QUERY_LIMITED_INFORMATION | SYNCHRONIZE, never a tree.
        if (handle == IntPtr.Zero) {
            if (Marshal.GetLastWin32Error() == 87) throw new StopRefused(409, "STALE_PROCESS", "The selected process no longer exists.");
            throw new StopRefused(403, "ACCESS_DENIED", "Windows did not grant safe access. No elevation is attempted.");
        }
    }
    public void Validate() {
        if (WaitForSingleObject(handle, 0) != 258) throw new StopRefused(409, "STALE_PROCESS", "The selected process already exited.");
        long created, exited, kernel, user;
        if (!GetProcessTimes(handle, out created, out exited, out kernel, out user)) Deny();
        CreatedAtUtc = DateTime.FromFileTimeUtc(created - created % 10000); // Conservative millisecond lower bound; CIM may truncate finer ticks.
        // fff truncates 100ns ticks exactly like the process-detail JSON's millisecond ISO date.
        if (DateTime.FromFileTimeUtc(created).ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture) != startedAt)
            throw new StopRefused(409, "STALE_PROCESS", "The process identity changed. Refresh its details before confirming again.");
        bool critical; uint protection;
        if (!IsProcessCritical(handle, out critical) || critical || !GetProcessInformation(handle, 7, out protection, 4) || protection != 0xfffffffe) Deny();
        IntPtr token;
        if (!OpenProcessToken(handle, 8, out token)) Deny();
        try {
            int session, needed;
            if (!GetTokenInformation(token, 12, out session, 4, out needed) || session == 0 || session != System.Diagnostics.Process.GetCurrentProcess().SessionId) Deny();
            using (var owner = new WindowsIdentity(token))
            using (var current = WindowsIdentity.GetCurrent()) {
                if (owner.User == null || current.User == null || !owner.User.Equals(current.User)) Deny();
            }
        } finally { CloseHandle(token); }
        var image = new StringBuilder(32768); int length = image.Capacity;
        if (!QueryFullProcessImageName(handle, 0, image, ref length)) Deny();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (image.ToString().StartsWith(windows, StringComparison.OrdinalIgnoreCase)) Deny();
        string name = Path.GetFileNameWithoutExtension(image.ToString()).ToLowerInvariant();
        foreach (string protectedName in new [] { "system", "idle", "registry", "smss", "csrss", "wininit", "services", "lsass", "svchost", "winlogon", "explorer", "dwm", "sihost", "conhost", "msmpeng", "securityhealthservice", "runtimebroker" }) {
            if (name == protectedName) Deny();
        }
    }
    private static void Deny() { throw new StopRefused(403, "PROTECTED_PROCESS", "Process ownership, session or Windows protection could not be verified safely."); }
    private bool OwnsPort(int port) {
        bool found = false;
        foreach (int family in new [] { 2, 23 }) {
            int size = 0;
            uint result = GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 3, 0);
            if ((result != 122 && result != 0) || size < 4 || size > 16777216) throw new StopRefused(500, "STOP_FAILED", "Windows listener ownership could not be verified.");
            IntPtr table = Marshal.AllocHGlobal(size);
            try {
                if (GetExtendedTcpTable(table, ref size, false, family, 3, 0) != 0) throw new StopRefused(409, "PORT_OWNER_CHANGED", "The listener table changed. Refresh and confirm again.");
                int count = Marshal.ReadInt32(table), stride = family == 2 ? 24 : 56;
                if (count < 0 || count > (size - 4) / stride) throw new StopRefused(500, "STOP_FAILED", "Windows returned an invalid listener table.");
                for (int index = 0; index < count; index++) {
                    IntPtr row = IntPtr.Add(table, 4 + index * stride);
                    int offset = family == 2 ? 8 : 20;
                    int localPort = Marshal.ReadByte(row, offset) * 256 + Marshal.ReadByte(row, offset + 1);
                    if (localPort != port) continue;
                    byte[] bytes = new byte[family == 2 ? 4 : 16];
                    Marshal.Copy(IntPtr.Add(row, family == 2 ? 4 : 0), bytes, 0, bytes.Length);
                    var address = new IPAddress(bytes);
                    if (!(IPAddress.IsLoopback(address) || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) ||
                        (address.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(address.MapToIPv4())))) continue;
                    if (Marshal.ReadInt32(row, family == 2 ? 20 : 52) != id) return false;
                    found = true;
                }
            } finally { Marshal.FreeHGlobal(table); }
        }
        return found;
    }
    public void Stop(int port) {
        Validate();
        if (!OwnsPort(port)) throw new StopRefused(409, "PORT_OWNER_CHANGED", "The selected process no longer uniquely owns this listener.");
        if (!TerminateProcess(handle, 1)) throw new StopRefused(403, "ACCESS_DENIED", "Windows refused to stop this process.");
        if (WaitForSingleObject(handle, 3000) != 0) throw new StopRefused(409, "STOP_UNCONFIRMED", "Termination was sent but exit was not confirmed. Refresh; do not automatically retry.");
    }
    public void Dispose() { if (handle != IntPtr.Zero) { CloseHandle(handle); handle = IntPtr.Zero; } }
}
`;

function windowsScript(spec) {
  return [
    "$ErrorActionPreference = 'Stop'", "$WarningPreference = 'SilentlyContinue'",
    "[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)",
    '$pinned = $null', 'try {',
    "Add-Type -TypeDefinition @'", NATIVE_SOURCE, "'@ -ReferencedAssemblies System.dll",
    "$pinned = New-Object PinnedStop(" + spec.pid + ", '" + spec.startedAt + "')",
    '$pinned.Validate()',
    '$appId = ' + process.pid,
    '$all = @(Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,CreationDate,Name)',
    '$ancestors = @{}; $current = $appId; $born = [datetime]::MaxValue; $verifiedRoot = $false',
    'for ($depth = 0; $current -gt 0; $depth++) {',
    '  if ($depth -ge 64 -or $ancestors.ContainsKey($current)) { throw [StopRefused]::new(403,"PROTECTED_PROCESS","Application ancestry could not be verified safely.") }',
    '  $ancestors[$current] = $true',
    '  if ($current -eq ' + spec.pid + ') { throw [StopRefused]::new(403,"PROTECTED_PROCESS","PortScope and its ancestors cannot be stopped.") }',
    '  $row = $all | Where-Object { $_.ProcessId -eq $current } | Select-Object -First 1',
    '  if ($null -eq $row -or $null -eq $row.CreationDate -or $row.CreationDate.ToUniversalTime() -gt $born) {',
    '    # A hidden ancestor must predate its verified descendant. A strictly newer pinned target cannot be that ancestor.',
    '    if ($pinned.CreatedAtUtc -gt $born) { $verifiedRoot = $true; break }',
    '    throw [StopRefused]::new(403,"PROTECTED_PROCESS","Application ancestry is unavailable or its PID was reused.")',
    '  }',
    '  if ($current -eq 4 -and $row.Name -ceq "System" -and $row.ParentProcessId -eq 0) { $verifiedRoot = $true; break }',
    '  $born = $row.CreationDate.ToUniversalTime(); $current = [int]$row.ParentProcessId',
    '}',
    'if (-not $verifiedRoot) { throw [StopRefused]::new(403,"PROTECTED_PROCESS","Application ancestry has no verified system boundary.") }',
    'function Assert-NotService {',
    '  if (@(Get-CimInstance Win32_Service -Filter "ProcessId=' + spec.pid + '").Count -ne 0) { throw [StopRefused]::new(403,"PROTECTED_PROCESS","Windows services cannot be stopped here.") }',
    '}',
    'Assert-NotService',
    "Write-Output '{\"phase\":\"ready\"}'",
    'if ([Console]::ReadLine() -cne "COMMIT") { throw [StopRefused]::new(409,"STOP_ABORTED","Stop cancelled before termination was sent.") }',
    'Assert-NotService',
    '$pinned.Stop(' + spec.port + ')',
    "Write-Output '{\"phase\":\"stopped\"}'",
    '} catch {',
    '  $failure = $_.Exception; while ($failure.InnerException) { $failure = $failure.InnerException }',
    '  if ($failure -is [StopRefused]) { @{status=$failure.Status;code=$failure.Code;message=$failure.Message} | ConvertTo-Json -Compress }',
    '  else { @{status=403;code="PROTECTED_PROCESS";message="Windows identity and protection checks could not be completed. No safe stop was confirmed."} | ConvertTo-Json -Compress }',
    '} finally { if ($null -ne $pinned) { $pinned.Dispose() } }',
  ].join('\n');
}

function freshListeners(signal) {
  return new Promise((resolve, reject) => {
    const executable = path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'netstat.exe');
    execFile(executable, ['-ano'], { windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 4 * 1024 * 1024, signal }, (error, stdout) => {
      if (error) return reject(stopError(500, 'STOP_FAILED', 'A fresh Windows listener scan could not be completed.'));
      resolve(parseWindowsNetstat(stdout));
    });
  });
}

function stopWindows(spec, signal) {
  return new Promise((resolve, reject) => {
    const executable = path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const bootstrap = '& ([scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::ReadLine()))))';
    const child = spawn(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(bootstrap, 'utf16le').toString('base64')], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const scanner = new AbortController();
    let committed = false, ready = false, stopped = false, pending = '', outputBytes = 0, failure = null;
    const uncertain = () => stopError(409, 'STOP_UNCONFIRMED', 'Termination may have been sent but exit was not confirmed. Refresh; do not automatically retry.');
    const fail = error => { failure ||= error; scanner.abort(); child.kill(); };
    const abort = () => { if (!committed) fail(stopError(409, 'STOP_ABORTED', 'Stop cancelled before termination was sent.')); };
    const timer = setTimeout(() => fail(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'Safe stop preparation timed out. No termination was sent.')), STOP_TIMEOUT_MS);
    signal?.addEventListener('abort', abort, { once: true });
    child.stdin.on('error', () => { if (!failure) fail(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'The native stop helper disconnected.')); });
    child.on('error', () => { failure ||= stopError(500, 'STOP_FAILED', 'Windows PowerShell could not start the safe stop helper.'); });
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      outputBytes += Buffer.byteLength(chunk); pending += chunk;
      if (outputBytes > 16384) return fail(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'Invalid native stop response.'));
      let newline;
      while ((newline = pending.indexOf('\n')) !== -1) {
        const line = pending.slice(0, newline).trim(); pending = pending.slice(newline + 1);
        if (!line) continue;
        let event;
        try { event = JSON.parse(line); } catch { return fail(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'Invalid native stop response.')); }
        if (event.phase === 'ready' && !ready) {
          ready = true;
          (async () => {
            assertListenerOwner(await freshListeners(scanner.signal), spec);
            if (failure || signal?.aborted) return abort();
            committed = true; // Abort cannot revoke an irreversible native command after this point.
            child.stdin.end('COMMIT\n');
          })().catch(error => fail(error));
        } else if (event.phase === 'stopped' && committed) stopped = true;
        else if ([403, 409, 500].includes(event.status) && typeof event.code === 'string' && typeof event.message === 'string') {
          failure ||= stopError(event.status, event.code, event.message);
        } else return fail(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'Invalid native stop response.'));
      }
    });
    child.stderr.resume(); // Diagnostic text is never a success signal or an API response.
    child.on('close', code => {
      clearTimeout(timer); scanner.abort(); signal?.removeEventListener('abort', abort);
      if (failure) return reject(failure);
      if (code === 0 && stopped) return resolve({ ok: true, pid: spec.pid, port: spec.port, status: 'stopped' });
      reject(committed ? uncertain() : stopError(500, 'STOP_FAILED', 'Native safety checks did not complete. No termination was sent.'));
    });
    if (signal?.aborted) return abort();
    child.stdin.write(Buffer.from(windowsScript(spec), 'utf8').toString('base64') + '\n');
  });
}

class ProcessControlService {
  constructor() { this.active = false; this.lastAttemptAt = 0; }
  async stop(rawPort, input, signal) {
    const spec = validateStop(rawPort, input);
    if (process.platform !== 'win32') throw stopError(501, 'STOP_UNSUPPORTED', 'Safe process stop is currently supported on Windows only.');
    if (spec.pid <= 4 || spec.pid === process.pid || spec.pid === process.ppid) {
      throw stopError(403, 'PROTECTED_PROCESS', 'PortScope, its ancestors and protected Windows processes cannot be stopped.');
    }
    if (signal?.aborted) throw stopError(409, 'STOP_ABORTED', 'Stop cancelled before termination was sent.');
    if (this.active || Date.now() - this.lastAttemptAt < STOP_COOLDOWN_MS) throw stopError(429, 'STOP_BUSY', 'Another stop is active or the two-second safety cooldown has not elapsed.');
    this.active = true; this.lastAttemptAt = Date.now();
    try { return await stopWindows(spec, signal); } finally { this.active = false; }
  }
}

function selfCheck() {
  const assert = require('node:assert/strict');
  const input = { pid: 12345, startedAt: '2026-01-01T00:00:00.123Z', confirm: true };
  assert.deepEqual(validateStop('3000', input), { pid: input.pid, startedAt: input.startedAt, port: 3000 });
  for (const port of ['0', '03000', '65536', '3e3', '3000;whoami', '%33']) assert.throws(() => validateStop(port, input), { code: 'INVALID_STOP' });
  for (const extra of [{ confirm: false }, { pid: '12345' }, { pid: 0 }, { startedAt: '2026-02-30T00:00:00.000Z' }, { startedAt: '2026-01-01T00:00:00.1234567Z' }, { tree: true }]) assert.throws(() => validateStop('3000', { ...input, ...extra }), { code: 'INVALID_STOP' });
  const spec = validateStop('3000', input);
  assertListenerOwner([{ port: 3000, address: '127.0.0.1', pid: input.pid }], spec);
  for (const rows of [[], [{ port: 3000, address: '127.0.0.1', pid: 42 }], [{ port: 3000, address: '192.0.2.1', pid: input.pid }], [{ port: 3000, address: '::', pid: 42 }, { port: 3000, address: '127.0.0.1', pid: input.pid }]]) assert.throws(() => assertListenerOwner(rows, spec), { code: 'PORT_OWNER_CHANGED' });
  console.log('process-control self-check passed (validation/ownership only; no processes stopped).');
}

module.exports = { ProcessControlService, validateStop, assertListenerOwner, STOP_TIMEOUT_MS, STOP_COOLDOWN_MS };
if (require.main === module && process.argv[2] === '--self-check') selfCheck();
