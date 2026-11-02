param(
  [string]$Address,
  [ValidateSet('ping', 'mtr')][string]$Mode = 'ping',
  [ValidateRange(250, 3000)][int]$TimeoutMs = 1000,
  [ValidateRange(500, 10000)][int]$IntervalMs = 1000,
  [ValidateRange(1, 32)][int]$MaxHops = 24,
  [ValidateRange(1, 300)][int]$Cycles = 60,
  [switch]$Continuous,
  [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
function Write-Event($Value) {
  [Console]::Out.WriteLine(($Value | ConvertTo-Json -Depth 4 -Compress))
  [Console]::Out.Flush()
}

try {
  Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading.Tasks;

public sealed class PortScopePingResult {
  public long Sequence;
  public int Ttl;
  public string Address;
  public string Status;
  public double? Ms;
  public string At;
}

// Pure per-TTL scheduling state: no global round barrier and never overlapping a lane.
public sealed class PortScopeIcmpLanes {
  private readonly long[] started;
  private readonly long[] completed;
  private readonly bool[] pending;
  private readonly bool[] discovery;
  private readonly double[] due;
  private readonly int count, limit, interval;
  private readonly bool continuous;
  public int Cap { get; private set; }
  public long Progress { get; private set; }
  public int DestinationTtl { get; private set; }
  private int misses;
  public PortScopeIcmpLanes(int count, int limit, int interval, bool continuous) {
    this.count = count; this.limit = limit; this.interval = interval; this.continuous = continuous;
    Cap = count; started = new long[count + 1]; completed = new long[count + 1];
    pending = new bool[count + 1]; discovery = new bool[count + 1]; due = new double[count + 1];
  }
  public bool CanStart(int ttl, double now) {
    return (ttl <= Cap || discovery[ttl]) && !pending[ttl] && now >= due[ttl] && (continuous || started[ttl] < limit);
  }
  public long Start(int ttl, double now) {
    if (!CanStart(ttl, now)) throw new InvalidOperationException("Overlapping or early lane start.");
    pending[ttl] = true; discovery[ttl] = false; due[ttl] = now + interval;
    return ++started[ttl];
  }
  public void Complete(int ttl, long sequence) {
    if (!pending[ttl] || sequence != started[ttl]) throw new InvalidOperationException("Out of order lane completion.");
    pending[ttl] = false; completed[ttl] = sequence;
    long minimum = completed[1];
    for (int i = 2; i <= Cap; i++) minimum = Math.Min(minimum, completed[i]);
    Progress = Math.Max(Progress, minimum);
  }
  public void SetCap(int cap) { Cap = cap; }
  public void Rediscover() { for (int i = Cap + 1; i <= count; i++) discovery[i] = true; }
  public void Observe(int ttl, bool success) {
    if (success) {
      if (DestinationTtl == 0 || ttl < DestinationTtl) { DestinationTtl = ttl; Cap = ttl; }
      if (ttl == DestinationTtl) misses = 0;
    } else if (ttl == DestinationTtl && ++misses >= 3) {
      DestinationTtl = 0; misses = 0; Cap = count; Rediscover();
    }
  }
  public bool Done {
    get {
      if (continuous) return false;
      for (int i = 1; i <= Cap; i++) if (completed[i] < limit) return false;
      return true;
    }
  }
  public static void SelfCheck() {
    var lanes = new PortScopeIcmpLanes(2, 20, 500, true);
    if (lanes.Start(1, 0) != 1) throw new Exception("slow start");
    for (int at = 0; at <= 2500; at += 500) {
      if (lanes.CanStart(1, at)) throw new Exception("slow lane overlapped");
      long sequence = lanes.Start(2, at);
      if (sequence != at / 500 + 1) throw new Exception("fast lane stalled");
      lanes.Complete(2, sequence); // fake probe returns immediately; slow TTL remains pending until 3000.
      if (lanes.CanStart(2, at + 499)) throw new Exception("fast lane overran cadence");
    }
    lanes.Complete(1, 1);
    if (!lanes.CanStart(1, 3000) || lanes.Done) throw new Exception("continuous lane ended");
    lanes.Observe(1, true); lanes.Rediscover();
    if (!lanes.CanStart(2, 3000)) throw new Exception("route rediscovery failed");
    lanes.Observe(1, false); lanes.Observe(1, false);
    if (lanes.Cap != 1) throw new Exception("route recovered too early");
    lanes.Observe(1, false);
    if (lanes.Cap != 2 || lanes.DestinationTtl != 0) throw new Exception("three-miss route recovery failed");
    lanes.Observe(2, true);
    if (lanes.Cap != 2 || lanes.DestinationTtl != 2) throw new Exception("longer route not rediscovered");
    var finite = new PortScopeIcmpLanes(1, 1, 500, false);
    finite.Complete(1, finite.Start(1, 0));
    if (!finite.Done || finite.CanStart(1, 500)) throw new Exception("finite completion failed");
  }
}

public static class PortScopeNativePing {
  public static async Task<PortScopePingResult> Probe(string address, int ttl, int timeout, long sequence, bool mtr) {
    using (var ping = new Ping()) {
      var watch = Stopwatch.StartNew();
      var result = new PortScopePingResult { Sequence = sequence, Ttl = mtr ? ttl : 1 };
      try {
        var reply = await ping.SendPingAsync(IPAddress.Parse(address), timeout, new byte[32], new PingOptions(ttl, true)).ConfigureAwait(false);
        // Read here on completion, never later when PowerShell collects the task.
        var elapsed = watch.Elapsed.TotalMilliseconds;
        result.Status = reply.Status.ToString();
        result.Address = reply.Address == null ? null : reply.Address.ToString();
        if (reply.Status == IPStatus.Success) result.Ms = reply.RoundtripTime;
        else if (reply.Status == IPStatus.TtlExpired || reply.Status == IPStatus.TimeExceeded ||
                 reply.Status.ToString().Contains("Unreachable") || reply.Status == IPStatus.BadRoute ||
                 reply.Status == IPStatus.DestinationScopeMismatch) result.Ms = elapsed;
      } catch { result.Status = "Error"; }
      result.At = DateTime.UtcNow.ToString("o");
      return result;
    }
  }
}
'@
  if ($SelfTest) {
    [PortScopeIcmpLanes]::SelfCheck()
    Write-Event @{ type = 'self-test'; ok = $true; fastReplies = 6; slowReplies = 1 }
    exit 0
  }
  $ip = [Net.IPAddress]::Parse($Address)
  $Address = $ip.ToString()
  if ($ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any) -or $ip.IsIPv6Multicast) {
    throw 'Invalid unicast diagnostic target.'
  }
  $count = if ($Mode -eq 'ping') { 1 } else { $MaxHops }
  $lanes = New-Object PortScopeIcmpLanes($count, $Cycles, $IntervalMs, $Continuous.IsPresent)
  $tasks = New-Object 'System.Threading.Tasks.Task[]' ($count + 1)
  $clock = [Diagnostics.Stopwatch]::StartNew()
  $nextSweep = 9 * $IntervalMs
  Write-Event @{ type = 'ready' }
  while (-not $lanes.Done) {
    $now = $clock.Elapsed.TotalMilliseconds
    if ($Mode -eq 'mtr' -and $now -ge $nextSweep) {
      $lanes.Rediscover()
      $nextSweep = $now + 10 * $IntervalMs
    }
    for ($ttl = 1; $ttl -le $count; $ttl++) {
      if ($null -ne $tasks[$ttl] -and $tasks[$ttl].IsCompleted) {
        $reply = $tasks[$ttl].GetAwaiter().GetResult()
        $lanes.Complete($ttl, $reply.Sequence)
        $tasks[$ttl] = $null
        $oldCap = $lanes.Cap
        $oldDestination = $lanes.DestinationTtl
        $lanes.Observe($ttl, $reply.Status -eq 'Success' -and $reply.Address -eq $Address)
        if ($oldCap -ne $lanes.Cap -or $oldDestination -ne $lanes.DestinationTtl) {
          $destination = if ($lanes.DestinationTtl -gt 0) { $lanes.DestinationTtl } else { $null }
          Write-Event @{ type = 'route'; cap = $lanes.Cap; reachedTtl = $destination }
        }
        Write-Event @{ type = 'probe'; sequence = $reply.Sequence; ttl = $reply.Ttl; address = $reply.Address; status = $reply.Status; ms = $reply.Ms; at = $reply.At }
      }
    }
    if ($lanes.Done) { break }
    $now = $clock.Elapsed.TotalMilliseconds
    for ($ttl = 1; $ttl -le $count; $ttl++) {
      if ($lanes.CanStart($ttl, $now)) {
        $sequence = $lanes.Start($ttl, $now)
        $packetTtl = if ($Mode -eq 'ping') { 128 } else { $ttl }
        $tasks[$ttl] = [PortScopeNativePing]::Probe($Address, $packetTtl, $TimeoutMs, $sequence, $Mode -eq 'mtr')
      }
    }
    # Only a short wakeup, never a timeout barrier across lanes.
    [Threading.Thread]::Sleep(10)
  }
  Write-Event @{ type = 'done' }
} catch {
  Write-Event @{ type = 'error'; error = 'Native ICMP worker failed to initialize or collect replies.' }
  exit 1
}
