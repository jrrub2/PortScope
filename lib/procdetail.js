'use strict';

/**
 * On-demand process details for the dashboard's detail modal.
 *
 * `GET /api/process/:pid` is a lazy, low-frequency endpoint, so accuracy is
 * more important than speed here:
 *   - Windows: a single PowerShell invocation against Win32_Process (path,
 *     command line, parent PID, start time, working set);
 *   - Unix: `ps` plus the /proc/<pid>/exe symlink where available.
 *
 * Results are cached for 20 s and concurrent calls for the same PID share one
 * in-flight query, so a modal that is opened/closed repeatedly cannot spawn a
 * PowerShell storm.
 */

const fs = require('node:fs');
const { runCommand, errorText } = require('./util');

const CACHE_TTL_MS = 20_000;
const QUERY_TIMEOUT_MS = 10_000;
const MAX_CACHE_ENTRIES = 200;

/** @param {unknown} value @returns {string|null} */
function nullableString(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
}

/** @param {unknown} value @returns {number|null} */
function nullableNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

/**
 * Convert the many date shapes that OS tooling produces into an ISO string.
 * Handles ISO-8601, .NET `/Date(ms)/`, and WMI CIM `yyyymmddHHMMSS.ffffff+zzz`.
 *
 * @param {unknown} value
 * @returns {string|null}
 */
function normalizeDate(value) {
  if (value === null || value === undefined) return null;

  if (typeof value === 'number' && Number.isFinite(value)) {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;

  const dotnet = text.match(/^\/Date\((-?\d+)\)\/$/);
  if (dotnet) {
    const date = new Date(Number(dotnet[1]));
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }

  const cim = text.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})[.,](\d+)([+-]\d{3})?$/);
  if (cim) {
    const [, year, month, day, hour, minute, second, fraction, offset] = cim;
    let ms = 0;
    const fractionNumber = Number(`0.${fraction}`);
    if (Number.isFinite(fractionNumber)) ms = Math.round(fractionNumber * 1000);
    const date = new Date(
      Date.UTC(
        Number(year),
        Number(month) - 1,
        Number(day),
        Number(hour),
        Number(minute),
        Number(second),
        ms,
      ),
    );
    if (Number.isNaN(date.getTime())) return null;
    if (offset) {
      // WMI/CIM datetimes end with ±UUU where UUU is a signed offset in
      // MINUTES from UTC (e.g. `+420` = UTC+07:00), not an HHMM clock offset.
      const sign = offset.startsWith('-') ? -1 : 1;
      const offsetMinutes = sign * Number(offset.slice(1));
      if (Number.isFinite(offsetMinutes)) {
        date.setTime(date.getTime() - offsetMinutes * 60_000);
      }
    }
    return date.toISOString();
  }

  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

/**
 * Convert bytes to megabytes with one decimal (contract: `workingSetMB`).
 * @param {unknown} bytes
 * @returns {number|null}
 */
function bytesToMb(bytes) {
  // Number(null) === 0, which would silently report an unavailable working set
  // as "0 MB". Missing values must stay null.
  if (bytes === null || bytes === undefined) return null;
  const number = Number(bytes);
  if (!Number.isFinite(number) || number < 0) return null;
  return Math.round((number / (1024 * 1024)) * 10) / 10;
}

// ---------------------------------------------------------------------------
// Windows query
// ---------------------------------------------------------------------------

/**
 * Query Win32_Process through one PowerShell invocation.
 *
 * The script is passed as -EncodedCommand (UTF-16LE base64) so quoting/Unicode
 * in paths never has to survive cmd.exe. PowerShell is told to emit UTF-8 and
 * a compact JSON object.
 *
 * @param {number} pid
 * @returns {Promise<{found: boolean, process?: object, error?: string}>}
 */
async function queryWindowsProcess(pid) {
  const script = [
    '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
    "$ErrorActionPreference = 'Stop'",
    `$process = Get-CimInstance Win32_Process -Filter "ProcessId=${pid}" | Select-Object -First 1`,
    'if ($null -eq $process) {',
    "  Write-Output '{\"__notFound\":true}'",
    '} else {',
    '  [pscustomobject]@{',
    '    pid = [int]$process.ProcessId',
    '    name = $process.Name',
    '    path = $process.ExecutablePath',
    '    commandLine = $process.CommandLine',
    '    parentPid = [int]$process.ParentProcessId',
    "    startedAt = if ($process.CreationDate) { $process.CreationDate.ToUniversalTime().ToString('o') } else { $null }",
    '    workingSetBytes = [double]$process.WorkingSetSize',
    '  } | ConvertTo-Json -Compress',
    '}',
  ].join('\n');

  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const result = await runCommand(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    { timeoutMs: QUERY_TIMEOUT_MS, maxBuffer: 4 * 1024 * 1024 },
  );

  if (!result.ok) {
    return {
      found: false,
      error: `Gagal membaca detail proses: ${result.error || 'powershell tidak tersedia'}`,
    };
  }

  const stdout = result.stdout.trim();
  if (!stdout) {
    return { found: false, process: null };
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return { found: false, error: `Output proses tidak valid: ${stdout.slice(0, 120)}` };
  }

  if (!parsed || parsed.__notFound === true) {
    return { found: false, process: null };
  }

  return {
    found: true,
    process: {
      pid: nullableNumber(parsed.pid) ?? pid,
      name: nullableString(parsed.name),
      path: nullableString(parsed.path),
      commandLine: nullableString(parsed.commandLine),
      parentPid: nullableNumber(parsed.parentPid),
      startedAt: normalizeDate(parsed.startedAt),
      workingSetMB: bytesToMb(parsed.workingSetBytes),
    },
  };
}

// ---------------------------------------------------------------------------
// Unix query
// ---------------------------------------------------------------------------

/**
 * Query a process with a single `ps` call. `lstart` is kept last-but-one and
 * `args` last so the space-containing fields can be reconstructed.
 * @param {number} pid
 */
async function queryUnixProcess(pid) {
  const result = await runCommand(
    'ps',
    ['-p', String(pid), '-o', 'pid=,ppid=,rss=,comm=,lstart=,args='],
    { timeoutMs: QUERY_TIMEOUT_MS },
  );
  if (!result.ok) {
    return { found: false, process: null };
  }

  const line = result.stdout.split(/\r?\n/).find((entry) => entry.trim().length > 0);
  if (!line) {
    return { found: false, process: null }; // ps prints nothing for a dead PID
  }

  // pid ppid rss comm <5 date fields> args...
  const parts = line.trim().split(/\s+/);
  if (parts.length < 9) return { found: false, process: null };

  const pidValue = Number(parts[0]);
  const parentPid = Number(parts[1]);
  const rssKb = Number(parts[2]);
  const name = parts[3];
  const startedAtRaw = parts.slice(4, 9).join(' ');
  const commandLine = parts.slice(9).join(' ') || null;

  let executablePath = null;
  try {
    executablePath = fs.readlinkSync(`/proc/${pid}/exe`);
  } catch {
    executablePath = null;
  }

  return {
    found: true,
    process: {
      pid: Number.isFinite(pidValue) ? pidValue : pid,
      name: name || null,
      path: executablePath,
      commandLine,
      parentPid: Number.isFinite(parentPid) ? parentPid : null,
      startedAt: normalizeDate(startedAtRaw),
      workingSetMB: Number.isFinite(rssKb) ? Math.round((rssKb / 1024) * 10) / 10 : null,
    },
  };
}

// ---------------------------------------------------------------------------
// Cached service
// ---------------------------------------------------------------------------

class ProcessDetailService {
  constructor(options = {}) {
    this.ttlMs = options.ttlMs ?? CACHE_TTL_MS;
    /** @type {Map<number, {at: number, result: object}>} */
    this.cache = new Map();
    /** @type {Map<number, Promise<object>>} */
    this.inflight = new Map();
  }

  /**
   * @param {number} pid
   * @returns {Promise<{found: boolean, process?: object|null, error?: string}>}
   */
  async get(pid) {
    const now = Date.now();
    const cached = this.cache.get(pid);
    if (cached && now - cached.at < this.ttlMs) {
      return cached.result;
    }

    const pending = this.inflight.get(pid);
    if (pending) return pending;

    const query = this.query(pid)
      .then((result) => {
        this.inflight.delete(pid);
        this.store(pid, result);
        return result;
      })
      .catch((error) => {
        this.inflight.delete(pid);
        return { found: false, error: errorText(error) };
      });

    this.inflight.set(pid, query);
    return query;
  }

  /** @param {number} pid */
  async query(pid) {
    if (process.platform === 'win32') return queryWindowsProcess(pid);
    return queryUnixProcess(pid);
  }

  /** @param {number} pid @param {object} result */
  store(pid, result) {
    this.cache.set(pid, { at: Date.now(), result });
    if (this.cache.size > MAX_CACHE_ENTRIES) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) this.cache.delete(oldestKey);
    }
  }
}

module.exports = {
  ProcessDetailService,
  normalizeDate,
  bytesToMb,
  CACHE_TTL_MS,
};
