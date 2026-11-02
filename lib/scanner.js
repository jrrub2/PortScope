'use strict';

/**
 * Listening-port discovery.
 *
 * Windows is the primary target:
 *   - one `netstat -ano` run per scan, only TCP LISTENING rows are considered;
 *   - only loopback-reachable sockets (127.x, ::1, 0.0.0.0, ::) are kept;
 *   - listeners for the same port (IPv4 + IPv6, loopback + wildcard) are merged
 *     into a single logical port;
 *   - PID -> process name comes from a process snapshot command (PowerShell
 *     GetProcesses, with tasklist as fallback), never one command per port.
 *
 * The process snapshot is cached and only refreshed when a new PID appears or
 * the cache is older than PROCESS_NAME_TTL_MS. That keeps the steady-state
 * listener scan at a single netstat spawn (~100 ms on a machine with ~130
 * listeners) while still resolving every PID to a name. At most one process
 * snapshot command is ever spawned per scan.
 *
 * Unix gets a best-effort fallback via `lsof`, then `ss`, plus `ps` for names.
 * A missing platform binary is reported as a scan error, never thrown.
 */

const { runCommand, parseCsvLine, errorText, firstLine } = require('./util');
const { parseWindowsConnections, scanUnixConnections, networkSnapshot } = require('./network');
const {
  isLoopbackReachable,
  isWildcardAddress,
  compareAddresses,
} = require('./classify');

/** Refresh cached PID -> name map at most this often, even if nothing changed. */
const PROCESS_NAME_TTL_MS = 30_000;
const NETSTAT_TIMEOUT_MS = 15_000;
const PROCESS_SNAPSHOT_TIMEOUT_MS = 12_000;

// ---------------------------------------------------------------------------
// Endpoint parsing helpers
// ---------------------------------------------------------------------------

/**
 * Parse one local address token from netstat/lsof/ss.
 * Supports `127.0.0.1:3000`, `0.0.0.0:135`, `[::1]:3000`, `[::]:80`, `*:3000`.
 *
 * @param {string} token
 * @returns {{address: string, port: number}|null}
 */
function parseEndpoint(token) {
  if (typeof token !== 'string') return null;
  const value = token.trim();
  if (!value) return null;

  if (value.startsWith('[')) {
    const close = value.indexOf(']');
    if (close === -1) return null;
    const address = value.slice(1, close);
    const rest = value.slice(close + 1);
    if (!rest.startsWith(':')) return null;
    const port = Number.parseInt(rest.slice(1), 10);
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
    return { address: normalizeAddress(address), port };
  }

  const separator = value.lastIndexOf(':');
  if (separator <= 0) return null;
  const address = value.slice(0, separator);
  const port = Number.parseInt(value.slice(separator + 1), 10);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  if (!address) return null;
  return { address: normalizeAddress(address), port };
}

/** lsof/ss print `*` for wildcard binds; keep the wildcard semantics. */
function normalizeAddress(address) {
  const value = String(address).trim();
  if (value === '*') return '0.0.0.0';
  return value;
}

/** @param {number} pid */
function parsePid(pid) {
  const value = Number.parseInt(String(pid ?? ''), 10);
  if (!Number.isInteger(value) || value < 0) return null;
  return value;
}

// ---------------------------------------------------------------------------
// Platform parsers. Each returns raw rows: {address, port, pid, processName?}
// ---------------------------------------------------------------------------

/**
 * Robust `netstat -ano` parser.
 *
 * Layout (Windows 11, English):
 *   Proto  Local Address   Foreign Address  State      PID
 *   TCP    0.0.0.0:135     0.0.0.0:0        LISTENING  1776
 *   TCP    [::1]:3000      [::1]:0          LISTENING  1234
 *
 * We tolerate leading whitespace, CRLF, and both `LISTENING`/`LISTEN` states.
 * PID is taken from the last column and state from the second-to-last, which
 * avoids depending on the exact header columns.
 *
 * @param {string} stdout
 * @returns {Array<{address: string, port: number, pid: number}>}
 */
function parseWindowsNetstat(stdout) {
  const rows = [];
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 5) continue;
    if (tokens[0].toUpperCase() !== 'TCP') continue;

    const state = tokens[tokens.length - 2].toUpperCase();
    if (state !== 'LISTENING' && state !== 'LISTEN') continue;

    const pid = parsePid(tokens[tokens.length - 1]);
    if (pid === null) continue;

    const endpoint = parseEndpoint(tokens[1]);
    if (!endpoint) continue;

    rows.push({ address: endpoint.address, port: endpoint.port, pid });
  }
  return rows;
}

/**
 * Parse `lsof -nP -iTCP -sTCP:LISTEN`.
 *
 * ```
 * COMMAND  PID USER FD   TYPE  DEVICE SIZE/OFF NODE NAME
 * node    1234 user 23u  IPv4  0x...    0t0  TCP 127.0.0.1:3000 (LISTEN)
 * node    1234 user 24u  IPv6  0x...    0t0  TCP [::1]:3000 (LISTEN)
 * ```
 *
 * @param {string} stdout
 * @returns {Array<{address: string, port: number, pid: number, processName: string|null}>}
 */
function parseLsof(stdout) {
  const rows = [];
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || /^COMMAND\s/.test(trimmed)) continue;
    if (!trimmed.includes('(LISTEN)')) continue;

    const tokens = trimmed.split(/\s+/);
    const pid = parsePid(tokens[1]);
    const tcpIndex = tokens.findIndex((token) => token === 'TCP' || token === 'TCPv6');
    if (pid === null || tcpIndex === -1 || tcpIndex + 1 >= tokens.length) continue;

    const endpoint = parseEndpoint(tokens[tcpIndex + 1]);
    if (!endpoint) continue;

    rows.push({
      address: endpoint.address,
      port: endpoint.port,
      pid,
      processName: tokens[0] || null,
    });
  }
  return rows;
}

/**
 * Parse `ss -ltnp` (Linux fallback).
 *
 * ```
 * State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
 * LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=1234,fd=20))
 * ```
 *
 * @param {string} stdout
 * @returns {Array<{address: string, port: number, pid: number, processName: string|null}>}
 */
function parseSs(stdout) {
  const rows = [];
  for (const line of stdout.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^LISTEN/i.test(trimmed)) continue;
    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 4) continue;

    const endpoint = parseEndpoint(tokens[3]);
    if (!endpoint) continue;

    const pidMatch = trimmed.match(/pid=(\d+)/);
    const nameMatch = trimmed.match(/users:\(\("([^"]+)"/);
    const pid = pidMatch ? parsePid(pidMatch[1]) : 0;
    if (pid === null) continue;

    rows.push({
      address: endpoint.address,
      port: endpoint.port,
      pid: pid ?? 0,
      processName: nameMatch ? nameMatch[1] : null,
    });
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Process name snapshot (cached, at most one OS command per scan)
// ---------------------------------------------------------------------------

class ProcessNames {
  /**
   * @param {{ttlMs?: number}} [options]
   */
  constructor(options = {}) {
    this.ttlMs = options.ttlMs ?? PROCESS_NAME_TTL_MS;
    this.names = new Map();
    this.refreshedAt = 0;
    this.windowsProvider = null;
    this.lastWarning = null;
  }

  /**
   * Resolve PID -> process name, refreshing the snapshot only when needed.
   * @param {number[]} pids
   * @returns {Promise<{names: Map<number, string|null>, warnings: string[]}>}
   */
  async resolve(pids) {
    const warnings = [];
    const uniquePids = [...new Set(pids.filter((pid) => Number.isInteger(pid) && pid >= 0))];
    const now = Date.now();
    const stale = now - this.refreshedAt > this.ttlMs;
    const hasUnknown = uniquePids.some((pid) => !this.names.has(pid));

    if (this.refreshedAt === 0 || stale || hasUnknown) {
      const snapshot = await this.refresh();
      if (snapshot.ok) {
        this.names = snapshot.names;
        this.refreshedAt = Date.now();
        this.lastWarning = null;
      } else {
        this.lastWarning = snapshot.error;
        warnings.push(snapshot.error);
      }
    }

    const names = new Map();
    for (const pid of uniquePids) {
      names.set(pid, this.names.get(pid) ?? null);
    }
    return { names, warnings };
  }

  /** Force a snapshot refresh (used when a process is new). */
  async refresh() {
    if (process.platform === 'win32') {
      const result = await this.refreshWindows();
      if (result.ok) return result;
      this.lastWarning = result.error;
      return result;
    }
    return this.refreshUnix();
  }

  /**
   * Windows: PowerShell's .NET process list is meaningfully faster than
   * tasklist CSV (~0.5 s vs ~1.5 s on a heavily loaded machine) and returns
   * PID + image name in one shot. tasklist CSV is the fallback.
   */
  async refreshWindows() {
    const script = [
      '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8',
      '[Diagnostics.Process]::GetProcesses() | ForEach-Object {',
      '  try { "{0}|{1}" -f $_.Id, $_.ProcessName } catch { }',
      '}',
    ].join('\n');
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    const powershell = await runCommand(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
      { timeoutMs: PROCESS_SNAPSHOT_TIMEOUT_MS },
    );

    if (powershell.ok) {
      const names = new Map();
      for (const line of powershell.stdout.split(/\r?\n/)) {
        const separator = line.indexOf('|');
        if (separator <= 0) continue;
        const pid = parsePid(line.slice(0, separator));
        const name = line.slice(separator + 1).trim();
        if (pid === null || !name) continue;
        names.set(pid, windowsImageName(name));
      }
      if (names.size > 0) {
        this.windowsProvider = 'powershell';
        return { ok: true, names };
      }
    }

    const tasklist = await runCommand('tasklist', ['/FO', 'CSV', '/NH'], {
      timeoutMs: PROCESS_SNAPSHOT_TIMEOUT_MS,
      maxBuffer: 32 * 1024 * 1024,
    });
    if (!tasklist.ok) {
      const reason = firstLine(tasklist.stderr) || tasklist.error || 'tidak diketahui';
      return {
        ok: false,
        error: `Snapshot proses gagal (powershell: ${powershell.error || 'output kosong'}; tasklist: ${reason}).`,
        names: new Map(),
      };
    }

    const names = new Map();
    for (const line of tasklist.stdout.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const fields = parseCsvLine(line);
      if (fields.length < 2) continue;
      const pid = parsePid(fields[1]);
      const name = fields[0].trim();
      if (pid === null || !name) continue;
      names.set(pid, name);
    }
    if (names.size === 0) {
      return { ok: false, error: 'Snapshot proses kosong (tasklist tidak menghasilkan data).', names: new Map() };
    }
    this.windowsProvider = 'tasklist';
    return { ok: true, names };
  }

  /** Unix fallback: `ps -eo pid=,comm=` is available everywhere. */
  async refreshUnix() {
    const ps = await runCommand('ps', ['-eo', 'pid=,comm='], { timeoutMs: PROCESS_SNAPSHOT_TIMEOUT_MS });
    if (!ps.ok) {
      return { ok: false, error: `Snapshot proses gagal: ${ps.error || firstLine(ps.stderr)}`, names: new Map() };
    }
    const names = new Map();
    for (const line of ps.stdout.split(/\r?\n/)) {
      const match = line.match(/^\s*(\d+)\s+(.+?)\s*$/);
      if (!match) continue;
      const pid = parsePid(match[1]);
      const name = match[2].trim();
      if (pid === null || !name) continue;
      names.set(pid, name);
    }
    if (names.size === 0) {
      return { ok: false, error: 'Snapshot proses kosong (ps tidak menghasilkan data).', names: new Map() };
    }
    return { ok: true, names };
  }
}

/** One shared cache for the whole process lifetime. */
const processNames = new ProcessNames();

/**
 * .NET's ProcessName strips the executable extension (`node`), while tasklist
 * and the contract examples (`node.exe`) keep it. Restore the image-name form
 * for regular user-mode processes, but keep kernel/special process names that
 * genuinely have no image extension.
 */
const SPECIAL_WINDOWS_PROCESS_NAMES = new Set([
  'system',
  'system idle process',
  'idle',
  'secure system',
  'registry',
  'memory compression',
  'vmmem',
  'vmmemwsl',
  'vmmemcmfirstboot',
]);

/**
 * @param {string} name .NET ProcessName
 * @returns {string} tasklist-style image name where appropriate
 */
function windowsImageName(name) {
  const trimmed = name.trim();
  if (!trimmed) return trimmed;
  const lower = trimmed.toLowerCase();
  if (SPECIAL_WINDOWS_PROCESS_NAMES.has(lower)) return trimmed;
  if (/\.[a-z0-9]{2,4}$/i.test(trimmed)) return trimmed; // already has an extension
  return `${trimmed}.exe`;
}

// ---------------------------------------------------------------------------
// Listener merging
// ---------------------------------------------------------------------------

/** Preference order for picking the owning PID when a port has several binds. */
function listenerRank(listener) {
  const address = listener.address;
  if (/^127\./.test(address)) return 0;
  if (address === '::1') return 1;
  if (address === '0.0.0.0') return 2;
  if (address === '::') return 3;
  return 4;
}

/**
 * Merge raw listeners into one record per port.
 *
 * @param {Array<{address: string, port: number, pid: number, processName?: string|null}>} rows
 * @param {Map<number, string|null>} names
 */
function mergeListeners(rows, names) {
  /** @type {Map<number, {port: number, addresses: Set<string>, listeners: Array}>} */
  const byPort = new Map();

  for (const row of rows) {
    if (!isLoopbackReachable(row.address)) continue;
    let bucket = byPort.get(row.port);
    if (!bucket) {
      bucket = { port: row.port, addresses: new Set(), listeners: [] };
      byPort.set(row.port, bucket);
    }
    bucket.addresses.add(row.address);
    bucket.listeners.push(row);
  }

  const merged = [];
  for (const bucket of byPort.values()) {
    const bindAddresses = [...bucket.addresses].sort(compareAddresses);
    const wildcard = bindAddresses.some(isWildcardAddress);

    const ordered = [...bucket.listeners].sort((a, b) => listenerRank(a) - listenerRank(b));
    const owner = ordered[0];
    const pid = owner.pid;
    // The process snapshot is authoritative; the row parser name (lsof/ss) is
    // only a fallback for Unix setups where ps cannot see the process.
    const processName = names.get(pid) ?? owner.processName ?? null;

    merged.push({
      port: bucket.port,
      bindAddresses,
      wildcard,
      pid,
      processName,
    });
  }

  merged.sort((a, b) => a.port - b.port);
  return merged;
}

// ---------------------------------------------------------------------------
// Public scan
// ---------------------------------------------------------------------------

/**
 * Scan TCP LISTENING sockets reachable via loopback.
 *
 * @returns {Promise<{
 *   ok: boolean,
 *   ports?: Array<{port: number, bindAddresses: string[], wildcard: boolean,
 *                  pid: number, processName: string|null}>,
 *   durationMs: number,
 *   warnings: string[],
 *   error?: string,
 * }>}
 */
async function scanListeningPorts() {
  const startedAt = Date.now();
  const warnings = [];

  let rawRows;
  let rowParserName;
  let networkResult;

  if (process.platform === 'win32') {
    const netstat = await runCommand('netstat', ['-ano'], { timeoutMs: NETSTAT_TIMEOUT_MS });
    if (!netstat.ok) {
      return {
        ok: false,
        durationMs: Date.now() - startedAt,
        warnings,
        error: `Gagal menjalankan netstat: ${netstat.error || firstLine(netstat.stderr) || 'tidak diketahui'}`,
      };
    }
    rawRows = parseWindowsNetstat(netstat.stdout);
    networkResult = { ok: true, connections: parseWindowsConnections(netstat.stdout) };
    rowParserName = 'netstat';

    // Windows always has a few TCP listeners (RPC, SMB, ...). Zero parsed rows
    // almost certainly means an unexpected output format, not an idle machine;
    // surface it as an error instead of silently reporting an empty system.
    if (rawRows.length === 0) {
      return {
        ok: false,
        durationMs: Date.now() - startedAt,
        warnings,
        error: 'Tidak ada listener TCP yang terbaca dari netstat (format output tidak dikenal?).',
      };
    }
  } else {
    const unixScan = await scanUnixListeners();
    if (!unixScan.ok) {
      return { ok: false, durationMs: Date.now() - startedAt, warnings, error: unixScan.error };
    }
    rawRows = unixScan.rows;
    rowParserName = unixScan.parser;
    networkResult = await scanUnixConnections();
  }

  const pids = [...new Set([...rawRows.map((row) => row.pid),
    ...networkResult.connections.map((row) => row.pid)])];
  const { names, warnings: nameWarnings } = await processNames.resolve(pids);
  warnings.push(...nameWarnings);

  for (const row of networkResult.connections) row.processName = names.get(row.pid) ?? row.processName;
  const ports = mergeListeners(rawRows, names);
  // Note: an empty merged list is legitimate (a machine may only have
  // non-loopback listeners); the parse-failure case was handled above.

  if (warnings.length > 0) {
    // Attach the parser name so the message is actionable in the UI footer.
    warnings[0] = `${warnings[0]} (parser: ${rowParserName})`;
  }

  return {
    ok: true,
    ports,
    network: networkSnapshot(networkResult),
    durationMs: Date.now() - startedAt,
    warnings,
  };
}

/**
 * Unix listener discovery: `lsof` first, then `ss` (Linux only).
 * @returns {Promise<{ok: true, rows: Array, parser: string}|{ok: false, error: string}>}
 */
async function scanUnixListeners() {
  const lsof = await runCommand('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], { timeoutMs: NETSTAT_TIMEOUT_MS });
  if (lsof.ok) {
    const rows = parseLsof(lsof.stdout);
    // lsof prints a header even with no sockets; an empty body is legitimate.
    return { ok: true, rows, parser: 'lsof' };
  }

  const ss = await runCommand('ss', ['-ltnp'], { timeoutMs: NETSTAT_TIMEOUT_MS });
  if (ss.ok) {
    return { ok: true, rows: parseSs(ss.stdout), parser: 'ss' };
  }

  const reason = lsof.error || firstLine(lsof.stderr) || 'tidak tersedia';
  return {
    ok: false,
    error: `Platform ini tidak didukung sepenuhnya: lsof dan ss tidak tersedia (${reason}).`,
  };
}

module.exports = {
  scanListeningPorts,
  // Exported for tests and for reuse by the process-detail helper.
  parseWindowsNetstat,
  parseLsof,
  parseSs,
  parseEndpoint,
  mergeListeners,
  ProcessNames,
  errorText,
};
