#!/usr/bin/env node
'use strict';

/**
 * PortScope server entry point.
 *
 *   node server.js [--port 4599] [--interval 3000] [--open] [--help]
 *
 * - Binds to 127.0.0.1 only (never exposed to the LAN).
 * - Serves the JSON API / SSE stream and static dashboard from web/.
 * - Passive observation by default; explicit, bounded networking tools may
 *   contact selected targets. Explicit guarded confirmation can stop a listener owner;
 *   no automatic process control or service reconfiguration occurs.
 */

const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const fs = require('node:fs/promises');
const { randomBytes, timingSafeEqual } = require('node:crypto');
const { spawn } = require('node:child_process');

const { Monitor } = require('./lib/monitor');
const { ProcessDetailService } = require('./lib/procdetail');
const { ProcessControlService } = require('./lib/process-control');
const { UpdateService } = require('./lib/updates');
const { serveStatic } = require('./lib/static');
const { errorText } = require('./lib/util');
const { probeHostFor } = require('./lib/classify');
const { CheckService, readInput } = require('./lib/check');
const { DiagnosticService } = require('./lib/diagnostics');
const { DnsService } = require('./lib/dns-tools');
const { GeoService } = require('./lib/geo');
const { requestTrustError, setSecurityHeaders } = require('./lib/security');

const HOST = '127.0.0.1';
const DEFAULT_PORT = 4599;
const DEFAULT_INTERVAL_MS = 1000;
const MIN_INTERVAL_MS = 1000;
const PORT_FALLBACK_ATTEMPTS = 20;
const WEB_DIR = path.join(__dirname, 'web');
const PROBE_PUSH_INTERVAL_MS = 300; // SSE throttle for progressive probe updates
const SSE_PING_INTERVAL_MS = 15_000;
const SHUTDOWN_FORCE_MS = 2500;

/** @returns {string} */
function readVersion() {
  try {
    const pkg = require('./package.json');
    return typeof pkg.version === 'string' && pkg.version ? pkg.version : '1.0.0';
  } catch {
    return '1.0.0';
  }
}

const VERSION = readVersion();

const HELP_TEXT = `PortScope ${VERSION} - localhost port monitor

Usage:
  portscope [options]
  node server.js [options]

Options:
  --port <n>       Server port (default ${DEFAULT_PORT}; tries up to ${PORT_FALLBACK_ATTEMPTS} alternatives if busy)
  --interval <ms>  Automatic scan interval (default ${DEFAULT_INTERVAL_MS}, minimum ${MIN_INTERVAL_MS})
  --open           Open the dashboard in your browser
  --help, -h       Show this help
  --version, -v    Show version

Environment:
  PORT             Server port when --port is omitted
  SCAN_INTERVAL    Scan interval in milliseconds when --interval is omitted

Examples:
  portscope --open
  node server.js --port 4600 --interval 2000 --open

API: /api/state | /api/stream (SSE) | /api/scan | /api/process/:pid | /api/health
`;

// ---------------------------------------------------------------------------
// CLI parsing
// ---------------------------------------------------------------------------

/**
 * @param {string[]} argv
 * @returns {{help: boolean, version: boolean, open: boolean, port: number,
 *   interval: number, error: string|null, warnings: string[]}}
 */
function parseArgs(argv) {
  const config = {
    help: false,
    version: false,
    open: false,
    port: null,
    interval: null,
    error: null,
    warnings: [],
  };

  // Environment defaults first; an invalid env value falls back to the default
  // with a warning instead of refusing to boot.
  const envPort = process.env.PORT;
  if (envPort !== undefined && envPort.trim() !== '') {
    const value = Number(envPort);
    if (Number.isInteger(value) && value >= 0 && value <= 65535) {
      config.port = value;
    } else {
      config.warnings.push(`Nilai PORT tidak valid (${envPort}); memakai default ${DEFAULT_PORT}.`);
    }
  }
  const envInterval = process.env.SCAN_INTERVAL;
  if (envInterval !== undefined && envInterval.trim() !== '') {
    const value = Number(envInterval);
    if (Number.isInteger(value) && value >= MIN_INTERVAL_MS) {
      config.interval = value;
    } else {
      config.warnings.push(`Nilai SCAN_INTERVAL tidak valid (${envInterval}); memakai default ${DEFAULT_INTERVAL_MS}.`);
    }
  }

  const invalidPortMessage = (value) =>
    `Port tidak valid: ${value}. Gunakan angka 0-65535 (0 = port acak).`;
  const assignPort = (value) => {
    const number = Number(value);
    if (!Number.isInteger(number) || number < 0 || number > 65535) {
      config.error = invalidPortMessage(value);
      return;
    }
    config.port = number;
  };
  const assignInterval = (value) => {
    const number = Number(value);
    if (!Number.isInteger(number) || number <= 0) {
      config.error = `Interval tidak valid: ${value}. Gunakan angka milidetik, misalnya 3000.`;
      return;
    }
    if (number < MIN_INTERVAL_MS) {
      config.warnings.push(`Interval ${number} ms terlalu cepat; memakai minimum ${MIN_INTERVAL_MS} ms.`);
      config.interval = MIN_INTERVAL_MS;
      return;
    }
    config.interval = number;
  };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];

    if (arg === '--help' || arg === '-h') {
      config.help = true;
      continue;
    }
    if (arg === '--version' || arg === '-v') {
      config.version = true;
      continue;
    }
    if (arg === '--open') {
      config.open = true;
      continue;
    }
    if (arg === '--port' || arg === '--interval') {
      const value = argv[i + 1];
      if (value === undefined) {
        config.error = `Opsi ${arg} membutuhkan nilai.`;
        return config;
      }
      i += 1;
      if (arg === '--port') assignPort(value);
      else assignInterval(value);
      if (config.error) return config;
      continue;
    }
    if (arg.startsWith('--port=')) {
      assignPort(arg.slice('--port='.length));
      if (config.error) return config;
      continue;
    }
    if (arg.startsWith('--interval=')) {
      assignInterval(arg.slice('--interval='.length));
      if (config.error) return config;
      continue;
    }

    config.warnings.push(`Opsi tidak dikenal: ${arg} (diabaikan)`);
  }

  if (config.port === null) config.port = DEFAULT_PORT;
  if (config.interval === null) config.interval = DEFAULT_INTERVAL_MS;
  return config;
}

// ---------------------------------------------------------------------------
// Small HTTP helpers
// ---------------------------------------------------------------------------

/**
 * @param {import('node:http').ServerResponse} res
 * @param {number} status
 * @param {object} body
 * @param {{head?: boolean}} [options]
 */
function sendJson(res, status, body, options = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(payload),
    'X-Content-Type-Options': 'nosniff',
  });
  if (options.head) res.end();
  else res.end(payload);
}

function sendApiError(res, status, code, message, options = {}) {
  sendJson(res, status, { ok: false, error: { code, message } }, options);
}

function sendApiNotFound(res, options = {}) {
  sendApiError(res, 404, 'NOT_FOUND', 'Endpoint tidak ditemukan.', options);
}

function sendMethodNotAllowed(res, options = {}) {
  sendApiError(res, 405, 'METHOD_NOT_ALLOWED', 'Metode HTTP tidak didukung untuk endpoint ini.', options);
}

function sendPlainText(res, status, message) {
  const payload = Buffer.from(message, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': payload.length,
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(payload);
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * @param {number} port requested port (0 = OS picks a free one)
 * @returns {Promise<{port: number, fallbackFrom: number|null}>}
 */
function listenWithFallback(server, port) {
  const totalAttempts = port === 0 || process.env.PORTSCOPE_UPDATE_RESTART === '1' ? 1 : PORT_FALLBACK_ATTEMPTS + 1;

  return new Promise((resolve, reject) => {
    let attempt = 0;

    const tryListen = () => {
      const candidate = port === 0 ? 0 : port + attempt;

      const onError = (error) => {
        server.removeListener('listening', onListening);
        if (error && error.code === 'EADDRINUSE' && attempt < totalAttempts - 1) {
          console.log(`  Port ${candidate} sedang dipakai, mencoba ${candidate + 1}...`);
          attempt += 1;
          setImmediate(tryListen);
          return;
        }
        if (error && error.code === 'EACCES') {
          reject(new Error(`Tidak punya izin untuk memakai port ${candidate}.`));
          return;
        }
        reject(error instanceof Error ? error : new Error(errorText(error)));
      };

      const onListening = () => {
        server.removeListener('error', onError);
        const address = server.address();
        const actualPort = address && typeof address === 'object' ? address.port : candidate;
        resolve({ port: actualPort, fallbackFrom: attempt > 0 ? port : null });
      };

      server.once('error', onError);
      server.once('listening', onListening);
      try {
        server.listen({ host: HOST, port: candidate });
      } catch (error) {
        server.removeListener('listening', onListening);
        onError(error);
      }
    };

    tryListen();
  });
}

/** Open the default browser; failure is never fatal. */
function openBrowser(url) {
  try {
    /** @type {import('node:child_process').ChildProcess} */
    let child;
    if (process.platform === 'win32') {
      // `start "" <url>` is the documented Windows way to open the default
      // browser without breaking on an ampersand in the URL.
      child = spawn('cmd', ['/c', 'start', '""', url], { detached: true, stdio: 'ignore', windowsHide: true });
    } else if (process.platform === 'darwin') {
      child = spawn('open', [url], { detached: true, stdio: 'ignore' });
    } else {
      child = spawn('xdg-open', [url], { detached: true, stdio: 'ignore' });
    }
    child.on('error', () => {
      console.warn('  Tidak bisa membuka browser otomatis. Buka URL di atas secara manual.');
    });
    child.unref();
  } catch {
    console.warn('  Tidak bisa membuka browser otomatis. Buka URL di atas secara manual.');
  }
}

function printStartupBanner({ port, requestedPort, interval }) {
  console.log('');
  // Console output is deliberately ASCII: Windows consoles often run with a
  // legacy code page, so box drawing/arrow glyphs would render as mojibake.
  console.log(`  PortScope ${VERSION} - localhost port monitor`);
  console.log(`  -> http://${HOST}:${port}/`);
  if (requestedPort === 0) {
    // --port 0 means "let the OS pick a free port"; the URL above already
    // shows it, so this is informational rather than a busy-port fallback.
    console.log('     (port acak dipilih OS)');
  } else if (requestedPort !== port) {
    console.log(`     (port ${requestedPort} sibuk, memakai ${port})`);
  }
  console.log(`  -> scan interval ${interval} ms | ${process.platform}/${process.arch} | ${os.hostname()}`);
  console.log('  -> Ctrl+C untuk berhenti');
  console.log('');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const cli = parseArgs(process.argv.slice(2));

  if (cli.help) {
    console.log(HELP_TEXT);
    return 0;
  }
  if (cli.version) {
    console.log(`PortScope ${VERSION}`);
    return 0;
  }
  for (const warning of cli.warnings) console.warn(`  ${warning}`);
  if (cli.error) {
    console.error(`\n  ${cli.error}`);
    console.error('  Jalankan "node server.js --help" untuk bantuan.\n');
    return 1;
  }

  const startedAt = Date.now();
  const monitor = new Monitor({
    serverPort: cli.port,
    scanIntervalMs: cli.interval,
    version: VERSION,
    startedAt,
  });
  const store = monitor.store;
  const processDetails = new ProcessDetailService();
  const processControl = new ProcessControlService();
  const updates = new UpdateService({ version: VERSION, appDir: __dirname });
  let updateRestarting = false;
  const controlToken = /^[a-f0-9]{64}$/.test(process.env.PORTSCOPE_CONTROL_TOKEN || '') ? process.env.PORTSCOPE_CONTROL_TOKEN : randomBytes(32).toString('hex');
  const canControl = req => { const value = req.headers['x-portscope-control']; return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value) && timingSafeEqual(Buffer.from(value, 'hex'), Buffer.from(controlToken, 'hex')); };
  const checks = new CheckService();
  const diagnostics = new DiagnosticService();
  const dnsTools = new DnsService();
  const geo = new GeoService();
  const diagnosticStreams = new Map();
  const diagnosticOrphans = new Map();
  const inputRequests = new Set();

  /** @type {Set<{res: import('node:http').ServerResponse, ping: NodeJS.Timeout, closed: boolean}>} */
  const sseClients = new Set();
  let lastBroadcastAt = 0;
  /** @type {NodeJS.Timeout|null} */
  let probeBroadcastTimer = null;
  let shuttingDown = false;

  // -- SSE broadcast plumbing ------------------------------------------------

  /**
   * @param {string} payload serialized SSE frame
   */
  function writeToClient(client, payload) {
    if (client.closed) return;
    const { res } = client;
    if (res.writableEnded || res.destroyed) {
      cleanupClient(client);
      return;
    }
    try {
      if (res.writableLength > 1024 * 1024) { cleanupClient(client); return; }
      res.write(payload);
    } catch {
      cleanupClient(client);
    }
  }

  function cleanupClient(client) {
    if (client.closed) return;
    client.closed = true;
    clearInterval(client.ping);
    sseClients.delete(client);
    store.setActiveClients(sseClients.size);
    if (!client.res.writableEnded) {
      try {
        client.res.end();
      } catch {
        /* socket already gone */
      }
    }
  }

  function stateFrame() {
    return `event: state\ndata: ${JSON.stringify(store.snapshot())}\n\n`;
  }

  function networkFrames() {
    return `event: network\ndata: ${JSON.stringify(store.network)}\n\nevent: history\ndata: ${JSON.stringify(store.historySnapshot())}\n\n`;
  }

  function broadcastState() {
    if (sseClients.size === 0) return;
    const payload = stateFrame();
    for (const client of [...sseClients]) writeToClient(client, payload);
  }

  function broadcastNow() {
    if (probeBroadcastTimer) {
      clearTimeout(probeBroadcastTimer);
      probeBroadcastTimer = null;
    }
    lastBroadcastAt = Date.now();
    broadcastState();
  }

  /**
   * Probe results arrive in bursts (32 at a time). Push progress to the UI at
   * most once per PROBE_PUSH_INTERVAL_MS; the coalesced update is flushed on a
   * short trailing timer.
   */
  function scheduleProbeBroadcast() {
    const now = Date.now();
    const sinceLast = now - lastBroadcastAt;
    if (sinceLast >= PROBE_PUSH_INTERVAL_MS) {
      lastBroadcastAt = now;
      broadcastState();
      return;
    }
    if (probeBroadcastTimer) return;
    probeBroadcastTimer = setTimeout(() => {
      probeBroadcastTimer = null;
      lastBroadcastAt = Date.now();
      broadcastState();
    }, PROBE_PUSH_INTERVAL_MS - sinceLast);
    probeBroadcastTimer.unref?.();
  }

  store.on('change', ({ kind }) => {
    if (shuttingDown) return;
    if (kind === 'probe') {
      scheduleProbeBroadcast();
      return;
    }
    // Push real socket/history observations once per finished scan, not probe burst.
    if (kind === 'scan-done') {
      const frames = networkFrames();
      for (const client of [...sseClients]) writeToClient(client, frames);
    }
    broadcastNow();
  });

  // -- SSE endpoint ----------------------------------------------------------

  function handleSse(req, res) {
    if (sseClients.size >= 32) return sendApiError(res, 429, 'STREAM_BUSY', 'Too many observation streams.');
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.flushHeaders?.();
    res.write('retry: 2000\n\n');

    const client = {
      res,
      closed: false,
      ping: setInterval(() => {
        if (client.closed || res.writableEnded || res.destroyed) {
          cleanupClient(client);
          return;
        }
        try {
          res.write(': ping\n\n');
        } catch {
          cleanupClient(client);
        }
      }, SSE_PING_INTERVAL_MS),
    };
    client.ping.unref?.();

    sseClients.add(client);
    store.setActiveClients(sseClients.size);

    // Initial snapshot immediately after the retry line.
    try {
      res.write(stateFrame() + networkFrames());
    } catch {
      cleanupClient(client);
    }

    req.on('close', () => cleanupClient(client));
    req.on('error', () => cleanupClient(client));
    res.on('close', () => cleanupClient(client));
    res.on('error', () => cleanupClient(client));
  }

  // Diagnostic streams are leases: closing the owner view stops probes after reconnect grace.
  const terminalJob = job => !['resolving', 'running'].includes(job.status);
  function leaseDiagnostic(id, delay = 15000) {
    clearTimeout(diagnosticOrphans.get(id)); diagnosticOrphans.delete(id);
    if (shuttingDown || diagnosticStreams.get(id)?.size || !diagnostics.get(id) || terminalJob(diagnostics.get(id))) return;
    const timer = setTimeout(() => { diagnosticOrphans.delete(id); diagnostics.cancel(id); }, delay);
    timer.unref?.(); diagnosticOrphans.set(id, timer);
  }
  diagnostics.on('update', job => {
    if (terminalJob(job)) { clearTimeout(diagnosticOrphans.get(job.id)); diagnosticOrphans.delete(job.id); }
    for (const client of diagnosticStreams.get(job.id) || []) client.update(job);
  });
  function handleDiagnosticStream(req, res, id) {
    const job = diagnostics.get(id);
    if (!job) return sendApiError(res, 404, 'NOT_FOUND', 'Diagnostic job not found.');
    const allClients = [...diagnosticStreams.values()].reduce((sum, clients) => sum + clients.size, 0);
    if (allClients >= 8) return sendApiError(res, 429, 'STREAM_BUSY', 'Too many diagnostic streams.');
    clearTimeout(diagnosticOrphans.get(id)); diagnosticOrphans.delete(id);
    res.writeHead(200, { 'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
    res.flushHeaders?.(); res.write('retry: 1000\n\n');
    let closed = false, pending = null, timer = null;
    const clients = diagnosticStreams.get(id) || new Set(); diagnosticStreams.set(id, clients);
    const close = () => {
      if (closed) return; closed = true; clearInterval(ping); clearTimeout(timer);
      clients.delete(client); if (!clients.size) diagnosticStreams.delete(id);
      req.removeListener('close', close); res.removeListener('close', close); res.removeListener('error', close);
      if (!res.writableEnded && !res.destroyed) res.end();
      leaseDiagnostic(id, 5000);
    };
    const flush = () => {
      timer = null;
      if (closed || res.destroyed || res.writableEnded || res.writableLength > 256 * 1024) return close();
      try {
        const frame = 'event: job\ndata: ' + JSON.stringify(pending) + '\n\n';
        if (res.writableLength + Buffer.byteLength(frame) > 256 * 1024) return close();
        res.write(frame); if (terminalJob(pending)) close();
      } catch { close(); }
    };
    const client = { close, update(next) { pending = next; if (terminalJob(next)) { clearTimeout(timer); flush(); } else if (!timer) timer = setTimeout(flush, 150); } };
    const ping = setInterval(() => { if (res.writableLength > 256 * 1024) return close(); res.write(': ping\n\n'); }, 15000); ping.unref?.();
    clients.add(client); req.on('close', close); res.on('close', close); res.on('error', close);
    pending = job; flush();
  }
  async function handleToolInput(req, res, handler) {
    if (inputRequests.size >= 8) { req.resume(); return sendApiError(res, 429, 'TOOLS_BUSY', 'Too many active tool requests.'); }
    const controller = new AbortController(); inputRequests.add(controller);
    const abort = () => controller.abort(); res.once('close', abort);
    try {
      const input = await readInput(req);
      if (controller.signal.aborted) return;
      const result = await handler(input, controller.signal);
      if (!res.destroyed) return sendJson(res, 200, result);
    } catch (error) {
      if (!error.status && !error.statusCode) throw error;
      if (!res.destroyed) { res.setHeader('Connection', 'close'); req.resume(); return sendApiError(res, error.status || error.statusCode, error.code || 'TOOL_ERROR', error.message); }
    } finally { inputRequests.delete(controller); res.removeListener('close', abort); }
  }

  // -- API routes ------------------------------------------------------------

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {string} pathname
   * @param {string} method
   */
  async function handleApi(req, res, pathname, method) {
    const isRead = method === 'GET' || method === 'HEAD';
    const head = method === 'HEAD';

    if (pathname === '/api/update/status') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, updates.status(), { head });
    }
    if (pathname === '/api/update/check') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      return handleToolInput(req, res, (input, signal) => updates.check(input, signal));
    }
    if (pathname === '/api/update/apply') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      if (!canControl(req)) return sendApiError(res, 403, 'CONTROL_REQUIRED', 'Open the private dashboard link printed in the PortScope console to authorize destructive actions.');
      return handleToolInput(req, res, async (input, signal) => {
        if (updateRestarting) throw Object.assign(new Error('An update restart is already pending.'), { status: 409, code: 'UPDATE_BUSY' });
        updateRestarting = true;
        try {
          const result = await updates.prepare(input, signal);
          if (signal.aborted) throw Object.assign(new Error('Update preparation was disconnected. Nothing was installed.'), { status: 499, code: 'UPDATE_ABORTED' });
          // Only the native launcher may apply the verified stage, after this server and its workers exit.
          const handoff = await fs.open(path.join(process.env.PORTSCOPE_UPDATE_DIR, 'handoff.json'), 'wx', 0o600);
          try { await handoff.writeFile(JSON.stringify({ port: listenInfo.port, interval: cli.interval }), 'utf8'); await handoff.sync(); } finally { await handoff.close(); }
          if (signal.aborted) throw Object.assign(new Error('Update handoff was disconnected. Restart PortScope before trying again.'), { status: 499, code: 'UPDATE_ABORTED' });
          res.once('finish', () => setTimeout(() => shutdown('update', 75), 100));
          return { ok: true, version: result.version, status: 'restarting' };
        } catch (error) {
          updateRestarting = false;
          if (error.status || error.statusCode) throw error;
          throw Object.assign(new Error('Update handoff could not be written. No files were installed; restart PortScope before retrying.'), { status: 500, code: 'UPDATE_STORAGE' });
        }
      });
    }
    if (pathname === '/api/state') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, store.snapshot(), { head });
    }

    if (pathname === '/api/diagnostics') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      return handleToolInput(req, res, async input => { const job = await diagnostics.create(input); leaseDiagnostic(job.id); return { ok: true, job }; });
    }
    const diagnosticMatch = /^\/api\/diagnostics\/([a-zA-Z0-9-]{1,80})(\/stream)?$/.exec(pathname);
    if (diagnosticMatch) {
      const [, id, stream] = diagnosticMatch;
      if (stream) { if (method !== 'GET') return sendMethodNotAllowed(res, { head }); return handleDiagnosticStream(req, res, id); }
      if (!isRead && method !== 'DELETE') return sendMethodNotAllowed(res, { head });
      const job = method === 'DELETE' ? diagnostics.cancel(id) : diagnostics.get(id);
      if (!job) return sendApiError(res, 404, 'NOT_FOUND', 'Diagnostic job not found.', { head });
      if (method !== 'DELETE') leaseDiagnostic(id);
      return sendJson(res, 200, { ok: true, job }, { head });
    }
    if (pathname === '/api/dns/config') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, dnsTools.config(), { head });
    }
    if (pathname === '/api/dns') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      return handleToolInput(req, res, (input, signal) => dnsTools.run(input, signal));
    }
    if (pathname === '/api/geo') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      return handleToolInput(req, res, (input, signal) => geo.run(input, signal));
    }

    if (pathname === '/api/network') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, store.network, { head });
    }

    if (pathname === '/api/history') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, store.historySnapshot(), { head });
    }

    if (pathname === '/api/check') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      try {
        // Resolve IPv6-only ports from our own scan, never from user input or DNS.
        const result = await checks.run(req, (port) => probeHostFor(store.ports.get(port)?.bindAddresses));
        return sendJson(res, 200, result);
      } catch (error) {
        if (!error.status) throw error;
        res.setHeader('Connection', 'close');
        req.resume();
        return sendApiError(res, error.status, error.code, error.message);
      }
    }

    if (pathname === '/api/health') {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return sendJson(res, 200, {
        ok: true,
        app: 'PortScope',
        version: VERSION,
        pid: process.pid,
        uptimeMs: Math.round(process.uptime() * 1000),
        ready: store.ready,
        ...(/^[a-f0-9]{32}$/.test(process.env.PORTSCOPE_UPDATE_HEALTH_NONCE || '') ? { updateNonce: process.env.PORTSCOPE_UPDATE_HEALTH_NONCE, updateCommitted: await updates.committed(listenInfo.port) } : {}),
      }, { head });
    }

    if (pathname === '/api/scan') {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      const queued = monitor.requestScan();
      req.resume(); // ignore request body; drain so keep-alive stays healthy
      return sendJson(res, 200, {
        ok: true,
        queued,
        scanning: store.isScanning,
      });
    }

    const stopMatch = /^\/api\/ports\/([^/]+)\/stop$/.exec(pathname);
    if (stopMatch) {
      if (method !== 'POST') return sendMethodNotAllowed(res, { head });
      if (!canControl(req)) return sendApiError(res, 403, 'CONTROL_REQUIRED', 'Open the private dashboard link printed in the PortScope console to authorize destructive actions.');
      return handleToolInput(req, res, async (input, signal) => {
        const result = await processControl.stop(stopMatch[1], input, signal);
        monitor.requestScan();
        return result;
      });
    }

    const processMatch = pathname.match(/^\/api\/process\/([^/]+)$/);
    if (processMatch) {
      if (!isRead) return sendMethodNotAllowed(res, { head });
      return handleProcessDetail(res, processMatch[1], { head });
    }

    if (pathname === '/api/stream') {
      if (method !== 'GET') return sendMethodNotAllowed(res, { head });
      return handleSse(req, res);
    }

    // Every exact route already rejected a wrong method above, so anything that
    // reaches this point is an unknown `/api/*` path (including deeper
    // subpaths such as `/api/state/extra`) and must be a 404 JSON response.
    return sendApiNotFound(res, { head });
  }

  /**
   * @param {import('node:http').ServerResponse} res
   * @param {string} rawPid
   * @param {{head: boolean}} options
   */
  async function handleProcessDetail(res, rawPid, options) {
    let decoded;
    try {
      decoded = decodeURIComponent(rawPid);
    } catch {
      return sendApiError(res, 400, 'INVALID_PID', 'PID tidak valid.', options);
    }

    if (!/^\d+$/.test(decoded)) {
      return sendApiError(res, 400, 'INVALID_PID', 'PID tidak valid.', options);
    }
    const pid = Number(decoded);
    if (!Number.isSafeInteger(pid) || pid <= 0 || pid > 2_147_483_647) {
      return sendApiError(res, 400, 'INVALID_PID', 'PID tidak valid.', options);
    }

    let result;
    try {
      result = await processDetails.get(pid);
    } catch (error) {
      console.error('[process] query error:', error);
      return sendApiError(res, 500, 'PROCESS_QUERY_FAILED', 'Gagal membaca detail proses.', options);
    }

    if (result.error) {
      return sendApiError(res, 500, 'PROCESS_QUERY_FAILED', result.error, options);
    }
    if (!result.found || !result.process) {
      return sendApiError(res, 404, 'NOT_FOUND', 'Proses tidak ditemukan.', options);
    }
    return sendJson(res, 200, { ok: true, process: result.process }, options);
  }

  // -- Request entry point ---------------------------------------------------

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   */
  function handleRequest(req, res) {
    setSecurityHeaders(res);
    let url;
    try {
      if (!req.url?.startsWith('/') || req.url.startsWith('//') || req.url.includes('\\')) throw new Error('Invalid request target');
      url = new URL(req.url, `http://${HOST}`);
    } catch {
      sendPlainText(res, 400, '400 — Permintaan tidak valid');
      return;
    }

    const pathname = url.pathname;
    const method = (req.method || 'GET').toUpperCase();
    const trustError = requestTrustError(req, req.socket.localPort, pathname.startsWith('/api'));
    if (trustError) {
      res.setHeader('Connection', 'close');
      req.resume();
      return sendApiError(res, 403, 'FORBIDDEN', trustError, { head: method === 'HEAD' });
    }

    handleApiOrStatic(req, res, pathname, method).catch((error) => {
      console.error('[http] request failed:', error);
      if (!res.headersSent) {
        sendJson(res, 500, { ok: false, error: { code: 'INTERNAL', message: 'Terjadi kesalahan internal.' } });
      } else if (!res.writableEnded) {
        res.destroy();
      }
    });
  }

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {string} pathname
   * @param {string} method
   */
  async function handleApiOrStatic(req, res, pathname, method) {
    if (pathname.startsWith('/api/')) {
      await handleApi(req, res, pathname, method);
      return;
    }

    if (method !== 'GET' && method !== 'HEAD') {
      sendPlainText(res, 405, '405 — Metode tidak didukung');
      return;
    }
    await serveStatic(req, res, WEB_DIR, pathname);
  }

  // -- HTTP server -----------------------------------------------------------

  const server = http.createServer({ requestTimeout: 5000, headersTimeout: 5000 }, handleRequest);

  server.on('clientError', (error, socket) => {
    // Malformed HTTP must never crash the server.
    if (socket.writable) {
      socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
    }
  });

  // NOTE: the persistent runtime 'error' handler is attached only after the
  // port is secured. During the listen fallback below, EADDRINUSE is an
  // expected, handled condition (try port +1), not a server error worth
  // logging or surfacing in meta.lastError.

  // -- Listen, start scanning, banner ---------------------------------------

  let listenInfo;
  try {
    listenInfo = await listenWithFallback(server, cli.port);
  } catch (error) {
    console.error(`\n  Gagal memulai server: ${errorText(error)}\n`);
    return 1;
  }

  store.setServerPort(listenInfo.port);

  // From here on, unexpected server errors are real runtime problems.
  server.on('error', (error) => {
    console.error('[server] error:', error);
    store.setLastError(`Kesalahan server: ${errorText(error)}`);
  });

  printStartupBanner({ port: listenInfo.port, requestedPort: cli.port, interval: cli.interval });
  const dashboardUrl = `http://${HOST}:${listenInfo.port}/#overview?control=${controlToken}`;
  console.log('  Private control link (do not share): ' + dashboardUrl);

  if (cli.open) {
    openBrowser(dashboardUrl);
  }

  // Scan immediately; the HTTP API is already answering (ready=false until the
  // first listener scan settles, as required by the contract).
  monitor.start();

  // -- Shutdown --------------------------------------------------------------

  function shutdown(signal, exitCode = 0) {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n  Menghentikan PortScope (${signal})...`);

    monitor.stop();
    checks.stop();
    diagnostics.close();
    dnsTools.close();
    geo.close();
    for (const controller of inputRequests) controller.abort();
    for (const timer of diagnosticOrphans.values()) clearTimeout(timer);
    for (const clients of diagnosticStreams.values()) for (const client of [...clients]) client.close();
    if (probeBroadcastTimer) {
      clearTimeout(probeBroadcastTimer);
      probeBroadcastTimer = null;
    }
    for (const client of [...sseClients]) cleanupClient(client);
    sseClients.clear();

    try {
      server.close(() => process.exit(exitCode));
      server.closeIdleConnections?.();
    } catch {
      process.exit(exitCode);
    }

    // Guarantee the process cannot hang on a stuck socket.
    setTimeout(() => process.exit(exitCode), SHUTDOWN_FORCE_MS);
  }

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGBREAK', () => shutdown('SIGBREAK'));

  // Non-fatal safety net: this is a long-running local monitor, so a stray
  // rejection is recorded instead of taking the whole dashboard down.
  process.on('unhandledRejection', (reason) => {
    console.error('[error] unhandledRejection:', reason);
    store.setLastError(`Kesalahan internal: ${errorText(reason)}`);
  });
  process.on('uncaughtException', (error) => {
    console.error('[error] uncaughtException:', error);
    store.setLastError(`Kesalahan internal: ${errorText(error)}`);
  });

  return null; // keep the process running
}

main()
  .then((exitCode) => {
    if (typeof exitCode === 'number') process.exitCode = exitCode;
  })
  .catch((error) => {
    console.error('\n  PortScope gagal berjalan:', error);
    process.exitCode = 1;
  });
