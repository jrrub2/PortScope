'use strict';

const { EventEmitter } = require('node:events');
const { randomUUID } = require('node:crypto');
const { Resolver } = require('node:dns').promises;
const net = require('node:net');
const tls = require('node:tls');
const { domainToASCII } = require('node:url');
const { performance } = require('node:perf_hooks');
const { spawn } = require('node:child_process');
const path = require('node:path');

const MAX_ACTIVE_JOBS = 2;
const MAX_RETAINED_JOBS = 10;
const MAX_SAMPLES = 240;
const MAX_HOP_SAMPLES = 60;
const MAX_LIFETIME_MS = 5 * 60 * 1000;
const RESOLVE_TIMEOUT_MS = 2000;
const WORKER_START_TIMEOUT_MS = 15000;
const ACTIVE = new Set(['resolving', 'running']);
const WORKER_PATH = path.join(__dirname, 'icmp-worker.ps1');

function diagnosticError(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

function isUnicast(address) {
  // ponytail: reject known non-unicast; directed broadcasts need subnet context, add only with interface-aware targeting.
  const family = net.isIP(address);
  if (family === 4) {
    const bytes = address.split('.').map(Number);
    return bytes[0] !== 0 && bytes[0] < 224;
  }
  if (family !== 6 || address.includes('%')) return false;
  const value = new URL('http://[' + address + ']/').hostname.slice(1, -1);
  if (value === '::' || value.startsWith('ff')) return false;
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(value);
  if (!mapped) return true;
  const high = Number.parseInt(mapped[1], 16);
  const low = Number.parseInt(mapped[2], 16);
  return isUnicast([high >> 8, high & 255, low >> 8, low & 255].join('.'));
}

function validateDiagnosticSpec(input) {
  const allowed = ['kind', 'target', 'family', 'port', 'timeoutMs', 'intervalMs', 'maxHops', 'cycles', 'continuous'];
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).some((key) => !allowed.includes(key))) {
    throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'Invalid diagnostic specification.');
  }
  if (!['ping', 'mtr', 'tcp', 'tls'].includes(input.kind) || typeof input.target !== 'string' ||
      !input.target || input.target.length > 253 || input.target !== input.target.trim()) {
    throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'A valid kind and hostname or numeric IP are required.');
  }
  const family = input.family === undefined ? 4 : input.family;
  if (family !== 4 && family !== 6) throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'Family must be 4 or 6.');
  let target = input.target;
  const literalFamily = net.isIP(target);
  if (literalFamily) {
    if (literalFamily !== family || !isUnicast(target)) {
      throw diagnosticError(400, 'INVALID_TARGET', 'Target must be a unicast IP matching the selected family.');
    }
    if (family === 6) target = new URL('http://[' + target + ']/').hostname.slice(1, -1);
  } else {
    if (/[\\/:#?@%\s\x00-\x1f\x7f]/.test(target) || /^[0-9.]+$/.test(target) || /^0x[0-9a-f]+$/i.test(target)) {
      throw diagnosticError(400, 'INVALID_TARGET', 'Use a hostname or literal IP, not a URL, port, scope ID or shell expression.');
    }
    target = domainToASCII(target).toLowerCase();
    if (!target || target.length > 253 || !/^[a-z0-9.-]+$/.test(target) || net.isIP(target) ||
        target.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
      throw diagnosticError(400, 'INVALID_TARGET', 'Target hostname is invalid.');
    }
  }
  if (input.continuous !== undefined && typeof input.continuous !== 'boolean') {
    throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'Continuous must be a boolean.');
  }
  const continuous = input.continuous === true;
  if (continuous && (!['ping', 'mtr'].includes(input.kind) || Object.hasOwn(input, 'cycles'))) {
    throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'Continuous is ICMP-only and must omit cycles.');
  }
  const spec = { kind: input.kind, target, family, port: null, continuous };
  if (input.kind === 'tcp' || input.kind === 'tls') {
    spec.port = input.port === undefined ? 443 : input.port;
    if (!Number.isInteger(spec.port) || spec.port < 1 || spec.port > 65535) {
      throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'Port must be an integer from 1 to 65535.');
    }
  } else if (input.port !== undefined) {
    throw diagnosticError(400, 'INVALID_DIAGNOSTIC', 'ICMP diagnostics do not use a port.');
  }
  for (const [field, fallback, min, max] of [
    ['timeoutMs', 1000, 250, 3000], ['intervalMs', 1000, 500, 10000],
    ['maxHops', 24, 1, 32], ['cycles', 60, 1, 300],
  ]) {
    if (field === 'cycles' && continuous) { spec.cycles = null; continue; }
    const value = input[field] === undefined ? fallback : input[field];
    if (!Number.isInteger(value) || value < min || value > max) {
      throw diagnosticError(400, 'INVALID_DIAGNOSTIC', field + ' is outside its allowed integer range.');
    }
    spec[field] = value;
  }
  return spec;
}

function round(value) { return Math.round(value * 1000) / 1000; }
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function safeString(value) { return typeof value === 'string' ? value.slice(0, 1024) : null; }
function certificateName(value) {
  if (!value || typeof value !== 'object') return null;
  return Object.fromEntries(Object.entries(value).slice(0, 20).map(([key, item]) =>
    [key, String(Array.isArray(item) ? item.join(', ') : item).slice(0, 512)]));
}

function inspectTls(socket, servername, error) {
  let cert = {}, cipher = null, protocol = null;
  try { cert = socket.getPeerCertificate() || {}; cipher = socket.getCipher(); protocol = socket.getProtocol(); }
  catch { /* a rejected handshake may not expose a certificate */ }
  return {
    authorized: !error && Boolean(socket.authorized),
    authorizationError: error ? safeString(error.code || error.message) :
      safeString(typeof socket.authorizationError === 'string' ? socket.authorizationError : socket.authorizationError?.message),
    protocol: protocol || null,
    cipher: cipher ? { name: cipher.name, standardName: cipher.standardName || null, version: cipher.version || null } : null,
    servername,
    subject: certificateName(cert.subject), issuer: certificateName(cert.issuer),
    validFrom: safeString(cert.valid_from), validTo: safeString(cert.valid_to),
    fingerprint256: safeString(cert.fingerprint256), serialNumber: safeString(cert.serialNumber),
    subjectAltName: safeString(cert.subjectaltname),
  };
}

class DiagnosticService extends EventEmitter {
  constructor(options = {}) {
    super();
    this.jobs = new Map();
    this.workers = new Set();
    this.closed = false;
    // Constructor-only trust configuration for fixtures; never request-controlled.
    this.ca = options.ca;
  }

  async create(input) {
    const spec = validateDiagnosticSpec(input);
    if (this.closed) throw diagnosticError(503, 'DIAGNOSTICS_CLOSED', 'Diagnostics service is closed.');
    const occupied = new Set([...this.jobs.values()].filter((job) => ACTIVE.has(job.snapshot.status)));
    for (const job of this.workers) occupied.add(job);
    if (occupied.size >= MAX_ACTIVE_JOBS) {
      throw diagnosticError(429, 'DIAGNOSTICS_BUSY', 'At most two diagnostic jobs may run concurrently.');
    }
    while (this.jobs.size >= MAX_RETAINED_JOBS) {
      const old = [...this.jobs.values()].find((job) => !ACTIVE.has(job.snapshot.status));
      if (!old) break;
      this.jobs.delete(old.snapshot.id);
    }
    const now = new Date().toISOString();
    const snapshot = { id: randomUUID(), ...spec, address: null, status: 'resolving',
      startedAt: now, updatedAt: now, finishedAt: null, error: null, cycle: 0,
      reached: false, timingMethod: spec.kind === 'tcp' ? 'Application-observed TCP connect time' :
        spec.kind === 'tls' ? 'Application-observed verified TLS handshake time' :
          'Native ICMP echo RTT; intermediate TTL-expired RTT is application-observed async completion time',
      hops: [], samples: [] };
    const job = { snapshot, hops: new Map(), cycleProbes: new Map(), sequences: new Map(),
      activeTtl: spec.kind === 'ping' ? 1 : spec.maxHops, destinationTtl: null, cleanups: new Set(), child: null };
    this.jobs.set(snapshot.id, job);
    if (!spec.continuous) {
      job.deadline = setTimeout(() => this.finish(job, 'error', 'Maximum diagnostic lifetime (5 minutes) reached.'), MAX_LIFETIME_MS);
      job.deadline.unref?.();
    }
    this.publish(job);
    setImmediate(() => this.run(job).catch(() => this.finish(job, 'error', 'Diagnostic execution failed.')));
    return clone(snapshot);
  }

  get(id) { return this.jobs.has(id) ? clone(this.jobs.get(id).snapshot) : null; }

  cancel(id) {
    const job = this.jobs.get(id);
    if (!job) return null;
    if (ACTIVE.has(job.snapshot.status)) this.finish(job, 'cancelled');
    return clone(job.snapshot);
  }

  close() {
    this.closed = true;
    for (const job of this.jobs.values()) if (ACTIVE.has(job.snapshot.status)) this.finish(job, 'cancelled');
  }

  publish(job) {
    job.snapshot.updatedAt = new Date().toISOString();
    this.emit('update', clone(job.snapshot));
  }

  finish(job, status, error = null) {
    if (!ACTIVE.has(job.snapshot.status)) return;
    job.snapshot.status = status;
    job.snapshot.finishedAt = new Date().toISOString();
    job.snapshot.error = error;
    clearTimeout(job.deadline);
    for (const cleanup of [...job.cleanups]) cleanup();
    job.cleanups.clear();
    if (job.child) {
      // Framework Ping.SendAsyncCancel blocks; terminate our isolated worker instead.
      try { job.child.kill(); } catch { /* already exited */ }
    }
    this.publish(job);
  }

  async resolve(job) {
    const { target, family } = job.snapshot;
    if (net.isIP(target)) return target;
    if (target === 'localhost') return family === 6 ? '::1' : '127.0.0.1';
    const resolver = new Resolver({ timeout: 1000, tries: 1 });
    return new Promise((resolve, reject) => {
      let done = false;
      const finish = (error, address) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        job.cleanups.delete(cancel);
        resolver.cancel();
        if (error) reject(error); else resolve(address);
      };
      const cancel = () => finish(new Error('Resolution cancelled.'));
      const timer = setTimeout(() => finish(new Error('DNS resolution timed out.')), RESOLVE_TIMEOUT_MS);
      timer.unref?.();
      job.cleanups.add(cancel);
      const query = family === 6 ? resolver.resolve6(target) : resolver.resolve4(target);
      query.then((addresses) => {
        const address = addresses.find((value) => net.isIP(value) === family && isUnicast(value));
        finish(address ? null : new Error('DNS did not return a usable unicast address.'), address);
      }, () => finish(new Error('DNS resolution failed for the selected address family.')));
    });
  }

  async run(job) {
    if (!ACTIVE.has(job.snapshot.status)) return;
    try { job.snapshot.address = await this.resolve(job); }
    catch (error) { this.finish(job, 'error', error.message); return; }
    if (!ACTIVE.has(job.snapshot.status)) return;
    if (!isUnicast(job.snapshot.address)) { this.finish(job, 'error', 'Resolved target is not unicast.'); return; }
    job.snapshot.status = 'running';
    this.publish(job);
    if (!ACTIVE.has(job.snapshot.status)) return;
    if (job.snapshot.kind === 'ping' || job.snapshot.kind === 'mtr') {
      if (process.platform !== 'win32') {
        this.finish(job, 'error', 'Native ICMP diagnostics are supported on Windows only.');
        return;
      }
      this.runIcmp(job);
    } else await this.runSockets(job);
  }

  recordProbe(job, input) {
    if (!ACTIVE.has(job.snapshot.status)) return;
    let state = job.hops.get(input.ttl);
    if (!state || (input.address && state.address && input.address !== state.address)) {
      state = { ttl: input.ttl, address: null, status: input.status, sent: 0, received: 0,
        lost: 0, lossPercent: 0, lastMs: null, minMs: null, avgMs: null, maxMs: null, jitterMs: null,
        samples: [], sum: 0, previous: null, jitterSum: 0, jitterPairs: 0 };
      job.hops.set(input.ttl, state);
    }
    const received = input.status === 'success' || input.status === 'ttl-expired' ||
      (input.status === 'unreachable' && isUnicast(input.address));
    state.sent += 1;
    state.status = input.status;
    if (input.address) state.address = input.address;
    if (received && Number.isFinite(input.ms)) {
      state.received += 1;
      state.lastMs = round(Math.max(0, input.ms));
      state.sum += state.lastMs;
      state.minMs = state.minMs === null ? state.lastMs : Math.min(state.minMs, state.lastMs);
      state.maxMs = state.maxMs === null ? state.lastMs : Math.max(state.maxMs, state.lastMs);
      state.avgMs = round(state.sum / state.received);
      if (state.previous !== null) { state.jitterSum += Math.abs(state.lastMs - state.previous); state.jitterPairs += 1; }
      state.previous = state.lastMs;
      state.jitterMs = state.jitterPairs > 0 ? round(state.jitterSum / state.jitterPairs) : null;
    } else { state.lastMs = null; state.previous = null; }
    state.samples.push({ at: input.at || new Date().toISOString(), ms: state.lastMs, status: input.status });
    if (state.samples.length > MAX_HOP_SAMPLES) state.samples.shift();
    state.lost = state.sent - state.received;
    state.lossPercent = round(state.lost / state.sent * 100);
    if (input.status === 'success' && input.address === job.snapshot.address) job.snapshot.reached = true;
    job.snapshot.hops = [...job.hops.values()].sort((a, b) => a.ttl - b.ttl).map(({ sum, previous, jitterSum, jitterPairs, ...hop }) => ({ ...hop }));
    job.cycleProbes.set(input.ttl, input);
    if (!input.sequence) this.publish(job);
  }

  completeCycle(job, cycle, reachedTtl) {
    if (!ACTIVE.has(job.snapshot.status)) return;
    if (Number.isInteger(reachedTtl) && reachedTtl > 0) {
      for (const ttl of job.hops.keys()) if (ttl > reachedTtl) job.hops.delete(ttl);
      job.snapshot.hops = job.snapshot.hops.filter((hop) => hop.ttl <= reachedTtl);
    }
    const probes = [...job.cycleProbes.values()].sort((a, b) => a.ttl - b.ttl);
    const final = job.snapshot.kind === 'mtr'
      ? probes.find((probe) => probe.address === job.snapshot.address && probe.status === 'success')
      : probes.find((probe) => probe.status === 'success') || probes.at(-1);
    if (final) {
      job.snapshot.samples.push({ at: final.at || new Date().toISOString(),
        ms: Number.isFinite(final.ms) ? final.ms : null, status: final.status });
      if (job.snapshot.samples.length > MAX_SAMPLES) job.snapshot.samples.shift();
    }
    job.cycleProbes.clear();
    job.snapshot.cycle = cycle;
    this.publish(job);
  }

  acceptIcmp(job, event) {
    const spec = job.snapshot;
    if (!ACTIVE.has(spec.status)) return false;
    const invalid = () => { this.finish(job, 'error', 'Native ICMP returned invalid probe metadata.'); return false; };
    if (!event || typeof event !== 'object') return invalid();
    if (event.type === 'route') {
      if (!Number.isInteger(event.cap) || event.cap < 1 || event.cap > spec.maxHops ||
          (event.reachedTtl !== null && event.reachedTtl !== event.cap)) return invalid();
      job.activeTtl = event.cap;
      if (event.reachedTtl !== null) job.destinationTtl = event.reachedTtl;
      this.icmpProgress(job);
      return true;
    }
    if (event.type !== 'probe' || !Number.isInteger(event.ttl) || event.ttl < 1 ||
        event.ttl > (spec.kind === 'ping' ? 1 : spec.maxHops) ||
        !Number.isSafeInteger(event.sequence) || event.sequence !== (job.sequences.get(event.ttl) || 0) + 1 ||
        (!spec.continuous && event.sequence > spec.cycles) || !Number.isFinite(Date.parse(event.at))) return invalid();
    const status = event.status === 'Success' ? 'success' :
      (event.status === 'TtlExpired' || event.status === 'TimeExceeded') ? 'ttl-expired' :
        event.status === 'TimedOut' ? 'timeout' : /Unreachable|BadRoute|DestinationScopeMismatch/.test(event.status) ? 'unreachable' : 'error';
    const address = status !== 'timeout' && isUnicast(event.address) ?
      (net.isIP(event.address) === 6 ? new URL('http://[' + event.address + ']/').hostname.slice(1, -1) : event.address) : null;
    if (status === 'error' || (status === 'success' && address !== spec.address) ||
        ((status === 'success' || status === 'ttl-expired') && (!address || !Number.isFinite(event.ms) || event.ms < 0))) {
      this.finish(job, 'error', 'Native ICMP probe failed or returned invalid response data.'); return false;
    }
    job.sequences.set(event.ttl, event.sequence);
    const probe = { ttl: event.ttl, sequence: event.sequence, status, address,
      ms: Number.isFinite(event.ms) && event.ms >= 0 ? round(event.ms) : null, at: new Date(event.at).toISOString() };
    this.recordProbe(job, probe);
    if (status === 'success' && (!job.destinationTtl || event.ttl < job.destinationTtl)) job.destinationTtl = event.ttl;
    // MTR's overview is the pinned destination only, never the last intermediate router.
    if (spec.kind === 'ping' || event.ttl === job.destinationTtl) {
      spec.samples.push({ at: probe.at, ms: status === 'success' && address === spec.address ? probe.ms : null, status });
      if (spec.samples.length > MAX_SAMPLES) spec.samples.shift();
    }
    this.icmpProgress(job);
    if (job.destinationTtl && job.activeTtl === job.destinationTtl) {
      spec.hops = spec.hops.filter((hop) => hop.ttl <= job.activeTtl);
    }
    this.publish(job);
    return true;
  }

  icmpProgress(job) {
    const counts = Array.from({ length: job.activeTtl }, (_, i) => job.sequences.get(i + 1) || 0);
    // High-water minimum over active lanes: rediscovery can never rewind displayed progress.
    job.snapshot.cycle = Math.max(job.snapshot.cycle, Math.min(...counts));
  }

  runIcmp(job) {
    const spec = job.snapshot;
    let buffer = '';
    let ready = false;
    let sawDone = false;
    const child = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
      '-File', WORKER_PATH, '-Address', spec.address, '-Mode', spec.kind,
      '-TimeoutMs', String(spec.timeoutMs), '-IntervalMs', String(spec.intervalMs),
      '-MaxHops', String(spec.maxHops), ...(spec.continuous ? ['-Continuous'] : ['-Cycles', String(spec.cycles)])],
    { windowsHide: true, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    job.child = child;
    this.workers.add(job);
    const startup = setTimeout(() => this.finish(job, 'error', 'Native ICMP worker startup timed out.'), WORKER_START_TIMEOUT_MS);
    startup.unref?.();
    const stall = setInterval(() => {
      if (ready && Date.now() - job.lastWorkerAt > Math.max(5000, spec.timeoutMs + spec.intervalMs + 3000)) {
        this.finish(job, 'error', 'Native ICMP worker stopped responding.');
      }
    }, 1000);
    stall.unref?.();
    const cleanup = () => { clearTimeout(startup); clearInterval(stall); };
    job.cleanups.add(cleanup);
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      if (!ACTIVE.has(spec.status)) return;
      buffer += chunk;
      let newline;
      while ((newline = buffer.indexOf('\n')) !== -1) {
        if (newline > 4096) { this.finish(job, 'error', 'Native ICMP message exceeded its bound.'); return; }
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        let event;
        try { event = JSON.parse(line); }
        catch { this.finish(job, 'error', 'Native ICMP returned invalid data.'); return; }
        job.lastWorkerAt = Date.now();
        if (!event || typeof event !== 'object') { this.finish(job, 'error', 'Native ICMP returned invalid data.'); return; }
        if (event.type === 'ready' && !ready) { ready = true; clearTimeout(startup); }
        else if (event.type === 'probe' || event.type === 'route') {
          if (!ready || !this.acceptIcmp(job, event)) return;
        } else if (event.type === 'done' && !spec.continuous &&
            Array.from({ length: job.activeTtl }, (_, i) => job.sequences.get(i + 1) || 0).every((count) => count === spec.cycles)) sawDone = true;
        else { this.finish(job, 'error', 'Native ICMP worker failed or returned invalid data.'); return; }
      }
      // Bound only the remaining partial message, not valid batches or monitor lifetime output.
      if (buffer.length > 4096) this.finish(job, 'error', 'Native ICMP message exceeded its bound.');
    });
    child.stderr.resume();
    child.on('error', () => this.finish(job, 'error', 'Unable to start the native Windows ICMP worker.'));
    child.on('close', (code) => {
      cleanup(); job.cleanups.delete(cleanup); job.child = null; this.workers.delete(job);
      if (ACTIVE.has(spec.status)) this.finish(job, code === 0 && sawDone ? 'completed' : 'error',
        code === 0 && sawDone ? null : 'Native ICMP worker exited before completing its measurements.');
    });
  }

  async runSockets(job) {
    const spec = job.snapshot;
    for (let cycle = 1; cycle <= spec.cycles && ACTIVE.has(spec.status); cycle += 1) {
      const started = performance.now();
      const result = await this.probeSocket(job);
      if (!ACTIVE.has(spec.status)) return;
      if (result.tls) spec.tls = result.tls;
      this.recordProbe(job, { ttl: 1, address: spec.address, ...result, at: new Date().toISOString() });
      this.completeCycle(job, cycle);
      if (cycle < spec.cycles && ACTIVE.has(spec.status)) await this.pause(job, Math.max(0, spec.intervalMs - (performance.now() - started)));
    }
    if (ACTIVE.has(spec.status)) this.finish(job, 'completed');
  }

  pause(job, ms) {
    return new Promise((resolve) => {
      const done = () => { clearTimeout(timer); job.cleanups.delete(done); resolve(); };
      const timer = setTimeout(done, ms);
      timer.unref?.(); job.cleanups.add(done);
    });
  }

  probeSocket(job) {
    const spec = job.snapshot;
    return new Promise((resolve) => {
      const started = performance.now();
      let socket;
      let done = false;
      const servername = spec.kind === 'tls' && !net.isIP(spec.target) ? spec.target : null;
      const finish = (status, error) => {
        if (done) return;
        done = true; clearTimeout(timer); job.cleanups.delete(cancel);
        const result = { status, ms: status === 'success' ? round(performance.now() - started) : null };
        if (spec.kind === 'tls' && socket) result.tls = inspectTls(socket, servername, error);
        socket?.destroy(); resolve(result);
      };
      const cancel = () => finish('error', new Error('Diagnostic cancelled.'));
      const timer = setTimeout(() => finish('timeout', new Error('Connection timed out.')), spec.timeoutMs);
      timer.unref?.(); job.cleanups.add(cancel);
      try {
        const options = { host: spec.address, port: spec.port, family: spec.family };
        if (spec.kind === 'tls') {
          socket = tls.connect({ ...options, servername: servername || undefined, rejectUnauthorized: true,
            ca: this.ca, checkServerIdentity: (_host, cert) => tls.checkServerIdentity(spec.target, cert) });
          socket.once('secureConnect', () => finish('success'));
        } else {
          socket = net.createConnection(options);
          socket.once('connect', () => finish('success'));
        }
        socket.once('error', (error) => finish(error.code === 'ECONNREFUSED' ? 'refused' : 'error', error));
        socket.once('close', () => finish('error', new Error('Connection closed before completion.')));
      } catch (error) { finish('error', error); }
    });
  }
}

module.exports = { DiagnosticService, validateDiagnosticSpec, isUnicast,
  MAX_ACTIVE_JOBS, MAX_RETAINED_JOBS, MAX_SAMPLES, MAX_HOP_SAMPLES, MAX_LIFETIME_MS, RESOLVE_TIMEOUT_MS };
