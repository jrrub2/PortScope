'use strict';

/**
 * In-memory state model for PortScope.
 *
 * The store owns:
 *   - the current port map (one record per listening TCP port),
 *   - the event log (online/offline diffs, max 100 entries, newest first),
 *   - scan metadata (ready/isScanning/scanCount/scannedAt/scanDurationMs),
 *   - per-port probe refresh policy (15 s / 30 s / 120 s),
 *   - snapshot building for GET /api/state and the SSE stream.
 *
 * It performs no I/O and never starts timers: the monitor drives scans and
 * probes, the HTTP layer subscribes to `change` events and decides how to
 * broadcast them.
 */

const os = require('node:os');
const { EventEmitter } = require('node:events');
const { classifyPort, buildPortUrl, probeHostFor } = require('./classify');
const { roundMs } = require('./util');
const { networkSnapshot } = require('./network');

const MAX_EVENTS = 100;
const MAX_HISTORY_SAMPLES = 240;
const MAX_LATENCY_HISTORY = 30;
const NEW_PORT_WINDOW_MS = 60_000;

/** Re-probe cadence from docs/API-CONTRACT.md section 9. */
const PROBE_INTERVAL_OK_MS = 15_000;
const PROBE_INTERVAL_FAIL_MS = 30_000;
const PROBE_INTERVAL_SYSTEM_MS = 120_000;

/**
 * @typedef {object} PortRecord
 * @property {number} port
 * @property {string[]} bindAddresses
 * @property {boolean} wildcard
 * @property {number} pid
 * @property {string|null} processName
 * @property {number} firstSeenMs
 * @property {number} lastSeenMs
 * @property {string} protocol
 * @property {'pending'|'done'|'timeout'|'error'} probeStatus
 * @property {string|null} url
 * @property {string|null} title
 * @property {number|null} statusCode
 * @property {string|null} statusText
 * @property {string|null} server
 * @property {string|null} poweredBy
 * @property {string|null} contentType
 * @property {string|null} framework
 * @property {number|null} responseTimeMs
 * @property {number[]} latencyHistory
 * @property {Record<string,string>} headers
 * @property {string|null} error
 * @property {number} nextProbeAt
 * @property {boolean} probing
 * @property {number} generation
 */

class Store extends EventEmitter {
  /**
   * @param {{serverPort: number, scanIntervalMs: number, version: string,
   *   startedAt?: number, platform?: string}} options
   */
  constructor(options) {
    super();
    this.serverPort = options.serverPort;
    this.scanIntervalMs = options.scanIntervalMs;
    this.version = options.version || '1.0.0';
    this.platform = options.platform || process.platform;
    this.startedAt = options.startedAt ?? Date.now();
    this.hostname = os.hostname();

    /** @type {Map<number, PortRecord>} */
    this.ports = new Map();
    /** @type {Array<object>} newest first */
    this.events = [];
    this.eventCounter = 0;

    this.history = [];
    this.network = networkSnapshot({ ok: false, scannedAt: null, error: 'Waiting for first scan.' });
    this.scanCount = 0;
    this.scannedAt = null;
    this.scanDurationMs = 0;
    this.isScanning = false;
    this.ready = false;
    this.lastError = null;
    this.activeClients = 0;

    this.hasBaseline = false;
    this.consecutiveFailures = 0;
    this.pendingProbesProvider = () => 0;
    // Every port record gets a process-lifetime unique generation. In-flight
    // probe results carry the generation they were queued for, so a result for
    // a port that disappeared, was re-created, or changed owner is discarded
    // instead of being applied to the wrong record.
    this.generationCounter = 0;

    this.addEvent({ type: 'start', atMs: this.startedAt });
  }

  // -------------------------------------------------------------------------
  // External wiring
  // -------------------------------------------------------------------------

  /** @param {number} port actual listening port once the server is bound */
  setServerPort(port) {
    this.serverPort = port;
  }

  /** @param {() => number} provider live probe-queue size */
  setPendingProbesProvider(provider) {
    this.pendingProbesProvider = typeof provider === 'function' ? provider : () => 0;
  }

  /** @param {number} count connected SSE clients */
  setActiveClients(count) {
    this.activeClients = count;
  }

  /** Record a non-fatal subsystem error (shown in meta.lastError). */
  setLastError(message) {
    this.lastError = message || null;
  }

  // -------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------

  /**
   * @param {{type: 'start'|'online'|'offline', port?: number|null,
   *   processName?: string|null, title?: string|null, category?: string|null,
   *   atMs?: number}} input
   */
  addEvent(input) {
    const atMs = input.atMs ?? Date.now();
    this.eventCounter += 1;
    this.events.unshift({
      id: `evt_${atMs}_${this.eventCounter}`,
      type: input.type,
      port: input.port ?? null,
      processName: input.processName ?? null,
      title: input.title ?? null,
      category: input.category ?? null,
      at: new Date(atMs).toISOString(),
    });
    if (this.events.length > MAX_EVENTS) {
      this.events.length = MAX_EVENTS;
    }
  }

  // -------------------------------------------------------------------------
  // Scan lifecycle
  // -------------------------------------------------------------------------

  /** Mark a listener scan as started and notify subscribers. */
  beginScan() {
    this.isScanning = true;
    this.emit('change', { kind: 'scan-start' });
  }

  /**
   * Apply one completed listener scan: diff ports, emit online/offline events,
   * update metadata. Does not emit; the monitor calls endScan() after it has
   * queued the probes that this scan made due, so the broadcast carries an
   * accurate pendingProbes value.
   *
   * @param {{ok: boolean, ports?: Array<object>, durationMs?: number,
   *   warnings?: string[], error?: string}} result
   */
  applyScanResult(result) {
    this.scanCount += 1;
    this.scannedAt = Date.now();
    this.network = result.network || networkSnapshot({ ok: false, error: result.error || 'Network snapshot unavailable.' });
    this.scanDurationMs = roundMs(Number(result.durationMs) || 0);
    this.isScanning = false;

    if (!result.ok) {
      this.consecutiveFailures += 1;
      this.lastError = result.error || 'Pemindaian port gagal.';
      // Contract: keep the previous list for one cycle, then expose an empty
      // list instead of stale data. No offline events are emitted here because
      // the ports were never observed shutting down.
      if (this.consecutiveFailures >= 2 && this.ports.size > 0) {
        this.ports.clear();
        this.hasBaseline = false;
      }
      if (!this.ready) this.ready = true;
      return;
    }

    this.consecutiveFailures = 0;
    this.lastError = Array.isArray(result.warnings) && result.warnings.length > 0
      ? result.warnings[0]
      : null;

    const now = Date.now();
    const baseline = !this.hasBaseline;
    const incoming = new Map();
    for (const scanned of result.ports || []) {
      incoming.set(scanned.port, scanned);
    }

    // Ports that disappeared while the scanner was healthy.
    for (const [port, record] of [...this.ports]) {
      if (incoming.has(port)) continue;
      if (!baseline) {
        this.addEvent({
          type: 'offline',
          port,
          processName: record.processName,
          title: record.title,
          category: this.categoryFor(record),
        });
      }
      this.ports.delete(port);
    }

    // New and existing ports.
    for (const scanned of incoming.values()) {
      const existing = this.ports.get(scanned.port);
      if (!existing) {
        const record = this.createRecord(scanned, now);
        this.ports.set(scanned.port, record);
        if (!baseline) {
          this.addEvent({
            type: 'online',
            port: scanned.port,
            processName: record.processName,
            title: null, // first probe has not run yet
            category: this.categoryFor(record),
          });
        }
        continue;
      }

      if (existing.pid !== scanned.pid) {
        // Same port number, different owner: the old service went away and a
        // new one took the port. Treat it as a real offline -> online change.
        if (!baseline) {
          this.addEvent({
            type: 'offline',
            port: existing.port,
            processName: existing.processName,
            title: existing.title,
            category: this.categoryFor(existing),
          });
        }
        const record = this.createRecord(scanned, existing.firstSeenMs);
        this.ports.set(scanned.port, record);
        if (!baseline) {
          this.addEvent({
            type: 'online',
            port: scanned.port,
            processName: record.processName,
            title: null,
            category: this.categoryFor(record),
          });
        }
        continue;
      }

      existing.bindAddresses = scanned.bindAddresses;
      existing.wildcard = scanned.wildcard;
      existing.processName = scanned.processName;
      existing.lastSeenMs = now;
    }

    this.ready = true;
    this.hasBaseline = true;
  }

  /** Notify subscribers that a scan fully settled (state may be broadcast). */
  endScan() {
    this.isScanning = false;
    const snapshot = this.snapshot();
    const latencies = snapshot.ports.filter((port) => port.protocol !== 'tcp' && Number.isFinite(port.responseTimeMs));
    if (this.ready && this.consecutiveFailures === 0) this.history.push({
      at: snapshot.meta.scannedAt,
      totalPorts: snapshot.stats.totalPorts,
      webPorts: snapshot.stats.webPorts,
      tcpOnlyPorts: snapshot.stats.tcpOnlyPorts,
      exposedPorts: snapshot.ports.filter((port) => port.wildcard).length,
      processCount: snapshot.stats.processCount,
      avgResponseTimeMs: latencies.length
        ? Math.round(latencies.reduce((sum, port) => sum + port.responseTimeMs, 0) / latencies.length) : null,
      errorPorts: snapshot.ports.filter((port) => port.error || (port.statusCode !== null && port.statusCode >= 400)).length,
    });
    if (this.history.length > MAX_HISTORY_SAMPLES) this.history.shift();
    this.emit('change', { kind: 'scan-done' });
  }

  historySnapshot() {
    return { ok: this.ready && this.consecutiveFailures === 0, samples: this.history.map((sample) => ({ ...sample })),
      startedAt: new Date(this.startedAt).toISOString() };
  }

  /**
   * @param {object} scanned
   * @param {number} firstSeenMs
   * @returns {PortRecord}
   */
  createRecord(scanned, firstSeenMs) {
    return {
      port: scanned.port,
      bindAddresses: [...scanned.bindAddresses],
      wildcard: Boolean(scanned.wildcard),
      pid: scanned.pid,
      processName: scanned.processName ?? null,
      firstSeenMs,
      lastSeenMs: Date.now(),
      protocol: 'tcp',
      probeStatus: 'pending',
      url: null,
      title: null,
      statusCode: null,
      statusText: null,
      server: null,
      poweredBy: null,
      contentType: null,
      framework: null,
      responseTimeMs: null,
      latencyHistory: [],
      headers: {},
      error: null,
      nextProbeAt: 0, // due immediately
      probing: false,
      generation: ++this.generationCounter,
    };
  }

  // -------------------------------------------------------------------------
  // Probes
  // -------------------------------------------------------------------------

  /** Category for a record using current (possibly probed) information. */
  categoryFor(record) {
    return classifyPort({
      port: record.port,
      pid: record.pid,
      processName: record.processName,
      framework: record.framework,
      platform: this.platform,
    });
  }

  /** Re-probe delay for a record based on category and last outcome. */
  probeIntervalFor(record) {
    if (record.probeStatus === 'done') return PROBE_INTERVAL_OK_MS;
    if (this.categoryFor(record) === 'system') return PROBE_INTERVAL_SYSTEM_MS;
    return PROBE_INTERVAL_FAIL_MS;
  }

  /**
   * Probe tasks that are due right now. The monitor enqueues these into the
   * bounded probe pool; the store itself never starts work.
   * @param {number} [now]
   */
  portsDueForProbe(now = Date.now()) {
    const due = [];
    for (const record of this.ports.values()) {
      if (record.probing) continue;
      if (record.nextProbeAt > now) continue;
      due.push({
        port: record.port,
        host: probeHostFor(record.bindAddresses),
        generation: record.generation,
      });
    }
    due.sort((a, b) => a.port - b.port);
    return due;
  }

  /** @param {number} port */
  markProbing(port) {
    const record = this.ports.get(port);
    if (record) record.probing = true;
  }

  /**
   * Apply a probe result. Late results for ports that disappeared, or for a
   * previous owner of the same port, are ignored.
   *
   * @param {number} port
   * @param {number} generation
   * @param {object} result
   * @returns {boolean} true when the state changed
   */
  applyProbe(port, generation, result) {
    const record = this.ports.get(port);
    if (!record || record.generation !== generation) return false;

    record.probing = false;
    record.probeStatus = result.probeStatus || 'error';

    if (result.protocol === 'http' || result.protocol === 'https') {
      record.protocol = result.protocol;
      record.url = buildPortUrl(result.protocol, port);
      record.title = result.title ?? null;
      record.statusCode = Number.isFinite(result.statusCode) ? result.statusCode : null;
      record.statusText = result.statusText || null;
      record.server = result.server ?? null;
      record.poweredBy = result.poweredBy ?? null;
      record.contentType = result.contentType ?? null;
      record.framework = result.framework ?? null;
      record.headers = result.headers || {};
      record.error = null;
      if (Number.isFinite(result.responseTimeMs)) {
        record.responseTimeMs = Math.max(0, Math.round(result.responseTimeMs));
        record.latencyHistory.push(record.responseTimeMs);
        if (record.latencyHistory.length > MAX_LATENCY_HISTORY) {
          record.latencyHistory.splice(0, record.latencyHistory.length - MAX_LATENCY_HISTORY);
        }
      }
    } else {
      // Listening socket that is not speaking HTTP(S). Keep the last good
      // latency history, clear everything that described an HTTP response.
      record.protocol = 'tcp';
      record.url = null;
      record.title = null;
      record.statusCode = null;
      record.statusText = null;
      record.server = null;
      record.poweredBy = null;
      record.contentType = null;
      record.framework = null;
      record.headers = {};
      record.error = result.error || 'Tidak merespons';
    }

    record.nextProbeAt = Date.now() + this.probeIntervalFor(record);
    this.emit('change', { kind: 'probe', port });
    return true;
  }

  // -------------------------------------------------------------------------
  // Snapshot
  // -------------------------------------------------------------------------

  /**
   * Build the full contract snapshot (also used as the SSE payload).
   * @returns {object}
   */
  snapshot() {
    const now = Date.now();
    /** @type {Array<object>} */
    const ports = [];
    /** @type {{dev: number, app: number, system: number}} */
    const categoryCounts = { dev: 0, app: 0, system: 0 };
    const pids = new Set();
    let webPorts = 0;
    let httpsPorts = 0;
    let newPorts = 0;

    const ordered = [...this.ports.values()].sort((a, b) => a.port - b.port);
    for (const record of ordered) {
      const category = this.categoryFor(record);
      categoryCounts[category] += 1;
      pids.add(record.pid);

      const isWeb = record.protocol === 'http' || record.protocol === 'https';
      if (isWeb) webPorts += 1;
      if (record.protocol === 'https') httpsPorts += 1;
      if (now - record.firstSeenMs < NEW_PORT_WINDOW_MS) newPorts += 1;

      ports.push({
        port: record.port,
        protocol: record.protocol,
        probeStatus: record.probeStatus,
        url: record.url,
        title: record.title,
        statusCode: record.statusCode,
        statusText: record.statusText,
        server: record.server,
        poweredBy: record.poweredBy,
        contentType: record.contentType,
        framework: record.framework,
        responseTimeMs: record.responseTimeMs,
        latencyHistory: record.latencyHistory.slice(-MAX_LATENCY_HISTORY),
        headers: record.headers,
        bindAddresses: record.bindAddresses,
        wildcard: record.wildcard,
        pid: record.pid,
        processName: record.processName,
        category,
        firstSeenAt: new Date(record.firstSeenMs).toISOString(),
        lastSeenAt: new Date(record.lastSeenMs).toISOString(),
        onlineForMs: Math.max(0, now - record.firstSeenMs),
        isSelf: record.port === this.serverPort,
        error: record.error,
      });
    }

    const totalPorts = ports.length;
    return {
      ok: true,
      meta: {
        app: 'PortScope',
        version: this.version,
        hostname: this.hostname,
        platform: this.platform,
        arch: process.arch,
        serverPort: this.serverPort,
        startedAt: new Date(this.startedAt).toISOString(),
        scannedAt: this.scannedAt ? new Date(this.scannedAt).toISOString() : null,
        scanDurationMs: this.scanDurationMs,
        scanCount: this.scanCount,
        scanIntervalMs: this.scanIntervalMs,
        isScanning: this.isScanning,
        ready: this.ready,
        pendingProbes: this.pendingProbesProvider(),
        activeClients: this.activeClients,
        uptimeMs: Math.round(process.uptime() * 1000),
        lastError: this.lastError,
      },
      stats: {
        totalPorts,
        webPorts,
        httpsPorts,
        tcpOnlyPorts: totalPorts - webPorts,
        processCount: pids.size,
        newPorts,
        categoryCounts,
      },
      ports,
      events: this.events.slice(),
    };
  }
}

module.exports = {
  Store,
  MAX_EVENTS,
  MAX_HISTORY_SAMPLES,
  NEW_PORT_WINDOW_MS,
  PROBE_INTERVAL_OK_MS,
  PROBE_INTERVAL_FAIL_MS,
  PROBE_INTERVAL_SYSTEM_MS,
  MAX_LATENCY_HISTORY,
};
