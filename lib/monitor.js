'use strict';

/**
 * Scan scheduler + probe orchestrator.
 *
 * Responsibilities:
 *   - run listener scans on the configured interval (never overlapping),
 *   - honour manual POST /api/scan requests,
 *   - after each scan, enqueue every port whose probe refresh is due,
 *   - tell the store when a scan fully settled so the HTTP layer broadcasts.
 *
 * Keeping this in one small class means server.js stays focused on HTTP, SSE
 * and CLI concerns.
 */

const { Store } = require('./store');
const { scanListeningPorts } = require('./scanner');
const { ProbePool } = require('./probe');
const { errorText } = require('./util');

const PROBE_CONCURRENCY = 32;
const PROBE_TIMEOUT_MS = 1200;

class Monitor {
  /**
   * @param {{serverPort: number, scanIntervalMs: number, version: string,
   *   startedAt?: number}} options
   */
  constructor(options) {
    this.scanIntervalMs = options.scanIntervalMs;
    this.store = new Store({
      serverPort: options.serverPort,
      scanIntervalMs: options.scanIntervalMs,
      version: options.version,
      startedAt: options.startedAt,
    });

    this.pool = new ProbePool({
      concurrency: PROBE_CONCURRENCY,
      timeoutMs: PROBE_TIMEOUT_MS,
      onResult: (task, result) => {
        this.store.applyProbe(task.port, task.generation, result);
      },
      onIdle: () => {
        this.store.emit('change', { kind: 'probe-idle' });
      },
    });
    this.store.setPendingProbesProvider(() => this.pool.pending);

    this.scanning = false;
    this.scanQueued = false;
    this.stopped = false;
    /** @type {NodeJS.Timeout|null} */
    this.timer = null;
  }

  /** Kick off the first scan; the HTTP server is already listening. */
  start() {
    this.runScan('startup');
  }

  /**
   * Run one scan unless one is already in flight.
   * @param {'startup'|'auto'|'manual'} reason
   */
  async runScan(reason) {
    if (this.stopped || this.scanning) return;
    this.scanning = true;
    this.store.beginScan();

    let result;
    try {
      result = await scanListeningPorts();
    } catch (error) {
      // scanListeningPorts resolves failures on its own; this is a last-resort
      // guard so an unexpected bug can never crash the process.
      result = {
        ok: false,
        durationMs: 0,
        warnings: [],
        error: `Pemindaian gagal: ${errorText(error)}`,
      };
    }

    if (this.stopped) {
      this.scanning = false;
      return;
    }

    this.store.applyScanResult(result);
    this.syncProbes();
    this.store.endScan();
    this.scanning = false;
    this.scheduleNextScan();

    // Contract: scan errors are logged as `[scan] ...`. Keep it to the first
    // occurrence so a persistently broken scanner cannot spam the console.
    if (!result.ok) {
      const failures = this.store.consecutiveFailures;
      if (failures <= 1 || failures % 20 === 0) {
        console.error(`  [scan] ${result.error}`);
      }
    } else if (result.warnings && result.warnings.length > 0) {
      console.warn(`  [scan] ${result.warnings[0]}`);
    }

    if (reason === 'manual') {
      // No noisy per-scan logging; manual scans are noteworthy enough for a
      // single short line.
      console.log(`  [scan] manual scan${result.ok ? '' : ' gagal'}: ${this.store.scanDurationMs} ms | ${this.store.ports.size} port`);
    }
  }

  /**
   * Queue every probe that is currently due. The store marks records as
   * `probing` before enqueueing so the same port cannot enter the pool twice.
   */
  syncProbes() {
    for (const task of this.store.portsDueForProbe()) {
      this.store.markProbing(task.port);
      this.pool.enqueue(task);
    }
  }

  /**
   * Handle POST /api/scan. Returns `false` when a scan is already in flight.
   * The scan itself runs on the next tick so the HTTP response can be sent
   * immediately (contract: always respond 200 with `{queued, scanning}`).
   * @returns {boolean} true when a scan was queued
   */
  requestScan() {
    if (this.stopped || this.scanning || this.scanQueued) return false;
    this.scanQueued = true;
    setImmediate(() => {
      this.scanQueued = false;
      this.runScan('manual').catch((error) => {
        console.error('[scan] unexpected error:', error);
        this.store.setLastError(`Kesalahan pemindaian: ${errorText(error)}`);
      });
    });
    return true;
  }

  /** Schedule the next automatic scan after the current one settles. */
  scheduleNextScan() {
    if (this.stopped) return;
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(() => {
      this.timer = null;
      this.runScan('auto').catch((error) => {
        console.error('[scan] unexpected error:', error);
        this.store.setLastError(`Kesalahan pemindaian: ${errorText(error)}`);
      });
    }, this.scanIntervalMs);
    this.timer.unref?.();
  }

  /** Stop timers and abort in-flight probes (graceful shutdown). */
  stop() {
    this.stopped = true;
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.pool.stop();
  }
}

module.exports = { Monitor, PROBE_CONCURRENCY, PROBE_TIMEOUT_MS };
