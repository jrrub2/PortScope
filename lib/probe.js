'use strict';

/**
 * Async HTTP/HTTPS probe engine.
 *
 * A port that owns a TCP LISTENING socket is not necessarily an HTTP server,
 * so every discovered port is probed in the background:
 *   1. GET http://<loopback>:<port>/  (up to 3 redirects, 128 KB of body)
 *   2. if that fails, GET https://<loopback>:<port>/ with TLS verification off
 *      (the connection is loopback-only and read-only).
 *
 * Probes never block the listener scan: they run through a bounded pool
 * (concurrency 32) with a hard per-request timeout. Every socket is destroyed
 * and every timer/listener is cleaned up so the process can shut down cleanly.
 */

const http = require('node:http');
const https = require('node:https');
const { isLoopbackHost } = require('./classify');
const { decodeHtmlEntities, collapseWhitespace, truncate } = require('./util');

const DEFAULT_TIMEOUT_MS = 1200;
const DEFAULT_CONCURRENCY = 32;
const MAX_REDIRECTS = 3;
const MAX_BODY_BYTES = 128 * 1024;
const MAX_HEADER_KEYS = 30;
const MAX_HEADER_VALUE = 512;
const MAX_TITLE = 160;
const USER_AGENT = 'PortScope/1.0 (localhost probe; read-only)';

/** User-facing (Indonesian) hints shown in port.error. */
const ERROR_HINTS = Object.freeze({
  timeout: 'Tidak merespons',
  refused: 'Koneksi ditolak',
  notHttp: 'Bukan layanan HTTP',
  aborted: 'Pemeriksaan dibatalkan',
  generic: 'Gagal memeriksa',
});

class ProbeError extends Error {
  /**
   * @param {'timeout'|'refused'|'notHttp'|'aborted'|'generic'} kind
   * @param {string} message
   */
  constructor(kind, message) {
    super(message);
    this.name = 'ProbeError';
    this.kind = kind;
  }
}

// ---------------------------------------------------------------------------
// Response parsing / framework inference
// ---------------------------------------------------------------------------

/**
 * Keep only plain string response headers (contract: max 30 keys, strings
 * only) and cap value length so /api/state stays under its size budget.
 *
 * @param {Record<string, string|string[]|undefined>} rawHeaders
 * @returns {Record<string, string>}
 */
function sanitizeHeaders(rawHeaders) {
  const headers = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return headers;

  let count = 0;
  for (const [rawName, rawValue] of Object.entries(rawHeaders)) {
    if (count >= MAX_HEADER_KEYS) break;
    if (typeof rawValue === 'string') {
      headers[rawName.toLowerCase()] = truncate(rawValue, MAX_HEADER_VALUE);
      count += 1;
    } else if (Array.isArray(rawValue)) {
      const joined = rawValue.filter((value) => typeof value === 'string').join(', ');
      if (!joined) continue;
      headers[rawName.toLowerCase()] = truncate(joined, MAX_HEADER_VALUE);
      count += 1;
    }
  }
  return headers;
}

/** True when the body looks like HTML (and therefore may expose a title). */
function looksLikeHtml(contentType, body) {
  if (/html/i.test(contentType || '')) return true;
  if (contentType) return false; // explicit non-HTML type: do not guess
  return /^\s*<(!doctype\s+html|html|head|body)/i.test(body);
}

/**
 * Extract and normalise the <title> of an HTML document.
 * @param {string} body
 * @returns {string|null}
 */
function extractTitle(body) {
  const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!match) return null;
  const title = truncate(collapseWhitespace(decodeHtmlEntities(match[1])), MAX_TITLE);
  return title || null;
}

/**
 * Framework inference. Only confident signals are accepted (header names set
 * by the framework itself, or unmistakable markup), because a wrong label is
 * worse than no label.
 *
 * @param {{headers: Record<string,string>, body: string}} input
 * @returns {string|null}
 */
function inferFramework({ headers, body }) {
  const contentType = headers['content-type'] || '';
  const server = headers.server || '';
  const poweredBy = headers['x-powered-by'] || '';
  const html = looksLikeHtml(contentType, body) ? body.toLowerCase() : '';
  const text = body.toLowerCase();

  /** @type {Array<{name: string, score: number, hit: boolean}>} */
  const rules = [
    {
      name: 'Next.js',
      score: 60,
      hit: /__next_data__|\/_next\//.test(html) || /next\.js/i.test(poweredBy) || /next\.js/i.test(server),
    },
    {
      name: 'Vite',
      score: 58,
      hit: /\/@vite\/client|@vite\/env|__vite__/.test(html) || /\bvite\b/i.test(server) || /vite/i.test(poweredBy),
    },
    {
      name: 'Nuxt',
      score: 56,
      hit: /__nuxt|_nuxt\//.test(html) || /nuxt/i.test(poweredBy),
    },
    {
      name: 'Svelte',
      score: 54,
      hit: /__svelte|svelte-[a-z0-9]|sveltekit/.test(html),
    },
    {
      name: 'Angular',
      score: 52,
      hit: /ng-version=|ng-app=|<app-root/.test(html),
    },
    {
      name: 'WordPress',
      score: 50,
      hit: /wp-content|wp-includes/.test(html),
    },
    {
      name: 'Vue',
      score: 46,
      hit: /data-v-[0-9a-f]{6,}|__vue__|vue\.runtime/.test(html),
    },
    {
      name: 'React',
      score: 42,
      hit: /data-reactroot|react-dom|_reactrootcontainer|__react/.test(html),
    },
    {
      name: 'Express',
      score: 48,
      hit: /^express$/i.test(poweredBy) || /express/i.test(server),
    },
    {
      name: 'Django',
      score: 47,
      hit: /csrfmiddlewaretoken|django/i.test(text) || /wsgiserver|django/i.test(server),
    },
    {
      name: 'Flask',
      score: 47,
      hit: /werkzeug/i.test(server) || /\bflask\b/i.test(server),
    },
    {
      name: 'FastAPI',
      score: 47,
      hit: /fastapi/i.test(server) || (/uvicorn/i.test(server) && /"detail"\s*:/.test(body)),
    },
    {
      name: 'ASP.NET',
      score: 47,
      hit: /asp\.net/i.test(poweredBy) || /kestrel/i.test(server),
    },
    {
      name: 'PHP',
      score: 40,
      hit: /^php/i.test(poweredBy) || /^php/i.test(server),
    },
  ];

  let best = null;
  for (const rule of rules) {
    if (!rule.hit) continue;
    if (!best || rule.score > best.score) best = rule;
  }
  return best ? best.name : null;
}

// ---------------------------------------------------------------------------
// Low-level single request
// ---------------------------------------------------------------------------

/**
 * Classify a socket/TLS error into one of the shared probe error kinds.
 * @param {unknown} error
 * @returns {'timeout'|'refused'|'notHttp'|'aborted'|'generic'}
 */
function classifyNetworkError(error) {
  const code = String(error?.code || '').toUpperCase();
  const message = String(error?.message || '');

  if (error?.kind) return error.kind;
  if (code === 'ETIMEDOUT' || code === 'ESOCKETTIMEDOUT' || /timed?\s*out/i.test(message)) {
    return 'timeout';
  }
  if (code === 'ECONNREFUSED') return 'refused';
  if (code === 'ECONNRESET' || code === 'ECONNABORTED' || code === 'EPIPE' || code === 'EHOSTUNREACH' || code === 'ENETUNREACH') {
    return 'notHttp';
  }
  // TLS/certificate errors and HTTP parser errors all mean "listening, but not
  // an HTTP(S) endpoint on this scheme".
  return 'notHttp';
}

/**
 * Perform exactly one HTTP(S) request. Resolves as soon as headers arrive and
 * the body is either complete or 128 KB has been read, then destroys the
 * response so no half-open socket is left behind.
 *
 * @param {{protocol: 'http'|'https', host: string, port: number, path: string,
 *   timeoutMs: number, signal?: AbortSignal}} options
 * @returns {Promise<{statusCode: number, statusMessage: string, headers: Record<string,string>,
 *   body: string, responseTimeMs: number}>}
 */
function requestOnce({ protocol, host, port, path, timeoutMs, signal, maxBodyBytes = MAX_BODY_BYTES }) {
  return new Promise((resolve, reject) => {
    if (!isLoopbackHost(host)) {
      reject(new ProbeError('generic', 'Numeric loopback required'));
      return;
    }
    if (host.startsWith('[')) host = host.slice(1, -1);
    if (signal?.aborted) {
      reject(new ProbeError('aborted', 'aborted'));
      return;
    }

    const transport = protocol === 'https' ? https : http;
    const isIpv6 = host.includes(':');
    const hostHeader = isIpv6 ? `[${host}]:${port}` : `${host}:${port}`;
    const options = {
      host,
      port,
      path,
      method: 'GET',
      agent: false,
      family: isIpv6 ? 6 : 4,
      headers: {
        Host: hostHeader,
        Accept: 'text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8',
        'User-Agent': USER_AGENT,
        Connection: 'close',
      },
    };
    if (protocol === 'https') {
      // Loopback-only, read-only probe: local dev servers commonly use
      // self-signed certificates, so verification is intentionally disabled.
      options.rejectUnauthorized = false;
    }

    const startedAt = Date.now();
    let settled = false;
    let timer = null;
    let request = null;

    const cleanup = () => {
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      if (signal) signal.removeEventListener('abort', onAbort);
    };

    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (request) request.destroy();
      reject(error instanceof ProbeError ? error : new ProbeError(classifyNetworkError(error), String(error?.message || error)));
    };

    const succeed = (result) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(result);
    };

    const onAbort = () => fail(new ProbeError('aborted', 'aborted'));
    if (signal) signal.addEventListener('abort', onAbort, { once: true });

    // Hard deadline. Node's socket timeout alone does not cover every phase
    // (e.g. a TLS handshake against a non-TLS service can stall), so keep an
    // independent watchdog as well.
    timer = setTimeout(() => fail(new ProbeError('timeout', 'timeout')), timeoutMs);
    timer.unref?.();

    const onResponse = (response) => {
      if (settled) {
        response.destroy();
        return;
      }
      const responseTimeMs = Math.max(0, Math.round(Date.now() - startedAt));
      const chunks = [];
      let size = 0;
      let finished = false;

      const finish = () => {
        if (finished) return;
        finished = true;
        const body = Buffer.concat(chunks).toString('utf8');
        succeed({
          statusCode: Number(response.statusCode) || 0,
          statusMessage: response.statusMessage || '',
          headers: response.headers || {},
          body,
          responseTimeMs,
        });
        response.destroy();
      };

      response.on('data', (chunk) => {
        if (finished) return;
        if (size + chunk.length >= maxBodyBytes) {
          chunks.push(chunk.subarray(0, maxBodyBytes - size));
          size = maxBodyBytes;
          finish();
          return;
        }
        chunks.push(chunk);
        size += chunk.length;
      });
      response.on('end', finish);
      response.on('error', fail);
      response.on('aborted', () => fail(new ProbeError('notHttp', 'Response aborted')));
    };

    try {
      request = transport.request(options, onResponse);
    } catch (error) {
      fail(error);
      return;
    }
    request.on('error', (error) => fail(error));
    request.end();
  });
}

// ---------------------------------------------------------------------------
// Redirect handling + port probe
// ---------------------------------------------------------------------------

/** @param {number} statusCode */
function isRedirect(statusCode) {
  return statusCode === 301 || statusCode === 302 || statusCode === 303 || statusCode === 307 || statusCode === 308;
}

/**
 * Resolve a Location header against the current request. Only loopback targets
 * are accepted; anything else stops redirect following (PortScope never talks
 * to the network).
 *
 * @param {string} location
 * @param {{protocol: 'http'|'https', host: string, port: number, path: string}} current
 * @returns {{protocol: 'http'|'https', host: string, port: number, path: string}|null}
 */
function resolveRedirect(location, current) {
  if (!isLoopbackHost(current.host)) return null;
  if (typeof location !== 'string' || !location.trim()) return null;
  try {
    const baseHost = current.host.includes(':') ? `[${current.host}]` : current.host;
    const base = new URL(`${current.protocol}://${baseHost}:${current.port}${current.path}`);
    const next = new URL(location, base);
    if (next.protocol !== 'http:' && next.protocol !== 'https:') return null;
    const localAlias = next.hostname === 'localhost' || next.hostname.endsWith('.localhost');
    if (!localAlias && !isLoopbackHost(next.hostname)) return null;

    // `localhost` is ambiguous on dual-stack machines (could resolve to ::1
    // while the listener is IPv4-only), so reuse the probe host that is known
    // to reach this port.
    let host = next.hostname.replace(/^\[|\]$/g, '');
    if (localAlias) host = current.host;
    if (!isLoopbackHost(host) || next.username || next.password) return null;

    const protocol = next.protocol.slice(0, -1);
    const defaultPort = protocol === 'https' ? 443 : 80;
    const port = next.port ? Number.parseInt(next.port, 10) : defaultPort;
    if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;

    return { protocol, host, port, path: `${next.pathname}${next.search}` };
  } catch {
    return null;
  }
}

/**
 * Follow up to MAX_REDIRECTS redirects for one scheme.
 * @param {{protocol: 'http'|'https', host: string, port: number,
 *   timeoutMs: number, signal?: AbortSignal}} options
 */
async function requestFollowingRedirects({ protocol, host, port, timeoutMs, signal }) {
  let current = { protocol, host, port, path: '/' };
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const response = await requestOnce({ ...current, timeoutMs, signal });
    const location = response.headers.location;
    if (!isRedirect(response.statusCode) || !location || hop === MAX_REDIRECTS) {
      return { ...response, protocol: current.protocol };
    }
    const next = resolveRedirect(location, current);
    if (!next) return { ...response, protocol: current.protocol }; // non-loopback or invalid redirect: stop here
    current = next;
  }
  return null; // unreachable, loop always returns
}

/** Build a successful probe result from a final HTTP response. */
function buildDoneResult(protocol, response) {
  const headers = sanitizeHeaders(response.headers);
  const contentType = headers['content-type'] ?? null;
  const bodyText = response.body;
  const title = looksLikeHtml(contentType, bodyText) ? extractTitle(bodyText) : null;
  const framework = inferFramework({ headers, body: bodyText });

  return {
    protocol: response.protocol || protocol,
    probeStatus: 'done',
    statusCode: response.statusCode || null,
    statusText: response.statusMessage || null,
    title,
    server: headers.server ?? null,
    poweredBy: headers['x-powered-by'] ?? null,
    contentType,
    framework,
    responseTimeMs: response.responseTimeMs,
    headers,
    error: null,
  };
}

/** Build the "not an HTTP service" result for a port. */
function buildFailureResult(attempts) {
  const sawTimeout = attempts.some((error) => error.kind === 'timeout');
  const sawRefused = attempts.length > 0 && attempts.every((error) => error.kind === 'refused');
  const kind = sawTimeout ? 'timeout' : sawRefused ? 'refused' : 'notHttp';
  return {
    protocol: 'tcp',
    probeStatus: sawTimeout ? 'timeout' : 'error',
    statusCode: null,
    statusText: null,
    title: null,
    server: null,
    poweredBy: null,
    contentType: null,
    framework: null,
    responseTimeMs: null,
    headers: {},
    error: ERROR_HINTS[kind] || ERROR_HINTS.generic,
  };
}

/**
 * Probe one listening port.
 *
 * @param {{port: number, host: string, timeoutMs?: number,
 *   signal?: AbortSignal}} input
 * @returns {Promise<object>} a probe result (see buildDoneResult/buildFailureResult)
 */
async function probePort({ port, host, timeoutMs = DEFAULT_TIMEOUT_MS, signal }) {
  if (!isLoopbackHost(host)) {
    throw new ProbeError('generic', `Host non-loopback ditolak: ${host}`);
  }

  const attempts = [];
  for (const protocol of ['http', 'https']) {
    if (signal?.aborted) throw new ProbeError('aborted', 'aborted');
    try {
      const response = await requestFollowingRedirects({ protocol, host, port, timeoutMs, signal });
      return buildDoneResult(protocol, response);
    } catch (error) {
      if (error instanceof ProbeError && error.kind === 'aborted') throw error;
      attempts.push(error instanceof ProbeError ? error : new ProbeError(classifyNetworkError(error), String(error)));
    }
  }
  return buildFailureResult(attempts);
}

// ---------------------------------------------------------------------------
// Bounded probe pool
// ---------------------------------------------------------------------------

class ProbePool {
  /**
   * @param {{concurrency?: number, timeoutMs?: number,
   *   onResult?: (task: object, result: object) => void,
   *   onIdle?: () => void}} [options]
   */
  constructor(options = {}) {
    this.concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.onResult = options.onResult ?? null;
    this.onIdle = options.onIdle ?? null;

    /** @type {Array<{port: number, host: string, generation: number}>} */
    this.queue = [];
    this.active = 0;
    this.hadWork = false;
    this.stopped = false;
    /** @type {Set<AbortController>} */
    this.controllers = new Set();
  }

  /** Number of probes running or queued. */
  get pending() {
    return this.queue.length + this.active;
  }

  /**
   * Queue a probe. Deduplication is the caller's responsibility (the store
   * marks a port as `probing` before enqueueing).
   * @param {{port: number, host: string, generation: number}} task
   */
  enqueue(task) {
    if (this.stopped) return;
    this.queue.push(task);
    this.hadWork = true;
    this.pump();
  }

  pump() {
    if (this.stopped) return;

    while (this.active < this.concurrency && this.queue.length > 0) {
      const task = this.queue.shift();
      if (!task) break;

      const controller = new AbortController();
      this.controllers.add(controller);
      this.active += 1;

      probePort({ port: task.port, host: task.host, timeoutMs: this.timeoutMs, signal: controller.signal })
        .then((result) => {
          if (this.stopped || controller.signal.aborted) return;
          try {
            this.onResult?.(task, result);
          } catch (error) {
            // A bug in the result handler must not take the pool down.
            console.error('[probe] onResult error:', error);
          }
        })
        .catch((error) => {
          if (this.stopped || controller.signal.aborted) return;
          try {
            this.onResult?.(task, buildFailureResult([error]));
          } catch (handlerError) {
            console.error('[probe] onResult error:', handlerError);
          }
        })
        .finally(() => {
          this.active -= 1;
          this.controllers.delete(controller);
          this.pump();
          this.notifyIdle();
        });
    }

    this.notifyIdle();
  }

  /** Fire onIdle once per busy -> idle transition. */
  notifyIdle() {
    if (this.stopped) return;
    if (this.active !== 0 || this.queue.length !== 0) return;
    if (!this.hadWork) return;
    this.hadWork = false;
    try {
      this.onIdle?.();
    } catch (error) {
      console.error('[probe] onIdle error:', error);
    }
  }

  /** Abort in-flight requests and drop the queue (graceful shutdown). */
  stop() {
    this.stopped = true;
    this.queue.length = 0;
    for (const controller of this.controllers) {
      try {
        controller.abort();
      } catch {
        /* already aborted */
      }
    }
    this.controllers.clear();
  }
}

module.exports = {
  requestOnce,
  probePort,
  ProbePool,
  inferFramework,
  extractTitle,
  sanitizeHeaders,
  looksLikeHtml,
  classifyNetworkError,
  resolveRedirect,
  ERROR_HINTS,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_CONCURRENCY,
};
