'use strict';

const { requestOnce, sanitizeHeaders, ERROR_HINTS } = require('./probe');
const { isLoopbackHost } = require('./classify');

const CHECK_CONCURRENCY = 8;
const CHECK_TIMEOUT_MS = 2000;
const CHECK_BODY_BYTES = 64 * 1024;
const INPUT_BODY_BYTES = 4096;

function inputError(status, code, message) {
  return Object.assign(new Error(message), { status, code });
}

function validateCheck(input) {
  const fields = ['port', 'protocol', 'path', 'expectedStatus'];
  if (!input || typeof input !== 'object' || Array.isArray(input) ||
      Object.keys(input).length !== fields.length || Object.keys(input).some((key) => !fields.includes(key))) {
    throw inputError(400, 'INVALID_CHECK', 'Only port, protocol, path and expectedStatus are accepted.');
  }
  if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535 ||
      (input.protocol !== 'http' && input.protocol !== 'https') ||
      !Number.isInteger(input.expectedStatus) || input.expectedStatus < 100 || input.expectedStatus > 599) {
    throw inputError(400, 'INVALID_CHECK', 'Invalid port, protocol or expected status.');
  }
  const validPath = (value) => value.startsWith('/') && !value.startsWith('//') && !/[\\#\x00-\x20\x7f]/.test(value);
  let decoded;
  try { decoded = typeof input.path === 'string' ? decodeURIComponent(input.path) : ''; } catch { decoded = ''; }
  if (typeof input.path !== 'string' || input.path.length > 1024 || !validPath(input.path) || !validPath(decoded)) {
    throw inputError(400, 'INVALID_CHECK', 'Path must start with a single /, without a fragment or control characters (max 1024).');
  }
  return { port: input.port, protocol: input.protocol, path: input.path, expectedStatus: input.expectedStatus };
}

function readInput(req) {
  if (!/^application\/json(?:\s*;.*)?$/i.test(req.headers['content-type'] || '') ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) {
    throw inputError(415, 'JSON_REQUIRED', 'Use uncompressed application/json.');
  }
  if (Number(req.headers['content-length']) > INPUT_BODY_BYTES) {
    throw inputError(413, 'BODY_TOO_LARGE', 'Check request exceeds 4096 bytes.');
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const timer = setTimeout(() => finish(inputError(408, 'BODY_TIMEOUT', 'Request body timed out.')), CHECK_TIMEOUT_MS);
    timer.unref?.();
    const cleanup = () => {
      clearTimeout(timer);
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onError);
      req.removeListener('aborted', onAborted);
    };
    const finish = (error, value) => {
      if (done) return;
      done = true;
      cleanup();
      if (error) { req.resume(); reject(error); } else resolve(value);
    };
    const onData = (chunk) => {
      size += chunk.length;
      if (size > INPUT_BODY_BYTES) return finish(inputError(413, 'BODY_TOO_LARGE', 'Check request exceeds 4096 bytes.'));
      chunks.push(chunk);
    };
    const onEnd = () => {
      try { finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { finish(inputError(400, 'INVALID_JSON', 'Invalid JSON.')); }
    };
    const onError = () => finish(inputError(400, 'INVALID_BODY', 'Unable to read request body.'));
    const onAborted = () => finish(inputError(400, 'INVALID_BODY', 'Request was aborted.'));
    req.on('data', onData);
    req.once('end', onEnd);
    req.once('error', onError);
    req.once('aborted', onAborted);
  });
}

async function checkEndpoint(input, host = '127.0.0.1', signal) {
  const spec = validateCheck(input);
  if (typeof host === 'function') host = host(spec.port);
  if (!isLoopbackHost(host)) throw inputError(400, 'INVALID_HOST', 'Numeric loopback required.');
  const startedAt = Date.now();
  const check = { ...spec, statusCode: null, responseTimeMs: 0, healthy: false,
    checkedAt: new Date(startedAt).toISOString(), error: null, headers: {} };
  try {
    // Exactly one GET: no redirects, URL, cookies, authorization or caller headers forwarded.
    const response = await requestOnce({ ...spec, host, timeoutMs: CHECK_TIMEOUT_MS, maxBodyBytes: CHECK_BODY_BYTES, signal });
    check.statusCode = response.statusCode || null;
    check.responseTimeMs = response.responseTimeMs;
    check.headers = sanitizeHeaders(Object.fromEntries(Object.entries(response.headers).filter(
      ([name]) => !/^(?:set-cookie2?|cookie|authorization|proxy-authorization|www-authenticate|proxy-authenticate)$/i.test(name),
    )));
    check.healthy = check.statusCode === spec.expectedStatus;
    if (!check.healthy) check.error = `Expected HTTP ${spec.expectedStatus}, received ${check.statusCode}.`;
  } catch (error) {
    check.responseTimeMs = Math.max(0, Date.now() - startedAt);
    check.error = ERROR_HINTS[error.kind] || ERROR_HINTS.generic;
  }
  return { ok: true, check };
}

class CheckService {
  constructor() { this.controllers = new Set(); }

  async run(req, host) {
    if (this.controllers.size >= CHECK_CONCURRENCY) {
      throw inputError(429, 'CHECK_BUSY', 'Too many concurrent checks; try again shortly.');
    }
    const controller = new AbortController();
    this.controllers.add(controller);
    const abort = () => controller.abort();
    req.socket.once('close', abort);
    try { return await checkEndpoint(await readInput(req), host, controller.signal); }
    finally {
      req.socket.removeListener('close', abort);
      this.controllers.delete(controller);
    }
  }

  stop() { for (const controller of this.controllers) controller.abort(); }
}

module.exports = { CheckService, validateCheck, checkEndpoint, readInput, CHECK_CONCURRENCY, CHECK_TIMEOUT_MS, CHECK_BODY_BYTES, INPUT_BODY_BYTES };
