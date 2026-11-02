'use strict';

/**
 * Static file serving for the self-contained dashboard in web/.
 *
 * Security notes:
 *   - the request path is percent-decoded exactly once and rejected when it
 *     contains a NUL byte or cannot be decoded;
 *   - backslashes are treated as separators (Windows), so `..\` is caught;
 *   - both the resolved path and its real path must stay inside web/, otherwise 403;
 *   - HTML is always served with `Cache-Control: no-store` so a developer
 *     never sees a stale dashboard after editing a file.
 */

const fs = require('node:fs/promises');
const path = require('node:path');

const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.webp': 'image/webp',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.txt': 'text/plain; charset=utf-8',
  '.xml': 'application/xml; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.wasm': 'application/wasm',
});

/** @param {string} filePath */
function mimeTypeFor(filePath) {
  return MIME_TYPES[path.extname(filePath).toLowerCase()] || 'application/octet-stream';
}

function sendText(res, status, message, extraHeaders = {}) {
  const payload = Buffer.from(message, 'utf8');
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': payload.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function isInside(root, file) {
  const relative = path.relative(root, file);
  return relative !== '..' && !relative.startsWith('..' + path.sep) && !path.isAbsolute(relative);
}

/**
 * Map a URL path to an absolute file path inside the web root.
 * @param {string} rootDir
 * @param {string} urlPath
 * @returns {{ok: true, file: string}|{ok: false, status: number, message: string}}
 */
function resolveStaticPath(rootDir, urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(String(urlPath || '/'));
  } catch {
    return { ok: false, status: 400, message: '400 — Permintaan tidak valid' };
  }

  if (decoded.includes('\u0000')) {
    return { ok: false, status: 400, message: '400 — Permintaan tidak valid' };
  }

  // Windows treats `\` as a separator too; normalise before resolving so
  // encoded traversal (`..%5c`) cannot slip through.
  let relative = decoded.replace(/\\/g, '/');
  if (relative === '/' || relative === '') relative = '/index.html';

  const root = path.resolve(rootDir);
  const resolved = path.resolve(root, relative.replace(/^\/+/, ''));

  if (!isInside(root, resolved)) {
    return { ok: false, status: 403, message: '403 — Akses ditolak' };
  }

  return { ok: true, file: resolved };
}

/**
 * Serve one static file (GET/HEAD).
 * @param {import('node:http').IncomingMessage} req
 * @param {import('node:http').ServerResponse} res
 * @param {string} rootDir absolute web/ directory
 * @param {string} urlPath pathname from the request URL
 */
async function serveStatic(req, res, rootDir, urlPath) {
  const resolved = resolveStaticPath(rootDir, urlPath);
  if (!resolved.ok) {
    sendText(res, resolved.status, resolved.message);
    return;
  }

  let stat, file;
  try {
    const root = await fs.realpath(rootDir);
    file = await fs.realpath(resolved.file);
    if (!isInside(root, file)) {
      sendText(res, 403, '403 — Akses ditolak');
      return;
    }
    stat = await fs.stat(file);
  } catch {
    const isDashboardEntry = urlPath === '/' || urlPath === '/index.html';
    const message = isDashboardEntry
      ? '404 — Frontend belum tersedia (folder web/ kosong atau index.html belum ada).'
      : '404 — Halaman tidak ditemukan';
    sendText(res, 404, message);
    return;
  }

  if (!stat.isFile()) {
    sendText(res, 404, '404 — Halaman tidak ditemukan');
    return;
  }

  let body;
  try {
    body = await fs.readFile(file);
  } catch {
    sendText(res, 500, '500 — Gagal membaca berkas');
    return;
  }

  const isHtml = path.extname(resolved.file).toLowerCase() === '.html';
  res.writeHead(200, {
    'Content-Type': mimeTypeFor(resolved.file),
    'Content-Length': body.length,
    // Never serve stale HTML in dev; other assets may be revalidated cheaply.
    'Cache-Control': isHtml ? 'no-store' : 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Last-Modified': stat.mtime.toUTCString(),
  });

  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  res.end(body);
}

module.exports = {
  MIME_TYPES,
  mimeTypeFor,
  resolveStaticPath,
  serveStatic,
  sendText,
};
