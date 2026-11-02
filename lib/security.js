'use strict';

const { isLoopbackAddress } = require('./classify');

// Parse the raw authority before URL normalisation can turn 127.1/hex into an IP.
function localAuthority(value, actualPort) {
  if (typeof value !== 'string') return null;
  const match = /^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::([0-9]{1,5}))?$/i.exec(value);
  if (!match) return null;
  const host = match[1].toLowerCase();
  const address = host.startsWith('[') ? host.slice(1, -1) : host;
  if (host.startsWith('[') && !address.includes(':')) return null;
  if (address !== 'localhost' && !isLoopbackAddress(address)) return null;
  const port = match[2] ? Number(match[2]) : 80;
  if (port !== actualPort || port < 1 || port > 65535) return null;
  return new URL(`http://${host}:${port}`).origin;
}

/** No proxies are trusted. Non-browser local clients may omit Origin/Fetch headers. */
function requestTrustError(req, actualPort, isApi) {
  for (const name of ['host', 'origin', 'sec-fetch-site', 'sec-fetch-dest']) {
    let count = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (req.rawHeaders[i].toLowerCase() === name) count += 1;
    }
    if (count > 1 || (name === 'host' && count !== 1)) return 'Duplicate or missing request authority.';
  }
  const authority = localAuthority(req.headers.host, actualPort);
  if (!authority) return 'Host must be localhost or a numeric loopback at this server port.';
  const origin = req.headers.origin;
  if (origin !== undefined) {
    if (typeof origin !== 'string' || !origin.startsWith('http://') ||
        localAuthority(origin.slice(7), actualPort) !== authority) {
      return 'Origin must match this server.';
    }
  }
  const site = req.headers['sec-fetch-site'];
  const dest = req.headers['sec-fetch-dest'];
  if (dest && /^(?:frame|iframe|object|embed)$/.test(dest)) return 'Framing is not allowed.';
  if (site && site !== 'same-origin' && site !== 'none') {
    // External top-level links may open the dashboard, never read or trigger APIs.
    if (isApi || req.headers['sec-fetch-mode'] !== 'navigate' || dest !== 'document') {
      return 'Cross-site requests are not allowed.';
    }
  }
  return null;
}

function setSecurityHeaders(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Referrer-Policy', 'no-referrer');
}

module.exports = { localAuthority, requestTrustError, setSecurityHeaders };
