'use strict';

const https = require('node:https');
const { isIP } = require('node:net');

const MAX_ADDRESSES = 32;
const CACHE_LIMIT = 512;
const error = (status, code, message) => Object.assign(new Error(message), { status, code });
function normalizeIp(value) {
  if (typeof value !== 'string' || value.length > 45 || !isIP(value)) throw error(400, 'INVALID_ADDRESS', 'Use numeric IPv4 or IPv6 addresses only.');
  return isIP(value) === 6 ? new URL('http://[' + value + ']/').hostname.slice(1, -1) : value;
}
function publicIp(value) {
  const ip = normalizeIp(value);
  if (isIP(ip) === 4) {
    const [a,b,c] = ip.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
  }
  // ponytail: geolocate globally routed unicast only; add future IANA allocations when assigned.
  const first = parseInt(ip.split(':')[0], 16);
  return first >= 0x2000 && first <= 0x3fff && !/^2001:(?:[01]?[0-9a-f]{1,2}:|db8:|:)/.test(ip) && !ip.startsWith('2002:') && !/^3fff:/.test(ip);
}
function validateGeo(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 2 ||
      input.consent !== true || !Array.isArray(input.addresses) || input.addresses.length < 1 || input.addresses.length > MAX_ADDRESSES) {
    throw error(400, 'INVALID_GEO', 'Explicit consent:true and 1–32 numeric addresses are required.');
  }
  return [...new Set(input.addresses.map(normalizeIp))];
}
function lookup(ip, signal) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    const req = https.get('https://ipwho.is/' + encodeURIComponent(ip), { signal, headers: { Accept: 'application/json', 'User-Agent': 'PortScope/2.1' } }, res => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error('GeoIP provider HTTP ' + res.statusCode)); }
      res.on('data', chunk => { size += chunk.length; if (size > 32768) req.destroy(new Error('GeoIP response exceeded 32 KiB.')); else chunks.push(chunk); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Invalid GeoIP response.')); } });
      res.on('error', reject);
    });
    const timer = setTimeout(() => req.destroy(new Error('GeoIP provider timed out.')), 4000);
    req.once('close', () => clearTimeout(timer)); req.on('error', reject);
  });
}
const clean = value => typeof value === 'string' ? value.replace(/[\x00-\x1f\x7f]/g, '').slice(0, 160) || null : null;
class GeoService {
  constructor(options = {}) { this.lookup = options.lookup || lookup; this.cache = new Map(); this.active = 0; this.requests = []; this.controllers = new Set(); }
  async run(input, signal) {
    const ips = validateGeo(input);
    if (this.active >= 2) throw error(429, 'GEO_BUSY', 'Two GeoIP batches are already active.');
    const now = Date.now();
    this.requests = this.requests.filter(at => now - at < 3600000);
    const missing = ips.filter(ip => publicIp(ip) && (!this.cache.has(ip) || this.cache.get(ip).expires <= now));
    if (this.requests.length + missing.length > 128 || this.requests.filter(at => now - at < 60000).length + missing.length > 48) {
      throw error(429, 'GEO_RATE_LIMIT', 'GeoIP limit: 48 new addresses/minute, 128/hour. Cached results remain available.');
    }
    this.requests.push(...missing.map(() => now)); this.active++;
    const controller = new AbortController(); this.controllers.add(controller);
    const deadline = setTimeout(() => controller.abort(), 10000);
    const abort = () => controller.abort(); signal?.addEventListener('abort', abort, { once: true }); if (signal?.aborted) abort();
    const results = new Array(ips.length); let next = 0;
    try {
      const worker = async () => {
        while (next < ips.length) {
          const index = next++, ip = ips[index];
          if (controller.signal.aborted) throw error(499, 'CANCELLED', 'GeoIP lookup cancelled.');
          const blank = { ip, status: 'private', longitude: null, latitude: null, country: null, city: null, asn: null, organization: null, source: 'ipwho.is', lookedUpAt: new Date().toISOString(), error: null };
          if (!publicIp(ip)) { results[index] = blank; continue; }
          const cached = this.cache.get(ip);
          if (cached && cached.expires > Date.now()) { results[index] = cached.value; continue; }
          let value;
          try {
            const data = await this.lookup(ip, controller.signal);
            if (data.success !== true || normalizeIp(data.ip) !== ip || typeof data.longitude !== 'number' || !Number.isFinite(data.longitude) || Math.abs(data.longitude) > 180 ||
                typeof data.latitude !== 'number' || !Number.isFinite(data.latitude) || Math.abs(data.latitude) > 90) throw new Error('Provider supplied no valid coordinates for this IP.');
            value = { ...blank, status: 'located', longitude: data.longitude, latitude: data.latitude, country: clean(data.country), city: clean(data.city),
              asn: Number.isSafeInteger(data.connection?.asn) ? 'AS' + data.connection.asn : null, organization: clean(data.connection?.org) };
          } catch (cause) {
            if (controller.signal.aborted) throw error(499, 'CANCELLED', 'GeoIP lookup cancelled.');
            value = { ...blank, status: 'unavailable', error: clean(cause.message) || 'GeoIP unavailable.' };
          }
          this.cache.delete(ip); this.cache.set(ip, { value, expires: Date.now() + (value.status === 'located' ? 86400000 : 900000) });
          if (this.cache.size > CACHE_LIMIT) this.cache.delete(this.cache.keys().next().value);
          results[index] = value;
        }
      };
      await Promise.all([worker(), worker()]);
      return { ok: true, provider: 'ipwho.is', results };
    } finally { clearTimeout(deadline); signal?.removeEventListener('abort', abort); this.controllers.delete(controller); this.active--; }
  }
  close() { for (const controller of this.controllers) controller.abort(); }
}
module.exports = { GeoService, validateGeo, publicIp, normalizeIp };
