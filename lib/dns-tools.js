'use strict';

const dns = require('node:dns');
const { Resolver } = require('node:dns/promises');
const { isIP } = require('node:net');
const { domainToASCII } = require('node:url');
const { performance } = require('node:perf_hooks');

const DNS_TYPES = Object.freeze(['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR']);
const DNS_TIMEOUT_MS = 2000;
const DNS_DEADLINE_MS = 10000;
const DNS_MAX_REQUESTS = 4;
const DNS_MAX_QUERIES = 24;
const DNSSEC_CONTROL = 'cloudflare.com';
const DNSSEC_BOGUS = 'dnssec-failed.org';

function failure(status, code, message) {
  return Object.assign(new Error(message), { status, statusCode: status, code });
}

function numericServer(value) {
  if (typeof value !== 'string' || !value || value.length > 80 || /[^0-9a-fA-F:.\[\]]/.test(value)) {
    throw failure(400, 'INVALID_DNS_SERVER', 'Resolvers must be numeric IPv4/IPv6 addresses, optionally with a port.');
  }
  let host = value, port = 53;
  const bracketed = value.match(/^\[([^\]]+)\](?::([0-9]+))?$/);
  const ipv4Port = value.match(/^([^:]+):([0-9]+)$/);
  if (bracketed) { host = bracketed[1]; port = bracketed[2] === undefined ? 53 : Number(bracketed[2]); if (isIP(host) !== 6) host = ''; }
  else if (ipv4Port) { host = ipv4Port[1]; port = Number(ipv4Port[2]); if (isIP(host) !== 4) host = ''; }
  if (!isIP(host) || !Number.isInteger(port) || port < 1 || port > 65535) {
    throw failure(400, 'INVALID_DNS_SERVER', 'Use an IP address and a DNS port between 1 and 65535. Bracket IPv6 when adding a port.');
  }
  const family = isIP(host);
  host = family === 6 ? new URL('http://[' + host + ']/').hostname.slice(1, -1) : host;
  const mapped = family === 6 && host.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
  const firstByte = mapped ? parseInt(mapped[1], 16) >> 8 : family === 4 ? Number(host.split('.')[0]) : null;
  if (host === '::' || /^ff/i.test(host) || firstByte !== null && (firstByte === 0 || firstByte >= 224)) {
    throw failure(400, 'INVALID_DNS_SERVER', 'DNS resolvers must be unicast addresses, not unspecified, multicast or broadcast destinations.');
  }
  return port === 53 ? host : (family === 6 ? '[' + host + ']' : host) + ':' + port;
}

function hostname(value) {
  if (typeof value !== 'string' || !value || value.length > 253 || /[\s\x00-\x20\x7f/\\@?#%:]/.test(value) && !isIP(value)) {
    throw failure(400, 'INVALID_DNS_NAME', 'Supply a hostname or IP, without a URL, whitespace, credentials or shell syntax.');
  }
  if (isIP(value) && !value.includes('%')) return value.toLowerCase();
  if (/^[0-9.]+$/.test(value)) throw failure(400, 'INVALID_DNS_NAME', 'Numeric IP shorthand is not accepted; use a full IP address.');
  const ascii = domainToASCII(value.replace(/\.$/, ''));
  if (isIP(ascii)) throw failure(400, 'INVALID_DNS_NAME', 'Use a canonical numeric IP address rather than a hostname that normalizes into an IP.');
  if (!ascii || ascii.length > 253 || !ascii.split('.').every(label => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(label))) {
    throw failure(400, 'INVALID_DNS_NAME', 'Invalid hostname: DNS labels may contain letters, digits, underscores or interior hyphens (maximum 63 characters each).');
  }
  return ascii.toLowerCase();
}

function validateDns(input) {
  const fields = ['mode', 'name', 'types', 'servers'];
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some(key => !fields.includes(key)) || !['records', 'compare', 'dnssec', 'reverse'].includes(input.mode)) {
    throw failure(400, 'INVALID_DNS', 'Accepts only mode, name, types and servers; mode must be records, compare, dnssec or reverse.');
  }
  let servers = null;
  if (Object.hasOwn(input, 'servers')) {
    if (!Array.isArray(input.servers) || input.servers.length < 1 || input.servers.length > 3) throw failure(400, 'INVALID_DNS_SERVER', 'Supply one to three resolver addresses, or omit servers for configured resolvers.');
    servers = input.servers.map(numericServer);
    if (new Set(servers).size !== servers.length) throw failure(400, 'INVALID_DNS_SERVER', 'Resolver addresses must be distinct.');
  }
  if (input.mode === 'dnssec') {
    if (Object.hasOwn(input, 'name') || Object.hasOwn(input, 'types')) throw failure(400, 'INVALID_DNS', 'DNSSEC behavior checks use fixed control and bogus domains; omit name and types.');
    return { mode: input.mode, name: null, types: ['A'], servers };
  }
  const name = hostname(input.name);
  if (input.mode === 'reverse') {
    if (!isIP(name)) throw failure(400, 'INVALID_DNS_NAME', 'Reverse lookup requires a numeric IPv4 or IPv6 address.');
    if (Object.hasOwn(input, 'types') && (!Array.isArray(input.types) || input.types.length !== 1 || input.types[0] !== 'PTR')) throw failure(400, 'INVALID_DNS_TYPE', 'Reverse lookups accept only PTR.');
    return { mode: input.mode, name, types: ['PTR'], servers };
  }
  const types = Object.hasOwn(input, 'types') ? input.types : ['A', 'AAAA'];
  if (!Array.isArray(types) || !types.length || types.length > DNS_TYPES.length || types.some(type => !DNS_TYPES.includes(type)) || new Set(types).size !== types.length) {
    throw failure(400, 'INVALID_DNS_TYPE', 'Select distinct supported types: ' + DNS_TYPES.join(', ') + '.');
  }
  return { mode: input.mode, name, types: [...types], servers };
}

function reverseName(address) {
  if (isIP(address) === 4) return address.split('.').reverse().join('.') + '.in-addr.arpa';
  const embedded = address.match(/\d+\.\d+\.\d+\.\d+$/);
  if (embedded) {
    const bytes = embedded[0].split('.').map(Number);
    address = address.slice(0, embedded.index) + ((bytes[0] << 8) | bytes[1]).toString(16) + ':' + ((bytes[2] << 8) | bytes[3]).toString(16);
  }
  const parts = address.split('::');
  const left = parts[0].split(':').filter(Boolean), right = (parts[1] || '').split(':').filter(Boolean);
  const words = parts.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return words.map(word => word.padStart(4, '0')).join('').split('').reverse().join('.') + '.ip6.arpa';
}

function dnssecEvidence(tests) {
  const servers = [...new Set(tests.map(test => test.server))];
  if (tests.some(test => test.role === 'bogus' && test.status === 'answer')) return {
    status: 'not-validating',
    explanation: 'At least one resolver returned records for the deliberately bogus DNSSEC zone. Validation was not enforced for that query; local overrides or interception can also affect this result.',
    tests,
  };
  const consistent = servers.length > 0 && servers.every(server => {
    const control = tests.find(test => test.server === server && test.role === 'valid-control');
    const bogus = tests.find(test => test.server === server && test.role === 'bogus');
    return control?.status === 'answer' && bogus?.status === 'error' && bogus.error === 'ESERVFAIL';
  });
  return {
    status: consistent ? 'validating' : 'inconclusive',
    explanation: consistent
      ? 'Every tested resolver answered the signed control zone and returned SERVFAIL for the deliberately bogus zone. This behavior is consistent with DNSSEC validation, not cryptographic proof: policy, filtering or interception can produce the same outcome. Node does not expose DNSSEC signatures or the AD bit here.'
      : 'DNSSEC behavior is inconclusive. A successful control answer plus rejection of the known bogus zone is required per resolver. SERVFAIL alone, timeouts, NXDOMAIN and empty answers do not establish validation; Node does not independently validate signatures.',
    tests,
  };
}

class DnsService {
  constructor() { this.active = new Set(); this.closed = false; }

  config() { return { ok: true, servers: dns.getServers(), platform: process.platform, source: 'Node backend resolver' }; }

  async run(input, signal) {
    const spec = validateDns(input);
    if (this.closed) throw failure(503, 'DNS_CLOSED', 'DNS service is closed.');
    if (signal?.aborted) throw failure(499, 'DNS_ABORTED', 'DNS request was cancelled.');
    if (this.active.size >= DNS_MAX_REQUESTS) throw failure(429, 'DNS_BUSY', 'At most four DNS requests may run concurrently.');
    const configured = spec.servers || dns.getServers();
    const servers = configured.slice(0, 3).map(numericServer);
    if (!servers.length) throw failure(503, 'DNS_NO_SERVERS', 'No DNS resolvers are configured on the backend.');
    const count = servers.length * (spec.mode === 'dnssec' ? 2 : spec.types.length);
    if (count > DNS_MAX_QUERIES) throw failure(400, 'DNS_QUERY_LIMIT', 'This request exceeds 24 DNS queries. Select fewer record types or resolvers.');
    const controller = new AbortController();
    const onAbort = () => controller.abort(failure(499, 'DNS_ABORTED', 'DNS request was cancelled.'));
    signal?.addEventListener('abort', onAbort, { once: true });
    const timer = setTimeout(() => controller.abort(failure(504, 'DNS_DEADLINE', 'The DNS request exceeded its ten-second deadline.')), DNS_DEADLINE_MS);
    const resolvers = new Set();
    const cancelQueries = () => { for (const resolver of resolvers) resolver.cancel(); };
    controller.signal.addEventListener('abort', cancelQueries, { once: true });
    this.active.add(controller);
    const checkedAt = new Date().toISOString();
    try {
      const queries = servers.flatMap(server => spec.mode === 'dnssec'
        ? [{ server, name: DNSSEC_CONTROL, type: 'A', role: 'valid-control' }, { server, name: DNSSEC_BOGUS, type: 'A', role: 'bogus' }]
        : spec.types.map(type => ({ server, name: spec.name, type })));
      const results = new Array(queries.length);
      let cursor = 0;
      const worker = async () => {
        while (cursor < queries.length) {
          const index = cursor++, query = queries[index];
          const started = performance.now();
          let resolver, queryTimer, timedOut = false;
          let answers = [], error = null, status = 'answer';
          try {
            if (controller.signal.aborted) throw controller.signal.reason;
            resolver = new Resolver({ timeout: DNS_TIMEOUT_MS, tries: 1 });
            resolver.setServers([query.server]); resolvers.add(resolver);
            queryTimer = setTimeout(() => { timedOut = true; resolver.cancel(); }, DNS_TIMEOUT_MS);
            // Resolver.reverse() may consult the OS hosts file on Windows, bypassing the chosen resolver.
            const value = spec.mode === 'reverse' ? await resolver.resolvePtr(reverseName(query.name))
              : query.type === 'A' ? await resolver.resolve4(query.name, { ttl: true })
              : query.type === 'AAAA' ? await resolver.resolve6(query.name, { ttl: true })
              : await resolver.resolve(query.name, query.type);
            if (controller.signal.aborted) throw controller.signal.reason;
            answers = Array.isArray(value) ? value : value == null ? [] : [value];
            if (!answers.length) status = 'nodata';
          } catch (reason) {
            error = controller.signal.aborted ? controller.signal.reason.code : timedOut ? 'ETIMEOUT' : typeof reason?.code === 'string' ? reason.code.slice(0, 80) : 'DNS_ERROR';
            // NXDOMAIN is an error, not proof that the requested RRset is merely absent.
            status = error === 'ENODATA' ? 'nodata' : 'error';
          } finally { clearTimeout(queryTimer); if (resolver) resolvers.delete(resolver); }
          results[index] = { server: query.server, type: query.type, status, durationMs: Math.round((performance.now() - started) * 100) / 100, answers, error };
        }
      };
      await Promise.all(Array.from({ length: Math.min(4, queries.length) }, worker));
      if (controller.signal.aborted && controller.signal.reason.code !== 'DNS_DEADLINE') throw controller.signal.reason;
      const result = { ok: true, mode: spec.mode, name: spec.name, checkedAt, source: 'backend', results };
      if (!spec.servers && configured.length > 3) result.notice = 'Only the first three of ' + configured.length + ' configured backend resolvers were tested.';
      if (spec.mode === 'dnssec') result.dnssec = dnssecEvidence(results.map((result, index) => ({ ...result, name: queries[index].name, role: queries[index].role })));
      return result;
    } finally {
      clearTimeout(timer); signal?.removeEventListener('abort', onAbort);
      controller.signal.removeEventListener('abort', cancelQueries); cancelQueries(); this.active.delete(controller);
    }
  }

  close() {
    this.closed = true;
    for (const controller of this.active) controller.abort(failure(503, 'DNS_CLOSED', 'DNS service is closed.'));
  }
}

module.exports = { DnsService, validateDns, numericServer, reverseName, dnssecEvidence, DNS_TYPES, DNS_TIMEOUT_MS, DNS_DEADLINE_MS, DNS_MAX_REQUESTS, DNS_MAX_QUERIES, DNSSEC_CONTROL, DNSSEC_BOGUS };
