'use strict';

const os = require('node:os');
const { isIP } = require('node:net');
const { isLoopbackAddress, isWildcardAddress } = require('./classify');
const { runCommand, firstLine } = require('./util');

const MAX_CONNECTIONS = 2000;

function addressScope(address) {
  if (typeof address !== 'string') return 'unknown';
  const value = address.toLowerCase().replace(/%[^%]+$/, '');
  const family = isIP(value);
  if (!family || isWildcardAddress(value)) return 'unknown';
  if (isLoopbackAddress(value)) return 'loopback';
  if (family === 4) {
    const [a, b] = value.split('.').map(Number);
    if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
        (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return 'private';
    return a === 0 || a >= 224 ? 'unknown' : 'public';
  }
  const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(canonical);
  if (mapped) {
    const high = Number.parseInt(mapped[1], 16);
    const low = Number.parseInt(mapped[2], 16);
    return addressScope(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  const prefix = Number.parseInt(canonical.split(':')[0], 16);
  if ((prefix & 0xfe00) === 0xfc00 || (prefix & 0xffc0) === 0xfe80) return 'private';
  return (prefix & 0xff00) === 0xff00 ? 'unknown' : 'public';
}

// Unlike listener endpoints, remote wildcard and zero ports are legitimate.
function connectionEndpoint(token) {
  if (token === '*:*') return { address: null, port: null };
  const match = /^(?:\[([^\]]+)\]|(.+)):([0-9]+|\*)$/.exec(token || '');
  if (!match) return null;
  const address = (match[1] || match[2]).replace(/^\*$/, '0.0.0.0');
  if (!isIP(address)) return null;
  const port = match[3] === '*' ? null : Number(match[3]);
  if (port !== null && (!Number.isInteger(port) || port < 0 || port > 65535)) return null;
  return { address, port };
}

function connection(protocol, localToken, remoteToken, state, rawPid, processName = null) {
  const local = connectionEndpoint(localToken);
  const remote = connectionEndpoint(remoteToken);
  if (!local || !remote || !local.port) return null;
  const pid = /^\d+$/.test(String(rawPid)) ? Number(rawPid) : null;
  const peer = remote.address && !isWildcardAddress(remote.address) ? remote.address : local.address;
  return {
    id: `${protocol}|[${local.address}]:${local.port}|[${remote.address}]:${remote.port}|${pid}`,
    protocol, localAddress: local.address, localPort: local.port,
    remoteAddress: remote.address, remotePort: remote.port,
    state: state === 'ESTAB' ? 'ESTABLISHED' : state,
    pid: Number.isSafeInteger(pid) ? pid : null, processName, scope: addressScope(peer),
  };
}

function parseWindowsConnections(stdout) {
  const rows = [];
  const seen = new Set();
  for (const line of stdout.split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/);
    const protocol = tokens[0].toLowerCase();
    if (protocol !== 'tcp' && protocol !== 'udp') continue;
    if (tokens.length < (protocol === 'tcp' ? 5 : 4)) continue;
    const row = connection(protocol, tokens[1], tokens[2],
      protocol === 'tcp' ? tokens[3].toUpperCase() : 'UNCONN', tokens.at(-1));
    if (row && !seen.has(row.id)) { rows.push(row); seen.add(row.id); }

  }
  return rows;
}

function parseSsConnections(stdout) {
  const rows = [];
  const seen = new Set();
  for (const line of stdout.split(/\r?\n/)) {
    const tokens = line.trim().split(/\s+/);
    const protocol = tokens[0].toLowerCase();
    if ((protocol !== 'tcp' && protocol !== 'udp') || tokens.length < 6) continue;
    const pid = /pid=(\d+)/.exec(line)?.[1];
    const name = /users:\(\("([^"]+)"/.exec(line)?.[1] || null;
    const row = connection(protocol, tokens[4], tokens[5], tokens[1].toUpperCase(), pid, name);
    if (row && !seen.has(row.id)) { rows.push(row); seen.add(row.id); }

  }
  return rows;
}

async function scanUnixConnections() {
  // ponytail: ss supplies Linux sockets; unsupported hosts report degraded data, add lsof when needed.
  const result = await runCommand('ss', ['-H', '-t', '-u', '-n', '-a', '-p'], { timeoutMs: 15_000 });
  return result.ok
    ? { ok: true, connections: parseSsConnections(result.stdout), error: null }
    : { ok: false, connections: [], error: `Connection snapshot unavailable: ${result.error || firstLine(result.stderr) || 'ss unavailable'}` };
}

function networkSnapshot(result = {}) {
  let error = result.error || null;
  const interfaces = [];
  try {
    for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
      for (const item of addresses || []) interfaces.push({
        name, address: item.address, family: item.family === 4 ? 'IPv4' : item.family === 6 ? 'IPv6' : item.family,
        internal: item.internal, netmask: item.netmask, cidr: item.cidr || null, mac: item.mac,
      });
    }
  } catch (cause) { error = error || `Interface snapshot unavailable: ${cause.message}`; }
  const observed = result.ok ? result.connections || [] : [];
  const limited = observed.length > MAX_CONNECTIONS;
  // OS command output is already byte-bounded. Cap only after prioritizing live sockets.
  const priority = item => item.state === 'ESTABLISHED' ? 0 : ['LISTENING', 'LISTEN', 'UNCONN'].includes(item.state) ? 2 : ['TIME_WAIT', 'CLOSED', 'CLOSE'].includes(item.state) ? 3 : 1;
  const connections = (limited ? [...observed].sort((a, b) => priority(a) - priority(b)) : observed).slice(0, MAX_CONNECTIONS);
  const summary = { total: connections.length, established: 0, external: 0, loopback: 0, private: 0, states: {} };
  for (const item of connections) {
    summary.states[item.state] = (summary.states[item.state] || 0) + 1;
    if (item.state === 'ESTABLISHED') summary.established += 1;
    if (item.scope === 'loopback') summary.loopback += 1;
    if (item.scope === 'private') summary.private += 1;
    if (item.scope === 'private' || item.scope === 'public') summary.external += 1;
  }
  return { ok: Boolean(result.ok) && !error, scannedAt: result.scannedAt === undefined ? new Date().toISOString() : result.scannedAt,
    platform: process.platform, interfaces, connections, summary, error, limited, totalObserved: observed.length, limit: MAX_CONNECTIONS };
}

module.exports = { MAX_CONNECTIONS, addressScope, parseWindowsConnections, parseSsConnections, scanUnixConnections, networkSnapshot };
