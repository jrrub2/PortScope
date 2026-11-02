'use strict';

/**
 * Port classification, address helpers and URL shaping.
 *
 * Everything in this module is pure (no I/O) so the rules are easy to scan and
 * to test. docs/API-CONTRACT.md section 3 is the authoritative definition of
 * the category order: system -> dev -> app.
 */

const { isIP } = require('node:net');

/** Ports owned by Windows services (contract list, exact matches). */
const SYSTEM_PORTS = new Set([135, 139, 445, 2869, 5357, 5040, 7680, 2179, 54235]);

/** Windows RPC dynamic range listed by the contract. */
const SYSTEM_PORT_RANGES = [[49664, 49714]];

/**
 * Common dev-server ports. A listener on one of these is assumed to be a
 * developer tool even when the owning process is unknown.
 */
const DEV_PORTS = new Set([
  3000, 3001, 3002, 3333, 4000, 4200, 4321, 5000, 5001, 5173, 5174, 5500, 5555,
  6006, 7000, 8000, 8080, 8081, 8088, 8888, 9000, 9090, 1420, 1234, 19006, 24678,
]);

/**
 * Windows process names that belong to the operating system or to a service
 * host. Compared against the normalised name (lowercase, `.exe` stripped).
 * The contract explicitly allows "similar Windows service hosts", so the list
 * covers the standard Windows 10/11 service binaries as well.
 */
const SYSTEM_PROCESS_NAMES = new Set([
  'system',
  'system idle process',
  'idle',
  'secure system',
  'registry',
  'memory compression',
  'smss',
  'csrss',
  'wininit',
  'services',
  'lsass',
  'svchost',
  'winlogon',
  'spoolsv',
  'dwm',
  'fontdrvhost',
  'wmiprvse',
  'searchindexer',
  'searchprotocolhost',
  'searchfilterhost',
  'sgrmbroker',
  'mpdefendercoreservice',
  'msmpeng',
  'nissrv',
  'securityhealthservice',
  'securityhealthsystray',
  'smartscreen',
  'dllhost',
  'taskhostw',
  'sihost',
  'ctfmon',
  'audiodg',
  'explorer',
  'startmenuexperiencehost',
  'shellexperiencehost',
  'runtimebroker',
  'applicationframehost',
  'textinputhost',
  'lockapp',
  'useroobebroker',
  'systemsettings',
  'backgroundtaskhost',
  'conhost',
  'werfault',
  'msdtc',
  'vmtoolsd',
  'vmwaretools',
  'vboxservice',
  'spoolss',
  'sppsvc',
  'fontcache',
  'wlanext',
  'wudfhost',
  'ngciso',
  'lsm',
  'wslservice',
]);

/** Normalise a process name so `.exe` suffixes and casing stop mattering. */
function normalizeProcessName(name) {
  if (typeof name !== 'string') return '';
  const trimmed = name.trim().toLowerCase();
  return trimmed.endsWith('.exe') ? trimmed.slice(0, -4) : trimmed;
}

const DEV_PROCESS_PATTERNS = [
  /^node$/,
  /^python[\d.]*$/,
  /^pythonw[\d.]*$/,
  /^py$/,
  /^java[\w.-]*$/,
  /^javaw[\w.-]*$/,
  /^dotnet$/,
  /^go$/,
  /^php[\d.]*$/,
  /^ruby[\d.]*$/,
  /^cargo$/,
  /^rustc$/,
  /^deno$/,
  /^bun$/,
  /^electron$/,
  /^docker[\w.-]*$/,
  /^com\.docker[\w.-]*$/,
  /^wsl.*$/,
  /^code$/,
  /^code-insiders$/,
  /^idea\d*$/,
  /^webstorm\d*$/,
  /^pycharm\d*$/,
  /^goland\d*$/,
  /^rider\d*$/,
  /^clion\d*$/,
  /^postman$/,
  /^insomnia$/,
];

/** True when the normalised process name is a known OS/service host. */
function isSystemProcessName(processName) {
  const name = normalizeProcessName(processName);
  if (!name) return false;
  return SYSTEM_PROCESS_NAMES.has(name);
}

/** True when the normalised process name is a developer runtime/app. */
function isDevProcessName(processName) {
  const name = normalizeProcessName(processName);
  if (!name) return false;
  return DEV_PROCESS_PATTERNS.some((pattern) => pattern.test(name));
}

/** @param {number} port */
function isSystemPort(port) {
  if (SYSTEM_PORTS.has(port)) return true;
  return SYSTEM_PORT_RANGES.some(([min, max]) => port >= min && port <= max);
}

/**
 * Classify a port per the contract (first match wins):
 *   1. system - Windows System process, system service host, known service port
 *   2. dev    - developer runtime, common dev port, or an inferred framework
 *   3. app    - everything else
 *
 * @param {{port: number, pid?: number|null, processName?: string|null,
 *   framework?: string|null, platform?: string}} input
 * @returns {'dev'|'app'|'system'}
 */
function classifyPort(input) {
  const port = Number(input.port);
  const pid = input.pid ?? null;
  const platform = input.platform ?? process.platform;

  // `pid === 4` only means NT System on Windows; on Unix pid 4 is arbitrary.
  const isWindowsSystemPid = platform === 'win32' && (pid === 4 || pid === 0);
  if (isWindowsSystemPid || isSystemProcessName(input.processName) || isSystemPort(port)) {
    return 'system';
  }

  if (isDevProcessName(input.processName) || DEV_PORTS.has(port) || Boolean(input.framework)) {
    return 'dev';
  }

  return 'app';
}

// ---------------------------------------------------------------------------
// Network address helpers
// ---------------------------------------------------------------------------

/** @param {string} address */
function isLoopbackAddress(address) {
  if (typeof address !== 'string') return false;
  const value = address.toLowerCase();
  const family = isIP(value);
  if (family === 4) return value.startsWith('127.');
  if (family !== 6 || value.includes('%')) return false;
  // URL canonicalisation covers expanded IPv6 and hexadecimal IPv4-mapped forms.
  const canonical = new URL(`http://[${value}]/`).hostname;
  return canonical === '[::1]' || /^\[::ffff:7f[0-9a-f]{2}:[0-9a-f]{1,4}\]$/.test(canonical);
}

/** @param {string} address */
function isWildcardAddress(address) {
  if (typeof address !== 'string') return false;
  const value = address.trim().toLowerCase();
  return value === '0.0.0.0' || value === '::' || value === '*';
}

/**
 * Contract rule: only sockets reachable through loopback stay in the list.
 * That means loopback addresses (127.x, ::1) and wildcards (0.0.0.0, ::);
 * a socket bound to one specific LAN interface is intentionally excluded.
 * @param {string} address
 */
function isLoopbackReachable(address) {
  return isLoopbackAddress(address) || isWildcardAddress(address);
}

/** @param {string} address */
function addressFamily(address) {
  return typeof address === 'string' && address.includes(':') ? 6 : 4;
}

/**
 * Deterministic ordering for the `bindAddresses` array: IPv4 first, then the
 * plain string order. Keeps snapshots stable between scans.
 * @param {string} a
 * @param {string} b
 */
function compareAddresses(a, b) {
  const familyDiff = addressFamily(a) - addressFamily(b);
  if (familyDiff !== 0) return familyDiff;
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/**
 * Pick the host used for the HTTP probe.
 *
 * Prefer 127.0.0.1 when actually bound or covered by a wildcard, otherwise use
 * the observed numeric loopback literal. Never substitute .1 for a .2 bind.
 *
 * @param {string[]} bindAddresses
 * @returns {string}
 */
function probeHostFor(bindAddresses) {
  const addresses = Array.isArray(bindAddresses) ? bindAddresses : [];
  if (addresses.includes('127.0.0.1') || addresses.includes('0.0.0.0')) return '127.0.0.1';
  const loopbacks = addresses.filter(isLoopbackAddress).sort(compareAddresses);
  const ipv4 = loopbacks.find((address) => isIP(address) === 4);
  if (ipv4) return ipv4;
  if (addresses.includes('::')) return '::1';
  return loopbacks[0] || '127.0.0.1';
}

/**
 * Only loopback destinations may ever be contacted. Used to guard probes and
 * redirect following: PortScope promises that no request leaves the machine.
 * @param {string} host
 */
function isLoopbackHost(host) {
  if (typeof host !== 'string') return false;
  // Numeric only: even localhost DNS can be overridden by local resolver settings.
  const bracketed = host.startsWith('[') && host.endsWith(']');
  const value = bracketed ? host.slice(1, -1) : host;
  return (!bracketed || isIP(value) === 6) && isLoopbackAddress(value);
}

/** Build the user-facing URL for a probed port. */
function buildPortUrl(protocol, port) {
  if (protocol !== 'http' && protocol !== 'https') return null;
  return `${protocol}://localhost:${port}/`;
}

module.exports = {
  SYSTEM_PORTS,
  DEV_PORTS,
  classifyPort,
  isSystemProcessName,
  isDevProcessName,
  isSystemPort,
  normalizeProcessName,
  isLoopbackAddress,
  isWildcardAddress,
  isLoopbackReachable,
  isLoopbackHost,
  addressFamily,
  compareAddresses,
  probeHostFor,
  buildPortUrl,
};
