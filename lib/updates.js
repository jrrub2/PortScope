'use strict';

const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { createHash } = require('node:crypto');

const REPOSITORY = 'jrrub2/PortScope';
const RELEASE_URL = 'https://github.com/' + REPOSITORY + '/releases';
const API_URL = 'https://api.github.com/repos/' + REPOSITORY + '/releases?per_page=20';
const MAX_ARCHIVE = 150 * 1024 * 1024;
const failure = (status, code, message) => Object.assign(new Error(message), { status, statusCode: status, code });
const aborted = () => failure(499, 'UPDATE_ABORTED', 'Update request cancelled.');
const assertActive = signal => { if (signal?.aborted) throw aborted(); };

function versionParts(value) {
  if (typeof value !== 'string' || value.length > 50 || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(value)) return null;
  const parts = value.split('.').map(Number);
  return parts.every(Number.isSafeInteger) ? parts : null;
}
function compareVersions(a, b) {
  const left = versionParts(a), right = versionParts(b);
  if (!left || !right) throw failure(400, 'INVALID_UPDATE', 'Use a canonical numeric X.Y.Z version.');
  for (let i = 0; i < 3; i++) if (left[i] !== right[i]) return left[i] > right[i] ? 1 : -1;
  return 0;
}
function exact(input, fields) {
  return input && typeof input === 'object' && !Array.isArray(input) &&
    [Object.prototype, null].includes(Object.getPrototypeOf(input)) &&
    Object.keys(input).length === fields.length && fields.every(field => Object.hasOwn(input, field));
}
function latestRelease(body, currentVersion) {
  if (!Array.isArray(body) || body.length > 20) throw failure(502, 'UPDATE_METADATA', 'GitHub returned an invalid or oversized release list.');
  let latest = null;
  for (const release of body) {
    if (!release || typeof release !== 'object' || Array.isArray(release)) throw failure(502, 'UPDATE_METADATA', 'GitHub returned malformed release metadata.');
    if (release.draft !== false || typeof release.tag_name !== 'string' || !release.tag_name.startsWith('v') || !versionParts(release.tag_name.slice(1))) continue;
    if (typeof release.prerelease !== 'boolean' || typeof release.published_at !== 'string' || release.published_at.length > 40 || !/^\d{4}-\d{2}-\d{2}T/.test(release.published_at) || !Number.isFinite(Date.parse(release.published_at)) ||
        release.html_url !== RELEASE_URL + '/tag/' + release.tag_name || !Array.isArray(release.assets) || release.assets.length > 100) {
      throw failure(502, 'UPDATE_METADATA', 'GitHub returned malformed public release metadata.');
    }
    const version = release.tag_name.slice(1), archive = 'PortScope-' + version + '-windows-x64.zip';
    const assets = release.assets.filter(asset => asset && asset.name === archive);
    const asset = assets.length === 1 ? assets[0] : null;
    const downloadUrl = RELEASE_URL + '/download/' + release.tag_name + '/' + archive;
    const valid = asset && asset.state === 'uploaded' && Number.isSafeInteger(asset.size) && asset.size > 0 && asset.size <= MAX_ARCHIVE &&
      typeof asset.digest === 'string' && /^sha256:[a-f0-9]{64}$/.test(asset.digest) && asset.browser_download_url === downloadUrl;
    const candidate = { version, tag: release.tag_name, name: typeof release.name === 'string' && release.name.length <= 200 ? release.name : release.tag_name,
      url: release.html_url, publishedAt: release.published_at, prerelease: release.prerelease, available: compareVersions(version, currentVersion) > 0,
      downloadUrl: valid ? downloadUrl : null, size: valid ? asset.size : null, sha256: valid ? asset.digest.slice(7) : null };
    if (!latest || compareVersions(version, latest.version) > 0) latest = candidate;
    else if (version === latest.version) throw failure(502, 'UPDATE_METADATA', 'GitHub returned duplicate canonical release versions.');
  }
  return latest;
}
function redirectUrl(location, from) {
  let url;
  try { url = new URL(location, from); } catch { throw failure(502, 'UPDATE_REDIRECT', 'GitHub returned an invalid download redirect.'); }
  if (typeof location !== 'string' || location.length > 16384 || url.protocol !== 'https:' || url.username || url.password || url.port || url.hash ||
      !['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(url.hostname)) {
    throw failure(502, 'UPDATE_REDIRECT', 'Update redirects must remain on allowed credentialless HTTPS GitHub download hosts.');
  }
  return url.href;
}
async function deadline(signal, ms, action) {
  assertActive(signal);
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, ms);
  timer.unref?.();
  try { return await action(controller.signal); }
  catch (error) {
    if (controller.signal.aborted) throw timedOut ? failure(504, 'UPDATE_TIMEOUT', 'The GitHub update request timed out.') : aborted();
    if (error.code?.startsWith('UPDATE_')) throw error;
    throw failure(502, 'UPDATE_NETWORK', 'Unable to retrieve the update from GitHub. Check connectivity and retry.');
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); }
}
function response(url, signal, metadata) {
  assertActive(signal);
  return new Promise((resolve, reject) => {
    const request = https.get(url, { signal, agent: false, maxHeaderSize: 16384, headers: {
      Accept: metadata ? 'application/vnd.github+json' : 'application/octet-stream', 'Accept-Encoding': 'identity',
      'User-Agent': 'PortScope-update', ...(metadata ? { 'X-GitHub-Api-Version': '2022-11-28' } : {}),
    } }, res => { res.on('error', () => {}); resolve(res); });
    request.on('error', reject);
  });
}
function checkResponse(res, limit, metadata) {
  if (res.statusCode !== 200) {
    const limited = res.statusCode === 429 || res.statusCode === 403 && res.headers['x-ratelimit-remaining'] === '0';
    res.destroy();
    throw failure(limited ? 429 : 502, limited ? 'UPDATE_RATE_LIMIT' : metadata ? 'UPDATE_METADATA' : 'UPDATE_DOWNLOAD',
      limited ? 'GitHub rate limit reached. Wait before checking again.' : 'GitHub rejected the update request (HTTP ' + res.statusCode + ').');
  }
  const length = res.headers['content-length'], encoding = res.headers['content-encoding'];
  if (encoding && encoding !== 'identity' || length !== undefined && (typeof length !== 'string' || !/^[0-9]+$/.test(length) || !Number.isSafeInteger(Number(length)) || Number(length) > limit)) {
    res.destroy(); throw failure(502, metadata ? 'UPDATE_METADATA' : 'UPDATE_DOWNLOAD', 'GitHub returned an oversized or encoded update response.');
  }
}
async function fetchLatest(currentVersion, signal) {
  return deadline(signal, 15000, async bounded => {
    const res = await response(API_URL, bounded, true);
    checkResponse(res, 1024 * 1024, true);
    const chunks = []; let size = 0;
    try {
      for await (const chunk of res) {
        assertActive(bounded); size += chunk.length;
        if (size > 1024 * 1024) throw failure(502, 'UPDATE_METADATA', 'GitHub release metadata exceeded 1 MiB.');
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw failure(502, 'UPDATE_METADATA', 'GitHub did not return valid release JSON.'); }
      return latestRelease(body, currentVersion);
    } finally { res.destroy(); }
  });
}

function samePath(a, b) { return a.toLowerCase() === b.toLowerCase(); }
function absent(file) {
  try { fs.lstatSync(file); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; }
}
function safeDirectory(directory) {
  for (let at = directory; ; at = path.dirname(at)) {
    const stat = fs.lstatSync(at);
    if (!stat.isDirectory() || stat.isSymbolicLink() || !samePath(fs.realpathSync.native(at), at) || !absent(path.join(at, '.git'))) return false;
    if (at === path.parse(at).root) return true;
  }
}
function portableLayout(appDir, env) {
  try {
    if (process.platform !== 'win32' || process.arch !== 'x64' || env.PORTSCOPE_UPDATE_PROTOCOL !== '1') return null;
    const root = env.PORTSCOPE_PORTABLE_ROOT, stage = env.PORTSCOPE_UPDATE_DIR;
    if (typeof root !== 'string' || typeof stage !== 'string' || !/^[A-Za-z]:\\/.test(root) || root.includes(':', 2) || root.includes('\0') ||
        path.normalize(root) !== root || !samePath(fs.realpathSync.native(root), root) || !safeDirectory(root)) return null;
    const parent = path.join(root, '.portscope-update');
    if (path.dirname(stage) !== parent || !/^[a-f0-9]{32}$/.test(path.basename(stage)) || stage !== path.join(parent, path.basename(stage))) return null;
    if (!samePath(appDir, path.join(root, 'app')) || !samePath(process.execPath, path.join(root, 'runtime', 'node.exe')) ||
        !safeDirectory(appDir) || !safeDirectory(path.join(root, 'runtime'))) return null;
    // The native capability issuer additionally rejects every Windows ReparsePoint attribute, including non-symlink tags unavailable to Node stdlib.
    for (const file of [process.execPath, path.join(root, 'PortScope.exe')]) {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || !samePath(fs.realpathSync.native(file), file)) return null;
    }
    if (!absent(parent) && !safeDirectory(parent)) return null;
    return { root, parent, stage };
  } catch { return null; }
}
function sameEntry(a, b) { return a.dev === b.dev && a.ino === b.ino && !b.isSymbolicLink(); }
async function ownedFile(stage, name) {
  if (!sameEntry(stage.stat, await fs.promises.lstat(stage.directory, { bigint: true }))) throw failure(409, 'UPDATE_STAGE_CHANGED', 'The update staging directory changed. Restart PortScope before retrying.');
  const handle = await fs.promises.open(path.join(stage.directory, name), 'wx', 0o600);
  stage.files.set(name, await handle.stat({ bigint: true }));
  return handle;
}
async function cleanup(stage) {
  try {
    if (!sameEntry(stage.stat, await fs.promises.lstat(stage.directory, { bigint: true }))) return false;
    for (const [name, original] of stage.files) {
      const file = path.join(stage.directory, name);
      if (absent(file)) continue;
      if (!sameEntry(original, await fs.promises.lstat(file, { bigint: true }))) return false;
      await fs.promises.unlink(file);
    }
    await fs.promises.rmdir(stage.directory);
    return true;
  } catch { return false; }
}
async function download(update, stage, signal) {
  return deadline(signal, 120000, async bounded => {
    let url = update.downloadUrl, res;
    for (let redirects = 0; ; redirects++) {
      res = await response(url, bounded, false);
      if (![301, 302, 303, 307, 308].includes(res.statusCode)) break;
      const location = res.headers.location; res.destroy();
      if (redirects >= 3) throw failure(502, 'UPDATE_REDIRECT', 'GitHub exceeded the three-redirect update limit.');
      url = redirectUrl(location, url);
    }
    checkResponse(res, update.size, false);
    if (res.headers['content-length'] !== undefined && Number(res.headers['content-length']) !== update.size) {
      res.destroy(); throw failure(502, 'UPDATE_INTEGRITY', 'The update archive size no longer matches GitHub metadata.');
    }
    let handle;
    try {
      handle = await ownedFile(stage, 'package.zip');
      let size = 0; const hash = createHash('sha256');
      for await (const chunk of res) {
        assertActive(bounded); size += chunk.length;
        if (size > update.size || size > MAX_ARCHIVE) throw failure(502, 'UPDATE_INTEGRITY', 'The update archive exceeded its verified size.');
        hash.update(chunk); await handle.writeFile(chunk);
      }
      assertActive(bounded);
      if (size !== update.size || hash.digest('hex') !== update.sha256) throw failure(502, 'UPDATE_INTEGRITY', 'The downloaded archive failed SHA-256 or size verification. No update was installed.');
      await handle.sync();
    } catch (error) {
      if (['ENOSPC', 'EDQUOT', 'EACCES', 'EPERM', 'EROFS', 'EMFILE', 'ENFILE', 'EIO', 'EEXIST'].includes(error.code)) throw failure(500, 'UPDATE_STORAGE', 'Unable to write the private update archive. Check free space and folder permissions.');
      throw error;
    } finally { res.destroy(); await handle?.close(); }
  });
}
async function waitFor(promise, signal) {
  assertActive(signal);
  if (!signal) return promise;
  let cancel;
  const cancelled = new Promise((_resolve, reject) => { cancel = () => reject(aborted()); signal.addEventListener('abort', cancel, { once: true }); });
  try { return await Promise.race([promise, cancelled]); } finally { signal.removeEventListener('abort', cancel); }
}

class UpdateService {
  constructor({ version, appDir }) {
    if (!versionParts(version) || typeof appDir !== 'string' || !path.isAbsolute(appDir)) throw failure(400, 'INVALID_UPDATE', 'Updater requires the application version and absolute directory.');
    this.version = version; this.appDir = path.resolve(appDir);
    this.env = { PORTSCOPE_PORTABLE_ROOT: process.env.PORTSCOPE_PORTABLE_ROOT, PORTSCOPE_UPDATE_DIR: process.env.PORTSCOPE_UPDATE_DIR, PORTSCOPE_UPDATE_PROTOCOL: process.env.PORTSCOPE_UPDATE_PROTOCOL, PORTSCOPE_UPDATE_HEALTH_NONCE: process.env.PORTSCOPE_UPDATE_HEALTH_NONCE };
    this.cache = null; this.flight = null; this.busy = false; this.staged = false;
  }
  status() { return { ok: true, currentVersion: this.version, portable: Boolean(portableLayout(this.appDir, this.env)), repository: REPOSITORY, releaseUrl: RELEASE_URL }; }
  async committed(port) {
    const layout = portableLayout(this.appDir, this.env), nonce = this.env.PORTSCOPE_UPDATE_HEALTH_NONCE;
    if (!layout || !/^[a-f0-9]{32}$/.test(nonce || '')) return false;
    let handle;
    try {
      const directory = path.join(layout.parent, nonce), file = path.join(directory, 'result.json');
      if (!safeDirectory(directory)) return false;
      const before = await fs.promises.lstat(file, { bigint: true });
      if (!before.isFile() || before.isSymbolicLink() || before.size > 4096n || !samePath(await fs.promises.realpath(file), file)) return false;
      handle = await fs.promises.open(file, 'r');
      if (!sameEntry(before, await handle.stat({ bigint: true }))) return false;
      const bytes = Buffer.alloc(4097), { bytesRead } = await handle.read(bytes, 0, bytes.length, 0);
      if (bytesRead > 4096) return false;
      const result = JSON.parse(bytes.subarray(0, bytesRead).toString('utf8'));
      return exact(result, ['ok', 'version', 'port', 'status']) && result.ok === true && result.status === 'updated' && result.version === this.version && result.port === port;
    } catch { return false; }
    finally { await handle?.close().catch(() => {}); }
  }
  async check(input, signal) {
    if (!exact(input, [])) throw failure(400, 'INVALID_UPDATE', 'Update checks accept exactly {}.');
    assertActive(signal);
    if (this.cache && this.cache.until > Date.now()) {
      if (this.cache.error) throw failure(this.cache.error.status, this.cache.error.code, this.cache.error.message);
      return { ...this.status(), update: this.cache.update && { ...this.cache.update } };
    }
    let flight = this.flight;
    if (!flight || flight.controller.signal.aborted) {
      flight = { controller: new AbortController(), waiters: 0 };
      this.flight = flight;
      flight.promise = fetchLatest(this.version, flight.controller.signal).then(update => { this.cache = { until: Date.now() + 30000, update }; return update; })
        .catch(error => {
          if (error.code !== 'UPDATE_ABORTED') this.cache = { until: Date.now() + 30000, error: { status: error.status, code: error.code, message: error.message } };
          throw error;
        }).finally(() => { if (this.flight === flight) this.flight = null; });
    }
    flight.waiters++;
    try { const update = await waitFor(flight.promise, signal); return { ...this.status(), update: update && { ...update } }; }
    finally { if (--flight.waiters === 0 && this.flight === flight) flight.controller.abort(); }
  }
  async prepare(input, signal) {
    if (!exact(input, ['version', 'confirm']) || !versionParts(input.version) || input.confirm !== true) throw failure(400, 'INVALID_UPDATE', 'Confirm exactly {version:"X.Y.Z",confirm:true}; URLs, paths and hashes are never accepted.');
    let layout = portableLayout(this.appDir, this.env);
    if (!layout) throw failure(501, 'UPDATE_UNSUPPORTED', 'In-app updates require the new Windows x64 portable launcher. Source checkouts and older launchers must update manually.');
    assertActive(signal);
    if (this.busy || this.staged) throw failure(409, 'UPDATE_BUSY', 'An update is already being prepared or is staged for the launcher.');
    this.busy = true;
    let stage;
    try {
      const update = await fetchLatest(this.version, signal);
      if (!update || !update.available || update.version !== input.version) throw failure(409, 'UPDATE_CHANGED', 'The newest GitHub release changed or is not newer. Check again before confirming.');
      if (!update.downloadUrl) throw failure(502, 'UPDATE_ASSET_UNAVAILABLE', 'The release does not provide the exact Windows x64 ZIP with GitHub SHA-256 digest and bounded size. Use its GitHub release page.');
      assertActive(signal);
      layout = portableLayout(this.appDir, this.env);
      if (!layout) throw failure(409, 'UPDATE_LAYOUT_CHANGED', 'The portable installation changed before staging. No update was installed.');
      try { await fs.promises.mkdir(layout.parent, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
      if (!safeDirectory(layout.parent)) throw failure(409, 'UPDATE_LAYOUT_CHANGED', 'The update parent directory is not canonical and safe.');
      try { await fs.promises.mkdir(layout.stage, { mode: 0o700 }); }
      catch (error) { if (error.code === 'EEXIST') throw failure(409, 'UPDATE_STAGE_EXISTS', 'This launcher staging path already exists. Restart PortScope for a fresh staging capability.'); throw error; }
      stage = { directory: layout.stage, stat: await fs.promises.lstat(layout.stage, { bigint: true }), files: new Map() };
      if (!safeDirectory(stage.directory)) throw failure(409, 'UPDATE_STAGE_CHANGED', 'The new staging directory is not canonical and safe.');
      await download(update, stage, signal);
      assertActive(signal);
      if (!portableLayout(this.appDir, this.env)) throw failure(409, 'UPDATE_LAYOUT_CHANGED', 'The portable installation changed during staging.');
      const handle = await ownedFile(stage, 'request.json');
      try { await handle.writeFile(JSON.stringify({ version: update.version, sha256: update.sha256, size: update.size, archive: 'package.zip' }) + '\n', 'utf8'); await handle.sync(); }
      finally { await handle.close(); }
      assertActive(signal);
      this.staged = true;
      return { ok: true, version: update.version, status: 'staged' };
    } catch (error) {
      if (stage && !await cleanup(stage)) throw failure(500, 'UPDATE_CLEANUP', 'Partial staging could not be safely removed. No update was installed; restart PortScope before retrying.');
      if (error.code?.startsWith('UPDATE_')) throw error;
      throw failure(500, 'UPDATE_STORAGE', 'Unable to create the private update staging files. Check free space and folder permissions.');
    } finally { this.busy = false; }
  }
}

function selfCheck() {
  const assert = require('node:assert/strict');
  assert(compareVersions('2.10.0', '2.9.9') > 0);
  for (const value of ['v2.2.1', '02.2.1', '2.2', '2.2.1-beta', '2.2.9007199254740992', '../2.2.1']) assert.equal(versionParts(value), null);
  const digest = 'a'.repeat(64), version = '2.3.0', tag = 'v' + version;
  const release = { tag_name: tag, draft: false, prerelease: true, name: 'Preview', html_url: RELEASE_URL + '/tag/' + tag, published_at: '2026-01-01T00:00:00Z', assets: [{ name: 'PortScope-' + version + '-windows-x64.zip', state: 'uploaded', size: 42, digest: 'sha256:' + digest, browser_download_url: RELEASE_URL + '/download/' + tag + '/PortScope-' + version + '-windows-x64.zip' }] };
  assert.equal(latestRelease([release], '2.2.1').sha256, digest);
  assert.equal(latestRelease([release], '2.2.1').prerelease, true);
  assert.equal(latestRelease([{ ...release, assets: [] }], '2.2.1').downloadUrl, null);
  assert.equal(latestRelease([{ ...release, draft: true }], '2.2.1'), null);
  assert.throws(() => latestRelease(Array(21).fill(release), '2.2.1'), { code: 'UPDATE_METADATA' });
  for (const url of ['http://github.com/a', 'https://evil.test/a', 'https://github.com.evil.test/a', 'https://user:pass@github.com/a', 'https://github.com:444/a']) assert.throws(() => redirectUrl(url, RELEASE_URL), { code: 'UPDATE_REDIRECT' });
  assert.match(redirectUrl('https://release-assets.githubusercontent.com/asset?sig=one', RELEASE_URL), /^https:/);
  assert(exact({}, []) && !exact({ url: RELEASE_URL }, []));
  return 'Updater version, release, digest and redirect self-checks passed; no network, writes or install performed.';
}
module.exports = { UpdateService, selfCheck };
if (require.main === module) {
  if (process.argv.length === 3 && process.argv[2] === '--self-check') console.log(selfCheck());
  else { console.error('Usage: node lib/updates.js --self-check'); process.exitCode = 1; }
}
