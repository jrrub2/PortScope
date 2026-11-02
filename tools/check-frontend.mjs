// Pure feature checks: no browser, server, network, or new test framework.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';
const require = createRequire(import.meta.url);
const modules = new Map(), storage = new Map(), document = { documentElement: { lang: 'en' } };
function load(name) {
  if (modules.has(name)) return modules.get(name);
  const path = 'frontend/src/' + name;
  const source = fs.readFileSync(path, 'utf8');
  assert(!source.includes('\0'), path + ' must be text without NUL bytes');
  const module = { exports: {} };
  const isolatedRequire = spec => spec === '@/lib/i18n' ? load('lib/i18n.ts') : spec === './legacy-i18n.js' ? load('lib/legacy-i18n.js') : spec === './ui-translations' ? load('lib/ui-translations.ts') : spec.startsWith('@/') ? {} : require(spec);
  const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  vm.runInNewContext(output, { module, exports: module.exports, require: isolatedRequire, URL, TextEncoder, console, crypto: globalThis.crypto, document, window: { localStorage: { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value) } } }, { filename: path });
  modules.set(name, module.exports);
  return module.exports;
}
for (const [file, name] of [['features/snapshots.tsx', 'snapshotSelfCheck'], ['features/health.tsx', 'healthSelfCheck'], ['features/atlas.tsx', 'atlasSelfCheck'], ['features/diagnostics.tsx', 'diagnosticsSelfCheck'], ['features/dns-tools.tsx', 'dnsToolsSelfCheck'], ['features/browser-dns.tsx', 'browserDnsSelfCheck']]) console.log(load(file)[name]());
const controlSource = ts.transpileModule(fs.readFileSync('frontend/src/lib/control.ts', 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
const capability = new Map(), listeners = new Map(), controlLocation = { hash: '#overview?control=' + 'a'.repeat(64), pathname: '/', search: '' };
const control = { exports: {} };
vm.runInNewContext(controlSource, { exports: control.exports, URLSearchParams, location: controlLocation, sessionStorage: { getItem: key => capability.get(key), setItem: (key, value) => capability.set(key, value) }, history: { replaceState: (_a, _b, url) => { controlLocation.hash = url.slice(url.indexOf('#')); } }, window: { addEventListener: (event, handler) => listeners.set(event, handler) } });
assert.equal(control.exports.controlHeaders()['X-PortScope-Control'], 'a'.repeat(64));
assert.equal(controlLocation.hash, '#overview');
controlLocation.hash = '#settings?control=' + 'b'.repeat(64); listeners.get('hashchange')();
assert.equal(control.exports.controlHeaders()['X-PortScope-Control'], 'b'.repeat(64));
assert.equal(controlLocation.hash, '#settings');
capability.set('portscope.control', 'invalid'); assert.equal(Object.keys(control.exports.controlHeaders()).length, 0);
console.log('Private control fragment, renewal, stripping and header checks passed');
const { readUpdateStatus } = load('components/updates.tsx');
const releaseStatus = { ok: true, currentVersion: '2.2.1', portable: false, repository: 'jrrub2/PortScope', releaseUrl: 'https://github.com/jrrub2/PortScope/releases' };
assert.equal(readUpdateStatus(releaseStatus).portable, false);
const release = { version: '2.2.2', url: releaseStatus.releaseUrl + '/tag/v2.2.2', prerelease: true, available: true, downloadUrl: releaseStatus.releaseUrl + '/download/v2.2.2/PortScope-2.2.2-windows-x64.zip', size: 36000000, sha256: 'a'.repeat(64) };
assert.equal(readUpdateStatus({ ...releaseStatus, update: release }).update.version, '2.2.2');
for (const patch of [{ url: 'https://evil.test/update' }, { version: 'bad' }, { size: -1 }, { size: 151 * 1024 * 1024 }, { sha256: 'bad' }, { downloadUrl: 'http://github.com/download.zip' }, { prerelease: 'false' }]) assert.throws(() => readUpdateStatus({ ...releaseStatus, update: { ...release, ...patch } }));
for (const invalid of [null, {}, { ...releaseStatus, repository: 'other/repo' }, { ...releaseStatus, releaseUrl: 'https://evil.test' }]) assert.throws(() => readUpdateStatus(invalid));
console.log('Fixed-repository update status and release link validation checks passed');
const { observedLatency } = load('features/insights.tsx');
const empty = observedLatency([]);
assert.equal(empty.p95, null);
const measured = observedLatency([0, 10, 20, 30, NaN, -1]);
assert.equal(measured.p95, 30);
assert.equal(measured.average, 15);
const { toCsv } = load('lib/utils.ts');
assert.equal(toCsv([[' =1', 'a"b', '@evil']]), '\"\' =1\",\"a\"\"b\",\"\'@evil\"');
console.log('Latency sample statistics and formula-safe export checks passed');

const i18n = load('lib/i18n.ts'), legacy = load('lib/legacy-i18n.js'), { UI_TRANSLATIONS } = load('lib/ui-translations.ts');
assert.deepEqual(Array.from(i18n.LOCALES), ['en', 'id', 'es', 'ja', 'zh']);
assert.equal(i18n.LANGUAGES.length, 5);
const coreCopy = new Map(), routeKeys = [];
for (const name of ['App.tsx', 'components/port-detail.tsx', 'components/updates.tsx']) {
  const source = ts.createSourceFile(name, fs.readFileSync('frontend/src/' + name, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  function visit(node) {
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'l' && node.arguments.length === 2 && node.arguments.every(ts.isStringLiteral)) coreCopy.set(node.arguments[0].text, node.arguments[1].text);
    if (ts.isObjectLiteralExpression(node)) {
      const values = new Map(node.properties.filter(ts.isPropertyAssignment).map(property => [property.name.getText(source), property.initializer]));
      if (ts.isStringLiteral(values.get('en') ?? {}) && ts.isStringLiteral(values.get('idLabel') ?? {})) {
        if (ts.isStringLiteral(values.get('key') ?? {})) routeKeys.push(values.get('key').text);
        else coreCopy.set(values.get('en').text, values.get('idLabel').text);
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
}
assert(coreCopy.size > 150, 'Check actual current core controls and dynamic route titles');
for (const locale of i18n.LOCALES) {
  i18n.setLocale(locale);
  assert.equal(i18n.getLocale(), locale);
  assert.equal(storage.get('portscope.lang'), locale);
  assert.equal(document.documentElement.lang, locale);
  assert.equal(i18n.t('dialog.title', { port: 47123 }), legacy.t('dialog.title', { port: 47123 }));
  assert(i18n.t('dialog.title', { port: 47123 }).includes('47123'));
  assert.equal(i18n.t('no.such.key'), 'no.such.key');
  for (const key of routeKeys) assert.notEqual(i18n.t(key), key);
  for (const [en, id] of coreCopy) {
    const existing = legacy.translateText(en);
    if (!['en', 'id'].includes(locale)) assert(existing !== undefined || Object.hasOwn(UI_TRANSLATIONS, en), 'Missing ' + locale + ' core translation: ' + en);
    assert.equal(i18n.l(en, id), locale === 'en' ? en : locale === 'id' ? id : existing ?? UI_TRANSLATIONS[en][locale]);
  }
  assert.equal(legacy.translateText('Favorites'), i18n.t('tabs.favorites'));
  assert.equal(i18n.t('help.footnote'), i18n.l('Monitoring is read-only. Stopping a listener requires explicit confirmation.', 'Pemantauan hanya membaca. Menghentikan listener memerlukan konfirmasi eksplisit.'));
  if (!['en', 'id'].includes(locale)) {
    assert.equal(i18n.l('Favorites', 'Favorit'), i18n.t('tabs.favorites'));
    for (const label of ['Force stop', 'Yes, force stop', 'Process control', 'Force stop this process?']) assert.notEqual(i18n.l(label, ''), label);
    for (const text of ['constructor', '__proto__', 'Unknown future copy']) assert.equal(i18n.l(text, ''), text);
  }
}
for (const [english, entries] of Object.entries(UI_TRANSLATIONS)) {
  assert.deepEqual(Object.keys(entries).sort(), ['es', 'ja', 'zh']);
  for (const value of Object.values(entries)) assert(typeof value === 'string' && (value.length > 0 || english === ' ago'));
  assert(Object.values(entries).some(value => value !== english), 'Untranslated supplemental entry: ' + english);
}
assert.equal(legacy.translateText('Unknown future copy'), undefined);
i18n.setLocale('invalid'); assert.equal(i18n.getLocale(), 'en');
console.log('Five-locale core copy, legacy reuse, confirmed-stop warnings and locale persistence checks passed (' + coreCopy.size + ' literals)');
