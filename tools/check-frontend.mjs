// Pure feature checks: no browser, server, network, or new test framework.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { createRequire } from 'node:module';
import ts from 'typescript';
const require = createRequire(import.meta.url);
function load(name) {
  const path = 'frontend/src/' + name;
  const source = fs.readFileSync(path, 'utf8');
  assert(!source.includes('\0'), path + ' must be text without NUL bytes');
  const module = { exports: {} };
  const isolatedRequire = spec => spec === '@/lib/i18n' ? { getLocale: () => 'en', t: key => key } : spec.startsWith('@/') ? {} : require(spec);
  const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  vm.runInNewContext(output, { module, exports: module.exports, require: isolatedRequire, URL, TextEncoder, console, crypto: globalThis.crypto }, { filename: path });
  return module.exports;
}
for (const [file, name] of [['features/snapshots.tsx', 'snapshotSelfCheck'], ['features/health.tsx', 'healthSelfCheck'], ['features/atlas.tsx', 'atlasSelfCheck'], ['features/diagnostics.tsx', 'diagnosticsSelfCheck'], ['features/dns-tools.tsx', 'dnsToolsSelfCheck'], ['features/browser-dns.tsx', 'browserDnsSelfCheck']]) console.log(load(file)[name]());
const { observedLatency } = load('features/insights.tsx');
const empty = observedLatency([]);
assert.equal(empty.p95, null);
const measured = observedLatency([0, 10, 20, 30, NaN, -1]);
assert.equal(measured.p95, 30);
assert.equal(measured.average, 15);
const { toCsv } = load('lib/utils.ts');
assert.equal(toCsv([[' =1', 'a"b', '@evil']]), '\"\' =1\",\"a\"\"b\",\"\'@evil\"');
console.log('Latency sample statistics and formula-safe export checks passed');
