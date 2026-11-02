import { existsSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, join, parse, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
const MARKER = '===== GENERATED INSTALLED DEPENDENCY LICENSES =====';
const EXTRA_CSS = ['tailwindcss', 'tw-animate-css'];
const normalize = text => text.replace(/^\uFEFF/, '').replace(/\r\n?/g, '\n').trim();
const legalFile = /^(?:licen[sc]e|copying|copyright|notice|third[-_ ]party[-_ ](?:licen[sc]e|notice)s?)(?:$|[._ -])/i;
const terms = /Permission is hereby granted|Permission to use, copy|Redistribution and use|TERMS AND CONDITIONS|public domain|This is free and unencumbered software/i;
const json = file => JSON.parse(readFileSync(file, 'utf8'));

function dependencyDirectory(name, from, optional) {
  for (let at = from; ; at = dirname(at)) {
    const candidate = join(at, 'node_modules', name, 'package.json');
    if (existsSync(candidate)) return dirname(realpathSync(candidate));
    if (at === parse(at).root) break;
  }
  if (!optional) throw new Error('Missing installed dependency: ' + name);
}
function licenseFiles(directory, relative = '') {
  const files = [];
  for (const entry of readdirSync(join(directory, relative), { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
    const name = relative ? relative + '/' + entry.name : entry.name;
    if (entry.isFile() && legalFile.test(entry.name)) files.push({ name, text: normalize(readFileSync(join(directory, name), 'utf8')) });
    else if (entry.isDirectory() && /^(?:licenses?|licences?|legal|notices?)$/i.test(entry.name)) files.push(...licenseFiles(directory, name));
  }
  return files;
}
function packageNotices(directory, pkg) {
  const files = licenseFiles(directory);
  if (!files.some(file => terms.test(file.text))) {
    // ponytail: published packages without LICENSE are accepted only when README contains the full grant, never an SPDX/link substitute.
    for (const entry of readdirSync(directory).filter(name => /^readme(?:\.|$)/i.test(name)).sort()) {
      const readme = normalize(readFileSync(join(directory, entry), 'utf8'));
      const start = /^#{1,6}\s+(?:licen[sc]e|copyright)[^\n]*$/im.exec(readme);
      if (start && terms.test(readme.slice(start.index))) { files.push({ name: entry + ' (license section)', text: readme.slice(start.index) }); break; }
    }
  }
  if (!files.some(file => terms.test(file.text)) && pkg.name === 'react-remove-scroll-bar' && pkg.version === '2.3.8') {
    const manual = readFileSync(join(ROOT, 'frontend/THIRD-PARTY-NOTICES.txt'), 'utf8').split(MARKER)[0];
    const start = manual.indexOf('===== VERIFIED UPSTREAM LICENSE react-remove-scroll-bar@2.3.8 =====');
    const end = manual.indexOf('===== END VERIFIED UPSTREAM LICENSE =====', start);
    if (start >= 0 && end > start) files.push({ name: 'verified upstream LICENSE (published package omitted text)', text: normalize(manual.slice(start, end)) });
  }
  if (!files.some(file => file.text.length > 100 && terms.test(file.text))) throw new Error('Missing full license text for ' + pkg.name + '@' + pkg.version);
  if (files.some(file => !file.text)) throw new Error('Empty license or notice file for ' + pkg.name + '@' + pkg.version);
  return files.map(file => '--- ' + file.name + ' ---\n' + file.text).join('\n\n');
}
function collect(directory, resolveDependency = dependencyDirectory, readPackage = at => json(join(at, 'package.json')), readNotices = packageNotices) {
  const seen = new Set(), sections = new Map();
  function visit(at) {
    if (seen.has(at)) return;
    seen.add(at);
    const pkg = readPackage(at), label = pkg.name + '@' + pkg.version;
    if (!pkg.name || !pkg.version) throw new Error('Installed package is missing name/version.');
    const notice = readNotices(at, pkg);
    if (sections.has(label) && sections.get(label) !== notice) throw new Error('Conflicting license texts for ' + label);
    sections.set(label, notice);
    edges(pkg, at);
  }
  function edges(pkg, at, extras = []) {
    const names = new Set([...Object.keys(pkg.dependencies || {}), ...Object.keys(pkg.optionalDependencies || {}), ...Object.keys(pkg.peerDependencies || {}), ...extras]);
    for (const name of [...names].sort()) {
      const optional = Object.hasOwn(pkg.optionalDependencies || {}, name) || (!Object.hasOwn(pkg.dependencies || {}, name) && pkg.peerDependenciesMeta?.[name]?.optional === true);
      const dependency = resolveDependency(name, at, optional);
      if (dependency) visit(dependency);
    }
  }
  const root = readPackage(directory);
  // CSS sources are build-time packages, but their generated styles are distributed with the app.
  edges({ dependencies: root.dependencies, optionalDependencies: root.optionalDependencies }, directory, EXTRA_CSS);
  return [...sections].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
}
export function generateNotices(root = ROOT) {
  const file = join(root, 'frontend/THIRD-PARTY-NOTICES.txt');
  const manual = normalize(readFileSync(file, 'utf8').split(MARKER)[0].replace('Other bundled dependencies retain their own licenses in node_modules.', 'Full installed dependency license and notice texts are included below; no installation is required to read them.'));
  const sections = collect(root);
  const text = manual + '\n\n' + MARKER + '\nGenerated by tools/update-notices.mjs from the installed production dependency graph,\nincluding installed peer/optional dependencies, MapLibre worker dependencies and shipped CSS sources.\nThis conservative superset may include packages whose code was removed by bundling.\nNo build timestamp or local installation path is included.\n\n' + sections.map(([label, notice]) => '===== ' + label + ' =====\n\n' + notice).join('\n\n') + '\n';
  return { text, packages: sections.length };
}
export function noticeSelfCheck() {
  const packages = { root: { dependencies: { a: '1', b: '1' } }, a: { name: 'a', version: '1', dependencies: { b: '1' }, peerDependencies: { absent: '1' }, peerDependenciesMeta: { absent: { optional: true } } }, b: { name: 'b', version: '1', dependencies: { a: '1' } }, tailwindcss: { name: 'tailwindcss', version: '1' }, 'tw-animate-css': { name: 'tw-animate-css', version: '1' } };
  const resolveDependency = (name, _from, optional) => { if (packages[name]) return name; if (!optional) throw new Error('Missing installed dependency: ' + name); };
  const notices = collect('root', resolveDependency, at => packages[at], (_at, pkg) => pkg.name + ' full LICENSE and NOTICE');
  assert.deepEqual(notices.map(([name]) => name), ['a@1', 'b@1', 'tailwindcss@1', 'tw-animate-css@1']);
  assert.equal(notices.filter(([name]) => name === 'b@1').length, 1, 'Cycles/shared dependencies are collected once');
  assert.throws(() => collect('root', resolveDependency, at => packages[at], () => { throw new Error('Missing full license text'); }), /Missing full license/);
  assert.throws(() => collect('root', () => { throw new Error('Missing installed dependency'); }, at => packages[at]), /Missing installed dependency/);
  assert(legalFile.test('LICENSE-MIT') && legalFile.test('NOTICE.txt') && legalFile.test('COPYING') && legalFile.test('THIRD-PARTY-LICENSES.txt'));
  assert(!terms.test('MIT https://example.test/license'), 'SPDX/link-only text is not a license grant');
  return 'Notice dependency cycle, shared graph, optional, missing-license and NOTICE checks passed';
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const mode = process.argv[2];
    if (mode === '--self-test') console.log(noticeSelfCheck());
    else {
      if (mode && mode !== '--check') throw new Error('Usage: node tools/update-notices.mjs [--check|--self-test]');
      const { text, packages } = generateNotices();
      for (const file of ['frontend/THIRD-PARTY-NOTICES.txt', 'web/THIRD-PARTY-NOTICES.txt']) {
        if (mode === '--check') { if (readFileSync(join(ROOT, file), 'utf8') !== text) throw new Error(file + ' is stale; run node tools/update-notices.mjs'); }
        else writeFileSync(join(ROOT, file), text);
      }
      console.log((mode ? 'Verified' : 'Updated') + ' full notices for ' + packages + ' installed packages.');
    }
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
