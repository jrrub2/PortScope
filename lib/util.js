'use strict';

/**
 * Small shared helpers for PortScope.
 *
 * The backend deliberately uses only Node's standard library. A few OS
 * commands (netstat, tasklist, PowerShell, ps, lsof) are unavoidable, so most
 * of this file is about running them safely and turning their text output into
 * plain data.
 */

const { execFile } = require('node:child_process');

const DEFAULT_MAX_BUFFER = 16 * 1024 * 1024;

/**
 * Execute a command and capture stdout/stderr.
 *
 * PortScope must never crash because an OS binary is missing, slow, or killed.
 * This helper therefore never rejects: it always resolves with a result object
 * and lets callers decide whether the failure is fatal.
 *
 * @param {string} command executable name or path
 * @param {string[]} args
 * @param {{timeoutMs?: number, maxBuffer?: number}} [options]
 * @returns {Promise<{ok: boolean, code: number|null, stdout: string, stderr: string,
 *   error: string|null, timedOut: boolean, durationMs: number}>}
 */
function runCommand(command, args = [], options = {}) {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const maxBuffer = options.maxBuffer ?? DEFAULT_MAX_BUFFER;
  const startedAt = Date.now();

  return new Promise((resolve) => {
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve({ ...result, durationMs: Date.now() - startedAt });
    };

    const onDone = (error, stdout, stderr) => {
      const stdoutText = typeof stdout === 'string' ? stdout : String(stdout ?? '');
      const stderrText = typeof stderr === 'string' ? stderr : String(stderr ?? '');
      if (!error) {
        finish({ ok: true, code: 0, stdout: stdoutText, stderr: stderrText, error: null, timedOut: false });
        return;
      }
      // execFile reports a timeout by killing the child: `killed` is set and the
      // signal is SIGTERM. A spawn failure (ENOENT) has no `killed` flag.
      const timedOut = Boolean(error.killed) || error.signal === 'SIGTERM';
      finish({
        ok: false,
        code: typeof error.code === 'number' ? error.code : null,
        stdout: stdoutText,
        stderr: stderrText,
        error: errorText(error),
        timedOut,
      });
    };

    try {
      execFile(
        command,
        args,
        { windowsHide: true, timeout: timeoutMs, maxBuffer, encoding: 'utf8' },
        onDone,
      );
    } catch (error) {
      finish({ ok: false, code: null, stdout: '', stderr: '', error: errorText(error), timedOut: false });
    }
  });
}

/**
 * Turn anything thrown/rejected into a short single-line message.
 * @param {unknown} value
 * @returns {string}
 */
function errorText(value) {
  if (value instanceof Error) return value.message || value.name || 'Error';
  return String(value);
}

/**
 * Parse one CSV line (used for `tasklist /FO CSV /NH`).
 * Handles quoted fields, embedded commas and doubled quotes.
 * @param {string} line
 * @returns {string[]}
 */
function parseCsvLine(line) {
  const fields = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (inQuotes) {
      if (char === '"') {
        if (line[i + 1] === '"') {
          field += '"';
          i += 1;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
    } else if (char === '"') {
      inQuotes = true;
    } else if (char === ',') {
      fields.push(field);
      field = '';
    } else {
      field += char;
    }
  }

  fields.push(field);
  return fields;
}

const HTML_ENTITIES = Object.freeze({
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  ndash: '\u2013',
  mdash: '\u2014',
  hellip: '\u2026',
  rsquo: '\u2019',
  lsquo: '\u2018',
  ldquo: '\u201c',
  rdquo: '\u201d',
  copy: '\u00a9',
  middot: '\u00b7',
});

/**
 * Decode the handful of HTML entities that realistically appear in a <title>.
 * @param {string} text
 * @returns {string}
 */
function decodeHtmlEntities(text) {
  return text.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (match, entity) => {
    if (entity[0] === '#') {
      const isHex = entity[1] === 'x' || entity[1] === 'X';
      const code = Number.parseInt(isHex ? entity.slice(2) : entity.slice(1), isHex ? 16 : 10);
      if (Number.isFinite(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return match;
        }
      }
      return match;
    }
    const known = HTML_ENTITIES[entity.toLowerCase()];
    return known ?? match;
  });
}

/**
 * Collapse any run of whitespace (including tabs/newlines) into single spaces.
 * @param {string} text
 * @returns {string}
 */
function collapseWhitespace(text) {
  return String(text).replace(/\s+/g, ' ').trim();
}

/**
 * Slice a string to a maximum length without splitting surrogate pairs.
 * @param {string} text
 * @param {number} max
 * @returns {string}
 */
function truncate(text, max) {
  if (text.length <= max) return text;
  return text.slice(0, max);
}

/**
 * @param {number} ms epoch milliseconds
 * @returns {string} ISO-8601 string
 */
function toIso(ms) {
  return new Date(ms).toISOString();
}

/**
 * Round to the nearest integer and keep it non-negative.
 * @param {number} value
 * @returns {number}
 */
function roundMs(value) {
  return Math.max(0, Math.round(value));
}

/**
 * Windows netstat/ss wrap long listener lists; never trust one giant line to
 * stay one line. Used to include an error excerpt in meta.lastError.
 * @param {string} text
 * @returns {string}
 */
function firstLine(text) {
  return String(text).split(/\r?\n/).find((line) => line.trim().length > 0)?.trim() ?? '';
}

module.exports = {
  runCommand,
  errorText,
  parseCsvLine,
  decodeHtmlEntities,
  collapseWhitespace,
  truncate,
  toIso,
  roundMs,
  firstLine,
};
