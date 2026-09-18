#!/usr/bin/env node
'use strict';
const fs = require('fs');
const path = require('path');
const F = require('./fixer.js');

const USAGE = `HAR Fixer ${F.VERSION} — make HAR files load in Google's HAR Analyzer

Usage: node cli.js input.har [output.har] [options]

Options:
  --sanitize        redact cookies, auth headers, secret query params and bodies
  --strip-custom    remove non-standard "_fields" (Chrome's _initiator, _priority, ...)
  --strip-bodies    drop response bodies (keeps sizes/timings) to shrink the file
  --compact         write minified JSON instead of pretty-printed
  --check           only report what would crash Google's analyzer; exit 1 if anything would
  -h, --help        show this help

Without output.har the fixed HAR is written to stdout.`;

const argv = process.argv.slice(2);
const flags = new Set(argv.filter((a) => a.startsWith('-')));
const files = argv.filter((a) => !a.startsWith('-'));
if (flags.has('-h') || flags.has('--help') || !files.length) {
  console.error(USAGE);
  process.exit(files.length ? 0 : 1);
}

let raw;
try {
  raw = fs.readFileSync(files[0], 'utf8');
} catch (e) {
  console.error('Cannot read file: ' + e.message);
  process.exit(1);
}

const parsed = F.parseHARText(raw);
if (!parsed.har) {
  console.error(parsed.error);
  process.exit(1);
}

const before = F.googleCheck(parsed.har);
if (flags.has('--check')) {
  parsed.fixes.forEach((f) => console.error('json: ' + f));
  if (!before.length) {
    console.error('OK — Google HAR Analyzer should load this file.');
    process.exit(parsed.fixes.length ? 1 : 0);
  }
  before.forEach((p) => console.error((p.entry == null ? 'file' : '#' + p.entry) + ': ' + p.message + (p.url ? '  ' + p.url : '')));
  process.exit(1);
}

let har = F.fixHAR(parsed.har);
const fixes = parsed.fixes.concat(F.fixHAR.lastFixes || []);
if (flags.has('--strip-bodies')) { har = F.stripResponseBodies(har); fixes.push('Stripped response bodies'); }
if (flags.has('--sanitize')) { har = F.sanitizeHAR(har); fixes.push('Sanitized cookies, auth headers and bodies'); }
if (flags.has('--strip-custom')) { har = F.stripNonStandard(har); fixes.push('Removed non-standard _fields'); }

const after = F.googleCheck(har);
console.error('Applied ' + fixes.length + ' fix(es)');
fixes.forEach((f) => console.error('  - ' + f));
console.error(after.length
  ? 'WARNING: ' + after.length + ' problem(s) remain: ' + after[0].message
  : 'Google HAR Analyzer check: OK (' + before.length + ' crash cause(s) before, 0 after)');

const json = flags.has('--compact') ? JSON.stringify(har) : JSON.stringify(har, null, 2);
if (files[1]) {
  fs.writeFileSync(files[1], json);
  console.error('Wrote ' + path.resolve(files[1]));
} else {
  process.stdout.write(json + '\n');
}
