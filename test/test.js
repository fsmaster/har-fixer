'use strict';
// Run: node test/test.js   (no dependencies)
const assert = require('assert');
const F = require('../fixer.js');
const { googleLoad } = require('./google-loader.js');

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; console.log('  ok  ' + name); }
  catch (e) { console.error('  FAIL ' + name + '\n       ' + (e && e.stack || e)); process.exitCode = 1; }
}
const ISO = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/;
const fix = (h) => F.fixHAR(h);
const loads = (h) => googleLoad(JSON.stringify(h));

// A tiny valid PNG / WOFF2-ish payloads (valid base64)
const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';
const WOFF2_B64 = Buffer.from('wOF2\u0000\u0001\u0000\u0000fake-font-bytes').toString('base64');

function chromeEntry(i, content, extra) {
  return Object.assign({
    _initiator: { type: 'parser' }, _priority: 'High', _resourceType: 'script',
    cache: {}, connection: '443', pageref: 'page_1',
    request: { method: 'GET', url: 'https://example.com/r' + i, httpVersion: 'http/2.0',
      headers: [{ name: ':authority', value: 'example.com' }, { name: 'user-agent', value: 'Mozilla/5.0' }],
      queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
    response: { status: 200, statusText: '', httpVersion: 'http/2.0',
      headers: [{ name: 'content-type', value: content.mimeType }], cookies: [],
      content: content, redirectURL: '', headersSize: -1, bodySize: -1, _transferSize: 1234, _error: null },
    serverIPAddress: '93.184.216.34', startedDateTime: '2026-09-17T19:12:00.' + String(100 + i) + 'Z', time: 20.5,
    timings: { blocked: 1.1, dns: -1, ssl: -1, connect: -1, send: 0.1, wait: 15.2, receive: 4.1, _blocked_queueing: 0.9 },
  }, extra || {});
}
function chromeHar(entries) {
  return { log: { version: '1.2', creator: { name: 'WebInspector', version: '537.36' },
    pages: [{ startedDateTime: '2026-09-17T19:12:00.000Z', id: 'page_1', title: 'https://example.com/', pageTimings: { onContentLoad: 300, onLoad: 700 } }],
    entries } };
}

console.log('\nA) synthetic spec case');
test('fixes the one-line spec HAR', () => {
  const input = { log: { entries: [{ startedDateTime: 'bad', request: null, response: { content: { encoding: 'base64', mimeType: 'text/javascript', text: '[text/javascript redacted]', size: 999999 } } }] } };
  assert.strictEqual(loads(input).ok, false, 'Google should reject the input');
  const out = fix(input);
  const e = out.log.entries[0], c = e.response.content;
  assert.ok(!('encoding' in c), 'encoding absent');
  assert.strictEqual(c.size, c.text.length, 'size === text.length');
  assert.ok(e.request && e.request.method === 'GET' && typeof e.request.url === 'string', 'request stub present');
  assert.match(e.startedDateTime, ISO, 'startedDateTime valid ISO');
  assert.ok(Object.values(e.timings).every((v) => typeof v === 'number'), 'timings all numbers');
  assert.ok(F.fixHAR.lastFixes.some((f) => /base64/.test(f)), 'lastFixes mentions base64');
  assert.deepStrictEqual(loads(out), { ok: true, error: null });
});

console.log('\nB) real sanitized-file pattern');
test('redacted base64 bodies no longer crash; real base64 kept', () => {
  const entries = [];
  for (let i = 0; i < 13; i++) entries.push(chromeEntry(i, { size: 3533145, mimeType: 'text/javascript', encoding: 'base64', text: '[text/javascript redacted]' }));
  entries.push(chromeEntry(20, { size: 67, mimeType: 'image/png', encoding: 'base64', text: PNG_B64 }));
  entries.push(chromeEntry(21, { size: 30, mimeType: 'font/woff2', encoding: 'base64', text: WOFF2_B64 }));
  entries.push(chromeEntry(22, { size: 43, mimeType: 'image/gif', encoding: 'base64', text: 'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7' }));
  const har = chromeHar(entries);
  const g0 = loads(har);
  assert.strictEqual(g0.ok, false);
  assert.match(g0.error, /Unknown base64 encoding at char: \[/);
  assert.ok(F.googleCheck(har).length >= 13, 'googleCheck predicts the crash');

  const out = fix(har);
  assert.deepStrictEqual(loads(out), { ok: true, error: null });
  assert.deepStrictEqual(F.googleCheck(out), []);
  const byUrl = (u) => out.log.entries.find((e) => e.request.url.endsWith(u)).response.content;
  assert.strictEqual(byUrl('r20').encoding, 'base64', 'png keeps base64');
  assert.strictEqual(byUrl('r21').encoding, 'base64', 'woff2 keeps base64');
  assert.strictEqual(byUrl('r22').encoding, 'base64', 'gif keeps base64');
  assert.strictEqual(byUrl('r0').size, '[text/javascript redacted]'.length);
  assert.ok(F.fixHAR.lastFixes.includes('Dropped invalid content.encoding=base64 on 13 redacted/non-base64 bodies (Google HAR Analyzer crash)'), F.fixHAR.lastFixes.join('\n'));
  assert.ok(F.fixHAR.lastFixes.includes('Aligned content.size with redacted placeholder text on 13 entries'));
  assert.ok(out.log.entries[0]._initiator, 'custom fields preserved by default');
});

console.log('\nC) known-good unmodified Chrome HAR');
test('passes through unchanged and loads', () => {
  const har = chromeHar([
    chromeEntry(1, { size: 67, mimeType: 'image/png', encoding: 'base64', text: PNG_B64 }),
    chromeEntry(2, { size: 30, mimeType: 'application/javascript', encoding: 'base64', text: Buffer.from('console.log(1)').toString('base64') }),
    chromeEntry(3, { size: 5, mimeType: 'text/html', text: '<p>x</p>' }),
    chromeEntry(4, { size: 7, mimeType: 'application/x-www-form-urlencoded', text: 'a=1&b=%20' }),
  ]);
  assert.deepStrictEqual(loads(har), { ok: true, error: null });
  const out = fix(har);
  assert.deepStrictEqual(out, har, 'no changes to a valid Chrome HAR');
  assert.deepStrictEqual(F.fixHAR.lastFixes, []);
  assert.deepStrictEqual(F.googleCheck(har), []);
});

console.log('\nOther Google landmines');
test('malformed urlencoded body -> text/plain', () => {
  const har = chromeHar([chromeEntry(1, { size: 5, mimeType: 'application/x-www-form-urlencoded', text: 'q=100%&x=%E0%A4%A' })]);
  assert.match(loads(har).error, /URI malformed/);
  const out = fix(har);
  assert.strictEqual(out.log.entries[0].response.content.mimeType, 'text/plain');
  assert.ok(loads(out).ok);
});
test('non-string mimeType / method / header names', () => {
  const har = chromeHar([chromeEntry(1, { size: 5, mimeType: 42, text: 'x' })]);
  har.log.entries[0].request.method = 7;
  har.log.entries[0].response.headers.push({ name: 12, value: 3 });
  assert.strictEqual(loads(har).ok, false);
  assert.ok(F.googleCheck(har).length >= 1);
  assert.ok(loads(fix(har)).ok);
});
test('null entry, string timings, missing everything', () => {
  const har = { log: { entries: [null, { timings: 'fast' }, {}] } };
  assert.strictEqual(loads(har).ok, false);
  const out = fix(har);
  assert.strictEqual(out.log.entries.length, 2);
  assert.ok(loads(out).ok);
});
test('empty entries stays empty and says why', () => {
  const out = fix({ log: { entries: [] } });
  assert.strictEqual(out.log.entries.length, 0);
  assert.ok(F.fixHAR.lastFixes.some((f) => /No log entries/.test(f)));
});
test('structural rescues: bare array, har.har, root entries, header object', () => {
  assert.strictEqual(fix([{ request: { url: 'https://a' } }]).log.entries.length, 1);
  assert.strictEqual(fix({ har: { log: { entries: [{}] } } }).log.entries.length, 1);
  assert.strictEqual(fix({ entries: [{}, {}] }).log.entries.length, 2);
  const o = fix({ log: { entries: [{ request: { headers: { Host: 'a.com' } } }] } });
  assert.deepStrictEqual(o.log.entries[0].request.headers, [{ name: 'Host', value: 'a.com' }]);
});
test('epoch startedDateTime becomes ISO', () => {
  const o = fix({ log: { entries: [{ startedDateTime: 1758136320 }] } });
  assert.strictEqual(o.log.entries[0].startedDateTime, '2025-09-17T19:12:00.000Z');
});
test('invalid date inherits previous entry timestamp', () => {
  const o = fix({ log: { entries: [{ startedDateTime: '2026-01-01T00:00:01.000Z' }, { startedDateTime: 'bad' }] } });
  assert.strictEqual(o.log.entries[1].startedDateTime, '2026-01-01T00:00:01.000Z');
});
test('lastFixes is compact (one line per fix type, not per field)', () => {
  const entries = [];
  for (let i = 0; i < 199; i++) entries.push({ timings: { wait: 'x', send: 'y', receive: 'z' }, time: 'n' });
  fix({ log: { entries } });
  assert.ok(F.fixHAR.lastFixes.length < 10, F.fixHAR.lastFixes.join('\n'));
  assert.ok(F.fixHAR.lastFixes.includes('Filled missing/non-numeric timing fields on 199 entries'));
});

console.log('\nJSON recovery');
test('BOM', () => {
  const r = F.parseHARText('\uFEFF{"log":{"entries":[]}}');
  assert.ok(r.har && r.fixes.length === 1);
});
test('trailing commas', () => {
  const r = F.parseHARText('{"log":{"entries":[{"a":"x,]"},],},}');
  assert.deepStrictEqual(r.har, { log: { entries: [{ a: 'x,]' }] } });
});
test('truncated mid-entry keeps complete entries', () => {
  const full = JSON.stringify(chromeHar([chromeEntry(1, { size: 1, mimeType: 'text/plain', text: 'a' }), chromeEntry(2, { size: 1, mimeType: 'text/plain', text: 'b' })]), null, 2);
  const cut = full.slice(0, full.indexOf('/r2') + 3);
  const r = F.parseHARText(cut);
  assert.ok(r.har, r.error);
  assert.ok(r.fixes.some((f) => /truncated/.test(f)));
  const out = fix(r.har);
  assert.ok(out.log.entries.length >= 1);
  assert.strictEqual(out.log.entries[0].request.url, 'https://example.com/r1');
  assert.ok(loads(out).ok);
});
test('garbage stays an error', () => {
  const r = F.parseHARText('hello world');
  assert.strictEqual(r.har, null);
  assert.match(r.error, /Not valid JSON/);
});

console.log('\nOptional passes');
test('sanitizeHAR redacts secrets and stays loadable', () => {
  const har = chromeHar([chromeEntry(1, { size: 1, mimeType: 'text/plain', text: 'secret body' })]);
  const req = har.log.entries[0].request;
  req.url = 'https://example.com/cb?code=abc&state=ok&access_token=zzz';
  req.headers.push({ name: 'Authorization', value: 'Bearer x' }, { name: 'X-Goog-AuthUser', value: '0' }, { name: 'Cookie', value: 'a=b' });
  req.cookies = [{ name: 'a', value: 'b' }];
  req.postData = { mimeType: 'application/json', text: '{"password":"p"}' };
  const s = F.sanitizeHAR(fix(har));
  const json = JSON.stringify(s);
  for (const secret of ['Bearer x', 'a=b', 'secret body', '"p"', 'abc', 'zzz']) assert.ok(!json.includes(secret), 'leaked ' + secret);
  assert.ok(json.includes('state=ok'));
  assert.ok(loads(s).ok);
});
test('stripNonStandard removes _fields deeply', () => {
  const s = F.stripNonStandard(chromeHar([chromeEntry(1, { size: 1, mimeType: 'text/plain', text: 'a' })]));
  assert.ok(!/"_/.test(JSON.stringify(s)));
});
test('broken sample: Google rejects, fixer repairs', () => {
  const b = F.brokenSample();
  assert.strictEqual(loads(b).ok, false);
  assert.ok(F.googleCheck(b).length >= 3);
  const out = fix(b);
  assert.ok(loads(out).ok);
  assert.deepStrictEqual(F.googleCheck(out), []);
});

console.log('\n' + passed + ' passed' + (process.exitCode ? ', some FAILED' : ''));
