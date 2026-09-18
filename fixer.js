/*!
 * HAR Fixer — https://harfixer.com
 * Repairs HAR (HTTP Archive) files so Google's HAR Analyzer
 * (https://toolbox.googleapps.com/apps/har_analyzer/) will load them.
 * Runs 100% locally (browser or Node). MIT License.
 */
(function (root) {
  'use strict';

  var VERSION = '1.0.0';
  var CREATOR = { name: 'har-fixer', version: VERSION };
  var TIMING_KEYS = ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl'];

  // Exact alphabet Google's decoder accepts (toolbox_qb): A-Z a-z 0-9 + / = - _ .
  // Whitespace (incl. \xa0) is skipped. Anything else throws "Unknown base64 encoding at char".
  var GOOGLE_B64 = /^[\s\xa0A-Za-z0-9+/=_.-]*$/;
  // Placeholders sanitizers leave behind: "[text/javascript redacted]", "[REDACTED]", "[Filtered]", ...
  var REDACTED = /^\s*\[(?:[^\]]+ redacted|redacted|filtered|removed|omitted|scrubbed)\]\s*$/i;

  /* ------------------------------------------------------------------ */
  /* small helpers                                                       */
  /* ------------------------------------------------------------------ */

  function isObj(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }

  function isValidDate(d) {
    return typeof d === 'string' && d.trim().length > 0 && !isNaN(Date.parse(d));
  }

  function toNumber(v, def) {
    if (typeof v === 'number' && isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && isFinite(Number(v))) return Number(v);
    return def;
  }

  function toStr(v, def) {
    if (typeof v === 'string') return v;
    if (v === null || v === undefined) return def;
    if (typeof v === 'object') { try { return JSON.stringify(v); } catch (e) { return def; } }
    return String(v);
  }

  function isGoogleBase64(text) { return GOOGLE_B64.test(text); }
  function isRedacted(text) { return typeof text === 'string' && REDACTED.test(text); }

  // Normalize name/value lists (headers, cookies, queryString, params).
  // Google silently drops items without a truthy name; we keep the data but make every item well-formed.
  function normalizeNV(list, st, what) {
    if (!Array.isArray(list)) {
      if (isObj(list)) { // {"Host": "x"} style — convert to [{name, value}]
        st.count(what + 'obj');
        return Object.keys(list).map(function (k) { return { name: k, value: toStr(list[k], '') }; });
      }
      if (list !== undefined) st.count(what + 'bad');
      return [];
    }
    var out = [];
    for (var i = 0; i < list.length; i++) {
      var it = list[i];
      if (typeof it === 'string') { // "Name: value"
        var p = it.indexOf(':');
        out.push(p > 0 ? { name: it.slice(0, p).trim(), value: it.slice(p + 1).trim() } : { name: it, value: '' });
        st.count(what + 'fix');
        continue;
      }
      if (!isObj(it) || it.name === null || it.name === undefined || it.name === '') { st.count(what + 'drop'); continue; }
      if (typeof it.name !== 'string' || (it.value !== undefined && typeof it.value !== 'string')) st.count(what + 'fix');
      it.name = toStr(it.name, '');
      it.value = toStr(it.value, '');
      out.push(it);
    }
    return out;
  }

  function Stats() { this.c = {}; }
  Stats.prototype.count = function (k, n) { this.c[k] = (this.c[k] || 0) + (n || 1); };
  Stats.prototype.get = function (k) { return this.c[k] || 0; };

  /* ------------------------------------------------------------------ */
  /* text → JSON, with recovery for BOM, trailing commas and truncation  */
  /* ------------------------------------------------------------------ */

  // Remove commas that directly precede } or ] (outside strings).
  function stripTrailingCommas(s) {
    // Collect offending comma offsets, then rebuild with slices (cheap on 100 MB files).
    var drop = [], inStr = false, esc = false, pendingComma = -1;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charCodeAt(i);
      if (inStr) {
        if (esc) esc = false; else if (ch === 92) esc = true; else if (ch === 34) inStr = false;
        continue;
      }
      if (ch === 34) { pendingComma = -1; inStr = true; }
      else if (ch === 44) pendingComma = i;
      else if (ch === 125 || ch === 93) { if (pendingComma >= 0) drop.push(pendingComma); pendingComma = -1; }
      else if (ch !== 32 && ch !== 9 && ch !== 10 && ch !== 13) pendingComma = -1;
    }
    if (!drop.length) return s;
    var parts = [], last = 0;
    for (var k = 0; k < drop.length; k++) { parts.push(s.slice(last, drop[k])); last = drop[k] + 1; }
    parts.push(s.slice(last));
    return parts.join('');
  }

  // Salvage a truncated JSON document: cut after the last fully-closed object/array
  // and close whatever is still open. Typical cause: a HAR export killed mid-write.
  function repairTruncated(s) {
    var stack = [], inStr = false, esc = false, cut = -1;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charCodeAt(i);
      if (inStr) {
        if (esc) esc = false; else if (ch === 92) esc = true; else if (ch === 34) inStr = false;
        continue;
      }
      if (ch === 34) inStr = true;
      else if (ch === 123 || ch === 91) stack.push(ch);
      else if (ch === 125 || ch === 93) {
        stack.pop();
        if (stack.length === 0) return null; // document is complete — truncation is not the problem
        cut = i + 1;
      }
    }
    if (cut < 0) return null;
    // Rescan only to rebuild the stack at the cut point (keeps the main loop allocation-free).
    stack = []; inStr = false; esc = false;
    for (var r = 0; r < cut; r++) {
      var c2 = s.charCodeAt(r);
      if (inStr) { if (esc) esc = false; else if (c2 === 92) esc = true; else if (c2 === 34) inStr = false; continue; }
      if (c2 === 34) inStr = true; else if (c2 === 123 || c2 === 91) stack.push(c2); else if (c2 === 125 || c2 === 93) stack.pop();
    }
    var closers = '';
    for (var j = stack.length - 1; j >= 0; j--) closers += stack[j] === 123 ? '}' : ']';
    return { text: s.slice(0, cut) + closers, dropped: s.length - cut };
  }

  /**
   * Parse HAR text. Never throws; returns { har, fixes[], error }.
   * har is null only if nothing could be recovered.
   */
  function parseHARText(text) {
    var fixes = [];
    if (typeof text !== 'string') text = String(text == null ? '' : text);
    if (text.charCodeAt(0) === 0xFEFF) { text = text.slice(1); fixes.push('Removed UTF-8 byte-order mark (BOM) that breaks JSON.parse'); }
    var firstErr;
    try { return { har: JSON.parse(text), fixes: fixes, error: null }; } catch (e) { firstErr = e; }

    var t2 = stripTrailingCommas(text);
    if (t2 !== text) {
      try { var h2 = JSON.parse(t2); fixes.push('Removed trailing commas (invalid JSON)'); return { har: h2, fixes: fixes, error: null }; } catch (e) { /* continue */ }
    }
    var t3 = repairTruncated(t2);
    if (t3) {
      try {
        var h3 = JSON.parse(t3.text);
        fixes.push('Recovered truncated file: kept everything up to the last complete object (' +
          fmtBytes(t3.dropped) + ' of partial data dropped)');
        return { har: h3, fixes: fixes, error: null };
      } catch (e) { /* continue */ }
    }
    return { har: null, fixes: fixes, error: 'Not valid JSON: ' + (firstErr && firstErr.message) };
  }

  function fmtBytes(n) {
    n = Math.max(0, n);
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  /* ------------------------------------------------------------------ */
  /* Google HAR Analyzer load simulation                                 */
  /* ------------------------------------------------------------------ */

  /**
   * Replays the parts of Google's HAR Analyzer load path that can throw
   * (reverse-engineered from har_analyzer__en.js). Returns an array of
   * problems; empty array = Google will load the file.
   * Each problem: { entry: index|null, url, message }
   */
  function googleCheck(har, opts) {
    var max = (opts && opts.max) || 200;
    var problems = [];
    function add(i, url, msg) { if (problems.length < max) problems.push({ entry: i, url: url || '', message: msg }); }
    if (!isObj(har) || !har.log || !har.log.entries || !(har.log.entries.length >= 1)) {
      add(null, '', 'No log entries found in the file.');
      return problems;
    }
    var entries = har.log.entries;
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (!isObj(e)) { add(i, '', 'Entry is ' + (e === null ? 'null' : typeof e) + ' — analyzer crashes reading its properties'); continue; }
      var req = e.request, res = e.response;
      var url = isObj(req) && typeof req.url === 'string' ? req.url : '';
      if (e.startedDateTime && typeof e.startedDateTime !== 'string') add(i, url, 'startedDateTime is not a string (.trim() throws)');
      if (isObj(req)) {
        if (req.method && typeof req.method !== 'string') add(i, url, 'request.method is not a string (.trim() throws)');
        if (req.url !== undefined && typeof req.url !== 'string') add(i, url, 'request.url is not a string');
        if (req.postData && req.postData.mimeType && typeof req.postData.mimeType !== 'string') add(i, url, 'postData.mimeType is not a string (.toLowerCase() throws)');
        checkNV(req.headers, 'request.headers', i, url, add);
        checkNV(req.cookies, 'request.cookies', i, url, add);
        checkNV(req.queryString, 'request.queryString', i, url, add);
      }
      if (isObj(res)) {
        checkNV(res.headers, 'response.headers', i, url, add);
        checkNV(res.cookies, 'response.cookies', i, url, add);
        var c = res.content;
        if (c) {
          if (c.mimeType && typeof c.mimeType !== 'string') { add(i, url, 'content.mimeType is not a string (.toLowerCase() throws)'); continue; }
          if (c.encoding && typeof c.encoding !== 'string') { add(i, url, 'content.encoding is not a string (.toLowerCase() throws)'); continue; }
          var mime = (c.mimeType || '').toLowerCase(), enc = (c.encoding || '').toLowerCase(), text = c.text || '';
          if (text && typeof text !== 'string') { add(i, url, 'content.text is not a string'); continue; }
          if (text) {
            if (mime.indexOf('urlencoded') > 0) {
              try { decodeURIComponent(text.replace(/\+/g, ' ')); } catch (err) { add(i, url, 'URIError: URI malformed — urlencoded body has a bad % sequence'); }
            } else if (enc === 'base64' && mime.indexOf('image/') !== 0) {
              var bad = firstBadB64Char(text);
              if (bad !== null) add(i, url, 'Error: Unknown base64 encoding at char: ' + bad);
            }
          }
        }
      }
      if (e.timings !== undefined && e.timings !== null && typeof e.timings !== 'object') add(i, url, 'timings is not an object');
    }
    return problems;
  }

  function firstBadB64Char(text) {
    for (var i = 0; i < text.length; i++) {
      var ch = text[i];
      if (!/[A-Za-z0-9+/=_.\-\s\xa0]/.test(ch)) return ch;
    }
    return null;
  }

  function checkNV(list, label, i, url, add) {
    if (!list || typeof list.length !== 'number') return;
    for (var k = 0; k < list.length; k++) {
      var it = list[k];
      if (it && it.name && typeof it.name !== 'string') { add(i, url, label + ' has a non-string name (.toLowerCase() throws)'); return; }
    }
  }

  /* ------------------------------------------------------------------ */
  /* fixHAR                                                              */
  /* ------------------------------------------------------------------ */

  function fixEntry(entry, st, now) { // now = { last, fallback } date context
    if (!isObj(entry)) { st.count('removedEntries'); return null; }

    if (!isValidDate(entry.startedDateTime)) {
      if (typeof entry.startedDateTime === 'number' && isFinite(entry.startedDateTime)) {
        // epoch seconds or ms
        var ms = entry.startedDateTime < 1e12 ? entry.startedDateTime * 1000 : entry.startedDateTime;
        entry.startedDateTime = new Date(ms).toISOString();
      } else {
        // Borrow the previous request's timestamp so the waterfall stays in order.
        entry.startedDateTime = now.last || now.fallback;
      }
      st.count('dates');
    }
    now.last = entry.startedDateTime;

    var t0 = entry.time;
    entry.time = toNumber(entry.time, -1);
    if (t0 !== entry.time) st.count('numbers');

    /* request */
    if (!isObj(entry.request)) { entry.request = {}; st.count('missingRequest'); }
    var req = entry.request;
    var m0 = req.method;
    req.method = (toStr(req.method, 'GET').trim() || 'GET').toUpperCase();
    req.url = toStr(req.url, '').trim() || 'about:blank';
    req.httpVersion = toStr(req.httpVersion, '') || 'HTTP/1.1';
    req.cookies = normalizeNV(req.cookies, st, 'nv');
    req.headers = normalizeNV(req.headers, st, 'nv');
    req.queryString = normalizeNV(req.queryString, st, 'nv');
    var h0 = req.headersSize, b0 = req.bodySize;
    req.headersSize = toNumber(req.headersSize, -1);
    req.bodySize = toNumber(req.bodySize, -1);
    if (h0 !== req.headersSize || b0 !== req.bodySize || (m0 !== undefined && typeof m0 !== 'string')) st.count('numbers');
    if (req.postData !== undefined && req.postData !== null) {
      if (!isObj(req.postData)) {
        req.postData = { mimeType: 'text/plain', text: toStr(req.postData, '') };
        st.count('postData');
      } else {
        var pm = req.postData.mimeType;
        req.postData.mimeType = toStr(pm, '');
        if (pm !== undefined && typeof pm !== 'string') st.count('postData');
        if (req.postData.params !== undefined) req.postData.params = normalizeNV(req.postData.params, st, 'nv');
        if (req.postData.text !== undefined && typeof req.postData.text !== 'string') { req.postData.text = toStr(req.postData.text, ''); st.count('postData'); }
        if (req.postData.text === undefined && req.postData.params === undefined) req.postData.text = '';
      }
    } else if (req.postData === null) {
      delete req.postData;
    }

    /* response */
    if (!isObj(entry.response)) { entry.response = {}; st.count('missingResponse'); }
    var res = entry.response;
    res.status = toNumber(res.status, 0);
    res.statusText = toStr(res.statusText, '');
    res.httpVersion = toStr(res.httpVersion, '') || 'HTTP/1.1';
    res.cookies = normalizeNV(res.cookies, st, 'nv');
    res.headers = normalizeNV(res.headers, st, 'nv');
    res.redirectURL = toStr(res.redirectURL, '');
    res.headersSize = toNumber(res.headersSize, -1);
    res.bodySize = toNumber(res.bodySize, -1);

    if (!isObj(res.content)) { res.content = {}; st.count('missingContent'); }
    var c = res.content;
    if (c.text === null || c.text === undefined) delete c.text;
    else if (typeof c.text !== 'string') { c.text = toStr(c.text, ''); st.count('contentText'); }
    var mt0 = c.mimeType;
    c.mimeType = toStr(c.mimeType, '') ;
    if (mt0 !== undefined && typeof mt0 !== 'string') st.count('mimeType');
    if (c.encoding === null) delete c.encoding;
    else if (c.encoding !== undefined && typeof c.encoding !== 'string') { c.encoding = toStr(c.encoding, ''); st.count('mimeType'); }
    var s0 = c.size;
    c.size = toNumber(c.size, typeof c.text === 'string' ? c.text.length : 0);
    if (s0 !== undefined && s0 !== c.size) st.count('numbers');
    if (c.compression !== undefined && toNumber(c.compression, null) === null) delete c.compression;

    googleCompat(c, st);

    /* timings — one counter per entry, not per field */
    var hadTimings = isObj(entry.timings);
    if (!hadTimings) { entry.timings = {}; st.count('missingTimings'); }
    var t = entry.timings, touched = false;
    for (var k = 0; k < TIMING_KEYS.length; k++) {
      var key = TIMING_KEYS[k];
      if (key === 'ssl' && t.ssl === undefined) continue; // optional in HAR 1.2
      var n = toNumber(t[key], -1);
      if (t[key] !== n) touched = true;
      t[key] = n;
    }
    if (hadTimings && touched) st.count('partialTimings');

    if (!isObj(entry.cache)) entry.cache = {};
    if (entry.pageref === null || entry.pageref === undefined) delete entry.pageref;
    else if (typeof entry.pageref !== 'string') entry.pageref = String(entry.pageref);
    if (entry.serverIPAddress !== undefined && typeof entry.serverIPAddress !== 'string') entry.serverIPAddress = toStr(entry.serverIPAddress, '');
    if (entry.connection !== undefined && typeof entry.connection !== 'string') entry.connection = toStr(entry.connection, '');
    return entry;
  }

  // The three fixes that make sanitized HARs load in Google's analyzer.
  function googleCompat(c, st) {
    var text = typeof c.text === 'string' ? c.text : '';
    var enc = typeof c.encoding === 'string' ? c.encoding.toLowerCase() : '';
    var mime = (c.mimeType || '').toLowerCase();

    // 1) base64 flag on text that is not decodable by Google's decoder (e.g. "[text/javascript redacted]")
    if (enc === 'base64' && text && !isGoogleBase64(text)) {
      delete c.encoding;
      st.count(isRedacted(text) ? 'b64redacted' : 'b64invalid');
    }
    // 2) placeholder text with the original multi-MB size left behind
    if (text && isRedacted(text) && c.size > text.length) {
      c.size = text.length;
      st.count('redactedSize');
    }
    // 3) urlencoded body that decodeURIComponent() rejects
    if (text && mime.indexOf('urlencoded') > 0) {
      try { decodeURIComponent(text.replace(/\+/g, ' ')); }
      catch (e) { c.mimeType = 'text/plain'; st.count('urlencoded'); }
    }
  }

  function fixPage(p, i, st, now) {
    if (!isObj(p)) { st.count('removedPages'); return null; }
    if (!isValidDate(p.startedDateTime)) { p.startedDateTime = now; st.count('pageFix'); }
    if (typeof p.id !== 'string' || !p.id) { p.id = p.id != null && p.id !== '' ? String(p.id) : 'page_' + (i + 1); st.count('pageFix'); }
    if (typeof p.title !== 'string') { p.title = toStr(p.title, ''); st.count('pageFix'); }
    if (!isObj(p.pageTimings)) { p.pageTimings = {}; st.count('pageFix'); }
    p.pageTimings.onContentLoad = toNumber(p.pageTimings.onContentLoad, -1);
    p.pageTimings.onLoad = toNumber(p.pageTimings.onLoad, -1);
    return p;
  }

  function newLog(entries, pages) {
    return { version: '1.2', creator: { name: CREATOR.name, version: CREATOR.version }, pages: pages || [], entries: entries || [] };
  }

  /**
   * Repair a parsed HAR object. Returns a new object (input is not mutated).
   * A compact human-readable list of fixes is stored on fixHAR.lastFixes.
   */
  function fixHAR(input, options) {
    options = options || {};
    var extra = [], st = new Stats();
    var now = new Date().toISOString();

    var har;
    try { har = JSON.parse(JSON.stringify(input)); } catch (e) { har = null; }

    if (Array.isArray(har)) {
      har = { log: newLog(har) }; extra.push('Wrapped a bare entries[] array into log.entries');
    } else if (!isObj(har)) {
      har = { log: newLog() }; extra.push('Input was not a HAR object — created an empty HAR');
    }
    if (!har.log && isObj(har.har)) { har = har.har; extra.push('Unwrapped nested { "har": { "log": … } }'); }
    if (!isObj(har.log)) {
      if (Array.isArray(har.entries)) {
        har = { log: newLog(har.entries, Array.isArray(har.pages) ? har.pages : []) };
        extra.push('Moved root-level entries/pages under log');
      } else {
        har = { log: newLog() }; extra.push('Added missing log object');
      }
    }
    var log = har.log;
    if (typeof log.version !== 'string' || !log.version) { log.version = '1.2'; extra.push('Set log.version to 1.2'); }
    if (!isObj(log.creator)) { log.creator = { name: CREATOR.name, version: CREATOR.version }; extra.push('Added missing log.creator'); }
    else { log.creator.name = toStr(log.creator.name, 'unknown'); log.creator.version = toStr(log.creator.version, ''); }
    if (log.browser !== undefined && !isObj(log.browser)) delete log.browser;
    if (!Array.isArray(log.entries)) {
      if (isObj(log.entries)) { log.entries = Object.keys(log.entries).map(function (k) { return log.entries[k]; }); extra.push('Converted log.entries object into an array'); }
      else { log.entries = []; extra.push('Initialized missing log.entries'); }
    }
    if (!Array.isArray(log.pages)) {
      if (log.pages !== undefined) extra.push('Replaced invalid log.pages');
      log.pages = [];
    }

    var firstDate = null;
    log.pages.concat(log.entries).some(function (x) { if (isObj(x) && isValidDate(x.startedDateTime)) { firstDate = x.startedDateTime; return true; } return false; });
    var dateCtx = { last: null, fallback: firstDate || now };
    log.pages = log.pages.map(function (p, i) { return fixPage(p, i, st, dateCtx.fallback); }).filter(Boolean);
    log.entries = log.entries.map(function (e) { return fixEntry(e, st, dateCtx); }).filter(Boolean);

    // Entries that point at a page that does not exist confuse some viewers.
    var ids = {};
    log.pages.forEach(function (p) { ids[p.id] = true; });
    var orphan = 0;
    if (log.pages.length) log.entries.forEach(function (e) { if (e.pageref && !ids[e.pageref]) { delete e.pageref; orphan++; } });
    if (orphan) st.count('orphans', orphan);

    if (options.sortEntries) {
      log.entries.sort(function (a, b) { return Date.parse(a.startedDateTime) - Date.parse(b.startedDateTime); });
    }

    if (!log.entries.length) extra.push('Warning: the HAR has no entries — Google will say "No log entries found in the file."');

    var fixes = summarize(st, extra);
    fixHAR.lastFixes = fixes;
    fixHAR.lastStats = st.c;
    return har;
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

  function summarize(st, extra) {
    var f = extra.slice(), g = function (k) { return st.get(k); };
    var b64 = g('b64redacted') + g('b64invalid');
    if (b64) f.push('Dropped invalid content.encoding=base64 on ' + plural(b64, 'redacted/non-base64 body', 'redacted/non-base64 bodies') + ' (Google HAR Analyzer crash)');
    if (g('redactedSize')) f.push('Aligned content.size with redacted placeholder text on ' + plural(g('redactedSize'), 'entry', 'entries'));
    if (g('urlencoded')) f.push('Re-labelled ' + plural(g('urlencoded'), 'malformed urlencoded body', 'malformed urlencoded bodies') + ' as text/plain (URIError crash)');
    if (g('removedEntries')) f.push('Removed ' + plural(g('removedEntries'), 'null/non-object entry', 'null/non-object entries'));
    if (g('dates')) f.push('Repaired ' + plural(g('dates'), 'invalid startedDateTime'));
    if (g('missingRequest')) f.push('Added stub request to ' + plural(g('missingRequest'), 'entry', 'entries'));
    if (g('missingResponse')) f.push('Added stub response to ' + plural(g('missingResponse'), 'entry', 'entries'));
    if (g('missingContent')) f.push('Added missing response.content on ' + plural(g('missingContent'), 'entry', 'entries'));
    if (g('mimeType') || g('contentText')) f.push('Converted non-string mimeType/encoding/text on ' + plural(g('mimeType') + g('contentText'), 'entry', 'entries'));
    if (g('numbers')) f.push('Coerced non-numeric times/sizes on ' + plural(g('numbers'), 'field'));
    if (g('missingTimings')) f.push('Added default timings to ' + plural(g('missingTimings'), 'entry', 'entries'));
    if (g('partialTimings')) f.push('Filled missing/non-numeric timing fields on ' + plural(g('partialTimings'), 'entry', 'entries'));
    if (g('postData')) f.push('Normalized postData on ' + plural(g('postData'), 'entry', 'entries'));
    var nv = g('nvfix') + g('nvobj') + g('nvbad');
    if (nv) f.push('Normalized ' + plural(nv, 'malformed header/cookie/query list'));
    if (g('nvdrop')) f.push('Dropped ' + plural(g('nvdrop'), 'header/cookie item') + ' with no name');
    if (g('removedPages')) f.push('Removed ' + plural(g('removedPages'), 'invalid page'));
    if (g('pageFix')) f.push('Repaired ' + plural(g('pageFix'), 'page field'));
    if (g('orphans')) f.push('Cleared pageref on ' + plural(g('orphans'), 'entry', 'entries') + ' pointing at missing pages');
    return f;
  }

  /* ------------------------------------------------------------------ */
  /* optional passes                                                     */
  /* ------------------------------------------------------------------ */

  var SENSITIVE_HEADERS = ['authorization', 'cookie', 'set-cookie', 'proxy-authorization', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token'];
  var SENSITIVE_QUERY = /^(access_token|id_token|refresh_token|token|api_key|apikey|key|code|password|passwd|secret|sig|signature|session|sessionid|auth)$/i;

  /** Remove credentials: cookies, auth headers, request bodies, response bodies, secret query params. */
  function sanitizeHAR(input) {
    var har = JSON.parse(JSON.stringify(input));
    var n = { headers: 0, bodies: 0, params: 0 };
    function redactHeaders(list) {
      return (Array.isArray(list) ? list : []).map(function (h) {
        if (!h || !h.name) return h;
        var name = String(h.name).toLowerCase();
        if (SENSITIVE_HEADERS.indexOf(name) >= 0 || (name.indexOf('x-') === 0 && name.indexOf('auth') >= 0)) {
          n.headers++; return { name: h.name, value: '[REDACTED]' };
        }
        return h;
      });
    }
    var entries = (har && har.log && Array.isArray(har.log.entries)) ? har.log.entries : [];
    entries.forEach(function (e) {
      if (!e) return;
      var req = e.request, res = e.response;
      if (req) {
        req.cookies = [];
        req.headers = redactHeaders(req.headers);
        if (Array.isArray(req.queryString)) req.queryString.forEach(function (q) {
          if (q && SENSITIVE_QUERY.test(q.name || '')) { q.value = '[REDACTED]'; n.params++; }
        });
        if (typeof req.url === 'string') req.url = req.url.replace(/([?&])([^=&#]+)=([^&#]*)/g, function (all, sep, k, v) {
          return SENSITIVE_QUERY.test(decodeSafe(k)) ? sep + k + '=[REDACTED]' : all;
        });
        if (req.postData) {
          req.postData = { mimeType: toStr(req.postData.mimeType, ''), text: '[REDACTED]' };
          n.bodies++;
        }
      }
      if (res) {
        res.cookies = [];
        res.headers = redactHeaders(res.headers);
        var c = res.content;
        if (c && (c.text || c.encoding)) {
          c.text = '[REDACTED]';
          delete c.encoding;
          c.size = c.text.length;
          n.bodies++;
        }
      }
    });
    sanitizeHAR.lastStats = n;
    return har;
  }

  function decodeSafe(s) { try { return decodeURIComponent(s); } catch (e) { return s; } }

  /** Deep-remove non-standard keys (Chrome's _initiator, _priority, _resourceType, ...). */
  function stripNonStandard(obj) {
    if (Array.isArray(obj)) return obj.map(stripNonStandard);
    if (isObj(obj)) {
      var out = {};
      for (var k in obj) if (Object.prototype.hasOwnProperty.call(obj, k) && k.charAt(0) !== '_') out[k] = stripNonStandard(obj[k]);
      return out;
    }
    return obj;
  }

  /** Drop response bodies but keep sizes — shrinks huge HARs, keeps the waterfall intact. */
  function stripResponseBodies(input) {
    var har = JSON.parse(JSON.stringify(input));
    ((har.log && har.log.entries) || []).forEach(function (e) {
      var c = e && e.response && e.response.content;
      if (c && c.text !== undefined) { delete c.text; delete c.encoding; }
    });
    return har;
  }

  /** A tiny HAR that crashes Google's analyzer in several different ways. */
  function brokenSample() {
    return {
      log: {
        version: '1.2',
        creator: { name: 'WebInspector', version: '537.36' },
        pages: [{ startedDateTime: '2026-09-17T19:12:00.000Z', id: 'page_1', title: 'https://example.com/', pageTimings: { onContentLoad: 412, onLoad: 980 } }],
        entries: [
          {
            pageref: 'page_1',
            startedDateTime: '2026-09-17T19:12:00.120Z',
            time: 231.4,
            request: { method: 'GET', url: 'https://example.com/static/app.js', httpVersion: 'http/2.0', headers: [{ name: 'Authorization', value: 'Bearer eyJhbGciOi.example' }], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
            response: {
              status: 200, statusText: '', httpVersion: 'http/2.0', headers: [{ name: 'content-type', value: 'text/javascript' }], cookies: [], redirectURL: '',
              content: { size: 3533145, mimeType: 'text/javascript', encoding: 'base64', text: '[text/javascript redacted]' },
              headersSize: -1, bodySize: -1
            },
            cache: {},
            timings: { blocked: 2.1, dns: -1, connect: -1, send: 0.2, wait: '180.5', receive: 48.6, ssl: -1 }
          },
          {
            startedDateTime: 'bad',
            time: 'n/a',
            request: null,
            response: { status: 200, content: { size: 42, mimeType: 'application/x-www-form-urlencoded', text: 'q=100%&done=1' } },
            timings: { wait: 'fast' }
          },
          {
            startedDateTime: '2026-09-17T19:12:01.004Z',
            time: 12,
            request: { method: 'POST', url: 'https://example.com/api/login', headers: [{ name: 'Cookie', value: 'sid=abc123' }], postData: { mimeType: 'application/json', text: '{"user":"demo","password":"hunter2"}' } },
            response: { status: 200, content: { size: 9999999, mimeType: 'application/json', encoding: 'base64', text: '[REDACTED]' } }
          },
          null
        ]
      }
    };
  }

  var api = {
    VERSION: VERSION,
    parseHARText: parseHARText,
    fixHAR: fixHAR,
    googleCheck: googleCheck,
    sanitizeHAR: sanitizeHAR,
    stripNonStandard: stripNonStandard,
    stripResponseBodies: stripResponseBodies,
    brokenSample: brokenSample,
    isGoogleBase64: isGoogleBase64,
    isRedacted: isRedacted
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') {
    window.HarFixer = api;
    window.fixHAR = fixHAR;
    window.sanitizeHAR = sanitizeHAR;
    window.stripNonStandard = stripNonStandard;
  }
})(this);
