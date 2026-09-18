'use strict';
/*
 * A line-by-line port of the load path in Google's HAR Analyzer
 * (toolbox.googleapps.com/apps/har_analyzer/js/har_analyzer__en.js):
 * the FileReader "load" handler, the entry loop and the toolbox_Iw entry constructor.
 * It's independent of fixer.js, so the tests can check the fixer against
 * Google's real logic instead of against the fixer's own idea of it.
 * Throws exactly where Google throws.
 */

const trim = (a) => a.trim(); // toolbox_Sa (String.prototype.trim — throws on non-strings)

// toolbox_qb / toolbox_ob: union of the five alphabets
const B64 = {};
(() => {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split('');
  for (const tail of ['+/=', '+/', '-_=', '-_.', '-_']) {
    const d = a.concat(tail.split(''));
    d.forEach((ch, i) => { if (B64[ch] === undefined) B64[ch] = i; });
  }
})();

// toolbox_rb / toolbox_sb
function googleBase64Decode(a) {
  let out = '';
  let d = 0;
  function c(k) {
    while (d < a.length) {
      const l = a.charAt(d++);
      const m = B64[l];
      if (m != null) return m;
      if (!/^[\s\xa0]*$/.test(l)) throw Error('Unknown base64 encoding at char: ' + l);
    }
    return k;
  }
  for (;;) {
    const e = c(-1), f = c(0), g = c(64), h = c(64);
    if (h === 64 && e === -1) break;
    out += String.fromCharCode(e << 2 | f >> 4);
    if (g != 64) { out += String.fromCharCode(f << 4 & 240 | g >> 2); if (h != 64) out += String.fromCharCode(g << 6 & 192 | h); }
  }
  return out;
}

const urlDecode = (a) => decodeURIComponent(a.replace(/\+/g, ' ')); // toolbox_ut

// toolbox_iv + toolbox_jv
function nvList(a) {
  const c = [];
  if (a) for (let d = 0; d < a.length; d++) {
    const x = a[d];
    if (x && x.name) {
      const b = { name: x.name, value: x.value || '' };
      for (const k in x) if (k != 'name' && k != 'value') b[k] = x[k] || '';
      c.push(b);
    }
  }
  return c;
}

// toolbox_Kw(list, name, true) — used by the response checks after load
function findHeaderCI(list, name) {
  for (let d = 0, e; (e = list[d]); d++) if (e.name.toLowerCase() == name.toLowerCase()) return e;
  return null;
}

// toolbox_mv
const num = (a, b = -1) => typeof a === 'number' ? a : typeof a === 'string' ? (isNaN(parseFloat(a)) ? b : parseFloat(a)) : b;

function buildEntry(startedDateTime, time, request, response, timings) {
  trim(startedDateTime || ''); // toolbox_ev
  let a = request;
  const b = {};
  if (!a) a = { method: 'ERROR', url: 'Unknown/Invalid' };
  b.method = trim(a.method || 'GET').toUpperCase();
  b.url = a.url || '/';
  b.query = b.method + ' ' + b.url;
  b.cookies = nvList(a.cookies);
  b.headers = nvList(a.headers);
  b.queryString = nvList(a.queryString);
  if (a.postData) {
    b.postData = { mimeType: (a.postData.mimeType || '').toLowerCase(), params: nvList(a.postData.params), text: a.postData.text || '' };
  }
  // toolbox_hx: browser-channel check on the url
  if (b.query.indexOf('google.com/') > 0) b.url.indexOf('/bind?');

  const e = response || { status: -1 };
  const r = {};
  r.status = e.status || 0;
  r.cookies = nvList(e.cookies);
  r.headers = nvList(e.headers);
  if (e.content) {
    r.content = {
      size: e.content.size || 0,
      mimeType: (e.content.mimeType || '').toLowerCase(),
      text: e.content.text || '',
      encoding: (e.content.encoding || '').toLowerCase(),
    };
    if (r.content.text) {
      if (r.content.mimeType.indexOf('urlencoded') > 0) r.content.text = urlDecode(r.content.text);
      else if (!(r.content.encoding != 'base64' || r.content.mimeType.startsWith('image/'))) r.content.text = googleBase64Decode(r.content.text);
    }
  } else {
    r.content = { size: -1, mimeType: '', text: '', encoding: '' };
  }
  findHeaderCI(r.headers, 'Refresh'); // toolbox_kx
  trim(r.content.mimeType.toLowerCase()); // toolbox_ix
  const t = timings || {};
  for (const k of ['blocked', 'dns', 'connect', 'send', 'wait', 'receive', 'ssl']) t[k] = num(t[k]);
  return { request: b, response: r, time };
}

/** Returns { ok, error } exactly like the analyzer would react to this text. */
function googleLoad(text) {
  let g;
  try { g = JSON.parse(text); } catch (A) { return { ok: false, error: 'Unable to process the HAR file: ' + A }; }
  if (!g.log || !g.log.entries || g.log.entries.length < 1) return { ok: false, error: 'No log entries found in the file.' };
  try {
    const entries = g.log.entries;
    for (let f = 0; f < entries.length; f++) {
      const l = entries[f];
      // page lookup reads l.request.url and l.startedDateTime (crashes on null entries)
      if (!(l.request ? l.request.url : 'x')) void 0;
      buildEntry(l.startedDateTime, l.time, l.request, l.response, l.timings);
    }
  } catch (err) {
    return { ok: false, error: String(err) };
  }
  return { ok: true, error: null };
}

module.exports = { googleLoad, googleBase64Decode };
