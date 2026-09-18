/* HAR Fixer web UI — everything runs locally; no network calls. */
(function () {
  'use strict';
  var F = window.HarFixer;
  var $ = function (id) { return document.getElementById(id); };
  var drop = $('drop'), input = $('input');
  var state = { name: '', bytes: 0, parsed: null, output: '', outName: '' };

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1048576) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function toast(msg) { var t = $('toast'); t.textContent = msg; t.classList.add('show'); clearTimeout(toast.t); toast.t = setTimeout(function () { t.classList.remove('show'); }, 2600); }
  function countEntries(h) { return (h && h.log && h.log.entries && h.log.entries.length) || 0; }
  function countPages(h) { return (h && h.log && Array.isArray(h.log.pages) && h.log.pages.length) || 0; }

  var ICON_BAD = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></svg>';
  var ICON_OK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/></svg>';
  var ICON_WARN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/></svg>';

  function problemsHtml(list, limit) {
    var items = list.slice(0, limit).map(function (p) {
      var where = p.entry === null ? 'file' : 'entry #' + p.entry;
      return '<li><span>' + esc(where) + '</span> ' + esc(p.message) + (p.url ? ' — ' + esc(p.url.length > 90 ? p.url.slice(0, 90) + '…' : p.url) : '') + '</li>';
    }).join('');
    if (list.length > limit) items += '<li>…and ' + (list.length - limit) + ' more</li>';
    return '<ul class="problems">' + items + '</ul>';
  }

  function diagnose() {
    var d = $('diag'), p = state.parsed;
    if (!p.har) {
      d.innerHTML = '<div class="verdict bad">' + ICON_BAD + '<div><b>Not a readable HAR.</b> ' + esc(p.error) + '</div></div>';
      $('fix').disabled = true;
      return;
    }
    $('fix').disabled = false;
    var probs = F.googleCheck(p.har);
    state.before = probs.length;
    var pre = p.fixes.length ? ' The JSON also needs repair: ' + esc(p.fixes.join('; ')) + '.' : '';
    if (probs.length) {
      var n = probs.length >= 200 ? '200+' : probs.length;
      d.innerHTML = '<div class="verdict bad">' + ICON_BAD + '<div><b>Google HAR Analyzer would reject this file</b> (' + n + ' problem' + (probs.length === 1 ? '' : 's') + ', first one: <code>' + esc(probs[0].message) + '</code>).' + pre + problemsHtml(probs, 6) + '</div></div>';
    } else if (p.fixes.length) {
      d.innerHTML = '<div class="verdict bad">' + ICON_BAD + '<div><b>Google HAR Analyzer would reject this file:</b> <code>Unable to process the HAR file</code>.' + pre + '</div></div>';
    } else {
      d.innerHTML = '<div class="verdict good">' + ICON_OK + '<div><b>This HAR already looks loadable</b> in Google HAR Analyzer. Fixing it will still normalize any non-standard fields' + (countEntries(p.har) ? '' : ', but it has no entries') + '.</div></div>';
    }
  }

  function loadText(text, name, bytes) {
    state.name = name; state.bytes = bytes;
    state.parsed = F.parseHARText(text);
    $('fname').textContent = name;
    $('fmeta').textContent = fmtBytes(bytes) + (state.parsed.har ? ' · ' + countEntries(state.parsed.har).toLocaleString() + ' entries' : '');
    $('file').classList.add('show');
    $('result').classList.remove('show');
    drop.style.display = 'none';
    diagnose();
    $('fix').focus();
  }

  function readFile(file) {
    if (!file) return;
    $('fname').textContent = file.name;
    $('fmeta').textContent = 'reading ' + fmtBytes(file.size) + '…';
    var r = new FileReader();
    r.onload = function () { setTimeout(function () { loadText(String(r.result), file.name, file.size); }, 0); };
    r.onerror = function () { toast('Could not read the file: ' + (r.error && r.error.message)); };
    r.readAsText(file);
  }

  function runFix() {
    var btn = $('fix');
    btn.disabled = true; btn.lastChild.textContent = ' Fixing…';
    setTimeout(function () {
      try {
        var har = F.fixHAR(state.parsed.har);
        var fixes = state.parsed.fixes.concat(F.fixHAR.lastFixes || []);
        if ($('optBodies').checked) { har = F.stripResponseBodies(har); fixes.push('Dropped response bodies (sizes and timings kept)'); }
        if ($('optSanitize').checked) {
          har = F.sanitizeHAR(har);
          var s = F.sanitizeHAR.lastStats || {};
          fixes.push('Sanitized: cookies emptied, ' + (s.headers || 0) + ' auth headers, ' + (s.params || 0) + ' secret query params and ' + (s.bodies || 0) + ' bodies redacted');
        }
        if ($('optStrip').checked) { har = F.stripNonStandard(har); fixes.push('Removed non-standard _fields'); }
        var after = F.googleCheck(har);
        state.output = $('optPretty').checked ? JSON.stringify(har, null, 2) : JSON.stringify(har);
        state.outName = state.name.replace(/\.(har|json)$/i, '') + '.fixed.har';
        render(har, fixes, after);
      } catch (e) {
        toast('Fix failed: ' + e.message);
      } finally {
        btn.disabled = false; btn.lastChild.textContent = ' Fix HAR';
      }
    }, 30);
  }

  function render(har, fixes, after) {
    var outBytes = new Blob([state.output]).size;
    var delta = state.bytes ? Math.round((outBytes - state.bytes) / state.bytes * 100) : 0;
    var stat = function (k, v) { return '<div class="stat"><div class="k">' + k + '</div><div class="v">' + v + '</div></div>'; };
    $('stats').innerHTML =
      stat('Entries', countEntries(har).toLocaleString()) +
      stat('Pages', countPages(har).toLocaleString()) +
      stat('Fixes applied', fixes.length) +
      stat('Google check', (state.before || 0) + ' → <span style="color:' + (after.length ? 'var(--bad)' : 'var(--ok)') + '">' + after.length + '</span> <small>crashes</small>') +
      stat('Output size', fmtBytes(outBytes) + ' <small>' + (delta > 0 ? '+' : '') + delta + '%</small>');
    $('fixes').innerHTML = fixes.length
      ? fixes.map(function (f) { return '<li>' + esc(f) + '</li>'; }).join('')
      : '<li class="none">Nothing needed fixing. The file was already valid.</li>';
    if (after.length) {
      $('after').innerHTML = '<div class="verdict warn">' + ICON_WARN + '<div><b>' + after.length + ' problem(s) remain.</b> Please <a href="https://github.com/fsmaster/har-fixer/issues" rel="noopener">open an issue</a> with the message below (not the HAR).' + problemsHtml(after, 5) + '</div></div>';
    } else if (!countEntries(har)) {
      $('after').innerHTML = '<div class="verdict warn">' + ICON_WARN + '<div><b>The HAR has no requests.</b> Google will say “No log entries found in the file.” Record it again with the Network panel open.</div></div>';
    } else {
      $('after').innerHTML = '<div class="verdict good">' + ICON_OK + '<div><b>Ready for Google HAR Analyzer.</b> Download the fixed file and upload it at toolbox.googleapps.com/apps/har_analyzer.</div></div>';
    }
    $('dlname').textContent = 'Download ' + state.outName;
    $('result').classList.add('show');
    $('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function download() {
    var url = URL.createObjectURL(new Blob([state.output], { type: 'application/json' }));
    var a = document.createElement('a');
    a.href = url; a.download = state.outName;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
  }

  function preview() {
    var LIMIT = 300000, s = state.output;
    $('mpre').textContent = s.length > LIMIT ? s.slice(0, LIMIT) + '\n\n… (' + fmtBytes(s.length - LIMIT) + ' more, download to see it all)' : s;
    $('mnote').textContent = fmtBytes(s.length);
    var m = $('modal');
    if (m.showModal) m.showModal(); else m.setAttribute('open', '');
  }

  function reset() {
    state = { name: '', bytes: 0, parsed: null, output: '', outName: '' };
    input.value = '';
    $('file').classList.remove('show');
    $('result').classList.remove('show');
    drop.style.display = '';
    drop.focus();
  }

  // dropzone: clicking anywhere opens the picker, except the inner buttons (no double dialog)
  drop.addEventListener('click', function () { input.click(); });
  drop.addEventListener('keydown', function (e) { if (e.target === drop && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); input.click(); } });
  $('choose').addEventListener('click', function (e) { e.stopPropagation(); input.click(); });
  $('sample').addEventListener('click', function (e) {
    e.stopPropagation();
    var text = JSON.stringify(F.brokenSample(), null, 2);
    loadText(text, 'broken-sample.har', new Blob([text]).size);
  });
  input.addEventListener('click', function (e) { e.stopPropagation(); });
  input.addEventListener('change', function () { readFile(input.files && input.files[0]); });
  ['dragenter', 'dragover'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
  ['dragleave', 'drop'].forEach(function (t) { drop.addEventListener(t, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
  drop.addEventListener('drop', function (e) { readFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]); });
  // dropping anywhere on the page works too, and never navigates away
  window.addEventListener('dragover', function (e) { e.preventDefault(); });
  window.addEventListener('drop', function (e) { e.preventDefault(); if (e.target !== drop && !drop.contains(e.target)) readFile(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]); });

  $('fix').addEventListener('click', runFix);
  $('reset').addEventListener('click', reset);
  $('download').addEventListener('click', download);
  $('preview').addEventListener('click', preview);
  $('mclose').addEventListener('click', function () { $('modal').close(); });
  $('modal').addEventListener('click', function (e) { if (e.target === this) this.close(); });
})();
