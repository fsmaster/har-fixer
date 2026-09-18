# HAR Fixer

**Make broken, sanitized and truncated HAR files load in [Google HAR Analyzer](https://toolbox.googleapps.com/apps/har_analyzer/).**

🌐 **Live: <https://harfixer.com>**. 100% client-side: your HAR never leaves the browser.

[![test](https://github.com/fsmaster/har-fixer/actions/workflows/test.yml/badge.svg)](https://github.com/fsmaster/har-fixer/actions/workflows/test.yml)

A customer sends a HAR and Google's analyzer shows nothing, or throws
`Unknown base64 encoding at char: [`. HAR Fixer finds the requests that crash the
analyzer, repairs them and gives you back a file that loads. Every change is listed.

## Why Google rejects some HARs

We reverse-engineered the load path in `har_analyzer__en.js`. For every entry it does:

```js
mimeType = (content.mimeType || "").toLowerCase()
encoding = (content.encoding || "").toLowerCase()
if (content.text) {
  if (mimeType.indexOf("urlencoded") > 0)
    text = decodeURIComponent(text.replace(/\+/g, " "))      // throws on bad % sequences
  else if (encoding == "base64" && !mimeType.startsWith("image/"))
    text = goog.crypt.base64.decode(text)                    // throws on non-base64 chars
}
```

One throw rejects **the whole file**.

| Crash | Typical cause | Fix |
|---|---|---|
| `Unknown base64 encoding at char: [` | A sanitizer replaced a body with `[text/javascript redacted]` but kept `encoding: "base64"` and the original multi-MB `size` | Drop `encoding` only where the text isn't valid Google-base64 (`^[\s\xa0A-Za-z0-9+/=_.-]*$`); set `size = text.length` on placeholders. Real images/fonts keep base64. |
| `URIError: URI malformed` | `application/x-www-form-urlencoded` body with a stray `%` | Relabel that body `text/plain` |
| `Unable to process the HAR file` | BOM, trailing commas, truncated export | Strip BOM, remove trailing commas, recover up to the last complete object |
| `No log entries found in the file.` | Bare array, `{har:{log}}`, root-level `entries` | Move entries under `log` |
| Silent crash / blank page | `null` entry, numeric `mimeType`/`method`/header names, `timings: "fast"` | Remove null entries, convert fields to strings/numbers, add stubs |

Other normalization: invalid/epoch `startedDateTime` → ISO (inherits the previous request's time),
non-numeric sizes/timings → numbers (`-1` = n/a), missing `request`/`response`/`content`/`timings`/`cache`
are added, `pageref: null` is deleted, header objects `{Host: "x"}` become `[{name, value}]`.

A valid Chrome/Firefox/Safari HAR passes through **unchanged**.

## Features

- Drag and drop, or a file picker, for `.har` / `.json`. **Load broken sample** gives you a demo file.
- **Google check before and after**: a replica of the analyzer's loader lists which entry would crash it and why.
- A compact fix summary, e.g. `Dropped invalid content.encoding=base64 on 13 redacted/non-base64 bodies (Google HAR Analyzer crash)`
- Options:
  - **Extra sanitize**: empty cookies; redact `Authorization`, `Cookie`, `Set-Cookie`, `Proxy-Authorization`, `x-api-key`, `x-auth-token`, `x-*auth*`, tokens in URLs/query strings, `postData.text` and `content.text`.
  - **Strip non-standard `_fields`** (Chrome's `_initiator`, `_priority`, …)
  - **Drop response bodies** to shrink huge HARs while keeping the waterfall
  - Pretty-print or minified output
- Preview JSON, then download `name.fixed.har`
- Strict CSP in production (`connect-src 'none'`), so the page physically can't upload anything

## Use it

**Web:** <https://harfixer.com>, or run it locally:

```bash
python3 -m http.server 8080    # open http://127.0.0.1:8080
```

**CLI** (Node ≥ 14, zero dependencies):

```bash
node cli.js input.har [output.har] [--sanitize] [--strip-custom] [--strip-bodies] [--compact]
node cli.js input.har --check          # diagnose only; exit 1 if Google would reject it
```

It strips the BOM, runs `JSON.parse` (with recovery), `fixHAR` and the optional passes, and pretty-prints the result.
`Applied N fix(es)` goes to stderr, and the HAR goes to the output file or stdout.

**Library:**

```js
const { parseHARText, fixHAR, googleCheck, sanitizeHAR, stripNonStandard } = require('./fixer.js');
const { har } = parseHARText(text);
const fixed = fixHAR(har);
console.log(fixHAR.lastFixes, googleCheck(fixed)); // [] = loads in Google HAR Analyzer
```

In the browser, `<script src="fixer.js">` exposes `window.HarFixer` plus `fixHAR`, `sanitizeHAR` and `stripNonStandard`.

## Tests

```bash
node test/test.js
```

`test/google-loader.js` is a line-by-line port of the analyzer's load path, including its base64
decoder. The tests check the fixer against Google's own logic, not against the fixer's view of it:
the spec's synthetic case, the sanitized-Chrome pattern (13 redacted bodies plus valid png/woff2/gif),
a known-good Chrome HAR that must pass through unchanged, and JSON recovery.

## Deploy (harfixer.com)

Static files behind nginx: see `deploy/harfixer.nginx` and `deploy/deploy.sh`.

```bash
cd /opt/har-fixer && git pull && sudo ./deploy/deploy.sh
```

## License

MIT © [Igor Marchuk](https://fsmaster.com)
