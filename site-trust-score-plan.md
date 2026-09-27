# Site Trust Score — Chrome Extension Plan

## Overview

Build a Manifest V3 Chrome/Edge extension called **Site Trust Score** that passively analyzes the current webpage and assigns a trust score (0–100), displayed as a colored badge on the extension icon. Analysis happens in two levels:

- **Level 1** (automatic, every page load): HTTPS check, security headers, cookie flags, Google Safe Browsing lookup.
- **Level 2** (manual, triggered via popup): vulnerable JS libraries, mixed content, form security heuristics, exposed secrets in source.

**Constraints:** Plain HTML/CSS/JS only. No frameworks, no build step, no external npm packages. Passive analysis only — no active probing of hidden endpoints.

---

## Architecture

### Component Roles

| File | Role |
|---|---|
| `manifest.json` | MV3 manifest; declares permissions, content scripts, service worker, popup |
| `config.js` | Hardcoded Safe Browsing API key + vulnerable library version patterns |
| `background.js` | Service worker: imports `scoring.js`, owns header cache per tab (headers + parsed `Set-Cookie` flags), calls Safe Browsing API, calculates score, updates badge, fires notifications, routes messages |
| `content.js` | Injected into every page: collects URL, HTTPS status, DOM data, scripts; sends Level 1 data on load; sends Level 2 data on demand. Does NOT handle cookie flags — those are read from response headers in background. |
| `scoring.js` | Pure standalone scoring module: exports `calculateScore(findings)` — no side effects, no browser APIs |
| `popup.html` | Extension popup UI: score display, risk label, collapsible `<details>` sections per category, "Run Deep Scan" button |
| `popup.js` | Requests cached results from background via messages; triggers Level 2 scan; updates UI |
| `icons/` | 16, 48, 128 px icons in three color states: green (Safe), yellow (Caution), red (Risky) |

### Data Flow

```
Page Load
  └─> content.js (Level 1 collect) ──message──> background.js
        └─> chrome.webRequest cache (headers + Set-Cookie flags for this tab)
        └─> Safe Browsing API call
        └─> scoring.js.calculateScore(findings)
        └─> chrome.action.setBadgeText/Color
        └─> chrome.storage.session check → notification if Risky + unseen domain

User clicks icon
  └─> popup.html opens
        └─> popup.js ──message──> background.js (GET_RESULTS)
              └─> returns cached score + findings
        └─> popup.js renders score, label, collapsible sections

User clicks "Run Deep Scan"
  └─> popup.js ──message──> background.js (RUN_DEEP_SCAN)
        └─> background.js ──message──> content.js (COLLECT_LEVEL2)
              └─> content.js scans DOM, scripts, forms, comments
              └─> returns Level 2 findings to background.js
        └─> background.js merges Level 1 + Level 2 findings
        └─> scoring.js.calculateScore(allFindings)
        └─> updates badge + returns full results to popup.js
  └─> popup.js re-renders with full findings
```

### Scoring Rules

Start at 100. Apply deductions in order, then clamp to [0, 100].

| Finding | Deduction | Cap |
|---|---|---|
| Not HTTPS | -30 | — |
| Safe Browsing flagged | Force score to 0–10 | — |
| Form action over HTTP | -25 | — |
| Missing CSP header | -10 | — |
| Cookie missing Secure flag | -10 | -15 total |
| Cookie missing HttpOnly flag | -8 | -12 total |
| Missing HSTS | -5 | — |
| Missing X-Frame-Options | -5 | — |
| Missing X-Content-Type-Options | -3 | — |
| Form without CSRF token heuristic | -5 | — |
| Exposed API key/secret in source (L2) | -30 | — |
| Vulnerable JS library (L2, per library) | -15 | -30 total |
| Mixed content (L2) | -10 | — |
| Exposed internal path/comment (L2) | -5 | -10 total |

Risk labels: **Safe** (80–100) · **Caution** (50–79) · **Risky** (0–49)

### Vulnerable Library List (initial — extensible)

Defined as an array of objects in `config.js`:
- jQuery < 3.5
- Angular 1.x (any 1.x version)
- Bootstrap < 4

Each entry has: `name`, `pattern` (regex to detect version string in script src or inline), `maxSafeVersion`.

---

## Sub-Tasks

---

### Sub-Task 1 — Manifest + Skeleton Files

**Intent:** Establish the full file structure and permissions upfront so every subsequent sub-task has a valid, loadable extension to build on.

**Expected Outcomes:**
- Extension loads in Chrome without errors (`chrome://extensions` → Load unpacked).
- All files exist with correct names and empty/stub content.
- All required permissions declared in manifest.

**Todo List:**
- [x] Create `manifest.json` with: `manifest_version: 3`, name, version, description, `action` (popup), `background` service worker, `content_scripts` (matches `<all_urls>`), permissions: `activeTab`, `scripting`, `storage`, `notifications`, `webRequest`, `host_permissions: ["<all_urls>"]`.
- [x] Create stub `background.js` (single console.log to confirm load).
- [x] Create stub `content.js` (single console.log).
- [x] Create stub `scoring.js` (export placeholder function).
- [x] Create stub `popup.html` with `<script src="popup.js">`.
- [x] Create stub `popup.js`.
- [x] Create stub `config.js`.
- [x] Create `icons/` directory with placeholder icon files (16, 48, 128 px) — can be simple colored PNGs for now.
- [x] Verify extension loads in Chrome with no manifest errors.

**Relevant Context:**
- MV3 service workers use `importScripts()` to load shared modules (not ES module `import` unless `"type": "module"` is set in manifest background — keep it simple, use `importScripts`).
- `webRequest` in MV3: `chrome.webRequest` is available for reading headers; `webRequestBlocking` is not available in MV3 for modification but is not needed here.
- Content scripts declared in manifest run at `document_idle` by default.

**Status:** [x] done

---

### Sub-Task 2 — Header Capture in Background

**Intent:** Intercept HTTP response headers for every tab load in the background service worker and cache them by `tabId`. This is the only reliable way to read security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) in MV3.

**Expected Outcomes:**
- `background.js` registers a `chrome.webRequest.onHeadersReceived` listener.
- Headers for the most recent main-frame navigation of each tab are stored in an in-memory `Map<tabId, headersObject>`.
- Old entries are cleaned up when a tab is removed (`chrome.tabs.onRemoved`).
- `console.log` in background confirms headers are captured when navigating to any HTTPS site.

**Todo List:**
- [ ] In `background.js`, register `chrome.webRequest.onHeadersReceived` listener with filter `{urls: ["<all_urls>"], types: ["main_frame"]}` and `extraInfoSpec: ["responseHeaders"]`.
- [ ] Parse the `responseHeaders` array into a normalized flat object (lowercase header names → value string) and store in a `tabHeaderCache` Map keyed by `tabId`.
- [ ] **Also parse all `set-cookie` response headers** (there may be multiple) into an array of `{ name, secure, httpOnly }` objects by inspecting each `Set-Cookie` string for the `; Secure` and `; HttpOnly` attribute tokens. Store this parsed cookie list alongside the other headers in `tabHeaderCache` (e.g. as `tabHeaderCache[tabId].cookies`).
- [ ] Register `chrome.tabs.onRemoved` to delete stale entries from the cache.
- [ ] Export/expose a `getHeadersForTab(tabId)` helper (returns `{ headers, cookies }`) for use later in the scoring pipeline.

**Relevant Context:**
- `responseHeaders` is an array of `{name, value}` objects — must be normalized to `{ "content-security-policy": "...", ... }`.
- `Set-Cookie` headers: the `responseHeaders` array can contain **multiple entries with the name `set-cookie`** (one per cookie). Each value is a string like `sessionId=abc; Path=/; Secure; HttpOnly`. Parse each one by splitting on `;` and checking for the `Secure` and `HttpOnly` tokens (case-insensitive).
- This is the **only reliable source** of cookie flag data — `document.cookie` exposes names/values only, never the flags.
- Service worker memory is not persistent across restarts; cache will be empty on restart — this is acceptable, score will recalculate on next navigation.

**Status:** [ ] pending

---

### Sub-Task 3 — Level 1 Content Script Collection

**Intent:** `content.js` collects the Level 1 data available in the page context (URL, HTTPS status) and sends it to `background.js` via `chrome.runtime.sendMessage` on page load. Cookie flag detection (Secure and HttpOnly) is **not** done here — it is handled entirely in background via `Set-Cookie` response header parsing (see Sub-Task 2).

**Expected Outcomes:**
- On every page load, `background.js` receives a `LEVEL1_DATA` message containing:
  - `url`: current page URL
  - `isHttps`: boolean
  - `hostname`: extracted from URL
- Background logs the received data and correlates it with the already-cached headers and cookie flags for that tab.

**Todo List:**
- [ ] In `content.js`, on `DOMContentLoaded` (or immediately at `document_idle`), collect: `window.location.href`, `window.location.protocol === 'https:'`, `window.location.hostname`.
- [ ] Send `{ type: 'LEVEL1_DATA', payload: { url, isHttps, hostname } }` to background via `chrome.runtime.sendMessage`.
- [ ] In `background.js`, add a `chrome.runtime.onMessage` listener that handles `LEVEL1_DATA` and logs the payload alongside the cached headers and cookie flags for the same tab.
- [ ] **Do not include any `document.cookie` parsing in content.js** — cookie flag detection belongs entirely in background via `Set-Cookie` header parsing. Add a code comment explaining this.

**Relevant Context:**
- `document.cookie` exposes only name/value pairs, never the Secure or HttpOnly flags — these flags are only visible in the raw `Set-Cookie` response header, which is available to the `chrome.webRequest` listener in background.
- This correction applies to both the Secure and the HttpOnly flag: neither can be detected from `document.cookie`.

**Status:** [ ] pending

---

### Sub-Task 4 — Scoring Engine (Level 1 Rules)

**Intent:** Implement `scoring.js` as a pure, side-effect-free module that takes a `findings` object and returns `{ score, label, breakdown }`. This is the single source of truth for all scoring logic.

**Expected Outcomes:**
- `calculateScore(findings)` correctly applies all deductions from the scoring table.
- Caps are respected (cookie Secure cap -15, cookie HttpOnly cap -12).
- Safe Browsing override forces score to 0–10.
- Returns `{ score: Number, label: 'Safe'|'Caution'|'Risky', breakdown: Array<{category, finding, deduction}> }`.
- Unit-testable in isolation (no browser APIs required).

**Todo List:**
- [ ] Define `calculateScore(findings)` in `scoring.js`.
- [ ] Implement each deduction rule in order, accumulating into a `breakdown` array.
- [ ] Apply cookie caps: sum per-cookie Secure deductions, cap at 15; sum per-cookie HttpOnly deductions, cap at 12.
- [ ] Apply Safe Browsing override last (if flagged, clamp score to max 10).
- [ ] Apply Level 2 deductions conditionally (only if `findings.level2` is present).
- [ ] Apply vulnerable library cap at -30 total.
- [ ] Apply exposed path cap at -10 total.
- [ ] Clamp final score to [0, 100].
- [ ] Map score to label: ≥80 → 'Safe', 50–79 → 'Caution', <50 → 'Risky'.
- [ ] In `background.js`, add `importScripts('scoring.js')` at the top.
- [ ] Manually test with mock findings objects in browser console.

**Relevant Context:**
- `scoring.js` must not reference any `chrome.*` APIs — pure logic only.
- The `breakdown` array will be used directly by `popup.js` to render per-finding rows.

**Status:** [x] done

---

### Sub-Task 5 — Badge Update Logic

**Intent:** Wire the scoring result into the extension's action badge so the icon reflects the current page's trust level at all times.

**Expected Outcomes:**
- Badge text shows the numeric score (e.g. "72").
- Badge background color: green (`#2ecc71`) for Safe, yellow (`#f39c12`) for Caution, red (`#e74c3c`) for Risky.
- Badge updates every time a page finishes loading in the active tab.
- Navigating to a new page resets and recalculates the badge.

**Todo List:**
- [ ] In `background.js`, create `updateBadge(tabId, score, label)` that calls `chrome.action.setBadgeText` and `chrome.action.setBadgeBackgroundColor`.
- [ ] After receiving `LEVEL1_DATA`, retrieve cached headers for the tab, run `calculateScore`, call `updateBadge`.
- [ ] Call `chrome.action.setBadgeText({ text: '', tabId })` on `chrome.tabs.onUpdated` when `changeInfo.status === 'loading'` to clear the stale badge during navigation.
- [ ] Store the latest `{ score, label, breakdown }` per tab in a `tabResultsCache` Map for later retrieval by the popup.

**Relevant Context:**
- `chrome.action.setBadgeText` requires `{ text: string, tabId: number }`.
- Badge text has limited space — 4 characters max renders cleanly; 2–3 digit numbers are fine.

**Status:** [ ] pending

---

### Sub-Task 6 — Safe Browsing API Integration

**Intent:** Query the Google Safe Browsing Lookup API v4 for the current page's URL and factor the result into the score. Skip gracefully if the API key is blank or the request fails.

**Expected Outcomes:**
- If `SAFE_BROWSING_API_KEY` in `config.js` is non-empty, background fetches the Safe Browsing API for the hostname.
- If the domain is flagged, `findings.safeBrowsingFlagged = true` is set before scoring.
- If the key is blank or the request errors, `findings.safeBrowsingFlagged = false` (no penalty).
- API call happens in `background.js` (service workers can `fetch`; content scripts should not make cross-origin calls).

**Todo List:**
- [ ] In `config.js`, define `const SAFE_BROWSING_API_KEY = '';` (blank placeholder).
- [ ] In `background.js`, implement `checkSafeBrowsing(url)` that POSTs to `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=KEY` with the appropriate request body.
- [ ] Return `true` if any match is returned, `false` otherwise.
- [ ] Wrap in try/catch; on any error or empty key, return `false`.
- [ ] Call `checkSafeBrowsing` as part of the Level 1 pipeline (after receiving `LEVEL1_DATA`, before scoring).

**Relevant Context:**
- Safe Browsing v4 `threatMatches:find` endpoint takes a JSON body with `threatInfo.urlList`.
- The `host_permissions: ["<all_urls>"]` already declared in manifest allows the `fetch` call.

**Status:** [ ] pending

---

### Sub-Task 7 — Notification Logic

**Intent:** Show a browser notification exactly once per domain per browser session when a page is rated Risky, to alert the user without spamming on every reload.

**Expected Outcomes:**
- When a page scores Risky (<50) and the domain has not been notified this session, a notification fires.
- Subsequent loads of the same domain (including reloads) do not fire again.
- Notification is cleared from `chrome.storage.session` when the browser closes (session storage semantics).
- Notification has a meaningful title and body referencing the domain and score.

**Todo List:**
- [ ] After scoring, check `chrome.storage.session.get('notifiedDomains')` (a stored Set/array of hostnames).
- [ ] If score label is 'Risky' and hostname not in the set, call `chrome.notifications.create` with title "⚠️ Risky Site Detected" and body including hostname + score.
- [ ] Add hostname to `notifiedDomains` in `chrome.storage.session`.
- [ ] Ensure `notifications` permission is declared in manifest.

**Relevant Context:**
- `chrome.storage.session` was introduced in Chrome 102 — safe for the target audience.
- `chrome.notifications` requires the `notifications` permission in manifest.

**Status:** [ ] pending

---

### Sub-Task 8 — Popup UI (Level 1 Results Display)

**Intent:** Build the popup UI that displays the current tab's cached Level 1 results — score, risk label, and collapsible per-category findings — without triggering any new analysis.

**Expected Outcomes:**
- Popup opens and immediately displays the cached score and risk label for the current tab.
- Score is shown as a large number with color matching the badge.
- Collapsible `<details>`/`<summary>` sections show findings per category (e.g. "Headers", "Cookies", "HTTPS", "Safe Browsing") with individual deductions.
- If no results are cached yet (e.g. popup opened before page finished loading), shows a "Analyzing…" placeholder.
- "Run Deep Scan" button is visible but disabled until Level 2 is implemented.

**Todo List:**
- [ ] Build `popup.html`: score circle/badge, label text, `<details>` sections for each category, "Run Deep Scan" button.
- [ ] Style with plain CSS: color-coded score display, clean findings list, responsive within popup constraints (max ~400px wide).
- [ ] In `popup.js`, on `DOMContentLoaded`, get current tab ID via `chrome.tabs.query({ active: true, currentWindow: true })`.
- [ ] Send `{ type: 'GET_RESULTS', tabId }` to background and receive `{ score, label, breakdown }`.
- [ ] Render: populate score display, set color class, iterate `breakdown` to fill `<details>` sections.
- [ ] In `background.js`, handle `GET_RESULTS` message — return from `tabResultsCache` for the requested `tabId`.
- [ ] Handle missing cache entry gracefully (return null → popup shows placeholder).

**Relevant Context:**
- Popup JS cannot use `importScripts` — it is a normal HTML page context. All communication must go through `chrome.runtime.sendMessage`.
- `<details>`/`<summary>` collapsible behavior is native CSS — no JS toggle needed.

**Status:** [ ] pending

---

### Sub-Task 9 — Level 2 Content Scan

**Intent:** Implement the deep-scan data collection in `content.js` that runs on demand (triggered by the popup), gathering data for vulnerable library detection, mixed content, form security, and exposed secrets.

**Expected Outcomes:**
- When `background.js` sends `{ type: 'COLLECT_LEVEL2' }` to the content script, it returns:
  - `vulnerableLibraries`: array of `{ name, detectedVersion, reason }` for each match against `config.js` patterns
  - `mixedContent`: array of HTTP resource URLs found on an HTTPS page
  - `unsafeForms`: array of `{ action, hasCsrfToken }` for forms missing HTTPS action or CSRF-like input
  - `exposedSecrets`: array of `{ type, snippet }` for API keys / tokens found in page source
  - `exposedPaths`: array of `{ snippet }` for internal paths found in comments or source

**Todo List:**
- [ ] In `content.js`, add a `chrome.runtime.onMessage` listener for `COLLECT_LEVEL2`.
- [ ] Detect vulnerable libraries: iterate `document.scripts`, check `src` attribute and `textContent` against patterns in `config.js`; also check for version-bearing global variables (e.g. `jQuery.fn.jquery`, `angular.version.full`, `$.fn.jquery`).
- [ ] Detect mixed content: query `document.querySelectorAll('img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]')` — only flag on HTTPS pages.
- [ ] Detect unsafe forms: for each `<form>`, check `action` starts with `http://`; check for hidden input whose name contains "csrf", "token", or "_token".
- [ ] Detect exposed secrets: scan `document.documentElement.innerHTML` with regex patterns for common API key formats (e.g. `AIza[0-9A-Za-z-_]{35}` for Google, `sk-[a-zA-Z0-9]{48}` for OpenAI, generic `api[_-]?key\s*=\s*['"][^'"]{16,}['"]`).
- [ ] Detect exposed paths: scan HTML comments (`<!-- ... -->`) for Unix-style paths, Windows paths, or common internal paths.
- [ ] Return all findings as the message response.
- [ ] In `config.js`, define the `VULNERABLE_LIBRARIES` array with the initial 3 entries (jQuery <3.5, Angular 1.x, Bootstrap <4), each with `{ name, globalVar, versionRegex, maxSafeVersion }`.

**Relevant Context:**
- Content scripts have full DOM access but no `chrome.storage` access (without `storage` permission granted to content scripts — keep communication through background).
- Regex patterns for secrets should be conservative to minimize false positives.
- `document.documentElement.innerHTML` gives the full rendered DOM source; HTML comments are preserved.

**Status:** [ ] pending

---

### Sub-Task 10 — Level 2 Scoring + Popup Wiring

**Intent:** Connect the "Run Deep Scan" button in the popup to the Level 2 collection pipeline, recalculate the full score including Level 2 findings, and update both badge and popup UI.

**Expected Outcomes:**
- Clicking "Run Deep Scan" triggers the full Level 2 pipeline.
- Button shows a loading state during the scan.
- Popup re-renders with the updated score and new Level 2 findings sections.
- Badge updates to reflect the new score.
- `tabResultsCache` is updated with the full results.

**Todo List:**
- [ ] In `popup.js`, attach click handler to "Run Deep Scan" button; disable button and show "Scanning…" text.
- [ ] Send `{ type: 'RUN_DEEP_SCAN', tabId }` to `background.js`.
- [ ] In `background.js`, handle `RUN_DEEP_SCAN`: use `chrome.tabs.sendMessage(tabId, { type: 'COLLECT_LEVEL2' })` to trigger content script.
- [ ] Merge Level 2 findings with existing Level 1 findings for the tab; call `calculateScore` with combined findings.
- [ ] Update `tabResultsCache` and badge.
- [ ] Return updated `{ score, label, breakdown }` to popup.
- [ ] In `popup.js`, re-render the full UI with updated results; re-enable button (or hide it since scan is done).
- [ ] Ensure `breakdown` categories for Level 2 findings (Libraries, Mixed Content, Forms, Secrets, Paths) appear as new `<details>` sections in popup.

**Relevant Context:**
- `chrome.tabs.sendMessage` returns a promise in MV3 — use `await`.
- Level 2 `<details>` sections should only appear after deep scan has run — conditionally render based on presence of Level 2 data in breakdown.

**Status:** [ ] pending

---

## Build & Test Order

```
Sub-Task 1  →  Sub-Task 2  →  Sub-Task 3  →  Sub-Task 4
                                                    ↓
Sub-Task 6  ←  Sub-Task 5  ←──────────────────────┘
     ↓
Sub-Task 7  →  Sub-Task 8  →  Sub-Task 9  →  Sub-Task 10
```

Each sub-task produces a loadable, testable extension state. Never merge a sub-task that breaks the extension load.
