// background.js — Service worker for Site Trust Score extension
// Uses importScripts (not ES modules) to load shared modules.

importScripts('scoring.js');
importScripts('secrets.js');
importScripts('config.js');

console.log('[SiteTrustScore] background service worker loaded');

// ---------------------------------------------------------------------------
// Sub-Task 2 — Header Capture in Background
// ---------------------------------------------------------------------------

// In-memory cache: tabId → { headers: Object, cookies: Array<{name,secure,httpOnly}> }
const tabHeaderCache = new Map();

function parseResponseHeaders(responseHeaders) {
  const headers = {};
  const cookies = [];

  for (const { name, value } of responseHeaders) {
    const lower = name.toLowerCase();

    if (lower === 'set-cookie') {
      const parts = value.split(';').map((p) => p.trim());
      const cookieName = parts[0].split('=')[0].trim();
      const lowerParts = parts.map((p) => p.toLowerCase());
      cookies.push({
        name: cookieName,
        secure: lowerParts.includes('secure'),
        httpOnly: lowerParts.includes('httponly'),
      });
    } else {
      headers[lower] = value;
    }
  }

  return { headers, cookies };
}

function getHeadersForTab(tabId) {
  return tabHeaderCache.get(tabId) ?? null;
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const { tabId, responseHeaders } = details;
    if (tabId < 0) return;
    const parsed = parseResponseHeaders(responseHeaders);
    tabHeaderCache.set(tabId, parsed);
    console.log(
      `[SiteTrustScore] Headers captured for tab ${tabId}:`,
      Object.keys(parsed.headers),
      '| cookies:', parsed.cookies.length
    );
  },
  { urls: ['<all_urls>'], types: ['main_frame'] },
  ['responseHeaders']
);

chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeaderCache.delete(tabId);
  tabResultsCache.delete(tabId);
});

// ---------------------------------------------------------------------------
// Sub-Task 5 — Badge Update Logic
// ---------------------------------------------------------------------------

// In-memory cache: tabId → { score, label, breakdown, url, hostname }
const tabResultsCache = new Map();

const BADGE_COLORS = {
  Safe:    '#2ecc71',
  Caution: '#f39c12',
  Risky:   '#e74c3c',
};

/**
 * The ONLY function that calls setBadgeText / setBadgeBackgroundColor.
 * Nothing else in this file touches those APIs.
 */
function updateBadge(tabId, score, label) {
  const text  = String(score);
  const color = BADGE_COLORS[label] ?? '#888888';
  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  console.log(`[SiteTrustScore] updateBadge tab=${tabId} text="${text}" color=${color}`);
}

// ---------------------------------------------------------------------------
// Sub-Task 6 — Safe Browsing API
// ---------------------------------------------------------------------------

/**
 * Queries the Google Safe Browsing Lookup API v4 for the given URL.
 * Returns true if the URL is flagged as a threat, false in all other cases
 * (key blank, request error, no matches).  Never throws.
 *
 * @param {string} url
 * @returns {Promise<boolean>}
 */
async function checkSafeBrowsing(url) {
  if (!SAFE_BROWSING_API_KEY) return false;

  const endpoint =
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;

  const body = {
    client: { clientId: 'site-trust-score', clientVersion: '1.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!response.ok) return false;

    const data = await response.json();
    // matches is an array; any entry means the URL is flagged
    return Array.isArray(data.matches) && data.matches.length > 0;
  } catch (_err) {
    // Network error, parse error, or any unexpected failure — treat as safe
    return false;
  }
}

// ---------------------------------------------------------------------------
// Sub-Task 3 — Level 1 Message Handler
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Sub-Task 8 — GET_RESULTS handler (used by popup.js)
// ---------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'GET_RESULTS') {
    const cached = tabResultsCache.get(message.tabId) ?? null;
    sendResponse(cached);
    return; // synchronous response — no need to return true
  }
});

// ---------------------------------------------------------------------------
// Sub-Task 10 — RUN_DEEP_SCAN handler
// ---------------------------------------------------------------------------
//
// Flow:
//   popup.js  ──RUN_DEEP_SCAN──>  background.js
//     background.js  ──COLLECT_LEVEL2──>  content.js  (with 10s timeout)
//     background.js  calls mergeLevel2() directly  (no self-messaging)
//     background.js  returns updated { score, label, breakdown, … } to popup
//
// Why chrome.tabs.sendMessage and NOT chrome.runtime.sendMessage to self:
//   Service workers cannot receive messages sent to themselves via
//   chrome.runtime.sendMessage — the call silently fails.  The correct pattern
//   is to forward the message to the content script that lives in the tab.

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== 'RUN_DEEP_SCAN') return;

  const { tabId } = message;
  if (tabId == null) {
    sendResponse({ ok: false, error: 'Missing tabId' });
    return true;
  }

  (async () => {
    // -- 1. Send COLLECT_LEVEL2 to the content script in the target tab ------
    //    Wrap in a Promise.race so we never hang forever if the content script
    //    is absent (chrome:// pages, restricted tabs, etc.).
    const TIMEOUT_MS = 10_000;

    let l2Response;
    try {
      l2Response = await Promise.race([
        chrome.tabs.sendMessage(tabId, { type: 'COLLECT_LEVEL2' }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('timeout')), TIMEOUT_MS)
        ),
      ]);
    } catch (err) {
      const isTimeout = err.message === 'timeout';
      const errMsg = isTimeout
        ? 'Deep scan timed out — the page may not support content scripts (e.g. chrome:// pages).'
        : `Deep scan failed: ${err.message}`;
      console.warn('[SiteTrustScore] RUN_DEEP_SCAN error:', errMsg);
      sendResponse({ ok: false, error: errMsg });
      return;
    }

    // content.js sends back { type: 'LEVEL2_DATA', payload: { … } }
    if (!l2Response || !l2Response.payload) {
      sendResponse({ ok: false, error: 'Content script returned no Level 2 data.' });
      return;
    }

    // -- 2. Merge + rescore (updates tabResultsCache + badge) ----------------
    const mergeResult = await mergeLevel2(tabId, l2Response.payload);
    if (!mergeResult.ok) {
      sendResponse({ ok: false, error: mergeResult.error });
      return;
    }

    // -- 3. Return the full updated result so popup can re-render ------------
    const updated = tabResultsCache.get(tabId) ?? null;
    sendResponse({ ok: true, result: updated });
  })();

  return true; // keep the message channel open for the async response
});

// ---------------------------------------------------------------------------
// Sub-Task 9 — Level 2 merge/rescore
// ---------------------------------------------------------------------------
//
// mergeLevel2(tabId, l2payload) is a plain async function so it can be called
// directly from within the service worker (Sub-Task 10's RUN_DEEP_SCAN handler)
// without the service worker trying to message itself — which doesn't work.
//
// Test from the service-worker DevTools console:
//
//   NOTE: omit `currentWindow:true` — the DevTools panel steals that context.
//
//   chrome.tabs.query({active:true}, (tabs) => {
//     const tab = tabs.find(t => /^https?:/.test(t.url));
//     if (!tab) { console.error('No http(s) tab found'); return; }
//     chrome.tabs.sendMessage(tab.id, {type:'COLLECT_LEVEL2'}, async (l2) => {
//       console.log('L2 raw payload:', l2);
//       const r = await mergeLevel2(tab.id, l2.payload);
//       console.log('Merge result:', r);
//     });
//   });

/**
 * Merge Level 2 findings with the cached Level 1 data for a tab, re-score,
 * update the badge, and return { ok, score, label } (or { ok:false, error }).
 *
 * @param {number} tabId
 * @param {object} l2payload  — the payload from content.js's COLLECT_LEVEL2 response
 * @returns {Promise<{ok:boolean, score?:number, label?:string, error?:string}>}
 */
async function mergeLevel2(tabId, l2payload) {
  if (!l2payload) {
    console.warn('[SiteTrustScore] mergeLevel2: no payload');
    return { ok: false, error: 'no payload' };
  }

  const existing = tabResultsCache.get(tabId);
  if (!existing) {
    console.warn(`[SiteTrustScore] mergeLevel2: no Level 1 cache for tab=${tabId}`);
    return { ok: false, error: 'No Level 1 data cached for this tab' };
  }

  const cached = getHeadersForTab(tabId);

  const mergedFindings = {
    isHttps:             existing.url ? existing.url.startsWith('https:') : false,
    // Stored directly in L1 cache entry — reliable even when score was already ≤10.
    safeBrowsingFlagged: existing.safeBrowsingFlagged ?? false,
    headers: cached ? cached.headers : {},
    cookies: cached ? cached.cookies : [],
    // Level 2 surfaces real form data; Level 1 had an empty array.
    forms: (l2payload.unsafeForms || []).map((f) => ({
      action:       f.action,
      hasCsrfToken: f.hasCsrfToken,
    })),
    level2: {
      exposedSecret:       l2payload.exposedSecrets.length > 0,
      vulnerableLibraries: l2payload.vulnerableLibraries,
      mixedContent:        l2payload.mixedContent.length > 0,
      exposedPaths:        l2payload.exposedPaths,
    },
  };

  const result = calculateScore(mergedFindings);

  tabResultsCache.set(tabId, {
    ...result,
    url:                existing.url,
    hostname:           existing.hostname,
    safeBrowsingFlagged: existing.safeBrowsingFlagged ?? false,
    // Flag read by popup.js on reopen to restore the "Scan Complete" button state.
    level2Done: true,
    // Raw L2 detail kept for popup rendering in Sub-Task 10.
    level2Detail: {
      vulnerableLibraries: l2payload.vulnerableLibraries,
      mixedContent:        l2payload.mixedContent,
      unsafeForms:         l2payload.unsafeForms,
      exposedSecrets:      l2payload.exposedSecrets,
      exposedPaths:        l2payload.exposedPaths,
    },
  });

  updateBadge(tabId, result.score, result.label);

  console.log(
    `[SiteTrustScore] Level 2 merged tab=${tabId} (${existing.hostname}):`,
    `score=${result.score} label=${result.label}`,
    '| libs=' + l2payload.vulnerableLibraries.length,
    'mixed=' + l2payload.mixedContent.length,
    'forms=' + l2payload.unsafeForms.length,
    'secrets=' + l2payload.exposedSecrets.length,
    'paths=' + l2payload.exposedPaths.length
  );

  return { ok: true, score: result.score, label: result.label };
}

// Message listener — used by Sub-Task 10's RUN_DEEP_SCAN handler (popup → background).
// Content-script messages arrive here; the function above does the real work.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'LEVEL2_DATA') return;

  const tabId = message.tabId ?? sender.tab?.id;
  if (tabId == null) {
    console.warn('[SiteTrustScore] LEVEL2_DATA: missing tabId');
    sendResponse({ ok: false, error: 'missing tabId' });
    return true;
  }

  mergeLevel2(tabId, message.payload).then(sendResponse);
  return true; // keep channel open for the async response
});

// ---------------------------------------------------------------------------
// Pre-Scan — PRESCAN_URL handler
// ---------------------------------------------------------------------------
//
// Checks a URL independently of any open tab.  Level 1 signals only:
//   1. HTTPS from the URL string itself (no I/O).
//   2. Safe Browsing via checkSafeBrowsing() — reused as-is.
//   3. Single HEAD request with a 5-second AbortController timeout to read
//      the four security response headers.  No body is fetched; no HTML
//      parsing; no Level 2 content scanning.
//   4. calculateScore() on the collected findings.
//
// Returns { ok, result } where result carries preliminary:true so popup.js
// can label it "Preliminary Check".

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== 'PRESCAN_URL') return;

  const { url } = message;
  if (!url) {
    sendResponse({ ok: false, error: 'No URL provided.' });
    return true;
  }

  (async () => {
    // trySend — absorbs "disconnected port" errors that occur when the popup
    // closes before the async work completes.  Without this guard the throw
    // from sendResponse() on a dead port becomes an unhandled Promise
    // rejection that Chrome treats as fatal and terminates the service worker.
    function trySend(payload) {
      try { sendResponse(payload); } catch (_) { /* port already closed */ }
    }

    // One AbortController, 5-second hard limit covering Safe Browsing + HEAD.
    const abortCtrl  = new AbortController();
    const abortTimer = setTimeout(() => abortCtrl.abort(), 5_000);

    try {
      // 1. HTTPS — synchronous, no I/O.
      let isHttps = false;
      try {
        isHttps = new URL(url).protocol === 'https:';
      } catch (_) {
        trySend({ ok: false, error: 'Invalid URL.' });
        return;
      }

      // 2. Safe Browsing — has its own internal try/catch, never throws.
      const safeBrowsingFlagged = await checkSafeBrowsing(url);

      // 3. HEAD request — reads security headers, no body.
      //    CORS blocks many sites; fall back gracefully to an empty headers
      //    object with a note row in the breakdown.
      let headers     = {};
      let headersNote = null;

      const HEADER_NAMES = [
        'content-security-policy',
        'strict-transport-security',
        'x-frame-options',
        'x-content-type-options',
      ];

      try {
        const resp = await fetch(url, { method: 'HEAD', mode: 'cors', signal: abortCtrl.signal });
        if (resp.type === 'opaque') throw new Error('opaque');
        for (const name of HEADER_NAMES) {
          const val = resp.headers.get(name);
          if (val !== null) headers[name] = val;
        }
      } catch (fetchErr) {
        if (fetchErr.name === 'AbortError') throw fetchErr; // let outer catch handle timeout
        headersNote = 'Unable to verify (site blocks cross-origin checks)';
      }

      // 4. Score and respond.
      const findings = {
        isHttps,
        safeBrowsingFlagged,
        headers,
        cookies: [],
        forms:   [],
      };

      const { score, label, breakdown } = calculateScore(findings);
      const finalBreakdown = [...breakdown];
      if (headersNote) {
        finalBreakdown.push({ category: 'Headers', finding: headersNote, deduction: 0 });
      }

      trySend({
        ok: true,
        result: { url, score, label, breakdown: finalBreakdown, preliminary: true },
      });

    } catch (err) {
      // AbortError = 5-second timeout expired.
      // Any other error = unexpected failure (network stack, etc.).
      const timedOut = err.name === 'AbortError';
      trySend({
        ok: false,
        error: timedOut
          ? 'Pre-scan timed out (site did not respond within 5 seconds).'
          : `Pre-scan failed: ${err.message}`,
      });
    } finally {
      clearTimeout(abortTimer);
    }
  })();

  return true; // keep message channel open for async response
});

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message.type !== 'LEVEL1_DATA') return;

  const { url, isHttps, hostname } = message.payload;
  const tabId = sender.tab?.id;
  if (tabId == null) return;

  // Run async work in a contained IIFE so the listener itself stays synchronous
  // (no sendResponse is used here, so returning true is not needed).
  (async () => {
    const cached = getHeadersForTab(tabId);

    console.log(
      `[SiteTrustScore] LEVEL1_DATA tab=${tabId}`,
      { url, isHttps, hostname },
      '| headers:', cached ? Object.keys(cached.headers).length : 0,
      '| cookies:', cached ? cached.cookies.length : 0
    );

    // Sub-Task 6: check Safe Browsing before scoring
    const safeBrowsingFlagged = await checkSafeBrowsing(url);
    if (safeBrowsingFlagged) {
      console.warn(`[SiteTrustScore] Safe Browsing flagged tab=${tabId} url=${url}`);
    }

    const findings = {
      isHttps,
      safeBrowsingFlagged,
      headers: cached ? cached.headers : {},
      cookies: cached ? cached.cookies : [],
      forms:   [],
    };

    const result = calculateScore(findings);
    // Store safeBrowsingFlagged alongside the result so the Level 2 merge handler
    // can reconstruct the full findings without re-reading the breakdown heuristically.
    tabResultsCache.set(tabId, { ...result, url, hostname, safeBrowsingFlagged });

    // Sub-Task 5: badge update — always runs first, unconditionally.
    updateBadge(tabId, result.score, result.label);

    console.log(`[SiteTrustScore] Score tab=${tabId} (${hostname}): ${result.score} ${result.label}`);

    // -------------------------------------------------------------------------
    // Sub-Task 7 — Notification Logic
    // Fire a browser notification once per domain per session when score < 50.
    // Badge update above is already done before this block is entered, so no
    // notification failure can ever delay or block the badge.
    // -------------------------------------------------------------------------
    if (result.label === 'Risky') {
      try {
        const stored = await chrome.storage.session.get('notifiedDomains');
        // notifiedDomains is persisted as an array; convert to Set for O(1) lookup.
        const notifiedDomains = new Set(stored.notifiedDomains ?? []);

        if (!notifiedDomains.has(hostname)) {
          chrome.notifications.create(`risky-${hostname}`, {
            type:    'basic',
            iconUrl: 'icons/icon48.png',
            title:   '⚠️ Risky Site Detected',
            message: `${hostname} scored ${result.score}/100 (Risky). Proceed with caution.`,
          });

          notifiedDomains.add(hostname);
          await chrome.storage.session.set({ notifiedDomains: [...notifiedDomains] });
          console.log(`[SiteTrustScore] Notification fired for ${hostname}`);
        } else {
          console.log(`[SiteTrustScore] Notification suppressed (already notified this session): ${hostname}`);
        }
      } catch (err) {
        // Non-fatal: notification failure must never propagate or affect the badge.
        console.error('[SiteTrustScore] Notification error:', err);
      }
    }
  })();
});
