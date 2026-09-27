// content.js — Injected into every page at document_idle
// Collects page-level data for Level 1 and Level 2 analysis.
//
// NOTE: Cookie flag detection (Secure / HttpOnly) is intentionally NOT done here.
// Those flags are only visible in raw Set-Cookie response headers, which are
// read exclusively by the chrome.webRequest listener in background.js.
// document.cookie only exposes name=value pairs — never the Secure or HttpOnly
// attributes — so cookie flag analysis cannot be performed in a content script.

console.log('[SiteTrustScore] content script loaded on', window.location.href);

// ---------------------------------------------------------------------------
// Sub-Task 3 — Level 1 Content Script Collection
// ---------------------------------------------------------------------------

// Runs at document_idle (the manifest default), so the document URL is stable.
(function collectLevel1() {
  const url = window.location.href;
  const isHttps = window.location.protocol === 'https:';
  const hostname = window.location.hostname;

  chrome.runtime.sendMessage({
    type: 'LEVEL1_DATA',
    payload: { url, isHttps, hostname },
  });
})();

// ---------------------------------------------------------------------------
// Sub-Task 9 — Level 2 Content Scan (on-demand, triggered by background.js)
// ---------------------------------------------------------------------------
//
// config.js is NOT imported here — content scripts share the extension's
// background config via a message-based trigger, but VULNERABLE_LIBRARIES is
// small enough to inline.  background.js passes no payload with COLLECT_LEVEL2,
// so the library list must be available in the content script's own context.
//
// Because content scripts do NOT get importScripts(), the VULNERABLE_LIBRARIES
// constant is re-declared here, mirroring config.js exactly.  If you extend
// config.js you must update this copy too.

const LEVEL2_VULNERABLE_LIBRARIES = [
  // jQuery < 3.5
  {
    name: 'jQuery',
    globalPath: ['jQuery', 'fn', 'jquery'],
    altGlobalPath: ['$', 'fn', 'jquery'],
    versionRegex: /jquery[.\-v](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '3.5.0',
  },
  // Angular 1.x (any 1.x)
  {
    name: 'Angular 1.x',
    globalPath: ['angular', 'version', 'full'],
    altGlobalPath: null,
    versionRegex: /angular[.\-v](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '1.9999.9999',
  },
  // Bootstrap < 4
  {
    name: 'Bootstrap',
    globalPath: null,
    altGlobalPath: null,
    versionRegex: /bootstrap[.\-v](\d+\.\d+(?:\.\d+)?)/i,
    maxSafeVersion: '4.0.0',
  },
];

// Secret-detection patterns — conservative to minimise false positives.
// Each entry: { type: string, pattern: RegExp }
const SECRET_PATTERNS = [
  { type: 'Google API key',  pattern: /AIza[0-9A-Za-z\-_]{35}/g },
  { type: 'OpenAI API key',  pattern: /sk-[a-zA-Z0-9]{48}/g },
  { type: 'AWS access key',  pattern: /AKIA[0-9A-Z]{16}/g },
  { type: 'Stripe live key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
  // Generic: api_key = '...' / apiKey = '...' (16+ char value)
  {
    type: 'Generic API key assignment',
    pattern: /api[_\-]?key\s*[:=]\s*['"`][^'"`\s]{16,}['"`]/gi,
  },
  // Generic: token = '...' (20+ char value, avoids CSRF tokens which are fine)
  {
    type: 'Generic token assignment',
    pattern: /\btoken\s*[:=]\s*['"`][^'"`\s]{20,}['"`]/gi,
  },
];

// Path-in-comment patterns — look for Unix / Windows absolute paths.
const PATH_PATTERNS = [
  /\/(?:home|var|usr|etc|srv|opt|tmp|app|www|root)\b[^\s*>]*/g,   // Unix absolute paths
  /[A-Za-z]:\\(?:Users|Windows|Program Files)[^\s<>]*/g,           // Windows absolute paths
  /\/(?:src|app|project|build|dist|node_modules)\b[^\s*>]*/g,      // Common project paths
];

/**
 * Parse a semver string "major.minor.patch" into a comparable integer array.
 * Returns [0,0,0] if parsing fails.
 * @param {string} v
 * @returns {number[]}
 */
function parseSemver(v) {
  const parts = String(v).split('.').map(Number);
  return [parts[0] || 0, parts[1] || 0, parts[2] || 0];
}

/**
 * Returns true if version a is strictly less than version b.
 * Both are semver strings "major.minor.patch".
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function semverLessThan(a, b) {
  const [ma, na, pa] = parseSemver(a);
  const [mb, nb, pb] = parseSemver(b);
  if (ma !== mb) return ma < mb;
  if (na !== nb) return na < nb;
  return pa < pb;
}

/**
 * Safely walk a dot-path like ['jQuery','fn','jquery'] on window.
 * Returns the string value if found, or null.
 * @param {string[]|null} path
 * @returns {string|null}
 */
function readGlobalPath(path) {
  if (!path) return null;
  try {
    let obj = window;
    for (const key of path) {
      if (obj == null || typeof obj !== 'object' && typeof obj !== 'function') return null;
      obj = obj[key];
    }
    return (typeof obj === 'string' && obj.length) ? obj : null;
  } catch (_) {
    return null;
  }
}

/**
 * Truncate a string to a safe snippet length for reporting.
 * @param {string} s
 * @param {number} [max=80]
 * @returns {string}
 */
function snippet(s, max = 80) {
  s = String(s).replace(/\s+/g, ' ').trim();
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// ---------------------------------------------------------------------------
// 9-A. Vulnerable Library Detection
// ---------------------------------------------------------------------------
function detectVulnerableLibraries() {
  const found = [];

  for (const lib of LEVEL2_VULNERABLE_LIBRARIES) {
    // 1. Try global variable first (most reliable — version string already parsed)
    const fromGlobal =
      readGlobalPath(lib.globalPath) || readGlobalPath(lib.altGlobalPath);

    if (fromGlobal) {
      if (semverLessThan(fromGlobal, lib.maxSafeVersion)) {
        found.push({
          name: lib.name,
          detectedVersion: fromGlobal,
          reason: `Global variable reports version ${fromGlobal} (< ${lib.maxSafeVersion})`,
        });
        continue; // don't double-count via script src
      }
      // Global found but version is safe — no need to check src
      continue;
    }

    // 2. Fall back to scanning <script src="..."> URLs and inline script text
    const scripts = Array.from(document.scripts);
    let matched = false;
    for (const scriptEl of scripts) {
      const srcStr = scriptEl.src || '';
      const inlineStr = scriptEl.src ? '' : (scriptEl.textContent || '');
      const haystack = srcStr || inlineStr;
      if (!haystack) continue;

      const m = lib.versionRegex.exec(haystack);
      if (m) {
        const detectedVersion = m[1];
        if (semverLessThan(detectedVersion, lib.maxSafeVersion)) {
          found.push({
            name: lib.name,
            detectedVersion,
            reason: `Detected in ${srcStr ? 'script src' : 'inline script'}: ${snippet(haystack)}`,
          });
        }
        matched = true;
        lib.versionRegex.lastIndex = 0; // reset stateful regex
        break;
      }
      lib.versionRegex.lastIndex = 0;
    }
    void matched; // silence lint
  }

  return found;
}

// ---------------------------------------------------------------------------
// 9-B. Mixed Content Detection
// ---------------------------------------------------------------------------
function detectMixedContent() {
  // Only meaningful on HTTPS pages — mixed content on HTTP is not a regression.
  if (window.location.protocol !== 'https:') return [];

  const selector = [
    'img[src^="http:"]',
    'script[src^="http:"]',
    'link[href^="http:"]',
    'iframe[src^="http:"]',
    'audio[src^="http:"]',
    'video[src^="http:"]',
    'source[src^="http:"]',
  ].join(', ');

  return Array.from(document.querySelectorAll(selector)).map((el) => {
    const url = el.src || el.href || '';
    return { url: snippet(url, 120), tag: el.tagName.toLowerCase() };
  });
}

// ---------------------------------------------------------------------------
// 9-C. Unsafe Form Detection
// ---------------------------------------------------------------------------
function detectUnsafeForms() {
  const unsafe = [];

  for (const form of Array.from(document.forms)) {
    const action = (form.action || '').trim();
    const submitsOverHttp = action.toLowerCase().startsWith('http://');

    // CSRF token heuristic: look for a hidden input whose name or id contains
    // "csrf", "token", or "_token" (case-insensitive).
    const inputs = Array.from(form.elements);
    const hasCsrfToken = inputs.some((el) => {
      if (el.tagName.toLowerCase() !== 'input') return false;
      const nameAttr = (el.name || '').toLowerCase();
      const idAttr   = (el.id   || '').toLowerCase();
      return (
        nameAttr.includes('csrf') || nameAttr.includes('token') || nameAttr.includes('_token') ||
        idAttr.includes('csrf')   || idAttr.includes('token')
      );
    });

    // Flag forms that either submit over HTTP OR lack a CSRF token.
    // (The scoring engine will only penalise the HTTP-action case with -25;
    //  missing CSRF is scored separately.  We report both here so background
    //  can build the correct findings.forms array.)
    if (submitsOverHttp || !hasCsrfToken) {
      unsafe.push({
        action,
        submitsOverHttp,
        hasCsrfToken,
        method: (form.method || 'get').toUpperCase(),
      });
    }
  }

  return unsafe;
}

// ---------------------------------------------------------------------------
// 9-D. Exposed Secret Detection
// ---------------------------------------------------------------------------
function detectExposedSecrets() {
  const html = document.documentElement.innerHTML;
  const results = [];

  for (const { type, pattern } of SECRET_PATTERNS) {
    // Patterns use the /g flag; reset lastIndex before each scan.
    pattern.lastIndex = 0;
    let m;
    while ((m = pattern.exec(html)) !== null) {
      results.push({ type, snippet: snippet(m[0]) });
      // Stop after first match per pattern to avoid flooding.
      break;
    }
    pattern.lastIndex = 0;
  }

  return results;
}

// ---------------------------------------------------------------------------
// 9-E. Exposed Path Detection (in HTML comments)
// ---------------------------------------------------------------------------
function detectExposedPaths() {
  // Extract all HTML comments from the raw source.
  const html = document.documentElement.innerHTML;
  const commentRegex = /<!--([\s\S]*?)-->/g;
  const results = [];
  const seen = new Set();

  let cm;
  while ((cm = commentRegex.exec(html)) !== null) {
    const commentText = cm[1];
    for (const pathPattern of PATH_PATTERNS) {
      pathPattern.lastIndex = 0;
      let pm;
      while ((pm = pathPattern.exec(commentText)) !== null) {
        const match = pm[0].trim();
        if (match.length > 3 && !seen.has(match)) {
          seen.add(match);
          results.push({ snippet: snippet(match) });
        }
        pathPattern.lastIndex = 0; // prevent infinite loop on zero-width match
      }
    }
  }

  return results;
}

// ---------------------------------------------------------------------------
// COLLECT_LEVEL2 message listener
// ---------------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type !== 'COLLECT_LEVEL2') return; // not our message

  console.log('[SiteTrustScore] COLLECT_LEVEL2 triggered');

  const vulnerableLibraries = detectVulnerableLibraries();
  const mixedContentItems   = detectMixedContent();
  const unsafeForms         = detectUnsafeForms();
  const exposedSecrets      = detectExposedSecrets();
  const exposedPaths        = detectExposedPaths();

  console.log('[SiteTrustScore] Level 2 findings:', {
    vulnerableLibraries: vulnerableLibraries.length,
    mixedContent: mixedContentItems.length,
    unsafeForms: unsafeForms.length,
    exposedSecrets: exposedSecrets.length,
    exposedPaths: exposedPaths.length,
  });

  sendResponse({
    type: 'LEVEL2_DATA',
    payload: {
      vulnerableLibraries,
      mixedContent: mixedContentItems,
      unsafeForms,
      exposedSecrets,
      exposedPaths,
    },
  });

  return true; // keep channel open for async sendResponse
});
