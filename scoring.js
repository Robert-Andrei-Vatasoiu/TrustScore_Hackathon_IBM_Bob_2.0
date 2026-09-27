// scoring.js — Pure scoring module. No browser APIs. No side effects.
// Exported via global assignment so it works with importScripts() in the service worker.
//
// findings shape (all fields optional; missing fields are treated as "unknown / not checked"):
// {
//   isHttps:             boolean
//   safeBrowsingFlagged: boolean
//   headers: {
//     'content-security-policy':    string | undefined,
//     'strict-transport-security':  string | undefined,
//     'x-frame-options':            string | undefined,
//     'x-content-type-options':     string | undefined,
//   },
//   cookies: Array<{ name: string, secure: boolean, httpOnly: boolean }>,
//   forms:   Array<{ action: string, hasCsrfToken: boolean }>,   // Level 1 CSRF heuristic uses this
//   // Level 2 (present only after deep scan):
//   level2: {
//     exposedSecret:      boolean,
//     vulnerableLibraries: Array<{ name: string, detectedVersion: string, reason: string }>,
//     mixedContent:       boolean,
//     exposedPaths:       Array<{ snippet: string }>,
//   }
// }

/**
 * calculateScore(findings) → { score, label, breakdown }
 *
 * Starts at 100.  Deductions are applied in the order defined in the plan,
 * each capped where specified.  Returns the clamped score, a risk label, and
 * a breakdown array that popup.js can render row-by-row.
 *
 * @param {object} findings
 * @returns {{ score: number, label: 'Safe'|'Caution'|'Risky', breakdown: Array<{category: string, finding: string, deduction: number}> }}
 */
function calculateScore(findings) {
  let score = 100;
  const breakdown = [];

  // Helper: record a deduction and subtract it from the running score.
  function deduct(category, finding, amount) {
    score -= amount;
    breakdown.push({ category, finding, deduction: amount });
  }

  // ── 1. HTTPS check ──────────────────────────────────────────────────────────
  // -30 if the page is served over plain HTTP.
  if (findings.isHttps === false) {
    deduct('HTTPS', 'Page not served over HTTPS', 30);
  }

  // ── 2. Form action over HTTP ────────────────────────────────────────────────
  // -25 if any <form> submits its data to an HTTP (non-HTTPS) URL.
  // A missing/relative action is not penalised here — that's fine.
  const forms = Array.isArray(findings.forms) ? findings.forms : [];
  const hasHttpFormAction = forms.some(
    (f) => typeof f.action === 'string' && f.action.toLowerCase().startsWith('http://')
  );
  if (hasHttpFormAction) {
    deduct('Forms', 'Form action submits over HTTP (not HTTPS)', 25);
  }

  // ── 3. Missing CSP header ───────────────────────────────────────────────────
  // -10 if the Content-Security-Policy header is absent.
  const headers = (findings.headers && typeof findings.headers === 'object') ? findings.headers : {};
  if (!headers['content-security-policy']) {
    deduct('Headers', 'Missing Content-Security-Policy header', 10);
  }

  // ── 4. Cookie flags — Secure ────────────────────────────────────────────────
  // -10 per cookie missing the Secure flag, capped at -15 total.
  const cookies = Array.isArray(findings.cookies) ? findings.cookies : [];
  {
    const PER_COOKIE_DEDUCTION = 10;
    const CAP = 15;
    const insecure = cookies.filter((c) => !c.secure);
    if (insecure.length > 0) {
      const raw = insecure.length * PER_COOKIE_DEDUCTION;
      const capped = Math.min(raw, CAP);
      deduct(
        'Cookies',
        `${insecure.length} cookie(s) missing Secure flag`,
        capped
      );
    }
  }

  // ── 5. Cookie flags — HttpOnly ──────────────────────────────────────────────
  // -8 per cookie missing the HttpOnly flag, capped at -12 total.
  {
    const PER_COOKIE_DEDUCTION = 8;
    const CAP = 12;
    const nonHttpOnly = cookies.filter((c) => !c.httpOnly);
    if (nonHttpOnly.length > 0) {
      const raw = nonHttpOnly.length * PER_COOKIE_DEDUCTION;
      const capped = Math.min(raw, CAP);
      deduct(
        'Cookies',
        `${nonHttpOnly.length} cookie(s) missing HttpOnly flag`,
        capped
      );
    }
  }

  // ── 6. Missing HSTS ─────────────────────────────────────────────────────────
  // -5 if the Strict-Transport-Security header is absent.
  if (!headers['strict-transport-security']) {
    deduct('Headers', 'Missing Strict-Transport-Security (HSTS) header', 5);
  }

  // ── 7. Missing X-Frame-Options ──────────────────────────────────────────────
  // -5 if the X-Frame-Options header is absent.
  if (!headers['x-frame-options']) {
    deduct('Headers', 'Missing X-Frame-Options header', 5);
  }

  // ── 8. Missing X-Content-Type-Options ───────────────────────────────────────
  // -3 if the X-Content-Type-Options header is absent.
  if (!headers['x-content-type-options']) {
    deduct('Headers', 'Missing X-Content-Type-Options header', 3);
  }

  // ── 9. CSRF heuristic ───────────────────────────────────────────────────────
  // -5 if any POST-capable form lacks a CSRF token input.
  // forms without hasCsrfToken indicate a potential CSRF gap.
  const formsWithoutCsrf = forms.filter((f) => f.hasCsrfToken === false);
  if (formsWithoutCsrf.length > 0) {
    deduct(
      'Forms',
      `${formsWithoutCsrf.length} form(s) with no detectable CSRF token`,
      5
    );
  }

  // ── Level 2 rules (applied only when findings.level2 is present) ───────────
  if (findings.level2 && typeof findings.level2 === 'object') {
    const l2 = findings.level2;

    // ── L2-1. Exposed API key / secret in source ─────────────────────────────
    // -30 if any credential / API key pattern was found in the page source.
    if (l2.exposedSecret) {
      deduct('Secrets', 'Exposed API key or secret detected in page source', 30);
    }

    // ── L2-2. Vulnerable JS libraries ────────────────────────────────────────
    // -15 per vulnerable library, capped at -30 total.
    {
      const PER_LIB_DEDUCTION = 15;
      const CAP = 30;
      const libs = Array.isArray(l2.vulnerableLibraries) ? l2.vulnerableLibraries : [];
      if (libs.length > 0) {
        const raw = libs.length * PER_LIB_DEDUCTION;
        const capped = Math.min(raw, CAP);
        deduct(
          'Libraries',
          `${libs.length} vulnerable JS librar${libs.length === 1 ? 'y' : 'ies'} detected (${libs.map((lib) => lib.name).join(', ')})`,
          capped
        );
      }
    }

    // ── L2-3. Mixed content ───────────────────────────────────────────────────
    // -10 if HTTP resources are loaded on an HTTPS page.
    if (l2.mixedContent) {
      deduct('Mixed Content', 'HTTP resources loaded on HTTPS page (mixed content)', 10);
    }

    // ── L2-4. Exposed internal paths / comments ───────────────────────────────
    // -5 per exposed path, capped at -10 total.
    {
      const PER_PATH_DEDUCTION = 5;
      const CAP = 10;
      const paths = Array.isArray(l2.exposedPaths) ? l2.exposedPaths : [];
      if (paths.length > 0) {
        const raw = paths.length * PER_PATH_DEDUCTION;
        const capped = Math.min(raw, CAP);
        deduct(
          'Source Exposure',
          `${paths.length} internal path(s) or comment(s) exposed in source`,
          capped
        );
      }
    }
  }

  // ── Safe Browsing override ───────────────────────────────────────────────────
  // Applied LAST: if the domain is flagged, force the score down to at most 10.
  // This is intentionally applied after all other deductions so it always wins.
  if (findings.safeBrowsingFlagged) {
    if (score > 10) {
      const forced = score - 10;
      breakdown.push({
        category: 'Safe Browsing',
        finding: 'Domain flagged by Google Safe Browsing — score forced to ≤10',
        deduction: forced,
      });
      score = 10;
    }
  }

  // ── Clamp ───────────────────────────────────────────────────────────────────
  score = Math.max(0, Math.min(100, score));

  // ── Label ───────────────────────────────────────────────────────────────────
  // Safe: 80–100 | Caution: 50–79 | Risky: 0–49
  let label;
  if (score >= 80) {
    label = 'Safe';
  } else if (score >= 50) {
    label = 'Caution';
  } else {
    label = 'Risky';
  }

  return { score, label, breakdown };
}
