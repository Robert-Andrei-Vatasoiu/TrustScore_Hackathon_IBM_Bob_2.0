// popup.js — Popup page script for Site Trust Score.
// Communicates with background.js via chrome.runtime.sendMessage.
// Sub-Task 8: display cached Level 1 results.
// Sub-Task 10: wire "Run Deep Scan" button for Level 2 analysis.

// ── Category display order & friendly names ───────────────────────────────
// Defines the order sections appear and the human-readable label shown in the
// <summary>. Categories not listed here appear at the end in insertion order.
// Level 2 categories (Libraries, Mixed Content, Secrets, Source Exposure) are
// appended after the Level 1 categories — they only appear after a deep scan.
const CATEGORY_ORDER = [
  'HTTPS', 'Safe Browsing', 'Headers', 'Cookies', 'Forms',
  'Libraries', 'Mixed Content', 'Secrets', 'Source Exposure',
];

const CATEGORY_LABELS = {
  'HTTPS':           'HTTPS',
  'Safe Browsing':   'Safe Browsing',
  'Headers':         'Security Headers',
  'Cookies':         'Cookie Flags',
  'Forms':           'Forms',
  'Libraries':       'Vulnerable JS Libraries',
  'Mixed Content':   'Mixed Content',
  'Secrets':         'Exposed Secrets',
  'Source Exposure': 'Exposed Internal Paths',
};

// ── Helpers ───────────────────────────────────────────────────────────────

/**
 * Returns the CSS class name ('safe', 'caution', 'risky') for a given label.
 * @param {string} label
 * @returns {string}
 */
function labelClass(label) {
  return label ? label.toLowerCase() : '';
}

/**
 * Groups a flat breakdown array into a Map<category → [finding items]>.
 * @param {Array<{category: string, finding: string, deduction: number}>} breakdown
 * @returns {Map<string, Array>}
 */
function groupByCategory(breakdown) {
  const map = new Map();
  for (const item of breakdown) {
    if (!map.has(item.category)) map.set(item.category, []);
    map.get(item.category).push(item);
  }
  return map;
}

/**
 * Returns a sorted array of [category, items] pairs following CATEGORY_ORDER,
 * with any unlisted categories appended in their original order.
 * @param {Map<string, Array>} grouped
 * @returns {Array<[string, Array]>}
 */
function sortedCategories(grouped) {
  const known = CATEGORY_ORDER.filter((c) => grouped.has(c));
  const rest  = [...grouped.keys()].filter((c) => !CATEGORY_ORDER.includes(c));
  return [...known, ...rest].map((c) => [c, grouped.get(c)]);
}

// ── Rendering ─────────────────────────────────────────────────────────────

/**
 * Builds a single <details> section for one category.
 * @param {string} category
 * @param {Array<{finding: string, deduction: number}>} items
 * @returns {HTMLElement}
 */
function buildCategorySection(category, items) {
  const label = CATEGORY_LABELS[category] ?? category;
  const totalDeduction = items.reduce((sum, i) => sum + i.deduction, 0);

  const details = document.createElement('details');

  // ── <summary> ─────────────────────────────────────────────────────────
  const summary = document.createElement('summary');

  const titleSpan = document.createElement('span');
  titleSpan.className = 'summary-title';
  titleSpan.textContent = label;

  const badge = document.createElement('span');
  badge.className = 'summary-badge ' + (totalDeduction > 0 ? 'has-issues' : 'all-good');
  badge.textContent = totalDeduction > 0 ? `−${totalDeduction}` : '✓';

  summary.appendChild(titleSpan);
  summary.appendChild(badge);
  details.appendChild(summary);

  // ── finding rows ──────────────────────────────────────────────────────
  const ul = document.createElement('ul');
  ul.className = 'finding-list';

  for (const item of items) {
    const li = document.createElement('li');
    li.className = 'finding-item';

    const textSpan = document.createElement('span');
    textSpan.className = 'finding-text';
    textSpan.textContent = item.finding;

    const dedSpan = document.createElement('span');
    dedSpan.className = 'finding-deduction';
    dedSpan.textContent = `−${item.deduction}`;

    li.appendChild(textSpan);
    li.appendChild(dedSpan);
    ul.appendChild(li);
  }

  details.appendChild(ul);
  return details;
}

/**
 * Renders the full scored state into the DOM.
 * @param {{ score: number, label: string, breakdown: Array, url: string, hostname: string }} result
 */
function renderResults(result) {
  const { score, label, breakdown, url } = result;
  const cls = labelClass(label);

  // Score circle
  const circle = document.getElementById('score-circle');
  const numEl  = document.getElementById('score-number');
  circle.className = `score-circle ${cls}`;
  numEl.className  = `score-number ${cls}`;
  numEl.textContent = String(score);

  // Label + URL
  const labelEl = document.getElementById('score-label');
  labelEl.className = `score-label ${cls}`;
  labelEl.textContent = label;

  const urlEl = document.getElementById('score-url');
  urlEl.textContent = url ?? '';

  // Show hero, hide placeholder
  document.getElementById('score-section').hidden = false;
  document.getElementById('placeholder').hidden   = true;

  // Build findings sections
  const findingsEl = document.getElementById('findings-section');
  findingsEl.hidden = false;
  findingsEl.innerHTML = ''; // clear any previous content

  if (!Array.isArray(breakdown) || breakdown.length === 0) {
    // Score is perfect — no deductions to show
    const none = document.createElement('p');
    none.style.cssText = 'padding:8px 0; color:#57606a; font-size:12px; margin:0;';
    none.textContent = 'No issues found.';
    findingsEl.appendChild(none);
    return;
  }

  const grouped = groupByCategory(breakdown);
  for (const [category, items] of sortedCategories(grouped)) {
    findingsEl.appendChild(buildCategorySection(category, items));
  }
}

/**
 * Shows the placeholder message (used when no data is available yet).
 * @param {string} [message]
 */
function renderPlaceholder(message) {
  document.getElementById('placeholder').textContent = message ?? 'Analyzing…';
  document.getElementById('placeholder').hidden = false;
  document.getElementById('score-section').hidden = true;
  document.getElementById('findings-section').hidden = true;
}

// ── Deep scan helpers ─────────────────────────────────────────────────────

/**
 * Show an inline scan-error message below the findings section.
 * Re-enables the button so the user can try again (if applicable).
 * @param {string} message
 * @param {HTMLButtonElement} btn
 */
function showScanError(message, btn) {
  let errEl = document.getElementById('scan-error');
  if (!errEl) {
    errEl = document.createElement('p');
    errEl.id = 'scan-error';
    errEl.style.cssText =
      'margin:0; padding:8px 14px; font-size:12px; color:#c0392b; background:#fdecea;' +
      'border-top:1px solid #f5c6cb;';
    // Insert before the button section so it appears between findings and button.
    const buttonSection = document.querySelector('.button-section');
    buttonSection.parentNode.insertBefore(errEl, buttonSection);
  }
  errEl.textContent = message;
  errEl.hidden = false;

  // Re-enable so user can try on a different page after navigating, or retry.
  btn.disabled = false;
  btn.textContent = 'Run Deep Scan';
  btn.classList.remove('scanning');
}

/**
 * Wire the "Run Deep Scan" button for a specific tab.
 * @param {number} tabId
 */
function wireDeepScanButton(tabId) {
  const btn = document.getElementById('btn-deep-scan');
  if (!btn) return;

  // Enable the button now that we have a valid tab and Level 1 results.
  btn.disabled = false;
  btn.title = 'Run a deep scan for vulnerable libraries, mixed content, and exposed secrets';

  btn.addEventListener('click', function () {
    // Prevent double-clicks.
    btn.disabled = true;
    btn.textContent = 'Scanning…';

    // Clear any previous error message.
    const prevErr = document.getElementById('scan-error');
    if (prevErr) prevErr.hidden = true;

    chrome.runtime.sendMessage({ type: 'RUN_DEEP_SCAN', tabId }, function (response) {
      if (chrome.runtime.lastError) {
        showScanError(
          'Could not reach the extension background. Try reloading the extension.',
          btn
        );
        return;
      }

      if (!response || !response.ok) {
        showScanError(response?.error ?? 'Deep scan failed for an unknown reason.', btn);
        return;
      }

      // Success — re-render with the full updated results.
      renderResults(response.result);

      // Keep button disabled and relabelled: scan already done for this page load.
      btn.textContent = 'Scan Complete';
      btn.title = 'Deep scan already completed for this page load.';
      // btn.disabled remains true — no need to run again until the page reloads.
    });
  });
}

// ── Pre-Scan ──────────────────────────────────────────────────────────────

/**
 * Basic client-side URL validation: must be a valid http or https URL.
 * Returns null if valid, or an error string if not.
 * @param {string} raw
 * @returns {string|null}
 */
function validatePrescanUrl(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return 'Please enter a URL.';
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return 'URL must start with http:// or https://';
    }
  } catch (_) {
    return 'That doesn\'t look like a valid URL. Include https:// at the start.';
  }
  return null;
}

/**
 * Renders the pre-scan result into #prescan-results using the existing
 * buildCategorySection helper. Labels the block "Preliminary Check" with
 * a score pill so it's visually distinct from the current-tab results below.
 * @param {{ score: number, label: string, breakdown: Array, url: string }} result
 */
function renderPrescanResult(result) {
  const container = document.getElementById('prescan-results');
  container.innerHTML = '';

  const cls = labelClass(result.label);

  // Header row: "Preliminary Check" + score pill + italic note
  const header = document.createElement('div');
  header.className = 'prescan-results-header';

  const titleText = document.createElement('span');
  titleText.textContent = 'Preliminary Check';
  header.appendChild(titleText);

  const pill = document.createElement('span');
  pill.className = `prescan-score-pill ${cls}`;
  pill.textContent = `${result.score} · ${result.label}`;
  header.appendChild(pill);

  const note = document.createElement('span');
  note.className = 'prescan-preliminary';
  note.textContent = 'preliminary';
  header.appendChild(note);

  container.appendChild(header);

  // Breakdown using the existing collapsible <details> renderer
  if (!Array.isArray(result.breakdown) || result.breakdown.length === 0) {
    const none = document.createElement('p');
    none.style.cssText = 'margin:0; color:#57606a; font-size:12px;';
    none.textContent = 'No issues detected.';
    container.appendChild(none);
  } else {
    const grouped = groupByCategory(result.breakdown);
    for (const [category, items] of sortedCategories(grouped)) {
      container.appendChild(buildCategorySection(category, items));
    }
  }

  container.hidden = false;
}

/**
 * Wire the pre-scan input + button.
 * Fully self-contained — no tabId, no tabResultsCache interaction.
 */
function wirePrescan() {
  const input  = document.getElementById('prescan-input');
  const btn    = document.getElementById('btn-check-url');
  const errEl  = document.getElementById('prescan-error');
  const results = document.getElementById('prescan-results');

  function showPrescanError(msg) {
    errEl.textContent = msg;
    errEl.hidden = false;
    results.hidden = true;
  }

  function clearPrescanError() {
    errEl.hidden = true;
  }

  function submit() {
    clearPrescanError();

    const raw = input.value;
    const validationError = validatePrescanUrl(raw);
    if (validationError) {
      showPrescanError(validationError);
      return;
    }

    const url = raw.trim();

    // Loading state
    btn.disabled = true;
    btn.textContent = 'Checking…';
    results.hidden = true;

    chrome.runtime.sendMessage({ type: 'PRESCAN_URL', url }, function (response) {
      // Always restore button
      btn.disabled = false;
      btn.textContent = 'Check URL';

      if (chrome.runtime.lastError) {
        showPrescanError('Extension error — try reloading the extension.');
        return;
      }

      if (!response || !response.ok) {
        showPrescanError(response?.error ?? 'Pre-scan failed for an unknown reason.');
        return;
      }

      renderPrescanResult(response.result);
    });
  }

  btn.addEventListener('click', submit);

  // Allow Enter key in the input to trigger the check
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') submit();
  });
}

// ── Entry point ───────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  // Wire pre-scan immediately — it is independent of the active tab.
  wirePrescan();
  // 1. Find the active tab in the current window.
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const tab = tabs && tabs[0];
    if (!tab || tab.id == null) {
      renderPlaceholder('Could not identify the current tab.');
      return;
    }

    const tabId = tab.id;

    // 2. Ask background for any cached Level 1 results for this tab.
    chrome.runtime.sendMessage({ type: 'GET_RESULTS', tabId }, function (response) {
      // sendMessage callback fires with response === null when the background
      // found no cached entry for the tab (first load, not yet processed, etc.)
      if (chrome.runtime.lastError) {
        // Service worker may not be running yet — show a neutral state.
        renderPlaceholder('Analyzing…');
        return;
      }

      if (!response) {
        // No results cached yet for this tab.
        renderPlaceholder('No data yet — reload the page to analyze it.');
        return;
      }

      renderResults(response);

      // 3. Restore the correct button state based on whether a deep scan has
      //    already run for this tab (level2Done persists in tabResultsCache
      //    across popup close/reopen, until the page navigates away).
      if (response.level2Done) {
        const btn = document.getElementById('btn-deep-scan');
        if (btn) {
          btn.disabled = true;
          btn.textContent = 'Scan Complete';
          btn.title = 'Deep scan already completed for this page load.';
        }
      } else {
        // Level 2 not yet run — wire the active button as normal.
        wireDeepScanButton(tabId);
      }
    });
  });
});
