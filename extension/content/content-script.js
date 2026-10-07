var api = typeof browser !== 'undefined' ? browser : chrome;

// Reloading an unpacked MV3 extension can leave the previous content script
// in the same page. A second inject must stop immediately; otherwise `const`
// declarations throw "already been declared" and break the hover card.
if (window.__secPolicyCheckerInjected) {
  // Stale leftover — do not rebind listeners or redeclare locals.
} else {
window.__secPolicyCheckerInjected = true;

// Reloading an unpacked MV3 extension invalidates content scripts already
// injected into dashboard tabs. A stale script must quietly stop instead of
// throwing from a later hover/message callback; the fresh script takes over
// after the dashboard tab is reloaded.
function runtimeUrl(path) {
  try {
    return api && api.runtime && api.runtime.id ? api.runtime.getURL(path) : null;
  } catch (_) {
    return null;
  }
}

function safeRuntimeMessage(message, callback) {
  try {
    if (!api || !api.runtime || !api.runtime.id) {
      if (callback) callback(null);
      return false;
    }
    api.runtime.sendMessage(message, (response) => {
      try {
        if (api.runtime.lastError) {
          if (callback) callback(null);
          return;
        }
        if (callback) callback(response);
      } catch (_) {
        if (callback) callback(null);
      }
    });
    return true;
  } catch (_) {
    if (callback) callback(null);
    return false;
  }
}

// ---------------------------------------------------------------------------
// findRuleRows — matches the real Cisco Secure Access dashboard DOM.
//
// The dashboard is built on the Cisco Design System (CDS), which emits
// CSS-in-JS classes with a build/session-specific hash suffix appended to a
// stable base class, e.g. "cds-table__row_72958d5c77d62d67c0dac2ad1d50efd7
// cds-table__row cds-table__row--draggable" — both classes are present on
// the same element, space-separated.
//
// IMPORTANT: selectors here must only ever reference the stable, unhashed
// base class (e.g. ".cds-table__row"), never the hashed variant — the hash
// changes on every Cisco redeploy and would silently break matching. This is
// the standing rule for any future DOM-scraping code added to this file: if
// you're tempted to copy a class string straight from devtools, strip the
// hash suffix first.
//
// These selectors WILL break again if Cisco changes the CDS component
// structure (e.g. renames "cds-table__row" or restructures the table). If
// findRuleRows() starts returning [] again, re-inspect the live dashboard
// DOM and update the selectors below.
// ---------------------------------------------------------------------------

function findRuleRows() {
  const selectors = [
    'table[rowkey="ruleId"] tbody tr.cds-table__row',
    'table[rowkey="ruleId"] tr.cds-table__row',
    // Fallbacks in case the rowkey attribute or table structure shifts
    "[data-rule-id]",
    ".rule-row",
    "tr[class*='rule']",
    "table tbody tr",
  ];

  for (const selector of selectors) {
    const elements = Array.from(document.querySelectorAll(selector));
    if (elements.length > 0) return elements;
  }

  return [];
}

// ---------------------------------------------------------------------------
// findDefaultRuleRows — fallback search for default/catch-all rules (e.g.
// "For all private access", "All Internet access") that live in a visually
// separate "Default rules" section from the "Access control rules" table
// findRuleRows() targets.
//
// CONFIRMED via live inspection (org 8176184): the Default rules section is
// its own <table class="... policy-default-rule-table">, a stable
// (non-hashed) class distinct from the hashed classes on the same element —
// same tbody > tr.cds-table__row row shape as the main table, just scoped to
// this separate table instance. Row text lives in <td><div><span> here
// (no <p class="cds-text__weight--bold"> like the main table), but
// getRuleName()'s td:first-child fallback already handles that correctly
// since that first cell contains only the rule-name text.
// ---------------------------------------------------------------------------
function findDefaultRuleRows() {
  const confirmed = Array.from(
    document.querySelectorAll("table.policy-default-rule-table tbody tr.cds-table__row")
  );
  if (confirmed.length > 0) return confirmed;

  // Unconfirmed fallback heuristics, kept in case Cisco renames
  // policy-default-rule-table in a future redeploy.
  const selectors = [
    '[data-testid*="default" i] tr',
    '[class*="default" i] tr',
  ];

  for (const selector of selectors) {
    const elements = Array.from(document.querySelectorAll(selector));
    if (elements.length > 0) return elements;
  }

  // Heading-text heuristic: find an element whose own text is (roughly)
  // "Default rules", then search for row/card-like descendants that come
  // AFTER it in the document — resilient to unknown/changing markup since
  // it doesn't depend on a specific class or attribute, only on visible
  // text Cisco is unlikely to remove entirely.
  //
  // A heading is very often a SIBLING of its section's content (e.g.
  // <h2>Default rules</h2><table>...</table>), not an ancestor of it — so
  // searching heading.closest(...) alone can miss it, and searching a
  // broader ancestor (e.g. <body>) without filtering can wrongly include
  // unrelated rows that appear BEFORE the heading (caught while testing
  // this against a mock DOM: it was matching the earlier custom-rules
  // table too). Filtering by document position fixes both.
  const headingCandidates = Array.from(
    document.querySelectorAll("h1,h2,h3,h4,h5,h6,p,span,div")
  ).filter((el) => el.children.length === 0 && /default rules/i.test(el.textContent || ""));

  for (const heading of headingCandidates) {
    // Prefer the heading's immediate next sibling (the common case).
    const candidateContainers = [heading.nextElementSibling, heading.parentElement].filter(Boolean);

    for (const container of candidateContainers) {
      const rows = Array.from(
        container.querySelectorAll('tr, [class*="row" i], [data-testid*="rule" i]')
      ).filter((el) => heading.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING);

      if (rows.length > 0) return rows;
    }
  }

  return [];
}

// ---------------------------------------------------------------------------
// getRuleName — extracts the rule name text from a row element.
//
// Real DOM: the rule name lives in a <p class="... cds-text cds-text--p3
// cds-text__weight--bold"> nested inside a cell — the bold-weight text is
// specific to the name column (other columns use non-bold text). Only the
// stable "cds-text__weight--bold" class is matched (see findRuleRows()
// comment above re: hashed vs. stable classes).
// ---------------------------------------------------------------------------

function getRuleName(element) {
  const name =
    element.querySelector("p.cds-text__weight--bold")?.textContent ||
    element.querySelector("[data-rule-name]")?.textContent ||
    element.querySelector(".rule-name")?.textContent ||
    element.querySelector("td:first-child")?.textContent ||
    element.textContent.trim().split("\n")[0];

  return (name || "unknown").trim();
}

// ---------------------------------------------------------------------------
// highlightRule — scroll to and flash a rule row matching ruleName
// ---------------------------------------------------------------------------

/**
 * Inject the yellow-flash keyframe style once into <head>, then find the DOM
 * row whose displayed name matches `ruleName`, scroll it into view, and apply
 * the flash class for 2 s.
 *
 * findRuleRows() / getRuleName() target the real Cisco Secure Access
 * dashboard DOM (CDS components, matched via stable unhashed classes — see
 * the comment above findRuleRows()). If the dashboard's DOM structure
 * changes in a future Cisco redeploy, this will log a warning below when no
 * matching row is found, which is the signal to re-inspect and update them.
 *
 * @param {string} ruleName
 * @param {string[]} [matchedConditions] - Test Policy's "Matched because"
 *   reasoning, passed through from popup.js when triggered from a Test
 *   Policy result (absent/undefined when triggered from the Rules tab).
 *   When present, also shows the hover popover on the matched row with this
 *   specific reasoning — see showPopoverForRule() below.
 */
function highlightRule(ruleName, matchedConditions) {
  // Inject highlight style once
  if (!document.getElementById("sec-highlight-style")) {
    const style = document.createElement("style");
    style.id = "sec-highlight-style";
    style.textContent = `
      .sec-highlight td {
        background-color: rgba(148, 163, 184, 0.12) !important;
        border-top: 2px solid #94a3b8 !important;
        border-bottom: 2px solid #94a3b8 !important;
        box-shadow: inset 0 0 8px rgba(148, 163, 184, 0.15);
        transition: background-color 0.3s ease, box-shadow 0.3s ease;
      }
      .sec-highlight td:first-child {
        border-left: 4px solid #94a3b8 !important;
        border-radius: 0;
      }
      .sec-highlight td:last-child {
        border-right: 4px solid #94a3b8 !important;
        border-radius: 0;
      }
      .sec-highlight {
        position: relative;
        z-index: 1;
      }
    `;
    document.head.appendChild(style);
  }

  // Try the "Access control rules" table first (unchanged, confirmed
  // behavior for custom rules), then fall back to the default-rules search
  // if not found there — default/catch-all rules (e.g. "For all private
  // access") may live in a separate section (see findDefaultRuleRows()).
  const rows = findRuleRows();
  let target = rows.find(
    (row) => getRuleName(row).toLowerCase() === ruleName.toLowerCase()
  );

  if (!target) {
    const defaultRows = findDefaultRuleRows();
    target = defaultRows.find(
      (row) => getRuleName(row).toLowerCase() === ruleName.toLowerCase()
    );
  }

  if (!target) {
    console.warn(
      `[SecPolicyChecker] HIGHLIGHT_RULE: no row found for rule name '${ruleName}' in either ` +
      "the Access control rules table or the default-rules fallback search. " +
      "Update findRuleRows()/findDefaultRuleRows() selectors to match the real dashboard DOM."
    );
    return;
  }

  // Remove any existing highlight before re-applying (handles rapid clicks)
  target.classList.remove("sec-highlight");
  // Force reflow so removing+re-adding the class restarts the animation
  void target.offsetWidth;
  target.classList.add("sec-highlight");
  target.scrollIntoView({ behavior: "smooth", block: "center" });

  // Store reference so click-outside handler can remove it
  currentHighlightEl = target;

  // Also show the rich hover popover (same one used for hovering chips) on
  // this row, anchored to a source/destination chip if the row has one
  // (falls back to the row itself, which still works fine as an anchor for
  // positioning purposes). Only fires when triggered from a Test Policy
  // result — matchedConditions is undefined when triggered from the Rules
  // tab, and there's nothing test-specific to show in that case (hovering
  // the row's own chips already covers it).
  if (Array.isArray(matchedConditions) && matchedConditions.length > 0) {
    const anchorEl = target.querySelector(CHIP_SELECTOR) || target;
    clearTimeout(hoverHideTimer);
    showPopoverForRule(anchorEl, ruleName, matchedConditions);
  }
}

// ---------------------------------------------------------------------------
// highlightRules — Policy Checker result on the page. Draws a ring over each
// matched rule row with a tag naming the stages it decided ("DNS · Web —
// Block"), then scrolls to the first one. The ring lives in its own fixed
// overlay layer, so Cisco's table layout is never touched; it follows the
// row through scrolling, resizing and re-renders until the next check or
// until the result card is closed.
// ---------------------------------------------------------------------------
var HIT_LAYER_ID = "sec-hit-layer";
var currentHits = [];
var hitSyncFrame = null;
var hitListenersBound = false;
var HIT_ACTIONS = ["allow", "block", "warn", "isolate"];

function ensureHitStyle() {
  if (document.getElementById("sec-hit-style")) return;
  const style = document.createElement("style");
  style.id = "sec-hit-style";
  style.textContent = `
    #sec-hit-layer { position: fixed; inset: 0; z-index: 2147483000; pointer-events: none; }
    .sec-hit-ring {
      --sec-hit: #b91c1c; --sec-hit-soft: rgba(185, 28, 28, .07);
      position: fixed; box-sizing: border-box; border: 2px solid var(--sec-hit); border-radius: 2px;
      background: var(--sec-hit-soft); box-shadow: 0 0 0 4px color-mix(in srgb, var(--sec-hit) 14%, transparent);
      opacity: 0; transition: opacity .2s ease;
    }
    .sec-hit-ring.sec-hit-in { opacity: 1; }
    .sec-hit-ring.sec-hit-allow { --sec-hit: #15803d; --sec-hit-soft: rgba(21, 128, 61, .06); }
    .sec-hit-ring.sec-hit-warn, .sec-hit-ring.sec-hit-isolate { --sec-hit: #a16207; --sec-hit-soft: rgba(161, 98, 7, .07); }
    .sec-hit-ring[hidden] { display: none; }
    .sec-hit-tag {
      position: absolute; left: 8px; top: -10px; display: inline-flex; align-items: center; gap: 6px;
      max-width: calc(100% - 20px); height: 18px; padding: 0 7px 0 6px; border-radius: 2px;
      background: var(--sec-hit); color: #fff; box-shadow: 0 2px 6px rgba(15, 23, 42, .18);
      font: 600 10.5px/18px Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .sec-hit-tag-dot { flex: none; width: 7px; height: 7px; border-radius: 50%; background: #fff; }
    .sec-hit-tag-action { padding-left: 7px; border-left: 1px solid rgba(255, 255, 255, .4); font-weight: 700; }
    @media (prefers-reduced-motion: no-preference) {
      .sec-hit-ring.sec-hit-in { animation: sec-hit-pulse 1.1s ease-out 1; }
    }
    @keyframes sec-hit-pulse {
      0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--sec-hit) 45%, transparent); }
      100% { box-shadow: 0 0 0 4px color-mix(in srgb, var(--sec-hit) 14%, transparent); }
    }
  `;
  document.head.appendChild(style);
}

function findRuleRowByName(ruleName) {
  const wanted = String(ruleName || "").trim().toLowerCase();
  return findRuleRows().find((row) => getRuleName(row).toLowerCase() === wanted) ||
    findDefaultRuleRows().find((row) => getRuleName(row).toLowerCase() === wanted) || null;
}

function syncRuleHits() {
  hitSyncFrame = null;
  for (const hit of currentHits) {
    // Cisco's table re-renders rows; re-find by name when ours was replaced.
    if (!hit.row || !hit.row.isConnected) hit.row = findRuleRowByName(hit.ruleName);
    const rect = hit.row && hit.row.getBoundingClientRect();
    const visible = rect && rect.height > 0 && rect.bottom > 0 && rect.top < window.innerHeight;
    hit.ring.hidden = !visible;
    if (!visible) continue;
    hit.ring.style.left = `${rect.left - 3}px`;
    hit.ring.style.top = `${rect.top - 2}px`;
    hit.ring.style.width = `${rect.width + 6}px`;
    hit.ring.style.height = `${rect.height + 4}px`;
  }
}

function scheduleHitSync() {
  if (!currentHits.length || hitSyncFrame) return;
  hitSyncFrame = requestAnimationFrame(syncRuleHits);
}

function clearRuleHits() {
  currentHits = [];
  const layer = document.getElementById(HIT_LAYER_ID);
  if (layer) layer.remove();
}

// targets: [{ ruleName, stages: ["DNS", "Web"], action: "block" }]
function highlightRules(targets) {
  ensureHitStyle();
  clearRuleHits();
  const layer = document.createElement("div");
  layer.id = HIT_LAYER_ID;
  document.body.appendChild(layer);
  if (!hitListenersBound) {
    hitListenersBound = true;
    window.addEventListener("scroll", scheduleHitSync, true);
    window.addEventListener("resize", scheduleHitSync);
    if (window.MutationObserver) new MutationObserver(scheduleHitSync).observe(document.body, { childList: true, subtree: true });
  }
  const missing = [];
  for (const target of targets || []) {
    const row = findRuleRowByName(target.ruleName);
    if (!row) { missing.push(target.ruleName); continue; }
    const action = HIT_ACTIONS.includes(target.action) ? target.action : "block";
    const ring = document.createElement("div");
    ring.className = `sec-hit-ring sec-hit-${action}`;
    const tag = document.createElement("span");
    tag.className = "sec-hit-tag";
    const dot = document.createElement("span");
    dot.className = "sec-hit-tag-dot";
    const stages = document.createElement("span");
    stages.textContent = (target.stages || []).join(" · ") || "Match";
    const verb = document.createElement("span");
    verb.className = "sec-hit-tag-action";
    verb.textContent = action.charAt(0).toUpperCase() + action.slice(1);
    tag.append(dot, stages, verb);
    ring.appendChild(tag);
    layer.appendChild(ring);
    currentHits.push({ ruleName: target.ruleName, row, ring });
  }
  syncRuleHits();
  requestAnimationFrame(() => currentHits.forEach((hit) => hit.ring.classList.add("sec-hit-in")));
  if (currentHits[0]) scrollToRuleHit(currentHits[0].ruleName);
  if (missing.length) console.warn("[SecPolicyChecker] HIGHLIGHT_RULES: no row found for", missing);
  return { found: currentHits.length, missing };
}

function scrollToRuleHit(ruleName) {
  const hit = currentHits.find((item) => item.ruleName === ruleName);
  const row = (hit && hit.row && hit.row.isConnected ? hit.row : null) || findRuleRowByName(ruleName);
  if (row) row.scrollIntoView({ behavior: "smooth", block: "center" });
}

// ---------------------------------------------------------------------------
// Hover popover — shows rule-matching details when hovering a source/
// destination chip in the Access Control Rules table on the live dashboard.
//
// Confirmed via live inspection: destination chips are <div
// data-testid="policy-destination-item">, with the visible (truncated) text
// in a nested ".cds-tag__children--wrap". "policy-source-item" is assumed
// analogous for the Sources column but has NOT been independently confirmed
// live — if it doesn't exist, that half of CHIP_SELECTOR just matches zero
// elements and this feature silently does nothing for source chips (no
// error either way).
//
// This is a SEPARATE popover from Cisco's own native tooltip (rendered via
// a floating-ui portal on hover) — we don't touch that tooltip's DOM at all,
// we just position our own element near the chip.
// ---------------------------------------------------------------------------

// Live dashboard selectors supplied from the rendered policy table. Source
// uses its column wrapper; destination uses the individual policy item.
var CHIP_SELECTOR = '[data-testid="policy-source-column"], [data-testid="policy-destination-item"]';
var HOVER_ROW_SELECTOR = 'table[rowkey="ruleId"] tr.cds-table__row, table.policy-default-rule-table tr.cds-table__row, [data-rule-id], .rule-row';
var HOVER_HIDE_DELAY_MS = 150;
// Programmatically-triggered popovers (from "Highlight on page") aren't
// under a real hover, so there's no natural mouseleave to close them —
// unlike genuine chip hovers, which keep using HOVER_HIDE_DELAY_MS. A few
// seconds gives the user time to read the match reasoning; moving their
// mouse onto the popover to read longer still cancels this via the
// popover's own existing mouseenter listener (see getHoverPopoverEl()),
// same as normal hover behavior — so it degrades to "stay open until the
// user moves away" once they actually engage with it.
var TRIGGERED_POPOVER_AUTO_HIDE_MS = 4000;

var hoverPopoverEl = null;
var hoverHideTimer = null;
var hoverPointer = null;
var attachedChips = new WeakSet();
var currentHighlightEl = null;
var triggeredDismissListener = null;
// Member cascade data (see openMemberLevel).
var currentMemberMaps = {};
var currentLookups = {};

// Cisco Hummingbird (hbr) token VALUES duplicated here as literals — this
// stylesheet is injected into the live dashboard's own document (a separate
// DOM/document context from the extension popup), so it cannot see the
// var(--hbr-*) custom properties defined in popup.html's :root. If the
// tokens in popup.html ever change, these literals must be updated to match
// by hand. See popup/popup.html for the canonical token definitions.
function ensureHoverPopoverStyle() {
  if (document.getElementById("sec-hover-popover-style")) return;
  const style = document.createElement("style");
  style.id = "sec-hover-popover-style";
  style.textContent = `
    #sec-hover-popover {
      position: fixed;
      z-index: 2147483647;
      width: min(440px, calc(100vw - 32px));
      max-height: min(520px, calc(100vh - 32px));
      background: #FFFFFF;
      border: 1px solid #d8e0ea;
      border-left: 4px solid #64748b;
      border-radius: 0;
      box-shadow: 0 18px 42px rgba(15,23,42,0.20);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-weight: 400;
      font-size: 13px;
      color: #1e293b;
      display: none;
      overflow: auto;
      transition: opacity 0.12s ease, transform 0.12s ease;
    }
    #sec-hover-popover[data-action="allow"]  { border-left-color: #166534; }
    #sec-hover-popover[data-action="block"]  { border-left-color: #991b1b; }
    #sec-hover-popover[data-action="isolate"]{ border-left-color: #6b21a8; }
    #sec-hover-popover.sec-hover-visible { display: block; }
    #sec-hover-popover .sec-hp-header {
      background: linear-gradient(135deg, #f8fafc, #eef6ff);
      color: #0f172a;
      font-weight: 700;
      font-size: 14px;
      padding: 12px 14px;
      word-break: break-word;
      border-bottom: 1px solid #dbe5f0;
    }
    #sec-hover-popover .sec-hp-body { padding: 12px 14px 14px; display: flex; flex-direction: column; gap: 10px; }
    #sec-hover-popover .sec-hp-meta { display: flex; flex-wrap: wrap; gap: 7px; align-items: center; }
    #sec-hover-popover .sec-hp-action {
      display: inline-block; font-size: 10px; font-weight: 800; padding: 4px 9px;
      border-radius: 0; letter-spacing: 0.04em; flex-shrink: 0;
    }
    #sec-hover-popover .sec-hp-action-allow   { background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }
    #sec-hover-popover .sec-hp-action-block   { background: #fee2e2; color: #991b1b; border: 1px solid #fecaca; }
    #sec-hover-popover .sec-hp-action-isolate { background: #f3e8ff; color: #6b21a8; border: 1px solid #e9d5ff; }
    #sec-hover-popover .sec-hp-action-unknown { background: #f1f5f9; color: #6b7280; border: 1px solid #e2e8f0; }
    #sec-hover-popover .sec-hp-priority { color: #475569; background: #f1f5f9; border-radius: 0; padding: 3px 8px; font-size: 11px; font-weight: 600; }
    #sec-hover-popover .sec-hp-findings { display: flex; flex-direction: column; gap: 5px; }
    #sec-hover-popover .sec-hp-finding  { font-size: 12px; line-height: 1.45; }
    #sec-hover-popover .sec-hp-empty    { color: #64748b; font-style: italic; font-size: 12px; }
    #sec-hover-popover .sec-hp-section {
      font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em;
      color: #64748b; padding-top: 2px;
    }
    #sec-hover-popover .sec-hp-match-title {
      font-size: 10px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.08em;
      color: #64748b; margin-top: 4px; padding-top: 9px; border-top: 1px solid #e2e8f0;
    }
    #sec-hover-popover .sec-hp-match { display: flex; flex-direction: column; gap: 5px; }
    #sec-hover-popover .sec-hp-match-item {
      font-size: 12px; line-height: 1.45; color: #334155;
      background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0;
      padding: 6px 8px; display: inline-flex; align-items: center; gap: 5px;
      overflow-wrap: anywhere; word-break: break-word;
    }
    #sec-hover-popover .sec-hp-match-key { color: #64748b; font-weight: 600; flex-shrink: 0; }
    #sec-hover-popover .sec-hp-match-val { color: #0f172a; font-weight: 600; overflow-wrap: anywhere; word-break: break-word; }
    #sec-hover-popover .sec-hp-reason-title { color: #0f172a; border-top-color: #e2e8f0; }
    #sec-hover-popover .sec-hp-reason {
      background: #f8fafc; border-left: none; padding: 6px 8px; border-radius: 0;
    }
    /* Condition chips + security profile chips (matches rules tab psc-chip) */
    #sec-hover-popover .sec-hp-chips {
      display: flex; flex-wrap: wrap; gap: 4px;
    }
    #sec-hover-popover .sec-hp-chips.sec-hp-condition-list {
      flex-direction: column; align-items: stretch; gap: 6px;
    }
    #sec-hover-popover .sec-hp-chips.sec-hp-condition-list .sec-hp-chip {
      display: flex; width: 100%; box-sizing: border-box; padding: 7px 9px;
    }
    #sec-hover-popover .sec-hp-chip {
      background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 0;
      padding: 2px 6px; font-size: 10.5px; color: #334155;
      display: inline-flex; align-items: center; gap: 4px;
      overflow-wrap: anywhere; word-break: break-word;
    }
    #sec-hover-popover .sec-hp-chip-key { color: #64748b; font-weight: 600; flex-shrink: 0; }
    #sec-hover-popover .sec-hp-chip-val { color: #0f172a; font-weight: 600; overflow-wrap: anywhere; word-break: break-word; }

    /* Expandable group chips on the rule card + hover member cascade */
    #sec-hover-popover .sec-hp-chip-text { min-width: 0; flex: 1; }
    #sec-hover-popover .sec-hp-chip.sec-hp-expandable {
      cursor: default; border-color: #bfdbfe; background: #f5f9ff; color: #0f172a;
      transition: background-color .12s ease, border-color .12s ease, box-shadow .12s ease;
    }
    #sec-hover-popover .sec-hp-chip.sec-hp-expandable:hover,
    #sec-hover-popover .sec-hp-chip.sec-hp-expandable.sec-open {
      background: #e8f1ff; border-color: #60a5fa; box-shadow: inset 3px 0 0 #2563eb;
    }
    .sec-mp-chevron {
      flex: none; width: 7px; height: 7px; margin: 0 2px 0 8px;
      border-top: 1.5px solid currentColor; border-right: 1.5px solid currentColor;
      transform: rotate(45deg); color: #64748b; transition: transform .12s ease, color .12s ease;
    }
    .sec-open > .sec-mp-chevron, .sec-mp-expandable:hover > .sec-mp-chevron,
    .sec-hp-expandable:hover > .sec-mp-chevron { color: #2563eb; transform: translateX(2px) rotate(45deg); }
    .sec-member-panel {
      position: fixed; z-index: 2147483647; width: min(320px, calc(100vw - 32px));
      max-height: min(440px, calc(100vh - 24px)); display: flex; flex-direction: column;
      background: #fff; border: 1px solid #d8e0ea; border-radius: 0;
      box-shadow: 0 1px 2px rgba(15,23,42,.06), 0 16px 40px rgba(15,23,42,.18);
      font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      font-size: 13px; color: #1e293b; opacity: 0; transform: translateX(-4px);
      transition: opacity .12s ease, transform .12s ease;
    }
    .sec-member-panel[data-dir="left"] { transform: translateX(4px); }
    .sec-member-panel.sec-member-visible { opacity: 1; transform: none; }
    .sec-member-panel .sec-mp-header {
      display: flex; align-items: baseline; justify-content: space-between; gap: 10px;
      padding: 8px 10px 6px; border-bottom: 1px solid #edf1f6;
    }
    .sec-member-panel .sec-mp-title { min-width: 0; color: #0f172a; font-weight: 650; overflow-wrap: anywhere; }
    .sec-member-panel .sec-mp-count { flex: none; color: #64748b; font-size: 11px; font-variant-numeric: tabular-nums; }
    .sec-member-panel .sec-mp-filter {
      margin: 8px 10px 2px; height: 30px; padding: 4px 8px; border: 1px solid #d8e0ea; border-radius: 0;
      font-family: inherit; font-size: 12px; color: #0f172a; background: #f8fafc; outline: none;
    }
    .sec-member-panel .sec-mp-filter:focus { border-color: #2563eb; background: #fff; box-shadow: 0 0 0 2px rgba(37,99,235,.15); }
    .sec-member-panel .sec-mp-list { overflow-y: auto; padding: 4px 0 6px; overscroll-behavior: contain; }
    .sec-member-panel .sec-mp-row {
      display: flex; align-items: center; gap: 8px; min-height: 28px; padding: 4px 10px;
      color: #1e293b; outline: none;
    }
    .sec-member-panel .sec-mp-row[hidden] { display: none; }
    .sec-member-panel .sec-mp-row:hover { background: #f5f7fa; }
    .sec-member-panel .sec-mp-expandable:hover, .sec-member-panel .sec-mp-expandable.sec-open {
      background: #e8f1ff; box-shadow: inset 3px 0 0 #2563eb;
    }
    .sec-member-panel .sec-mp-row:focus-visible,
    #sec-hover-popover .sec-hp-expandable:focus-visible { outline: 2px solid #2563eb; outline-offset: -2px; }
    .sec-member-panel .sec-mp-label { flex: 1; min-width: 0; overflow-wrap: anywhere; line-height: 1.35; }
    .sec-member-panel .sec-mp-tag {
      flex: none; padding: 1px 6px; background: #f1f5f9; color: #64748b;
      font-size: 10px; font-weight: 600; letter-spacing: .02em;
    }
    .sec-member-panel .sec-mp-empty { padding: 10px 12px; color: #64748b; font-size: 12px; }
    .sec-member-panel .sec-mp-error { display: flex; flex-direction: column; align-items: flex-start; gap: 8px; padding: 10px 12px 12px; color: #475569; font-size: 12px; line-height: 1.45; }
    .sec-member-panel .sec-mp-retry {
      min-height: 28px; padding: 3px 10px; border: 1px solid #cbd5e1; border-radius: 0; background: #fff;
      color: #0f172a; font: 600 12px Inter, system-ui, sans-serif; cursor: pointer;
    }
    .sec-member-panel .sec-mp-retry:hover { border-color: #0f172a; }
    .sec-member-panel .sec-mp-retry:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
    .sec-member-panel .sec-mp-skel { height: 22px; margin: 6px 12px; width: auto; }
    @media (prefers-reduced-motion: reduce) {
      .sec-member-panel, .sec-mp-chevron, #sec-hover-popover .sec-hp-chip.sec-hp-expandable { transition: none; }
    }
    @keyframes sec-skel {
      0% { background-position: 100% 0; }
      100% { background-position: -100% 0; }
    }
    .sec-skel {
      background: linear-gradient(90deg, #eef2f7 0%, #f8fafc 45%, #eef2f7 90%);
      background-size: 200% 100%;
      animation: sec-skel 1.1s ease-in-out infinite;
      border: 1px solid #e2e8f0;
    }
    #sec-hover-popover .sec-hp-status { display: flex; flex-direction: column; gap: 2px; font-size: 12px; color: #475569; line-height: 1.45; }
    #sec-hover-popover .sec-hp-status strong { color: #0f172a; font-size: 13px; font-weight: 650; }
    #sec-hover-popover .sec-hp-status-stalled strong { color: #9a3412; }
    #sec-hover-popover .sec-hp-skel {
      height: 28px; width: 100%; box-sizing: border-box;
    }
    #sec-hover-popover .sec-hp-skel-title {
      height: 14px; width: 42%; margin-bottom: 2px;
    }
  `;
  document.head.appendChild(style);
}

function getHoverPopoverEl() {
  ensureHoverPopoverStyle();
  if (!hoverPopoverEl) {
    hoverPopoverEl = document.createElement("div");
    hoverPopoverEl.id = "sec-hover-popover";
    document.body.appendChild(hoverPopoverEl);

    // Interactive: keep it open if the mouse moves from the chip onto the
    // popover itself (e.g. to read a long finding message), same 150ms
    // hide-delay pattern as leaving the chip.
    hoverPopoverEl.addEventListener("mouseenter", () => clearTimeout(hoverHideTimer));
    hoverPopoverEl.addEventListener("mouseleave", (event) => {
      const next = event.relatedTarget;
      if (!next && memberLevels.length) return;
      if (isInsideMemberUi(next)) return;
      scheduleHideHoverPopover();
    });
  }
  return hoverPopoverEl;
}

function hideHoverPopover() {
  if (hoverPopoverEl) hoverPopoverEl.classList.remove("sec-hover-visible");
  hideMemberPopover();
}

function scheduleHideHoverPopover(delayMs) {
  clearTimeout(hoverHideTimer);
  hoverHideTimer = setTimeout(hideHoverPopover, delayMs !== undefined ? delayMs : HOVER_HIDE_DELAY_MS);
}

// Cursor-proximate placement for normal hovers; supports a DOMRect-like
// anchor for programmatic highlight popovers.
function positionHoverPopover(popover, anchor) {
  const margin = 12;
  const point = anchor && typeof anchor.x === "number"
    ? { x: anchor.x, y: anchor.y }
    : { x: anchor.left, y: anchor.bottom };
  let top = point.y + 16;
  let left = point.x + 16;

  const { width, height } = popover.getBoundingClientRect();

  if (left + width > window.innerWidth - margin) {
    left = Math.max(margin, point.x - width - 16);
  }
  if (top + height > window.innerHeight - margin) {
    top = Math.max(margin, point.y - height - 16);
  }

  popover.style.top  = `${top}px`;
  popover.style.left = `${left}px`;
}

// ---------------------------------------------------------------------------
// Member cascade — hover a group/list chip on the rule card and its members
// fly out beside it; hover a nested group inside that panel and the next
// level flies out beside that one, to any depth (like OS menus). Each level
// is its own panel, so opening a deeper level never rebuilds the row the
// pointer is on. Click / Enter / → open immediately for touch and keyboard.
// Everything closes when the pointer leaves the card and all panels.
// ---------------------------------------------------------------------------

var MEMBER_OPEN_DELAY_MS = 140;
var MEMBER_FILTER_THRESHOLD = 10;
var memberLevels = [];
var memberIntentTimer = null;
var memberOutsideListener = null;

function memberSurfaces() {
  return [hoverPopoverEl].concat(memberLevels.map((level) => level.el)).filter(Boolean);
}

function isInsideMemberUi(node) {
  return Boolean(node) && memberSurfaces().some((el) => el.contains(node));
}

function closeMemberLevels(fromDepth) {
  while (memberLevels.length > fromDepth) {
    const level = memberLevels.pop();
    level.el.remove();
    if (level.anchor) {
      level.anchor.classList.remove("sec-open");
      level.anchor.setAttribute("aria-expanded", "false");
    }
  }
  if (!memberLevels.length && memberOutsideListener) {
    document.removeEventListener("mousedown", memberOutsideListener, true);
    memberOutsideListener = null;
  }
}

function hideMemberPopover() {
  clearTimeout(memberIntentTimer);
  closeMemberLevels(0);
}

// Hover intent: a short delay so sweeping the pointer across rows does not
// flash every group open. `open` null means "close anything deeper".
function scheduleMemberIntent(depth, open) {
  clearTimeout(memberIntentTimer);
  memberIntentTimer = setTimeout(() => {
    if (open) open();
    else closeMemberLevels(depth);
  }, MEMBER_OPEN_DELAY_MS);
}

function positionMemberLevel(level) {
  const el = level.el;
  if (!level.anchor || !level.anchor.isConnected) return;
  const margin = 12;
  const gap = 6;
  const anchorRect = level.anchor.getBoundingClientRect();
  const container = level.anchor.closest(".sec-member-panel, #sec-hover-popover");
  const box = container ? container.getBoundingClientRect() : anchorRect;
  const { width, height } = el.getBoundingClientRect();
  // Panels already on screen (the card and shallower levels) must stay
  // readable, so a side only counts if the new panel clears all of them.
  const ancestors = memberSurfaces().filter((surface) => surface !== el).map((surface) => surface.getBoundingClientRect());
  const clears = (left) => ancestors.every((rect) => left >= rect.right || left + width <= rect.left);
  const rightLeft = box.right + gap;
  const leftLeft = box.left - gap - width;
  const fits = {
    right: rightLeft + width <= window.innerWidth - margin && clears(rightLeft),
    left: leftLeft >= margin && clears(leftLeft),
  };
  const other = level.dir === "right" ? "left" : "right";
  const chosen = fits[level.dir] ? level.dir : fits[other] ? other : null;
  let left;
  let top = anchorRect.top - 9;
  if (chosen) {
    level.dir = chosen;
    left = chosen === "right" ? rightLeft : leftLeft;
  } else {
    // No clear side: overlap the parent panel but drop below the row that
    // opened this level so it stays visible.
    left = level.dir === "right" ? rightLeft - width / 2 : leftLeft + width / 2;
    top = anchorRect.bottom + 4;
  }
  left = Math.max(margin, Math.min(left, window.innerWidth - margin - width));
  top = Math.max(margin, Math.min(top, window.innerHeight - margin - height));
  const dir = level.dir;
  el.style.left = `${left}px`;
  el.style.top = `${top}px`;
  el.dataset.dir = dir;
}

function memberTag(member) {
  const kind = member && member.kind;
  if (kind === "identityGroups" || kind === "networkObjectGroups" || kind === "serviceObjectGroups" || kind === "privateResourceGroups") return "Group";
  if (kind === "networkObjects") return "Object";
  if (kind === "serviceObjects" || kind === "service") return "Service";
  if (kind === "privateResources") return "Resource";
  if (kind === "application") return "App";
  if (kind === "category") return "Category";
  const value = member && member.value !== undefined ? String(member.value).trim() : "";
  if (value) {
    if (/^[0-9a-f.:]+\/\d+$/i.test(value)) return "Range";
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value) || (/^[0-9a-f:]+$/i.test(value) && value.includes(":"))) return "IP";
    return "Domain";
  }
  return "";
}

function isExpandableMember(member, memberMaps) {
  if (!member || member.id === undefined || !isExpandableKind(member.kind)) return false;
  const entry = memberMaps[member.kind] && memberMaps[member.kind][String(member.id)];
  // A cached empty object or leaf-only record has nothing to show.
  if (entry && entry.resolved && Array.isArray(entry.members) && entry.members.length === 0) return false;
  return true;
}

function renderMemberLevel(level, title, members, memberMaps, lookups, loading) {
  const el = level.el;
  el.replaceChildren();
  el.setAttribute("aria-busy", loading ? "true" : "false");
  const header = document.createElement("div");
  header.className = "sec-mp-header";
  const titleEl = document.createElement("span");
  titleEl.className = "sec-mp-title";
  titleEl.textContent = title;
  header.appendChild(titleEl);
  if (!loading) {
    const count = document.createElement("span");
    count.className = "sec-mp-count";
    count.textContent = `${members.length} ${members.length === 1 ? "member" : "members"}`;
    header.appendChild(count);
  }
  el.appendChild(header);

  const list = document.createElement("div");
  list.className = "sec-mp-list";
  list.setAttribute("role", "list");

  if (loading) {
    for (let i = 0; i < 4; i++) {
      const row = document.createElement("div");
      row.className = "sec-mp-skel sec-skel";
      list.appendChild(row);
    }
    el.appendChild(list);
    return;
  }
  if (!members.length) {
    const empty = document.createElement("div");
    empty.className = "sec-mp-empty";
    empty.textContent = "This group is empty.";
    list.appendChild(empty);
    el.appendChild(list);
    return;
  }

  const rows = members.map((member) => {
    const expandable = isExpandableMember(member, memberMaps);
    const label = resolveMemberLabel(member, memberMaps, lookups) || "Unnamed member";
    const row = document.createElement("div");
    row.className = "sec-mp-row" + (expandable ? " sec-mp-expandable" : "");
    row.setAttribute("role", "listitem");
    const text = document.createElement("span");
    text.className = "sec-mp-label";
    text.textContent = label;
    row.appendChild(text);
    const tag = memberTag(member);
    if (tag) {
      const tagEl = document.createElement("span");
      tagEl.className = "sec-mp-tag";
      tagEl.textContent = tag;
      row.appendChild(tagEl);
    }
    if (expandable) {
      const chevron = document.createElement("span");
      chevron.className = "sec-mp-chevron";
      chevron.setAttribute("aria-hidden", "true");
      row.appendChild(chevron);
      row.tabIndex = 0;
      row.setAttribute("aria-haspopup", "true");
      row.setAttribute("aria-expanded", "false");
      const open = () => openMemberLevel(level.depth + 1, row, label, member.kind, member.id, memberMaps, lookups);
      row.addEventListener("mouseenter", () => scheduleMemberIntent(level.depth + 1, open));
      row.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        clearTimeout(memberIntentTimer);
        open();
      });
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " " || event.key === "ArrowRight") {
          event.preventDefault();
          open();
          const next = memberLevels[level.depth + 1];
          if (next) setTimeout(() => { const first = next.el.querySelector(".sec-mp-row[tabindex]"); if (first) first.focus(); }, 0);
        }
      });
    } else {
      row.addEventListener("mouseenter", () => scheduleMemberIntent(level.depth + 1, null));
    }
    row.addEventListener("keydown", (event) => {
      if (event.key === "Escape" || event.key === "ArrowLeft") {
        event.preventDefault();
        const anchor = level.anchor;
        closeMemberLevels(level.depth);
        if (anchor && anchor.focus) anchor.focus();
      }
    });
    row.dataset.search = label.toLowerCase();
    return row;
  });

  if (members.length > MEMBER_FILTER_THRESHOLD) {
    const filter = document.createElement("input");
    filter.type = "search";
    filter.className = "sec-mp-filter";
    filter.placeholder = `Filter ${members.length} members`;
    filter.setAttribute("aria-label", "Filter members");
    filter.addEventListener("input", () => {
      const query = filter.value.trim().toLowerCase();
      closeMemberLevels(level.depth + 1);
      rows.forEach((row) => { row.hidden = Boolean(query) && !row.dataset.search.includes(query); });
    });
    filter.addEventListener("keydown", (event) => event.stopPropagation());
    el.appendChild(filter);
  }
  rows.forEach((row) => list.appendChild(row));
  el.appendChild(list);
}

function renderMemberError(level, title, retry) {
  const el = level.el;
  el.replaceChildren();
  el.setAttribute("aria-busy", "false");
  const header = document.createElement("div");
  header.className = "sec-mp-header";
  const titleEl = document.createElement("span");
  titleEl.className = "sec-mp-title";
  titleEl.textContent = title;
  header.appendChild(titleEl);
  const body = document.createElement("div");
  body.className = "sec-mp-error";
  body.setAttribute("role", "status");
  const text = document.createElement("span");
  text.textContent = "Couldn't load the members. Your dashboard session may have expired.";
  const button = document.createElement("button");
  button.type = "button";
  button.className = "sec-mp-retry";
  button.textContent = "Try again";
  button.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    retry();
  });
  body.append(text, button);
  el.append(header, body);
}

function openMemberLevel(depth, anchor, title, kind, id, memberMaps, lookups) {
  const existing = memberLevels[depth];
  if (existing && existing.anchor === anchor && existing.kind === kind && existing.id === String(id)) {
    closeMemberLevels(depth + 1);
    return;
  }
  closeMemberLevels(depth);
  if (!anchor || !anchor.isConnected) return;
  clearTimeout(hoverHideTimer);
  ensureHoverPopoverStyle();

  const el = document.createElement("div");
  el.className = "sec-member-panel";
  el.setAttribute("role", "group");
  el.setAttribute("aria-label", title || "Members");
  el.addEventListener("mouseenter", () => clearTimeout(hoverHideTimer));
  el.addEventListener("mouseleave", (event) => {
    if (isInsideMemberUi(event.relatedTarget)) return;
    scheduleHideHoverPopover();
  });
  document.body.appendChild(el);

  const parent = memberLevels[depth - 1];
  const level = { el, depth, kind, id: String(id), anchor, dir: parent ? parent.dir : "right" };
  memberLevels.push(level);
  anchor.classList.add("sec-open");
  anchor.setAttribute("aria-expanded", "true");

  if (!memberOutsideListener) {
    memberOutsideListener = (event) => {
      const path = typeof event.composedPath === "function" ? event.composedPath() : [event.target];
      if (path.some((node) => node && node.nodeType === 1 && isInsideMemberUi(node))) return;
      hideMemberPopover();
    };
    document.addEventListener("mousedown", memberOutsideListener, true);
  }

  const cached = memberMaps[kind] && memberMaps[kind][String(id)];
  const header = title || (cached && cached.name) || "Members";
  const ready = hasCachedMembers(memberMaps, kind, id);
  renderMemberLevel(level, header, ready ? cached.members : [], memberMaps, lookups, !ready);
  positionMemberLevel(level);
  requestAnimationFrame(() => el.classList.add("sec-member-visible"));
  if (ready) return;

  loadMemberLevel(level, header, title, memberMaps, lookups);
}

function loadMemberLevel(level, header, title, memberMaps, lookups) {
  const { depth, kind, id } = level;
  requestMembers(kind, id, (response) => {
    if (memberLevels[depth] !== level) return;
    if (!response || (response.ok === false && !(response.members && response.members.length))) {
      renderMemberError(level, header, () => {
        renderMemberLevel(level, header, [], memberMaps, lookups, true);
        loadMemberLevel(level, header, title, memberMaps, lookups);
      });
      positionMemberLevel(level);
      return;
    }
    const resolved = (response && response.members) || [];
    const name = title || resolveMemberLabel({ id, kind }, memberMaps, lookups) || (response && response.name) || header;
    persistMemberFrame(kind, id, name, resolved, memberMaps);
    renderMemberLevel(level, name, resolved, memberMaps, lookups, false);
    positionMemberLevel(level);
  });
}

function lookupName(map, id) {
  if (!map || id === undefined || id === null) return "";
  const raw = map[String(id)] !== undefined ? map[String(id)] : map[id];
  if (!raw) return "";
  if (typeof raw === "string") return raw;
  return raw.name || raw.label || raw.displayName || "";
}

// Resolve a member's display label from membership data first, then the
// already-loaded identity/object catalogs. Never prefer a bare numeric id
// when a name exists somewhere we already fetched.
function resolveMemberLabel(member, memberMaps, lookups) {
  if (member && member.value !== undefined && member.value !== "") return String(member.value);
  if (member && member.name) return String(member.name);
  if (member && member.label) return String(member.label);
  const id = member && member.id !== undefined ? String(member.id) : "";
  if (!id) return "";
  const maps = memberMaps || {};
  const lu = lookups || {};
  const om = lu.objectMaps || {};
  const kindMaps = {
    identityGroups: maps.identityGroups,
    identity: lu.identities,
    networkObjectGroups: maps.networkObjectGroups || om.networkObjectGroups,
    networkObjects: maps.networkObjects || om.networkObjects,
    networkObject: om.networkObjects,
    serviceObjectGroups: maps.serviceObjectGroups || om.serviceObjectGroups,
    serviceObjects: maps.serviceObjects || om.serviceObjects,
    serviceObject: om.serviceObjects,
    destinationLists: maps.destinationLists || om.destinationLists,
    applicationLists: maps.applicationLists || om.applicationLists,
    application: lu.apps,
    categoryLists: maps.categoryLists || om.categoryLists,
    category: lu.categories,
    privateResourceGroups: maps.privateResourceGroups || om.privateResourceGroups,
    privateResources: maps.privateResources || om.privateResources,
    privateResource: om.privateResources,
  };
  const fromKind = lookupName(kindMaps[member.kind], id);
  if (fromKind) return fromKind;
  const fromMember = maps[member.kind] && maps[member.kind][id] && maps[member.kind][id].name;
  if (fromMember) return fromMember;
  return lookupName(lu.identities, id)
    || lookupName(om.privateResources, id)
    || lookupName(om.networkObjects, id)
    || lookupName(om.networkObjectGroups, id)
    || lookupName(om.serviceObjects, id)
    || lookupName(om.serviceObjectGroups, id)
    || lookupName(om.destinationLists, id)
    || lookupName(om.applicationLists, id)
    || lookupName(om.categoryLists, id)
    || lookupName(om.privateResourceGroups, id)
    || lookupName(lu.apps, id)
    || lookupName(lu.categories, id)
    || "";
}

function isExpandableKind(kind) {
  return Boolean(kind && MEMBER_CONDITION_KIND[kind]);
}

function membersNeedNames(kind, members) {
  if (kind !== "identityGroups" && kind !== "sourceNetworks") return false;
  return (members || []).some((m) => m && m.id !== undefined && !m.name && !m.label && m.value === undefined);
}

function hasCachedMembers(memberMaps, kind, id) {
  const entry = memberMaps && memberMaps[kind] && memberMaps[kind][String(id)];
  if (!entry || !Array.isArray(entry.members) || entry.resolved === false) return false;
  if ((kind === "destinationLists" || kind === "identityGroups" || kind === "sourceNetworks") && !entry.members.length) return false;
  if (membersNeedNames(kind, entry.members)) return false;
  return true;
}

function logMembershipDebug(payload) {
  try {
    console.log("[policy-checker membership]", payload);
  } catch (_) {}
}

function requestMembers(kind, id, callback) {
  if (hasCachedMembers(currentMemberMaps, kind, id)) {
    const cached = currentMemberMaps[kind][String(id)];
    const response = { ok: true, name: cached.name, members: cached.members, cached: true, debug: { kind, id, source: "page-cache", members: cached.members } };
    logMembershipDebug(response.debug);
    callback(response);
    return;
  }
  safeRuntimeMessage({ type: "RESOLVE_MEMBERS", kind, id: String(id) }, (response) => {
    const next = response || { ok: false, members: [], name: String(id) };
    logMembershipDebug(next.debug || { kind, id, error: next.error || "no response", members: next.members });
    callback(next);
  });
}

function persistMemberFrame(kind, id, title, members, memberMaps) {
  if (!memberMaps[kind]) memberMaps[kind] = {};
  memberMaps[kind][String(id)] = { name: title, members: members || [] };
  currentMemberMaps = memberMaps;
}

// ---------------------------------------------------------------------------
// loadLookups / summarizeConditions — duplicated from popup-sections.js
// (same convention already used for the hbr design tokens and the
// condition-dimension bucketing in service-worker.js: content-script.js runs
// in the dashboard page's own document, a separate execution context from
// the popup, so it can't call popup-sections.js's functions directly — they
// live nested inside that file's buildRulesList() closure and aren't
// exported via window.PopupSections anyway).
//
// summarizeConditions() below is copied verbatim (same switch cases, same
// bitfieldPosition-vs-categoryId handling, same application_ids apps/
// protocols dual-lookup) so the dashboard popover shows the exact same
// "what this rule matches" text as the Rules tab card, not a simplified or
// diverging version.
//
// loadLookups() differs from popup-sections.js's version out of necessity:
// popup-sections.js fetches "../data/*.json" (relative to popup.html's own
// URL, which works because that request resolves against the extension's
// own origin). A content script's fetch() resolves relative to the
// DASHBOARD page's origin instead, so a relative path would 404 — this
// version uses api.runtime.getURL() to build an absolute chrome-extension://
// URL, the same technique already used for the iframe's src in
// initEmbeddedPopup().
// ---------------------------------------------------------------------------

var hoverLookupsPromise = null;
function loadLookups() {
  if (!hoverLookupsPromise) {
    const extensionUrl = runtimeUrl("data/categories-lookup.json");
    if (!extensionUrl) return Promise.resolve({ categories: {}, apps: {}, protocols: {} });
    const base = extensionUrl.replace(/data\/categories-lookup\.json$/, "data/");
    hoverLookupsPromise = Promise.all([
      fetch(base + "categories-lookup.json").then((r) => r.json()).catch(() => ({})),
      fetch(base + "apps-lookup.json").then((r) => r.json()).catch(() => ({})),
      fetch(base + "protocols-lookup.json").then((r) => r.json()).catch(() => ({})),
    ]).then(([categories, apps, protocols]) => ({ categories, apps, protocols }));
  }
  return hoverLookupsPromise;
}

// Default fallback dictionary for identity types — mirrors popup-sections.js's
// DEFAULT_IDENTITY_TYPES. Used when the service worker hasn't resolved the
// org's identity types yet, so the hover popover can still show human-readable
// labels instead of raw numeric IDs.
var HOVER_DEFAULT_IDENTITY_TYPES = {
  "0": "Tags", "1": "Networks", "2": "Network Devices", "3": "AD Groups",
  "4": "Users & AD Groups", "5": "AD Computers", "6": "Internal Networks",
  "7": "AD Users", "8": "SAML Users & Groups", "9": "Roaming Computers",
  "10": "Device Posture Profiles", "11": "Security Group Tags (SGT)",
  "21": "Sites", "32": "Network Devices", "34": "Posture",
  "36": "Mobile Devices", "37": "OS Version & Patch Level",
  "38": "Chromebooks", "40": "Network Tunnels", "43": "G Suite Users",
  "45": "G Suite OUs", "50": "Endpoint Requirements",
  "52": "Catalyst SD-WAN Service VPN IDs", "54": "Security Group Tags",
  "57": "ZTNA Client",
  "user": "Active Directory Users & Groups", "device": "Network Devices",
  "site": "Sites & Branches", "group": "Users & AD Groups",
  "roaming": "Roaming Computers", "internal_network": "Internal Networks",
  "tunnel": "Network Tunnels", "saml": "SAML Users & Groups",
  "ip_subnet": "IP Subnets / CIDR", "posture": "Device Posture Profiles",
  "sgt": "Security Group Tags (SGT)",
};

// identities differs from categories/apps/protocols above: those are static
// JSON shipped with the extension, this is live per-org data resolved by
// service-worker.js's resolveIdentities() during the most recent RUN_SCAN
// and cached in chrome.storage.session. This content script runs in its own
// execution context (separate from popup.js), so it can't read popup.js's
// in-memory copy — GET_IDENTITY_MAP asks the service worker for its cached
// copy instead. NOT cached at module scope like hoverLookupsPromise, since
// the map only exists after at least one successful scan and can go stale
// between hovers — re-fetching per hover is cheap (just a storage read).
function loadIdentityMap() {
  return new Promise((resolve) => {
    safeRuntimeMessage({ type: "GET_IDENTITY_MAP" }, (response) => {
      resolve(response && response.identityMap || {});
    });
  });
}

// Identity type map — live per-org data resolved by service-worker.js's
// resolveIdentityTypes() and cached in chrome.storage.local as
// sse_identity_type_map. Merged with HOVER_DEFAULT_IDENTITY_TYPES for
// fallback labels (same pattern as popup-sections.js's DEFAULT_IDENTITY_TYPES
// merge). Fetched per-hover like loadIdentityMap() — cheap storage read.
function loadIdentityTypeMap() {
  return new Promise((resolve) => {
    safeRuntimeMessage({ type: "GET_IDENTITY_TYPE_MAP" }, (response) => {
      resolve(response && response.identityTypeMap || {});
    });
  });
}

// Same live per-org pattern as loadIdentityMap() above, but for
// private_resource_ids/private_resource_group_ids — resolved by
// service-worker.js's resolveObjectRefs() and cached separately (different
// ID space, see popup.js's currentObjectMap comment).
function loadObjectMap() {
  return new Promise((resolve) => {
    safeRuntimeMessage({ type: "GET_OBJECT_MAP" }, (response) => {
      if (!response) {
        resolve({ objectMap: {}, objectMaps: {} });
        return;
      }
      resolve({ objectMap: response.objectMap || {}, objectMaps: response.objectMaps || {} });
    });
  });
}

// Group/list membership resolved by service-worker.js's resolveMembership()
// and cached in chrome.storage.local as sse_member_maps — powers the
// recursive "expand this source/destination" popover. Re-fetched per hover
// (cheap storage read); empty until at least one membership fetch has run.
function loadMemberMaps() {
  return new Promise((resolve) => {
    safeRuntimeMessage({ type: "GET_MEMBER_MAP" }, (response) => {
      resolve(response && response.memberMaps ? response.memberMaps : {});
    });
  });
}

// Maps a source/destination condition attributeName to the membership map key
// whose members should be expandable in the popover. Only group/list types
// are expandable; leaf conditions (identities, IPs, single apps) are not.
var MEMBER_CONDITION_KIND = {
  identityGroups: true,
  networkObjectGroups: true,
  networkObjects: true,
  serviceObjectGroups: true,
  serviceObjects: true,
  destinationLists: true,
  applicationLists: true,
  categoryLists: true,
  privateResourceGroups: true,
  privateResources: true,
};

var MEMBER_CONDITION_MAP = {
  "umbrella.source.networkobjectgroupids": "networkObjectGroups",
  "umbrella.source.networkobjectgroupids_shared": "networkObjectGroups",
  "umbrella.source.networkobjectids": "networkObjects",
  "umbrella.source.networkobjectids_shared": "networkObjects",
  "umbrella.destination.networkobjectgroupids": "networkObjectGroups",
  "umbrella.destination.networkobjectids": "networkObjects",
  "umbrella.destination.serviceobjectgroupids": "serviceObjectGroups",
  "umbrella.destination.serviceobjectids": "serviceObjects",
  "umbrella.destination.destination_list_ids": "destinationLists",
  "umbrella.destination.application_list_ids": "applicationLists",
  "umbrella.destination.category_list_ids": "categoryLists",
  "umbrella.destination.private_resource_group_ids": "privateResourceGroups",
  "umbrella.destination.private_resource_ids": "privateResources",
  "umbrella.source.identity_ids": "identityGroups",
  "umbrella.source.identity_ids_shared": "identityGroups",
};

var IDENTITY_GROUP_TYPE_IDS = {
  "3": true, "4": true, "8": true, "11": true, "40": true, "45": true, "54": true,
};

function conditionKindFor(attributeName) {
  const attr = String(attributeName || "").toLowerCase();
  if (MEMBER_CONDITION_MAP[attr]) return MEMBER_CONDITION_MAP[attr];
  if (attr.includes("private_resource_group")) return "privateResourceGroups";
  if (attr.includes("private_resource")) return "privateResources";
  if (attr.includes("networkobjectgroup")) return "networkObjectGroups";
  if (attr.includes("networkobject")) return "networkObjects";
  if (attr.includes("serviceobjectgroup")) return "serviceObjectGroups";
  if (attr.includes("serviceobject")) return "serviceObjects";
  if (attr.includes("destination_list")) return "destinationLists";
  if (attr.includes("application_list")) return "applicationLists";
  if (attr.includes("category_list")) return "categoryLists";
  if (attr.includes("identity_ids") || attr.includes("identity_group")) return "identityGroups";
  return null;
}

function isIdentityGroupId(id, lookups) {
  const sid = String(id);
  const typeId = lookups && lookups.sourceIdentityTypeIds && lookups.sourceIdentityTypeIds[sid];
  if (typeId !== undefined && typeId !== null) return Boolean(IDENTITY_GROUP_TYPE_IDS[String(typeId)]);
  // Fail closed: a named AD user / roaming computer / device is a leaf.
  // Only expand when we know this id is a group type.
  return false;
}

// Returns expandable member descriptors for a condition, or null if the
// condition is not a group/list type. Each descriptor: { id, kind, label }.
// Names come from membership data first, then already-loaded catalogs.
function expansionForCondition(cond, memberMaps, lookups) {
  if (!cond || !cond.raw || !cond.raw.attributeName) return null;
  const key = conditionKindFor(cond.raw.attributeName);
  if (!key) return null;
  const av = Array.isArray(cond.raw.attributeValue) ? cond.raw.attributeValue : [cond.raw.attributeValue];
  const byId = {};
  for (const id of av) {
    if (id === undefined || id === null || id === "*" || String(id).toLowerCase() === "any") continue;
    const sid = String(id);
    if (key === "identityGroups" && !isIdentityGroupId(sid, lookups)) continue;
    const label = resolveMemberLabel({ id: sid, kind: key }, memberMaps || {}, lookups || {});
    byId[sid] = { id: sid, kind: key, label };
  }
  return Object.keys(byId).length ? byId : null;
}

function summarizeConditions(rule, lookups) {
  const objectMaps = lookups.objectMaps || {};
  const objectName = (map, id, fallback) => {
    const raw = map && map[String(id)];
    if (typeof raw === "string" && raw) return raw;
    if (raw && typeof raw === "object") return raw.name || raw.label || raw.displayName || fallback;
    return fallback;
  };
  const networkObjects = objectMaps.networkObjects || {};
  const networkObjectGroups = objectMaps.networkObjectGroups || {};
  const serviceObjects = objectMaps.serviceObjects || {};
  const serviceObjectGroups = objectMaps.serviceObjectGroups || {};
  const destinationLists = objectMaps.destinationLists || {};
  const applicationLists = objectMaps.applicationLists || {};
  const categoryLists = objectMaps.categoryLists || {};
  const geolocations = objectMaps.geolocations || {};
  const postureProfiles = objectMaps.postureProfiles || {};
  const privateResources = objectMaps.privateResources || lookups.objects || {};
  const privateResourceGroups = objectMaps.privateResourceGroups || {};
  const countryName = (code) => {
    if (typeof code !== "string" || !/^[A-Za-z]{2}$/.test(code)) return String(code);
    try { return new Intl.DisplayNames(["en"], { type: "region" }).of(code.toUpperCase()) || code; }
    catch (_) { return code; }
  };
  const conds = rule.ruleConditions || rule.conditions || [];
  if (!Array.isArray(conds) || conds.length === 0) {
    return [{ text: "Applies to all traffic (no specific conditions)", raw: null }];
  }

  const summaries = [];
  for (const c of conds) {
    const type = c.attributeName;
    const values = c.attributeValue;

    if (!type || values === undefined) continue;

    let summaryText = "";
    switch (type) {
      case "umbrella.source.all":
      case "umbrella.destination.all":
        if (values === true) summaryText = `${type.split(".")[1]} = Any`;
        break;
      case "umbrella.source.identity_ids": {
        // Same resolution as popup-sections.js's identical case — see that
        // file's comment for the full explanation of what identityMap
        // (lookups.identities here) covers and why some IDs may still fall
        // back to raw.
        const mergedTypes = Object.assign({}, HOVER_DEFAULT_IDENTITY_TYPES, lookups.identityTypes || {});
        const identityNames = (Array.isArray(values) ? values : [values]).map((id) => {
          const raw = lookups.identities && (lookups.identities[String(id)] !== undefined ? lookups.identities[String(id)] : lookups.identities[id]);
          const name = typeof raw === "string" ? raw : (raw && (raw.name || raw.label || raw.displayName)) || "";
          const typeId = lookups.sourceIdentityTypeIds && lookups.sourceIdentityTypeIds[String(id)];
          const type = typeId !== undefined ? (mergedTypes[String(typeId)] || `Type ${typeId}`) : null;
          const label = name || "Deleted identity";
          return type ? `${label} (${type})` : label;
        });
        summaryText = `Source Identities: ${identityNames.join(", ")}`;
        break;
      }
      case "umbrella.source.identity_type_ids":
      case "umbrella.source.identity_type_ids_shared": {
        // Resolve identity type IDs to human-readable labels using the
        // live identityTypeMap from the service worker, with
        // HOVER_DEFAULT_IDENTITY_TYPES as fallback (same pattern as
        // popup-sections.js's DEFAULT_IDENTITY_TYPES merge).
        const mergedTypes = Object.assign({}, HOVER_DEFAULT_IDENTITY_TYPES, lookups.identityTypes || {});
        const typeNames = (Array.isArray(values) ? values : [values]).map((id) => {
          return mergedTypes[String(id)] || mergedTypes[id] || "Identity Type";
        });
        summaryText = `Identity Type: ${typeNames.join(", ")}`;
        break;
      }
      case "umbrella.destination.application_category_ids":
      case "umbrella.destination.category_ids": // alias — same concept, different field name per org (see matcher.js)
        // values here are bitfieldPosition, not categoryId — categories-lookup.json
        // is keyed by bitfieldPosition for exactly this reason (see data/categories-lookup.json).
        const catNames = Array.isArray(values) ? values.map((id) => {
          const entry = lookups.categories[id];
          if (!entry) return "Content Category";
          return typeof entry === "object" ? (entry.name || entry.label || "Content Category") : entry;
        }) : [];
        summaryText = `App Categories: ${catNames.length ? catNames.join(", ") : "Content Categories"}`;
        break;
      case "umbrella.destination.application_ids": {
        // CONFIRMED via live API payload: umbrella.destination.application_ids is
        // the ONLY field used for both Internet Applications AND Application
        // Protocols — there is no separate umbrella.destination.protocol_ids field.
        // Resolve against apps-lookup.json first, then protocols-lookup.json.
        const appMatches = [];
        const protoMatches = [];
        const unresolved = [];
        for (const id of Array.isArray(values) ? values : []) {
          if (lookups.apps[id] !== undefined) {
            appMatches.push(lookups.apps[id]);
          } else if (lookups.protocols[id] !== undefined) {
            protoMatches.push(lookups.protocols[id]);
          } else {
            unresolved.push(id);
          }
        }
        const parts = [];
        if (appMatches.length) parts.push(`Applications: ${appMatches.join(", ")}`);
        if (protoMatches.length) parts.push(`Protocols: ${protoMatches.join(", ")}`);
        if (unresolved.length) parts.push(`Applications: ${unresolved.map(() => "Internet Application").join(", ")}`);
        summaryText = parts.length ? parts.join(" ; ") : "Applications: Configured Apps";
        break;
      }
      case "umbrella.destination.composite_inline_ip": {
        const items = Array.isArray(values) ? values : [values];
        const parts = items.map((item) => {
          if (item && typeof item === "object" && !Array.isArray(item)) {
            const ip = Array.isArray(item.ip) ? item.ip.join(", ") : (item.ip || "*");
            const port = Array.isArray(item.port) ? item.port.join(", ") : (item.port || "*");
            const proto = item.protocol || "ANY";
            return `IP: ${ip}, Port: ${port}, Protocol: ${proto}`;
          }
          return String(item);
        });
        summaryText = `IP/Port/Protocol: ${parts.join(" + ")}`;
        break;
      }
      case "umbrella.destination.destination_list_ids": {
        const names = (Array.isArray(values) ? values : [values]).map((id) =>
          objectName(destinationLists, id, `Unresolved Destination List (${id})`));
        summaryText = `Destination List: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.application_list_ids": {
        const names = (Array.isArray(values) ? values : [values]).map((id) =>
          objectName(applicationLists, id, `Unresolved Application List (${id})`));
        summaryText = `Application List: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.category_list_ids": {
        const names = (Array.isArray(values) ? values : [values]).map((id) =>
          objectName(categoryLists, id, `Unresolved Category List (${id})`));
        summaryText = `Category List: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.geolocations": {
        const names = (Array.isArray(values) ? values : [values]).map((code) =>
          objectName(geolocations, code, countryName(code)));
        summaryText = `Countries: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.appRiskProfileId": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => {
          const name = lookups.appRiskProfiles && lookups.appRiskProfiles[String(id)];
          return name || "App Risk Profile";
        });
        summaryText = ids.length === 1
          ? `App Risk Profile: ${names[0]}`
          : `App Risk Profiles: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.private_resource_types": {
        const items = Array.isArray(values) ? values : [values];
        const labels = items.map((v) => {
          if (v === "apps") return "Applications";
          if (v === "networks") return "Networks";
          if (v === "websites") return "Websites";
          return String(v).charAt(0).toUpperCase() + String(v).slice(1);
        });
        summaryText = `Resource Types: ${labels.join(", ")}`;
        break;
      }
      case "umbrella.destination.private_resource_ids":
      case "umbrella.destination.private_resource_group_ids": {
        const isGroup = type.endsWith("_group_ids");
        const label = isGroup ? "Private Resource Groups" : "Private Resources";
        const map = isGroup ? privateResourceGroups : privateResources;
        const resNames = (Array.isArray(values) ? values : [values]).map((id) =>
          objectName(map, id, `Unresolved ${isGroup ? "Private Resource Group" : "Private Resource"} (${id})`));
        summaryText = `${label}: ${resNames.join(", ")}`;
        break;
      }
      case "umbrella.source.networkObjectIds":
      case "umbrella.source.networkObjectIds_shared": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(networkObjects, id, `Unresolved Network Object (${id})`));
        summaryText = `Source Network Objects: ${names.join(", ")}`;
        break;
      }
      case "umbrella.source.networkObjectGroupIds":
      case "umbrella.source.networkObjectGroupIds_shared": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(networkObjectGroups, id, `Unresolved Network Object Group (${id})`));
        summaryText = `Source Network Object Groups: ${names.join(", ")}`;
        break;
      }
      case "umbrella.source.geolocations": {
        const geos = Array.isArray(values) ? values : [values];
        const names = geos.map((g) => {
          if (!g || typeof g !== "string" || g.length !== 2 || !/^[A-Za-z]{2}$/.test(g)) return g;
          try {
            return new Intl.DisplayNames(["en"], { type: "region" }).of(g.toUpperCase()) || g;
          } catch {
            return g;
          }
        });
        summaryText = `Source Countries: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.networkObjectGroupIds": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(networkObjectGroups, id, `Unresolved Network Object Group (${id})`));
        summaryText = `Destination Network Object Groups: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.networkObjectIds": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(networkObjects, id, `Unresolved Network Object (${id})`));
        summaryText = `Destination Network Objects: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.serviceObjectIds": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(serviceObjects, id, `Unresolved Service Object (${id})`));
        summaryText = `Service Objects: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.serviceObjectGroupIds": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(serviceObjectGroups, id, `Unresolved Service Object Group (${id})`));
        summaryText = `Service Object Groups: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.application_category_ids": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => {
          const entry = lookups.categories && lookups.categories[id];
          return typeof entry === "object" ? (entry.name || entry.label || `Unresolved Application Category (${id})`) : (entry || `Unresolved Application Category (${id})`);
        });
        summaryText = `Application Categories: ${names.join(", ")}`;
        break;
      }
      case "umbrella.destination.saasTenantIds": {
        const ids = Array.isArray(values) ? values : [values];
        summaryText = `SaaS Tenant Controls: ${ids.join(", ")}`;
        break;
      }
      case "umbrella.destination.security_group_tag_ids":
      case "umbrella.destination.any_security_group_tag": {
        const ids = Array.isArray(values) ? values : [values];
        summaryText = `Security Group Tags (SGT): ${ids.join(", ")}`;
        break;
      }
      case "umbrella.posture.ipsProfileId": {
        const ids = Array.isArray(values) ? values : [values];
        const names = ids.map((id) => objectName(postureProfiles, id, `Unresolved IPS Profile (${id})`));
        summaryText = `IPS Profile: ${names.join(", ")}`;
        break;
      }
      case "umbrella.posture.profileIdClientbased":
      case "umbrella.posture.profileIdClientless":
      case "umbrella.posture.vpnProfileId":
      case "umbrella.posture.webProfileId": {
        const ids = Array.isArray(values) ? values : [values];
        const label = type.replace("umbrella.posture.", "").replace(/([A-Z])/g, " $1");
        const names = ids.map((id) => objectName(postureProfiles, id, `Unresolved Posture Profile (${id})`));
        summaryText = `Posture (${label}): ${names.join(", ")}`;
        break;
      }
      default: {
        // Generic fallback for any unrecognized umbrella.* condition type —
        // see popup-sections.js for the full comment on why this exists.
        const humanized = type
          .replace(/^umbrella\./, "")
          .replace(/\./g, " ")
          .replace(/_/g, " ")
          .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
          .toLowerCase()
          .trim();
        summaryText = `Matches a specific ${humanized} condition${Array.isArray(values) ? ` (${values.join(", ")})` : ` (${values})`}`;
        break;
      }
    }
    if (summaryText) {
      summaries.push({ text: summaryText, raw: { attributeName: type, attributeOperator: c.attributeOperator, attributeValue: values } });
    }
  }
  return summaries.length ? summaries : [{ text: "Has conditions, but of unknown types", raw: null }];
}

// testMatchReasons: the Test Policy result's "Matched because" strings,
// passed through from a "Highlight on page" click (see highlightRule()).
// When present, this REPLACES the generic "What this rule matches" summary
// (summarizeConditions() output) with the specific reasoning for the exact
// test the user ran — showing both would be redundant/confusing (one is
// "what this rule matches in general", the other is "why YOUR test matched
// it"). Findings are still shown either way ("in addition to findings").
function appendMatchReasonSection(body, reasons) {
  const title = document.createElement("div");
  title.className = "sec-hp-match-title sec-hp-reason-title";
  title.textContent = "Why your test matched this rule";
  body.appendChild(title);

  const wrap = document.createElement("div");
  wrap.className = "sec-hp-match sec-hp-reason";
  for (const reason of reasons) {
    const row = document.createElement("div");
    row.className = "sec-hp-match-item";
    if (typeof reason === "object" && reason !== null) {
      // Object-style condition: render as chips like rules tab
      if (reason.condition) {
        const keyEl = document.createElement("span");
        keyEl.className = "sec-hp-match-key";
        keyEl.textContent = reason.condition + ":";
        row.appendChild(keyEl);
      }
      const valParts = [];
      if (reason.value) valParts.push(reason.value);
      if (reason.operator) valParts.push("(" + reason.operator + ")");
      if (reason.action) valParts.push("→ " + reason.action);
      if (valParts.length > 0) {
        const valEl = document.createElement("span");
        valEl.className = "sec-hp-match-val";
        valEl.textContent = " " + valParts.join(" ");
        row.appendChild(valEl);
      } else {
        row.appendChild(document.createTextNode(JSON.stringify(reason)));
      }
    } else {
      row.textContent = String(reason);
    }
    wrap.appendChild(row);
  }
  body.appendChild(wrap);
}

function hoverSideForAnchor(anchorEl) {
  if (!anchorEl || !anchorEl.closest) return "all";
  if (anchorEl.closest('[data-testid="policy-source-column"]')) return "source";
  if (anchorEl.closest('[data-testid="policy-destination-item"]')) return "destination";
  const cell = anchorEl.closest("td");
  const row = anchorEl.closest("tr");
  const table = row && row.closest("table");
  if (!cell || !row || !table) return "all";
  const headers = Array.from(table.querySelectorAll("thead th, thead [role='columnheader']"));
  const index = Array.from(row.children).indexOf(cell);
  const headerText = ((headers[index] && (headers[index].innerText || headers[index].textContent)) || "").trim().toLowerCase();
  if (/^source/.test(headerText) || index === 2) return "source";
  if (/^dest/.test(headerText) || index === 3) return "destination";
  return "all";
}

function renderHoverPopoverContent(popover, ruleName, rule, findings, matchSummary, testMatchReasons, hoverSide) {
  hideMemberPopover();
  popover.innerHTML = "";

  // Set data-action for left border accent color (matches rules tab cards)
  if (rule && rule.action) {
    popover.setAttribute("data-action", (rule.action || "").toLowerCase());
  } else if (testMatchReasons && testMatchReasons.length > 0 && testMatchReasons[0].action) {
    popover.setAttribute("data-action", testMatchReasons[0].action.toLowerCase());
  } else {
    popover.removeAttribute("data-action");
  }

  const header = document.createElement("div");
  header.className = "sec-hp-header";
  header.textContent = ruleName;
  popover.appendChild(header);

  const body = document.createElement("div");
  body.className = "sec-hp-body";

  const hasReasons = Array.isArray(testMatchReasons) && testMatchReasons.length > 0;

  if (!rule) {
    if (hasReasons) {
      appendMatchReasonSection(body, testMatchReasons);
    } else {
      const empty = document.createElement("div");
      empty.className = "sec-hp-empty";
      empty.textContent = "Open the extension popup to see rule findings.";
      body.appendChild(empty);
    }
    popover.appendChild(body);
    return;
  }

  // --- Top line: action pill + priority (matches rules tab psc-rule-top-line) ---
  const meta = document.createElement("div");
  meta.className = "sec-hp-meta";

  const action = (rule.action || "unknown").toLowerCase();
  const actionBadge = document.createElement("span");
  actionBadge.className = `sec-hp-action sec-hp-action-${["allow", "block", "isolate"].includes(action) ? action : "unknown"}`;
  actionBadge.textContent = action.toUpperCase();
  meta.appendChild(actionBadge);

  const priorityValue = rule.rulePriority !== undefined ? rule.rulePriority : rule.order;
  if (priorityValue !== undefined && priorityValue !== null) {
    const priority = document.createElement("span");
    priority.className = "sec-hp-priority";
    priority.textContent = `Priority #${priorityValue}`;
    meta.appendChild(priority);
  }
  if (rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess)) {
    const scope = rule.trafficScope || rule.ruleAccess || rule.raw.ruleAccess;
    const scopeEl = document.createElement("span");
    scopeEl.className = "sec-hp-priority";
    scopeEl.textContent = scope === "private_network" ? "Private Access" : "Internet";
    meta.appendChild(scopeEl);
  }
  if (rule.is_default) {
    const priority = document.createElement("span");
    priority.className = "sec-hp-priority";
    priority.textContent = "Default rule (always evaluated last)";
    meta.appendChild(priority);
  }

  body.appendChild(meta);

  // --- Findings / Audit Feedback section ---
  const findingsWrap = document.createElement("div");
  findingsWrap.className = "sec-hp-findings";

  if (!findings || findings.length === 0) {
    const clean = document.createElement("div");
    clean.className = "sec-hp-empty";
    clean.textContent = "No findings for this rule.";
    findingsWrap.appendChild(clean);
  } else {
    for (const f of findings) {
      const row = document.createElement("div");
      row.className = "sec-hp-finding";
      row.appendChild(document.createTextNode(f.message));
      findingsWrap.appendChild(row);
    }
  }
  body.appendChild(findingsWrap);

  const sourceConditions = (matchSummary || []).filter(item => /^umbrella\.source\./.test(item.raw && item.raw.attributeName || ""));
  const destinationConditions = (matchSummary || []).filter(item => /^umbrella\.destination\./.test(item.raw && item.raw.attributeName || ""));
  const postureConditions = (matchSummary || []).filter(item => /^umbrella\.posture\./.test(item.raw && item.raw.attributeName || ""));
  const conditionDisplayLines = (condition) => {
    const attribute = (condition.raw && condition.raw.attributeName || "").toLowerCase();
    const text = condition.text || "";
    const colon = text.indexOf(":");
    const value = (colon >= 0 ? text.slice(colon + 1) : text).trim();
    if (attribute === "umbrella.source.all") return ["Any source"];
    if (attribute === "umbrella.destination.all") return ["Any destination"];
    // Type-only source conditions are policy scope, not a selectable person
    // or device. Keep that distinction explicit in the hover card.
    if (attribute.includes("identity_type")) {
      return value.split(", ").map(part => `Any ${part.trim()}`).filter(Boolean);
    }
    const typeLabel =
      attribute.includes("private_resource_group") ? "Private Resource Group" :
      attribute.includes("private_resource") ? "Private Resource" :
      attribute.includes("destination_list") ? "Destination List" :
      attribute.includes("application_list") ? "Application List" :
      attribute.includes("category_list") ? "Category List" :
      attribute.includes("application_category") ? "Application Category" :
      attribute.includes("category_ids") ? "Content Category" :
      attribute.includes("application_ids") ? "Application" :
      attribute.includes("networkobjectgroup") ? "Network Object Group" :
      attribute.includes("networkobject") ? "Network Object" :
      attribute.includes("serviceobjectgroup") ? "Service Object Group" :
      attribute.includes("appriskprofileid") ? "App Risk Profile" :
      attribute.includes("security_group_tag") ? "SGT" :
      attribute.includes("saastenant") ? "SaaS Tenant" :
      attribute.includes("geolocations") ? "Country" :
      attribute.includes("posture.") ? "Posture Profile" :
      "";
    // A condition can contain several selected catalog entries. Render each
    // as an individual fact, not a dense comma-separated field-value label.
    const values = value.split(" ; ").flatMap(part =>
      Array.isArray(condition.raw && condition.raw.attributeValue) && condition.raw.attributeValue.length > 1
        ? part.split(", ")
        : [part]
    ).map(part => part.trim()).filter(Boolean);
    return values.map(part => {
      if (!typeLabel || /\([^)]*\)$/.test(part)) return part;
      return `${part} (${typeLabel})`;
    });
  };

  const renderConditionGroup = (title, items) => {
    if (!items.length) return;
    const section = document.createElement("div");
    section.className = "sec-hp-section";
    section.textContent = title;
    body.appendChild(section);
    const chipsWrap = document.createElement("div");
    chipsWrap.className = "sec-hp-chips sec-hp-condition-list";
    for (const cs of items) {
      const expandableById = expansionForCondition(cs, currentMemberMaps, currentLookups) || {};
      const lines = conditionDisplayLines(cs);
      const ids = Array.isArray(cs.raw && cs.raw.attributeValue)
        ? cs.raw.attributeValue.map(String)
        : (cs.raw && cs.raw.attributeValue !== undefined ? [String(cs.raw.attributeValue)] : []);
      const count = Math.max(lines.length, ids.length);
      for (let i = 0; i < count; i++) {
        const item = expandableById[ids[i]] || null;
        const line = lines[i] || (item && item.label);
        if (!line) continue;
        const chip = document.createElement("span");
        chip.className = "sec-hp-chip" + (item ? " sec-hp-expandable" : "");
        const chipText = document.createElement("span");
        chipText.className = "sec-hp-chip-text";
        chipText.textContent = line;
        chip.appendChild(chipText);
        if (item) {
          const chevron = document.createElement("span");
          chevron.className = "sec-mp-chevron";
          chevron.setAttribute("aria-hidden", "true");
          chip.appendChild(chevron);
          chip.tabIndex = 0;
          chip.setAttribute("aria-haspopup", "true");
          chip.setAttribute("aria-expanded", "false");
          const open = () => openMemberLevel(0, chip, line, item.kind, item.id, currentMemberMaps, currentLookups);
          chip.addEventListener("mouseenter", () => scheduleMemberIntent(0, open));
          chip.addEventListener("click", (event) => {
            event.preventDefault();
            event.stopPropagation();
            clearTimeout(memberIntentTimer);
            open();
          });
          chip.addEventListener("keydown", (event) => {
            if (event.key === "Enter" || event.key === " " || event.key === "ArrowRight") {
              event.preventDefault();
              open();
            }
          });
        } else {
          chip.addEventListener("mouseenter", () => scheduleMemberIntent(0, null));
        }
        chipsWrap.appendChild(chip);
      }
    }
    body.appendChild(chipsWrap);
  };
  const side = hoverSide === "source" || hoverSide === "destination" ? hoverSide : "all";
  if (side !== "destination") renderConditionGroup("Source", sourceConditions);
  if (side !== "source") renderConditionGroup("Destination", destinationConditions);
  if (side === "all") renderConditionGroup("Posture / Security Profile", postureConditions);

  // --- Security profile chips (IPS, AMP, TLS, DLP) ---
  if (rule.security_profiles) {
    const sp = rule.security_profiles;
    const spWrap = document.createElement("div");
    spWrap.className = "sec-hp-chips";
    var spItems = [
      { label: "IPS", on: sp.ips_enabled },
      { label: "AMP", on: sp.amp_malware_enabled },
      { label: "TLS", on: sp.tls_decryption_enabled },
      { label: "DLP", on: sp.dlp_enabled }
    ];
    for (var i = 0; i < spItems.length; i++) {
      var s = spItems[i];
      if (s.on === undefined) continue;
      var chip = document.createElement("span");
      chip.className = "sec-hp-chip";
      chip.style.background = s.on ? "#f0fdf4" : "#f8fafc";
      chip.style.borderColor = s.on ? "#bbf7d0" : "#cbd5e1";
      chip.style.color = s.on ? "#166534" : "#64748b";
      chip.style.fontWeight = s.on ? "700" : "500";
      chip.textContent = s.label + ": " + (s.on ? "ON" : "OFF");
      spWrap.appendChild(chip);
    }
    if (spWrap.children.length > 0) body.appendChild(spWrap);
  }

  // --- Why your test matched this rule ---
  if (hasReasons) {
    appendMatchReasonSection(body, testMatchReasons);
  }

  popover.appendChild(body);
}

// Reuses the existing GET_RULES / GET_FINDINGS messages to service-worker.js
// (session-storage reads of data already fetched by RUN_SCAN) — does NOT
// trigger a new live API fetch.
function loadRulesAndFindings(callback) {
  let rules = null, findings = null;
  const maybeDone = () => {
    if (rules === null || findings === null) return;
    callback(rules, findings);
  };

  safeRuntimeMessage({ type: "GET_RULES" }, (response) => {
    rules = (response && response.rules) || [];
    maybeDone();
  });
  safeRuntimeMessage({ type: "GET_FINDINGS" }, (response) => {
    findings = (response && response.findings) || [];
    maybeDone();
  });
}

// Shared by both genuine chip hovers and the "Highlight on page" triggered
// popover (see highlightRule()). testMatchReasons and autoHideMs are both
// optional — omitted for normal hover (generic content, hover-only dismiss),
// provided for the triggered case (test-specific reasoning, timed dismiss).
function showPopoverForRule(anchorEl, ruleName, testMatchReasons, autoHideMs) {
  const anchorRect = anchorEl.getBoundingClientRect();
  const popover = getHoverPopoverEl();
  const isTriggered = Array.isArray(testMatchReasons) && testMatchReasons.length > 0;
  const hoverSide = isTriggered ? "all" : hoverSideForAnchor(anchorEl);

  // Clean up any previous triggered-dismiss listener
  if (triggeredDismissListener) {
    document.removeEventListener("mousedown", triggeredDismissListener, true);
    triggeredDismissListener = null;
  }

  function renderHoverSkeleton() {
    popover.innerHTML = "";
    const header = document.createElement("div");
    header.className = "sec-hp-header";
    header.textContent = ruleName;
    popover.appendChild(header);
    const body = document.createElement("div");
    body.className = "sec-hp-body";
    const title = document.createElement("div");
    title.className = "sec-hp-skel-title sec-skel";
    body.appendChild(title);
    for (let i = 0; i < 5; i++) {
      const row = document.createElement("div");
      row.className = "sec-hp-skel sec-skel";
      body.appendChild(row);
    }
    popover.appendChild(body);
  }

  function reveal() {
    popover.classList.add("sec-hover-visible");
    // Keep the native cursor beside the card rather than anchoring to the
    // complete table-row rectangle, which can be far from where the user is
    // reading. Triggered popovers still use their highlight row rectangle.
    const anchor = isTriggered
      ? { x: anchorRect.left, y: anchorRect.bottom }
      : (hoverPointer || { x: anchorRect.left, y: anchorRect.bottom });
    positionHoverPopover(popover, anchor);
    if (isTriggered) {
      // Triggered popover: stays open until user clicks outside
      triggeredDismissListener = (e) => {
        // Ignore clicks inside the popover or on the highlighted row
        if (popover.contains(e.target)) return;
        if (currentHighlightEl && currentHighlightEl.contains(e.target)) return;
        // Dismiss
        popover.classList.remove("sec-hover-visible");
        if (currentHighlightEl) {
          currentHighlightEl.classList.remove("sec-highlight");
          currentHighlightEl = null;
        }
        document.removeEventListener("mousedown", triggeredDismissListener, true);
        triggeredDismissListener = null;
      };
      document.addEventListener("mousedown", triggeredDismissListener, true);
    } else if (autoHideMs !== undefined) {
      scheduleHideHoverPopover(autoHideMs);
    }
  }

  // For triggered (simulation) popovers: show immediately with match reasons,
  // then enrich with rules/findings data if it arrives in time.
  if (isTriggered) {
    renderHoverPopoverContent(popover, ruleName, null, null, null, testMatchReasons, hoverSide);
    reveal();
  } else {
    renderHoverSkeleton();
    reveal();
  }

  const requestKey = ++hoverRequestSeq;
  let attempts = 0;
  const load = () => loadRulesAndFindings((rules, findings) => {
    if (requestKey !== hoverRequestSeq) return; // a newer hover took over
    // Enrich the already-visible popover with rule details if available
    const lowerName = ruleName.toLowerCase();
    const rule = rules.find(r => (r.name || "").trim().toLowerCase() === lowerName);
    const ruleFindings = findings.filter(f => f.ruleName.trim().toLowerCase() === lowerName);

    if (rule || ruleFindings.length > 0) {
      renderHoverPopoverContent(popover, ruleName, rule, ruleFindings, null, testMatchReasons, hoverSide);
      // Keep the native cursor beside the card rather than anchoring to the
      // complete table-row rectangle, which can be far from where the user is
      // reading. Triggered popovers still use their highlight row rectangle.
      const anchor = isTriggered
        ? { x: anchorRect.left, y: anchorRect.bottom }
        : (hoverPointer || { x: anchorRect.left, y: anchorRect.bottom });
      positionHoverPopover(popover, anchor);
    }

    if (!isTriggered) {
      // Hover-only: only show after data loads
      if (rules.length === 0 && findings.length === 0) {
        // Rules are still being read (first load after sign-in). Keep the
        // card in a loading state and retry until they arrive.
        attempts += 1;
        const stalled = attempts * HOVER_RETRY_MS >= HOVER_STALL_MS;
        renderHoverStatus(popover, ruleName, stalled ? "stalled" : "loading");
        reveal();
        if (!stalled) {
          setTimeout(() => {
            if (requestKey === hoverRequestSeq && popover.classList.contains("sec-hover-visible")) load();
          }, HOVER_RETRY_MS);
        }
        return;
      }

      if (!rule) {
        if (ruleFindings.length) renderHoverPopoverContent(popover, ruleName, null, ruleFindings, null, testMatchReasons, hoverSide);
        else renderHoverStatus(popover, ruleName, "missing");
        reveal();
        return;
      }
    }

    // Match summary needs the lookup JSONs (categories/apps/protocols) plus
    // the live identityMap, identityTypeMap, and objectMap — fetched lazily,
    // see loadLookups()/loadIdentityMap()/loadIdentityTypeMap()/loadObjectMap()
    // above. Still fetched even when testMatchReasons is provided, in case
    // some future caller wants both sections; renderHoverPopoverContent() itself
    // decides which one to actually show.
    Promise.all([loadLookups(), loadIdentityMap(), loadIdentityTypeMap(), loadObjectMap(), loadMemberMaps()]).then(([lookups, identityMap, identityTypeMap, objectMapResult, memberMaps]) => {
      lookups.identities = identityMap;
      lookups.identityTypes = Object.assign({}, HOVER_DEFAULT_IDENTITY_TYPES, identityTypeMap);
      const om = objectMapResult.objectMaps || {};
      lookups.sourceIdentityTypeIds = om.sourceIdentityTypeIds || {};
      lookups.objects = objectMapResult.objectMap || objectMapResult;
      lookups.objectMaps = om;
      // Wire typed object maps for lookups (appRiskProfiles, etc.)
      lookups.appRiskProfiles = om.appRiskProfiles || {};
      lookups.postureProfiles = om.postureProfiles || {};
      lookups.geolocations = om.geolocations || {};
      lookups.memberMaps = memberMaps || {};
      currentMemberMaps = memberMaps || {};
      currentLookups = lookups;
      const matchSummary = summarizeConditions(rule, lookups);
      renderHoverPopoverContent(popover, ruleName, rule, ruleFindings, matchSummary, testMatchReasons, hoverSide);
      reveal();
    });
  });
  load();
}

// Card states while the rule itself is not available. Never an empty card:
// say what is happening and what (if anything) the user can do.
var HOVER_RETRY_MS = 1500;
var HOVER_STALL_MS = 20000;
var hoverRequestSeq = 0;
var HOVER_STATUS_COPY = {
  loading: ["Loading your policy…", "Rule details appear here as soon as the rules are read from the dashboard."],
  stalled: ["Policy data hasn't loaded", "The checker reads rules with your dashboard sign-in. Reload this page; if it keeps happening, sign in again."],
  missing: ["Not in the loaded data yet", "This rule may be new. The checker picks it up when the page reloads."],
};

function renderHoverStatus(popover, ruleName, state) {
  hideMemberPopover();
  popover.removeAttribute("data-action");
  popover.replaceChildren();
  const header = document.createElement("div");
  header.className = "sec-hp-header";
  header.textContent = ruleName;
  const body = document.createElement("div");
  body.className = "sec-hp-body";
  const copy = HOVER_STATUS_COPY[state] || HOVER_STATUS_COPY.loading;
  const status = document.createElement("div");
  status.className = `sec-hp-status sec-hp-status-${state}`;
  status.setAttribute("role", "status");
  const title = document.createElement("strong");
  title.textContent = copy[0];
  const text = document.createElement("span");
  text.textContent = copy[1];
  status.append(title, text);
  body.appendChild(status);
  if (state === "loading") {
    for (let i = 0; i < 3; i++) {
      const row = document.createElement("div");
      row.className = "sec-hp-skel sec-skel";
      body.appendChild(row);
    }
  }
  popover.append(header, body);
}

function policyConditionCells() {
  // Cisco has changed the inner markup of these cells across dashboard builds,
  // so test IDs alone are not reliable. Resolve the Source/Destination column
  // indices from each table's visible headers and bind the corresponding cells.
  const cells = new Set(document.querySelectorAll(CHIP_SELECTOR));
  const rows = [...findRuleRows(), ...findDefaultRuleRows()];
  for (const row of rows) {
    const table = row.closest("table");
    if (!table) continue;
    const headerNodes = Array.from(table.querySelectorAll("thead th, thead [role='columnheader']"));
    const indices = headerNodes
      .map((header, index) => ({ index, text: (header.innerText || header.textContent || "").trim().toLowerCase() }))
      .filter(({ text }) => /^(source|sources|destination|destinations)$/.test(text))
      .map(({ index }) => index);
    const rowCells = row.querySelectorAll(":scope > td");
    // Current Cisco policy tables render Priority, Rule Name, Source and
    // Destination in cells 0–3. If a dashboard build hides its semantic
    // header markup, retain this observed column-position fallback.
    const candidateIndices = indices.length ? indices : [2, 3];
    for (const index of candidateIndices) {
      if (rowCells[index]) cells.add(rowCells[index]);
    }
  }
  return cells;
}

function handlePolicyColumnMouseEnter(event) {
  const target = event.currentTarget;
  clearTimeout(hoverHideTimer);
  hoverPointer = { x: event.clientX, y: event.clientY };
  const row = target.closest("tr");
  if (!row) return;
  const ruleName = getRuleName(row);
  if (ruleName && ruleName !== "unknown") showPopoverForRule(target, ruleName, null, undefined);
}

function handlePolicyColumnMouseLeave(event) {
  const target = event.currentTarget;
  const related = event.relatedTarget;
  if (related && target.contains(related)) return;
  scheduleHideHoverPopover();
}

function attachChipListeners() {
  // Bind directly to the live Cisco source-column and destination-item nodes.
  // The mutation observer below attaches handlers to replacement nodes after
  // the dashboard virtualizes, filters, or re-sorts its rule rows.
  const targets = document.querySelectorAll(CHIP_SELECTOR);
  for (const target of targets) {
    if (attachedChips.has(target)) continue;
    attachedChips.add(target);
    target.addEventListener("mouseenter", handlePolicyColumnMouseEnter);
    target.addEventListener("mouseleave", handlePolicyColumnMouseLeave);
  }
}

function initHoverPopover() {
  attachChipListeners();

  // Cisco replaces these source/destination nodes when the virtualized table
  // sorts, filters, or pages; bind handlers to each new live node.
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(attachChipListeners, 150);
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

// ---------------------------------------------------------------------------
// Embedded popup — injects the extension's existing popup.html as a toggled
// iframe panel on the dashboard page itself, as an alternative to only being
// reachable via the toolbar icon. This is a placement/injection wrapper only
// — popup.html/popup.js/popup-sections.js/matcher.js are reused completely
// unmodified and load inside the iframe exactly as they do in the toolbar
// popup today.
//
// Positioned bottom-right, separate from the hover popover (which appears
// near hovered chips higher up the page) to avoid overlap. Uses a slightly
// lower z-index (2147483646) than the hover popover's max value
// (2147483647) so the hover popover would still win in the rare case they
// ever visually coincide.
// ---------------------------------------------------------------------------

// popup.html's own body is hardcoded to width: 660px (see popup/popup.html)
// and we were told not to modify popup.html/js — so the panel WIDTH stays
// tied to that real width (plus a small buffer) rather than an arbitrary
// guess; shrinking it further would just push the iframe's own content into
// a horizontal scrollbar, not actually make it smaller. HEIGHT has no such
// constraint (the popup's content scrolls vertically fine at any height —
// #psc-panel-body/rules list just gets a taller/shorter viewport), so it's
// reduced here to cover less of the dashboard behind the panel. The iframe
// still scrolls internally for anything taller than this.
var EMBED_PANEL_WIDTH = 680;
var EMBED_PANEL_HEIGHT = 480;

function ensureEmbeddedPopupStyle() {
  const oldStyle = document.getElementById("sec-embed-popup-style");
  if (oldStyle) oldStyle.remove();
  const style = document.createElement("style");
  style.id = "sec-embed-popup-style";
  style.textContent = `
    #sec-embed-toggle {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 54px;
      height: 54px;
      border-radius: 9999px;
      background: linear-gradient(135deg, #0b64bd 0%, #004b99 100%) !important;
      color: #ffffff !important;
      border: 1.5px solid rgba(255, 255, 255, 0.28) !important;
      cursor: pointer;
      box-shadow: 0 12px 32px -4px rgba(11, 100, 189, 0.42), 0 4px 12px -2px rgba(19, 25, 35, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.35) !important;
      z-index: 2147483646;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: transform 220ms cubic-bezier(.2, .8, .2, 1), box-shadow 220ms ease, background 160ms ease;
      padding: 0;
    }
    #sec-embed-toggle:hover {
      background: linear-gradient(135deg, #0e72d4 0%, #0056b3 100%) !important;
      transform: translateY(-2px) scale(1.04);
      box-shadow: 0 16px 40px -4px rgba(11, 100, 189, 0.55), 0 6px 16px -2px rgba(19, 25, 35, 0.28), inset 0 1px 0 rgba(255, 255, 255, 0.45) !important;
    }
    #sec-embed-toggle:active {
      transform: translateY(0) scale(0.97);
    }
    #sec-embed-toggle .sec-mascot-svg {
      transition: transform 260ms cubic-bezier(.2, .8, .2, 1);
    }
    #sec-embed-toggle:hover .sec-mascot-svg {
      transform: scale(1.06);
    }
    #sec-embed-toggle:focus-visible { outline: 2px solid #0b64bd; outline-offset: 3px; }

    /* Full-height right side drawer panel design */
    #sec-embed-panel {
      position: fixed;
      top: 0;
      bottom: 0;
      right: 0;
      width: min(680px, 100vw);
      height: 100vh;
      max-width: 100vw;
      background: #ffffff;
      border-left: 1px solid #d9dee6;
      box-shadow: -16px 0 40px -8px rgba(19, 25, 35, .20), -4px 0 10px -4px rgba(19, 25, 35, .08);
      overflow-x: hidden;
      overflow-y: hidden;
      z-index: 2147483646;
      display: block;
      transform: translateX(100%);
      transition: transform 0.28s cubic-bezier(0.16, 1, 0.3, 1);
    }
    #sec-embed-panel.sec-embed-open {
      transform: translateX(0);
    }
    @media (prefers-reduced-motion: reduce) { #sec-embed-panel, #sec-embed-toggle { transition: none; } }

    #sec-result-dock {
      --sec-dock-accent: #4b5567; --sec-dock-soft: #e5e9ef;
      position: fixed; right: 24px; bottom: 88px; z-index: 2147483645; box-sizing: border-box;
      width: min(330px, calc(100vw - 48px)); padding: 12px 12px 10px 15px; overflow: hidden;
      border: 1px solid #d9dee6; border-radius: 8px; background: #fff; color: #222a37;
      box-shadow: 0 16px 40px -8px rgba(19, 25, 35, .22), 0 4px 10px -4px rgba(19, 25, 35, .10);
      font: 13px/1.45 Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; letter-spacing: -0.011em;
      opacity: 0; transform: translateY(8px); transition: opacity 180ms ease, transform 240ms cubic-bezier(.2,.8,.2,1);
    }
    #sec-result-dock::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--sec-dock-accent); }
    #sec-result-dock.sec-dock-in { opacity: 1; transform: none; }
    #sec-result-dock * { box-sizing: border-box; }
    #sec-result-dock.sec-dock-allow { --sec-dock-accent: #12703b; --sec-dock-soft: #d5f0de; }
    #sec-result-dock.sec-dock-block { --sec-dock-accent: #b42318; --sec-dock-soft: #fbdcd9; }
    #sec-result-dock.sec-dock-warn, #sec-result-dock.sec-dock-isolate { --sec-dock-accent: #855400; --sec-dock-soft: #faeac0; }
    #sec-result-dock.sec-dock-pending, #sec-result-dock.sec-dock-unsupported { --sec-dock-accent: #9a4700; --sec-dock-soft: #ffe4c7; }
    #sec-result-dock .sec-dock-head { display: flex; align-items: center; gap: 8px; }
    #sec-result-dock .sec-dock-icon { flex: none; display: grid; place-items: center; width: 28px; height: 28px; padding: 6px; border-radius: 50%; background: var(--sec-dock-soft); color: var(--sec-dock-accent); }
    #sec-result-dock .sec-dock-icon svg { display: block; width: 100%; height: 100%; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; }
    #sec-result-dock .sec-dock-titles { display: flex; flex: 1; flex-direction: column; min-width: 0; }
    #sec-result-dock .sec-dock-title { color: #131923; font-size: 14.5px; font-weight: 700; line-height: 1.25; letter-spacing: -.015em; }
    #sec-result-dock .sec-dock-sub { overflow: hidden; color: #4b5567; font-size: 12px; text-overflow: ellipsis; white-space: nowrap; font-variant-numeric: tabular-nums; }
    #sec-result-dock .sec-dock-close { flex: none; align-self: flex-start; width: 26px; height: 26px; margin: -3px -3px 0 0; border: 0; border-radius: 6px; background: transparent; color: #4b5567; font-size: 18px; line-height: 1; cursor: pointer; }
    #sec-result-dock .sec-dock-close:hover { background: #eef1f5; color: #131923; }
    #sec-result-dock .sec-dock-stages { margin: 6px -4px 6px; padding: 0; list-style: none; }
    #sec-result-dock .sec-dock-stage-inner {
      display: grid; grid-template-columns: 56px minmax(0, 1fr) auto; align-items: center; gap: 8px; width: 100%;
      min-height: 30px; padding: 3px 6px; border: 0; border-radius: 6px; background: transparent; color: inherit; font: inherit; text-align: left;
    }
    #sec-result-dock button.sec-dock-stage-inner { cursor: pointer; }
    #sec-result-dock button.sec-dock-stage-inner:hover { background: #f6f8fa; }
    #sec-result-dock .sec-dock-stage { color: #4b5567; font-size: 10.5px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
    #sec-result-dock .sec-dock-value { display: flex; align-items: center; gap: 8px; min-width: 0; }
    #sec-result-dock .sec-dock-rule { min-width: 0; overflow: hidden; color: #131923; font-weight: 600; text-overflow: ellipsis; white-space: nowrap; }
    #sec-result-dock .sec-dock-muted { color: #626d80; }
    #sec-result-dock .sec-dock-pill { flex: none; padding: 0 8px; border-radius: 999px; background: #eef1f5; color: #4b5567; font-size: 10.5px; font-weight: 700; line-height: 18px; }
    #sec-result-dock .sec-dock-pill-allow { background: #d5f0de; color: #0b4f29; }
    #sec-result-dock .sec-dock-pill-block { background: #fbdcd9; color: #7f1710; }
    #sec-result-dock .sec-dock-pill-warn, #sec-result-dock .sec-dock-pill-isolate { background: #faeac0; color: #5f3c00; }
    #sec-result-dock .sec-dock-go { width: 7px; height: 7px; margin-right: 4px; border-top: 1.5px solid #8f9aac; border-right: 1.5px solid #8f9aac; transform: rotate(45deg); }
    #sec-result-dock .sec-dock-foot { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding-top: 10px; border-top: 1px solid #eef1f5; }
    #sec-result-dock .sec-dock-expand { min-height: 30px; padding: 4px 12px; border: 1px solid #0b64bd; border-radius: 6px; background: #0b64bd; color: #fff; font: 600 12.5px Inter, system-ui, sans-serif; cursor: pointer; box-shadow: 0 1px 2px rgba(19, 25, 35, .06); transition: background-color 120ms ease; }
    #sec-result-dock .sec-dock-expand:hover { border-color: #0a519a; background: #0a519a; }
    #sec-result-dock .sec-dock-clear { min-height: 30px; padding: 4px 8px; border: 0; border-radius: 6px; background: transparent; color: #4b5567; font: 600 12.5px Inter, system-ui, sans-serif; cursor: pointer; }
    #sec-result-dock .sec-dock-clear:hover { background: #eef1f5; color: #131923; }
    #sec-result-dock button:focus-visible { outline: 2px solid #0b64bd; outline-offset: 2px; }
    @media (prefers-reduced-motion: reduce) { #sec-result-dock { transition: none; } }

    #sec-embed-iframe {
      width: 100%;
      height: 100%;
      border: none;
      display: block;
      background: transparent;
      overflow-x: hidden;
    }
  `;
  document.head.appendChild(style);
}

function initEmbeddedPopup() {
  if (!document.body) {
    document.addEventListener("DOMContentLoaded", initEmbeddedPopup);
    return;
  }
  const oldBtn = document.getElementById("sec-embed-toggle");
  if (oldBtn) oldBtn.remove();
  const oldPanel = document.getElementById("sec-embed-panel");
  if (oldPanel) oldPanel.remove();

  ensureEmbeddedPopupStyle();

  const toggleBtn = document.createElement("button");
  toggleBtn.id = "sec-embed-toggle";
  toggleBtn.title = "Secure Access Policy Checker";
  toggleBtn.innerHTML = `<svg width="28" height="28" viewBox="0 0 28 28" fill="none" xmlns="http://www.w3.org/2000/svg" class="sec-mascot-svg" aria-hidden="true">
    <defs>
      <linearGradient id="sec-shield-grad" x1="4" y1="3" x2="24" y2="25" gradientUnits="userSpaceOnUse">
        <stop stop-color="#ffffff"/>
        <stop offset="1" stop-color="#e0edff"/>
      </linearGradient>
      <filter id="sec-glow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="1" stdDeviation="1.2" flood-color="#002d6b" flood-opacity="0.3"/>
      </filter>
    </defs>
    <!-- Cisco shield motif with inner radar/secure pulse -->
    <path d="M14 2.75L4.5 6.75V13.25C4.5 19.5 8.6 24.8 14 26.25C19.4 24.8 23.5 19.5 23.5 13.25V6.75L14 2.75Z" fill="url(#sec-shield-grad)" filter="url(#sec-glow)"/>
    <path d="M14 5.25L6.5 8.4V13.25C6.5 18.25 9.7 22.65 14 23.95C18.3 22.65 21.5 18.25 21.5 13.25V8.4L14 5.25Z" fill="#0b64bd"/>
    <!-- Subtle Cisco bridge arch / radar scan -->
    <path d="M10.5 15.5C11.4 14.5 12.6 14 14 14C15.4 14 16.6 14.5 17.5 15.5" stroke="#70b6ff" stroke-width="1.6" stroke-linecap="round"/>
    <path d="M9 18C10.3 16.8 12.1 16 14 16C15.9 16 17.7 16.8 19 18" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round"/>
    <!-- Inner keyhole / checkpoint dot -->
    <circle cx="14" cy="11" r="2" fill="#ffffff"/>
  </svg>`;

  const panel = document.createElement("div");
  panel.id = "sec-embed-panel";

  // Loading the extension's own popup.html as an iframe src requires it (and
  // everything it loads: popup.js, popup-sections.js, matcher.js,
  // and the data/*.json lookups fetched at runtime) to be listed in
  // manifest.json's web_accessible_resources — see manifest.json.
  const iframe = document.createElement("iframe");
  iframe.id = "sec-embed-iframe";
  iframe.style.overflowX = "hidden";
  iframe.allow = "microphone";
  
  // Extract orgId from URL and pass it directly in the iframe src
  // This is more reliable than the postMessage handshake
  const orgMatch = window.location.href.match(/\/org\/(\d+)/);
  const orgId = orgMatch ? orgMatch[1] : null;
  const iframeSrcBase = runtimeUrl("popup/popup.html");
  if (!iframeSrcBase) return;
  const iframeSrc = iframeSrcBase + (orgId ? `?orgId=${orgId}` : "");
  iframe.src = iframeSrc;
  panel.appendChild(iframe);

  document.body.appendChild(panel);
  document.body.appendChild(toggleBtn);

  // ---------------------------------------------------------------------
  // Org-ID handshake for popup.js running inside this iframe.
  //
  // The iframe is cross-origin (chrome-extension://<id> embedded in this
  // https://*.cisco.com/* page), so popup.js CANNOT read window.parent's
  // location — the same-origin policy blocks reading a cross-origin
  // window's .location.href/.pathname/etc (only postMessage() is allowed
  // across origins). But THIS script runs in the dashboard page's own
  // origin/context and has direct access to window.location.href, so we
  // answer popup.js's request for the org ID here instead of it trying
  // (and failing) to read it directly.
  //
  // service-worker.js's chrome.tabs.query()-based org-ID detection (used
  // by the toolbar-popup path) is left completely unchanged — this is an
  // additive path only used when popup.js detects it's embedded.
  // ---------------------------------------------------------------------
  function extractOrgIdFromUrl(url) {
    const match = (url || "").match(/\/org\/(\d+)/);
    return match ? match[1] : null;
  }

  // Cache orgId in storage when we detect it — makes it resilient to timing issues
  // Use the orgId already extracted above for the iframe URL
  if (orgId && api && api.storage && api.storage.local) {
    try { api.storage.local.set({ cached_org_id: orgId }); } catch (_) {}
  }

  window.addEventListener("message", (event) => {
    if (event.source !== iframe.contentWindow) return;
    if (!event.data) return;

    if (event.data.type === "SEC_REQUEST_ORG_CONTEXT") {
      // Use cached orgId if extraction failed, or re-extract
      const currentOrgId = orgId || extractOrgIdFromUrl(window.location.href);
      const extensionOrigin = new URL(iframe.src).origin;
      event.source.postMessage({ type: "SEC_ORG_CONTEXT", orgId: currentOrgId }, extensionOrigin);
      return;
    }

    // Sent by popup.js's minimizeEmbeddedPanel() right after a successful
    // Run Test — collapses the panel so the row we just highlighted/scrolled
    // to on the dashboard (see highlightRule()) is actually visible instead
    // of sitting behind the panel.
    if (event.data.type === "SEC_MINIMIZE_PANEL") {
      panel.classList.remove("sec-embed-open");
      if (event.data.summary) showResultDock(event.data.summary, panel);
    }
  });

  toggleBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    panel.classList.toggle("sec-embed-open");
    if (panel.classList.contains("sec-embed-open")) hideResultDock(false);
  });

  // Click outside the panel hides it. Note: clicks that happen INSIDE the
  // iframe never reach this listener at all — the iframe is a separate
  // document, so a click there doesn't bubble into the parent dashboard
  // document's event flow. That means this listener only ever fires for
  // genuine clicks on the dashboard page itself, which is exactly "outside
  // the iframe's bounds" — no manual bounding-box hit-testing needed.
  //
  // Toggling display via the .sec-embed-open class (rather than removing/
  // recreating the iframe) means the iframe's document — and therefore
  // popup.js's in-memory scan results — persists across opens/closes for
  // the lifetime of the dashboard page.
  document.addEventListener("mousedown", (e) => {
    if (!panel.classList.contains("sec-embed-open")) return;
    if (panel.contains(e.target) || e.target === toggleBtn) return;
    panel.classList.remove("sec-embed-open");
  });
}

// ---------------------------------------------------------------------------
// Result dock — the compact Policy Checker result shown while the panel is
// minimized so the highlighted rows stay visible. Built with textContent
// only: rule names are tenant data.
// ---------------------------------------------------------------------------
var RESULT_DOCK_ID = "sec-result-dock";
var DOCK_ICONS = {
  allow: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  block: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M6.5 17.5l11-11"/></svg>',
  warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4.5l8.5 15h-17z"/><path d="M12 10v4M12 16.8h.01"/></svg>',
  pending: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 16.8h.01"/></svg>',
};

function hideResultDock(clearHits) {
  const dock = document.getElementById(RESULT_DOCK_ID);
  if (dock) dock.remove();
  if (clearHits) clearRuleHits();
}

function showResultDock(summary, panel) {
  hideResultDock(false);
  const text = (value) => (typeof value === "string" ? value : "");
  const status = ["allow", "block", "warn", "isolate", "pending", "unsupported", "unknown"].includes(summary.status) ? summary.status : "unknown";
  const make = (tag, className, content) => {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (content !== undefined) el.textContent = content;
    return el;
  };
  const dock = make("section");
  dock.id = RESULT_DOCK_ID;
  dock.className = `sec-dock-${status}`;
  dock.setAttribute("aria-label", "Policy check result");

  const head = make("div", "sec-dock-head");
  const iconEl = make("span", "sec-dock-icon");
  iconEl.innerHTML = DOCK_ICONS[status === "isolate" ? "warn" : status] || DOCK_ICONS.pending; // constant markup
  const titles = make("div", "sec-dock-titles");
  titles.append(make("strong", "sec-dock-title", text(summary.title)), make("span", "sec-dock-sub", text(summary.destination)));
  const close = make("button", "sec-dock-close", "×");
  close.type = "button";
  close.setAttribute("aria-label", "Close result and clear highlights");
  close.addEventListener("click", () => hideResultDock(true));
  head.append(iconEl, titles, close);

  const list = make("ul", "sec-dock-stages");
  for (const stage of Array.isArray(summary.stages) ? summary.stages : []) {
    const matched = stage.state === "matched" && text(stage.rule);
    const item = make("li", `sec-dock-stage-row sec-dock-${stage.state}`);
    const inner = make(matched ? "button" : "div", "sec-dock-stage-inner");
    if (matched) {
      inner.type = "button";
      inner.title = "Scroll to this rule";
      inner.addEventListener("click", () => scrollToRuleHit(stage.rule));
    }
    inner.appendChild(make("span", "sec-dock-stage", text(stage.label)));
    const value = make("span", "sec-dock-value");
    if (matched) {
      const action = String(stage.action || "").toLowerCase();
      value.append(make("span", `sec-dock-pill sec-dock-pill-${action}`, text(stage.action)), make("span", "sec-dock-rule", text(stage.rule)));
    } else {
      value.appendChild(make("span", "sec-dock-muted",
        stage.state === "needs-answer" ? "Waiting on an answer in the checker"
          : stage.state === "unsupported" ? "Unsupported path"
            : stage.state === "not-reached" ? "Not reached"
            : stage.state === "no-match" ? "No rule matched" : "Not evaluated"));
    }
    inner.appendChild(value);
    if (matched) inner.appendChild(make("span", "sec-dock-go"));
    item.appendChild(inner);
    list.appendChild(item);
  }

  const foot = make("div", "sec-dock-foot");
  const expand = make("button", "sec-dock-expand", "Open checker");
  expand.type = "button";
  expand.addEventListener("click", (e) => {
    e.stopPropagation();
    hideResultDock(false);
    panel.classList.add("sec-embed-open");
  });
  const clear = make("button", "sec-dock-clear", "Clear highlights");
  clear.type = "button";
  clear.addEventListener("click", () => hideResultDock(true));
  foot.append(expand, clear);

  dock.append(head, list, foot);
  document.body.appendChild(dock);
  requestAnimationFrame(() => dock.classList.add("sec-dock-in"));
}

// ---------------------------------------------------------------------------
// Run on page load & watch SPA route re-hydration
// ---------------------------------------------------------------------------

function isSecurePolicyPage(url) {
  try {
    const parsed = new URL(url || window.location.href);
    if (parsed.hostname.toLowerCase() !== "dashboard.sse.cisco.com") return false;
    return /\/secure\/policy(?:\/|$|\?|#)/.test(parsed.pathname);
  } catch (_) {
    return false;
  }
}

function teardownPolicyCheckerUi() {
  hideMemberPopover();
  hideHoverPopover();
  hideResultDock(true);
  const toggleBtn = document.getElementById("sec-embed-toggle");
  if (toggleBtn) toggleBtn.remove();
  const panel = document.getElementById("sec-embed-panel");
  if (panel) panel.remove();
}

function syncPolicyCheckerUi() {
  if (!isSecurePolicyPage()) {
    teardownPolicyCheckerUi();
    return;
  }
  initHoverPopover();
  if (!document.getElementById("sec-embed-toggle") || !document.getElementById("sec-embed-panel")) {
    initEmbeddedPopup();
  }
}

function setupPersistence() {
  syncPolicyCheckerUi();

  // Listen for messages from the popup (toolbar or embedded panel).
  // The popup sends HIGHLIGHT_RULE via chrome.tabs.sendMessage() after a
  // successful "Run Simulation" — this listener routes it to highlightRule().
  if (api && api.runtime && api.runtime.id && !window.__secPolicyCheckerMessages) {
    window.__secPolicyCheckerMessages = true;
    api.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (msg && msg.type === "HIGHLIGHT_RULES") {
        if (!isSecurePolicyPage()) {
          sendResponse({ ok: false, reason: "not-policy-page" });
          return;
        }
        sendResponse({ ok: true, ...highlightRules(Array.isArray(msg.targets) ? msg.targets : []) });
        return;
      }
      if (msg && msg.type === "HIGHLIGHT_RULE") {
        if (!isSecurePolicyPage()) {
          sendResponse({ ok: false, reason: "not-policy-page" });
          return;
        }
        highlightRule(msg.ruleName, msg.matchedConditions);
        sendResponse({ ok: true });
      }
    });
  }

  // Cisco's dashboard is an SPA. Re-check when the route or body children
  // change so the checker appears only on /secure/policy and is torn down
  // everywhere else.
  if (!window.__secPolicyCheckerRouteWatch) {
    window.__secPolicyCheckerRouteWatch = true;
    window.addEventListener("popstate", syncPolicyCheckerUi);
    window.addEventListener("hashchange", syncPolicyCheckerUi);
    ["pushState", "replaceState"].forEach((method) => {
      const original = history[method];
      if (typeof original !== "function") return;
      history[method] = function () {
        const result = original.apply(this, arguments);
        queueMicrotask(syncPolicyCheckerUi);
        return result;
      };
    });
    if (window.MutationObserver && document.documentElement) {
      let debounceTimer = null;
      const observer = new MutationObserver(() => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(syncPolicyCheckerUi, 150);
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
    }
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", setupPersistence);
} else {
  setupPersistence();
}
window.addEventListener("load", setupPersistence);
}
