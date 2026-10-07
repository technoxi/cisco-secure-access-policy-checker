// =============================================================================
// popup-sections.js — DOM builders for the Policy Match Tester split panel
// and the single collapsible audit-result sections.
//
// Visual design: Clean Light Mode UI with pure white background, dark slate
// typography, crisp borders, progressive disclosure controls, and human-readable
// condition chips.
//
// Exported to window.PopupSections. No browser-extension API calls.
// =============================================================================

(function (global) {
  "use strict";

  // Default fallback dictionary for identity types (matched with official Cisco API schema)
  const DEFAULT_IDENTITY_TYPES = {
    "0": "Tags",
    "1": "Networks",
    "2": "Network Devices",
    "3": "AD Groups",
    "4": "Users & AD Groups",
    "5": "AD Computers",
    "6": "Internal Networks",
    "7": "AD Users",
    "8": "SAML Users & Groups",
    "9": "Roaming Computers",
    "10": "Device Posture Profiles",
    "11": "Security Group Tags (SGT)",
    "21": "Sites",
    "32": "Network Devices",
    "34": "Posture",
    "36": "Mobile Devices",
    "37": "OS Version & Patch Level",
    "38": "Chromebooks",
    "40": "Network Tunnels",
    "43": "G Suite Users",
    "45": "G Suite OUs",
    "50": "Endpoint Requirements",
    "52": "Catalyst SD-WAN Service VPN IDs",
    "54": "Security Group Tags",
    "57": "ZTNA Client",
    "user": "Active Directory Users & Groups",
    "device": "Network Devices",
    "site": "Sites & Branches",
    "group": "Users & AD Groups",
    "roaming": "Roaming Computers",
    "internal_network": "Internal Networks",
    "tunnel": "Network Tunnels",
    "saml": "SAML Users & Groups",
    "ip_subnet": "IP Subnets / CIDR",
    "posture": "Device Posture Profiles",
    "sgt": "Security Group Tags (SGT)"
  };
  const COLOR = {
    critical: { bg: "var(--ds-block-soft)", text: "var(--ds-block-strong)", border: "var(--ds-block-line)" },
    high:     { bg: "var(--ds-pending-soft)", text: "var(--ds-pending-fg)", border: "var(--ds-pending-line)" },
    medium:   { bg: "var(--ds-warn-soft)", text: "var(--ds-warn-fg)", border: "var(--ds-warn-line)" },
    low:      { bg: "var(--ds-surface-subtle)", text: "var(--ds-text-secondary)", border: "var(--ds-border)" },
    allow:    { bg: "var(--ds-allow-soft)", text: "var(--ds-allow-fg)", border: "var(--ds-allow-line)" },
    block:    { bg: "var(--ds-block-soft)", text: "var(--ds-block-fg)", border: "var(--ds-block-line)" },
    isolate:  { bg: "var(--ds-isolate-soft)", text: "var(--ds-isolate-fg)", border: "var(--ds-isolate-line)" },
    unknown:  { bg: "var(--ds-surface-subtle)", text: "var(--ds-text-secondary)", border: "var(--ds-border)" },
  };

  function injectStyles() {
    if (document.getElementById("psc-style")) return;
    const s = document.createElement("style");
    s.id = "psc-style";
    s.textContent = `
      /* ================================================================== */
      #psc-panel {
        background: var(--ds-surface);
        color: var(--ds-text);
        display: flex;
        flex-direction: column;
        font-family: var(--hbr-font-family);
        width: 100%;
        max-width: 100% !important;
        overflow-x: hidden !important;
        box-sizing: border-box !important;
      }

      #psc-panel-title {
        padding: 14px 18px 2px;
        font-size: var(--ds-text-md);
        font-weight: 700;
        color: var(--ds-text-strong);
        letter-spacing: 0.02em;
        font-family: var(--hbr-font-family);
        display: flex;
        align-items: center;
        gap: 8px;
      }
      #psc-panel-desc {
        padding: 0 18px 10px;
        font-size: var(--ds-text-xs);
        color: var(--ds-text-muted);
        line-height: 1.45;
        border-bottom: 1px solid var(--ds-border);
      }

      #psc-panel-body {
        display: flex;
        flex-direction: column;
        min-height: 480px;
      }

      #psc-form-row {
        display: flex;
        flex-direction: column;
        gap: 12px;
        padding: 14px 18px 0;
        width: 100%;
        min-width: 0;
        box-sizing: border-box;
        position: relative;
        z-index: 20;
        overflow: visible;
      }
      #psc-panel-body,
      .psc-criteria-grid,
      .psc-and-slot {
        overflow: visible;
      }
      #psc-result-col {
        position: relative;
        z-index: 1;
      }

      /* Form Footer Actions */
      #psc-form-footer {
        padding: 12px 18px;
        border-bottom: 1px solid var(--ds-border);
      }
      #psc-form-actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: 10px;
      }
      #psc-reset-btn {
        background: var(--ds-surface);
        border: 1px solid var(--ds-border-control);
        color: var(--ds-text-secondary);
        font-size: var(--ds-text-xs);
        font-weight: 600;
        cursor: pointer;
        padding: 7px 14px;
        border-radius: var(--ds-radius-sm);
        font-family: var(--hbr-font-family);
        transition: background-color var(--ds-dur-fast), border-color var(--ds-dur-fast), color var(--ds-dur-fast);
      }
      #psc-reset-btn:hover { color: var(--ds-text-strong); border-color: var(--ds-border-hover); background: var(--ds-surface-subtle); }
      #psc-run-btn {
        background: var(--ds-accent-600);
        color: #fff;
        border: 1px solid var(--ds-accent-600);
        border-radius: var(--ds-radius-sm);
        padding: 7px 22px;
        font-size: var(--ds-text-xs);
        font-weight: 700;
        letter-spacing: 0.02em;
        cursor: pointer;
        font-family: var(--hbr-font-family);
        transition: background-color var(--ds-dur-fast), border-color var(--ds-dur-fast), color var(--ds-dur-fast);
      }
      #psc-run-btn:hover:not(:disabled) {
        background: var(--ds-accent-700);
        border-color: var(--ds-accent-700);
      }
      #psc-run-btn:disabled { background: var(--ds-border); border-color: var(--ds-border-control); color: var(--ds-border-hover); cursor: not-allowed; }
      #psc-form-error { font-size: var(--ds-text-xs); color: var(--ds-block-fg); min-height: 16px; margin-bottom: 6px; font-family: var(--hbr-font-family); }

      /* Results Area */
      #psc-result-col {
        padding: 14px 18px;
        display: flex;
        flex-direction: column;
      }
      #psc-result-placeholder {
        color: var(--ds-text-muted);
        font-size: var(--ds-text-xs);
        text-align: center;
        padding: 18px;
        background: var(--ds-surface-subtle);
        border: 1px dashed var(--ds-border-control);
        border-radius: var(--ds-radius-sm);
        font-family: var(--hbr-font-family);
      }

        font-size: var(--ds-text-xs);
        color: var(--ds-text-strong);
        margin-bottom: 10px;
        font-family: var(--hbr-font-family);
      }

      .psc-result-details { margin-top: 4px; }
      .psc-result-details summary {
        font-size: var(--ds-text-xs);
        font-weight: 600;
        color: var(--ds-text-strong);
        cursor: pointer;
        padding: 4px 0;
        user-select: none;
        list-style: none;
        font-family: var(--hbr-font-family);
        letter-spacing: 0.02em;
      }
      .psc-result-details summary::-webkit-details-marker { display: none; }
      .psc-result-details[open] summary { margin-bottom: 8px; }

      /* Rules Filter Bar */
      .psc-rules-filter-bar {
        display: flex;
        flex-direction: column;
        gap: 8px;
        margin-bottom: 12px;
        width: 100%;
        max-width: 100%;
        box-sizing: border-box;
      }
      .psc-search-input {
        width: 100%;
        height: 34px;
        padding: 6px 10px;
        border: 1px solid var(--ds-border-input);
        border-radius: var(--ds-radius-md);
        font-size: var(--ds-text-md);
        font-family: var(--hbr-font-family);
        outline: none;
        background: var(--ds-surface);
        color: var(--ds-text-strong);
        transition: border-color 0.2s;
        box-sizing: border-box;
      }
      .psc-search-input:focus {
        border-color: var(--ds-focus);
        box-shadow: var(--ds-focus-ring);
      }
      .psc-filter-pills {
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
        max-width: 100%;
      }
      .psc-filter-pill {
        background: var(--ds-surface);
        border: 1px solid var(--ds-border-control);
        border-radius: var(--ds-radius-sm);
        padding: 4px 10px;
        font-size: var(--ds-text-2xs);
        font-weight: 600;
        color: var(--ds-text-secondary);
        cursor: pointer;
        font-family: var(--hbr-font-family);
        transition: background-color var(--ds-dur-fast), border-color var(--ds-dur-fast), color var(--ds-dur-fast);
        max-width: 100%;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .psc-filter-pill:hover {
        background: var(--ds-surface-subtle);
        color: var(--ds-text-strong);
      }
      .psc-filter-pill.active {
        background: var(--ds-accent-50);
        color: var(--ds-accent-800);
        border-color: var(--ds-accent-300);
      }

      /* Policy Audit Summary Banner */
      #psc-audit-summary-container {
        width: 100%;
        margin-bottom: 8px;
      }
      .psc-audit-summary-card {
        border: 1px solid var(--ds-border-control);
        border-radius: var(--ds-radius-lg);
        background: var(--ds-surface);
        padding: 12px;
        box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
      }
      .psc-audit-summary-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid var(--ds-surface-sunken);
        padding-bottom: 8px;
        margin-bottom: 8px;
      }
      .psc-audit-summary-title {
        font-size: var(--ds-text-xs);
        font-weight: 700;
        color: var(--ds-text-strong);
        letter-spacing: 0.02em;
        font-family: var(--hbr-font-family);
      }
      .psc-audit-badge-warning {
        background: var(--ds-pending-soft);
        color: var(--ds-pending-fg);
        border: 1px solid var(--ds-pending-line);
        font-size: var(--ds-text-2xs);
        font-weight: 700;
        padding: 2px 8px;
        border-radius: var(--ds-radius-sm);
        font-family: var(--hbr-font-family);
      }
      .psc-audit-badge-pass {
        background: var(--ds-allow-soft);
        color: var(--ds-allow-fg);
        border: 1px solid var(--ds-allow-line);
        font-size: var(--ds-text-2xs);
        font-weight: 700;
        padding: 2px 8px;
        border-radius: var(--ds-radius-sm);
        font-family: var(--hbr-font-family);
      }
      .psc-audit-stats-row {
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
        margin-bottom: 4px;
      }
      .psc-audit-stat-chip {
        background: var(--ds-surface-subtle);
        border: 1px solid var(--ds-border);
        border-radius: var(--ds-radius-sm);
        padding: 3px 8px;
        font-size: var(--ds-text-2xs);
        font-family: var(--hbr-font-family);
        display: flex;
        gap: 4px;
        align-items: center;
      }
      .psc-audit-stat-label { color: var(--ds-text-muted); font-weight: 500; }
      .psc-audit-stat-val { color: var(--ds-text-strong); font-weight: 700; }
      .psc-audit-stat-chip.has-issues {
        background: var(--ds-pending-soft);
        border-color: var(--ds-pending-line);
      }
      .psc-audit-stat-chip.has-issues .psc-audit-stat-val {
        color: var(--ds-pending-fg);
      }

      /* Rule Cards */
      .psc-rule-group {
        border: 1px solid var(--ds-border-strong);
        border-radius: var(--ds-radius-md);
        box-shadow: var(--ds-shadow-xs);
        overflow-x: hidden !important;
        margin-bottom: 6px;
        background: var(--ds-surface);
        transition: border-color 0.15s;
        position: relative;
        width: 100%;
        max-width: 100%;
        box-sizing: border-box;
      }
      .psc-rule-group:hover {
        border-color: var(--ds-border-control);
      }
      .psc-rule-group-header {
        display: flex;
        flex-direction: column;
        gap: 6px;
        padding: 10px 12px;
        cursor: pointer;
        background: var(--ds-surface);
        list-style: none;
        user-select: none;
        width: 100%;
        max-width: 100%;
        box-sizing: border-box;
        overflow-x: hidden;
      }
      .psc-rule-group-header::-webkit-details-marker { display: none; }

      .psc-rule-top-line {
        display: flex;
        align-items: center;
        gap: 8px;
        width: 100%;
        max-width: 100%;
        min-width: 0;
      }
      .psc-rule-meta-row {
        display: flex;
        flex-wrap: wrap;
        gap: 4px;
        margin-top: 4px;
        width: 100%;
        max-width: 100%;
      }
      .psc-rule-meta-chip {
        font-size: var(--ds-text-2xs);
        font-weight: 500;
        color: var(--ds-text-muted);
        background: var(--ds-surface-sunken);
        border: 1px solid var(--ds-border);
        border-radius: var(--ds-radius-sm);
        padding: 2px 6px;
        font-family: var(--hbr-font-family);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 100%;
      }
      .psc-rule-prio {
        font-family: var(--hbr-font-family);
        font-size: var(--ds-text-2xs);
        font-weight: 700;
        color: var(--ds-text-strong);
        background: var(--ds-surface-sunken);
        border: 1px solid var(--ds-border-control);
        padding: 1px 5px;
        border-radius: var(--ds-radius-sm);
        font-variant-numeric: tabular-nums;
        flex-shrink: 0;
      }
      .psc-rule-name {
        flex: 1;
        font-weight: 600;
        font-size: var(--ds-text-sm);
        color: var(--ds-text-strong);
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        min-width: 0;
      }
      .psc-rule-action-pill {
        font-family: var(--hbr-font-family);
        font-size: var(--ds-text-2xs);
        font-weight: 700;
        padding: 1px 8px;
        border-radius: var(--ds-radius-pill);
        letter-spacing: 0.02em;
        flex-shrink: 0;
      }
      .psc-action-allow { background: var(--ds-allow-tint); color: var(--ds-allow-fg); border: 1px solid var(--ds-allow-line); }
      .psc-action-block { background: var(--ds-block-tint); color: var(--ds-block-strong); border: 1px solid var(--ds-block-line); }
      .psc-action-isolate { background: var(--ds-isolate-soft); color: var(--ds-isolate-fg); border: 1px solid var(--ds-isolate-line); }

      /* Inline Data Bar on Rules */
      .psc-inline-chips {
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
        font-family: var(--hbr-font-family);
        font-size: var(--ds-text-2xs);
        width: 100%;
        max-width: 100%;
        min-width: 0;
      }
      .psc-chip {
        background: var(--ds-surface-subtle);
        border: 1px solid var(--ds-border);
        border-radius: var(--ds-radius-sm);
        padding: 2px 6px;
        color: var(--ds-neutral-700);
        display: inline-flex;
        align-items: center;
        gap: 4px;
        max-width: 100%;
        min-width: 0;
        overflow-wrap: anywhere;
        word-break: break-word;
      }
      .psc-chip-key { color: var(--ds-text-muted); font-weight: 600; flex-shrink: 0; }
      .psc-chip-val { color: var(--ds-text-strong); font-weight: 600; overflow-wrap: anywhere; word-break: break-word; }

      .psc-check-list { padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; background: var(--ds-surface-subtle); border-top: 1px solid var(--ds-border); max-width: 100%; box-sizing: border-box; overflow-x: hidden; }
      .psc-check-item {
        border-left: 3px solid;
        padding: 6px 10px;
        border-radius: var(--ds-radius-sm);
        font-size: var(--ds-text-xs);
        line-height: 1.45;
        background: var(--ds-surface);
      }
      .psc-check-item-head {
        display: flex;
        align-items: center;
        gap: 6px;
        margin-bottom: 2px;
        font-weight: 600;
        font-size: var(--ds-text-2xs);
        font-family: var(--hbr-font-family);
      }
      .psc-check-msg { color: var(--ds-text); display: block; }
      .psc-check-detail { color: var(--ds-text-muted); font-size: var(--ds-text-2xs); margin-top: 2px; font-family: var(--hbr-font-family); }

      /* Tooltip */
      #psc-tooltip {
        position: fixed;
        display: none;
        background: var(--ds-neutral-900);
        color: #fff;
        border: 1px solid var(--ds-neutral-900);
        box-shadow: var(--ds-shadow-lg);
        padding: 8px 12px;
        border-radius: var(--ds-radius-sm);
        font-size: var(--ds-text-xs);
        font-family: var(--hbr-font-family);
        line-height: 1.45;
        white-space: pre-wrap;
        z-index: 99999;
        max-width: 350px;
        word-wrap: break-word;
        pointer-events: none;
      }
`;
    document.head.appendChild(s);
  }

  function el(tag, attrs = {}, children = []) {
    const element = document.createElement(tag);
    for (const [key, val] of Object.entries(attrs)) {
      if (key === "style" && typeof val === "object") {
        Object.assign(element.style, val);
      } else if (key === "htmlFor") {
        element.setAttribute("for", val);
      } else if (key.startsWith("on") && typeof val === "function") {
        element.addEventListener(key.slice(2).toLowerCase(), val);
      } else if (val !== null && val !== undefined) {
        element.setAttribute(key, val);
      }
    }
    for (const child of children) {
      if (typeof child === "string" || typeof child === "number") {
        element.appendChild(document.createTextNode(String(child)));
      } else if (child instanceof Node) {
        element.appendChild(child);
      }
    }
    return element;
  }

  let lookupsPromise = null;
  function loadLookups() {
    if (!lookupsPromise) {
      lookupsPromise = Promise.all([
        fetch("../data/categories-lookup.json").then(r => r.json()).catch(() => ({})),
        fetch("../data/apps-lookup.json").then(r => r.json()).catch(() => ({})),
        fetch("../data/protocols-lookup.json").then(r => r.json()).catch(() => ({})),
        fetch("../data/security-categories-lookup.json").then(r => r.json()).catch(() => ({})),
        fetch("../data/exclusions-lookup.json").then(r => r.json()).catch(() => ([]))
      ]).then(([categories, apps, protocols, securityCategories, exclusions]) => ({ categories, apps, protocols, securityCategories, exclusions }));
    }
    return lookupsPromise;
  }

  function buildRulesList(container) {
    injectStyles();

    const root = el("div", { id: "psc-rules-list-root", style: { display: "flex", flexDirection: "column", gap: "10px", padding: "var(--ds-space-3) var(--ds-space-4)", width: "100%", maxWidth: "100%", boxSizing: "border-box", overflowX: "hidden" } });
    container.appendChild(root);

    const summaryContainer = el("div", { id: "psc-audit-summary-container" });
    root.appendChild(summaryContainer);

    const filterBar = el("div", { class: "psc-rules-filter-bar" });
    const searchInput = el("input", {
      type: "text",
      class: "psc-search-input",
      placeholder: "Search rules by name, identity, destination, or app...",
      autocomplete: "off",
    });

    const pillsContainer = el("div", { class: "psc-filter-pills" });
    const filterOptions = [
      { id: "all", label: "All" },
      { id: "allow", label: "Permit" },
      { id: "block", label: "Deny" },
      { id: "private", label: "Private Access" },
      { id: "internet", label: "Internet Access" },
    ];

    let activeFilter = "all";
    filterOptions.forEach(opt => {
      const pill = el("button", {
        type: "button",
        class: opt.id === "all" ? "psc-filter-pill active" : "psc-filter-pill",
        "data-filter": opt.id,
        "aria-pressed": String(opt.id === "all")
      }, [opt.label]);

      pill.addEventListener("click", () => {
        activeFilter = opt.id;
        applyRulesFilter();
      });

      pillsContainer.appendChild(pill);
    });

    filterBar.appendChild(searchInput);
    filterBar.appendChild(pillsContainer);
    root.appendChild(filterBar);

    const rulesContainer = el("div", { id: "psc-rules-cards-container", style: { display: "flex", flexDirection: "column", gap: "6px" } });
    root.appendChild(rulesContainer);

    let loadedTotal = 0;
    const matchStatus = el("p", { role: "status", "aria-live": "polite", "aria-atomic": "true" });
    filterBar.appendChild(matchStatus);
    const emptyResult = el("div", { hidden: "" }, ["No matching rules"]);
    const resetFilters = el("button", { type: "button" }, ["Clear search/reset filters"]);
    emptyResult.appendChild(resetFilters);
    root.appendChild(emptyResult);
    resetFilters.addEventListener("click", () => {
      searchInput.value = "";
      activeFilter = "all";
      applyRulesFilter();
      searchInput.focus();
    });

    function applyRulesFilter() {
      pillsContainer.querySelectorAll(".psc-filter-pill").forEach(p => {
        const selected = p.getAttribute("data-filter") === activeFilter;
        p.classList.toggle("active", selected);
        p.setAttribute("aria-pressed", String(selected));
      });
      let matchingTotal = 0;
      const query = searchInput.value.toLowerCase().trim();
      const cards = rulesContainer.querySelectorAll(".psc-rule-group");
      cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        const action = card.getAttribute("data-action") || "";
        const type = card.getAttribute("data-type") || "";

        let matchesSearch = !query || text.includes(query);
        let matchesPill = true;

        if (activeFilter === "allow") matchesPill = action === "allow";
        else if (activeFilter === "block") matchesPill = action === "block";
        else if (activeFilter === "private") matchesPill = type.includes("private");
        else if (activeFilter === "internet") matchesPill = !type.includes("private");

        const matches = matchesSearch && matchesPill;
        card.style.display = matches ? "" : "none";
        if (matches) matchingTotal++;
      });
      const countText = `${matchingTotal} matching / ${loadedTotal} total rules`;
      if (matchStatus.textContent !== countText) matchStatus.textContent = countText;
      emptyResult.hidden = loadedTotal === 0 || matchingTotal !== 0;
    }

    searchInput.addEventListener("input", applyRulesFilter);

    function lookupItemName(mapObj, key) {
      if (!mapObj || key === undefined || key === null) return null;
      const kStr = String(key);
      const val = mapObj[kStr] !== undefined ? mapObj[kStr] : mapObj[key];
      if (!val) return null;
      if (typeof val === "string") return val;
      if (typeof val === "object" && val.name) return val.name;
      return String(val);
    }

    // resolveCountryCode — turns ISO 3166-1 alpha-2 country codes into
    // full country names for the geolocations/location condition display.
    // Uses Intl.DisplayNames (available in all Chromium-based browsers) so
    // we don't need a bundled country-name lookup table. Falls back to the
    // raw code if resolution fails.
    function resolveCountryCode(code) {
      if (!code || typeof code !== "string") return String(code || "");
      const trimmed = code.trim();
      // Already a full name (more than 2 chars or contains a space) — pass through
      if (trimmed.length !== 2 || !/^[A-Za-z]{2}$/.test(trimmed)) return trimmed;
      try {
        const dn = new Intl.DisplayNames(["en"], { type: "region" });
        return dn.of(trimmed.toUpperCase()) || trimmed;
      } catch {
        return trimmed;
      }
    }

    function summarizeConditions(rule, lookups) {
      const conds = rule.ruleConditions || rule.conditions || [];
      if (!Array.isArray(conds) || conds.length === 0) {
        return [{ text: "ANY TRAFFIC", raw: null }];
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
            if (values === true) summaryText = `${type.split(".")[1].toUpperCase()}: ANY`;
            break;
          case "umbrella.source.identity_ids":
          case "umbrella.source.identity_ids_shared": {
            const typeMap = lookups.sourceIdentityTypeIds || {};
            const identityNames = (Array.isArray(values) ? values : [values]).map((id) => {
              const name = lookupItemName(lookups.identities, id) || "Deleted identity";
              const typeId = typeMap[String(id)];
              const type = typeId !== undefined
                ? (lookupItemName(lookups.identityTypes, typeId) || lookupItemName(DEFAULT_IDENTITY_TYPES, typeId) || `Type ${typeId}`)
                : null;
              return type ? `${name} (${type})` : name;
            });
            summaryText = `Source Identity: ${identityNames.join(", ")}`;
            break;
          }
          case "umbrella.source.identity_type_ids":
          case "umbrella.source.identity_type_ids_shared": {
            const typeNames = (Array.isArray(values) ? values : [values]).map((id) => {
              return lookupItemName(lookups.identityTypes, id) || lookupItemName(DEFAULT_IDENTITY_TYPES, id) || "Identity Type";
            });
            summaryText = `Identity Type: ${typeNames.join(", ")}`;
            break;
          }
          case "umbrella.destination.application_ids": {
            const appMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.apps, id) || lookupItemName(lookups.protocols, id);
              appMatches.push(name || "Internet Application");
            }
            summaryText = `App: ${appMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.application_category_ids":
          case "umbrella.destination.category_ids": {
            const isApplicationCategory = type === "umbrella.destination.application_category_ids";
            const categoryMap = isApplicationCategory ? lookups.applicationCategories : lookups.categories;
            const fallback = isApplicationCategory ? "Application Category" : "Content Category";
            const catMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(categoryMap, id);
              catMatches.push(name || fallback);
            }
            summaryText = `${fallback}: ${catMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.private_resource_ids":
          case "umbrella.destination.private_resource_group_ids": {
            const resMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.privateResources, id) || lookupItemName(lookups.objects, id);
              resMatches.push(name || "Private Resource");
            }
            summaryText = `Private Resource: ${resMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.destination_list_ids": {
            const listMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.destinationLists, id);
              listMatches.push(name || "Destination List");
            }
            summaryText = `Destination List: ${listMatches.join(", ")}`;
            break;
          }
          case "umbrella.source.networkObjectIds":
          case "umbrella.source.networkObjectIds_shared": {
            const objMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.networkObjects, id);
              objMatches.push(name || "Network Object");
            }
            summaryText = `Network Object: ${objMatches.join(", ")}`;
            break;
          }
          case "umbrella.source.networkObjectGroupIds":
          case "umbrella.source.networkObjectGroupIds_shared": {
            const grpMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.networkObjects, id);
              grpMatches.push(name || "Network Group");
            }
            summaryText = `Network Group: ${grpMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.networkObjectGroupIds": {
            const grpMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.networkObjects, id);
              grpMatches.push(name || "Network Group");
            }
            summaryText = `Network Group: ${grpMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.serviceObjectIds": {
            const svcMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.serviceObjectGroups, id);
              svcMatches.push(name || "Service Group");
            }
            summaryText = `Service Group: ${svcMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.application_list_ids": {
            const listMatches = [];
            for (const id of Array.isArray(values) ? values : [values]) {
              const name = lookupItemName(lookups.applicationLists, id);
              listMatches.push(name || "Application List");
            }
            summaryText = `App List: ${listMatches.join(", ")}`;
            break;
          }
          case "umbrella.destination.composite_inline_ip": {
            const items = Array.isArray(values) ? values : [values];
            const parts = items.map((item) => {
              if (item && typeof item === "object") {
                const ip = Array.isArray(item.ip) ? item.ip.join(",") : (item.ip || "*");
                const port = Array.isArray(item.port) ? item.port.join(",") : (item.port || "*");
                const proto = item.protocol || "ANY";
                return `${ip}:${port}/${proto}`;
              }
              return String(item);
            });
            summaryText = `Dst IP/Port/Proto: ${parts.join(" + ")}`;
            break;
          }
          case "umbrella.source.composite_inline_ip": {
            const items = Array.isArray(values) ? values : [values];
            const parts = items.map((item) => {
              if (item && typeof item === "object") {
                const ip = Array.isArray(item.ip) ? item.ip.join(",") : (item.ip || "*");
                const port = Array.isArray(item.port) ? item.port.join(",") : (item.port || "*");
                const proto = item.protocol || "ANY";
                return `${ip}:${port}/${proto}`;
              }
              return String(item);
            });
            summaryText = `Src IP/Port/Proto: ${parts.join(" + ")}`;
            break;
          }
          case "umbrella.destination.security_group_tag_ids":
          case "umbrella.destination.any_security_group_tag": {
            const ids = Array.isArray(values) ? values : [values];
            summaryText = `SGT: ${ids.join(", ")}`;
            break;
          }
          case "umbrella.source.geolocations": {
            const geos = Array.isArray(values) ? values : [values];
            const names = geos.map((g) => resolveCountryCode(g));
            summaryText = `Source Countries: ${names.join(", ")}`;
            break;
          }
          case "umbrella.destination.geolocations": {
            const geos = Array.isArray(values) ? values : [values];
            const names = geos.map((g) => resolveCountryCode(g));
            summaryText = `Destination Countries: ${names.join(", ")}`;
            break;
          }
          case "umbrella.source.location":
          case "umbrella.destination.location": {
            const locs = Array.isArray(values) ? values : [values];
            summaryText = `Location: ${locs.join(", ")}`;
            break;
          }
          case "umbrella.source.tunnel":
          case "umbrella.destination.tunnel": {
            const tunnels = Array.isArray(values) ? values : [values];
            summaryText = `Tunnel: ${tunnels.join(", ")}`;
            break;
          }
          case "umbrella.source.sgt":
          case "umbrella.destination.sgt": {
            const sgts = Array.isArray(values) ? values : [values];
            summaryText = `SGT: ${sgts.join(", ")}`;
            break;
          }
          case "umbrella.posture.ipsProfileId": {
            summaryText = `IPS Profile: ${values}`;
            break;
          }
          case "umbrella.posture.profileIdClientbased":
          case "umbrella.posture.profileIdClientless":
          case "umbrella.posture.vpnProfileId":
          case "umbrella.posture.webProfileId": {
            const label = type.replace("umbrella.posture.", "").replace(/([A-Z])/g, " $1");
            summaryText = `${label}: ${values}`;
            break;
          }
          case "umbrella.destination.saasTenantIds": {
            const ids = Array.isArray(values) ? values : [values];
            summaryText = `SaaS Tenant: ${ids.join(", ")}`;
            break;
          }
          case "umbrella.destination.appRiskProfileId": {
            const ids = Array.isArray(values) ? values : [values];
            const names = ids.map((id) => {
              const name = lookups.appRiskProfiles && lookups.appRiskProfiles[String(id)];
              return name || `App Risk Profile #${String(id).substring(0, 8)}…`;
            });
            summaryText = `App Risk Profile: ${names.join(", ")}`;
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
          default: {
            // Fallback: strip umbrella. prefix and source./destination. prefix,
            // replace underscores with spaces, uppercase the dimension name.
            const simple = type.replace(/^umbrella\./i, "").replace(/^(source|destination)\./i, "").replace(/_/g, " ");
            const valStr = Array.isArray(values) ? values.map(v => typeof v === "object" ? JSON.stringify(v) : v).join(", ") : values;
            summaryText = `${simple.toUpperCase()}: ${valStr}`;
            break;
          }
        }

        if (summaryText) summaries.push({ text: summaryText, raw: c });
      }
      return summaries;
    }

    async function update(rules, findings, identityMap, objectMap, objectMaps, identityTypeMap) {
      const lookups = await loadLookups();
      lookups.identities = identityMap || {};
      lookups.identityTypes = Object.assign({}, DEFAULT_IDENTITY_TYPES, identityTypeMap || {});
      lookups.sourceIdentityTypeIds = (objectMaps && objectMaps.sourceIdentityTypeIds) || {};
      lookups.objects = objectMap || {};
      lookups.privateResources = (objectMaps && objectMaps.privateResources) || objectMap || {};
      lookups.destinationLists = (objectMaps && objectMaps.destinationLists) || {};
      lookups.networkObjects   = (objectMaps && objectMaps.networkObjects) || {};
      lookups.serviceObjectGroups = (objectMaps && objectMaps.serviceObjectGroups) || {};
      lookups.applicationLists = (objectMaps && objectMaps.applicationLists) || {};
      lookups.categoryLists    = (objectMaps && objectMaps.categoryLists) || {};
      lookups.applicationCategories = (objectMaps && objectMaps.applicationCategories) || {};

      // Render Policy Audit & Overlap Summary Banner at top of Rules tab
      const allFindings = findings || [];
      const totalIssues = allFindings.length;
      const shadowCount = allFindings.filter(f => f.checkId === "shadowing").length;
      const dupCount = allFindings.filter(f => f.checkId && f.checkId.includes("duplicate")).length;
      const conflictCount = allFindings.filter(f => f.checkId && f.checkId.includes("conflict")).length;
      const permissiveCount = allFindings.filter(f => f.checkId && f.checkId.includes("permissive")).length;

      summaryContainer.innerHTML = "";
      const summaryCard = el("div", { class: "psc-audit-summary-card" });
      const summaryHeader = el("div", { class: "psc-audit-summary-header" }, [
        el("span", { class: "psc-audit-summary-title" }, ["Policy Audit & Overlap Summary"]),
        totalIssues > 0
          ? el("span", { class: "psc-audit-badge-warning" }, [`⚠️ ${totalIssues} Issue${totalIssues > 1 ? "s" : ""} Detected`])
          : el("span", { class: "psc-audit-badge-pass" }, ["✓ 100% Healthy"])
      ]);

      const statsRow = el("div", { class: "psc-audit-stats-row" }, [
        el("div", { class: "psc-audit-stat-chip" }, [
          el("span", { class: "psc-audit-stat-label" }, ["Total Rules:"]),
          el("span", { class: "psc-audit-stat-val" }, [String((rules || []).length)])
        ]),
        el("div", { class: `psc-audit-stat-chip ${shadowCount > 0 ? "has-issues" : ""}` }, [
          el("span", { class: "psc-audit-stat-label" }, ["Shadowed:"]),
          el("span", { class: "psc-audit-stat-val" }, [String(shadowCount)])
        ]),
        el("div", { class: `psc-audit-stat-chip ${dupCount > 0 ? "has-issues" : ""}` }, [
          el("span", { class: "psc-audit-stat-label" }, ["Duplicate:"]),
          el("span", { class: "psc-audit-stat-val" }, [String(dupCount)])
        ]),
        el("div", { class: `psc-audit-stat-chip ${conflictCount > 0 ? "has-issues" : ""}` }, [
          el("span", { class: "psc-audit-stat-label" }, ["Conflicting:"]),
          el("span", { class: "psc-audit-stat-val" }, [String(conflictCount)])
        ]),
        el("div", { class: `psc-audit-stat-chip ${permissiveCount > 0 ? "has-issues" : ""}` }, [
          el("span", { class: "psc-audit-stat-label" }, ["Permissive:"]),
          el("span", { class: "psc-audit-stat-val" }, [String(permissiveCount)])
        ]),
      ]);

      summaryCard.appendChild(summaryHeader);
      summaryCard.appendChild(statsRow);

      if (totalIssues > 0) {
        const detailsBox = el("details", { class: "psc-result-details", style: { marginTop: "6px" } });
        const summaryLabel = el("summary", { style: { fontSize: "var(--ds-text-2xs)", fontWeight: "600", color: "var(--ds-pending-fg)", cursor: "pointer", fontFamily: "var(--hbr-font-family)" } }, [
          `▶ View overlap & conflict breakdown (${totalIssues})`
        ]);
        const issuesList = el("div", { style: { display: "flex", flexDirection: "column", gap: "4px", marginTop: "6px" } });
        allFindings.forEach(f => {
          const fc = COLOR[f.severity] || COLOR.low;
          issuesList.appendChild(el("div", { class: "psc-check-item", style: { borderLeftColor: fc.text, background: fc.bg } }, [
            el("div", { class: "psc-check-item-head", style: { color: fc.text } }, [`[${f.checkId || "Audit"}] ${f.severity ? f.severity : ""}`]),
            el("span", { class: "psc-check-msg" }, [f.message]),
            f.detail ? el("span", { class: "psc-check-detail" }, [f.detail]) : null
          ].filter(Boolean)));
        });
        detailsBox.appendChild(summaryLabel);
        detailsBox.appendChild(issuesList);
        summaryCard.appendChild(detailsBox);
      }

      summaryContainer.appendChild(summaryCard);

      const previousCards = Array.from(rulesContainer.querySelectorAll(".psc-rule-group"));
      const openIds = new Set(previousCards.filter(card => card.open).map(card => card.getAttribute("data-rule-id")));
      const focused = document.activeElement;
      const focusedCard = previousCards.find(card => card.contains(focused));
      const controlSelector = "summary, button, input, select, textarea, a[href], [tabindex]";
      const focusedControlIndex = focusedCard ? Array.from(focusedCard.querySelectorAll(controlSelector)).indexOf(focused) : -1;
      const focusedId = focusedCard && focusedCard.getAttribute("data-rule-id");
      loadedTotal = (rules || []).length;
      rulesContainer.innerHTML = "";
      if (!rules || rules.length === 0) {
        rulesContainer.appendChild(el("p", { class: "psc-empty", style: { textAlign: "center", color: "var(--ds-text-muted)", fontFamily: "var(--hbr-font-mono)" } }, ["No rules loaded"]));
        applyRulesFilter();
        return;
      }

      const findingsByRule = new Map();
      for (const f of findings || []) {
        if (f.ruleId !== undefined && f.ruleId !== null) {
          const k = String(f.ruleId);
          if (!findingsByRule.has(k)) findingsByRule.set(k, []);
          findingsByRule.get(k).push(f);
        }
        if (f.ruleName) {
          const kName = String(f.ruleName).trim().toLowerCase();
          if (!findingsByRule.has(kName)) findingsByRule.set(kName, []);
          findingsByRule.get(kName).push(f);
        }
      }

      for (const rule of rules) {
        const rName = rule.ruleName || rule.name || "(unnamed)";
        const rAction = (rule.ruleAction || rule.action || "allow").toLowerCase();
        const rPrio = rule.rulePriority !== undefined ? rule.rulePriority : rule.order;
        const rId = rule.ruleId !== undefined ? rule.ruleId : rule.id;

        const idKey = String(rId);
        const nameKey = String(rName).trim().toLowerCase();
        const idFindings = findingsByRule.get(idKey) || [];
        const nameFindings = findingsByRule.get(nameKey) || [];

        // Deduplicate findings for this rule
        const seen = new Set();
        const ruleFindings = [];
        for (const f of [...idFindings, ...nameFindings]) {
          const sig = `${f.checkId}:${f.message}`;
          if (!seen.has(sig)) {
            seen.add(sig);
            ruleFindings.push(f);
          }
        }

        const borderLeftColor = rAction === "allow" ? "var(--ds-allow-fg)" : (rAction === "block" ? "var(--ds-block-strong)" : "var(--ds-isolate-fg)");

        const card = el("details", {
          class: "psc-rule-group",
          "data-rule-id": rId,
          "data-action": rAction,
          "data-type": (rule.type || "").toLowerCase(),
          style: { borderLeft: `3px solid ${borderLeftColor}` }
        });

        if (rId !== undefined && rId !== null) card.open = openIds.has(String(rId));

        const condSummaries = summarizeConditions(rule, lookups);

        // Header Top Line: Priority Badge, Rule Name, Action Pill
        const actionCls = rAction === "allow" ? "psc-action-allow" : (rAction === "block" ? "psc-action-block" : "psc-action-isolate");
        const topBar = el("div", { class: "psc-rule-top-line" }, [
          el("span", { class: "psc-rule-prio" }, [`#${rPrio}`]),
          el("span", { class: "psc-rule-name" }, [rName]),
          el("span", { class: `psc-rule-action-pill ${actionCls}` }, [rAction.toUpperCase()]),
        ]);

        // Rich metadata row — description, ruleset, modified date, external ID
        const rawRule = rule.raw || rule;
        const metaFields = [];
        if (rawRule.ruleDescription) metaFields.push({ label: "DESC", value: rawRule.ruleDescription });
        if (rawRule.rulesetName) metaFields.push({ label: "RULESET", value: rawRule.rulesetName });
        if (rawRule.modifiedAt) {
          const d = new Date(rawRule.modifiedAt);
          metaFields.push({ label: "MODIFIED", value: d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }) });
        }
        if (rawRule.ruleExternalId) metaFields.push({ label: "EXT ID", value: String(rawRule.ruleExternalId) });
        if (rawRule.ruleIName) metaFields.push({ label: "I-NAME", value: rawRule.ruleIName });

        let metaRow = null;
        if (metaFields.length > 0) {
          metaRow = el("div", { class: "psc-rule-meta-row" });
          metaFields.slice(0, 3).forEach(m => {
            metaRow.appendChild(el("span", { class: "psc-rule-meta-chip" }, [`${m.label}: ${m.value}`]));
          });
        }

        // Inline Data Chips Bar
        const inlineChips = el("div", { class: "psc-inline-chips" });
        condSummaries.slice(0, 4).forEach(cs => {
          const colonIdx = cs.text.indexOf(":");
          if (colonIdx > -1) {
            inlineChips.appendChild(el("span", { class: "psc-chip" }, [
              el("span", { class: "psc-chip-key" }, [cs.text.slice(0, colonIdx)]),
              el("span", { class: "psc-chip-val" }, [cs.text.slice(colonIdx + 1)]),
            ]));
          } else {
            inlineChips.appendChild(el("span", { class: "psc-chip" }, [
              el("span", { class: "psc-chip-val" }, [cs.text]),
            ]));
          }
        });

        // Add Security Profile Chips directly to header bar (dynamically read live ruleSettings)
        const sp = (function() {
          const settings = (rule.raw && rule.raw.ruleSettings) || rule.ruleSettings || [];
          const getVal = (pattern) => {
            const found = settings.find(s => s.settingName === pattern || (s.settingName && s.settingName.toLowerCase().includes(pattern.toLowerCase())));
            return found ? found.settingValue : undefined;
          };

          const ipsVal = getVal("ipsProfileId") || getVal("ips");
          const webVal = getVal("webProfileId") || getVal("tls") || getVal("decryption");
          const ampVal = getVal("profileIdClientbased") || getVal("profileIdClientless") || getVal("amp") || getVal("malware");
          const dlpVal = getVal("tenantControlProfileId") || getVal("dlp");

          const isReal = (v) => v !== undefined && v !== null && v !== "" && v !== "DISABLED" && v !== "NONE" && v !== false && v !== 0;
          const pre = rule.security_profiles || {};

          return {
            ips_enabled: isReal(ipsVal) || pre.ips_enabled === true,
            amp_malware_enabled: isReal(ampVal) || pre.amp_malware_enabled === true,
            tls_decryption_enabled: isReal(webVal) || pre.tls_decryption_enabled === true,
            dlp_enabled: isReal(dlpVal) || pre.dlp_enabled === true,
          };
        })();

        const makeSpChip = (label, enabled) => {
          return el("span", {
            class: "psc-chip",
            style: {
              background: enabled ? "var(--ds-allow-soft)" : "var(--ds-surface-subtle)",
              borderColor: enabled ? "var(--ds-allow-line)" : "var(--ds-border-control)",
              color: enabled ? "var(--ds-allow-fg)" : "var(--ds-text-muted)",
              fontWeight: enabled ? "700" : "500"
            }
          }, [`${label}: ${enabled ? "ON" : "OFF"}`]);
        };
        inlineChips.appendChild(makeSpChip("IPS", sp.ips_enabled));
        inlineChips.appendChild(makeSpChip("AMP", sp.amp_malware_enabled));
        inlineChips.appendChild(makeSpChip("TLS", sp.tls_decryption_enabled));
        inlineChips.appendChild(makeSpChip("DLP", sp.dlp_enabled));

        const headerChildren = [topBar];
        if (metaRow) headerChildren.push(metaRow);
        headerChildren.push(inlineChips);

        const header = el("summary", { class: "psc-rule-group-header" }, headerChildren);

        card.appendChild(header);

        // Card Body
        const cardBody = el("div", { class: "psc-check-list" });

        // Findings / Audit Feedback section — render ONLY when issues exist
        if (ruleFindings.length > 0) {
          const findingsBox = el("div", { style: { display: "flex", flexDirection: "column", gap: "4px" } });
          ruleFindings.forEach(f => {
            const fc = COLOR[f.severity] || COLOR.low;
            findingsBox.appendChild(el("div", { class: "psc-check-item", style: { borderLeftColor: fc.text, background: fc.bg } }, [
              el("div", { class: "psc-check-item-head", style: { color: fc.text } }, [`[AUDIT ISSUE: ${f.checkId.toUpperCase()}] — ${f.severity.toUpperCase()}`]),
              el("span", { class: "psc-check-msg" }, [f.message]),
              f.detail ? el("span", { class: "psc-check-detail" }, [f.detail]) : null
            ].filter(Boolean)));
          });
          cardBody.appendChild(findingsBox);
        }

        card.appendChild(cardBody);
        rulesContainer.appendChild(card);
      }

      applyRulesFilter();
      if (focusedId !== null && focusedId !== undefined) {
        const replacement = Array.from(rulesContainer.querySelectorAll(".psc-rule-group"))
          .find(card => card.getAttribute("data-rule-id") === focusedId && card.style.display !== "none");
        if (replacement) {
          const control = replacement.querySelectorAll(controlSelector)[focusedControlIndex];
          if (control) control.focus({ preventScroll: true });
        }
      }
    }

    return { update };
  }

  global.PopupSections = {
    buildRulesList,
    loadLookups,
    buildAuditSections:    () => ({ goodSection: { update: () => {} }, badSection: { update: () => {} }, allRulesSection: { update: () => {} } }),
    buildWillMatchSection: () => ({ section: null, update: () => {} }),
    buildGoodSection:      () => ({ section: null, update: () => {} }),
    buildBadSection:       () => ({ section: null, update: () => {} }),
  };
})(window);