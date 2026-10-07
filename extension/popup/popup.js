// =============================================================================
// popup.js — main controller for the extension popup
//
// Architecture: data is auto-fetched by the service worker the moment a token
// is captured (fetch-on-token-capture). The popup just reads pre-fetched data
// from chrome.storage.local and listens for live updates.
//
// Depends on (loaded via <script> tags in popup.html, in this order):
//   1. matcher.js        → window.Matcher
//   2. popup-sections.js → window.PopupSections
//   3. this file
// =============================================================================

const api = typeof browser !== "undefined" ? browser : chrome;

document.addEventListener("DOMContentLoaded", () => {
  const errorBanner = document.getElementById("error-banner");
  const testerRoot = document.getElementById("tester-root");
  const rulesRoot = document.getElementById("rules-root");

  let catalogRefreshRequested = false;

  // ---------------------------------------------------------------------------
  // Header close button logic
  // ---------------------------------------------------------------------------
  const closeBtn = document.getElementById("toolbar-close");
  if (closeBtn) {
    closeBtn.addEventListener("click", () => {
      minimizeEmbeddedPanel();
    });
  }

  // ---------------------------------------------------------------------------
  // Tab Switching Logic
  // ---------------------------------------------------------------------------
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.getAttribute("data-target")).classList.add("active");
    });
  });

  // ---------------------------------------------------------------------------
  // State handles
  // ---------------------------------------------------------------------------
  let testerHandle = null;
  let auditHandle  = null;
  let currentRules       = [];
  let currentFindings    = [];
  let currentIdentityMap = {};
  let currentObjectMap   = {};
  let currentObjectMaps  = {
    privateResources: {},
    destinationLists: {},
    networkObjects: {},
    serviceObjectGroups: {},
    applicationLists: {},
    categoryLists: {},
    destinationScopes: { public_internet: "Internet", private_network: "Private Access" },
    appRiskProfiles: {},
  };
  let currentIdentityTypeMap = {};
  let currentMemberMaps = {};
  let currentRuleFetchStatus = {};
  let deferredStorageRender = false;
  let deferredRenderTimer = null;
  let dataRevision = 0;
  let loadSeq = 0;

  // ---------------------------------------------------------------------------
  // Highlight matched rule on the dashboard page
  // ---------------------------------------------------------------------------
  function lookupDestination(host, orgId) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => resolve({ ok: false, error: "timeout" }), 4000);
      try {
        api.runtime.sendMessage({ type: "LOOKUP_DESTINATION", host, orgId }, (response) => {
          clearTimeout(timer);
          resolve(api.runtime.lastError ? { ok: false, error: api.runtime.lastError.message } : (response || { ok: false }));
        });
      } catch (err) {
        clearTimeout(timer);
        resolve({ ok: false, error: err.message });
      }
    });
  }

  // targets: [{ ruleName, stages: ["DNS", "Web"], action, matchedConditions }]
  function highlightRulesOnPage(targets) {
    api.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || tabs.length === 0) return;
      api.tabs.sendMessage(tabs[0].id, { type: "HIGHLIGHT_RULES", targets }, () => {
        if (api.runtime.lastError) {
          console.warn("[popup] HIGHLIGHT_RULES — content script not reachable:",
            api.runtime.lastError.message);
        }
      });
    });
  }

  function buildNoMatchDiagnostic(rules, testInput, ruleFetchStatus) {
    const scopeText = String(testInput.destinationScope || "").trim().toLowerCase();
    const normalizedScope =
      scopeText === "internet" || scopeText === "public internet" || scopeText === "public_internet"
        ? "public_internet"
        : scopeText === "private access" || scopeText === "private_network"
          ? "private_network"
          : null;
    const defaults = (rules || []).filter(rule => rule.is_default || rule.ruleIsDefault).map(rule => ({
      id: rule.id || rule.ruleId,
      name: rule.name || rule.ruleName,
      scope: rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess) || null,
      action: rule.action || rule.ruleAction,
      conditions: (rule.conditions || rule.ruleConditions || []).map(condition => condition.attributeName),
    }));
    return {
      destination: testInput.destination || "",
      scope: testInput.destinationScope || "",
      normalizedScope,
      defaults,
      defaultRuleFetch: (ruleFetchStatus && ruleFetchStatus.defaultRuleFetch) || null,
    };
  }

  function policySnapshot() {
    return structuredClone({
      revision: dataRevision,
      rules: currentRules, catalogs: currentObjectMaps, identities: currentIdentityMap,
      objects: currentObjectMap, memberMaps: currentMemberMaps, identityTypeNames: currentIdentityTypeMap,
    });
  }

  async function buildLookups(snapshot) {
    const staticBase = await window.PopupSections.loadLookups();
    const lookups = { ...staticBase, ...snapshot.catalogs };
    lookups.sourceIdentityTypeIds = snapshot.catalogs.sourceIdentityTypeIds || {};
    lookups.identities = snapshot.identities;
    lookups.objects = snapshot.objects;
    lookups.privateResources = snapshot.catalogs.privateResources || snapshot.objects;
    for (const key of ["destinationLists", "networkObjects", "serviceObjectGroups", "applicationLists", "categoryLists", "appRiskProfiles", "postureProfiles", "geolocations", "applicationCategories", "enterpriseApplications"]) {
      lookups[key] = snapshot.catalogs[key] || {};
    }
    const orgExclusions = Array.isArray(snapshot.catalogs.exclusions) ? snapshot.catalogs.exclusions : [];
    const staticExclusions = Array.isArray(staticBase.exclusions) ? staticBase.exclusions : [];
    const merged = [...orgExclusions];
    const seen = new Set(orgExclusions.map(e => (e.domain || "").toLowerCase().trim()));
    for (const st of staticExclusions) {
      const d = (st.domain || "").toLowerCase().trim();
      if (d && !seen.has(d)) {
        merged.push(st);
        seen.add(d);
      }
    }
    lookups.exclusions = merged;
    lookups.memberMaps = snapshot.memberMaps;
    lookups.identityTypeNames = snapshot.identityTypeNames;
    return lookups;
  }

  async function renderResults(rules, findings, identityMap, objectMap, objectMaps, identityTypeMap) {
    rulesRoot.innerHTML = "";
    auditHandle  = null;

    const identityOptions = window.Matcher.getIdentityOptions(rules);
    const snapshot = policySnapshot();
    const lookups = await buildLookups(snapshot);

    if (!testerHandle) testerHandle = window.TrafficPathPanel.create(
      testerRoot,
      lookups,
      /* onRun */ async (request, options = {}) => {
        const snapshot = policySnapshot();
        if (!snapshot.rules.length) return { error: "No rules are loaded yet. Open the dashboard's policy page and wait for the data to load." };
        const lookups = await buildLookups(snapshot);
        const earlyExclusion = window.TrafficPath.matchExclusion(request.destination.host, lookups.exclusions);
        let destinationLookup = null;
        if (earlyExclusion && earlyExclusion.intent === "Bypass Secure Access") {
          destinationLookup = { ok: false, bypassed: true, reason: `Bypasses Secure Access via Traffic Steering (${earlyExclusion.domain})` };
        } else if (options.autoLookup !== false && request.destination.kind === "domain") {
          let lookupOrgId = new URLSearchParams(window.location.search).get("orgId");
          if (!lookupOrgId && isEmbeddedInPage()) lookupOrgId = await requestOrgIdFromParent();
          try {
            destinationLookup = await lookupDestination(request.destination.host, lookupOrgId);
            if (destinationLookup && destinationLookup.ok) {
              request = { ...request, facts: { ...window.TrafficPath.factsFromLookup(destinationLookup, lookups), ...request.facts } };
            }
          } catch (_) {
            destinationLookup = { ok: false, error: "lookup failed" };
          }
        }
        if (snapshot.revision !== dataRevision) return { error: "Policy data changed. Check again with the updated rules." };
        const evaluation = window.TrafficPath.evaluate(request, snapshot.rules, lookups, window.Matcher);
        return { ...evaluation, lookups, destinationLookup, facts: request.facts };
      },
      /* onHighlight */ (targets, summary) => {
        highlightRulesOnPage(targets);
        minimizeEmbeddedPanel(summary);
      },
      {
        getPolicy: async () => {
          const snapshot = policySnapshot();
          return { rules: snapshot.rules, lookups: await buildLookups(snapshot) };
        },
      }
    );

    testerHandle.setData({ rulesCount: rules.length, catalogs: lookups, revision: dataRevision, context: isEmbeddedInPage() ? "dashboard" : "toolbar" });

    // 2. Tab 2: Single Rules List — never an empty list while rules load.
    if (!rules.length) {
      renderRulesPlaceholder();
      return;
    }
    auditHandle = window.PopupSections.buildRulesList(rulesRoot);
    auditHandle.update(rules, findings, identityMap || {}, objectMap || {}, objectMaps || {}, identityTypeMap || {});
  }

  // Loading vs stalled state for the Rules tab while no rules are stored.
  let dataStalled = false;
  function renderRulesPlaceholder() {
    if (!dataStalled) {
      showAnalyzing("Loading your policy rules…");
      return;
    }
    rulesRoot.replaceChildren();
    const box = document.createElement("div");
    box.className = "psc-rules-stalled";
    box.setAttribute("role", "status");
    const title = document.createElement("strong");
    title.textContent = "Policy data hasn't loaded";
    const text = document.createElement("p");
    text.textContent = isEmbeddedInPage()
      ? "The checker reads your rules with the dashboard's sign-in. Reload the policy page; if it keeps happening, sign in again."
      : "Open the Secure Access dashboard's policy page so the checker can read your rules.";
    const retry = document.createElement("button");
    retry.type = "button";
    retry.textContent = "Try again";
    retry.addEventListener("click", () => {
      dataStalled = false;
      testerHandle && testerHandle.setData({ stalled: false });
      renderRulesPlaceholder();
      triggerRefresh();
      scheduleStallCheck();
    });
    box.append(title, text, retry);
    rulesRoot.appendChild(box);
  }

  const STALL_AFTER_MS = 25000;
  let stallTimer = null;
  function scheduleStallCheck() {
    clearTimeout(stallTimer);
    stallTimer = setTimeout(() => {
      if (currentRules.length) return;
      dataStalled = true;
      if (testerHandle) testerHandle.setData({ stalled: true });
      renderRulesPlaceholder();
    }, STALL_AFTER_MS);
  }
  scheduleStallCheck();

  // ---------------------------------------------------------------------------
  // Org-ID handshake — needed when popup is embedded in content-script.js's
  // injected iframe (cross-origin can't read parent location directly).
  // ---------------------------------------------------------------------------
  const DASHBOARD_ORIGIN_PATTERN = /^https:\/\/([a-z0-9-]+\.)*cisco\.com$/i;

  function isEmbeddedInPage() {
    return window.self !== window.top;
  }

  // `summary` (optional) lets the page dock a compact result card while the
  // panel is minimized.
  function minimizeEmbeddedPanel(summary) {
    if (!isEmbeddedInPage()) return;
    // The summary names policy rules, so send it only to the dashboard origin.
    const parentOrigin = (window.location.ancestorOrigins && window.location.ancestorOrigins[0]) || "";
    const targetOrigin = DASHBOARD_ORIGIN_PATTERN.test(parentOrigin) ? parentOrigin : null;
    window.parent.postMessage({ type: "SEC_MINIMIZE_PANEL", summary: targetOrigin ? summary || null : null }, targetOrigin || "*");
  }

  function requestOrgIdFromParent(timeoutMs = 1500) {
    return new Promise((resolve) => {
      let done = false;
      function onMessage(event) {
        if (done) return;
        if (!DASHBOARD_ORIGIN_PATTERN.test(event.origin)) return;
        if (event.source !== window.parent) return;
        if (!event.data || event.data.type !== "SEC_ORG_CONTEXT") return;
        done = true;
        window.removeEventListener("message", onMessage);
        resolve(event.data.orgId || null);
      }
      window.addEventListener("message", onMessage);
      window.parent.postMessage({ type: "SEC_REQUEST_ORG_CONTEXT" }, "*");
      setTimeout(() => {
        if (done) return;
        done = true;
        window.removeEventListener("message", onMessage);
        resolve(null);
      }, timeoutMs);
    });
  }

  // ---------------------------------------------------------------------------
  // "Analyzing" spinner — shown while waiting for pre-fetched data
  // ---------------------------------------------------------------------------
  function showAnalyzing(msg) {
    const text = msg || "Analyzing policies\u2026";
    rulesRoot.innerHTML = `
      <div role="status" style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                  padding:48px 20px;color:#64748b;font-size:13px;gap:12px;">
        <div style="width:22px;height:22px;border:2px solid #e2e8f0;border-top-color:#0f172a;
                    border-radius:50%;animation:psc-spin 0.8s linear infinite;"></div>
        <span>${text}</span>
      </div>
    `;
    // Inject keyframe if not already present
    if (!document.getElementById("psc-analyzing-style")) {
      const style = document.createElement("style");
      style.id = "psc-analyzing-style";
      style.textContent = "@keyframes psc-spin{to{transform:rotate(360deg)}}";
      document.head.appendChild(style);
    }
  }

  // ---------------------------------------------------------------------------
  // Load from chrome.storage.local and render
  // Returns "resolved" | "partial" | "empty"
  // ---------------------------------------------------------------------------
  function applyPolicyData(cached) {
    currentRules = Array.isArray(cached.sse_rules) ? cached.sse_rules : [];
    const ready = currentRules.length > 0;
    currentFindings = ready ? cached.sse_findings || [] : [];
    currentIdentityMap = ready ? cached.sse_identity_map || {} : {};
    currentIdentityTypeMap = ready ? cached.sse_identity_type_map || {} : {};
    currentRuleFetchStatus = ready ? cached.sse_rule_fetch_status || {} : {};
    currentObjectMaps = ready ? cached.sse_object_maps || {} : {};
    currentObjectMap = currentObjectMaps.privateResources || {};
    currentMemberMaps = ready ? cached.sse_member_maps || {} : {};
  }

  async function loadAndRender() {
    const seq = ++loadSeq;
    const revision = dataRevision;
    const cached = await api.storage.local.get([
      "sse_rules", "sse_findings", "sse_identity_map", "sse_identity_type_map", "sse_object_maps", "sse_member_maps", "sse_rule_fetch_status"
    ]);

    if (seq !== loadSeq || revision !== dataRevision) return "superseded";
    applyPolicyData(cached);
    if (!currentRules.length) {
      renderResults([], [], {}, {}, {}, {}).catch(() => {});
      triggerRefresh();
      return "empty";
    }
    const om = currentObjectMaps;

    // A partial object map must not suppress catalog loading. Source and
    // destination selectors are ready only after their own catalog keys exist.
    const requiredCatalogs = [
      "sourceUsers", "sourceRoaming", "sourceGroups", "sourceEndpointDevices",
      "sourceNetworks", "sourceSites", "sourceSecurityGroupTags", "sourceCatalystSdwan",
      "sourceTunnelGroups", "sourceNetworkDevices", "sourceMobileDevices", "sourceChromebooks", "sourceZtnaClients",
      "sourceGsuiteUsers", "sourceGsuiteOus",
      "destinationScopes",
    ];
    // Render immediately with available maps. Individual selectors convey
    // loading/unavailable/empty state, so one failed catalog must not hold the
    // entire Rules tab in a permanent "Resolving labels" loop.
    const missingCatalogs = requiredCatalogs.filter(key => !Object.prototype.hasOwnProperty.call(om, key));
    errorBanner.style.display = "none";
    renderResults(currentRules, currentFindings, currentIdentityMap, currentObjectMap, currentObjectMaps, currentIdentityTypeMap).catch(() => {});

    if (missingCatalogs.length === 0) {
      return "resolved";
    }

    // Only ask once per popup instance. Storage writes from a refresh used to
    // re-enter loadAndRender() and start another refresh indefinitely.
    if (!catalogRefreshRequested) {
      catalogRefreshRequested = true;
      triggerRefresh();
    }

    const resolvingBar = document.createElement("div");
    resolvingBar.id = "psc-resolving-bar";
    resolvingBar.setAttribute("role", "status");
    resolvingBar.style.cssText = "background:#f8fafc;color:#475569;padding:8px 16px;font-size:12px;" +
      "border-bottom:1px solid #e2e8f0;";
    resolvingBar.textContent = `Still loading ${missingCatalogs.length} identity or object list${missingCatalogs.length === 1 ? "" : "s"}. Names fill in as they arrive.`;
    rulesRoot.prepend(resolvingBar);
    return "partial";
  }

  // ---------------------------------------------------------------------------
  // Manual refresh — ask SW to re-fetch everything now
  // ---------------------------------------------------------------------------
  async function triggerRefresh() {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      let orgId = urlParams.get("orgId");
      if (!orgId && isEmbeddedInPage()) {
        orgId = await requestOrgIdFromParent();
      }
      api.runtime.sendMessage({ type: "RUN_SCAN", orgId });
    } catch (e) {
      // SW may be asleep — message will wake it, just ignore errors
    }
  }

  function editorIsActive() {
    const active = document.activeElement;
    return active && (active.matches("input, textarea, select") || active.isContentEditable);
  }

  function flushDeferredRender() {
    if (!deferredStorageRender || editorIsActive()) return;
    deferredStorageRender = false;
    loadAndRender();
  }

  // ---------------------------------------------------------------------------
  // Entry point — render results immediately and listen for live updates
  // ---------------------------------------------------------------------------

  loadAndRender();

  document.addEventListener("focusout", () => {
    clearTimeout(deferredRenderTimer);
    deferredRenderTimer = setTimeout(flushDeferredRender, 0);
  });

  // Live update: when SW writes new data to storage, re-render only when the
  // user is not actively editing a tester control. Rebuilding the form during
  // an input event destroys the focused element and its unsaved draft.
  api.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    const keys = ["sse_rules", "sse_findings", "sse_identity_map", "sse_object_maps", "sse_identity_type_map", "sse_member_maps", "sse_rule_fetch_status"];
    if (!keys.some(key => changes[key] && JSON.stringify(changes[key].oldValue) !== JSON.stringify(changes[key].newValue))) return;
    dataRevision++;
    if (testerHandle) testerHandle.invalidate();
    const cached = {
      sse_rules: currentRules, sse_findings: currentFindings, sse_identity_map: currentIdentityMap,
      sse_object_maps: currentObjectMaps, sse_identity_type_map: currentIdentityTypeMap,
      sse_member_maps: currentMemberMaps, sse_rule_fetch_status: currentRuleFetchStatus,
    };
    for (const key of keys) if (changes[key]) cached[key] = changes[key].newValue;
    applyPolicyData(cached);
    if (testerHandle) testerHandle.setData({ rulesCount: currentRules.length, catalogs: currentObjectMaps, revision: dataRevision });
    if (editorIsActive()) {
      deferredStorageRender = true;
      return;
    }
    deferredStorageRender = false;
    loadAndRender();
  });
});
