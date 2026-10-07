const api = typeof browser !== 'undefined' ? browser : chrome;

importScripts("../lib/debug-log.js");
const { logEvent, redactToken } = SecDebugLog;

// ---------------------------------------------------------------------------
// Cold-start pre-warm
//
// In MV3 the service worker terminates ~30s after the last event. The first
// sendMessage() from a freshly-opened popup is supposed to spin the SW back
// up, but the message can land during the spin-up window and be silently
// dropped, surfacing as `chrome.runtime.lastError` "The message port closed
// before a response was received." in the popup. To avoid that race:
//   1. Touch storage.session on onInstalled/onStartup so the SW is alive
//      before the first user action.
//   2. Hold a no-op keepalive for a few seconds after onInstalled so
//      in-flight start-up messages have a chance to land.
// The real listener registration (api.runtime.onMessage.addListener) below is
// synchronous at top level — it'll be active before the first message could
// realistically be sent, because onInstalled fires synchronously and the SW
// stays alive until the keepalive timer fires.
// ---------------------------------------------------------------------------
api.runtime.onInstalled.addListener(() => {
  try { logEvent("sw-startup", "onInstalled fired"); } catch {}
  // Force storage.session access — keeps SW alive for the keepalive window
  api.storage.session.get("__sw_keepalive").catch(() => {});
});
api.runtime.onStartup.addListener(() => {
  try { logEvent("sw-startup", "onStartup fired"); } catch {}
  api.storage.session.get("__sw_keepalive").catch(() => {});
});

function isSecurePolicyUrl(rawUrl) {
  try {
    const parsed = new URL(rawUrl);
    return parsed.hostname.toLowerCase() === "dashboard.sse.cisco.com"
      && /\/secure\/policy(?:\/|$|\?|#)/.test(parsed.pathname);
  } catch (_) {
    return false;
  }
}

async function syncToolbarPopup(tabId, rawUrl) {
  if (!api.action || !tabId) return;
  try {
    if (isSecurePolicyUrl(rawUrl)) {
      await api.action.setPopup({ tabId, popup: "popup/popup.html" });
    } else {
      await api.action.setPopup({ tabId, popup: "" });
    }
  } catch (_) {}
}

// Auto-inject only into a valid HTTPS Cisco dashboard URL. onUpdated also
// fires for transient chrome:// and extension URLs; passing those to scripting
// can produce an uncaught "Invalid URL" error during an extension reload.
// Token sniffing stays on all dashboard routes so prefetch can start before
// /secure/policy. The visible checker UI is gated in content-script.js.
api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  const rawUrl = tab.url || changeInfo.url;
  if (!rawUrl) return;
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return; }
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== "https:" || !(host === "cisco.com" || host.endsWith(".cisco.com"))) return;
  syncToolbarPopup(tabId, rawUrl);
  try {
    Promise.resolve(api.scripting.executeScript({
      target: { tabId },
      files: ["content/content-script.js"]
    })).catch(() => {});
  } catch (_) {
    // Chromium can synchronously reject an already-closed tab during reload.
  }
});

if (api.tabs && api.tabs.onActivated) {
  api.tabs.onActivated.addListener(async (activeInfo) => {
    try {
      const tab = await api.tabs.get(activeInfo.tabId);
      syncToolbarPopup(activeInfo.tabId, tab && tab.url);
    } catch (_) {}
  });
}

// ---------------------------------------------------------------------------
// Token storage
//
// Tokens are stored as OBJECTS, not bare strings: { token, capturedAt,
// source }, one per tokenKey. Cisco mints separately-scoped, separately-aged
// Bearer tokens per API host — confirmed live against org 8176184:
//   - sse_token        — api.sse.cisco.com / api.umbrella.com (original path)
//   - mgmt_authz_token — management.api.umbrella.com (issuer
//                        "umbrella-authz/authsvc", scope "role:root-readonly",
//                        ~5min TTL; serves both all_tag_identities/
//                        security_group_tag and .../catalyst_sdwan — same
//                        token, confirmed byte-for-byte identical JWT across
//                        both live-captured requests)
//   - opendns_token    — api.opendns.com (aud "https://api.opendns.com/v3/",
//                        only ~60s TTL — used for v3/organizations/{orgId}/
//                        internalnetworks)
// Each is tracked independently under its own chrome.storage.session key
// (the tokenKey itself), with its own staleness threshold in TOKEN_REGISTRY,
// since a 45s margin that's sane for opendns_token would be nonsense applied
// to sse_token and vice versa.
//
// Two independent capture paths can write any of them:
//   - "webrequest"       — the passive api.webRequest.onBeforeSendHeaders
//                           listener below (kept as a redundant fallback).
//   - "main-world-patch" — content/token-sniffer.js (MAIN world, patches
//                           fetch/XHR) relayed via content/token-relay.js
//                           and the TOKEN_CAPTURED message handler further
//                           down. This is the primary path, added to fix the
//                           MV3 service-worker cold-start race: it runs
//                           synchronously at document_start in the page's
//                           own realm, so it can't lose the race against the
//                           SW's webRequest listener re-registering after
//                           waking from idle.
//
// Whichever capture fires most recently wins (last-write-wins by
// capturedAt timestamp) — storeToken() below is the single write path for
// both sources, so this rule is enforced in one place.
// ---------------------------------------------------------------------------

const TOKEN_REGISTRY = {
  sse_token:        { maxAgeMs: 10 * 60 * 1000 }, // 10 min — starting point; real TTL not yet observed to expire in testing
  mgmt_authz_token: { maxAgeMs: 290 * 1000 },     // real TTL ~5min (300s) per JWT exp/iat — 10s margin
  opendns_token:    { maxAgeMs: 55 * 1000 },       // real TTL ~60s per JWT exp/iat — 5s margin (was 45s, too aggressive)
};

// url -> tokenKey, checked in order. Host-specific patterns must be checked
// before the broader (api\.sse\.cisco\.com|api\.umbrella\.com) one, since
// management.api.umbrella.com would also match a naive /umbrella\.com/-style
// regex.
const TOKEN_HOST_MAP = [
  { pattern: /^https:\/\/(management\.api\.umbrella\.com|investigate\.umbrella\.com)\//, tokenKey: "mgmt_authz_token" },
  { pattern: /^https:\/\/api\.opendns\.com\//, tokenKey: "opendns_token" },
  { pattern: /^https:\/\/(api\.sse\.cisco\.com|api\.umbrella\.com)\//, tokenKey: "sse_token" },
];

function tokenKeyForUrl(url) {
  if (typeof url !== "string") return null;
  for (const entry of TOKEN_HOST_MAP) {
    if (entry.pattern.test(url)) return entry.tokenKey;
  }
  return null;
}

async function storeToken(tokenKey, token, source, capturedAt, meta) {
  meta = meta || {};
  // Use chrome.storage.local so tokens survive MV3 service-worker termination
  // (~30s idle timeout). session storage is wiped on restart, which makes
  // identity resolution impossible when navigating between dashboard pages.
  const ST = api.storage.local;
  const result = await ST.get(tokenKey);
  const existing = result[tokenKey]; // { token, capturedAt, source } | undefined

  if (existing && (existing.token === token || existing.capturedAt >= capturedAt)) {
    logEvent("token-capture", "Ignored (existing token is identical or same age or newer)", {
      tokenKey, source, capturedAt, existingSource: existing.source, existingCapturedAt: existing.capturedAt,
      sameToken: existing.token === token,
    });
    return;
  }

  const ageSinceLastMs = existing ? capturedAt - existing.capturedAt : null;
  await ST.set({ [tokenKey]: { token, capturedAt, source } });

  const redacted = redactToken(token);
  logEvent("token-capture", "Token captured/updated", {
    tokenKey, source, url: meta.url || null, ageSinceLastMs,
    length: redacted.length, prefix: redacted.prefix,
  });

  // ── Fetch-on-token-capture ───────────────────────────────────────────
  // Every fresh token triggers a debounced full data fetch. Multiple tokens
  // arriving in quick succession (dashboard mints 2-3 within seconds) only
  // produce ONE fetch after the debounce window.
  _scheduleFetch();
}

// ---------------------------------------------------------------------------
// Auto-fetch: the moment a token is captured, fetch ALL data (rules,
// identities, objects, app lists) and store results in chrome.storage.local.
// Popup reads from there — no scan-trigger needed from the popup side.
//
// Debounced: rapid token arrivals (2-3 within seconds) batch into one fetch.
// Periodic: after each successful fetch, a 20-minute alarm is set to refetch.
// ---------------------------------------------------------------------------

const REFRESH_ALARM = "psc-periodic-refresh";
const REFRESH_INTERVAL_MIN = 20;

let _fetchInProgress = false;
let _fetchQueued = false;
let _queuedOrgId = undefined;
let _lastFetchAt = 0;
const MIN_FETCH_INTERVAL_MS = 3000; // 3s throttle — prevents rapid-fire fetches

function _scheduleFetch() {
  // Direct call with timestamp throttle. We avoid chrome.alarms for the
  // debounce because MV3 SW alarms have minimum 30s granularity and may
  // not fire reliably in all contexts. The 20-min REFRESH_ALARM handles
  // periodic refreshes separately.
  const now = Date.now();
  if (now - _lastFetchAt < MIN_FETCH_INTERVAL_MS) return;
  _lastFetchAt = now;
  fetchAllData().catch(err => {
    logEvent("auto-fetch", "fetchAllData failed", { error: err.message });
  });
}

async function fetchAllData(explicitOrgId) {
  if (_fetchInProgress) {
    _queuedOrgId = explicitOrgId || _queuedOrgId;
    _fetchQueued = true;
    return;
  }
  _fetchInProgress = true;
  const startTime = Date.now();

  try {
    logEvent("auto-fetch", "fetchAllData started");

    // 1. Get orgId
    let orgId = explicitOrgId;
    if (!orgId) {
      try { orgId = await getActiveOrgId(); } catch {}
    }
    if (!orgId) {
      const cached = await api.storage.local.get("cached_org_id");
      orgId = cached.cached_org_id;
    }
    if (!orgId) {
      logEvent("auto-fetch", "No orgId available, skipping fetch");
      return;
    }
    await api.storage.local.set({ cached_org_id: orgId });

    // 2. Get tabId for on-demand token checks
    let tabId = null;
    try {
      const tabs = await api.tabs.query({ active: true, currentWindow: true });
      tabId = tabs[0]?.id;
    } catch {}

    // 3. Fetch rules (needs sse_token)
    let rules = null;
    try {
      const tokenObj = await getFreshToken("sse_token", tabId);
      if (tokenObj) {
        const fetched = await fetchRules(tokenObj.token, orgId);
        rules = fetched.rules;
        const findings = runChecks(rules);
        await api.storage.local.set({
          sse_rules: rules,
          sse_findings: findings,
          sse_rule_fetch_status: { defaultRuleFetch: fetched.defaultRuleFetch, fetchedAt: Date.now() },
        });
        logEvent("auto-fetch", "Rules fetched", { count: rules.length, findings: findings.length, defaultRuleFetch: fetched.defaultRuleFetch });
      } else {
        logEvent("auto-fetch", "No sse_token available, skipping rules fetch");
      }
    } catch (err) {
      logEvent("auto-fetch", "Rules fetch failed", { error: err.message });
    }

    // If no rules fetched, use stored rules for identity/object resolution
    if (!rules) {
      const stored = await api.storage.local.get("sse_rules");
      rules = stored.sse_rules || [];
    }
    // Fetch source/destination catalogs independently of rule availability.
    // They power the tester and must not be blocked by a rule API failure.
    try {
      const catalogMaps = await resolveFullCatalogs(orgId, tabId);
      const previous = await api.storage.local.get("sse_object_maps");
      const previousMaps = (previous && previous.sse_object_maps) || {};
      for (const [key, map] of Object.entries(catalogMaps)) {
        if (Object.keys(map).length === 0 && previousMaps[key] && Object.keys(previousMaps[key]).length > 0) {
          catalogMaps[key] = previousMaps[key];
        }
      }
      await api.storage.local.set({ sse_object_maps: { ...previousMaps, ...catalogMaps } });
    } catch (err) {
      logEvent("auto-fetch", "Full catalog fetch failed", { error: err.message });
    }

    // Security profiles: which threat categories each web profile and the DNS
    // defaults block. Powers the checker's "is it flagged as a threat?" step.
    try {
      const securityProfiles = await resolveSecurityProfiles(orgId, tabId);
      if (securityProfiles) {
        const previous = await api.storage.local.get("sse_object_maps");
        await api.storage.local.set({ sse_object_maps: { ...((previous && previous.sse_object_maps) || {}), securityProfiles } });
      }
    } catch (err) {
      logEvent("auto-fetch", "Security profile fetch failed", { error: err.message });
    }

    if (rules.length === 0) {
      logEvent("auto-fetch", "No rules available; catalogs refreshed, skipping rule-dependent resolution");
      return;
    }

    // 4. Resolve identities (needs mgmt_authz_token)
    try {
      const identityResult = await resolveIdentities(rules, orgId, tabId);
      const identityMap = identityResult.names;
      if (Object.keys(identityMap).length > 0) {
        await api.storage.local.set({ sse_identity_map: identityMap });
        logEvent("auto-fetch", "Identities resolved", { count: Object.keys(identityMap).length });
      } else {
        logEvent("auto-fetch", "Empty identity map — keeping previous data if any");
      }
      // Catalog data stays authoritative, while targeted identity search fills
      // missing identity→type links when a paginated catalog did not load.
      if (Object.keys(identityResult.typeIds).length > 0) {
        const storedMaps = await api.storage.local.get("sse_object_maps");
        const objectMaps = (storedMaps && storedMaps.sse_object_maps) || {};
        const catalogTypeIds = objectMaps.sourceIdentityTypeIds || {};
        await api.storage.local.set({
          sse_object_maps: {
            ...objectMaps,
            sourceIdentityTypeIds: { ...identityResult.typeIds, ...catalogTypeIds },
          },
        });
        logEvent("auto-fetch", "Identity type links supplemented", { count: Object.keys(identityResult.typeIds).length });
      }
    } catch (err) {
      logEvent("auto-fetch", "Identity resolution failed", { error: err.message });
    }

    // 5. Resolve identity types (needs mgmt_authz_token)
    try {
      const identityTypeMap = await resolveIdentityTypes(orgId, tabId, rules);
      if (Object.keys(identityTypeMap).length > 0) {
        await api.storage.local.set({ sse_identity_type_map: identityTypeMap });
        logEvent("auto-fetch", "Identity types resolved", { count: Object.keys(identityTypeMap).length });
      }
    } catch (err) {
      logEvent("auto-fetch", "Identity type resolution failed", { error: err.message });
    }

    // 6. Resolve objects (needs various tokens)
    try {
      const objectMaps = await resolveObjectRefs(orgId, tabId, rules);
      // Merge with existing data — don't let a partial failure wipe good data
      const prev = await api.storage.local.get("sse_object_maps");
      const prevMaps = (prev && prev.sse_object_maps) || {};
      for (const [key, map] of Object.entries(objectMaps)) {
        if (Object.keys(map).length === 0 && prevMaps[key] && Object.keys(prevMaps[key]).length > 0) {
          objectMaps[key] = prevMaps[key];
        }
      }
      await api.storage.local.set({ sse_object_maps: { ...prevMaps, ...objectMaps } });
      const totalObjects = Object.values(objectMaps).reduce((sum, m) => sum + Object.keys(m).length, 0);
      logEvent("auto-fetch", "Objects resolved", { total: totalObjects });
    } catch (err) {
      logEvent("auto-fetch", "Object resolution failed", { error: err.message });
    }

    // 7. Resolve group/list membership (powers the popover's recursive
    //    expand). Best-effort; empty membership just leaves a group
    //    non-expandable rather than sinking the scan.
    try {
      const memberMaps = await resolveMembership(orgId, tabId, rules);
      await persistMemberMaps(memberMaps);
      logEvent("auto-fetch", "Membership resolved", {
        total: Object.values(memberMaps).reduce((s, m) => s + Object.keys(m).length, 0),
      });
    } catch (err) {
      logEvent("auto-fetch", "Membership resolution failed", { error: err.message });
    }

    // 8. Schedule next periodic refresh
    api.alarms.create(REFRESH_ALARM, { delayInMinutes: REFRESH_INTERVAL_MIN });

    logEvent("auto-fetch", "fetchAllData completed", { durationMs: Date.now() - startTime, orgId });
  } finally {
    _fetchInProgress = false;
    if (_fetchQueued) {
      _fetchQueued = false;
      const queuedOrgId = _queuedOrgId;
      _queuedOrgId = undefined;
      fetchAllData(queuedOrgId).catch(err => {
        logEvent("auto-fetch", "Queued fetchAllData failed", { error: err.message });
      });
    }
  }
}

// ---------------------------------------------------------------------------
// Token interception — fallback path (see comment above). Passive/
// non-blocking: never modifies or blocks the request. One listener covers
// all four hosts; tokenKeyForUrl() sorts out which stored token a given
// request's Authorization header belongs to.
// ---------------------------------------------------------------------------

api.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    for (const header of details.requestHeaders) {
      if (header.name.toLowerCase() === "authorization") {
        if (header.value.startsWith("Bearer ")) {
          const tokenKey = tokenKeyForUrl(details.url);
          if (tokenKey) {
            const token = header.value.slice(7);
            storeToken(tokenKey, token, "webrequest", Date.now(), { url: details.url });
          }
        }
        break;
      }
    }
  },
  {
    urls: [
      "https://api.sse.cisco.com/*",
      "https://api.umbrella.com/*",
      "https://management.api.umbrella.com/*",
      "https://investigate.umbrella.com/*",
      "https://api.opendns.com/*",
    ],
  },
  ["requestHeaders"]
);

// ---------------------------------------------------------------------------
// Helper: determine the active organization ID from the current tab's URL.
// Dashboard URLs look like https://dashboard.sse.cisco.com/org/{orgId}/...
// ---------------------------------------------------------------------------

async function getActiveOrgId() {
  // First try the active tab's URL
  const tabs = await api.tabs.query({ active: true, currentWindow: true });
  const url = tabs[0]?.url || "";
  const match = url.match(/\/org\/(\d+)/);
  if (match) {
    return match[1];
  }
  
  // Fallback: check cached org ID from storage (set by content-script.js when it detects the URL)
  const data = await api.storage.local.get("cached_org_id");
  if (data.cached_org_id) {
    return data.cached_org_id;
  }
  
  throw new Error(
    "Could not determine organization ID from the active tab. Open the Secure Access dashboard (e.g. https://dashboard.sse.cisco.com/org/<orgId>/secure/policy) and try again."
  );
}

// ---------------------------------------------------------------------------
// Helper: fetch rules from the SSE API
// ---------------------------------------------------------------------------

async function fetchRules(token, orgId) {
  // HAR-confirmed dashboard endpoint. It preserves `ruleAccess`, which is
  // required to distinguish private-network and public-Internet defaults.
  const BASE_URL = "https://api.sse.cisco.com";
  const defaultRuleUrl = `${BASE_URL}/policies/v2/rules?expandRuleDetails=true&ruleIsDefault=true`;
  const ORG_ID = orgId;
  const LIMIT = 100;
  let offset = 0;
  let allRules = [];
  let retries = 0;
  const MAX_RETRIES = 3;

  // No ruleIsDefault filter — default/catch-all rules (e.g. "All private
  // applications" - Block, "All Internet access" - Allow) are real, active
  // rules that affect traffic decisions and must be visible to the matcher
  // and checks, not silently excluded.
  //
  // UNVERIFIED: default rules' exact response shape (field completeness,
  // whether rulePriority is populated/meaningful for them, etc.) has not
  // been confirmed via a live fetch — the normalize step below relies on
  // the same defensive fallback chains already used for custom rules
  // (raw.sources || raw.source || ["any"], etc.), which should degrade
  // gracefully if default rules turn out to have fewer fields, but this
  // should be re-checked against real API output.
  while (true) {
    const url = `${BASE_URL}/policies/v2/rules?expandRuleDetails=true&ruleIsDefault=false&offset=${offset}&limit=${LIMIT}`;
    let response;
    const startedAt = Date.now();

    try {
      response = await fetch(url, {
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json",
          "Accept": "application/json"
        }
      });
      logEvent("rules-fetch", "API response", { url, status: response.status, latencyMs: Date.now() - startedAt });
    } catch (networkErr) {
      console.error("[fetchRules] fetch failed:", networkErr);
      logEvent("rules-fetch", "Network error", { url, error: networkErr.message, latencyMs: Date.now() - startedAt });
      throw new Error(`Network error fetching rules: ${networkErr.message}`);
    }

    // Handle rate limiting
    if (response.status === 429) {
      if (retries >= MAX_RETRIES) {
        throw new Error("Rate limit hit — max retries exceeded");
      }
      const retryAfter = parseInt(response.headers.get("Retry-After") || "5");
      await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
      retries++;
      continue; // retry same page
    }

    // 401 specifically means the token is expired/invalid — surfaced to
    // RUN_SCAN as a distinguishable error (err.isAuthError) so it can clear
    // the stale token and return a structured TOKEN_STALE response instead
    // of the raw Cisco error string.
    if (response.status === 401) {
      const body = await response.text().catch(() => "");
      logEvent("rules-fetch", "401 — token expired/invalid", { url, body: body.slice(0, 200) });
      const authErr = new Error(`API error 401 fetching rules: ${body.slice(0, 200)}`);
      authErr.isAuthError = true;
      throw authErr;
    }

    // Handle other non-2xx errors
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      logEvent("rules-fetch", "API error", { url, status: response.status, body: body.slice(0, 200) });
      throw new Error(
        `API error ${response.status} fetching rules: ${body.slice(0, 200)}`
      );
    }

    // Reset retry counter on success
    retries = 0;

    const data = await response.json();

    // HAR shape: { count, results, meta }; keep legacy fallbacks for cached
    // mock/test payloads.
    const pageRules = Array.isArray(data)
      ? data
      : (data.results || data.rules || data.data || data.items || []);

    // Normalize each raw rule into our internal shape.
    // API response shape is not yet confirmed.
    const normalized = pageRules.map(raw => {
      let ruleActionStr = raw.ruleAction || raw.action;
      if (!ruleActionStr) {
        console.warn(`[fetchRules] Rule ${raw.ruleId || raw.id || "unknown"} has no ruleAction/action, defaulting to allow`);
        ruleActionStr = "allow";
      }

      const ruleSettings = raw.ruleSettings || [];
      const getSetting = (name) => ruleSettings.find(s => s.settingName === name)?.settingValue;

      let loggingEnabled = true;
      if (raw.ruleSettings) {
        const logLevel = getSetting("umbrella.logLevel");
        // Assume missing or "NONE" means logging is off. LOG_ALL means on.
        loggingEnabled = logLevel !== undefined && logLevel !== "NONE";
      } else {
        // Fallback for mock payload
        loggingEnabled = raw.logging_enabled !== false && raw.loggingEnabled !== false;
      }

      // Security profiles — resolved from ruleSettings using confirmed Cisco API settingName keys.
      // Confirmed live API settingNames:
      //   - IPS: "umbrella.posture.ipsProfileId"
      //   - TLS / Web Inspection: "umbrella.posture.webProfileId"
      //   - AMP / Client Posture: "umbrella.posture.profileIdClientbased" / "umbrella.posture.profileIdClientless"
      //   - Tenant Control / DLP: "sse.tenantControlProfileId"
      const getProfile = (realSettingName, altNames) => {
        if (raw.ruleSettings) {
          let val = getSetting(realSettingName);
          if (val === undefined && altNames) {
            for (const alt of altNames) {
              val = getSetting(alt);
              if (val !== undefined) break;
            }
          }
          if (val !== undefined && val !== null && val !== "" && val !== false && val !== "DISABLED" && val !== "NONE") {
            return true;
          }
          return false;
        }
        return false;
      };

      return {
      id: raw.ruleId !== undefined ? raw.ruleId : (raw.id || String(Math.random())),
      name: raw.ruleName || raw.name || "Unnamed Rule",
      order: typeof raw.rulePriority === "number" ? raw.rulePriority : (typeof raw.order === "number" ? raw.order : parseInt(raw.rulePriority || raw.order || "0")),
      action: ruleActionStr.toLowerCase(),
      enabled: raw.ruleIsEnabled !== undefined ? raw.ruleIsEnabled : (raw.enabled !== false),
      is_default: raw.ruleIsDefault === true,
      sources: raw.sources || raw.source || ["any"],
      destinations: raw.destinations || raw.destination || ["any"],
      applications: raw.applications || raw.application || [],
      ports: raw.ports || raw.port || ["any"],
      protocol: raw.protocol || "any",
      // HAR-confirmed on default rules: public_internet | private_network.
      // destination.all is only a catch-all inside this traffic scope.
      trafficScope: raw.ruleAccess || null,
      conditions: Array.isArray(raw.ruleConditions) ? raw.ruleConditions : (Array.isArray(raw.conditions) ? raw.conditions : []),
      logging_enabled: loggingEnabled,
      security_profiles: {
        ips_enabled: getProfile("umbrella.posture.ipsProfileId", ["umbrella.security.ips", "ips_enabled"]),
        amp_malware_enabled: getProfile("umbrella.posture.profileIdClientbased", ["umbrella.posture.profileIdClientless", "umbrella.security.amp", "amp_malware_enabled"]),
        tls_decryption_enabled: getProfile("umbrella.posture.webProfileId", ["umbrella.security.tls", "tls_decryption_enabled"]),
        dlp_enabled: getProfile("sse.tenantControlProfileId", ["umbrella.security.dlp", "dlp_enabled"]),
      },
      raw: raw
    };
    });

    allRules = allRules.concat(normalized);

    // Stop paginating when we get fewer results than the page limit
    if (pageRules.length < LIMIT) break;
    offset += LIMIT;
  }

  // Fetch the two default rules separately: the HAR proves they are excluded
  // from the custom-rule query and carry the ruleAccess scope discriminator.
  let defaultRuleFetch = { loaded: 0, error: null };
  try {
    const defaultsResponse = await fetch(defaultRuleUrl, {
      headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
    });
    logEvent("rules-fetch", "Default-rule API response", { url: defaultRuleUrl, status: defaultsResponse.status });
    if (!defaultsResponse.ok) {
      const body = await defaultsResponse.text().catch(() => "");
      defaultRuleFetch.error = `HTTP ${defaultsResponse.status}: ${body.slice(0, 200)}`;
    } else {
      const defaultsData = await defaultsResponse.json();
      const defaults = Array.isArray(defaultsData)
        ? defaultsData
        : (defaultsData.results || defaultsData.rules || defaultsData.data || defaultsData.items || []);
      for (const raw of defaults) {
        const duplicate = allRules.some(rule => String(rule.id) === String(raw.ruleId || raw.id));
        if (!duplicate) allRules.push({
          id: raw.ruleId !== undefined ? raw.ruleId : raw.id,
          name: raw.ruleName || raw.name || "Unnamed Rule",
          order: typeof raw.rulePriority === "number" ? raw.rulePriority : parseInt(raw.rulePriority || raw.order || "0"),
          action: (raw.ruleAction || raw.action || "allow").toLowerCase(),
          enabled: raw.ruleIsEnabled !== false,
          is_default: true,
          sources: raw.sources || raw.source || ["any"],
          destinations: raw.destinations || raw.destination || ["any"],
          applications: raw.applications || raw.application || [],
          ports: raw.ports || raw.port || ["any"],
          protocol: raw.protocol || "any",
          trafficScope: raw.ruleAccess || null,
          conditions: Array.isArray(raw.ruleConditions) ? raw.ruleConditions : (Array.isArray(raw.conditions) ? raw.conditions : []),
          logging_enabled: (() => {
            const logLevel = (raw.ruleSettings || []).find(setting => setting.settingName === "umbrella.logLevel")?.settingValue;
            return logLevel === undefined ? true : logLevel !== "NONE";
          })(),
          security_profiles: (() => {
            const settings = raw.ruleSettings || [];
            const value = (name, alternatives = []) => {
              for (const key of [name, ...alternatives]) {
                const found = settings.find(setting => setting.settingName === key)?.settingValue;
                if (found !== undefined) return found;
              }
              return undefined;
            };
            const enabled = setting => setting !== undefined && setting !== null && setting !== "" && setting !== false && setting !== "DISABLED" && setting !== "NONE";
            return {
              ips_enabled: enabled(value("umbrella.posture.ipsProfileId", ["umbrella.security.ips", "ips_enabled"])),
              amp_malware_enabled: enabled(value("umbrella.posture.profileIdClientbased", ["umbrella.posture.profileIdClientless", "umbrella.security.amp", "amp_malware_enabled"])),
              tls_decryption_enabled: enabled(value("umbrella.posture.webProfileId", ["umbrella.security.tls", "tls_decryption_enabled"])),
              dlp_enabled: enabled(value("sse.tenantControlProfileId", ["umbrella.security.dlp", "dlp_enabled"])),
            };
          })(),
          raw,
        });
        defaultRuleFetch.loaded++;
      }
      if (defaultRuleFetch.loaded === 0) defaultRuleFetch.error = "Response contained no default rules";
    }
  } catch (err) {
    defaultRuleFetch.error = err.message;
  }
  if (defaultRuleFetch.error) {
    logEvent("rules-fetch", "Default-rule fetch failed", { url: defaultRuleUrl, error: defaultRuleFetch.error });
  }
  return { rules: allRules, defaultRuleFetch };
}

// ---------------------------------------------------------------------------
// compareRulePriority — sort comparator used everywhere rule evaluation
// order matters.
//
// Default/catch-all rules must always sort LAST, regardless of whatever
// rulePriority value the API assigns them — this is a policy invariant
// (defaults only apply when no custom rule matched), not something derived
// from the priority number, which may or may not even be meaningful for
// default rules (unverified — see fetchRules() note above).
// ---------------------------------------------------------------------------

function compareRulePriority(a, b) {
  if (a.is_default !== b.is_default) return a.is_default ? 1 : -1;
  return a.order - b.order;
}

// ---------------------------------------------------------------------------
// Check helpers
//
// BUG FIX (found investigating 13 false-positive conflicting-rules findings
// on org 8176184's real 33-rule set): the old versions of these helpers
// compared rule.sources/destinations/applications/ports/protocol — fields
// that only ever populate from mock-shaped payloads (fetchRules() always
// hits the live API now). The real Umbrella/SSE API expresses all rule scope
// through ruleConditions (normalized to rule.conditions below), so for every
// real rule those flat fields fell through their `|| ["any"]` / `|| []`
// fallbacks identically — every rule in an org looked like
// sources=["any"], destinations=["any"], applications=[], ports=["any"],
// protocol="any", regardless of its actual conditions. That made
// _matchCriteriaEqual() trivially true for every pair of real rules, so
// checkConflicts() degenerated into "flag every pair with different
// actions" — explaining exactly the "Enterprise Browser - HR Private App
// conflicts with 13 unrelated rules" symptom. checkShadowing()'s
// _isBroadOrEqual() and checkInspection()'s isBroad had the identical
// defect (always true).
//
// Fix: derive real per-dimension scope from rule.conditions itself, using
// the same source/destination/identity/app dimension split matcher.js uses
// for the Policy Tester (duplicated here, not shared — matcher.js's IIFE
// hardcodes `window`, which doesn't exist in this service worker context).
// Ports/protocol are dropped as a separate dimension: the real schema
// doesn't expose them as top-level fields either (they're bundled inside
// composite_inline_ip destination conditions per matcher.js's confirmed
// schema notes), so pretending to compare them separately would just
// reintroduce the same kind of fictional-field bug.
// ---------------------------------------------------------------------------

function _conditionDimension(attributeName) {
  const an = (attributeName || "").toLowerCase();
  if (an === "umbrella.source.all" || an === "umbrella.source.composite_inline_ip" || an.includes("umbrella.source.identity")) return "source";
  if (an.startsWith("umbrella.source.") && an.includes("networkobject")) return "source";
  if (an === "umbrella.destination.all" || an === "umbrella.destination.composite_inline_ip") return "destination";

  // HAR-confirmed destination attributes. They must be classified before the
  // generic app/category fallback, otherwise scope checks can compare unrelated
  // destinations as though they were equivalent.
  if (
    an.includes("private_resource") || an.includes("destination_list") ||
    an.includes("networkobject") || an.includes("serviceobjectgroup") ||
    an.includes("geolocation") || an.includes("application_ids") ||
    an.includes("application_list") || an.includes("category_ids") ||
    an.includes("category_list") || an.includes("appriskprofile")
  ) return "destination";

  if (an.includes("identity")) return "identity";
  if (an.includes("application") || an.includes("app") || an.includes("protocol") || an.includes("category")) return "app";
  return "unknown";
}

function _isCatchAllCondition(cond) {
  return cond.attributeValue === true && (cond.attributeName || "").toLowerCase().endsWith(".all");
}

function _bucketConditionsByDimension(rule) {
  const conds = rule.conditions || rule.ruleConditions || [];
  const buckets = { source: [], destination: [], identity: [], app: [], unknown: [] };
  for (const c of conds) buckets[_conditionDimension(c.attributeName)].push(c);
  return buckets;
}

// Stable, order-independent string form of a condition list, for equality
// comparisons — real APIs don't guarantee condition array order is
// meaningful, so two rules with the same conditions in a different order
// must still compare equal.
function _canonicalConditionSet(conds) {
  return JSON.stringify(
    [...conds]
      .map((c) => ({ n: c.attributeName, o: c.attributeOperator || "=", v: c.attributeValue }))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
  );
}

function _dimensionUnconstrained(conds) {
  return conds.length === 0 || (conds.length === 1 && _isCatchAllCondition(conds[0]));
}

// Used by checkShadowing: is `blocker`'s scope on this dimension broader
// than or equal to `rule`'s (i.e. blocker matches everything rule matches,
// on this one dimension)?
function _dimensionBroadOrEqual(blockerConds, ruleConds) {
  if (_dimensionUnconstrained(blockerConds)) return true;
  return _canonicalConditionSet(blockerConds) === _canonicalConditionSet(ruleConds);
}

// Used by checkShadowing: true only if blocker is broader-or-equal on
// EVERY dimension (source, destination, identity, app, unknown).
//
// BUG FIX (found investigating 6 false-positive conflicting-rules findings
// on "Geoblocking2", org 8176184): this used to only check source/
// destination/identity/app, silently skipping the "unknown" bucket — any
// condition type _conditionDimension() doesn't recognize (e.g.
// destination_list_ids before the fix above) landed in "unknown" and was
// never compared at all. Two rules with completely different unrecognized
// conditions (different destination list IDs, in Geoblocking2's case) both
// had empty source/destination/identity/app buckets, so they looked
// "identical" regardless of what their real (ignored) condition said —
// reproducing the exact same class of false positive the org 8176184
// investigation already fixed once, via a different mechanism. Comparing
// "unknown" too closes this gap generally, not just for destination_list_ids
// specifically — there will always be condition types _conditionDimension()
// doesn't yet recognize.
function _matchCriteriaBroadOrEqual(blocker, rule) {
  const bB = _bucketConditionsByDimension(blocker);
  const bR = _bucketConditionsByDimension(rule);
  return (
    _dimensionBroadOrEqual(bB.source, bR.source) &&
    _dimensionBroadOrEqual(bB.destination, bR.destination) &&
    _dimensionBroadOrEqual(bB.identity, bR.identity) &&
    _dimensionBroadOrEqual(bB.app, bR.app) &&
    _dimensionBroadOrEqual(bB.unknown, bR.unknown)
  );
}

// Used by checkConflicts: true only if a and b have IDENTICAL scope on
// EVERY dimension (including "unknown" — see the bug-fix comment above
// _matchCriteriaBroadOrEqual) — genuine overlap, not just "neither is
// unconstrained".
function _matchCriteriaEqual(a, b) {
  const bA = _bucketConditionsByDimension(a);
  const bB = _bucketConditionsByDimension(b);
  return (
    _canonicalConditionSet(bA.source) === _canonicalConditionSet(bB.source) &&
    _canonicalConditionSet(bA.destination) === _canonicalConditionSet(bB.destination) &&
    _canonicalConditionSet(bA.identity) === _canonicalConditionSet(bB.identity) &&
    _canonicalConditionSet(bA.app) === _canonicalConditionSet(bB.app) &&
    _canonicalConditionSet(bA.unknown) === _canonicalConditionSet(bB.unknown)
  );
}

function _fullyCriticalEqual(a, b) {
  return a.action === b.action && _matchCriteriaEqual(a, b);
}

// ---------------------------------------------------------------------------
// Check: permissive
// ---------------------------------------------------------------------------

function checkPermissive(rules) {
  const findings = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cisco's default access rule is an intentional scoped fallback, not a
    // customer-configured any-to-any policy finding.
    if (rule.is_default) continue;
    if (rule.action !== "allow") continue;
    const buckets = _bucketConditionsByDimension(rule);
    const conds = rule.conditions || rule.ruleConditions || [];
    const sourceUnconstrained = conds.length === 0 || _dimensionUnconstrained(buckets.source);
    const destinationUnconstrained = conds.length === 0 || _dimensionUnconstrained(buckets.destination);
    const identityUnconstrained = conds.length === 0 || _dimensionUnconstrained(buckets.identity);
    const appUnconstrained = conds.length === 0 || _dimensionUnconstrained(buckets.app);
    if (sourceUnconstrained && destinationUnconstrained && identityUnconstrained && appUnconstrained) {
      findings.push({
        checkId: "overly-permissive",
        severity: "critical",
        ruleId: rule.id,
        ruleName: rule.name,
        message: `Rule '${rule.name}' allows any-to-any traffic with no conditions.`,
        detail:
          "Sources, destinations, and applications are all unrestricted with no extra conditions. This rule permits all traffic.",
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check: shadowing
// ---------------------------------------------------------------------------

function checkShadowing(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];

  for (let i = 0; i < sorted.length; i++) {
    const rule = sorted[i];
    if (!rule.enabled) continue;
    // Default/catch-all rules are BY DESIGN only reached when nothing else
    // matched — being "shadowed" by any earlier custom rule with the same
    // action is the expected, intended behavior, not a policy mistake. Flag
    // it here would just be noise on every org that has any custom rules.
    if (rule.is_default) continue;

    for (let j = 0; j < i; j++) {
      const blocker = sorted[j];
      if (!blocker.enabled) continue;

      if (
        blocker.action === rule.action &&
        _matchCriteriaBroadOrEqual(blocker, rule)
      ) {
        findings.push({
          checkId: "shadowing",
          severity: "high",
          ruleId: rule.id,
          ruleName: rule.name,
          message: `Rule '${rule.name}' is shadowed by earlier rule '${blocker.name}' and will never be evaluated.`,
          detail: `Rule '${blocker.name}' (order ${blocker.order}) has broader or equal match criteria and the same action, so '${rule.name}' (order ${rule.order}) can never be reached first.`,
        });
        break;
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check: conflicts
// ---------------------------------------------------------------------------

function checkConflicts(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];

  for (let i = 0; i < sorted.length; i++) {
    const ruleA = sorted[i];
    if (!ruleA.enabled) continue;

    for (let j = i + 1; j < sorted.length; j++) {
      const ruleB = sorted[j];
      if (!ruleB.enabled) continue;
      // A custom rule differing in action from the org's default/catch-all
      // fallback (e.g. Block rule vs. the "All Internet access" - Allow
      // default) is normal, intended design — the specific rule is SUPPOSED
      // to override the broad default. Not a real policy conflict. Same
      // reasoning as the is_default guards in checkShadowing/checkDuplicates.
      if (ruleA.is_default || ruleB.is_default) continue;

      if (_matchCriteriaEqual(ruleA, ruleB) && ruleA.action !== ruleB.action) {
        findings.push({
          checkId: "conflicting-rules",
          severity: "high",
          ruleId: ruleA.id,
          ruleName: ruleA.name,
          message:
            "Rule conflicts with another rule that has the same match criteria but opposite action.",
          detail: `Rule '${ruleA.name}' (order ${ruleA.order}) has the same match criteria as '${ruleB.name}' (order ${ruleB.order}) but action '${ruleA.action}' vs '${ruleB.action}'.`,
        });
        findings.push({
          checkId: "conflicting-rules",
          severity: "high",
          ruleId: ruleB.id,
          ruleName: ruleB.name,
          message:
            "Rule conflicts with another rule that has the same match criteria but opposite action.",
          detail: `Rule '${ruleB.name}' (order ${ruleB.order}) has the same match criteria as '${ruleA.name}' (order ${ruleA.order}) but action '${ruleB.action}' vs '${ruleA.action}'.`,
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check: duplicates
// ---------------------------------------------------------------------------

function checkDuplicates(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];

  for (let i = 0; i < sorted.length; i++) {
    const ruleA = sorted[i];
    if (!ruleA.enabled) continue;

    for (let j = i + 1; j < sorted.length; j++) {
      const ruleB = sorted[j];
      if (!ruleB.enabled) continue;
      // A default rule "duplicating" a custom rule isn't a real duplicate-rule
      // problem — defaults are Cisco's fixed catch-all, not something the org
      // configured redundantly, and it will always sort after custom rules
      // (see compareRulePriority), so it never "wins" over a real duplicate.
      if (ruleB.is_default) continue;

      if (_fullyCriticalEqual(ruleA, ruleB)) {
        findings.push({
          checkId: "duplicate-rule",
          severity: "low",
          ruleId: ruleB.id,
          ruleName: ruleB.name,
          message:
            "Rule is an exact duplicate of an earlier rule and will never be reached first.",
          detail: `Rule '${ruleB.name}' (order ${ruleB.order}) is an exact duplicate of '${ruleA.name}' (order ${ruleA.order}). The earlier rule will always match first.`,
        });
      }
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check: logging
// ---------------------------------------------------------------------------

function checkLogging(rules) {
  const findings = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.logging_enabled === false) {
      findings.push({
        checkId: "logging-disabled",
        severity: "medium",
        ruleId: rule.id,
        ruleName: rule.name,
        message:
          "Rule has logging disabled — its traffic is invisible for audit and incident response.",
        detail: null,
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Check: inspection
// ---------------------------------------------------------------------------

function checkInspection(rules) {
  const findings = [];

  const profileKeys = [
    { field: "ips_enabled", label: "ips" },
    { field: "amp_malware_enabled", label: "amp_malware" },
    { field: "tls_decryption_enabled", label: "tls_decryption" },
    { field: "dlp_enabled", label: "dlp" },
  ];

  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.action !== "allow") continue;

    // Same fictional-field bug as checkConflicts/checkShadowing — real
    // scope must come from rule.conditions, not the mock-only sources/
    // destinations placeholder fields (see the big comment above
    // _conditionDimension).
    const buckets = _bucketConditionsByDimension(rule);
    const isBroad =
      _dimensionUnconstrained(buckets.source) || _dimensionUnconstrained(buckets.destination);
    if (!isBroad) continue;

    const sp = rule.security_profiles || {};
    const missing = profileKeys
      .filter(({ field }) => sp[field] === false)
      .map(({ label }) => label);

    if (missing.length > 0) {
      findings.push({
        checkId: "inspection-bypass",
        severity: "high",
        ruleId: rule.id,
        ruleName: rule.name,
        message: `Rule bypasses security inspection. Missing: ${missing.join(", ")}`,
        detail: `Rule '${rule.name}' has broad match criteria (any source or destination) but the following inspection profiles are disabled: ${missing.join(", ")}.`,
      });
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Engine: run all checks
// ---------------------------------------------------------------------------

function runChecks(rules) {
  const sorted = [...rules].sort(compareRulePriority);

  const findings = [
    ...checkPermissive(sorted),
    ...checkShadowing(sorted),
    ...checkConflicts(sorted),
    ...checkDuplicates(sorted),
    ...checkLogging(sorted),
    ...checkInspection(sorted),
  ];

  return findings;
}

// ---------------------------------------------------------------------------
// getFreshToken — used by RUN_SCAN and resolveIdentities(). Returns the
// stored token object for the given tokenKey if it's present and within
// that token's own TOKEN_REGISTRY maxAgeMs. If missing/stale, asks the
// active tab's content/token-relay.js for the MAIN-world patch's last-seen
// token for that specific tokenKey (REQUEST_TOKEN_CHECK) before giving up —
// covers the case where a request fired very recently but the
// postMessage->sendMessage->storage chain hasn't finished propagating yet.
// Returns null if nothing valid is found.
// ---------------------------------------------------------------------------

async function getFreshToken(tokenKey, tabId) {
  const maxAgeMs = (TOKEN_REGISTRY[tokenKey] || TOKEN_REGISTRY.sse_token).maxAgeMs;
  // Read from local storage (tokens survive SW restarts). storeToken() was
  // changed to use storage.local for the same reason — see storeToken().
  const result = await api.storage.local.get(tokenKey);
  const stored = result[tokenKey]; // { token, capturedAt, source } | undefined
  const now = Date.now();
  const isStale = !stored || (now - stored.capturedAt) > maxAgeMs;

  if (!isStale) return stored;

  logEvent("token-check", "Stored token missing/stale — trying proactive fetch", {
    tokenKey, hadStored: !!stored, ageMs: stored ? now - stored.capturedAt : null, tabId,
  });

  if (!tabId) return null;

  // Phase 1: try passive on-demand check first (fast path — maybe the
  // MAIN-world patch already saw this token recently and we just haven't
  // propagated it yet).
  try {
    const reply = await api.tabs.sendMessage(tabId, { type: "REQUEST_TOKEN_CHECK", tokenKey });
    if (reply && reply.token) {
      await storeToken(tokenKey, reply.token, "main-world-patch", reply.capturedAt || now, { url: "on-demand-check" });
      const refreshed = await api.storage.local.get(tokenKey);
      return refreshed[tokenKey];
    }
    logEvent("token-check", "On-demand check returned no token", { tokenKey, tabId });
  } catch (err) {
    logEvent("token-check", "REQUEST_TOKEN_CHECK failed", { tokenKey, error: err.message, tabId });
  }

  // Phase 2: proactive fetch — ask the MAIN-world script to scan the page's
  // sessionStorage/localStorage for cached JWT tokens matching this tokenKey.
  // Uses the same tab.sendMessage + token-relay.js postMessage mechanism
  // as REQUEST_TOKEN_CHECK, but now carries a PROACTIVE_FETCH_TOKEN type.
  try {
    const reply = await api.tabs.sendMessage(tabId, { type: "PROACTIVE_FETCH_TOKEN", tokenKey });
    if (reply && reply.token) {
      await storeToken(tokenKey, reply.token, "main-world-patch", reply.capturedAt || Date.now(), { url: "proactive-fetch" });
      const refreshed = await api.storage.local.get(tokenKey);
      return refreshed[tokenKey];
    }
    logEvent("token-check", "Proactive fetch returned no token", { tokenKey, error: reply?.error });
  } catch (err) {
    logEvent("token-check", "PROACTIVE_FETCH_TOKEN failed", { tokenKey, error: err.message, tabId });
  }

  return null;
}

// ---------------------------------------------------------------------------
// Identity resolution — resolves rule.ruleConditions'
// umbrella.source.identity_ids numeric IDs into human-readable names.
//
// Confirmed live against org 8176184: Cisco's own dashboard batches every
// identity ID visible on the Access Policy page into ONE request per type
// below, and keeps whatever each endpoint actually matches — e.g.
// security_group_tag returned {total:0,data:[]} for a 5-ID batch that
// catalyst_sdwan matched 1 of the same 5 IDs on. This replicates that same
// "ask every known type, merge whatever comes back" strategy rather than
// trying to pre-classify an ID's type ourselves (which we can't do reliably
// from the rule condition alone).
//
// Real captured request shapes (not guessed):
//   security_group_tag / catalyst_sdwan:
//     GET https://management.api.umbrella.com/identity/v2/organizations/{orgId}/all_tag_identities/{type}?id=1,2,3
//     -> { total, limit, offset, data: [{ id, label, typeId, ... }] }
//     Both types share ONE token: mgmt_authz_token (issuer
//     "umbrella-authz/authsvc", scope "role:root-readonly", ~5min TTL).
//   internalnetworks:
//     GET https://api.opendns.com/v3/organizations/{orgId}/internalnetworks?filters={"label":"%%%"}&page=1&limit=500
//     -> [{ originId, label, ... }, ...]  (top-level array, NOT wrapped in
//     {data:...} like the other three)
//     Does NOT support filtering by id batch like the others — Cisco's own
//     frontend fetches up to 500 with a wildcard label filter and matches
//     originId client-side, so that's what this does too. Uses
//     opendns_token (aud "https://api.opendns.com/v3/", only ~60s TTL).
//   networkTunnelGroupsAndBranches (branch/tunnel identities, private-access
//   rules):
//     GET https://api.sse.cisco.com/deployments/v2/msa/networkTunnelGroupsAndBranches?offset=0&limit=100&filters={"ids":[1,2,3]}
//     -> { data: [{ id, name, type: "Branch"|"Network Tunnel Group", ... }] }
//     Reuses the existing sse_token — no new host/token needed for this one.
// ---------------------------------------------------------------------------

const IDENTITY_ENDPOINTS = [
  {
    name: "security_group_tag",
    tokenKey: "mgmt_authz_token",
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/all_tag_identities/security_group_tag?id=${ids.join(",")}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.label, typeId: e.typeId })),
  },
  {
    name: "catalyst_sdwan",
    tokenKey: "mgmt_authz_token",
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/all_tag_identities/catalyst_sdwan?id=${ids.join(",")}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.label, typeId: e.typeId })),
  },
  {
    name: "internalnetworks",
    tokenKey: "opendns_token",
    buildUrl: (orgId) =>
      `https://api.opendns.com/v3/organizations/${orgId}/internalnetworks?filters=${encodeURIComponent(
        JSON.stringify({ label: "%%%" })
      )}&page=1&limit=500`,
    parse: (json, ids) => {
      const idSet = new Set(ids.map(String));
      return (Array.isArray(json) ? json : [])
        .filter((e) => idSet.has(String(e.originId)))
        .map((e) => ({ id: e.originId, name: e.label }));
    },
  },
  {
    name: "networkTunnelGroupsAndBranches",
    tokenKey: "sse_token",
    buildUrl: (orgId, ids) =>
      `https://api.sse.cisco.com/deployments/v2/msa/networkTunnelGroupsAndBranches?offset=0&limit=100&filters=${encodeURIComponent(
        JSON.stringify({ ids })
      )}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.name })),
  },
  {
    name: "active_directory",
    tokenKey: "mgmt_authz_token",
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/all_tag_identities/active_directory?id=${ids.join(",")}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.label, typeId: e.typeId })),
  },
  {
    name: "saml",
    tokenKey: "mgmt_authz_token",
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/all_tag_identities/saml?id=${ids.join(",")}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.label, typeId: e.typeId })),
  },
  {
    name: "azure_ad",
    tokenKey: "mgmt_authz_token",
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/all_tag_identities/azure_ad?id=${ids.join(",")}`,
    parse: (json) => (Array.isArray(json && json.data) ? json.data : []).map((e) => ({ id: e.id, name: e.label, typeId: e.typeId })),
  },
  {
    name: "identity_search",
    tokenKey: "mgmt_authz_token",
    // CONFIRMED via CDP intercept: dashboard uses ?id= with specific IDs.
    // Handles arrays, { data: [...] }, { items: [...] }, and direct ID-keyed maps.
    buildUrl: (orgId, ids) =>
      `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/search?id=${ids.join(",")}`,
    parse: (json, ids) => {
      if (!json) return [];
      // Helper: extract id and name from a single entry, checking all known field names
      const extract = (e) => {
        if (!e || typeof e !== "object") return null;
        // ID fields: originId is the primary key in /search responses, id is secondary
        const id = e.originId !== undefined ? e.originId : (e.id !== undefined ? e.id : null);
        // Name fields: label is primary, name/friendlyName are fallbacks
        const name = e.label || e.name || e.friendlyName || e.displayName || null;
        if (id !== null && id !== undefined && name) {
          return { id: String(id), name, typeId: e.typeId };
        }
        return null;
      };
      if (Array.isArray(json)) {
        return json.map(extract).filter(Boolean);
      }
      if (Array.isArray(json.data)) {
        return json.data.map(extract).filter(Boolean);
      }
      if (Array.isArray(json.items)) {
        return json.items.map(extract).filter(Boolean);
      }
      if (typeof json === "object") {
        const entries = [];
        for (const [key, val] of Object.entries(json)) {
          if (val && typeof val === "object") {
            const name = val.label || val.name || val.friendlyName || val.displayName;
            if (name) entries.push({ id: key, name, typeId: val.typeId });
          } else if (typeof val === "string") {
            entries.push({ id: key, name: val });
          }
        }
        return entries;
      }
      return [];
    },
  },
];

function collectIdentityIds(rules) {
  const ids = new Set();
  for (const rule of rules || []) {
    const conds = rule.ruleConditions || rule.conditions || [];
    if (!Array.isArray(conds)) continue;
    for (const c of conds) {
      const attr = (c.attributeName || "").toLowerCase();
      if (attr !== "umbrella.source.identity_ids" && attr !== "umbrella.source.identity_ids_shared") continue;
      const values = c.attributeValue;
      if (Array.isArray(values)) {
        values.forEach((v) => ids.add(v));
      } else if (values !== undefined && values !== null) {
        ids.add(values);
      }
    }
  }
  return Array.from(ids);
}

// Resolves identity IDs and a supplementary identityId → typeId bridge. Search
// responses carry typeId, so this remains accurate when a paginated source
// catalog is unavailable or incomplete.
async function resolveIdentities(rules, orgId, tabId) {
  const ids = collectIdentityIds(rules);
  if (ids.length === 0) return { names: {}, typeIds: {} };

  const names = {};
  const typeIds = {};
  await Promise.all(
    IDENTITY_ENDPOINTS.map(async (endpoint) => {
      try {
        const tokenObj = await getFreshToken(endpoint.tokenKey, tabId);
        if (!tokenObj) {
          logEvent("identity-resolve", "Skipped endpoint — no fresh token", {
            endpoint: endpoint.name, tokenKey: endpoint.tokenKey,
          });
          return;
        }
        const url = endpoint.buildUrl(orgId, ids);
        const response = await fetch(url, {
          headers: {
            Authorization: `Bearer ${tokenObj.token}`,
            Accept: "application/json",
            Origin: "https://dashboard.sse.cisco.com",
            Referer: "https://dashboard.sse.cisco.com/",
          },
        });
        if (!response.ok) {
          logEvent("identity-resolve", "Endpoint returned non-OK status", {
            endpoint: endpoint.name, status: response.status,
          });
          return;
        }
        const text = await response.text();
        let json;
        try {
          json = JSON.parse(text);
        } catch (_) {
          logEvent("identity-resolve", "Endpoint non-JSON response", { endpoint: endpoint.name });
          return;
        }
        const entries = endpoint.parse(json, ids);
        // Each endpoint may resolve different identity families. Preserve a type
        // link already supplied by a family-specific result instead of replacing
        // it with an empty/missing value from a broader fallback.
        for (const e of entries) {
          if (e && e.id !== undefined && e.name) names[String(e.id)] = e.name;
          if (e && e.id !== undefined && e.typeId !== undefined && e.typeId !== null && typeIds[String(e.id)] === undefined) {
            typeIds[String(e.id)] = e.typeId;
          }
        }
        logEvent("identity-resolve", "Endpoint resolved", { endpoint: endpoint.name, matched: entries.length });
      } catch (err) {
        logEvent("identity-resolve", "Endpoint fetch failed", { endpoint: endpoint.name, error: err.message });
      }
    })
  );

  return { names, typeIds };
}

// Resolves identity types (typeId → type name) using the /search?id= endpoint.
// CONFIRMED via CDP intercept + direct test: /search?id=... returns entries
// with both typeId and type fields. The /containers endpoint only returns
// container-level types (3,5,7) but rules reference many more typeIds (34,36,38,50,57,etc).
async function resolveIdentityTypes(orgId, tabId, rules) {
  const typeMap = {};
  
  try {
    const tokenObj = await getFreshToken("mgmt_authz_token", tabId);
    if (!tokenObj) {
      logEvent("identity-type-resolve", "No mgmt_authz_token available");
      return typeMap;
    }
    
    // Always call /containers to get the full typeId → label mapping.
    // This is the same endpoint the dashboard uses. CONFIRMED via CDP
    // intercept: dashboard GETs /containers with 200 and extracts all type
    // info. The /search?id= approach only returns types of SPECIFIC identity
    // IDs searched, missing typeIds referenced directly in rule conditions
    // (e.g. umbrella.source.identity_type_ids = [34,36,38,50,57]).
    //
    // CRITICAL: The /containers endpoint returns 403 without Origin/Referer
    // headers. Adding these (dashboard origin) makes it work from the SW
    // context — confirmed by live test returning 16 type entries.
    const containersUrl = `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/containers?offset=0&limit=100`;
    const resp = await fetch(containersUrl, {
      headers: {
        Authorization: `Bearer ${tokenObj.token}`,
        Accept: "application/json",
        Origin: "https://dashboard.sse.cisco.com",
        Referer: "https://dashboard.sse.cisco.com/",
      },
    });
    if (resp.ok) {
      const json = await resp.json();
      for (const entry of (json.data || [])) {
        if (entry.typeId !== undefined && entry.label) {
          typeMap[entry.typeId] = entry.label;
        }
      }
    } else {
      logEvent("identity-type-resolve", "Containers returned non-OK", { status: resp.status });
      // Fallback: try /search?id= for partial coverage from identity IDs
      const ids = collectIdentityIds(rules);
      if (ids.length > 0) {
        const url = `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/search?id=${ids.join(",")}`;
        const searchResp = await fetch(url, {
          headers: { Authorization: `Bearer ${tokenObj.token}`, Accept: "application/json" },
        });
        if (searchResp.ok) {
          const searchJson = await searchResp.json();
          for (const entry of (searchJson.data || [])) {
            if (entry.typeId !== undefined && entry.type) {
              typeMap[entry.typeId] = entry.type;
            }
          }
        }
      }
    }
    
    logEvent("identity-type-resolve", "Resolved identity types from /containers", { count: Object.keys(typeMap).length });
  } catch (err) {
    logEvent("identity-type-resolve", "Failed to resolve identity types", { error: err.message });
  }
  
  // --- Hardcoded fallback for Cisco-known identity types not in /containers ---
  // The /containers endpoint only returns types for identities the org actually
  // has, but rules can reference typeIds that are Cisco-defined platform types
  // not present in any org. These are documented in Cisco Secure Access and
  // confirmed by the dashboard panel labels.
  const HARDCODED_TYPE_NAMES = {
    34: "Posture",
    50: "Endpoint Requirements",
    // Common Cisco identity type IDs — add more as discovered
    12: "IP Range",
    15: "Secure Client",
    16: "AnyConnect",
  };
  
  // Collect all typeIds referenced by rules
  const referencedTypeIds = new Set();
  for (const rule of rules) {
    const conds = rule.ruleConditions || rule.conditions || [];
    for (const cond of conds) {
      // Format 1: direct arrays (e.g. identityTypeIds / identity_type_ids)
      if (cond.identityTypeIds) {
        for (const id of cond.identityTypeIds) referencedTypeIds.add(id);
      }
      if (cond.identity_type_ids) {
        for (const id of cond.identity_type_ids) referencedTypeIds.add(id);
      }
      // Format 2: rule condition objects with attributeName/attributeValue
      if (cond.attributeName === "umbrella.source.identity_type_ids" &&
          Array.isArray(cond.attributeValue)) {
        for (const id of cond.attributeValue) referencedTypeIds.add(id);
      }
    }
  }
  
  // Fill in missing types from hardcoded map
  let fallbackCount = 0;
  for (const tid of referencedTypeIds) {
    if (!typeMap[tid] && HARDCODED_TYPE_NAMES[tid]) {
      typeMap[tid] = HARDCODED_TYPE_NAMES[tid];
      fallbackCount++;
    }
  }
  if (fallbackCount > 0) {
    logEvent("identity-type-resolve", `Applied ${fallbackCount} hardcoded fallback type name(s)`);
  }
  
  return typeMap;
}

// ---------------------------------------------------------------------------
// Destination-object resolution — private_resource_ids /
// private_resource_group_ids (Private Access rule destinations). Kept as a
// SEPARATE map from identityMap, not merged into it — both are just numeric
// IDs from unrelated ID spaces (an identity ID and a private-resource-group
// ID could easily collide on the same number), so merging them into one
// flat { id: name } map risks one silently overwriting the other.
//
// Real captured request/response shapes (org 8176184, not guessed):
//   GET https://api.umbrella.com/v1/organizations/{orgId}/private_resources?offset=0&limit=1000&sortBy=name&sortOrder=asc
//     -> { items: [{ resourceId, name, friendlyName, ... }], offset, limit, total }
//   GET https://api.umbrella.com/v1/organizations/{orgId}/private_resource_groups?offset=0&limit=1000&sortBy=name&sortOrder=asc
//     -> { items: [{ resourceGroupId, name, description, resourceIds, ... }], offset, limit, total }
// Both reuse the existing sse_token (same host as fetchRules) — no new
// token/audience needed, unlike the identity endpoints.
//
// Unlike the identity endpoints (which need a targeted ID batch query),
// these support no id-filter that's confirmed reliable, and the org-wide
// list is small (14 resources / 3 groups on org 8176184) — so this always
// fetches the FULL unfiltered list rather than pre-collecting which IDs are
// actually referenced. Simpler, and covers every rule's references at once
// regardless of which specific rule triggered the scan.
//
// networkObjectIds / serviceObjectGroupIds are classified as destination-
// dimension too (see matcher.js's conditionDimension()) but are NOT
// resolved here yet — their real endpoint response shapes haven't been
// confirmed live. They still fall back to summarizeConditions()'s generic
// humanized-fallback text with the raw ID visible, same as before.
// ---------------------------------------------------------------------------

const OBJECT_ENDPOINTS = [
  {
    name: "private_resources",
    tokenKey: "sse_token",
    buildUrl: (orgId) =>
      `https://api.umbrella.com/v1/organizations/${orgId}/private_resources?offset=0&limit=1000&sortBy=name&sortOrder=asc`,
    parse: (json) =>
      (Array.isArray(json && json.items) ? json.items : []).map((e) => ({
        id: e.resourceId,
        name: e.name || e.friendlyName,
      })),
  },
  {
    name: "private_resource_groups",
    tokenKey: "sse_token",
    buildUrl: (orgId) =>
      `https://api.umbrella.com/v1/organizations/${orgId}/private_resource_groups?offset=0&limit=1000&sortBy=name&sortOrder=asc`,
    parse: (json) =>
      (Array.isArray(json && json.items) ? json.items : []).map((e) => ({
        id: e.resourceGroupId,
        name: e.name,
      })),
  },
  {
    name: "destination_lists",
    tokenKey: "opendns_token",
    // HAR-confirmed catalog request: this org has 13 destination lists, so
    // fetch the complete small catalog. This avoids a failed/partial targeted
    // response leaving a policy hover with only an opaque numeric list ID.
    buildUrl: (orgId) =>
      `https://api.opendns.com/v3/organizations/${orgId}/destinationlists?sort=%7B%22name%22%3A%22asc%22%2C%22createdAt%22%3A%22desc%22%7D&outputFormat=jsonHttpStatusOverride&page=1&limit=100&filters=%7B%22bundleTypeId%22%3A%5B2%5D%7D`,
    parse: (json) => {
      // HAR-confirmed list response is { status, meta, data: [...] }. The
      // dashboard's targeted form can use other wrappers, so retain those as
      // fallbacks instead of treating a successful catalog response as empty.
      const items = Array.isArray(json) ? json : (json?.data || json?.items || []);
      return items.map((e) => ({ id: e.id, name: e.name }));
    },
  },
  {
    name: "network_objects",
    tokenKey: "sse_token",
    // CONFIRMED via CDP: endpoint returns 400 without ?ids=
    buildUrl: (orgId, ids) => {
      if (ids && ids.length > 0) {
        return `https://api.sse.cisco.com/policies/v2/objects/networkObjects?ids=${ids.join(",")}`;
      }
      return `https://api.sse.cisco.com/policies/v2/objects/networkObjects?offset=0&limit=100`;
    },
    parse: (json) => {
      const items = Array.isArray(json) ? json : (json?.results || json?.data || []);
      return items.map((e) => ({ id: e.id, name: e.name }));
    },
  },
  {
    name: "network_object_groups",
    tokenKey: "sse_token",
    // CONFIRMED via CDP: dashboard queries networkObjectGroups
    buildUrl: (orgId, ids) => {
      if (ids && ids.length > 0) {
        return `https://api.sse.cisco.com/policies/v2/objects/networkObjectGroups?ids=${ids.join(",")}`;
      }
      return `https://api.sse.cisco.com/policies/v2/objects/networkObjectGroups?offset=0&limit=100`;
    },
    parse: (json) => {
      const items = Array.isArray(json) ? json : (json?.results || json?.data || []);
      return items.map((e) => ({ id: e.id, name: e.name }));
    },
  },
  {
    name: "service_objects",
    tokenKey: "sse_token",
    // CONFIRMED via CDP: dashboard queries serviceObjects
    buildUrl: (orgId, ids) => {
      if (ids && ids.length > 0) {
        return `https://api.sse.cisco.com/policies/v2/objects/serviceObjects?ids=${ids.join(",")}`;
      }
      return `https://api.sse.cisco.com/policies/v2/objects/serviceObjects?offset=0&limit=100`;
    },
    parse: (json) => {
      const items = Array.isArray(json) ? json : (json?.results || json?.data || []);
      return items.map((e) => ({ id: e.id, name: e.name }));
    },
  },
  {
    name: "service_object_groups",
    tokenKey: "sse_token",
    // CONFIRMED via CDP: endpoint returns 400 without ?ids=
    buildUrl: (orgId, ids) => {
      if (ids && ids.length > 0) {
        return `https://api.sse.cisco.com/policies/v2/objects/serviceObjectGroups?ids=${ids.join(",")}`;
      }
      return `https://api.sse.cisco.com/policies/v2/objects/serviceObjectGroups?offset=0&limit=100`;
    },
    parse: (json) => {
      const items = Array.isArray(json) ? json : (json?.results || json?.data || []);
      return items.map((e) => ({ id: e.id, name: e.name }));
    },
  },
  {
    name: "application_lists",
    tokenKey: "sse_token",
    buildUrl: (orgId) =>
      `https://api.umbrella.com/v1/organizations/${orgId}/application_lists`,
    parse: (json) => {
      // CONFIRMED: response is { applicationLists: [...] } with
      // applicationListId / applicationListName, NOT { items: [...] }
      const items = json?.applicationLists || json?.items || json?.data || [];
      return items.map((e) => ({
        id: e.applicationListId || e.id,
        name: e.applicationListName || e.name,
      }));
    },
  },
  {
    name: "category_lists",
    tokenKey: "opendns_token",
    // CONFIRMED via CDP intercept: dashboard uses /categorysettings, NOT
    // /categorylists (which returns 405). Response wraps data in { status, data }.
    buildUrl: (orgId) =>
      `https://api.opendns.com/v3/organizations/${orgId}/categorysettings?sort=%7B%20%22name%22%3A%20%22asc%22%2C%20%22createdAt%22%3A%20%22desc%22%20%7D&outputFormat=jsonHttpStatusOverride&filters=%7B%7D`,
    parse: (json) => {
      // Response shape: { status: {...}, data: [...] } or array or { items: [...] }
      const raw = json?.data || (Array.isArray(json) ? json : json?.items || []);
      const items = Array.isArray(raw) ? raw : [];
      return items.map((e) => ({
        id: e.categorySettingId || e.id,
        name: e.categorySettingName || e.name,
      }));
    },
  },
  {
    name: "app_risk_profiles",
    tokenKey: "mgmt_authz_token",
    // DISCOVERED via CDP network interception of dashboard: the dashboard SPA
    // calls this internal endpoint to resolve App Risk Profile UUIDs to names.
    // Response is base64-encoded JSON: {"items":[{"app_risk_profile_id":"uuid",
    // "app_risk_profile_name":"name",...}]}. Requires mgmt_authz_token.
    buildUrl: () =>
      "https://management.api.umbrella.com/policies.us/v2/appRiskProfileManager/appRiskProfiles",
    parse: (json) => {
      // Response may be base64-encoded; the items array has UUID-keyed profiles
      let data = json;
      if (typeof json === "string") {
        try { data = JSON.parse(atob(json)); } catch (e) { data = json; }
      }
      const items = data?.items || [];
      return items.map((e) => ({
        id: e.app_risk_profile_id || e.id,
        name: e.app_risk_profile_name || e.name,
      }));
    },
  },
  {
    name: "posture_profiles",
    tokenKey: "sse_token",
    buildUrl: (orgId) =>
      `https://api.umbrella.com/v1/organizations/${orgId}/postureprofiles`,
    parse: (json) => {
      // HAR response: { resources: [{ resourceInstanceId,
      // resourceInstanceName, postureProfile, ... }] }. Keep the alternate
      // wrappers only as compatibility fallbacks.
      const items = Array.isArray(json) ? json : (json?.resources || json?.items || json?.data || []);
      return items.map((e) => ({
        id: e.resourceInstanceId || e.postureProfileId || e.id,
        name: e.resourceInstanceName || e.postureProfileName || e.name,
      }));
    },
  },
];
// Collect all object IDs referenced in rule conditions, grouped by type.
// These are needed by endpoints that require ?ids= parameters (networkObjects,
// serviceObjectGroups, etc.)
function collectObjectIds(rules) {
  const result = {
    networkObjects: new Set(),
    networkObjectGroups: new Set(),
    serviceObjects: new Set(),
    serviceObjectGroups: new Set(),
    destinationLists: new Set(),
    applicationLists: new Set(),
    categoryLists: new Set(),
  };
  
  for (const rule of rules || []) {
    const conds = rule.conditions || rule.ruleConditions || [];
    if (!Array.isArray(conds)) continue;
    for (const c of conds) {
      const name = (c.attributeName || "").toLowerCase();
      const values = Array.isArray(c.attributeValue) ? c.attributeValue : [c.attributeValue];
      // Match both snake_case and camelCase attribute names
      if ((name.includes("network_object") || name.includes("networkobject")) && !name.includes("group")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.networkObjects.add(String(v)); });
      }
      if (name.includes("network_object_group") || name.includes("networkobjectgroup")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.networkObjectGroups.add(String(v)); });
      }
      if ((name.includes("service_object") || name.includes("serviceobject")) && !name.includes("group")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.serviceObjects.add(String(v)); });
      }
      if (name.includes("service_object_group") || name.includes("serviceobjectgroup")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.serviceObjectGroups.add(String(v)); });
      }
      if (name.includes("destination_list")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.destinationLists.add(String(v)); });
      }
      if (name.includes("application_list")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.applicationLists.add(String(v)); });
      }
      if (name.includes("category_list")) {
        values.forEach(v => { if (v && v !== "*" && String(v) !== "any") result.categoryLists.add(String(v)); });
      }
    }
  }
  
  // Convert Sets to Arrays
  for (const key of Object.keys(result)) {
    result[key] = Array.from(result[key]);
  }
  return result;
}

// Resolves all destination object references into separate maps by type.
// Returns { privateResources, destinationLists, networkObjects, serviceObjectGroups, applicationLists, categoryLists }
// Each map is { [id]: name }. Best-effort per endpoint — a skipped/failed
// endpoint just leaves those IDs unresolved ("[unknown ...]" in the UI)
// rather than sinking the whole scan.
async function resolveObjectRefs(orgId, tabId, rules) {
  // Collect IDs referenced in rules so endpoints that require ?ids= get them
  const refIds = collectObjectIds(rules);
  
  const maps = {
    privateResources: {},
    privateResourceGroups: {},
    destinationLists: {},
    networkObjects: {},
    networkObjectGroups: {},
    serviceObjects: {},
    serviceObjectGroups: {},
    applicationLists: {},
    categoryLists: {},
    appRiskProfiles: {},
    postureProfiles: {},
  };
  
  await Promise.all(
    OBJECT_ENDPOINTS.map(async (endpoint) => {
      try {
        const tokenObj = await getFreshToken(endpoint.tokenKey, tabId);
        if (!tokenObj) {
          logEvent("object-resolve", "Skipped endpoint — no fresh token", {
            endpoint: endpoint.name, tokenKey: endpoint.tokenKey,
          });
          return;
        }
        // Pass collected IDs to buildUrl (endpoints that need ?ids= will use them)
        // Map endpoint names to the refIds keys from collectObjectIds
        const idKeyMap = {
          "destination_lists": "destinationLists",
          "network_objects": "networkObjects",
          "network_object_groups": "networkObjectGroups",
          "service_objects": "serviceObjects",
          "service_object_groups": "serviceObjectGroups",
          "application_lists": "applicationLists",
          "category_lists": "categoryLists",
        };
        const ids = refIds[idKeyMap[endpoint.name]] || [];
        const url = endpoint.buildUrl(orgId, ids);
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${tokenObj.token}`, Accept: "application/json" },
        });
        if (!response.ok) {
          logEvent("object-resolve", "Endpoint returned non-OK status", {
            endpoint: endpoint.name, status: response.status,
          });
          return;
        }
        const json = await response.json();
        const entries = endpoint.parse(json);
        
        // Populate the appropriate map based on endpoint name
        const mapKey =
          endpoint.name === "private_resources" ? "privateResources" :
          endpoint.name === "private_resource_groups" ? "privateResourceGroups" :
          endpoint.name === "destination_lists" ? "destinationLists" :
          endpoint.name === "network_objects" ? "networkObjects" :
          endpoint.name === "network_object_groups" ? "networkObjectGroups" :
          endpoint.name === "service_objects" ? "serviceObjects" :
          endpoint.name === "service_object_groups" ? "serviceObjectGroups" :
          endpoint.name === "application_lists" ? "applicationLists" :
          endpoint.name === "category_lists" ? "categoryLists" :
          endpoint.name === "app_risk_profiles" ? "appRiskProfiles" :
          endpoint.name === "posture_profiles" ? "postureProfiles" :
          null;
        
        if (mapKey && maps[mapKey]) {
          for (const e of entries) {
            if (e && e.id !== undefined && e.name) {
              maps[mapKey][String(e.id)] = e.name;
            }
          }
        }
        
        logEvent("object-resolve", "Endpoint resolved", { endpoint: endpoint.name, count: entries.length });
      } catch (err) {
        logEvent("object-resolve", "Endpoint fetch failed", { endpoint: endpoint.name, error: err.message });
      }
    })
  );

  return maps;
}

// ---------------------------------------------------------------------------
// Full source/destination catalog fetches. These endpoints and payloads were
// captured from the Cisco dashboard HAR while opening its rule builder.
// Entries are kept in separate maps so numeric IDs from different namespaces
// cannot collide. Unsupported dashboard categories are intentionally omitted
// until their endpoint has been observed; we never guess endpoint paths.
// ---------------------------------------------------------------------------
const FULL_CATALOGS = [
  { key: "sourceUsers", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/directory_user", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 7 },
  { key: "sourceRoaming", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/roaming", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 9 },
  { key: "sourceGroups", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/directory_group", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 3 },
  { key: "sourceEndpointDevices", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/directory_computer", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 5 },
  { key: "sourceNetworks", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/network", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 1 },
  { key: "sourceSites", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/site", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 21 },
  { key: "sourceSecurityGroupTags", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/security_group_tag", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 54 },
  { key: "sourceCatalystSdwan", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/catalyst_sdwan", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 52 },
  { key: "sourceTunnelGroups", tokenKey: "sse_token", host: "https://api.sse.cisco.com", path: "deployments/v2/msa/networkTunnelGroupsAndBranches?limit=100&offset=0&sortBy=name&sortOrder=asc", dataKey: "data", idKey: "id", labelKey: "name", sourcePolicyTypeId: 40, mapEntries: (items) => items.filter(entry => entry.type === "Network Tunnel Group").map(entry => ({ id: entry.id, label: entry.name })) },
  // The same response lists SD-WAN branches (e.g. "RTP Campus vMX"). Activity
  // Search logs them as "Branches" and rules match them by identity ID and by
  // the Network Tunnels type (40), so they are their own source catalog.
  { key: "sourceBranches", tokenKey: "sse_token", host: "https://api.sse.cisco.com", path: "deployments/v2/msa/networkTunnelGroupsAndBranches?limit=100&offset=0&sortBy=name&sortOrder=asc", dataKey: "data", idKey: "id", labelKey: "name", sourcePolicyTypeId: 40, mapEntries: (items) => items.filter(entry => entry.type !== "Network Tunnel Group").map(entry => ({ id: entry.id, label: entry.name })) },
  // Network/service objects were captured only as destination conditions.
  // The identity container response supplies these child URLs and type IDs;
  // load them so every dashboard source category has a real catalog state.
  { key: "sourceNetworkDevices", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/network_device", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 32 },
  { key: "sourceMobileDevices", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/mobile_device", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 36 },
  { key: "sourceChromebooks", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/chromebook_user", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 38 },
  { key: "sourceZtnaClients", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/ztna_client", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 57 },
  { key: "sourceGsuiteUsers", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/gsuite_user", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 43 },
  { key: "sourceGsuiteOus", tokenKey: "mgmt_authz_token", path: "identity/v2/organizations/{orgId}/gsuite_group", dataKey: "data", idKey: "id", labelKey: "label", paged: true, sourcePolicyTypeId: 45 },
  { key: "applications", tokenKey: "opendns_token", path: "v3/organizations/{orgId}/applications?outputFormat=jsonHttpStatusOverride", dataKey: "data", idKey: "id", labelKey: "name" },
  { key: "enterpriseApplications", tokenKey: "opendns_token", path: "v3/organizations/{orgId}/enterpriseapplications", dataKey: "data", idKey: "id", labelKey: "name" },
  { key: "applicationCategories", tokenKey: "opendns_token", path: "v3/organizations/{orgId}/applicationcategories?optionalFields=%5B%22applicationsCount%22%5D&outputFormat=jsonHttpStatusOverride", dataKey: "data", idKey: "id", labelKey: "name" },
  { key: "contentCategories", tokenKey: "opendns_token", path: "v3/categories?sort=%7B%22name%22%3A%22asc%22%2C%22createdAt%22%3A%22desc%22%7D&filters=%7B%22CategoryTypeId%22%3A1%7D&GenAIContentCategory=%7B%22showGenAIContentCategory%22%3A1%7D&outputFormat=jsonHttpStatusOverride", dataKey: "data", idKey: "categoryId", labelKey: "name" },
  { key: "geolocations", tokenKey: "sse_token", path: "v1/geolocations", dataKey: "results", idKey: "id", labelKey: "name", mapEntries: (items) => items.flatMap(continent => (continent.countries || []).map(country => ({ id: country.code, label: `${country.name} (${country.code})` }))) },
];

// ---------------------------------------------------------------------------
// Group / list membership resolution — powers the dashboard popover's
// recursive "expand this source/destination" feature (see content-script.js's
// renderMemberTree / showMemberPopover).
//
// The live popover shows a rule's source/destination conditions as resolved
// names. Several of those conditions reference GROUPS/LISTS (network object
// groups, service object groups, destination lists, application lists,
// category lists, private resource groups, identity groups) whose *members*
// the dashboard does not show inline. This layer fetches each referenced
// group, records its members, and — because a member can itself be a group —
// recurses to arbitrary depth so the popover can drill all the way down.
//
// Membership (group→member) endpoint shapes were NOT captured in a HAR like
// the name-resolution endpoints above; the parsers below use candidate
// field names observed across Cisco's object/group APIs and degrade
// gracefully (empty members) when a shape differs. Marked UNVERIFIED so a
// future live capture can correct the exact member-field names without
// touching the recursion logic. Best-effort per group type — a failed fetch
// just leaves that group un-expandable, exactly like an unresolved name.
// ---------------------------------------------------------------------------

function emptyMemberMaps() {
  return {
    networkObjectGroups: {}, networkObjects: {},
    serviceObjectGroups: {}, serviceObjects: {},
    destinationLists: {}, applicationLists: {}, categoryLists: {},
    privateResourceGroups: {}, privateResources: {},
    identityGroups: {},
  };
}

function memberCacheKey(kind, id) {
  return `${kind}:${String(id)}`;
}

function normalizeMemberEntry(entry, fallbackName) {
  if (!entry || typeof entry !== "object") return null;
  const name = entry.name || fallbackName || "";
  const members = Array.isArray(entry.members)
    ? entry.members
        .map((m) => {
          if (!m) return null;
          if (m.id !== undefined) {
            const next = { id: String(m.id), kind: m.kind };
            const name = m.name || m.label || "";
            if (name) next.name = String(name);
            return next;
          }
          if (m.value !== undefined) {
            const next = { value: m.value, kind: m.kind };
            const name = m.name || m.label || "";
            if (name) next.name = String(name);
            return next;
          }
          return null;
        })
        .filter(Boolean)
    : [];
  // Collection endpoints for dest lists / AD groups / networks have no
  // members. Keep those as unresolved names so click-to-expand still hits
  // the HAR per-id destinations/children URLs.
  const resolved = entry.resolved === true || (entry.resolved !== false && members.length > 0);
  return { name, members, resolved };
}

function needsPerIdMembers(kind) {
  return kind === "destinationLists" || kind === "identityGroups" || kind === "sourceNetworks";
}

function membersNeedNames(kind, members) {
  if (kind !== "identityGroups" && kind !== "sourceNetworks") return false;
  return (members || []).some((m) => m && m.id !== undefined && !m.name && !m.label && m.value === undefined);
}

function getCachedMembers(maps, kind, id) {
  const entry = maps && maps[kind] && maps[kind][String(id)];
  if (!entry || !entry.resolved) return null;
  // A previous collection prefetch stored dest lists / AD groups / networks
  // as resolved with zero members. That is never a real answer — Cisco only
  // puts those entries on the per-id destinations/children URLs.
  if (needsPerIdMembers(kind) && (!entry.members || !entry.members.length)) return null;
  // Nameless AD/network children were persisted before we kept `label`.
  // Treat them as stale so expand hits /children again.
  if (membersNeedNames(kind, entry.members)) return null;
  return entry;
}

async function getMembershipTabId(preferredTabId) {
  if (preferredTabId) return preferredTabId;
  try {
    const tabs = await api.tabs.query({ url: ["https://dashboard.sse.cisco.com/*", "https://*.sse.cisco.com/*"] });
    if (tabs && tabs[0] && tabs[0].id) return tabs[0].id;
  } catch (_) {}
  try {
    const tabs = await api.tabs.query({ active: true, currentWindow: true });
    return tabs && tabs[0] && tabs[0].id || null;
  } catch (_) {
    return null;
  }
}

var _memberInflight = {};
const MEMBERSHIP_FAILURE_COOLDOWN_MS = 24 * 60 * 60 * 1000;

function membershipFailureKey(orgId, kind, id) {
  return JSON.stringify([String(orgId), String(kind), String(id)]);
}

function membershipFailureCoolingDown(failures, orgId, kind, id, now = Date.now()) {
  const failure = failures && failures[membershipFailureKey(orgId, kind, id)];
  return !!(failure && failure.expiresAt > now);
}

async function recordMembershipFailure(orgId, kind, id, status) {
  const stored = await api.storage.local.get("sse_membership_failures");
  const failures = stored.sse_membership_failures || {};
  const now = Date.now();
  for (const [key, failure] of Object.entries(failures)) {
    if (!failure || failure.expiresAt <= now) delete failures[key];
  }
  failures[membershipFailureKey(orgId, kind, id)] = {
    status,
    expiresAt: now + MEMBERSHIP_FAILURE_COOLDOWN_MS,
  };
  await api.storage.local.set({ sse_membership_failures: failures });
}

async function clearMembershipFailure(orgId, kind, id) {
  const stored = await api.storage.local.get("sse_membership_failures");
  const failures = stored.sse_membership_failures || {};
  delete failures[membershipFailureKey(orgId, kind, id)];
  await api.storage.local.set({ sse_membership_failures: failures });
}

function mergeMemberMaps(base, extra) {
  const out = emptyMemberMaps();
  for (const source of [base, extra]) {
    if (!source) continue;
    for (const key of Object.keys(out)) {
      out[key] = Object.assign(out[key], source[key] || {});
    }
  }
  return out;
}

async function persistMemberMaps(extra) {
  const stored = await api.storage.local.get("sse_member_maps");
  const merged = mergeMemberMaps(stored.sse_member_maps || {}, extra || {});
  await api.storage.local.set({ sse_member_maps: merged });
  return merged;
}

function collectGroupIds(rules) {
  const result = {
    networkObjectGroups: new Set(),
    networkObjects: new Set(),
    serviceObjectGroups: new Set(),
    serviceObjects: new Set(),
    destinationLists: new Set(),
    applicationLists: new Set(),
    categoryLists: new Set(),
    privateResourceGroups: new Set(),
    privateResources: new Set(),
    identityGroups: new Set(),
  };
  for (const rule of rules || []) {
    const conds = rule.conditions || rule.ruleConditions || [];
    if (!Array.isArray(conds)) continue;
    for (const c of conds) {
      const name = (c.attributeName || "").toLowerCase();
      const values = Array.isArray(c.attributeValue) ? c.attributeValue : [c.attributeValue];
      const add = (key) => values.forEach((v) => {
        if (v && v !== "*" && String(v).toLowerCase() !== "any") result[key].add(String(v));
      });
      if (name.includes("networkobjectgroup")) add("networkObjectGroups");
      else if (name.includes("networkobject")) add("networkObjects");
      else if (name.includes("serviceobjectgroup")) add("serviceObjectGroups");
      else if (name.includes("serviceobject")) add("serviceObjects");
      else if (name.includes("destination_list")) add("destinationLists");
      else if (name.includes("application_list")) add("applicationLists");
      else if (name.includes("category_list")) add("categoryLists");
      else if (name.includes("private_resource_group")) add("privateResourceGroups");
      else if (name.includes("private_resource")) add("privateResources");
      else if (name.includes("identity_ids") || name.includes("identity_group")) add("identityGroups");
    }
  }
  for (const key of Object.keys(result)) result[key] = Array.from(result[key]);
  return result;
}

// Per group-type config. `leafKind` is the kind assigned to each resolved
// member (used by content-script.js to resolve leaf names + to detect nested
// groups). `memberFields` are the candidate member-array property names, tried
// in order. UNVERIFIED member-field names — adjust against a live capture.
const MEMBERSHIP_CONFIG = {
  networkObjectGroups: {
    tokenKey: "sse_token", leafKind: "networkObjects",
    wrapper: ["data", "items", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: ["objects", "objectIds", "networkObjectIds"],
    groupFields: ["groups"],
    // Returns 400 without ?ids= (see OBJECT_ENDPOINTS).
    url: (o, ids) => `https://api.sse.cisco.com/policies/v2/objects/networkObjectGroups?ids=${(ids || []).map(encodeURIComponent).join(",")}`,
    needsIds: true,
  },
  networkObjects: {
    tokenKey: "sse_token", leafKind: "address",
    wrapper: ["data", "items", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: [],
    // Returns 400 without ?ids= (see OBJECT_ENDPOINTS).
    url: (o, ids) => `https://api.sse.cisco.com/policies/v2/objects/networkObjects?ids=${(ids || []).map(encodeURIComponent).join(",")}`,
    needsIds: true,
  },
  serviceObjectGroups: {
    tokenKey: "sse_token", leafKind: "serviceObjects",
    wrapper: ["data", "items", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: ["objects", "serviceObjects", "serviceObjectIds"],
    groupFields: ["groups"],
    // Returns 400 without ?ids= (see OBJECT_ENDPOINTS).
    url: (o, ids) => `https://api.sse.cisco.com/policies/v2/objects/serviceObjectGroups?ids=${(ids || []).map(encodeURIComponent).join(",")}`,
    needsIds: true,
  },
  serviceObjects: {
    tokenKey: "sse_token", leafKind: "service",
    wrapper: ["data", "items", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: [],
    // Returns 400 without ?ids= (see OBJECT_ENDPOINTS).
    url: (o, ids) => `https://api.sse.cisco.com/policies/v2/objects/serviceObjects?ids=${(ids || []).map(encodeURIComponent).join(",")}`,
    needsIds: true,
  },
  destinationLists: {
    tokenKey: "opendns_token", leafKind: "fqdn",
    wrapper: ["data", "items", "destinations", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: ["domains", "destinations", "entries"],
    url: (o) => `https://api.opendns.com/v3/organizations/${o}/destinationlists?sort=%7B%22name%22%3A%22asc%22%7D&outputFormat=jsonHttpStatusOverride&page=1&limit=100&filters=%7B%22bundleTypeId%22%3A%5B2%5D%7D`,
  },
  applicationLists: {
    tokenKey: "sse_token", leafKind: "application",
    wrapper: ["applicationLists", "data", "items", "results"], idField: "applicationListId",
    nameField: ["applicationListName", "name", "label"],
    memberFields: ["applicationIds", "applications", "items", "members"],
    url: (o) => `https://api.umbrella.com/v1/organizations/${o}/application_lists`,
  },
  categoryLists: {
    tokenKey: "opendns_token", leafKind: "category",
    wrapper: ["data", "items", "results"], idField: "id",
    nameField: ["name", "categorySettingName", "label"],
    memberFields: ["categories", "categoryIds", "members"],
    url: (o) => `https://api.opendns.com/v3/organizations/${o}/categorysettings?outputFormat=jsonHttpStatusOverride&filters=%7B%7D`,
  },
  privateResourceGroups: {
    tokenKey: "sse_token", leafKind: "privateResources",
    wrapper: ["items", "data", "results"], idField: "resourceGroupId", nameField: ["name", "label"],
    memberFields: ["resourceIds", "resources", "members"],
    url: (o) => `https://api.umbrella.com/v1/organizations/${o}/private_resource_groups?offset=0&limit=1000&sortBy=name&sortOrder=asc`,
  },
  privateResources: {
    tokenKey: "sse_token", leafKind: "address",
    wrapper: ["items", "data", "results"], idField: "resourceId", nameField: ["name", "friendlyName", "label"],
    memberFields: [],
    url: (o) => `https://api.umbrella.com/v1/organizations/${o}/private_resources?offset=0&limit=1000&sortBy=name&sortOrder=asc`,
  },
  identityGroups: {
    tokenKey: "mgmt_authz_token", leafKind: "identity",
    wrapper: ["data", "items", "results"], idField: "id", nameField: ["name", "label"],
    memberFields: ["members", "users", "identities", "children"],
    url: (o) => `https://management.api.umbrella.com/identity/v2/organizations/${o}/directory_group?offset=0&limit=100`,
  },
};

function membershipAuthHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/json",
    Origin: "https://dashboard.sse.cisco.com",
    Referer: "https://dashboard.sse.cisco.com/",
  };
}

function classifyAddressValue(value) {
  const v = String(value || "").trim();
  if (!v) return null;
  return { value: v, kind: "address" };
}

// HAR: private_resources[].resourceAddresses[].destinationAddr[] plus
// accessTypes[].reachableAddresses[] / externalFQDN hostnames.
function extractPrivateResourceAddresses(item) {
  const out = [];
  const seen = new Set();
  const add = (value) => {
    const classified = classifyAddressValue(value);
    if (!classified || seen.has(classified.value)) return;
    seen.add(classified.value);
    out.push(classified);
  };
  for (const addr of item && Array.isArray(item.resourceAddresses) ? item.resourceAddresses : []) {
    for (const dest of (addr && addr.destinationAddr) || []) add(dest);
    for (const id of (addr && addr.networkObjectIds) || []) {
      if (id === undefined || id === null || id === "") continue;
      out.push({ id: String(id), kind: "networkObjects" });
    }
  }
  for (const access of item && Array.isArray(item.accessTypes) ? item.accessTypes : []) {
    for (const dest of (access && access.reachableAddresses) || []) add(dest);
    if (access && access.externalFQDN) {
      const raw = String(access.externalFQDN).trim();
      const host = raw.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0].split(":")[0];
      add(host || raw);
    }
  }
  return out;
}

// HAR: networkObjects[].value.addresses is a string[] of hosts/CIDRs.
function extractNetworkObjectAddresses(item) {
  const value = item && item.value;
  const addresses = value && Array.isArray(value.addresses) ? value.addresses : [];
  return addresses.map(classifyAddressValue).filter(Boolean);
}

// HAR: serviceObjects[].value = { protocol, ports: string[] }.
function extractServiceObjectLeaves(item) {
  const value = item && item.value;
  if (!value || typeof value !== "object") return [];
  const protocol = value.protocol ? String(value.protocol) : "";
  const ports = Array.isArray(value.ports) ? value.ports.filter(Boolean) : [];
  const label = [protocol, ports.join(",")].filter(Boolean).join(" ");
  return label ? [{ value: label, kind: "service" }] : [];
}

function _classifyMember(m, key) {
  const cfg = MEMBERSHIP_CONFIG[key];
  const leafKind = cfg ? cfg.leafKind : "unknown";
  // HAR: destination list members are { destination, type }, not IDs.
  if (key === "destinationLists") {
    const v = typeof m === "string" ? m : (m && (m.destination || m.domain || m.value || m.name)) || "";
    return v ? { value: v, kind: "fqdn" } : null;
  }
  if (typeof m === "string") return { id: m, kind: leafKind };
  if (typeof m === "number") return { id: String(m), kind: leafKind };
  if (m && typeof m === "object") {
    const id = m.id !== undefined ? m.id
      : (m.groupId !== undefined ? m.groupId
        : (m.objectId !== undefined ? m.objectId
          : (m.resourceId !== undefined ? m.resourceId
            : (m.applicationId !== undefined ? m.applicationId
              : (m.categoryId !== undefined ? m.categoryId : undefined)))));
    if (id === undefined) return null;
    const name = m.label || m.name || m.displayName || "";
    // Nested group detection: any member that carries its own children or is
    // typed as a group is itself recursively expandable.
    const classified = Array.isArray(m.children) && m.children.length
      ? { id: String(id), kind: key }
      : (m.type && /group/i.test(String(m.type))
        ? { id: String(id), kind: key }
        : { id: String(id), kind: leafKind });
    if (name) classified.name = String(name);
    return classified;
  }
  return null;
}

// Category lists ("category settings") carry their categories as a hex
// bitmask, not a member array: bit N set means the category at position N of
// data/categories-lookup.json (keyed by bit position, holding categoryId).
// Verified against Activity Search: "Finance Restricted" decodes to include
// Encrypted DNS and Chat and Instant Messaging, both blocked under its rule.
var categoryBitIndex = null;

async function loadCategoryBitIndex() {
  if (categoryBitIndex) return categoryBitIndex;
  try {
    const response = await fetch(api.runtime.getURL("data/categories-lookup.json"));
    categoryBitIndex = await response.json();
  } catch (err) {
    logEvent("membership", "category lookup unavailable", { error: err.message });
    categoryBitIndex = {};
  }
  return categoryBitIndex;
}

function decodeCategoryBits(hex, index) {
  if (typeof hex !== "string" || !/^[0-9a-f]+$/i.test(hex)) return [];
  const members = [];
  let bits = BigInt(`0x${hex}`);
  for (let position = 0; bits > 0n; position++, bits >>= 1n) {
    if (!(bits & 1n)) continue;
    const entry = index[String(position)];
    if (entry && entry.categoryId !== undefined) members.push({ id: String(entry.categoryId), kind: "category", name: entry.name });
  }
  return members;
}

function _extractMemberList(item, key) {
  if (key === "categoryLists" && item && item.categoryBits) return decodeCategoryBits(item.categoryBits, categoryBitIndex || {});
  if (key === "privateResources") return extractPrivateResourceAddresses(item);
  if (key === "networkObjects") return extractNetworkObjectAddresses(item);
  if (key === "serviceObjects") return extractServiceObjectLeaves(item);
  const cfg = MEMBERSHIP_CONFIG[key];
  if (!cfg) return [];
  const members = [];
  const seen = new Set();
  const push = (classified) => {
    if (!classified) return;
    const token = classified.id !== undefined
      ? `${classified.kind}:${classified.id}`
      : `${classified.kind}:${classified.value}`;
    if (seen.has(token)) return;
    seen.add(token);
    members.push(classified);
  };
  for (const f of cfg.memberFields || []) {
    if (Array.isArray(item[f]) && item[f].length) {
      item[f].forEach((m) => push(_classifyMember(m, key)));
    }
  }
  for (const f of cfg.groupFields || []) {
    if (Array.isArray(item[f]) && item[f].length) {
      item[f].forEach((m) => {
        const classified = _classifyMember(m, key);
        if (classified && classified.id !== undefined) classified.kind = key;
        push(classified);
      });
    }
  }
  return members;
}

function parseMembership(json, key) {
  const cfg = MEMBERSHIP_CONFIG[key];
  if (!cfg) return [];
  let items = Array.isArray(json) ? json : null;
  if (!items) {
    for (const w of cfg.wrapper) {
      if (json && Array.isArray(json[w])) { items = json[w]; break; }
    }
  }
  if (!items) return [];
  return items.map((item) => {
    if (!item || typeof item !== "object") return null;
    const id = item[cfg.idField];
    if (id === undefined || id === null) return null;
    const name = cfg.nameField.map((f) => item[f]).find((v) => v) || String(id);
    return { id, name, members: _extractMemberList(item, key) };
  }).filter(Boolean);
}

function classifyPerIdMember(kind, row) {
  if (kind === "destinationLists") {
    const value = typeof row === "string" ? row : (row && (row.destination || row.domain || row.value || row.name));
    return value ? { value: String(value), kind: "fqdn" } : null;
  }
  if (!row || row.id === undefined) return null;
  const nested = row.type === "directory_group" || Number(row.childCount) > 0 || (typeof row.children === "string" && /\/children/.test(row.children));
  return {
    id: String(row.id),
    kind: nested ? "identityGroups" : "identity",
    name: row.label || row.name || String(row.id),
  };
}

function perIdMemberUrl(kind, orgId, id, page) {
  if (kind === "destinationLists") {
    return `https://api.opendns.com/v3/organizations/${orgId}/destinationlists/${id}/destinations?page=${page}&outputFormat=jsonHttpStatusOverride&optionalFields={meta:%27meta%27}`;
  }
  if (kind === "identityGroups") {
    return `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/directory_group/${id}/children?offset=${(page - 1) * 100}&limit=100`;
  }
  if (kind === "sourceNetworks") {
    return `https://management.api.umbrella.com/identity/v2/organizations/${orgId}/network/${id}/children?offset=${(page - 1) * 100}&limit=100`;
  }
  return null;
}

// HAR-backed per-id member fetch. Destination lists do not include members
// on the collection endpoint; Cisco loads
// /destinationlists/{id}/destinations. AD groups expose a children URL, not
// an inline members array. Networks use /network/{id}/children.
async function fetchMembersById(kind, id, orgId, tabId, existing) {
  const tokenKey =
    kind === "destinationLists" ? "opendns_token" :
    (kind === "identityGroups" || kind === "sourceNetworks") ? "mgmt_authz_token" :
    null;
  if (!tokenKey) return existing || { name: String(id), members: [], resolved: false };
  const tokenObj = await getFreshToken(tokenKey, tabId);
  if (!tokenObj) return existing || { name: String(id), members: [], resolved: false, debug: { kind, id, error: "no token", tokenKey } };

  const members = [];
  const pages = [];
  let page = 1;
  const maxPages = 40;
  while (page <= maxPages) {
    const url = perIdMemberUrl(kind, orgId, id, page);
    if (!url) return existing || { name: String(id), members: [], resolved: false };
    const response = await fetch(url, { headers: membershipAuthHeaders(tokenObj.token) });
    if (!response.ok) {
      logEvent("membership", "per-id non-OK", { kind, id, status: response.status, page });
      pages.push({ url, status: response.status, ok: false });
      if (page === 1) {
        if ((response.status === 403 || response.status === 405) && kind === "identityGroups") {
          await recordMembershipFailure(orgId, kind, id, response.status);
        }
        return existing || { name: String(id), members: [], resolved: false, debug: { kind, id, pages } };
      }
      break;
    }
    const json = await response.json();
    const rows = Array.isArray(json) ? json : (json.data || json.items || json.results || []);
    const classified = [];
    rows.forEach((row) => {
      const member = classifyPerIdMember(kind, row);
      if (member) {
        members.push(member);
        classified.push(member);
      }
    });
    pages.push({
      url,
      status: response.status,
      ok: true,
      rowCount: rows.length,
      keys: json && !Array.isArray(json) ? Object.keys(json) : ["<array>"],
      raw: rows.slice(0, 20),
      classified: classified.slice(0, 20),
    });
    const meta = json && json.meta;
    const total = meta && Number(meta.total);
    const limit = (meta && Number(meta.limit)) || (kind === "destinationLists" ? 25 : 100);
    if (!rows.length) break;
    if (Number.isFinite(total) && members.length >= total) break;
    if (rows.length < limit) break;
    page += 1;
  }
  await clearMembershipFailure(orgId, kind, id);
  return {
    name: (existing && existing.name) || String(id),
    members,
    resolved: true,
    debug: { kind, id, orgId, pages, memberCount: members.length },
  };
}

// Breadth-first recursive fetch. Each group's members are recorded flat under
// its kind; any member that is itself a known group type is pushed onto the
// next frontier so the popover can drill arbitrarily deep. `visited` prevents
// cycles / re-fetches; MAX_DEPTH is a safety bound.
async function fetchMembershipKind(kind, orgId, tabId, existingMaps, ids) {
  const cfg = MEMBERSHIP_CONFIG[kind];
  if (!cfg) return existingMaps[kind] || {};
  if (cfg.needsIds && !(ids && ids.length)) return existingMaps[kind] || {};
  const tokenObj = await getFreshToken(cfg.tokenKey, tabId);
  if (!tokenObj) { logEvent("membership", "no token", { kind }); return existingMaps[kind] || {}; }
  const response = await fetch(cfg.url(orgId, ids), {
    headers: { Authorization: `Bearer ${tokenObj.token}`, Accept: "application/json" },
  });
  if (!response.ok) { logEvent("membership", "non-OK", { kind, status: response.status }); return existingMaps[kind] || {}; }
  const json = await response.json();
  if (kind === "categoryLists") await loadCategoryBitIndex();
  const entries = parseMembership(json, kind);
  const next = Object.assign({}, existingMaps[kind] || {});
  for (const e of entries) {
    if (!e || e.id === undefined) continue;
    const normalized = normalizeMemberEntry(e, String(e.id));
    if (normalized) next[String(e.id)] = normalized;
  }
  logEvent("membership", "resolved", { kind, count: entries.length });
  return next;
}

async function resolveOneMembership(kind, id, orgId, tabId) {
  const cacheId = memberCacheKey(kind, id);
  if (_memberInflight[cacheId]) return _memberInflight[cacheId];
  _memberInflight[cacheId] = (async () => {
    const stored = await api.storage.local.get("sse_member_maps");
    const maps = stored.sse_member_maps || emptyMemberMaps();
    const cached = getCachedMembers(maps, kind, id);
    if (cached) return cached;
    const liveTabId = await getMembershipTabId(tabId);
    let entry = null;
    if (needsPerIdMembers(kind)) {
      entry = await fetchMembersById(kind, id, orgId, liveTabId, maps[kind] && maps[kind][String(id)]);
    } else {
      const kindMap = await fetchMembershipKind(kind, orgId, tabId, maps, [String(id)]);
      maps[kind] = kindMap;
      entry = getCachedMembers(maps, kind, id);
    }
    if (!entry) entry = { name: String(id), members: [], resolved: false };
    if (!maps[kind]) maps[kind] = {};
    maps[kind][String(id)] = entry;
    await persistMemberMaps({ [kind]: { [String(id)]: entry } });
    return entry;
  })().finally(() => { delete _memberInflight[cacheId]; });
  return _memberInflight[cacheId];
}

async function resolveMembership(orgId, tabId, rules) {
  const stored = await api.storage.local.get("sse_member_maps");
  const memberMaps = mergeMemberMaps(stored.sse_member_maps || {}, {});
  const initialIds = collectGroupIds(rules);
  const visited = new Set();
  let frontier = [];
  for (const key of Object.keys(initialIds)) {
    for (const id of initialIds[key]) {
      if (getCachedMembers(memberMaps, key, id)) continue;
      frontier.push({ key, ids: [id] });
    }
  }
  const MAX_DEPTH = 12;
  let depth = 0;
  while (frontier.length && depth < MAX_DEPTH) {
    depth++;
    const byKind = {};
    for (const item of frontier) {
      const todo = (item.ids || []).filter((id) => !visited.has(memberCacheKey(item.key, id)) && !getCachedMembers(memberMaps, item.key, id));
      if (!todo.length) continue;
      todo.forEach((id) => visited.add(memberCacheKey(item.key, id)));
      byKind[item.key] = (byKind[item.key] || []).concat(todo);
    }
    frontier = [];
    await Promise.all(Object.keys(byKind).map(async (key) => {
      try {
        if (needsPerIdMembers(key)) {
          const storedFailures = await api.storage.local.get("sse_membership_failures");
          for (const id of byKind[key]) {
            if (membershipFailureCoolingDown(storedFailures.sse_membership_failures, orgId, key, id)) continue;
            const entry = await fetchMembersById(key, id, orgId, tabId, memberMaps[key] && memberMaps[key][String(id)]);
            if (!memberMaps[key]) memberMaps[key] = {};
            memberMaps[key][String(id)] = entry;
            // Nested AD groups: the policy checker resolves a user's groups
            // through every level, so follow child groups too.
            for (const m of (entry && entry.members) || []) {
              if (m && m.kind === key && m.id !== undefined && !visited.has(memberCacheKey(key, m.id))) {
                frontier.push({ key, ids: [String(m.id)] });
              }
            }
          }
          return;
        }
        const kindMap = await fetchMembershipKind(key, orgId, tabId, memberMaps, byKind[key]);
        memberMaps[key] = Object.assign({}, memberMaps[key] || {}, kindMap);
        for (const id of byKind[key]) {
          const entry = getCachedMembers(memberMaps, key, id);
          for (const m of (entry && entry.members) || []) {
            if (m && m.id !== undefined && MEMBERSHIP_CONFIG[m.kind] && !visited.has(memberCacheKey(m.kind, m.id)) && !getCachedMembers(memberMaps, m.kind, m.id)) {
              frontier.push({ key: m.kind, ids: [String(m.id)] });
            }
          }
        }
      } catch (err) {
        logEvent("membership", "error", { key, error: err.message });
      }
    }));
  }
  return memberMaps;
}

function catalogHost(catalog) {
  if (catalog.host) return catalog.host;
  return catalog.tokenKey === "mgmt_authz_token" ? "https://management.api.umbrella.com" :
    catalog.tokenKey === "opendns_token" ? "https://api.opendns.com" : "https://api.umbrella.com";
}

// ---------------------------------------------------------------------------
// Destination lookup (Cisco Investigate, as the dashboard's Investigate page
// calls it, with the management token):
//   /domains/categorization/{host}?taloscategories=true → content and
//     security categories as bit positions (same numbering as the bundled
//     category lookups)
//   /url/{host}/classifiers → security categories by name; catches threats
//     the domain categorization misses (verified: a Malware domain from
//     Activity Search that categorization no longer lists)
//   /get-casi-data?fqdn={host} → the cloud application ("TikTok")
// One host per call (the bulk endpoint needs a higher Investigate tier).
// A 403 has two known causes, handled in order:
//   1. a superseded token: ask the dashboard tab for the token it holds now
//      and retry once (the dashboard's own calls use the latest token);
//   2. throttling after a burst (seen after ~400 calls in 5 minutes; cleared
//      by itself ~25 minutes later): pause lookups for a while so checks fall
//      back to questions immediately instead of failing each time.
// Results are cached for 24 hours in storage.local to spend as few calls as
// possible; the URL classifier is only called when categorization lists no
// threat.
// ---------------------------------------------------------------------------
var destinationLookupCache = new Map();
var LOOKUP_CACHE_KEY = "psc_destination_lookups";
var LOOKUP_TTL_MS = 24 * 60 * 60 * 1000;
var INVESTIGATE_PAUSE_MS = 10 * 60 * 1000;
var investigatePausedUntil = 0;

async function lookupDestination(host, tabId, requestedOrgId) {
  const name = host.trim().toLowerCase();
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(name)) return { ok: false, error: "not a domain" };
  let dashboardTabId = null;
  try {
    const tabs = await api.tabs.query({ url: "https://dashboard.sse.cisco.com/org/*" });
    if (tabId && tabs && tabs.some(tab => tab.id === tabId)) dashboardTabId = tabId;
    else dashboardTabId = tabs && tabs[0] && tabs[0].id || null;
  } catch (_) {
    dashboardTabId = tabId || null;
  }
  if (!dashboardTabId) return { ok: false, error: "Open the authenticated Cisco dashboard to look up destination categories" };
  let orgId = requestedOrgId ? String(requestedOrgId) : null;
  if (!orgId) {
    try {
      const tabs = await api.tabs.query({ url: "https://dashboard.sse.cisco.com/org/*" });
      const match = (tabs || []).map(tab => String(tab.url || "").match(/\/org\/(\d+)/)).find(Boolean);
      if (match) orgId = match[1];
    } catch (_) {}
  }
  if (!orgId) {
    const cached = await api.storage.local.get("cached_org_id");
    orgId = cached.cached_org_id || null;
  }
  if (!orgId) return { ok: false, error: "Could not determine active organization" };
  const cacheKey = `${orgId}:${name}`;
  const cached = destinationLookupCache.get(cacheKey);
  if (cached && Date.now() - cached.at < LOOKUP_TTL_MS) return cached.result;
  let stored = {};
  try { stored = (await api.storage.local.get(LOOKUP_CACHE_KEY))[LOOKUP_CACHE_KEY] || {}; } catch (_) {}
  if (stored[cacheKey] && Date.now() - stored[cacheKey].at < LOOKUP_TTL_MS) {
    destinationLookupCache.set(cacheKey, stored[cacheKey]);
    return stored[cacheKey].result;
  }
  if (Date.now() < investigatePausedUntil) return { ok: false, error: "Investigate paused after a refusal", retryAt: investigatePausedUntil };
  let lookup;
  try {
    lookup = await api.tabs.sendMessage(dashboardTabId, { type: "LOOKUP_DESTINATION_IN_PAGE", host: name, orgId: String(orgId) });
  } catch (error) {
    lookup = { error: error.message };
  }
  if (!lookup || !lookup.result || !lookup.result.ok) {
    const message = lookup && lookup.error || lookup && lookup.result && lookup.result.error || "Investigate page lookup failed";
    if (/returned 403/.test(message)) investigatePausedUntil = Date.now() + INVESTIGATE_PAUSE_MS;
    logEvent("destination-lookup", "dashboard-context lookup failed", { error: message, pausedUntil: investigatePausedUntil });
    return { ok: false, error: message };
  }
  const result = lookup.result;
  const record = { at: Date.now(), result };
  destinationLookupCache.set(cacheKey, record);
  try {
    for (const [key, value] of Object.entries(stored)) if (!value || Date.now() - value.at >= LOOKUP_TTL_MS) delete stored[key];
    stored[cacheKey] = record;
    await api.storage.local.set({ [LOOKUP_CACHE_KEY]: stored });
  } catch (_) {}
  return result;
}

// ---------------------------------------------------------------------------
// Security profiles (captured from the dashboard's security profile editor):
//   /v3/organizations/{org}/securitysettings  threat protections per setting:
//     malware/botnet/phishing toggles + categoryBits (bit positions into
//     data/security-categories-lookup.json)
//   /v3/organizations/{org}/bundles?filters={"bundleTypeId":[2,5]}  web
//     profiles; a rule's umbrella.posture.webProfileId is a bundle id whose
//     securitySettingGroupId names its security setting
// The DNS default is the isDefault security setting for DNS (bundleTypeId 1).
// Verified against Activity Search: Malware / Potentially Harmful / Command
// and Control blocks under Allow rules, and DNS "Block due to security setting".
// ---------------------------------------------------------------------------
var securityCategoryIndex = null;

async function loadSecurityCategoryIndex() {
  if (securityCategoryIndex) return securityCategoryIndex;
  try {
    securityCategoryIndex = await (await fetch(api.runtime.getURL("data/security-categories-lookup.json"))).json();
  } catch (err) {
    logEvent("security-profiles", "security category lookup unavailable", { error: err.message });
    securityCategoryIndex = {};
  }
  return securityCategoryIndex;
}

function securitySettingCategories(setting, index) {
  const names = new Set();
  if (setting.malwareProtection) names.add("Malware");
  if (setting.botnetProtection) names.add("Command and Control");
  if (setting.phishingProtection) names.add("Phishing");
  if (typeof setting.categoryBits === "string" && /^[0-9a-f]+$/i.test(setting.categoryBits)) {
    let bits = BigInt(`0x${setting.categoryBits}`);
    for (let position = 0; bits > 0n; position++, bits >>= 1n) {
      if (bits & 1n && index[String(position)]) names.add(index[String(position)].name);
    }
  }
  return [...names];
}

async function resolveSecurityProfiles(orgId, tabId) {
  const tokenObj = await getFreshToken("opendns_token", tabId);
  if (!tokenObj) { logEvent("security-profiles", "skipped — no opendns token"); return null; }
  const headers = { Authorization: `Bearer ${tokenObj.token}`, Accept: "application/json" };
  const base = `https://api.opendns.com/v3/organizations/${orgId}`;
  const [settingsResponse, bundlesResponse, index] = await Promise.all([
    fetch(`${base}/securitysettings?outputFormat=jsonHttpStatusOverride`, { headers }),
    fetch(`${base}/bundles?filters=${encodeURIComponent(JSON.stringify({ bundleTypeId: [2, 5] }))}&outputFormat=jsonHttpStatusOverride`, { headers }),
    loadSecurityCategoryIndex(),
  ]);
  if (!settingsResponse.ok || !bundlesResponse.ok) {
    logEvent("security-profiles", "non-OK", { settings: settingsResponse.status, bundles: bundlesResponse.status });
    return null;
  }
  const settingsRows = ((await settingsResponse.json()).data) || [];
  const bundleRows = ((await bundlesResponse.json()).data) || [];
  const securitySettings = {};
  let dnsDefaultSettingId = null;
  for (const row of settingsRows) {
    if (!row || row.id === undefined) continue;
    securitySettings[String(row.id)] = { name: row.name, isDefault: !!row.isDefault, bundleTypeId: row.bundleTypeId, categories: securitySettingCategories(row, index) };
    if (row.isDefault && row.bundleTypeId === 1) dnsDefaultSettingId = String(row.id);
  }
  const webProfiles = {};
  for (const row of bundleRows) {
    if (!row || row.id === undefined) continue;
    webProfiles[String(row.id)] = {
      name: row.name,
      securitySettingId: row.securitySettingGroupId !== undefined && row.securitySettingGroupId !== null ? String(row.securitySettingGroupId) : null,
    };
  }
  logEvent("security-profiles", "resolved", { settings: settingsRows.length, profiles: bundleRows.length, dnsDefaultSettingId });
  return { securitySettings, webProfiles, dnsDefaultSettingId };
}

async function resolveFullCatalogs(orgId, tabId) {
  const maps = { destinationScopes: { public_internet: "Internet", private_network: "Private Access" } };
  await Promise.all(FULL_CATALOGS.map(async (catalog) => {
    // Always publish a key, including on token/API failure. The popup can then
    // render that selector as configured-empty/unavailable instead of treating
    // one failed optional catalog as an endless global loading operation.
    maps[catalog.key] = {};
    const tokenObj = await getFreshToken(catalog.tokenKey, tabId);
    if (!tokenObj) {
      logEvent("catalog-fetch", "Catalog skipped — no fresh token", { catalog: catalog.key, tokenKey: catalog.tokenKey });
      return;
    }
    const entries = [];
    let offset = 0;
    try {
      do {
        const separator = catalog.path.includes("?") ? "&" : "?";
        const suffix = catalog.paged ? `${separator}offset=${offset}&limit=100` : "";
        const response = await fetch(`${catalogHost(catalog)}/${catalog.path.replace("{orgId}", orgId)}${suffix}`, {
          headers: {
            Authorization: `Bearer ${tokenObj.token}`,
            Accept: "application/json",
            Origin: "https://dashboard.sse.cisco.com",
            Referer: "https://dashboard.sse.cisco.com/",
          },
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const json = await response.json();
        // Cisco uses different collection wrappers across catalog endpoints.
        // Prefer the HAR-observed key but accept the other observed wrappers.
        const page = Array.isArray(json) ? json :
          (Array.isArray(json[catalog.dataKey]) ? json[catalog.dataKey] :
            (Array.isArray(json.data) ? json.data :
              (Array.isArray(json.results) ? json.results :
                (Array.isArray(json.items) ? json.items : []))));
        entries.push(...page);
        if (!catalog.paged || page.length === 0 || offset + page.length >= (json.total || 0) || page.length < 100) break;
        offset += page.length;
      } while (true);
      const normalizedEntries = catalog.mapEntries
        ? catalog.mapEntries(entries)
        : entries.map(entry => ({ id: entry[catalog.idKey], label: entry[catalog.labelKey] }));
      maps[catalog.key] = Object.fromEntries(normalizedEntries
        .filter(entry => entry && entry.id !== undefined && entry.label)
        .map(entry => [String(entry.id), entry.label]));
      // HAR: /applications is a mixed 10k-item catalog. Protocol signatures
      // are exactly the Application Protocol group, not a separate endpoint.
      if (catalog.key === "applications") {
        maps.applicationProtocols = Object.fromEntries(entries
          .filter(entry => entry && entry.groupName === "Application Protocol" && entry.id !== undefined && entry.name)
          .map(entry => [String(entry.id), entry.name]));
        maps.internetApplications = Object.fromEntries(entries
          .filter(entry => entry && entry.groupName !== "Application Protocol" && entry.id !== undefined && entry.name)
          .map(entry => [String(entry.id), entry.name]));
      }
      // Prefer the item's actual API typeId when Cisco supplies one. The
      // catalog endpoint groups entries for browsing, but its individual
      // typeId is what `umbrella.source.identity_type_ids` evaluates. Some
      // roaming entries, for example, are returned as AnyConnect/Posture
      // identities even though they appear in the Roaming Computers catalog.
      // Endpoint families without an entry-level type use the HAR-backed
      // sourcePolicyTypeId fallback.
      if (catalog.key.startsWith("source")) {
        maps.sourceIdentityTypeIds = maps.sourceIdentityTypeIds || {};
        for (const entry of entries) {
          if (entry && entry.id !== undefined) {
            const policyTypeId = entry.typeId ?? catalog.sourcePolicyTypeId;
            if (policyTypeId !== undefined) maps.sourceIdentityTypeIds[String(entry.id)] = policyTypeId;
          }
        }
      }
      logEvent("catalog-fetch", "Catalog fetched", { catalog: catalog.key, count: Object.keys(maps[catalog.key]).length });
    } catch (err) {
      logEvent("catalog-fetch", "Catalog fetch failed", { catalog: catalog.key, error: err.message });
    }
  }));
  await labelBranchPeers(maps, tabId);
  maps.exclusions = await resolveExclusions(orgId, tabId);
  return maps;
}

async function resolveExclusions(orgId, tabId) {
  let fallback = [];
  try {
    const res = await fetch(api.runtime.getURL("data/exclusions-lookup.json"));
    if (res.ok) fallback = (await res.json()) || [];
  } catch (_) {}

  const defaultLocal = [
    { id: "default-rfc1918", domain: "RFC-1918", description: "Non-publicly routable address spaces used only for reverse DNS on internal", intent: "Bypass Secure Access", appliesTo: "All Devices" },
    { id: "default-local", domain: "local", description: "All *.local domains", intent: "Bypass Secure Access", appliesTo: "All Devices" },
    { id: "default-arpa", domain: "10.in-addr.arpa", description: "", intent: "Bypass Secure Access", appliesTo: "All Devices" },
  ];

  const liveItems = [];

  try {
    const sseTokenObj = await getFreshToken("sse_token", tabId);
    if (sseTokenObj) {
      const response = await fetch("https://api.sse.cisco.com/deployments/v2/internaldomains", {
        headers: {
          Authorization: `Bearer ${sseTokenObj.token}`,
          Accept: "application/json",
          Origin: "https://dashboard.sse.cisco.com",
          Referer: "https://dashboard.sse.cisco.com/",
        },
      });
      if (response.ok) {
        const json = await response.json();
        const items = Array.isArray(json) ? json : (json?.data || json?.results || json?.items || []);
        for (const item of items) {
          if (!item || !(item.domain || item.name)) continue;
          let appliesTo = "All Devices, All Sites";
          if (item.type) {
            const hasVa = !!item.type.va;
            const hasRoaming = !!item.type.roaming;
            const hasSites = Array.isArray(item.type.sites) && item.type.sites.length > 0;
            if (hasVa && hasRoaming) appliesTo = hasSites ? "All Devices, Some Sites" : "All Devices, All Sites";
            else if (hasVa && !hasRoaming) appliesTo = hasSites ? "Some Sites" : "All Sites";
            else if (hasRoaming) appliesTo = "All Devices";
          }
          liveItems.push({
            id: item.id ? String(item.id) : `int-${liveItems.length}`,
            domain: item.domain || item.name,
            description: item.description || "",
            intent: "Bypass Secure Access",
            appliesTo,
          });
        }
      }
    }
  } catch (err) {
    logEvent("catalog-fetch", "Internal domains fetch error", { error: err.message });
  }

  if (!liveItems.length) {
    try {
      const openDnsTokenObj = await getFreshToken("opendns_token", tabId);
      if (openDnsTokenObj && orgId) {
        const response = await fetch(`https://api.opendns.com/v3/organizations/${orgId}/internaldomains?filters={"includeGlobal":false}`, {
          headers: {
            Authorization: `Bearer ${openDnsTokenObj.token}`,
            Accept: "application/json",
            Origin: "https://dashboard.sse.cisco.com",
            Referer: "https://dashboard.sse.cisco.com/",
          },
        });
        if (response.ok) {
          const json = await response.json();
          const items = Array.isArray(json) ? json : [];
          for (const item of items) {
            if (!item || !item.domain) continue;
            liveItems.push({
              id: item.id ? String(item.id) : `int-${liveItems.length}`,
              domain: item.domain,
              description: item.description || "",
              intent: "Bypass Secure Access",
              appliesTo: "All Devices, All Sites",
            });
          }
        }
      }
    } catch (_) {}
  }

  try {
    const mgmtTokenObj = await getFreshToken("mgmt_authz_token", tabId);
    if (mgmtTokenObj && orgId) {
      const headers = {
        Authorization: `Bearer ${mgmtTokenObj.token}`,
        Accept: "application/json",
        Origin: "https://dashboard.sse.cisco.com",
        Referer: "https://dashboard.sse.cisco.com/",
      };

      try {
        const domResp = await fetch(`https://management.api.umbrella.com/api/v1/organizations/${orgId}/domains`, { headers });
        if (domResp.ok) {
          const json = await domResp.json();
          const list = Array.isArray(json) ? json : (json?.data || []);
          for (const item of list) {
            if (!item || !item.domain) continue;
            liveItems.push({
              id: item.id ? String(item.id) : `ext-dom-${liveItems.length}`,
              domain: item.domain,
              description: item.description || "",
              intent: "Bypass Web Proxy",
              appliesTo: "Hosted PAC, AnyConnect",
            });
          }
        }
      } catch (_) {}

      try {
        const ipResp = await fetch(`https://management.api.umbrella.com/api/v1/organizations/${orgId}/ips`, { headers });
        if (ipResp.ok) {
          const json = await ipResp.json();
          const list = (json?.data?.ips) || (Array.isArray(json?.data) ? json.data : []) || [];
          for (const item of list) {
            if (!item || !item.ip) continue;
            liveItems.push({
              id: item.id ? String(item.id) : `ext-ip-${liveItems.length}`,
              domain: item.ip,
              description: item.description || "",
              intent: "Bypass Web Proxy",
              appliesTo: "AnyConnect",
            });
          }
        }
      } catch (_) {}
    }
  } catch (err) {
    logEvent("catalog-fetch", "External exclusions fetch error", { error: err.message });
  }

  const merged = [];
  const seen = new Set();
  for (const item of [...liveItems, ...defaultLocal, ...fallback]) {
    if (!item || !item.domain) continue;
    const d = item.domain.toLowerCase().trim();
    const intent = item.intent || "Bypass Secure Access";
    const key = `${intent}:${d}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push({ ...item, domain: item.domain.trim(), intent });
    }
  }
  return merged;
}

// Activity Search names a branch "Branch With Peer ID 140147", while the
// catalog calls it "LON Campus vMX". The tunnel-management API links the two
// (as the dashboard overview loads it); add the peer IDs to each branch label
// so either name finds it. Best-effort: the plain names stay on failure.
async function labelBranchPeers(maps, tabId) {
  const branches = maps.sourceBranches || {};
  if (!Object.keys(branches).length) return;
  try {
    const tokenObj = await getFreshToken("sse_token", tabId);
    if (!tokenObj) return;
    const response = await fetch("https://api.sse-network-tunnel-mgmt.internal.umbrella.com/v1/branches/peers?limit=100", {
      headers: { Authorization: `Bearer ${tokenObj.token}`, Accept: "application/json" },
    });
    if (!response.ok) { logEvent("catalog-fetch", "Branch peers non-OK", { status: response.status }); return; }
    const peers = ((await response.json()) || {}).data || [];
    const peerIdsByName = {};
    for (const peer of peers) {
      if (!peer || !peer.name || peer.peerId === undefined) continue;
      (peerIdsByName[peer.name] = peerIdsByName[peer.name] || new Set()).add(String(peer.peerId));
    }
    for (const [id, name] of Object.entries(branches)) {
      const ids = peerIdsByName[name];
      if (ids && ids.size) branches[id] = `${name} (Peer ID ${[...ids].join(", ")})`;
    }
  } catch (err) {
    logEvent("catalog-fetch", "Branch peers failed", { error: err.message });
  }
}

// ---------------------------------------------------------------------------
// Message listener — simplified for fetch-on-token-capture architecture.
//
// TOKEN_CAPTURED: store the token (which triggers _scheduleFetch → fetchAllData)
// RUN_SCAN:       manual refresh — just calls fetchAllData() directly
// GET_*:          read from storage.local (used by content-script.js hover popovers)
// ---------------------------------------------------------------------------

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "TOKEN_CAPTURED") {
    storeToken(
      msg.tokenKey || "sse_token",
      msg.token,
      msg.source || "main-world-patch",
      msg.capturedAt || Date.now(),
      { url: sender?.tab?.url }
    );
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "RUN_SCAN") {
    // Manual refresh — data is already being auto-fetched on token capture,
    // but this lets the popup request an immediate refetch (e.g. Refresh button).
    logEvent("run-scan", "RUN_SCAN invoked (manual refresh)", { orgId: msg.orgId });
    fetchAllData(msg.orgId || undefined).then(() => {
      sendResponse({ ok: true });
    }).catch(err => {
      sendResponse({ error: err.message });
    });
    return true;
  }

  if (msg.type === "GET_FINDINGS") {
    api.storage.local.get("sse_findings").then(result => {
      sendResponse({ findings: result.sse_findings || [] });
    });
    return true;
  }

  if (msg.type === "GET_RULES") {
    api.storage.local.get("sse_rules").then(result => {
      sendResponse({ rules: result.sse_rules || [] });
    });
    return true;
  }

  if (msg.type === "GET_IDENTITY_MAP") {
    api.storage.local.get("sse_identity_map").then(result => {
      sendResponse({ identityMap: result.sse_identity_map || {} });
    });
    return true;
  }

  if (msg.type === "GET_OBJECT_MAP") {
    api.storage.local.get("sse_object_maps").then(result => {
      const objectMaps = result.sse_object_maps || {};
      const objectMap = {};
      for (const map of Object.values(objectMaps)) {
        Object.assign(objectMap, map);
      }
      sendResponse({ objectMap, objectMaps });
    });
    return true;
  }

  if (msg.type === "GET_MEMBER_MAP") {
    api.storage.local.get("sse_member_maps").then(result => {
      sendResponse({ memberMaps: result.sse_member_maps || {} });
    });
    return true;
  }

  // On-demand membership resolve for a single group/list. Used by the
  // dashboard popover's click-to-expand so names/members are fetched when
  // the user actually opens a group instead of relying on a stale prefetch.
  if (msg.type === "RESOLVE_MEMBERS") {
    const kind = msg.kind;
    const id = msg.id !== undefined && msg.id !== null ? String(msg.id) : "";
    if (!kind || !id || !MEMBERSHIP_CONFIG[kind]) {
      sendResponse({ ok: false, error: "unknown group kind", members: [], name: id });
      return true;
    }
    (async () => {
      try {
        const stored = await api.storage.local.get(["sse_member_maps", "cached_org_id"]);
        const maps = stored.sse_member_maps || {};
        const cached = getCachedMembers(maps, kind, id);
        if (cached) {
          sendResponse({
            ok: true,
            name: cached.name || id,
            members: cached.members,
            cached: true,
            debug: { kind, id, source: "cache", memberCount: (cached.members || []).length, members: cached.members },
          });
          return;
        }
        const orgId = stored.cached_org_id || await getActiveOrgId().catch(() => null);
        if (!orgId) {
          sendResponse({ ok: false, error: "no org", name: id, members: [], debug: { kind, id, error: "no org" } });
          return;
        }
        const tabId = await getMembershipTabId(msg.tabId || (sender && sender.tab && sender.tab.id));
        const fresh = await resolveOneMembership(kind, id, orgId, tabId);
        sendResponse({
          // resolved:false means the fetch failed (token, network, API), not
          // an empty group — let the page show a retry instead of "empty".
          ok: fresh.resolved !== false,
          name: fresh.name || id,
          members: fresh.members || [],
          cached: false,
          debug: fresh.debug || { kind, id, source: "fetch", members: fresh.members },
        });
      } catch (err) {
        sendResponse({ ok: false, error: err.message, members: [], name: id });
      }
    })();
    return true;
  }

  if (msg.type === "LOOKUP_DESTINATION") {
    lookupDestination(String(msg.host || ""), sender && sender.tab && sender.tab.id, msg.orgId)
      .then((result) => sendResponse(result))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "GET_IDENTITY_TYPE_MAP") {
    api.storage.local.get("sse_identity_type_map").then(result => {
      sendResponse({ identityTypeMap: result.sse_identity_type_map || {} });
    });
    return true;
  }
});

// ---------------------------------------------------------------------------
// Periodic refresh alarm — refetches all data every REFRESH_INTERVAL_MIN
// minutes to keep it fresh. Scheduled by fetchAllData() after each success.
// ---------------------------------------------------------------------------

api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === REFRESH_ALARM) {
    logEvent("alarm", "Periodic refresh triggered");
    fetchAllData().catch(err => {
      logEvent("alarm", "fetchAllData failed", { error: err.message });
    });
  }
});

// Also schedule a refresh on SW startup in case the alarm was lost
// (alarms don't survive browser restart in MV3).
api.runtime.onInstalled.addListener(() => {
  api.alarms.get(REFRESH_ALARM).then(alarm => {
    if (!alarm) {
      api.storage.local.get(["sse_token", "mgmt_authz_token", "opendns_token"]).then(data => {
        if (data.sse_token || data.mgmt_authz_token || data.opendns_token) {
          logEvent("sw-startup", "Found tokens on startup — scheduling refresh + fetch");
          api.alarms.create(REFRESH_ALARM, { delayInMinutes: REFRESH_INTERVAL_MIN });
          _scheduleFetch();
        }
      });
    }
  });
});
