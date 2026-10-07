// =============================================================================
// content/token-sniffer.js — MAIN-world content script.
//
// Runs at document_start, in the PAGE's own JS realm (manifest.json:
// "world": "MAIN") — not the extension's isolated world. This is why it
// can't lose the cold-start race against the MV3 service worker waking up:
// it patches window.fetch / XMLHttpRequest synchronously as the page's own
// scripts start running, before the SPA has fired its first authenticated
// request, regardless of whether the service worker's webRequest listener
// has re-registered yet.
//
// MAIN-world scripts have NO chrome.* API access — cannot call
// chrome.storage or chrome.runtime.sendMessage directly. Captured tokens are
// relayed via window.postMessage() to content/token-relay.js, an
// ISOLATED-world script (default world) also injected at document_start,
// which forwards them into extension messaging.
//
// Also exposes an on-demand "what's the last token you saw" query (see the
// REQUEST_LAST_TOKEN handler below), used by service-worker.js's RUN_SCAN
// handler when its own stored token is missing/stale — this covers the case
// where a request fired very recently but the async postMessage->
// sendMessage->storage.session.set chain hasn't finished propagating yet.
//
// MULTI-TOKEN NOTE (identity resolution, added after the initial race fix):
// Cisco's dashboard mints separate, differently-scoped Bearer tokens per API
// host, confirmed live against org 8176184:
//   - api.sse.cisco.com / api.umbrella.com -> "sse_token" (original path)
//   - management.api.umbrella.com          -> "mgmt_authz_token"
//     (issuer "umbrella-authz/authsvc", scope "role:root-readonly", ~5min TTL
//     — used for both all_tag_identities/security_group_tag and
//     all_tag_identities/catalyst_sdwan; same token serves both, confirmed by
//     comparing the two captured JWTs byte-for-byte)
//   - api.opendns.com                      -> "opendns_token"
//     (aud "https://api.opendns.com/v3/", only ~60s TTL — used for
//     v3/organizations/{orgId}/internalnetworks)
// api.sse.cisco.com's networkTunnelGroupsAndBranches endpoint (branch/tunnel
// identities for private-access rules) reuses the existing sse_token — no
// new host/token needed for that one.
// HOST_TOKEN_MAP below is what tags each capture with the right tokenKey so
// service-worker.js can store/serve them as independent, separately-aged
// tokens instead of clobbering one shared value.
// =============================================================================
(function () {
  const HOST_TOKEN_MAP = [
    { pattern: /^https:\/\/(management\.api\.umbrella\.com|investigate\.umbrella\.com)\//, tokenKey: "mgmt_authz_token" },
    { pattern: /^https:\/\/api\.opendns\.com\//, tokenKey: "opendns_token" },
    // Checked last: broadest pattern, and management.api.umbrella.com would
    // also match a naive /umbrella\.com/ regex, so host-specific entries
    // above must be checked first.
    { pattern: /^https:\/\/(api\.sse\.cisco\.com|api\.umbrella\.com)\//, tokenKey: "sse_token" },
  ];
  const MSG_NS = "__secPolicyChecker";

  const lastTokens = Object.create(null); // tokenKey -> { token, capturedAt }
  let dashboardCsrfToken = null;
  const dashboardInvestigateTokens = new Map();

  function relay(tokenKey, token) {
    lastTokens[tokenKey] = { token, capturedAt: Date.now() };
    window.postMessage(
      {
        [MSG_NS]: true,
        type: "TOKEN_CAPTURED",
        tokenKey,
        token,
        capturedAt: lastTokens[tokenKey].capturedAt,
      },
      window.location.origin
    );
  }

  function matchTokenKey(url) {
    if (typeof url !== "string") return null;
    for (const entry of HOST_TOKEN_MAP) {
      if (entry.pattern.test(url)) return entry.tokenKey;
    }
    return null;
  }

  function maybeCapture(url, authHeaderValue) {
    if (!authHeaderValue || typeof authHeaderValue !== "string") return;
    if (!authHeaderValue.startsWith("Bearer ")) return;
    const tokenKey = matchTokenKey(url);
    if (!tokenKey) return;
    relay(tokenKey, authHeaderValue.slice(7));
  }

  // ---------------------------------------------------------------------
  // Response-body token capture — intercept token-minting endpoints
  //
  // The dashboard mints fresh tokens from its own backend on every page
  // load. The minting endpoints return tokens in RESPONSE bodies, and the
  // POST endpoints (jwt-bearer/token) carry NO Authorization header —
  // they authenticate via session cookies only. Our request-header sniffer
  // can't see those. This patch chains onto fetch responses and XHR
  // onload to extract tokens from the response body.
  //
  // Endpoint → token mapping (confirmed from live intercept):
  //   GET  dashboard.sse.cisco.com/token       → { token: "..." }         → opendns_token
  //   GET  dashboard.sse.cisco.com/piamtoken    → { piam_access_token: "" } → (stored for reference)
  //   POST management.api.umbrella.com/.../jwt-bearer/token → { access_token: "" } → mgmt_authz_token
  //   POST api.sse.cisco.com/.../jwt-bearer/token          → { access_token: "" } → sse_token
  // ---------------------------------------------------------------------
  function isTokenMintUrl(url) {
    if (!url || typeof url !== "string") return false;
    return (
      /dashboard\.sse\.cisco\.com\/token(?:\?|$)/.test(url) ||
      /dashboard\.sse\.cisco\.com\/piamtoken(?:\?|$)/.test(url) ||
      /\/auth\/v2\/(?:oauth2\/)?jwt-bearer\/token(?:\?|$)/.test(url)
    );
  }

  function captureFromBody(url, bodyText) {
    try {
      const body = typeof bodyText === "string" ? JSON.parse(bodyText) : bodyText;
      if (!body || typeof body !== "object") return;

      // dashboard.sse.cisco.com/token → OpenDNS JWT (~60s TTL)
      if (/dashboard\.sse\.cisco\.com\/token(?:\?|$)/.test(url) && body.token) {
        relay("opendns_token", body.token);
      }

      // dashboard.sse.cisco.com/piamtoken → PIAM token (DashX context only)
      // NOT relayed as sse_token — the extension needs the management JWT
      // for api.umbrella.com/api.sse.cisco.com/deployments calls, and the
      // PIAM token would overwrite it. The PIAM token is already captured
      // from request headers by the existing maybeCapture() path.

      // POST .../jwt-bearer/token → Management JWT or SSE admin JWT
      if (/\/auth\/v2\/(?:oauth2\/)?jwt-bearer\/token(?:\?|$)/.test(url) && body.access_token) {
        if (/management\.api\.umbrella\.com/.test(url)) {
          relay("mgmt_authz_token", body.access_token);
        } else if (/api\.sse\.cisco\.com/.test(url)) {
          relay("sse_token", body.access_token);
        }
      }
    } catch (e) { /* not JSON or parse error — ignore */ }
  }

  // ---------------------------------------------------------------------
  // fetch() patch
  // ---------------------------------------------------------------------
  const origFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === "string" ? input : (input && input.url) || "";
      let authHeader = null;
      if (init && init.headers) {
        if (typeof Headers !== "undefined" && init.headers instanceof Headers) {
          authHeader = init.headers.get("Authorization") || init.headers.get("authorization");
        } else if (typeof init.headers === "object") {
          const key = Object.keys(init.headers).find((k) => k.toLowerCase() === "authorization");
          if (key) authHeader = init.headers[key];
        }
      } else if (typeof Request !== "undefined" && input instanceof Request) {
        authHeader = input.headers.get("Authorization");
      }
      maybeCapture(url, authHeader);
      const requestHeaders = init && init.headers || (typeof Request !== "undefined" && input instanceof Request ? input.headers : null);
      try {
        const requestUrl = new URL(url, window.location.href);
        if (requestUrl.hostname === "dashboard.sse.cisco.com" && requestUrl.pathname === "/token" && requestHeaders) {
          let csrf = null;
          if (typeof Headers !== "undefined" && requestHeaders instanceof Headers) {
            csrf = requestHeaders.get("X-CSRF-TOKEN");
          } else {
            const key = Object.keys(requestHeaders).find((name) => name.toLowerCase() === "x-csrf-token");
            if (key) csrf = requestHeaders[key];
          }
          if (typeof csrf === "string" && csrf) dashboardCsrfToken = csrf;
        }
      } catch (_) {}

      // Response-body capture for token-minting endpoints
      if (isTokenMintUrl(url)) {
        const result = origFetch.apply(this, arguments);
        result.then(async (response) => {
          try {
            const cloned = response.clone();
            const text = await cloned.text();
            captureFromBody(url, text);
          } catch (e) {}
        }).catch(() => {});
        return result;
      }
    } catch (e) {
      // Never let capture-side errors break the page's real fetch call.
    }
    return origFetch.apply(this, arguments);
  };

  // ---------------------------------------------------------------------
  // XMLHttpRequest patch
  // ---------------------------------------------------------------------
  const origOpen = XMLHttpRequest.prototype.open;
  const origSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
  const origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__secPolicyCheckerUrl = url;
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
    try {
      if (name && name.toLowerCase() === "authorization") {
        this.__secPolicyCheckerAuth = value;
      }
    } catch (e) {}
    return origSetRequestHeader.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function () {
    try {
      maybeCapture(this.__secPolicyCheckerUrl, this.__secPolicyCheckerAuth);
    } catch (e) {}
    // Response-body capture for token-minting endpoints (XHR path)
    const _url = this.__secPolicyCheckerUrl;
    if (isTokenMintUrl(_url)) {
      this.addEventListener("load", function () {
        try { captureFromBody(_url, this.responseText); } catch (e) {}
      });
    }
    return origSend.apply(this, arguments);
  };

  // ---------------------------------------------------------------------
  // PROACTIVE_FETCH_TOKEN — scan the page's sessionStorage / localStorage
  // for cached JWT tokens from the SPA, rather than trying to make a fetch
  // (which the SPA's module-scoped auth interceptor/wrapper wouldn't
  // attach its Bearer header to anyway since it uses its own fetch ref).
  //
  // The Cisco dashboard SPA caches Bearer tokens in the browser's storage
  // (sessionStorage being the most common). Our MAIN-world script can read
  // those directly — no network call needed, no dependence on the SPA's
  // fetch interceptor.
  //
  // We scan all storage keys, find strings that look like JWTs, decode the
  // payload to match them against the host patterns in HOST_TOKEN_MAP via
  // the JWT's `aud` or `iss` claim, and return the one the caller asked for.
  //
  // This is the "smart" proactive path: instead of waiting for the user to
  // visit the right dashboard page, we read tokens that already exist in
  // the page's storage from whatever API host calls have already happened.
  // ---------------------------------------------------------------------
  function decodeJWT(token) {
    try {
      const payload = token.split('.')[1];
      if (!payload) return null;
      const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(json);
    } catch (e) { return null; }
  }

  function tokenKeyFromJWT(payload) {
    if (!payload) return null;
    const testStr = (payload.aud || payload.iss || '');
    for (const entry of HOST_TOKEN_MAP) {
      if (entry.pattern.test(testStr)) return entry.tokenKey;
    }
    return null;
  }

  function scanStorageForTokens() {
    const found = {}; // tokenKey -> { token, capturedAt }
    const stores = [sessionStorage, localStorage];
    for (const store of stores) {
      try {
        if (!store) continue;
        for (let i = 0; i < store.length; i++) {
          const key = store.key(i);
          const raw = store.getItem(key);
          if (!raw || typeof raw !== 'string') continue;
          // Direct JWT value
          if (/^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/.test(raw.trim())) {
            const decoded = decodeJWT(raw.trim());
            let tk = tokenKeyFromJWT(decoded);
            // Fallback: match storage key against HOST_TOKEN_MAP (JWT claims
            // like "umbrella-authz/authsvc" don't match URL patterns, but the
            // storage key e.g. "aping_jwt_bearer-...-https://api.sse.cisco.com/..."
            // contains the target URL).
            if (!tk) tk = keyFromHostPattern(key);
            if (tk && !found[tk]) found[tk] = { token: raw.trim(), capturedAt: Date.now() };
          }
          // JSON object containing JWT values
          try {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object') {
              for (const val of Object.values(parsed)) {
                if (typeof val === 'string' && /^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/.test(val.trim())) {
                  const decoded = decodeJWT(val.trim());
                  let tk = tokenKeyFromJWT(decoded);
                  // Same fallback: match the storage key, not just JWT claims
                  if (!tk) tk = keyFromHostPattern(key);
                  if (tk && !found[tk]) found[tk] = { token: val.trim(), capturedAt: Date.now() };
                }
              }
            }
          } catch (e) { /* not JSON */ }
        }
      } catch (e) { /* storage blocked */ }
    }
    return found;
  }

  // Match a storage key against HOST_TOKEN_MAP patterns — the dashboard SPA
  // stores tokens under keys containing the target API URL, e.g.
  // "aping_jwt_bearer-standard-org/8176184-https://api.sse.cisco.com/...".
  // HOST_TOKEN_MAP patterns start with ^https:// so we extract the URL portion
  // from the key (which starts with a prefix like "aping_jwt_bearer-...").
  function keyFromHostPattern(storageKey) {
    const urlStart = storageKey.indexOf("https://");
    if (urlStart === -1) return null;
    const url = storageKey.slice(urlStart);
    for (const entry of HOST_TOKEN_MAP) {
      if (entry.pattern.test(url)) return entry.tokenKey;
    }
    return null;
  }

  // Scan page storage on load — runs on every page the content script
  // loads into, not just the policy page. Proactively relays any cached
  // JWT tokens it finds so the SW has them ready regardless of which
  // dashboard page the user opened first.
  try {
    const autoFound = scanStorageForTokens();
    for (const tk of Object.keys(autoFound)) {
      if (!lastTokens[tk]) relay(tk, autoFound[tk].token);
    }
  } catch (e) {}

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (event.origin !== window.location.origin) return;
    const data = event.data;
    if (!data || data[MSG_NS] !== true) return;

    // REQUEST_LAST_TOKEN — passive: what did we see recently?
    if (data.type === "REQUEST_LAST_TOKEN") {
      let entry = data.tokenKey ? lastTokens[data.tokenKey] : null;
      // Fallback: if in-memory cache missed, scan localStorage NOW — the
      // auto-scan at document_start may have fired before the SPA wrote its
      // tokens into storage, so we re-scan on demand to catch late arrivals.
      if (!entry && data.tokenKey) {
        const fresh = scanStorageForTokens();
        entry = fresh[data.tokenKey] || null;
        if (entry) lastTokens[data.tokenKey] = entry; // warm the cache
      }
      window.postMessage(
        {
          [MSG_NS]: true,
          type: "LAST_TOKEN_REPLY",
          requestId: data.requestId,
          tokenKey: data.tokenKey,
          token: entry ? entry.token : null,
          capturedAt: entry ? entry.capturedAt : null,
        },
        window.location.origin
      );
      return;
    }

    if (data.type === "REQUEST_INVESTIGATE_LOOKUP") {
      (async () => {
        try {
          const host = String(data.host || "").trim().toLowerCase();
          const orgId = String(data.orgId || "");
          if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) || !/^\d+$/.test(orgId)) throw new Error("invalid destination or organization");
          if (!dashboardCsrfToken) throw new Error("dashboard CSRF token unavailable");
          const base = "https://investigate.umbrella.com";
          const encoded = encodeURIComponent(host);
          const getToken = async () => {
            const assertionResponse = await origFetch.call(window, "/token", {
              credentials: "include",
              headers: { Accept: "application/json", "X-CSRF-TOKEN": dashboardCsrfToken },
            });
            if (!assertionResponse.ok) throw new Error(`assertion request returned ${assertionResponse.status}`);
            const assertionBody = await assertionResponse.json();
            if (!assertionBody || typeof assertionBody.token !== "string") throw new Error("dashboard assertion missing");
            const form = new URLSearchParams({
              grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
              assertion: assertionBody.token,
              scope: `org/${orgId}`,
            });
            const tokenResponse = await origFetch.call(window, "https://management.api.umbrella.com/auth/v2/oauth2/jwt-bearer/token", {
              method: "POST",
              credentials: "omit",
              headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8" },
              body: form.toString(),
            });
            if (!tokenResponse.ok) throw new Error(`Investigate token exchange returned ${tokenResponse.status}`);
            const tokenBody = await tokenResponse.json();
            if (!tokenBody || typeof tokenBody.access_token !== "string") throw new Error("Investigate access token missing");
            const expiresIn = Number(tokenBody.expires_in) || 300;
            dashboardInvestigateTokens.set(orgId, { token: tokenBody.access_token, expiresAt: Date.now() + expiresIn * 1000 });
            return tokenBody.access_token;
          };
          const getJson = async (path, token) => {
            const response = await origFetch.call(window, `${base}${path}`, {
              credentials: "omit",
              headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
              referrer: "https://dashboard.sse.cisco.com/",
            });
            return { response, json: response.ok ? await response.json() : null };
          };
          let category;
          for (let attempt = 0; attempt < 2; attempt++) {
            let tokenEntry = dashboardInvestigateTokens.get(orgId);
            if (!tokenEntry || tokenEntry.expiresAt <= Date.now() + 10000) {
              await getToken();
              tokenEntry = dashboardInvestigateTokens.get(orgId);
            }
            category = await getJson(`/domains/categorization/${encoded}?taloscategories=true`, tokenEntry.token);
            if (category.response.status === 403 && attempt === 0) {
              dashboardInvestigateTokens.delete(orgId);
              continue;
            }
            break;
          }
          if (!category || !category.response.ok) throw new Error(`Investigate returned ${category ? category.response.status : "unknown error"}`);
          const entry = category.json && category.json[host] || {};
          const securityBits = (entry.security_categories || []).map(String);
          const [casi, classifiers] = await Promise.all([
            getJson(`/get-casi-data?fqdn=${encoded}`, dashboardInvestigateTokens.get(orgId).token).catch(() => null),
            securityBits.length ? Promise.resolve(null) : getJson(`/url/${encoded}/classifiers`, dashboardInvestigateTokens.get(orgId).token).catch(() => null),
          ]);
          const appData = casi && casi.json;
          const result = {
            ok: true,
            host,
            contentBits: (entry.content_categories || []).map(String),
            securityBits,
            securityNames: classifiers && classifiers.response.ok ? ((classifiers.json || {}).securityCategories || []).map(String) : [],
            app: appData && appData.name && appData.service_type !== "Website" ? { name: String(appData.name), category: appData.category || "" } : null,
          };
          window.postMessage({ [MSG_NS]: true, type: "INVESTIGATE_PAGE_LOOKUP_REPLY", requestId: data.requestId, result }, window.location.origin);
        } catch (error) {
          window.postMessage({ [MSG_NS]: true, type: "INVESTIGATE_PAGE_LOOKUP_REPLY", requestId: data.requestId, error: error.message }, window.location.origin);
        }
      })();
      return;
    }

    // PROACTIVE_FETCH_TOKEN — smart: scan page storage for JWT tokens.
    // The Cisco SPA caches tokens in sessionStorage/locaStorage; our
    // MAIN-world script reads them directly by decoding JWTs and matching
    // their 'aud'/'iss' claims against our host patterns.
    if (data.type === "PROACTIVE_FETCH_TOKEN") {
      const { tokenKey, requestId } = data;
      if (!tokenKey) {
        window.postMessage(
          { [MSG_NS]: true, type: "PROACTIVE_FETCH_REPLY", requestId, error: "missing tokenKey" },
          window.location.origin
        );
        return;
      }

      // 1. Already captured from a live request?
      const fromLast = lastTokens[tokenKey];
      if (fromLast && fromLast.token) {
        window.postMessage(
          { [MSG_NS]: true, type: "PROACTIVE_FETCH_REPLY", requestId, tokenKey,
            token: fromLast.token, capturedAt: fromLast.capturedAt, source: "last-tokens" },
          window.location.origin
        );
        return;
      }

      // 2. Scan sessionStorage/localStorage for JWTs matching this tokenKey
      const allTokens = scanStorageForTokens();
      const fromStorage = allTokens[tokenKey];
      if (fromStorage) {
        relay(tokenKey, fromStorage.token);
        window.postMessage(
          { [MSG_NS]: true, type: "PROACTIVE_FETCH_REPLY", requestId, tokenKey,
            token: fromStorage.token, capturedAt: fromStorage.capturedAt, source: "storage-scan" },
          window.location.origin
        );
        return;
      }

      // 3. Last resort — scan window globals (some SPAs stash tokens here)
      for (const key of Object.keys(window)) {
        try {
          const val = window[key];
          if (typeof val === 'string' && /^[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$/.test(val.trim())) {
            const decoded = decodeJWT(val.trim());
            const tk = tokenKeyFromJWT(decoded);
            if (tk === tokenKey) {
              relay(tokenKey, val.trim());
              window.postMessage(
                { [MSG_NS]: true, type: "PROACTIVE_FETCH_REPLY", requestId, tokenKey,
                  token: val.trim(), capturedAt: Date.now(), source: "window-scan" },
                window.location.origin
              );
              return;
            }
          }
        } catch (e) {}
      }

      window.postMessage(
        { [MSG_NS]: true, type: "PROACTIVE_FETCH_REPLY", requestId, tokenKey,
          error: "no token found in page storage" },
        window.location.origin
      );
    }
  });
})();
