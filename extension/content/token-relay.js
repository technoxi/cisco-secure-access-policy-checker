// =============================================================================
// content/token-relay.js — ISOLATED-world content script (default world).
//
// Bridges content/token-sniffer.js (MAIN world, no chrome.* API access) to
// the service worker. Two responsibilities:
//
//   1. Listen for TOKEN_CAPTURED postMessages pushed from the MAIN-world
//      patch and forward them via chrome.runtime.sendMessage.
//   2. Answer REQUEST_TOKEN_CHECK messages FROM the service worker (used by
//      RUN_SCAN's expiry handling when its stored token is missing/stale) by
//      asking the MAIN-world script for its last-seen token and relaying
//      the reply back.
//
// Same document_start timing as token-sniffer.js so the message listener is
// registered before the page's own scripts start firing requests.
//
// MULTI-TOKEN NOTE: token-sniffer.js now tracks three independently-aged
// tokens (sse_token, mgmt_authz_token, opendns_token — see the comment at
// the top of that file for why). Every message here carries a tokenKey so
// the service worker's REQUEST_TOKEN_CHECK can ask for a specific one
// instead of "the" token, and TOKEN_CAPTURED relays tag which one fired.
// =============================================================================
(function () {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const MSG_NS = "__secPolicyChecker";
  const REQUEST_TIMEOUT_MS = 500;
  const INVESTIGATE_LOOKUP_TIMEOUT_MS = 45000;

  const pendingRequests = new Map(); // requestId -> resolver

  function extensionContextAlive() {
    try { return Boolean(api.runtime && api.runtime.id); } catch (_) { return false; }
  }

  function relayCapturedToken(data, captureTime) {
    // Content scripts injected before a reload retain the old extension
    // context. Chrome throws "Extension context invalidated" for both
    // runtime messaging and storage in that state; do not surface it as an
    // uncaught dashboard error. A page reload installs the current relay.
    if (!extensionContextAlive()) return;
    try {
      api.runtime.sendMessage(
        {
          type: "TOKEN_CAPTURED",
          tokenKey: data.tokenKey,
          token: data.token,
          source: "main-world-patch",
          capturedAt: captureTime,
        },
        () => { void api.runtime.lastError; }
      );
      Promise.resolve(api.storage.local.set({
        [data.tokenKey]: { token: data.token, capturedAt: captureTime, source: "main-world-patch" }
      })).catch(() => {});
    } catch (_) {
      // The context may be invalidated between the check and this call.
    }
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    if (event.origin !== window.location.origin) return;
    const data = event.data;
    if (!data || data[MSG_NS] !== true) return;

    if (data.type === "TOKEN_CAPTURED") {
      // Write directly to chrome.storage.local so tokens persist even when
      // the MV3 service worker is asleep/terminated. This is the "always on
      // lookout" path: the relay runs in the isolated world, has full
      // chrome.* API access, and writes tokens the moment the MAIN-world
      // sniffer catches one — no SW wake needed. Also sends via
      // runtime.sendMessage as a live-forward for any actively-awake SW.
      const captureTime = data.capturedAt || Date.now();
      relayCapturedToken(data, captureTime);
      return;
    }

    if (data.type === "LAST_TOKEN_REPLY" || data.type === "PROACTIVE_FETCH_REPLY") {
      const resolve = pendingRequests.get(data.requestId);
      if (resolve) {
        pendingRequests.delete(data.requestId);
        resolve({ token: data.token, capturedAt: data.capturedAt, error: data.error });
      }
      return;
    }

    if (data.type === "INVESTIGATE_PAGE_LOOKUP_REPLY") {
      const resolve = pendingRequests.get(data.requestId);
      if (resolve) {
        pendingRequests.delete(data.requestId);
        resolve(data.result ? { result: data.result } : { error: data.error || "Investigate lookup failed" });
      }
    }
  });

  api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "LOOKUP_DESTINATION_IN_PAGE") {
      const requestId = `investigate_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const timeout = setTimeout(() => {
        pendingRequests.delete(requestId);
        sendResponse({ error: "Investigate lookup timed out" });
      }, INVESTIGATE_LOOKUP_TIMEOUT_MS);
      pendingRequests.set(requestId, (result) => {
        clearTimeout(timeout);
        sendResponse(result);
      });
      window.postMessage({
        [MSG_NS]: true,
        type: "REQUEST_INVESTIGATE_LOOKUP",
        requestId,
        host: msg.host,
        orgId: msg.orgId,
      }, window.location.origin);
      return true;
    }

    if (msg.type === "REQUEST_TOKEN_CHECK") {
      const requestId = `req_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const timeout = setTimeout(() => {
        pendingRequests.delete(requestId);
        sendResponse({ token: null, capturedAt: null });
      }, REQUEST_TIMEOUT_MS);

      pendingRequests.set(requestId, (result) => {
        clearTimeout(timeout);
        sendResponse(result);
      });

      window.postMessage(
        { [MSG_NS]: true, type: "REQUEST_LAST_TOKEN", requestId, tokenKey: msg.tokenKey },
        window.location.origin
      );
      return true;
    }

    if (msg.type === "PROACTIVE_FETCH_TOKEN") {
      // Proactive fetch: ask the MAIN-world script to fire a fetch to the
      // given URL so the dashboard's auth interceptor attaches the Bearer
      // header (captured by our fetch/XHR patch).
      const requestId = `pro_${Date.now()}_${Math.random().toString(36).slice(2)}`;
      const timeout = setTimeout(() => {
        pendingRequests.delete(requestId);
        sendResponse({ token: null, capturedAt: null, error: "timeout" });
      }, 10000); // 10s timeout — fetch + auth can take a moment

      pendingRequests.set(requestId, (result) => {
        clearTimeout(timeout);
        sendResponse(result);
      });

      window.postMessage(
        {
          [MSG_NS]: true, type: "PROACTIVE_FETCH_TOKEN",
          requestId, tokenKey: msg.tokenKey, url: msg.url,
        },
        window.location.origin
      );
      return true;
    }
  });
})();
