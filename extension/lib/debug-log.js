// =============================================================================
// lib/debug-log.js — persistent, structured debug logging.
//
// The service worker's live console disappears every time it goes idle
// (routinely, in MV3), so a console.log-only debugging story is unusable for
// diagnosing intermittent capture/race failures after the fact. This writes
// a ring buffer into chrome.storage.local instead, which survives SW
// idle/wake cycles and is readable from the popup's Debug tab.
//
// Loaded via importScripts() in the service worker and via a <script> tag in
// popup.html — both share the same storage-backed ring buffer. Never logs
// the raw token value, only its length and a short prefix.
// =============================================================================
(function (global) {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const LOG_KEY = "debugLog";
  const MAX_ENTRIES = 200;

  // Serializes writes so concurrent logEvent() calls (e.g. a webRequest
  // capture firing while a RUN_SCAN log is also being written) don't clobber
  // each other via a read-modify-write race on chrome.storage.local.
  let writeQueue = Promise.resolve();

  function isEnabled() {
    return api.storage.local.get({ DEBUG_ENABLED: true }).then((r) => r.DEBUG_ENABLED !== false);
  }

  function logEvent(scope, message, data) {
    writeQueue = writeQueue.then(async () => {
      try {
        const enabled = await isEnabled();
        if (!enabled) return;
        const entry = { timestamp: Date.now(), scope, message, data: data || {} };
        const result = await api.storage.local.get(LOG_KEY);
        const log = Array.isArray(result[LOG_KEY]) ? result[LOG_KEY] : [];
        log.push(entry);
        while (log.length > MAX_ENTRIES) log.shift();
        await api.storage.local.set({ [LOG_KEY]: log });
      } catch (e) {
        // Logging must never throw/break the caller's real work.
        console.error("[debug-log] logEvent failed:", e);
      }
    });
    return writeQueue;
  }

  // Redacts a raw token down to length + a short prefix — never store or log
  // the actual token value here.
  function redactToken(token) {
    if (!token || typeof token !== "string") return { length: 0, prefix: "(none)" };
    return { length: token.length, prefix: token.length >= 6 ? token.slice(0, 6) + "..." : "(short)" };
  }

  global.SecDebugLog = { logEvent, redactToken, LOG_KEY, MAX_ENTRIES };
})(typeof self !== "undefined" ? self : window);
