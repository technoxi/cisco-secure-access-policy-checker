#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

async function main() {
  const messages = [];
  const requests = [];
  const listeners = {};
  const csrfToken = "csrf-test-value";
  class FakeXHR {
    open() {}
    setRequestHeader() {}
    send() {}
    addEventListener() {}
  }
  const window = {
    location: { origin: "https://dashboard.sse.cisco.com", href: "https://dashboard.sse.cisco.com/org/8176184/secure/policy" },
    postMessage(message) { messages.push(message); },
    addEventListener(type, listener) { listeners[type] = listener; },
    fetch: async (url, options = {}) => {
      requests.push({ url: String(url), options });
      if (String(url) === "/token" || String(url) === "https://dashboard.sse.cisco.com/token") {
        return { ok: true, status: 200, async json() { return { token: "signed-dashboard-assertion" }; }, clone() { return this; }, async text() { return JSON.stringify({ token: "signed-dashboard-assertion" }); } };
      }
      if (String(url).includes("jwt-bearer/token")) {
        return { ok: true, status: 200, async json() { return { access_token: "org-investigate-token", expires_in: 300 }; }, clone() { return this; }, async text() { return JSON.stringify({ access_token: "org-investigate-token", expires_in: 300 }); } };
      }
      if (String(url).includes("/domains/categorization/")) {
        return { ok: true, status: 200, async json() { return { "google.com": { content_categories: ["2"], security_categories: [] } }; }, clone() { return this; }, async text() { return "{}"; } };
      }
      if (String(url).includes("/get-casi-data")) {
        return { ok: false, status: 404, async json() { return {}; }, clone() { return this; }, async text() { return "null"; } };
      }
      if (String(url).includes("/classifiers")) {
        return { ok: true, status: 200, async json() { return { securityCategories: ["Malware"] }; }, clone() { return this; }, async text() { return "{}"; } };
      }
      return { ok: true, status: 200, async json() { return {}; }, clone() { return this; }, async text() { return "{}"; } };
    },
  };
  const emptyStorage = { length: 0, key() { return null; }, getItem() { return null; } };
  const sandbox = {
    window,
    XMLHttpRequest: FakeXHR,
    sessionStorage: emptyStorage,
    localStorage: emptyStorage,
    atob,
    URL,
    URLSearchParams,
    Date,
    Promise,
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync("extension/content/token-sniffer.js", "utf8"), sandbox);

  await window.fetch("https://dashboard.sse.cisco.com/token", {
    headers: { "X-CSRF-TOKEN": csrfToken },
  });
  await window.fetch("https://investigate.umbrella.com/domains/categorization/google.com", {
    headers: { Authorization: "Bearer ui-session-token" },
  });
  const uiToken = messages.find(message => message.type === "TOKEN_CAPTURED");
  assert.ok(uiToken);
  assert.equal(uiToken.tokenKey, "mgmt_authz_token");
  assert.equal(uiToken.token, "ui-session-token");

  const request = requests.find(item => item.url === "https://dashboard.sse.cisco.com/token");
  assert.equal(request.options.headers["X-CSRF-TOKEN"], csrfToken);
  listeners.message({
    source: window,
    origin: window.location.origin,
    data: { __secPolicyChecker: true, type: "REQUEST_INVESTIGATE_LOOKUP", requestId: "req-test", host: "google.com", orgId: "8176184" },
  });
  await new Promise(resolve => setTimeout(resolve, 0));
  const reply = messages.find(message => message.type === "INVESTIGATE_PAGE_LOOKUP_REPLY");
  assert.ok(reply && reply.result);
  assert.deepEqual(Array.from(reply.result.contentBits), ["2"]);
  assert.deepEqual(Array.from(reply.result.securityNames), ["Malware"]);
  const exchange = requests.find(item => item.url.includes("jwt-bearer/token"));
  assert.equal(exchange.options.method, "POST");
  const form = new URLSearchParams(exchange.options.body);
  assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
  assert.equal(form.get("assertion"), "signed-dashboard-assertion");
  assert.equal(form.get("scope"), "org/8176184");
  assert.ok(!messages.some(message => message.token === "org-investigate-token"), "org-scoped token never leaves the page context");
  assert.equal(reply.assertion, undefined);
  assert.equal(reply.token, undefined);

  console.log("Dashboard-scoped JWT exchange and Investigate lookup: passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
