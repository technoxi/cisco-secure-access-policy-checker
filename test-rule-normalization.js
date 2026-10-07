#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const fixture = {
  ruleId: 2875533,
  ruleName: "SaaS Advanced Controls",
  rulePriority: 1,
  ruleAction: "allow",
  ruleIsEnabled: true,
  ruleIsDefault: false,
  ruleAccess: "public_internet",
  ruleConditions: [
    { attributeId: 2, attributeName: "umbrella.source.identity_ids", attributeOperator: "INTERSECT", attributeValue: [679318559] },
    { attributeId: 7, attributeName: "umbrella.destination.application_ids", attributeOperator: "INTERSECT", attributeValue: [258] },
  ],
};

async function main() {
  const listener = { addListener() {} };
  const chrome = {
    runtime: { id: "test", onInstalled: listener, onStartup: listener, onMessage: listener },
    storage: { local: { async get() { return {}; }, async set() {} }, session: { async get() { return {}; }, async set() {} } },
    tabs: { onUpdated: listener },
    alarms: { onAlarm: listener, create() {}, async get() {} },
    webRequest: { onBeforeSendHeaders: listener },
    scripting: { async executeScript() {} },
  };
  const sandbox = {
    chrome, console, Date, Map, Set, Promise, URL, setTimeout, clearTimeout,
    importScripts() {}, SecDebugLog: { logEvent() {}, redactToken() { return {}; } },
  };
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync("extension/background/service-worker.js", "utf8"), sandbox);
  const matcherContext = { window: { IPAddress: require("./extension/popup/ip-address.js") }, console };
  vm.createContext(matcherContext);
  vm.runInContext(fs.readFileSync("extension/popup/matcher.js", "utf8"), matcherContext);
  const { Matcher } = matcherContext.window;
  const canonical = fixture.ruleConditions;
  const cases = [
    ["canonical populated, legacy empty", { ruleConditions: canonical, conditions: [] }, canonical],
    ["canonical empty, legacy populated", { ruleConditions: [], conditions: canonical }, []],
    ["legacy only", { ruleConditions: undefined, conditions: canonical }, canonical],
    ["malformed canonical fallback", { ruleConditions: {}, conditions: canonical }, canonical],
    ["both malformed", { ruleConditions: "invalid", conditions: {} }, []],
    ["both absent", { ruleConditions: undefined, conditions: undefined }, []],
  ];
  let fetchCount = 0;
  for (const defaultOnly of [false, true]) {
    for (const [label, fields, expected] of cases) {
      const raw = { ...fixture, ...fields, ruleIsDefault: defaultOnly };
      sandbox.fetch = async url => {
        fetchCount++;
        const defaults = new URL(url).searchParams.get("ruleIsDefault") === "true";
        return { ok: true, status: 200, async json() { return { results: defaults === defaultOnly ? [raw] : [] }; } };
      };
      const result = await vm.runInContext('fetchRules("test-token", "8176184")', sandbox);
      assert.equal(result.rules.length, 1, label);
      assert.equal(result.defaultRuleFetch.error, defaultOnly ? null : "Response contained no default rules");
      const normalized = result.rules[0];
      assert.deepEqual(JSON.parse(JSON.stringify(normalized.conditions)), expected, label);
      assert.equal(normalized.id, 2875533);
      assert.equal(normalized.is_default, defaultOnly);
      for (const trafficStage of ["dns", "web"]) {
        const input = { trafficStage, destination: "example.com", sourceUserId: 679318559, applicationId: 258, ruledOutAll: ["applicationId"] };
        const match = overrides => Matcher.matchPolicy([normalized], { ...input, ...overrides }, {});
        assert.equal(match({}).rule.id, 2875533, `${label}: ${trafficStage} matching source/app`);
        if (expected.length) {
          assert.equal(match({ sourceUserId: 1 }).noMatch, true, `${label}: ${trafficStage} source restriction`);
          assert.equal(match({ applicationId: 999 }).noMatch, true, `${label}: ${trafficStage} app restriction`);
        } else {
          assert.equal(match({ sourceUserId: 1, applicationId: 999 }).rule.id, 2875533, `${label}: ${trafficStage} authoritative empty conditions`);
        }
      }
    }
  }
  assert.equal(fetchCount, 24);
  console.log("fetchRules normalization: 12 cases; rule 2875533 DNS/Web source/app restrictions passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
