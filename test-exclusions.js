#!/usr/bin/env node
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const ip = require("./extension/popup/ip-address.js");
globalThis.IPAddress = ip;
const model = require("./extension/popup/traffic-path.js");
const context = vm.createContext({ window: { IPAddress: ip }, console });
vm.runInContext(fs.readFileSync("extension/popup/matcher.js", "utf8"), context);
const matcher = context.window.Matcher;

const exclusions = JSON.parse(fs.readFileSync("extension/data/exclusions-lookup.json", "utf8"));
const catalogs = {
  exclusions,
  sourceUsers: { 7: "Denise Adams" },
  sourceRoaming: { 9: "Staff Laptop" },
};

const defaultInternet = {
  ruleId: 26, ruleName: "Default Allow Rule", rulePriority: 26, ruleAction: "allow",
  ruleIsEnabled: true, trafficScope: "public_internet",
  ruleConditions: [
    { attributeName: "umbrella.source.all", attributeOperator: "=", attributeValue: true },
    { attributeName: "umbrella.destination.all", attributeOperator: "=", attributeValue: true },
  ],
};

// 1. Remote Access VPN with unconstrained (blank) source
{
  const built = model.buildRequest({
    connection: "vpn",
    sources: {},
    destination: "10.141.46.1",
    port: "443",
    protocol: "TCP"
  }, catalogs);
  assert.ok(!built.error, "VPN with no source should succeed without error");
  assert.equal(built.request.identities[0].label, "Any source");
  assert.equal(built.request.identities[0].id, undefined);

  // Evaluate against default rule
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.notEqual(evaluation.outcome.title, "Source IP needed for candidate rule");
}

// 2. Exclusion: Bypass Secure Access (e.g. ninjarmm.com)
{
  const built = model.buildRequest({
    connection: "client",
    sources: { roaming: "sourceRoaming:9" },
    destination: "ninjarmm.com"
  }, catalogs);
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.equal(evaluation.outcome.status, "bypassed");
  assert.match(evaluation.outcome.title, /Bypassed via Traffic Steering/);
  assert.equal(evaluation.stages[0].state, "bypassed");
  assert.equal(evaluation.stages[1].state, "bypassed");
  assert.match(evaluation.stages[0].reason, /ninjarmm\.com/);
}

// 3. Exclusion: Bypass Web Proxy only (e.g. api.us-2.crowdstrike.com)
{
  const built = model.buildRequest({
    connection: "client",
    sources: { roaming: "sourceRoaming:9" },
    destination: "api.us-2.crowdstrike.com"
  }, catalogs);
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.equal(evaluation.stages[0].state, "matched");
  assert.equal(evaluation.stages[0].match.rule.ruleName, "Default Allow Rule");
  assert.equal(evaluation.stages[1].state, "bypassed");
  assert.match(evaluation.stages[1].reason, /Bypass Web Proxy/);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.outcome.stage, "dns");
}

// 4. Exclusion wildcard: *halcyon.ai
{
  const built = model.buildRequest({
    connection: "client",
    sources: { roaming: "sourceRoaming:9" },
    destination: "sub.halcyon.ai"
  }, catalogs);
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.equal(evaluation.stages[1].state, "bypassed");
  assert.match(evaluation.stages[1].reason, /halcyon\.ai/);
}

// 5. Non-excluded destination (e.g. yahoo.com)
{
  const built = model.buildRequest({
    connection: "client",
    sources: { roaming: "sourceRoaming:9" },
    destination: "yahoo.com"
  }, catalogs);
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.stages[0].state, "matched");
  assert.equal(evaluation.stages[1].state, "matched");
}

// 6. matchExclusion export and RFC-1918 private IP matching
{
  assert.equal(typeof model.matchExclusion, "function");
  const defaultLocal = [
    { id: "default-rfc1918", domain: "RFC-1918", intent: "Bypass Secure Access" },
    { id: "default-local", domain: "local", intent: "Bypass Secure Access" },
  ];
  const matchedRfc = model.matchExclusion("10.50.1.20", defaultLocal);
  assert.ok(matchedRfc, "RFC-1918 private IP should match RFC-1918 exclusion");
  assert.equal(matchedRfc.intent, "Bypass Secure Access");
  const matchedLocal = model.matchExclusion("printer.local", defaultLocal);
  assert.ok(matchedLocal, ".local domain should match local exclusion");
}

// 7. Category API lookup failure does not block exception evaluation
{
  const built = model.buildRequest({
    connection: "client",
    sources: { roaming: "sourceRoaming:9" },
    destination: "api.us-2.crowdstrike.com",
    facts: {}
  }, catalogs);
  const earlyExclusion = model.matchExclusion(built.request.destination.host, catalogs.exclusions);
  assert.ok(earlyExclusion);
  assert.equal(earlyExclusion.intent, "Bypass Web Proxy");
  const lookupFailed = { ok: false, error: "category API failed" };
  const evaluation = model.evaluate(built.request, [defaultInternet], catalogs, matcher);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.stages[1].state, "bypassed");
}

console.log("PASS exclusion list and unconstrained VPN evaluations");
