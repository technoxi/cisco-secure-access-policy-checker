#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const vm = require("vm");
const context = { window: { IPAddress: require("./extension/popup/ip-address.js") }, console, Array, String, Object, JSON, Math, Set, RegExp, parseInt, isNaN };
vm.createContext(context);
vm.runInContext(fs.readFileSync("extension/popup/matcher.js", "utf8"), context);
const { Matcher } = context.window;

function condition(attributeName, attributeOperator, attributeValue) {
  return { attributeName, attributeOperator, attributeValue };
}
function rule(id, name, scope, conditions, priority = id) {
  return { id, name, enabled: true, action: "allow", order: priority, trafficScope: scope, conditions };
}
function mustMatch(rules, input, lookups, id, label) {
  const result = Matcher.matchPolicy(rules, input, lookups);
  assert(!result.noMatch, `${label}: expected a match; got ${JSON.stringify(result.rejected)}`);
  assert.strictEqual(result.rule.id, id, `${label}: wrong rule`);
}

const sourceAll = condition("umbrella.source.all", "=", true);
const destinationAll = condition("umbrella.destination.all", "=", true);
const lookups = { sourceIdentityTypeIds: { "42": 7, "644963088": 40 } };

// HAR rule #1 shape: exact source identity and Private Resource.
const hrPrivate = rule(2737575, "Enterprise Browser - HR Private App", "private_network", [
  condition("umbrella.source.identity_ids", "INTERSECT", [42]),
  condition("umbrella.destination.private_resource_ids", "IN", [8627]),
], 1);
mustMatch([hrPrivate], { sourceUserId: 42, privateResourceId: 8627 }, lookups, 2737575, "private resource infers Private Access");

// HAR default rule shape: public FQDN is Internet; explicit visible label also works.
const internetDefault = { ...rule(27803, "For all Internet access", "public_internet", [sourceAll, destinationAll], 0), is_default: true };
mustMatch([internetDefault], { destination: "cisco.com" }, lookups, 27803, "domain infers Internet");
mustMatch([internetDefault], { destination: "cisco.com", destinationScope: "Internet" }, lookups, 27803, "Internet label normalizes");

// Internet app scope inference must work through the public policy selection API.
const internetAppRule = rule(6500000, "Internet app policy", "public_internet", [
  sourceAll, condition("umbrella.destination.application_ids", "INTERSECT", [6500000]),
], 4);
mustMatch([internetAppRule], { sourceUserId: 42, applicationId: 6500000 }, lookups, 6500000,
  "Internet Application infers Internet scope");

const privateAppRule = rule(6500001, "Private app policy", "private_network", [
  sourceAll, condition("umbrella.destination.application_ids", "INTERSECT", [6500000]),
], 5);
const wrongScope = Matcher.matchPolicy([privateAppRule], { applicationId: 6500000 }, lookups);
assert(wrongScope.noMatch && /test resolved to public_internet/.test(wrongScope.rejected[0].reason),
  "Internet Application must not match a Private Access rule");

const adUsers = rule(732519, "AD user policy", "public_internet", [
  condition("umbrella.source.identity_type_ids", "INTERSECT", [7]), destinationAll,
], 3);
mustMatch([adUsers], { sourceUserId: 42, destination: "example.com" }, lookups, 732519, "identity catalog type matches rule type");

// The display layer must retain a known identity name even while a catalog
// refresh has not yet supplied its type link.
const namedIdentityRule = rule(6500002, "Named identity policy", "public_internet", [
  condition("umbrella.source.identity_ids", "INTERSECT", [42]), destinationAll,
], 6);
const namedIdentityResult = Matcher.matchPolicy(
  [namedIdentityRule],
  { sourceUserId: 42, destination: "example.com" },
  { identities: { "42": "Carol Freeman" }, sourceIdentityTypeIds: {} }
);
assert(!namedIdentityResult.noMatch,
  "known identity remains matchable while its type link is being refreshed");

const exactIp = rule(831480, "Exact IP", "public_internet", [
  sourceAll,
  condition("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["8.8.8.8"], port: ["1-65535"], protocol: "ICMP" }]),
], 2);
const ipMiss = Matcher.matchPolicy([exactIp], { destination: "8.8.8.80", destinationScope: "Internet" }, lookups);
assert(ipMiss.noMatch, "literal IP near-miss must not match");

// A no-match returns inspectable per-rule reasons instead of a silent null.
const trace = Matcher.matchPolicy([hrPrivate], { sourceUserId: 99, privateResourceId: 8627 }, lookups);
assert(trace.noMatch && trace.rejected.length === 1 && /identity_ids/.test(trace.rejected[0].reason), "no-match exposes condition trace");

// Source picker options are identity IDs, never destination catalog IDs.
assert.deepStrictEqual([...Matcher.getIdentityOptions([hrPrivate])], ["42"], "identity options contain source IDs");

console.log("policy regression tests passed");
