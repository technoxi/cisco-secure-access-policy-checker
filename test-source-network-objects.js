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
const worker = fs.readFileSync("extension/background/service-worker.js", "utf8");
vm.runInContext(worker.slice(worker.indexOf("function _conditionDimension("), worker.indexOf("function _isCatchAllCondition(")), context);
const [r39, r40, dns] = require("./qa/source-network-rules.json");
const address = value => ({ members: [{ kind: "address", value }], resolved: true });
const lookups = { sourceUsers: { 7: "Test user" }, memberMaps: {
  networkObjects: { 151027: address("10.0.0.0/8"), 151028: address("10.141.195.0/24"), 500288057: address("10.141.197.0/24"), syntheticDnsSubnet: address("192.0.2.0/24") },
  networkObjectGroups: { 500004219: { members: [{ kind: "networkObjects", id: "syntheticDnsSubnet" }], resolved: true } },
  identityGroups: { 99: { members: [{ kind: "identity", id: "7" }], resolved: true } },
} };
const cond = (attributeName, attributeValue) => ({ attributeName, attributeOperator: "IN", attributeValue });
const match = (rules, input) => matcher.matchPolicy(rules, { destinationScope: rules[0].ruleAccess, ...input }, lookups);
for (const suffix of ["networkObjectIds", "networkObjectGroupIds"]) {
  for (const side of ["source", "destination"]) {
    const name = `umbrella.${side}.${suffix}`;
    assert.equal(matcher.conditionDimension(name), side);
    assert.equal(context._conditionDimension(name), side);
  }
}
for (const source of ["", "10.141.195.20", "10.141.197.20"]) {
  assert.equal(match([r39], { source, destination: "10.141.50.10" }).noMatch, true);
}
for (const source of ["10.141.195.20", "10.141.197.20"]) {
  assert.equal(match([r39, r40], { source, destination: "10.141.50.10" }).rule.ruleId, 2022063);
}
assert.equal(match([r39], { source: "10.141.50.10", destination: "10.141.195.20" }).rule.ruleId, 2022066);
assert.equal(match([r40], { source: "10.141.50.10", destination: "10.141.50.10" }).noMatch, true);
for (const [suffix, destKey, srcKey] of [["networkObjectIds", "networkObjectId", "sourceNetworkObjectId"], ["networkObjectGroupIds", "networkObjectGroupId", "sourceNetworkObjectGroupId"]]) {
  const make = side => ({ ruleId: 1, ruleConditions: [cond(`umbrella.${side}.${suffix}`, [123])] });
  assert.equal(match([make("source")], { [destKey]: 123 }).noMatch, true);
  assert.equal(match([make("destination")], { [srcKey]: 123 }).noMatch, true);
  assert.equal(match([make("source")], { [srcKey]: 123 }).rule.ruleId, 1);
  assert.equal(match([make("destination")], { [destKey]: 123 }).rule.ruleId, 1);
}
// DNS group members are synthetic; the uploaded export contains no member definitions.
const dnsInput = { destination: "example.com", categoryListId: 16420305 };
assert.equal(match([dns], dnsInput).noMatch, true);
assert.equal(match([dns], { ...dnsInput, source: "198.51.100.1" }).noMatch, true);
assert.equal(match([dns], { ...dnsInput, source: "192.0.2.7" }).rule.ruleId, 2579644);
assert.equal(match([dns], { ...dnsInput, networkObjectGroupId: 500004219 }).noMatch, true);
assert.equal(match([dns], { ...dnsInput, sourceNetworkObjectGroupId: 500004219 }).rule.ruleId, 2579644);
function evaluate(rules, extra = {}) {
  const built = model.buildRequest({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "10.141.50.10", port: "443", ...extra }, lookups);
  assert.ok(!built.error, built.error);
  return model.evaluate(built.request, rules, lookups, matcher);
}
assert.notEqual(evaluate([r39]).outcome.title, "Source IP needed for candidate rule");
const pending = evaluate([r39, r40]);
assert.equal(pending.outcome.status, "pending");
assert.equal(pending.stages[0].state, "needs-answer");
assert.equal(pending.outcome.rule, r40);
assert.equal(pending.stages[0].match.rule, r40);
assert.equal(model.questionFor(pending.stages[0], "10.141.50.10", lookups), null);
assert.match(pending.outcome.reason, /This rule requires.*source-address constraints/);
const earlier = { ruleId: 2, rulePriority: 1, ruleAction: "allow", ruleAccess: "private_network", ruleConditions: [cond("umbrella.source.identity_ids", [99]), { attributeName: "umbrella.destination.all", attributeValue: true }] };
for (const id of [7, 99]) {
  const winner = { ...earlier, ruleConditions: [cond("umbrella.source.identity_ids", [id]), earlier.ruleConditions[1]] };
  assert.equal(evaluate([winner, r40]).outcome.rule, winner);
  assert.equal(evaluate([winner, r40]).stages[0].state, "matched");
}
const grouped = { ...r40, ruleConditions: [cond("umbrella.source.networkObjectGroupIds", [500004219]), r40.ruleConditions[1], cond("umbrella.source.identity_ids", [99])] };
assert.equal(evaluate([grouped]).outcome.title, "Source IP needed for candidate rule");
const wrongIdentity = { ...grouped, ruleConditions: [...grouped.ruleConditions.slice(0, 2), cond("umbrella.source.identity_ids", [100])] };
assert.notEqual(evaluate([wrongIdentity]).outcome.title, "Source IP needed for candidate rule");
console.log("source network object regressions passed");
