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
const catalogs = {
  sourceUsers: { 101: "Alice" }, sourceGroups: { 201: "Staff" }, sourceRoaming: { 301: "Laptop" },
  sourceIdentityTypeIds: { 101: 7, 201: 3, 301: 9 },
  memberMaps: { identityGroups: { 201: { name: "Staff", members: [{ id: "101", kind: "identity" }], resolved: true } } },
};
const condition = (attributeName, attributeValue) => ({ attributeName, attributeOperator: "INTERSECT", attributeValue });
const rule = (ruleName, condition, priority = 1) => ({
  ruleId: priority, ruleName, rulePriority: priority, ruleAction: "allow", ruleIsEnabled: true,
  trafficScope: "public_internet", ruleConditions: [condition, { attributeName: "umbrella.destination.all", attributeOperator: "=", attributeValue: true }],
});
const catchall = rule("Any source", { attributeName: "umbrella.source.all", attributeOperator: "=", attributeValue: true }, 999);
const device = rule("Specific device", condition("umbrella.source.identity_ids", [301]));
const roaming = rule("Roaming type", condition("umbrella.source.identity_type_ids", [9]), 2);
const user = rule("Specific user", condition("umbrella.source.identity_ids", [101]), 3);
const group = rule("Specific group", condition("umbrella.source.identity_ids", [201]), 4);
const userType = rule("User type", condition("umbrella.source.identity_type_ids", [7]), 5);
const groupType = rule("Group type", condition("umbrella.source.identity_type_ids", [3]), 6);
let checks = 0;
function build(sources, connection = "client") {
  const built = model.buildRequest({ connection, sources, destination: "example.com" }, catalogs);
  assert.ok(!built.error, built.error);
  return built.request;
}
function matches(request, rules, expected) {
  const result = model.evaluate(request, [...rules, catchall], catalogs, context.window.Matcher);
  assert.equal(result.stages.length, 2);
  for (const stage of result.stages) {
    assert.equal(stage.state, "matched");
    assert.equal(stage.match.rule.ruleName, expected);
  }
  checks++;
}
for (const sources of [{}, { roaming: "any:roaming" }, { identity: "sourceUsers:101" }, { roaming: "any:roaming", identity: "sourceUsers:101" }, { roaming: "any:roaming", identity: "any:identity" }, { identity: "any:identity" }]) {
  const request = build(sources);
  assert.equal(request.testInput.sourceRoamingId, undefined);
  assert.ok(request.identities.some(identity => identity.kind === "roaming" && identity.label === "Any roaming computer" && identity.id === undefined));
  matches(request, [device], "Any source");
  matches(request, [device, roaming], "Roaming type");
}
for (const sources of [{ identity: "any:identity" }, { roaming: "any:roaming", identity: "any:identity" }]) {
  const request = build(sources);
  assert.equal(request.testInput.sourceUserId, undefined);
  assert.equal(request.testInput.sourceGroupId, undefined);
  assert.ok(request.identities.every(identity => identity.id === undefined));
  matches(request, [device, user, group, groupType], "Any source");
  matches(request, [user, group, groupType, userType], "User type");
}
matches(build({ identity: "sourceUsers:101" }), [user], "Specific user");
matches(build({ identity: "sourceUsers:101" }), [group], "Specific group");
matches(build({ roaming: "sourceRoaming:301" }), [device], "Specific device");
matches(build({}), [userType, groupType], "Any source");
const anyVa = build({ identity: "any:identity" }, "va");
assert.deepEqual(anyVa.testInput, { identityTypeIds: ["7"] });
assert.ok(model.buildRequest({ connection: "network", sources: {}, destination: "example.com" }, catalogs).error);
assert.ok(model.buildRequest({ connection: "client", sources: { roaming: "any:identity" }, destination: "example.com" }, catalogs).error);
assert.ok(model.buildRequest({ connection: "client", sources: { identity: "sourceUsers:999" }, destination: "example.com" }, catalogs).error);
console.log(`PASS ${checks} real-model Any source evaluations`);
