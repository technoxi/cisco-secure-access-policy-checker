#!/usr/bin/env node
"use strict";
// Policy Checker model (extension/popup/traffic-path.js) driven through the
// real matcher. Run: node test-traffic-path.js
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const ip = require("./extension/popup/ip-address.js");
globalThis.IPAddress = ip;
const model = require("./extension/popup/traffic-path.js");
const context = vm.createContext({ window: { IPAddress: ip }, console, Array, String, Object, JSON, Math, Set, Map, RegExp, parseInt, isNaN, Number });
vm.runInContext(fs.readFileSync("extension/popup/matcher.js", "utf8"), context);
const Matcher = context.window.Matcher;

let passed = 0;
function test(name, fn) {
  try { fn(); passed++; } catch (error) { console.error(`FAIL ${name}`); throw error; }
}

const catalogs = {
  sourceUsers: { 7: "Carol Freeman", 8: "Dan Ruiz" },
  sourceGroups: { 3: "HR", 4: "All staff" },
  sourceRoaming: { 9: "DAPQA-CSE-13" },
  sourceSites: { 21: "Default Site" },
  sourceNetworks: { 1: "London 1" },
  sourceTunnelGroups: { 33: "Branch Tunnel" },
  sourceEndpointDevices: { 55: "RWKST1.corp.example" },
  sourceCatalystSdwan: { 66: "IOT_OT" },
  sourceSecurityGroupTags: { 77: "Finance" },
  contentCategories: { 27: "Gambling", 28: "Social Networking" },
  sourceIdentityTypeIds: { 7: 7, 8: 7, 3: 3, 4: 3, 9: 9, 21: 21, 1: 1, 33: 40 },
};
const memberMaps = {
  identityGroups: {
    3: { name: "HR", members: [{ id: "7", kind: "identity", name: "Carol Freeman" }], resolved: true },
    4: { name: "All staff", members: [{ id: "3", kind: "identityGroups", name: "HR" }], resolved: true },
  },
  privateResources: {
    8627: { name: "HR app", members: [{ value: "hr.internal.example", kind: "address" }, { value: "10.20.0.0/16", kind: "address" }], resolved: true },
  },
  privateResourceGroups: {},
};
const lookups = { ...catalogs, memberMaps };

const cond = (attributeName, attributeOperator, attributeValue) => ({ attributeName, attributeOperator, attributeValue });
const SRC_ALL = cond("umbrella.source.all", "=", true);
const DST_ALL = cond("umbrella.destination.all", "=", true);
let nextId = 1;
function rule(name, action, conditions, extra = {}) {
  const id = nextId++;
  return { ruleId: id, ruleName: name, rulePriority: id, ruleAction: action, ruleIsEnabled: true, trafficScope: "public_internet", ruleConditions: conditions, ...extra };
}
const internetDefault = rule("Default Internet", "allow", [SRC_ALL, DST_ALL], { ruleIsDefault: true, rulePriority: 999 });
const geoBlock = rule("Block selected countries", "block", [SRC_ALL, cond("umbrella.destination.geolocations", "INTERSECT", ["AQ", "FO"])]);
const privateDefault = rule("Default Private", "block", [SRC_ALL, DST_ALL], { ruleIsDefault: true, rulePriority: 998, trafficScope: "private_network" });

function build(form) {
  const built = model.buildRequest(form, catalogs);
  assert.ok(!built.error, built.error);
  return built.request;
}
function run(form, rules) {
  return model.evaluate(build(form), [...rules, internetDefault, privateDefault], lookups, Matcher);
}
const states = evaluation => evaluation.stages.map(result => `${result.stage.key}:${result.state}${result.match && result.match.rule && result.state === "matched" ? `:${result.match.rule.ruleName}` : ""}`);

// --- Destination parsing ----------------------------------------------------
test("destination parsing", () => {
  assert.deepEqual(model.parseDestination("Example.com."), { host: "example.com", kind: "domain", port: "" });
  assert.deepEqual(model.parseDestination("https://example.com/login?x=1"), { host: "example.com", kind: "domain", port: "443", fromUrl: true });
  assert.equal(model.parseDestination("http://example.com:8080/").port, "8080");
  assert.deepEqual(model.parseDestination("203.0.113.10:445"), { host: "203.0.113.10", kind: "ip", port: "445" });
  assert.deepEqual(model.parseDestination("[2001:db8::1]:443"), { host: "2001:db8::1", kind: "ip", port: "443" });
  assert.equal(model.parseDestination("2001:db8::1").kind, "ip");
  for (const bad of ["", "10.0.0.0/8", "*.example.com", "ftp://example.com", "exa mple.com", "10.0.0.1:99999", "example"]) {
    assert.ok(model.parseDestination(bad).error, bad);
  }
});

// --- Sources per connection ------------------------------------------------
test("connection limits sources", () => {
  assert.deepEqual(model.CONNECTIONS.client.sources, ["roaming", "identity"]);
  assert.deepEqual(model.CONNECTIONS.va.sources, ["site", "internalIp", "identity", "computer", "network"]);
  assert.deepEqual(model.CONNECTIONS.network.sources, ["network"]);
  assert.deepEqual(model.CONNECTIONS.tunnel.sources, ["tunnel", "branch", "internalIp", "identity", "computer", "sdwan", "sgt"]);
  // A site picked earlier is ignored once the connection is Secure Client.
  const request = build({ connection: "client", sources: { roaming: "sourceRoaming:9", site: "sourceSites:21" }, destination: "example.com" });
  assert.deepEqual(request.testInput, { sourceRoamingId: "9" });
  assert.ok(model.buildRequest({ connection: "client", sources: { site: "sourceSites:21" }, destination: "example.com" }, catalogs).request);
  assert.match(model.buildRequest({ connection: "", sources: {}, destination: "example.com" }, catalogs).error, /connects/);
});

test("source validation", () => {
  const va = build({ connection: "va", sources: { site: "sourceSites:21", internalIp: "10.1.2.3", identity: "sourceUsers:7", network: "sourceNetworks:1" }, destination: "example.com" });
  assert.deepEqual(va.testInput, { sourceSiteId: "21", source: "10.1.2.3", sourceUserId: "7", sourceNetworkId: "1" });
  assert.equal(va.identities.length, 4);
  assert.match(model.buildRequest({ connection: "va", sources: { internalIp: "10.1.2.0/24" }, destination: "example.com" }, catalogs).error, /not a range/);
  assert.match(model.buildRequest({ connection: "va", sources: { internalIp: "10.1.2.300" }, destination: "example.com" }, catalogs).error, /not a valid/);
  assert.match(model.buildRequest({ connection: "client", sources: { identity: "sourceUsers:999" }, destination: "example.com" }, catalogs).error, /no longer in the loaded catalog/);
  assert.match(model.buildRequest({ connection: "client", sources: { roaming: "sourceUsers:7" }, destination: "example.com" }, catalogs).error, /from the list/);
  assert.match(model.buildRequest({ connection: "va", sources: { site: "sourceSites:21" }, destination: "203.0.113.10" }, catalogs).error, /only sees DNS/);
});

// --- Stage plan ------------------------------------------------------------
test("stage plan per connection", () => {
  const plan = form => {
    const request = build(form);
    const scope = model.resolveScope(request.destination.host, lookups);
    const result = model.planStages(request, scope);
    if (result.error && !result.stages.length) return `error:${result.error}`;
    if (result.unsupported) return `unsupported:${result.unsupported.stage.key}`;
    return result.stages.map(stage => stage.key).join(",") + (result.skipped && result.skipped.length ? ` skip:${result.skipped.map(stage => stage.key)}` : "");
  };
  const client = { connection: "client", sources: { roaming: "sourceRoaming:9" } };
  const tunnel = { connection: "tunnel", sources: { tunnel: "sourceTunnelGroups:33" } };
  assert.equal(plan({ ...client, destination: "example.com" }), "dns,web");
  assert.equal(plan({ ...client, destination: "https://example.com/x" }), "dns,web");
  assert.equal(plan({ ...client, destination: "203.0.113.10" }), "web");
  assert.match(plan({ ...client, destination: "203.0.113.10", port: "22" }), /^error:/);
  assert.equal(plan({ connection: "va", sources: { site: "sourceSites:21" }, destination: "example.com" }), "dns");
  // Branch DNS never shows up as a tunnel identity in Activity Search.
  assert.equal(plan({ ...tunnel, destination: "example.com" }), "web skip:firewall");
  assert.equal(plan({ ...tunnel, destination: "203.0.113.10", port: "445" }), "firewall");
  assert.equal(plan({ ...tunnel, destination: "203.0.113.10" }), "firewall,web");
  assert.equal(plan({ ...tunnel, destination: "203.0.113.10", protocol: "ICMP" }), "firewall");
  assert.equal(plan({ ...tunnel, destination: "hr.internal.example" }), "firewall");
  // Branch traffic to internal IPs is logged as firewall events.
  assert.equal(plan({ ...tunnel, destination: "10.9.9.9" }), "firewall");
  assert.equal(plan({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "10.9.9.9" }), "unsupported:private");
  assert.match(plan({ connection: "va", sources: { site: "sourceSites:21" }, destination: "hr.internal.example" }), /error:Private Access is not reached/);
});

// --- Evaluation ------------------------------------------------------------
test("user matches a rule on a nested group", () => {
  const staff = rule("Block gambling for staff", "block", [cond("umbrella.source.identity_ids", "INTERSECT", [4]), DST_ALL]);
  const evaluation = run({ connection: "client", sources: { roaming: "sourceRoaming:9", identity: "sourceUsers:7" }, destination: "example.com" }, [staff]);
  assert.deepEqual(evaluation.groups.map(group => group.name).sort(), ["All staff", "HR"]);
  // DNS may not know the user, so Web is still evaluated as the fallback
  // (Activity Search shows proxy blocks for requests whose DNS rule blocks).
  assert.deepEqual(states(evaluation), ["dns:matched:Block gambling for staff", "web:matched:Block gambling for staff"]);
  assert.equal(evaluation.stages[1].afterBlock.key, "dns");
  assert.equal(evaluation.outcome.status, "block");
  assert.equal(evaluation.outcome.title, "Blocked at DNS");
  // Dan is not in HR, so the default applies at both stages.
  const other = run({ connection: "client", sources: { identity: "sourceUsers:8" }, destination: "example.com" }, [staff]);
  assert.deepEqual(states(other), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
  assert.equal(other.outcome.status, "allow");
});

test("roaming computer identity type rule", () => {
  const roamingRule = rule("All roaming computers", "warn", [cond("umbrella.source.identity_type_ids", "INTERSECT", [9]), DST_ALL]);
  const evaluation = model.evaluate(build({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "example.com" }), [roamingRule, internetDefault], { ...lookups, sourceIdentityTypeIds: catalogs.sourceIdentityTypeIds }, Matcher);
  assert.deepEqual(states(evaluation), ["dns:matched:All roaming computers", "web:matched:All roaming computers"]);
  assert.equal(evaluation.outcome.status, "warn");
});

test("GeoIP-only rules are skipped and the next rule decides", () => {
  const evaluation = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "google.com" }, [geoBlock]);
  assert.deepEqual(states(evaluation), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.outcome.rule.ruleName, "Default Internet");
});

test("mixed GeoIP and category rule is skipped as a whole", () => {
  const geoAndCategory = rule("Block country gambling", "block", [SRC_ALL, cond("umbrella.destination.geolocations", "INTERSECT", ["AQ"]), cond("umbrella.destination.category_ids", "INTERSECT", [27])]);
  const evaluation = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "bet.example" }, [geoAndCategory]);
  assert.deepEqual(states(evaluation), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.outcome.rule.ruleName, "Default Internet");
});

test("GeoIP firewall rule is skipped before the next TCP rule", () => {
  const evaluation = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "203.0.113.10", port: "443" }, [geoBlock]);
  assert.deepEqual(states(evaluation), ["firewall:matched:Default Internet", "web:matched:Default Internet"]);
  assert.equal(evaluation.outcome.status, "allow");
  assert.equal(evaluation.outcome.rule.ruleName, "Default Internet");
});

test("skipped GeoIP firewall rule does not demand VPN client IP", () => {
  const geoVpnRule = rule("Geo block by client subnet", "block", [cond("umbrella.source.composite_inline_ip", "IN", [{ ip: ["10.99.0.0/16"], port: ["0-65535"], protocol: "ANY" }]), cond("umbrella.destination.geolocations", "INTERSECT", ["AQ"])], { trafficScope: "private_network" });
  const evaluation = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "10.20.1.5", port: "443" }, [geoVpnRule]);
  assert.deepEqual(states(evaluation), ["firewall:matched:Default Private"]);
  assert.equal(evaluation.outcome.status, "block");
});

test("missing tunnel identity cannot select a later generic branch rule", () => {
  const den = rule("Secure DIA for DEN branch", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [644963088]), DST_ALL], { ruleId: 398936, rulePriority: 31 });
  const branches = rule("Secure DIA for all branch locations_Copy 1", "allow", [cond("umbrella.source.identity_type_ids", "INTERSECT", [40]), DST_ALL], { ruleId: 2118553, rulePriority: 32 });
  const catalog = { ...lookups, sourceTunnelGroups: { 644963088: "den1", 615488204: "SJ 1" } };
  const evaluate = sources => model.evaluate(model.buildRequest({ connection: "tunnel", sources, destination: "example.com" }, catalog).request, [den, branches, internetDefault], catalog, Matcher);
  assert.match(evaluate({ internalIp: "10.1.2.3" }).error, /Select the network tunnel or branch/);
  assert.equal(evaluate({ tunnel: "sourceTunnelGroups:644963088" }).outcome.rule.ruleId, 398936);
  assert.equal(evaluate({ tunnel: "sourceTunnelGroups:615488204" }).outcome.rule.ruleId, 2118553);
  const earlier = rule("Known earlier winner", "block", [SRC_ALL, DST_ALL], { rulePriority: 1 });
  const request = model.buildRequest({ connection: "tunnel", sources: { internalIp: "10.1.2.3" }, destination: "example.com" }, catalog).request;
  assert.equal(model.evaluate(request, [earlier, den, branches], catalog, Matcher).outcome.status, "block");
  assert.equal(model.evaluate(request, [earlier, den, branches], catalog, Matcher).outcome.rule.ruleId, earlier.ruleId);
  assert.equal(model.evaluate(request, [{ ...den, ruleIsEnabled: false }, branches, internetDefault], catalog, Matcher).outcome.rule.ruleId, branches.ruleId);
  const unrelated = { ...den, ruleConditions: [den.ruleConditions[0], cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["203.0.113.99"], port: ["0-65535"], protocol: "ANY" }])] };
  assert.equal(model.evaluate(request, [unrelated, branches, internetDefault], catalog, Matcher).outcome.rule.ruleId, branches.ruleId);
  const privateTunnel = { ...den, trafficScope: "private_network" };
  assert.equal(model.evaluate(request, [privateTunnel, branches, internetDefault], catalog, Matcher).outcome.rule.ruleId, branches.ruleId);
});

test("explicit SD-WAN or SGT identity does not demand a missing tunnel", () => {
  const den = rule("Secure DIA for DEN branch", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [644963088]), DST_ALL], { ruleId: 398936, rulePriority: 31 });
  const branches = rule("Secure DIA for all branch locations_Copy 1", "allow", [cond("umbrella.source.identity_type_ids", "INTERSECT", [40]), DST_ALL], { ruleId: 2118553, rulePriority: 32 });
  const catalog = { ...lookups, sourceTunnelGroups: { 644963088: "den1" } };
  for (const sources of [
    { sdwan: "sourceCatalystSdwan:66", sgt: "sourceSecurityGroupTags:77" },
    { sdwan: "sourceCatalystSdwan:66" },
    { sgt: "sourceSecurityGroupTags:77" },
  ]) {
    const request = model.buildRequest({ connection: "tunnel", sources, destination: "https://example.com/" }, catalog).request;
    assert.ok(!request.testInput.sourceTunnelGroupId);
    const evaluation = model.evaluate(request, [den, branches, internetDefault], catalog, Matcher);
    assert.ok(!evaluation.error, evaluation.error);
    assert.equal(evaluation.outcome.status, "allow");
    assert.equal(evaluation.outcome.rule.ruleId, 2118553);
    assert.deepEqual(states(evaluation), ["firewall:skipped", "web:matched:Secure DIA for all branch locations_Copy 1"]);
  }
});

test("category rule asks, then resolves from the answer", () => {
  const gambling = rule("Block gambling", "block", [SRC_ALL, cond("umbrella.destination.category_ids", "INTERSECT", [27, 28])]);
  const form = { connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "bet.example" };
  const first = run(form, [gambling]);
  assert.deepEqual(states(first), ["dns:needs-answer", "web:needs-answer"]);
  assert.equal(first.outcome.status, "pending");
  const question = model.questionFor(first.stages[0], "bet.example", lookups);
  assert.equal(question.ruleName, "Block gambling");
  assert.deepEqual(question.groups[0].options.map(option => option.label), ["Gambling", "Social Networking"]);

  const yes = run({ ...form, facts: model.answer({}, question, ["27"]) }, [gambling]);
  assert.deepEqual(states(yes), ["dns:matched:Block gambling", "web:matched:Block gambling"]);
  assert.equal(yes.outcome.title, "Blocked at DNS");

  const no = run({ ...form, facts: model.answer({}, question, []) }, [gambling]);
  assert.deepEqual(states(no), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
});

test("DNS and Web can land on different rules", () => {
  const webOnly = rule("Block uploads over web", "block", [SRC_ALL, cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["example.com"], port: ["443"], protocol: "TCP" }])]);
  const evaluation = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "https://example.com/upload" }, [webOnly]);
  // The lookup itself goes to UDP 53, so the HTTPS-only rule applies at Web.
  assert.deepEqual(states(evaluation), ["dns:matched:Default Internet", "web:matched:Block uploads over web"]);
  assert.equal(evaluation.outcome.title, "Blocked at Web");
});

test("tunnel firewall: port rules match, categories apply too", () => {
  const rpc = rule("Block RPC", "block", [SRC_ALL, cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["0.0.0.0/0"], port: ["135"], protocol: "TCP" }])]);
  const social = rule("Block social", "block", [SRC_ALL, cond("umbrella.destination.category_ids", "INTERSECT", [28])]);
  const tunnel = { connection: "tunnel", sources: { tunnel: "sourceTunnelGroups:33", internalIp: "10.1.2.3" } };
  assert.deepEqual(states(run({ ...tunnel, destination: "203.0.113.10", port: "135" }, [rpc, social])), ["firewall:matched:Block RPC"]);
  // Until the application is identified, the firewall allows the flow under
  // the first rule whose source matches (Activity Search logs Block rules as
  // Allowed this way); the web layer still asks.
  const web = run({ ...tunnel, destination: "203.0.113.10" }, [rpc, social]);
  assert.deepEqual(states(web), ["firewall:matched:Block social", "web:needs-answer"]);
  assert.equal(web.stages[0].action, "allow");
  assert.equal(web.stages[0].provisional, true);
  // Once the category is known, the firewall decides for real.
  const known = run({ ...tunnel, destination: "203.0.113.10", facts: { contentCategoryId: { yes: ["28"], no: [], all: true } } }, [rpc, social]);
  assert.equal(known.stages[0].action, "block");
  assert.equal(known.stages[0].provisional, undefined);
});

test("firewall block stops web", () => {
  const blockIp = rule("Block bad IP", "block", [SRC_ALL, cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["203.0.113.0/24"], port: ["0-65535"], protocol: "ANY" }])]);
  const evaluation = run({ connection: "tunnel", sources: { tunnel: "sourceTunnelGroups:33" }, destination: "203.0.113.10" }, [blockIp]);
  assert.deepEqual(states(evaluation), ["firewall:matched:Block bad IP", "web:not-reached"]);
  assert.equal(evaluation.outcome.title, "Blocked at Firewall");
});

test("Secure Client cannot be evaluated for private destinations", () => {
  for (const destination of ["10.99.1.1", "hr.internal.example"]) {
    const evaluation = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination }, [internetDefault]);
    assert.equal(evaluation.outcome.status, "unsupported");
    assert.match(evaluation.outcome.reason, /Standard Secure Client doesn’t route to private resources/);
    assert.deepEqual(states(evaluation), ["private:unsupported"]);
  }
  const internet = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "google.com" }, [internetDefault]);
  assert.deepEqual(states(internet), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
});

test("VPN firewall rules preserve source and destination direction", () => {
  const sourceNetwork = range => cond("umbrella.source.composite_inline_ip", "IN", [{ ip: [range], port: ["0-65535"], protocol: "ANY" }]);
  const destinationNetwork = range => cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: [range], port: ["0-65535"], protocol: "ANY" }]);
  const outbound = rule("VPN client to internal resource", "allow", [sourceNetwork("10.99.1.0/24"), destinationNetwork("10.20.0.0/16")], { trafficScope: "private_network" });
  const inbound = rule("Internal resource to VPN client", "block", [sourceNetwork("10.20.0.0/16"), destinationNetwork("10.99.1.0/24")], { trafficScope: "private_network" });
  const missingIp = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "10.20.1.5", port: "443" }, [outbound]);
  assert.deepEqual(states(missingIp), ["firewall:needs-answer"]);
  assert.equal(missingIp.outcome.status, "pending");
  assert.equal(missingIp.outcome.rule, outbound);
  assert.equal(missingIp.stages[0].match.rule, outbound);
  assert.equal(model.questionFor(missingIp.stages[0], "10.20.1.5", lookups), null);
  assert.match(missingIp.outcome.reason, /VPN-assigned client IP/);
  const identityOnlyRule = rule("Private app for user", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [7]), cond("umbrella.destination.private_resource_ids", "IN", [8627])], { trafficScope: "private_network" });
  const identityOnly = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "hr.internal.example" }, [identityOnlyRule]);
  assert.deepEqual(states(identityOnly), ["firewall:matched:Private app for user"]);
  for (const id of [7, 3]) {
    const earlier = rule("Earlier identity winner", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [id]), destinationNetwork("10.20.0.0/16")], { trafficScope: "private_network", rulePriority: outbound.rulePriority - 1 });
    const control = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "10.20.1.5" }, [earlier, outbound]);
    assert.deepEqual(states(control), ["firewall:matched:Earlier identity winner"]);
  }
  const unrelatedSourceRule = rule("Other source range", "block", [sourceNetwork("10.80.0.0/16"), destinationNetwork("10.20.0.0/16")], { trafficScope: "private_network" });
  const unrelated = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "hr.internal.example" }, [unrelatedSourceRule, identityOnlyRule]);
  assert.deepEqual(states(unrelated), ["firewall:matched:Private app for user"]);
  const request = { connection: "vpn", sources: { internalIp: "10.99.1.25", identity: "sourceUsers:7" }, destination: "10.20.1.5", port: "443" };
  assert.deepEqual(states(run(request, [outbound])), ["firewall:matched:VPN client to internal resource"]);
  assert.deepEqual(states(run(request, [inbound])), ["firewall:matched:Default Private"]);
});

test("private resource destination", () => {
  const hrApp = rule("HR app for HR", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [3]), cond("umbrella.destination.private_resource_ids", "IN", [8627])], { trafficScope: "private_network" });
  const hr = run({ connection: "vpn", sources: { identity: "sourceUsers:7", internalIp: "10.99.1.25" }, destination: "hr.internal.example" }, [hrApp]);
  assert.deepEqual(hr.scope.resourceNames, ["HR app"]);
  assert.deepEqual(states(hr), ["firewall:matched:HR app for HR"]);
  const standardClient = run({ connection: "client", sources: { identity: "sourceUsers:7" }, destination: "hr.internal.example" }, [hrApp]);
  assert.deepEqual(standardClient.scope.resourceNames, ["HR app"]);
  assert.deepEqual(states(standardClient), ["private:unsupported"]);
  const byIp = run({ connection: "tunnel", sources: { identity: "sourceUsers:7" }, destination: "10.20.1.5", port: "443" }, [hrApp]);
  assert.deepEqual(states(byIp), ["firewall:matched:HR app for HR"]);
  const outsider = run({ connection: "vpn", sources: { identity: "sourceUsers:8", internalIp: "10.99.1.25" }, destination: "hr.internal.example" }, [hrApp]);
  assert.deepEqual(states(outsider), ["firewall:matched:Default Private"]);
});

test("VA site and internal IP", () => {
  const siteRule = rule("Branch DNS filtering", "block", [cond("umbrella.source.identity_ids", "INTERSECT", [21]), DST_ALL]);
  const ipRule = rule("Lab subnet", "allow", [cond("umbrella.source.composite_inline_ip", "IN", [{ ip: ["10.50.0.0/16"], port: ["any"], protocol: "ANY" }]), DST_ALL]);
  assert.deepEqual(states(run({ connection: "va", sources: { internalIp: "10.50.3.4" }, destination: "example.com" }, [ipRule, siteRule])), ["dns:matched:Lab subnet"]);
  assert.deepEqual(states(run({ connection: "va", sources: { site: "sourceSites:21", internalIp: "10.60.3.4" }, destination: "example.com" }, [ipRule, siteRule])), ["dns:matched:Branch DNS filtering"]);
});

test("Network DNS and the identity kinds seen in Activity Search", () => {
  // DNS from a registered network (525 export events): only the network.
  const byNetwork = rule("Block by network", "block", [cond("umbrella.source.identity_ids", "INTERSECT", [1]), DST_ALL]);
  assert.deepEqual(states(run({ connection: "network", sources: { network: "sourceNetworks:1" }, destination: "example.com" }, [byNetwork])), ["dns:matched:Block by network"]);
  assert.match(model.buildRequest({ connection: "network", sources: { network: "sourceNetworks:1" }, destination: "203.0.113.5" }, catalogs).error, /only sees DNS/);
  // AD computer through a tunnel to an internal broadcast (15,396 events).
  const byComputer = rule("Block computer", "block", [cond("umbrella.source.identity_ids", "INTERSECT", [55]), DST_ALL], { trafficScope: "private_network" });
  assert.deepEqual(states(run({ connection: "tunnel", sources: { computer: "sourceEndpointDevices:55" }, destination: "10.100.67.255", port: "138", protocol: "UDP" }, [byComputer])), ["firewall:matched:Block computer"]);
  // SD-WAN VPN and security group tag carried by a tunnel (1,398 events).
  const bySgt = rule("SGT web", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [77]), DST_ALL]);
  const request = build({ connection: "tunnel", sources: { tunnel: "sourceTunnelGroups:33", sdwan: "sourceCatalystSdwan:66", sgt: "sourceSecurityGroupTags:77" }, destination: "https://example.com/" });
  assert.deepEqual(request.testInput, { sourceTunnelGroupId: "33", sourceCatalystSdwanId: "66", sourceSecurityGroupTagId: "77" });
  assert.equal(model.evaluate(request, [bySgt, internetDefault], lookups, Matcher).stages.find(stage => stage.stage.key === "web").match.rule.ruleName, "SGT web");
});

test("category conditions are bit positions, not category IDs", () => {
  // Activity Search: rule 334892 lists category [10] and blocked Gambling
  // domains; bit 10 is Gambling (categoryId 11), categoryId 10 is File Storage.
  const bits = { 10: { name: "Gambling", categoryId: 11 }, 9: { name: "File Storage", categoryId: 10 } };
  const gambling = rule("Block category bit 10", "block", [SRC_ALL, cond("umbrella.destination.category_ids", "INTERSECT", [10])]);
  const withBits = { ...lookups, categories: bits, contentCategories: { 10: "File Storage", 11: "Gambling" } };
  const form = { connection: "network", sources: { network: "sourceNetworks:1" }, destination: "bet.example" };
  const first = model.evaluate(build(form), [gambling, internetDefault], withBits, Matcher);
  const question = model.questionFor(first.stages[0], "bet.example", withBits);
  assert.deepEqual(question.groups[0].options.map(option => option.label), ["Gambling"]);
  const yes = model.evaluate(build({ ...form, facts: model.answer({}, question, ["11"]) }), [gambling, internetDefault], withBits, Matcher);
  assert.deepEqual(states(yes), ["dns:matched:Block category bit 10"]);
});

test("security settings: DNS default before rules, web profile on allow rules", () => {
  // Shapes from the tenant: web profile 14451715 → security setting "All
  // Categories"; DNS default "Default Settings". Activity Search: Malware blocks
  // under Allow rules (web) and rule 0 "Block due to security setting" (DNS).
  const securityProfiles = {
    dnsDefaultSettingId: "1",
    securitySettings: {
      1: { name: "Default Settings", categories: ["Command and Control", "Malware", "Phishing"] },
      2: { name: "All Categories", categories: ["Command and Control", "Malware", "Phishing", "Potentially Harmful"] },
    },
    webProfiles: { 500: { name: "PseudoCo Web Profile", securitySettingId: "2" } },
  };
  const withSecurity = { ...lookups, securityProfiles };
  const dia = rule("Secure DIA", "allow", [cond("umbrella.source.identity_ids", "INTERSECT", [9]), DST_ALL],
    { raw: { ruleSettings: [{ settingName: "umbrella.posture.webProfileId", settingValue: 500 }] } });
  const evaluateWith = facts => model.evaluate(build({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "https://bad.example/", facts }), [dia, internetDefault], withSecurity, Matcher);

  // Unanswered: allowed, unless flagged; the union of categories is asked.
  const open = evaluateWith(undefined);
  assert.equal(open.outcome.title, "Allowed");
  assert.equal(open.outcome.unlessFlagged, true);
  const question = model.threatQuestion(open, "bad.example");
  assert.deepEqual(question.groups[0].options.map(option => option.id), ["Command and Control", "Malware", "Phishing", "Potentially Harmful"]);

  // Flagged only in the web profile: DNS resolves, the proxy blocks under the allow rule.
  const harmful = evaluateWith(model.answer({}, question, ["Potentially Harmful"]));
  assert.deepEqual(harmful.stages.map(stage => `${stage.stage.key}:${stage.action || stage.state}`), ["dns:allow", "web:block"]);
  const web = harmful.stages.find(stage => stage.stage.key === "web");
  assert.equal(web.match.rule.ruleName, "Secure DIA");
  assert.equal(web.security.profile, "PseudoCo Web Profile");
  assert.equal(harmful.outcome.title, "Blocked at Web");
  assert.equal(harmful.threatCheck, null);

  // Flagged in the DNS default: blocked before any rule. Web stays the
  // fallback (the web profile blocks Malware too) in case DNS bypasses.
  const malware = evaluateWith(model.answer({}, question, ["Malware"]));
  assert.deepEqual(malware.stages.map(stage => `${stage.stage.key}:${stage.action}`), ["dns:block", "web:block"]);
  assert.equal(malware.stages[1].afterBlock.key, "dns");
  assert.equal(malware.stages[0].match.rule.ruleName, "DNS security settings");
  assert.equal(malware.outcome.title, "Blocked at DNS");

  // Not flagged: plain allow, no caveat.
  const clean = evaluateWith(model.answer({}, question, []));
  assert.equal(clean.outcome.title, "Allowed");
  assert.equal(clean.outcome.unlessFlagged, undefined);
});

test("Cisco Investigate lookup answers every question", () => {
  // Shapes from investigate.umbrella.com for this tenant: categorization gives
  // bit positions (content 113 = Computer Security, security 66 = Malware),
  // CASI names the app, the URL classifier names extra threats.
  const bundledLookups = {
    ...lookups,
    categories: { 10: { name: "Gambling", categoryId: 11 }, 113: { name: "Computer Security", categoryId: 331 } },
    securityCategories: { 66: { name: "Malware", categoryId: 94 } },
    applications: { 993005: "TikTok" },
    memberMaps: { ...memberMaps, applicationLists: { 20230: { name: "AUP", members: [{ id: "993005", kind: "application" }] } }, categoryLists: { 7: { name: "Restricted", members: [{ id: "11", kind: "category" }] } } },
    securityProfiles: { dnsDefaultSettingId: "1", securitySettings: { 1: { name: "Default Settings", categories: ["Malware", "Phishing"] } }, webProfiles: {} },
  };
  const facts = model.factsFromLookup({ ok: true, contentBits: ["10"], securityBits: [], securityNames: [], app: { name: "TikTok" } }, bundledLookups);
  assert.deepEqual(facts.contentCategoryId.yes, ["11"]);
  assert.deepEqual(facts.applicationId.yes, ["993005"]);
  assert.deepEqual(facts.applicationListId.yes, ["20230"]);
  assert.deepEqual(facts.categoryListId.yes, ["7"]);

  // A rule on an app list and a rule on a category both resolve without asking.
  const aup = rule("AUP apps", "block", [SRC_ALL, cond("umbrella.destination.application_list_ids", "INTERSECT", [20230])]);
  const onGambling = rule("Gambling", "block", [SRC_ALL, cond("umbrella.destination.category_ids", "INTERSECT", [10])]);
  const request = build({ connection: "network", sources: { network: "sourceNetworks:1" }, destination: "www.tiktok.com", facts });
  const evaluation = model.evaluate(request, [aup, onGambling, internetDefault], bundledLookups, Matcher);
  assert.deepEqual(states(evaluation), ["dns:matched:AUP apps"]);
  assert.equal(evaluation.threatCheck, null);

  // Nothing on record: every rule that depends on it resolves as "no", no question.
  const plain = model.factsFromLookup({ ok: true, contentBits: [], securityBits: [], securityNames: [], app: null }, bundledLookups);
  const quiet = model.evaluate(build({ connection: "network", sources: { network: "sourceNetworks:1" }, destination: "example.org", facts: plain }), [aup, onGambling, internetDefault], bundledLookups, Matcher);
  assert.deepEqual(states(quiet), ["dns:matched:Default Internet"]);
  assert.equal(quiet.threatCheck, null);

  // A threat named only by the URL classifier still counts.
  const flagged = model.factsFromLookup({ ok: true, contentBits: [], securityBits: [], securityNames: ["Malware"], app: null }, bundledLookups);
  const blocked = model.evaluate(build({ connection: "network", sources: { network: "sourceNetworks:1" }, destination: "marksidfgs.ug", facts: flagged }), [internetDefault], bundledLookups, Matcher);
  assert.equal(blocked.outcome.title, "Blocked at DNS");
  assert.equal(blocked.stages[0].security.category, "Malware");

  // A failed lookup leaves the questions in place.
  assert.deepEqual(model.factsFromLookup({ ok: false }, bundledLookups), {});
});

test("tunnel traffic carries the Network Tunnels type", () => {
  // Activity Search: SD-WAN VPN + security group identities only, matched by a
  // rule on identity type 40 (Network Tunnels).
  const allBranches = rule("Secure DIA for all branches", "allow", [cond("umbrella.source.identity_type_ids", "INTERSECT", [40]), DST_ALL]);
  const sdwanOnly = run({ connection: "tunnel", sources: { sdwan: "sourceCatalystSdwan:66", sgt: "sourceSecurityGroupTags:77" }, destination: "1.1.1.1", port: "53", protocol: "UDP" }, [allBranches]);
  assert.deepEqual(states(sdwanOnly), ["firewall:matched:Secure DIA for all branches"]);
  // Not on other connections.
  const client = run({ connection: "client", sources: { roaming: "sourceRoaming:9" }, destination: "example.com" }, [allBranches]);
  assert.deepEqual(states(client), ["dns:matched:Default Internet", "web:matched:Default Internet"]);
});

test("firewall timing: TCP is provisional, UDP decides; URL-path lists wait", () => {
  // Activity Search (1M events): a Block rule on apps was logged as Allowed for
  // TCP flows (handshake carries no payload), not for UDP 53; destination
  // lists with URL paths were logged provisionally, plain domain lists not.
  const apps = rule("Block Telnet and SSH", "block", [SRC_ALL, cond("umbrella.destination.application_ids", "INTERSECT", [6500911])]);
  const tcp = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "104.208.203.90", port: "443", protocol: "TCP" }, [apps]);
  assert.equal(tcp.stages[0].provisional, true);
  assert.equal(tcp.stages[0].action, "allow");
  assert.equal(tcp.stages[0].match.rule.ruleName, "Block Telnet and SSH");
  const udp = run({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "1.1.1.1", port: "53", protocol: "UDP" }, [apps]);
  assert.equal(udp.stages[0].state, "needs-answer");

  const withLists = { ...lookups, memberMaps: { ...memberMaps, destinationLists: {
    1: { name: "AUP Exceptions", members: [{ value: "reddit.com/r/cisco", kind: "fqdn" }] },
    2: { name: "Geo", members: [{ value: "fo", kind: "fqdn" }, { value: "aq", kind: "fqdn" }] },
  } } };
  const byList = id => rule(`List ${id}`, "allow", [SRC_ALL, cond("umbrella.destination.destination_list_ids", "INTERSECT", [id])]);
  const request = build({ connection: "vpn", sources: { identity: "sourceUsers:7" }, destination: "104.208.203.90", port: "443" });
  const paths = model.evaluate(request, [byList(1), internetDefault], withLists, Matcher);
  assert.equal(paths.stages[0].match.rule.ruleName, "List 1");
  assert.equal(paths.stages[0].provisional, true);
  const domains = model.evaluate(request, [byList(2), internetDefault], withLists, Matcher);
  assert.equal(domains.stages[0].match.rule.ruleName, "Default Internet");
});

test("disabled rules are skipped", () => {
  const off = rule("Disabled block", "block", [SRC_ALL, DST_ALL], { ruleIsEnabled: false });
  assert.deepEqual(states(run({ connection: "va", sources: { site: "sourceSites:21" }, destination: "example.com" }, [off])), ["dns:matched:Default Internet"]);
});

console.log(`traffic path checker: ${passed} tests passed`);
