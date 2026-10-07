#!/usr/bin/env node
// =============================================================================
// test-membership.js — Exercises the group/list membership recursion logic
// that powers the dashboard popover's recursive source/destination expand
// (service-worker.js: collectGroupIds / MEMBERSHIP_CONFIG / _classifyMember /
// parseMembership / _extractMemberList).
//
// These are PURE functions; we pull them out of service-worker.js via a vm
// sandbox (no chrome.* / browser needed) so the recursion + nested-group
// detection stay covered without a live Cisco API.
//
// Run: node test-membership.js
// =============================================================================

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const swSrc = fs.readFileSync(
  path.join(__dirname, "extension/background/service-worker.js"),
  "utf-8"
);

// service-worker.js touches chrome.* / importScripts at top level (token
// storage, listeners). Stub those minimally so the file can be loaded in a
// vm; the pure membership helpers under test (collectGroupIds / parseMembership
// / etc.) don't call any of them.
const listener = () => {};
const chromeStub = {
  runtime: { id: "test", onInstalled: { addListener: listener }, onStartup: { addListener: listener }, onMessage: { addListener: listener } },
  storage: { session: { get: () => Promise.resolve({}), set: () => Promise.resolve() }, local: { get: () => Promise.resolve({}), set: () => Promise.resolve() } },
  tabs: { onUpdated: { addListener: listener }, query: () => Promise.resolve([]) },
  alarms: { onAlarm: { addListener: listener }, create: () => {}, get: () => Promise.resolve(undefined) },
  webRequest: { onBeforeSendHeaders: { addListener: listener } },
  scripting: { executeScript: () => Promise.resolve() },
};
const sandbox = { console, chrome: chromeStub, importScripts: () => {}, SecDebugLog: { logEvent() {}, redactToken: () => ({ length: 0, prefix: "" }) } };
sandbox.window = sandbox;
sandbox.global = sandbox;
sandbox.self = sandbox;
vm.createContext(sandbox);

// Extract just the membership-related pure helpers (no fetch / chrome API use
// inside them — collectGroupIds, MEMBERSHIP_CONFIG, _classifyMember,
// _extractMemberList, parseMembership). We grab them by injecting a named
// export shim at the end of the source.
const exportShim = `
global.__membership = {
  collectGroupIds,
  MEMBERSHIP_CONFIG,
  _classifyMember,
  _extractMemberList,
  parseMembership,
  membershipFailureKey,
  membershipFailureCoolingDown,
  MEMBERSHIP_FAILURE_COOLDOWN_MS,
  classifyPerIdMember,
  perIdMemberUrl,
  normalizeMemberEntry,
  getCachedMembers,
  membersNeedNames,
};
`;
// The helpers are declared with `function`/`const` at top level, so they're
// reachable in the sandbox global after running the file.
vm.runInContext(swSrc + exportShim, sandbox);
const M = sandbox.__membership;

let passed = 0, failed = 0, total = 0;
function assert(cond, msg) {
  total++;
  if (cond) passed++;
  else { failed++; console.error(`  FAIL: ${msg}`); }
}
function eq(a, b, msg) {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} — got ${JSON.stringify(a)} expected ${JSON.stringify(b)}`);
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 1: collectGroupIds (rule condition → group IDs) ===");
{
  const rules = [
    { conditions: [
      { attributeName: "umbrella.source.networkObjectGroupIds", attributeValue: [10, 11] },
      { attributeName: "umbrella.destination.serviceObjectGroupIds", attributeValue: [20] },
    ]},
    { conditions: [
      { attributeName: "umbrella.destination.destination_list_ids", attributeValue: ["99"] },
      { attributeName: "umbrella.destination.application_list_ids", attributeValue: [300] },
      { attributeName: "umbrella.destination.category_list_ids", attributeValue: [400] },
      { attributeName: "umbrella.destination.private_resource_group_ids", attributeValue: [500] },
      { attributeName: "umbrella.destination.private_resource_ids", attributeValue: [8627] },
      { attributeName: "umbrella.destination.networkObjectIds", attributeValue: [500029741] },
      { attributeName: "umbrella.source.identity_ids", attributeValue: [7] },
      { attributeName: "umbrella.destination.application_ids", attributeValue: [123] },
    ]},
  ];
  const ids = M.collectGroupIds(rules);
  eq(ids.networkObjectGroups, ["10", "11"], "networkObjectGroups");
  eq(ids.serviceObjectGroups, ["20"], "serviceObjectGroups");
  eq(ids.destinationLists, ["99"], "destinationLists");
  eq(ids.applicationLists, ["300"], "applicationLists");
  eq(ids.categoryLists, ["400"], "categoryLists");
  eq(ids.privateResourceGroups, ["500"], "privateResourceGroups");
  eq(ids.privateResources, ["8627"], "privateResources");
  eq(ids.networkObjects, ["500029741"], "networkObjects");
  eq(ids.identityGroups, ["7"], "identityGroups");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 2: _classifyMember (leaf vs nested-group) ===");
{
  // Nested group detection: a member carrying its own children array.
  eq(M._classifyMember({ id: 5, children: [{ id: 6 }] }, "networkObjectGroups"),
     { id: "5", kind: "networkObjectGroups" }, "member with children → its own group kind");
  // Nested group detection: typed as a group.
  eq(M._classifyMember({ id: 5, type: "NetworkObjectGroup" }, "networkObjectGroups"),
     { id: "5", kind: "networkObjectGroups" }, "member typed group → group kind");
  // Plain leaf object.
  eq(M._classifyMember({ id: 8, name: "Obj8" }, "networkObjectGroups"),
     { id: "8", kind: "networkObjects", name: "Obj8" }, "plain leaf keeps name");
  // Numeric id → string.
  eq(M._classifyMember(42, "serviceObjectGroups"), { id: "42", kind: "serviceObjects" }, "numeric id → leafKind");
  // Null / unresolvable → null.
  assert(M._classifyMember(null, "networkObjectGroups") === null, "null member → null");
  assert(M._classifyMember({}, "networkObjectGroups") === null, "member with no id → null");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 3: _extractMemberList (candidate member-field names) ===");
{
  const items = [
    { objects: [101, 102] },          // networkObjectGroups candidate field
    { members: [{ id: 7 }] },          // NOT a networkObjectGroups candidate → ignored
    { resourceIds: [5001] },           // privateResourceGroups candidate field
    {},                                // no members
  ];
  eq(M._extractMemberList(items[0], "networkObjectGroups").map(m => m.id), ["101", "102"], "objects field");
  eq(M._extractMemberList(items[1], "networkObjectGroups"), [], "non-candidate field (members) ignored");
  eq(M._extractMemberList(items[2], "privateResourceGroups").map(m => m.id), ["5001"], "resourceIds field");
  eq(M._extractMemberList(items[3], "networkObjectGroups"), [], "no members → []");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 4: parseMembership (shape + recursive nesting) ===");
{
  // A network object group whose members include a leaf object AND another
  // nested group (which the popover would drill into).
  const json = {
    data: [
      { id: "G1", name: "Top Group",
        objects: [
          { id: 100, name: "Leaf Obj" },
          { id: "G2", name: "Nested Group", children: [{ id: 201 }] },
        ] },
    ],
  };
  const parsed = M.parseMembership(json, "networkObjectGroups");
  eq(parsed.length, 1, "one group parsed");
  eq(parsed[0].id, "G1", "group id");
  eq(parsed[0].name, "Top Group", "group name");
  // members: leaf + nested group
  eq(parsed[0].members.map(m => m.id), ["100", "G2"], "members include nested group id");
  const nested = parsed[0].members.find(m => m.id === "G2");
  assert(nested.kind === "networkObjectGroups", "nested member keeps group kind → recursive expand");
  const leaf = parsed[0].members.find(m => m.id === "100");
  assert(leaf.kind === "networkObjects", "leaf member is leaf kind (expandable to addresses)");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 5: parseMembership — destination list FQDN strings ===");
{
  const json = { data: [ { id: 99, name: "My List", destinations: ["example.com", "10.0.0.0/8"] } ] };
  const parsed = M.parseMembership(json, "destinationLists");
  eq(parsed[0].members.map(m => m.value).sort(), ["10.0.0.0/8", "example.com"], "FQDN/string members");
  assert(parsed[0].members.every(m => m.kind === "fqdn"), "destination list members are fqdn leaves");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 5b: HAR destination object members ===");
{
  const classified = M._classifyMember({ id: "36", destination: "ebay.com", type: "domain" }, "destinationLists");
  eq(classified, { value: "ebay.com", kind: "fqdn" }, "HAR destination object → fqdn value");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 5c: per-id dest-list destinations stay unresolved until fetched ===");
{
  const emptyCollection = M.normalizeMemberEntry({ id: "18147945", name: "Social Media", members: [] }, "18147945");
  eq(emptyCollection.resolved, false, "collection dest-list with no members is unresolved");
  assert(M.getCachedMembers({ destinationLists: { "18147945": emptyCollection } }, "destinationLists", "18147945") === null,
    "unresolved dest-list is not treated as cached members");

  const fromHar = M.classifyPerIdMember("destinationLists", { id: "34", destination: "facebook.com", type: "domain" });
  eq(fromHar, { value: "facebook.com", kind: "fqdn" }, "per-id dest row → fqdn value");
  const url = M.perIdMemberUrl("destinationLists", "8176184", "18147945", 1);
  assert(/destinationlists\/18147945\/destinations\?page=1/.test(url), "per-id dest-list URL matches HAR");

  const resolved = M.normalizeMemberEntry({ name: "Social Media", members: [fromHar], resolved: true }, "18147945");
  eq(resolved.resolved, true, "per-id dest-list with members is resolved");
  eq(resolved.members.map(m => m.value), ["facebook.com"], "resolved dest-list keeps fqdn members");

  const staleEmpty = { name: "Social Media", members: [], resolved: true };
  assert(M.getCachedMembers({ destinationLists: { "18147945": staleEmpty } }, "destinationLists", "18147945") === null,
    "stale empty dest-list cache is ignored so per-id fetch can run");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 5d: AD group children keep HAR labels ===");
{
  const user = M.classifyPerIdMember("identityGroups", {
    type: "directory_user",
    id: 1353332001,
    label: "William Chang",
    typeId: 7,
    childCount: 0,
  });
  eq(user, { id: "1353332001", kind: "identity", name: "William Chang" }, "AD user child keeps label");

  const nested = M.classifyPerIdMember("identityGroups", {
    type: "directory_group",
    id: 1353331193,
    label: "Domain Computers (d1.pseudoco.org\\\\Domain Computers)",
    typeId: 3,
    childCount: 3,
    children: "https://management.api.umbrella.com/identity/v2/organizations/8176184/directory_group/1353331193/children",
  });
  eq(nested.id, "1353331193", "nested group id");
  eq(nested.kind, "identityGroups", "nested group stays expandable");
  eq(nested.name, "Domain Computers (d1.pseudoco.org\\\\Domain Computers)", "nested group keeps label");

  const persisted = M.normalizeMemberEntry({
    name: "Finance",
    resolved: true,
    members: [user, nested],
  }, "Finance");
  eq(persisted.members.map(m => m.name), [user.name, nested.name], "persist keeps child names");

  const nameless = { name: "Finance", resolved: true, members: [{ id: "1", kind: "identity" }] };
  assert(M.membersNeedNames("identityGroups", nameless.members), "nameless AD children need names");
  assert(M.getCachedMembers({ identityGroups: { "99": nameless } }, "identityGroups", "99") === null,
    "nameless AD children are not treated as cached");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 5e: HAR private resources + network objects expand to addresses ===");
{
  const pr = M._extractMemberList({
    resourceId: 8627,
    name: "File Server",
    resourceAddresses: [{
      destinationAddr: ["smb.d1.pseudoco.org"],
      networkObjectIds: [],
      protocolPorts: [{ protocol: "any", ports: "1-65535" }],
    }],
    accessTypes: [
      { type: "network" },
      { type: "client", reachableAddresses: ["smb.d1.pseudoco.org"] },
      { type: "browser", externalFQDN: "https://intranet-8176184.ztna.sse.cisco.io" },
    ],
  }, "privateResources");
  eq(pr.map(m => m.value).sort(), ["intranet-8176184.ztna.sse.cisco.io", "smb.d1.pseudoco.org"],
    "private resource expands to destination + ZTNA host");

  const no = M._extractMemberList({
    id: 500029741,
    name: "Secure Access Secondary DNS",
    value: { type: "host", addresses: ["208.67.220.220"] },
  }, "networkObjects");
  eq(no, [{ value: "208.67.220.220", kind: "address" }], "network object expands to host address");

  const sog = M.parseMembership({
    results: [{
      id: 500001148,
      name: "Secure Access DNS",
      objects: [
        { id: 500029741, name: "Secure Access Secondary DNS" },
        { id: 500029742, name: "Secure Access Primary DNS" },
      ],
    }],
  }, "networkObjectGroups");
  eq(sog[0].members.map(m => m.id), ["500029741", "500029742"], "network object group members keep ids");
  assert(sog[0].members.every(m => m.kind === "networkObjects"), "group members are expandable network objects");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 6: parseMembership — unknown wrapper degrades to [] ===");
{
  eq(M.parseMembership({}, "networkObjectGroups"), [], "empty object → no items → []");
  eq(M.parseMembership({ unrelated: [] }, "networkObjectGroups"), [], "non-wrapper key → []");
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 7: MEMBERSHIP_CONFIG keys are expandable kinds ===");
{
  const keys = Object.keys(M.MEMBERSHIP_CONFIG);
  eq(keys.sort(),
     ["applicationLists", "categoryLists", "destinationLists", "identityGroups", "networkObjectGroups", "networkObjects", "privateResourceGroups", "privateResources", "serviceObjectGroups", "serviceObjects"].sort(),
     "configured group/list kinds include identityGroups and object leaves");
  for (const k of keys) {
    assert(M.MEMBERSHIP_CONFIG[k] && M.MEMBERSHIP_CONFIG[k].tokenKey, `config ${k} has tokenKey`);
  }
}

// ---------------------------------------------------------------------------
console.log("\n=== Group 8: denied membership fetch cooldown ===");
{
  const now = 1000;
  const failures = {
    [M.membershipFailureKey("org-a", "identityGroups", "group-1")]: {
      status: 403,
      expiresAt: now + M.MEMBERSHIP_FAILURE_COOLDOWN_MS,
    },
  };
  assert(M.membershipFailureCoolingDown(failures, "org-a", "identityGroups", "group-1", now),
    "denied group fetch is suppressed during cooldown");
  assert(!M.membershipFailureCoolingDown(failures, "org-b", "identityGroups", "group-1", now),
    "cooldown does not cross organizations");
  assert(!M.membershipFailureCoolingDown(failures, "org-a", "identityGroups", "group-2", now),
    "cooldown does not suppress another group");
  assert(!M.membershipFailureCoolingDown(failures, "org-a", "identityGroups", "group-1", now + M.MEMBERSHIP_FAILURE_COOLDOWN_MS),
    "expired cooldown permits automatic retry");
  assert(!M.membershipFailureCoolingDown({}, "org-a", "identityGroups", "group-1", now),
    "manual resolve path is not blocked by auto-prefetch cooldown lookup");
}

// ---------------------------------------------------------------------------
console.log(`\n${"=".repeat(60)}`);
console.log(`RESULTS: ${passed} passed, ${failed} failed, ${total} total`);
console.log(`${"=".repeat(60)}`);

if (failed > 0) { process.exit(1); } else { console.log("All membership tests passed!"); process.exit(0); }
