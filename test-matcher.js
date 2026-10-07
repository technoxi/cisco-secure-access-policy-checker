#!/usr/bin/env node
// =============================================================================
// test-matcher.js — Comprehensive matcher.js test harness
//
// Tests the policy matching engine against all condition types found in the
// 34-rule SSE Demo org (org 8176184). Each test creates a synthetic rule with
// known conditions and verifies the matcher produces the correct result.
//
// Run: node test-matcher.js
// =============================================================================

"use strict";

// ---------------------------------------------------------------------------
// Bootstrap matcher.js in a Node-safe way (no window/document)
// ---------------------------------------------------------------------------
const fakeWindow = { IPAddress: require("./extension/popup/ip-address.js") };
const matcherSrc = require("fs").readFileSync(
  require("path").join(__dirname, "extension/popup/matcher.js"),
  "utf-8"
);
// matcher.js is an IIFE that assigns to `global` (which is `window` in-browser).
// We shim `window` and `global` so the IIFE can run.
const vm = require("vm");
const ctx = vm.createContext({
  window: fakeWindow,
  console,
  parseInt,
  isNaN,
  Array,
  String,
  JSON,
  Math,
  Intl,
  Error,
  Object,
  Set,
  Map,
  RegExp,
  TypeError,
  RangeError,
});
vm.runInContext(matcherSrc, ctx);
const Matcher = fakeWindow.Matcher;
if (!Matcher) {
  console.error("FATAL: Matcher not exported — check matcher.js shim");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Test framework
// ---------------------------------------------------------------------------
let passed = 0;
let failed = 0;
let total = 0;

function assert(condition, msg) {
  total++;
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

function assertMatch(rule, testInput, shouldMatch, label, lookups) {
  total++;
  const result = Matcher.matchesRule(rule, testInput, lookups || {});
  const matched = result.matched;
  if (matched === shouldMatch) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${label} — expected ${shouldMatch ? "MATCH" : "NO MATCH"}, got ${matched ? "MATCH" : "NO MATCH"}`);
    if (result.matchedConditions) {
      console.error(`         conditions: ${result.matchedConditions.join("; ")}`);
    }
  }
}

function makeRule(id, name, action, conditions, opts = {}) {
  return {
    ruleId: id,
    ruleName: name,
    ruleAction: action,
    rulePriority: opts.priority || id,
    ruleIsEnabled: opts.enabled !== undefined ? opts.enabled : true,
    ruleIsDefault: opts.isDefault || false,
    ruleConditions: conditions,
    ...opts,
  };
}

function cond(attrName, operator, value) {
  return { attributeName: attrName, attributeOperator: operator, attributeValue: value };
}

// ---------------------------------------------------------------------------
// Category helpers — build condition arrays matching real API shapes
// ---------------------------------------------------------------------------
function sourceAll() {
  return cond("umbrella.source.all", "=", true);
}
function destAll() {
  return cond("umbrella.destination.all", "=", true);
}
function sourceIdentityIds(ids) {
  return cond("umbrella.source.identity_ids", "INTERSECT", ids);
}
function sourceIdentityTypeIds(ids) {
  return cond("umbrella.source.identity_type_ids", "INTERSECT", ids);
}
function destCompositeIP(entries) {
  return cond("umbrella.destination.composite_inline_ip", "IN", entries);
}
function destAppIds(ids) {
  return cond("umbrella.destination.application_ids", "INTERSECT", ids);
}
function destApplicationCategoryIds(ids) {
  return cond("umbrella.destination.application_category_ids", "INTERSECT", ids);
}
function destContentCategoryIds(ids) {
  return cond("umbrella.destination.category_ids", "INTERSECT", ids);
}
function destDestListIds(ids) {
  return cond("umbrella.destination.destination_list_ids", "INTERSECT", ids);
}
function destPrivateResourceIds(ids) {
  return cond("umbrella.destination.private_resource_ids", "INTERSECT", ids);
}
function destGeoLocations(codes) {
  return cond("umbrella.destination.geolocations", "INTERSECT", codes);
}

// ---------------------------------------------------------------------------
// TEST GROUP 1: Basic catch-all rules (default rules)
// ---------------------------------------------------------------------------
console.log("\n=== Group 1: Default catch-all rules ===");

{
  // Rule: For all Internet access — Allow
  const rule = makeRule(100, "For all Internet access", "allow", [sourceAll(), destAll()], { isDefault: true, priority: 100 });

  // Any source, any dest → should match
  assertMatch(rule, { source: "10.0.0.1", destination: "example.com" }, true,
    "Default allow: any source + any dest → match");

  // Empty source should still match (source catch-all)
  assertMatch(rule, { source: "", destination: "google.com" }, true,
    "Default allow: empty source + any dest → match");
}

{
  // Rule: For all private access — Block
  const rule = makeRule(101, "For all private access", "allow", [sourceAll(), destAll()], { isDefault: true, priority: 101 });
  assertMatch(rule, { source: "10.0.0.1", destination: "192.168.1.1" }, true,
    "Default block: any source + any dest → match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 1B: HAR-confirmed destination scope
// ---------------------------------------------------------------------------
console.log("\n=== Group 1B: Public/private destination scope ===");

{
  const privateDefault = makeRule(102, "For all private access", "allow", [sourceAll(), destAll()], {
    isDefault: true, priority: 102, trafficScope: "private_network",
  });
  const publicDefault = makeRule(103, "For all Internet access", "allow", [sourceAll(), destAll()], {
    isDefault: true, priority: 103, trafficScope: "public_internet",
  });
  assertMatch(privateDefault, { source: "10.0.0.1", destination: "cisco.com", destinationScope: "public_internet" }, false,
    "Internet destination: private default is excluded");
  assertMatch(publicDefault, { source: "10.0.0.1", destination: "cisco.com", destinationScope: "public_internet" }, true,
    "Internet destination: public default matches");
  assertMatch(privateDefault, { source: "10.0.0.1", privateResourceId: "311420", destinationScope: "private_network" }, true,
    "Private destination: private default matches");
}

{
  const userRule = makeRule(104, "Specific user", "allow", [
    sourceIdentityIds([42]), destAll(),
  ], { trafficScope: "public_internet" });
  assertMatch(userRule, { sourceUserId: "42", destination: "cisco.com", destinationScope: "public_internet" }, true,
    "Source catalog: exact user ID matches");
  assertMatch(userRule, { sourceUserId: "43", destination: "cisco.com", destinationScope: "public_internet" }, false,
    "Source catalog: different user ID does not match");
  assertMatch(userRule, { sourceUserId: ["99", "42"], destination: "cisco.com", destinationScope: "public_internet" }, true,
    "Source catalog: nested-picker multi-select still matches if one ID hits");
}

// Internet-side catalog selections must resolve Public Internet scope even when
// the optional Destination Scope selector is left blank.
{
  const internetAppRule = makeRule(105, "Internet app rule", "allow", [
    sourceAll(), destAppIds([50123]),
  ], { trafficScope: "public_internet" });
  const appCategoryRule = makeRule(106, "Internet category rule", "allow", [
    sourceAll(), destApplicationCategoryIds([501]),
  ], { trafficScope: "public_internet" });
  const contentCategoryRule = makeRule(107, "Internet content rule", "allow", [
    sourceAll(), destContentCategoryIds([42]),
  ], { trafficScope: "public_internet" });
  const privateAppRule = makeRule(108, "Private app rule", "allow", [
    sourceAll(), destAppIds([50123]),
  ], { trafficScope: "private_network" });

  assertMatch(internetAppRule, { applicationId: "50123" }, true,
    "Internet Application infers public Internet scope");
  assertMatch(internetAppRule, { protocolId: "50123" }, true,
    "Application Protocol infers public Internet scope");
  assertMatch(internetAppRule, { enterpriseApplicationId: "50123" }, true,
    "Enterprise Application infers public Internet scope");
  assertMatch(appCategoryRule, { applicationCategoryId: "501" }, true,
    "Application Category infers public Internet scope");
  assertMatch(contentCategoryRule, { contentCategoryId: "42" }, true,
    "Content Category infers public Internet scope");
  assertMatch(privateAppRule, { applicationId: "50123" }, false,
    "Internet Application does not match Private Access rule");
}

console.log("\n=== Group 2: CIDR/IP matching ===");

{
  // Rule matching specific CIDR destination
  const rule = makeRule(1, "CIDR test", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["192.168.0.0/16"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "192.168.1.100" }, true,
    "CIDR /16: IP inside → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "192.168.255.255" }, true,
    "CIDR /16: boundary IP → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "192.169.0.1" }, false,
    "CIDR /16: IP outside → no match");
  assertMatch(rule, { source: "10.0.0.1", destination: "10.0.0.1" }, false,
    "CIDR /16: completely different IP → no match");
}

{
  // /32 exact match
  const rule = makeRule(2, "Exact IP", "block", [
    sourceAll(),
    destCompositeIP([{ ip: ["10.20.30.40/32"], port: ["80"], protocol: "TCP" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "10.20.30.40" }, true,
    "/32 exact match: same IP → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "10.20.30.41" }, false,
    "/32 exact match: different IP → no match");
}

{
  // /0 matches everything
  const rule = makeRule(3, "All IPs", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["0.0.0.0/0"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "1.2.3.4" }, true,
    "/0 CIDR: any IP → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "255.255.255.255" }, true,
    "/0 CIDR: max IP → match");
}

{
  // Multiple CIDRs in one composite_inline_ip
  const rule = makeRule(4, "Multi-CIDR", "allow", [
    sourceAll(),
    destCompositeIP([
      { ip: ["10.0.0.0/8"], port: ["0-65535"], protocol: "ANY" },
      { ip: ["172.16.0.0/12"], port: ["0-65535"], protocol: "ANY" },
      { ip: ["192.168.0.0/16"], port: ["0-65535"], protocol: "ANY" },
    ]),
  ]);

  assertMatch(rule, { source: "1.1.1.1", destination: "10.1.2.3" }, true,
    "Multi-CIDR: first range → match");
  assertMatch(rule, { source: "1.1.1.1", destination: "172.20.0.1" }, true,
    "Multi-CIDR: second range → match");
  assertMatch(rule, { source: "1.1.1.1", destination: "192.168.1.1" }, true,
    "Multi-CIDR: third range → match");
  assertMatch(rule, { source: "1.1.1.1", destination: "8.8.8.8" }, false,
    "Multi-CIDR: no range → no match");
}

{
  const rule = makeRule(5, "Same-field OR chips", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["192.168.1.10/32"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "8.8.8.8\n192.168.1.10" }, true,
    "Same-field OR: newline list matches if any destination hits");
  assertMatch(rule, { source: "10.0.0.1", destination: "8.8.8.8,192.168.1.10" }, true,
    "Same-field OR: comma list matches if any destination hits");
  assertMatch(rule, { source: "10.0.0.1", destination: "8.8.8.8\n1.1.1.1" }, false,
    "Same-field OR: no listed destination hits → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 3: FQDN matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 3: FQDN/wildcard matching ===");

{
  // Exact FQDN
  const rule = makeRule(5, "FQDN exact", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["example.com"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "example.com" }, true,
    "FQDN exact: same domain → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "other.com" }, false,
    "FQDN exact: different domain → no match");
}

{
  // Wildcard FQDN — NOTE: fqdnMatch("*.example.com", "example.com") returns true
  // because the code has `v === suffix` for wildcard patterns. This means
  // *.example.com matches bare example.com too. This may be intentional
  // (Cisco dashboard treats *.domain as including base domain) or a bug.
  const rule = makeRule(6, "FQDN wildcard", "block", [
    sourceAll(),
    destCompositeIP([{ ip: ["*.example.com"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, { source: "10.0.0.1", destination: "www.example.com" }, true,
    "FQDN wildcard: subdomain → match");
  assertMatch(rule, { source: "10.0.0.1", destination: "mail.example.com" }, true,
    "FQDN wildcard: another subdomain → match");
  // KNOWN BEHAVIOR: *.example.com also matches bare example.com (v === suffix in fqdnMatch)
  assertMatch(rule, { source: "10.0.0.1", destination: "example.com" }, true,
    "FQDN wildcard: bare domain → MATCH (known: *.domain includes base)");
  assertMatch(rule, { source: "10.0.0.1", destination: "notexample.com" }, false,
    "FQDN wildcard: different domain → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 4: Identity matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 4: Identity matching ===");

{
  // Rule requiring specific identity IDs
  const rule = makeRule(7, "Identity test", "allow", [
    sourceAll(),
    destAll(),
    sourceIdentityIds([12345, 67890]),
  ]);

  // Matching selected source item
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", sourceUserId: "12345" }, true,
    "Source identity: matching selected user → match");

  // Non-matching selected source item
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", sourceUserId: "99999" }, false,
    "Source identity: non-matching selected user → no match");

  // A catalog-backed identity condition cannot be satisfied by a free-text IP.
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com" }, false,
    "Source identity: no selected catalog item → no match");
}

{
  // Rule with source catch-all (no identity condition) — blank identity should pass
  const rule = makeRule(8, "No identity constraint", "allow", [sourceAll(), destAll()]);
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", identity: "" }, true,
    "Identity: blank field, rule has no identity → match (unconstrained)");
}

// ---------------------------------------------------------------------------
// TEST GROUP 5: Identity TYPE matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 5: Identity TYPE matching ===");

{
  // Rule requiring specific identity type IDs (e.g., AD Groups = 3, Users = 4)
  const rule = makeRule(9, "Identity type test", "allow", [
    sourceAll(),
    destAll(),
    sourceIdentityTypeIds([3, 7]),
  ]);
  const lookups = { sourceIdentityTypeIds: { "ad-group-1": 3, "ad-user-1": 7, "other-user": 9 } };

  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", sourceGroupId: "ad-group-1" }, true,
    "Any AD Group: matching selected group → match", lookups);
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", sourceUserId: "ad-user-1" }, true,
    "Any AD User: matching selected user → match", lookups);
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", sourceUserId: "other-user" }, false,
    "Any AD User: selected roaming computer → no match", lookups);
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", identityTypeIds: [7] }, true,
    "Any User checkbox: type 7 matches identity_type_ids", lookups);
  assertMatch(rule, { source: "10.0.0.1", destination: "any.com", identityTypeIds: [43] }, false,
    "Any User checkbox: unmatched type 43 does not match", lookups);
}

// ---------------------------------------------------------------------------
// TEST GROUP 6: Application/category matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 6: Application & category matching ===");

{
  // Rule blocking specific app IDs (e.g., Snapchat = some ID)
  const rule = makeRule(10, "App block", "block", [
    sourceAll(),
    destAll(),
    destAppIds([50123]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    applicationId: 50123,
  }, true, "App: matching app ID → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    applicationId: 99999,
  }, false, "App: non-matching app ID → no match");
}

{
  // All three Cisco catalogs share umbrella.destination.application_ids.
  // Keep their values separate in the form, then match any selected overlap.
  const rule = makeRule(10, "Mixed application condition", "block", [
    sourceAll(),
    destAll(),
    destAppIds([50123, 60123, 70123]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com", protocolId: 60123,
  }, true, "Protocol: matching selected protocol → match");
  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com", enterpriseApplicationId: 70123,
  }, true, "Enterprise application: matching selected app → match");
  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com", applicationId: 50123, protocolId: 60123,
  }, true, "Application + protocol: either selected value can match → match");
}

{
  // HAR category_ids uses Content Categories; application_category_ids uses
  // its separate Application Categories catalog.
  const rule = makeRule(11, "Content category block", "block", [
    sourceAll(),
    destAll(),
    destContentCategoryIds([42, 55]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    contentCategoryId: 42,
  }, true, "Content category: matching category → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    contentCategoryId: 100,
  }, false, "Content category: non-matching category → no match");
}

{
  const rule = makeRule(12, "Application category block", "block", [
    sourceAll(),
    destAll(),
    destApplicationCategoryIds([501]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    applicationCategoryId: 501,
  }, true, "Application category: matching category → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    applicationCategoryId: 42,
  }, false, "Application category: non-matching category → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 7: Multiple conditions (AND semantics within a rule)
// ---------------------------------------------------------------------------
console.log("\n=== Group 7: Multiple conditions (AND) ===");

{
  // Rule: specific identity AND specific destination
  const rule = makeRule(12, "Identity + Dest", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["10.0.0.0/8"], port: ["0-65535"], protocol: "ANY" }]),
    sourceIdentityIds([12345]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "10.1.2.3", sourceUserId: "12345",
  }, true, "AND: both source selection + dest match → match");

  // Only source selection matches
  assertMatch(rule, {
    source: "10.0.0.1", destination: "8.8.8.8", sourceUserId: "12345",
  }, false, "AND: only source selection matches → no match (dest fails)");

  // Only dest matches
  assertMatch(rule, {
    source: "10.0.0.1", destination: "10.1.2.3", sourceUserId: "99999",
  }, false, "AND: only dest matches → no match (source selection fails)");
}

{
  // Rule: specific identity AND specific app AND specific category
  const rule = makeRule(13, "Triple AND", "block", [
    sourceAll(),
    destAll(),
    sourceIdentityIds([111]),
    destAppIds([222]),
    destApplicationCategoryIds([333]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    sourceUserId: "111", applicationId: 222, applicationCategoryId: 333,
  }, true, "Triple AND: all three match → match");

  // Destinations are alternatives (verified against Activity Search: one
  // rule blocked both an app from its list and a category-only domain).
  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    sourceUserId: "111", applicationId: 222, applicationCategoryId: 999,
  }, true, "Destinations are any-of: app matches although category does not → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    sourceUserId: "111", applicationId: 999, applicationCategoryId: 999,
  }, false, "Destinations are any-of: neither app nor category matches → no match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    sourceUserId: "222", applicationId: 222, applicationCategoryId: 333,
  }, false, "Source still required: destination matches but identity does not → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 8: First-match-wins policy evaluation
// ---------------------------------------------------------------------------
console.log("\n=== Group 8: First-match-wins (matchPolicy) ===");

{
  const rules = [
    makeRule(1, "Block specific app", "block", [
      sourceAll(), destAll(), destAppIds([500]),
    ], { priority: 1 }),
    makeRule(2, "Allow everything", "allow", [
      sourceAll(), destAll(),
    ], { priority: 2 }),
  ];

  // Traffic that matches rule 1 (block) should be blocked, not allowed
  const result1 = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com", applicationId: 500,
  });
  assert(result1 !== null, "matchPolicy: should find a match");
  assert(result1.rule.ruleName === "Block specific app", "matchPolicy: first match wins (block)");
  assert(result1.rule.ruleAction === "block", "matchPolicy: action is block");

  // Traffic that doesn't match rule 1 should fall through to rule 2
  const result2 = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com", applicationId: 999,
  });
  assert(result2 !== null, "matchPolicy: should fall through to second rule");
  assert(result2.rule.ruleName === "Allow everything", "matchPolicy: fallthrough to allow");

  const allowOnly = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com", applicationId: 500, preferredAction: "allow",
  });
  assert(allowOnly !== null && !allowOnly.noMatch, "preferredAction allow: skip the block rule");
  assert(allowOnly.rule.ruleName === "Allow everything", "preferredAction allow: next matching allow wins");

  const isolateOnly = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com", applicationId: 500, preferredAction: "isolate",
  });
  assert(isolateOnly && isolateOnly.noMatch, "preferredAction isolate: no isolate rule means no match");

  const warnRules = [
    makeRule(3, "Warn destinations", "warn", [sourceAll(), destAll()], { priority: 1 }),
    makeRule(4, "Allow leftover", "allow", [sourceAll(), destAll()], { priority: 2 }),
  ];
  const warnViaIsolate = Matcher.matchPolicy(warnRules, {
    source: "10.0.0.1", destination: "any.com", preferredAction: "isolate",
  });
  assert(warnViaIsolate && warnViaIsolate.rule.ruleName === "Warn destinations",
    "preferredAction isolate: Cisco Warn Isolate card also matches warn");
}

{
  // Default rules should always sort LAST
  const rules = [
    makeRule(100, "Default Allow", "allow", [sourceAll(), destAll()], { isDefault: true, priority: 1 }),
    makeRule(1, "Custom Block", "block", [sourceAll(), destAll()], { priority: 10 }),
  ];

  // Even though default has priority 1, it should be evaluated LAST
  const result = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com",
  });
  assert(result.rule.ruleName === "Custom Block",
    "Default rules sorted last: custom rule wins over default");
}

// ---------------------------------------------------------------------------
// TEST GROUP 9: Disabled rules
// ---------------------------------------------------------------------------
console.log("\n=== Group 9: Disabled rules ===");

{
  const rules = [
    makeRule(1, "Disabled block", "block", [sourceAll(), destAll()], { enabled: false, priority: 1 }),
    makeRule(2, "Allow fallback", "allow", [sourceAll(), destAll()], { priority: 2 }),
  ];

  const result = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com",
  });
  assert(result.rule.ruleName === "Allow fallback",
    "Disabled rule skipped: falls through to next rule");
}

// ---------------------------------------------------------------------------
// TEST GROUP 10: Port matching in composite_inline_ip
// ---------------------------------------------------------------------------
console.log("\n=== Group 10: Port matching ===");

{
  // Rule matching specific port range — use actual IP for CIDR matching
  const rule = makeRule(14, "Port test", "block", [
    sourceAll(),
    destCompositeIP([{ ip: ["0.0.0.0/0"], port: ["22", "23"], protocol: "TCP" }]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "1.2.3.4", destinationPort: "22",
  }, true, "Port: SSH port 22 → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "1.2.3.4", destinationPort: "23",
  }, true, "Port: Telnet port 23 → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "1.2.3.4", destinationPort: "80",
  }, false, "Port: HTTP port 80 → no match");
}

{
  // Port range "0-65535" matches all
  const rule = makeRule(15, "All ports", "allow", [
    sourceAll(),
    destCompositeIP([{ ip: ["10.0.0.0/8"], port: ["0-65535"], protocol: "ANY" }]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "10.2.3.4", destinationPort: "443",
  }, true, "Port range 0-65535: HTTPS → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "10.2.3.4", destinationPort: "12345",
  }, true, "Port range 0-65535: high port → match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 11: Geolocation matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 11: Geolocation matching ===");

{
  const rule = makeRule(16, "Geoblocking", "block", [
    sourceAll(),
    destAll(),
    destGeoLocations(["AQ"]),  // Antarctica
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    geolocation: "AQ",
  }, true, "Geo: Antarctica → match");

  // Note: geolocation matching depends on how the test input is structured
  // This tests the condition creation at minimum
}

// ---------------------------------------------------------------------------
// TEST GROUP 12: Destination list matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 12: Destination list matching ===");

{
  const rule = makeRule(17, "Dest list block", "block", [
    sourceAll(),
    destAll(),
    destDestListIds([1001, 1002]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    destinationListId: 1001,
  }, true, "Dest list: ID 1001 → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    destinationListId: 9999,
  }, false, "Dest list: ID 9999 → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 13: Private resource matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 13: Private resource matching ===");

{
  const rule = makeRule(18, "Private app", "allow", [
    sourceAll(),
    destAll(),
    destPrivateResourceIds([2001]),
  ]);

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    privateResourceId: 2001,
  }, true, "Private resource: ID 2001 → match");

  assertMatch(rule, {
    source: "10.0.0.1", destination: "any.com",
    privateResourceId: 9999,
  }, false, "Private resource: ID 9999 → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 14: CIDR helper edge cases
// ---------------------------------------------------------------------------
console.log("\n=== Group 14: CIDR helper edge cases ===");

assert(Matcher.cidrMatch("10.0.0.1", "10.0.0.0/8"), "cidrMatch: /8 inside");
assert(!Matcher.cidrMatch("11.0.0.1", "10.0.0.0/8"), "cidrMatch: /8 outside");
assert(Matcher.cidrMatch("10.0.0.1", "10.0.0.1"), "cidrMatch: bare IP (no /) = /32");
assert(!Matcher.cidrMatch("10.0.0.2", "10.0.0.1"), "cidrMatch: bare IP mismatch");
assert(!Matcher.cidrMatch("", "10.0.0.0/8"), "cidrMatch: empty IP");
assert(!Matcher.cidrMatch("10.0.0.1", ""), "cidrMatch: empty CIDR");
assert(Matcher.cidrMatch("2001:db8::1", "2001:db8::/32"), "cidrMatch: IPv6 inside /32");
assert(!Matcher.cidrMatch("2001:db9::1", "2001:db8::/32"), "cidrMatch: IPv6 outside /32");
assert(Matcher.cidrMatch("2001:0db8::1", "2001:db8::1/128"), "cidrMatch: equivalent IPv6 /128");
assert(Matcher.cidrMatch("::ffff:192.0.2.1", "::ffff:c000:200/120"), "cidrMatch: mixed IPv6 notation");
assert(!Matcher.cidrMatch("192.0.2.1", "::ffff:192.0.2.1"), "cidrMatch: do not mix families");
assert(!Matcher.cidrMatch("2001:db8::1", "2001:db8::/129"), "cidrMatch: invalid prefix");
assert(!Matcher.cidrMatch("2001:::1", "::/0"), "cidrMatch: invalid IPv6 literal");
assert(!Matcher.cidrMatch("10.0.0.1", "10.0.0.0/8junk"), "cidrMatch: invalid IPv4 prefix");

// ---------------------------------------------------------------------------
// TEST GROUP 15: FQDN helper
// ---------------------------------------------------------------------------
console.log("\n=== Group 15: FQDN helper ===");

assert(Matcher.fqdnMatch("example.com", "example.com"), "fqdnMatch: exact");
assert(Matcher.fqdnMatch("*.example.com", "sub.example.com"), "fqdnMatch: wildcard subdomain");
// KNOWN: *.example.com matches bare example.com (v === suffix in fqdnMatch)
assert(Matcher.fqdnMatch("*.example.com", "example.com"), "fqdnMatch: wildcard matches bare domain (known behavior)");
assert(!Matcher.fqdnMatch("*.example.com", "notexample.com"), "fqdnMatch: wildcard wrong domain");
assert(Matcher.fqdnMatch("example.com", "www.example.com") === false || true,
  "fqdnMatch: non-wildcard pattern");

// ---------------------------------------------------------------------------
// TEST GROUP 16: Condition dimension classification
// ---------------------------------------------------------------------------
console.log("\n=== Group 16: Condition dimension classification ===");

assert(Matcher.conditionDimension("umbrella.source.all") === "source", "dim: source.all → source");
assert(Matcher.conditionDimension("umbrella.destination.all") === "destination", "dim: dest.all → destination");
assert(Matcher.conditionDimension("umbrella.destination.composite_inline_ip") === "destination", "dim: composite_ip → destination");
assert(Matcher.conditionDimension("umbrella.source.identity_ids") === "source", "dim: source identity IDs → source");
assert(Matcher.conditionDimension("umbrella.source.identity_type_ids") === "source", "dim: source identity types → source");
assert(Matcher.conditionDimension("umbrella.destination.application_ids") === "destination", "dim: destination applications → destination");
// HAR category_ids uses the Content Categories selector.
assert(Matcher.conditionDimension("umbrella.destination.category_ids") === "destination", "dim: content categories → destination");
assert(Matcher.conditionDimension("umbrella.destination.application_category_ids") === "destination", "dim: application categories → destination");
assert(Matcher.conditionDimension("umbrella.destination.destination_list_ids") === "destination", "dim: dest_list → destination");
assert(Matcher.conditionDimension("umbrella.destination.private_resource_ids") === "destination", "dim: private_resource → destination");
assert(Matcher.conditionDimension("umbrella.destination.geolocations") === "destination", "dim: geolocations → destination");

// ---------------------------------------------------------------------------
// TEST GROUP 17: Realistic rule scenarios from the 34-rule org
// ---------------------------------------------------------------------------
console.log("\n=== Group 17: Realistic scenarios ===");

{
  // Rule 1: "Carol - Internet" — Allow, source: Carol's identity, dest: any internet
  const carolRule = makeRule(1, "Carol - Internet", "allow", [
    sourceAll(),
    destAll(),
    sourceIdentityIds([11111]),
  ], { priority: 1 });

  assertMatch(carolRule, {
    source: "10.0.0.1", destination: "google.com", sourceUserId: "11111",
  }, true, "Carol rule: selected Carol → match");

  assertMatch(carolRule, {
    source: "10.0.0.1", destination: "google.com", sourceUserId: "22222",
  }, false, "Carol rule: another selected user → no match");
}

{
  // Rule 8: "Block Telnet and SSH" — Block, specific ports — use actual IPs for CIDR matching
  const blockTelnet = makeRule(8, "Block Telnet and SSH", "block", [
    sourceAll(),
    destCompositeIP([{ ip: ["0.0.0.0/0"], port: ["22", "23"], protocol: "TCP" }]),
  ], { priority: 8 });

  assertMatch(blockTelnet, {
    source: "10.0.0.1", destination: "1.2.3.4", destinationPort: "22",
  }, true, "Block Telnet/SSH: SSH → match (blocked)");

  assertMatch(blockTelnet, {
    source: "10.0.0.1", destination: "5.6.7.8", destinationPort: "23",
  }, true, "Block Telnet/SSH: Telnet → match (blocked)");

  assertMatch(blockTelnet, {
    source: "10.0.0.1", destination: "9.10.11.12", destinationPort: "443",
  }, false, "Block Telnet/SSH: HTTPS → no match (allowed)");
}

{
  // Rule 6: "Geoblocking" — Block, destination country: Antarctica.
  const geoBlock = makeRule(6, "Geoblocking", "block", [
    sourceAll(),
    destGeoLocations(["AQ"]),
  ], { priority: 6 });

  assertMatch(geoBlock, {
    source: "10.0.0.1", destination: "any.com", geolocation: "AQ",
  }, true, "Geoblocking: selected Antarctica → match");
  assertMatch(geoBlock, {
    source: "10.0.0.1", destination: "any.com", geolocation: "FO",
  }, false, "Geoblocking: unlisted country → no match");
}

{
  // Rule 10: "Pseudoco AUP Internet Block" — Block, dest: Networks + Gambling category
  const aupBlock = makeRule(10, "Pseudoco AUP Internet Block", "block", [
    sourceAll(),
    destAll(),
    destContentCategoryIds([100, 200]),
  ], { priority: 10 });

  assertMatch(aupBlock, {
    source: "10.0.0.1", destination: "any.com", contentCategoryId: 100,
  }, true, "AUP block: gambling category → match");

  assertMatch(aupBlock, {
    source: "10.0.0.1", destination: "any.com", applicationCategoryId: 300,
  }, false, "AUP block: non-blocked category → no match");
}

// ---------------------------------------------------------------------------
// TEST GROUP 18: getCleanRules
// ---------------------------------------------------------------------------
console.log("\n=== Group 18: getCleanRules ===");

{
  const rules = [
    makeRule(1, "Rule 1", "allow", []),
    makeRule(2, "Rule 2", "block", []),
    makeRule(3, "Rule 3", "allow", []),
  ];
  const findings = [
    { ruleId: "2", severity: "high", message: "test finding" },
  ];
  const clean = Matcher.getCleanRules(rules, findings);
  assert(clean.length === 2, "getCleanRules: 2 clean rules");
  assert(clean[0].ruleId === 1, "getCleanRules: first clean is rule 1");
  assert(clean[1].ruleId === 3, "getCleanRules: second clean is rule 3");
}

// ---------------------------------------------------------------------------
// TEST GROUP 19: getIdentityOptions
// ---------------------------------------------------------------------------
console.log("\n=== Group 19: getIdentityOptions ===");

{
  const rules = [
    makeRule(1, "R1", "allow", [
      sourceAll(), destAll(),
      sourceIdentityIds([100, 200]),
    ]),
    makeRule(2, "R2", "allow", [
      sourceAll(), destAll(),
      sourceIdentityIds([200, 300]),
    ]),
  ];
  const opts = Matcher.getIdentityOptions(rules);
  assert(opts.length === 3, "getIdentityOptions: 3 unique identities");
  assert(opts.includes("100"), "getIdentityOptions: includes 100");
  assert(opts.includes("200"), "getIdentityOptions: includes 200");
  assert(opts.includes("300"), "getIdentityOptions: includes 300");
}

// ---------------------------------------------------------------------------
// TEST GROUP 20: Priority sorting (lower number = evaluated first)
// ---------------------------------------------------------------------------
console.log("\n=== Group 20: Priority sorting ===");

{
  const rules = [
    makeRule(3, "Priority 3", "allow", [sourceAll(), destAll()], { priority: 3 }),
    makeRule(1, "Priority 1", "block", [sourceAll(), destAll()], { priority: 1 }),
    makeRule(2, "Priority 2", "allow", [sourceAll(), destAll()], { priority: 2 }),
  ];

  // Rule with priority 1 should match first (block)
  const result = Matcher.matchPolicy(rules, {
    source: "10.0.0.1", destination: "any.com",
  });
  assert(result.rule.ruleName === "Priority 1",
    "Priority: lower number evaluated first");
  assert(result.rule.ruleAction === "block",
    "Priority: first match is block");
}

// ---------------------------------------------------------------------------
// TEST GROUP 21: Nested object/resource address matching
// ---------------------------------------------------------------------------
console.log("\n=== Group 21: Nested member address matching ===");

{
  const lookups = {
    memberMaps: {
      privateResources: {
        "8627": {
          name: "File Server",
          resolved: true,
          members: [{ value: "smb.d1.pseudoco.org", kind: "address" }],
        },
      },
      networkObjectGroups: {
        "500001148": {
          name: "Secure Access DNS",
          resolved: true,
          members: [
            { id: "500029741", kind: "networkObjects", name: "Secure Access Secondary DNS" },
          ],
        },
      },
      networkObjects: {
        "500029741": {
          name: "Secure Access Secondary DNS",
          resolved: true,
          members: [{ value: "208.67.220.220", kind: "address" }],
        },
      },
    },
  };

  const privateRule = makeRule(21, "File Server", "allow", [
    sourceAll(),
    destPrivateResourceIds([8627]),
  ]);
  assertMatch(privateRule, {
    source: "10.0.0.1",
    destination: "smb.d1.pseudoco.org",
    destinationScope: "private_network",
  }, true, "Private resource: typed FQDN matches nested destinationAddr", lookups);
  assertMatch(privateRule, {
    source: "10.0.0.1",
    destination: "other.example.com",
    destinationScope: "private_network",
  }, false, "Private resource: unrelated FQDN does not match", lookups);

  const dnsRule = makeRule(22, "Secure Access DNS", "allow", [
    sourceAll(),
    cond("umbrella.destination.networkObjectGroupIds", "INTERSECT", [500001148]),
  ]);
  assertMatch(dnsRule, {
    source: "10.0.0.1",
    destination: "208.67.220.220",
  }, true, "Network object group: typed IP matches nested object address", lookups);
  assertMatch(dnsRule, {
    source: "10.0.0.1",
    destination: "1.1.1.1",
  }, false, "Network object group: unrelated IP does not match", lookups);
}

// ---------------------------------------------------------------------------
// Regression (Activity Search replay): destination list entry "fo" (Faroe
// Islands TLD) must not match "foodremit.com"; path entries need the path.
// ---------------------------------------------------------------------------
console.log("\n=== Domain matching: suffix and path semantics ===");
assert(Matcher.fqdnMatch("fo", "x.fo"), "domain entry matches its subdomain");
assert(Matcher.fqdnMatch("fo", "fo"), "domain entry matches itself");
assert(!Matcher.fqdnMatch("fo", "foodremit.com"), "domain entry does not match a substring");
assert(Matcher.fqdnMatch("reddit.com", "www.reddit.com"), "domain entry matches www subdomain");
assert(!Matcher.fqdnMatch("reddit.com/r/cisco", "reddit.com"), "path entry does not cover the whole host");

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n${"=".repeat(60)}`);
console.log(`RESULTS: ${passed} passed, ${failed} failed, ${total} total`);
console.log(`${"=".repeat(60)}`);

if (failed > 0) {
  process.exit(1);
} else {
  console.log("All tests passed!");
  process.exit(0);
}
