#!/usr/bin/env node
// =============================================================================
// test-checks.js — Policy checks test harness (shadowing, conflicts, etc.)
//
// Extracts the check functions from service-worker.js and tests them against
// synthetic rule sets that exercise each check type.
//
// Run: node test-checks.js
// =============================================================================

"use strict";

// ---------------------------------------------------------------------------
// Bootstrap service-worker check helpers (pure functions, no browser APIs)
// ---------------------------------------------------------------------------
const fs = require("fs");
const path = require("path");
const vm = require("vm");

// Extract just the check-related functions from service-worker.js
const swSrc = fs.readFileSync(
  path.join(__dirname, "extension/background/service-worker.js"),
  "utf-8"
);

// Create a sandbox with the functions we need
const sandbox = { console, JSON, Array, Object, String, parseInt, isNaN, Math, Date, RegExp, Set, Map, Promise, Error };
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.globalThis = sandbox;
vm.createContext(sandbox);

// Inject the helper functions by evaluating them
const helpersCode = `
function compareRulePriority(a, b) {
  if (a.is_default !== b.is_default) return a.is_default ? 1 : -1;
  return a.order - b.order;
}

function _conditionDimension(attributeName) {
  const an = (attributeName || "").toLowerCase();
  if (an === "umbrella.source.all") return "source";
  if (an === "umbrella.destination.all") return "destination";
  if (an === "umbrella.destination.composite_inline_ip") return "destination";
  if (an === "umbrella.source.composite_inline_ip") return "source";
  if (an.includes("identity")) return "identity";
  if (an.includes("application") || an.includes("app") || an.includes("protocol") || an.includes("category")) return "app";
  if (an.includes("destination_list") || an.includes("geo")) return "destination";
  return "unknown";
}

function _isCatchAllCondition(cond) {
  return cond.attributeValue === true && (cond.attributeName || "").toLowerCase().endsWith(".all");
}

function _bucketConditionsByDimension(rule) {
  const conds = rule.conditions || rule.ruleConditions || [];
  const buckets = { source: [], destination: [], identity: [], app: [], unknown: [] };
  for (const c of conds) buckets[_conditionDimension(c.attributeName)].push(c);
  return buckets;
}

function _canonicalConditionSet(conds) {
  return JSON.stringify(
    [...conds]
      .map((c) => ({ n: c.attributeName, o: c.attributeOperator || "=", v: c.attributeValue }))
      .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)))
  );
}

function _dimensionUnconstrained(conds) {
  return conds.length === 0 || (conds.length === 1 && _isCatchAllCondition(conds[0]));
}

function _dimensionBroadOrEqual(blockerConds, ruleConds) {
  if (_dimensionUnconstrained(blockerConds)) return true;
  return _canonicalConditionSet(blockerConds) === _canonicalConditionSet(ruleConds);
}

function _matchCriteriaBroadOrEqual(blocker, rule) {
  const bBuckets = _bucketConditionsByDimension(blocker);
  const rBuckets = _bucketConditionsByDimension(rule);
  const dimensions = ["source", "destination", "identity", "app"];
  for (const dim of dimensions) {
    if (!_dimensionBroadOrEqual(bBuckets[dim], rBuckets[dim])) return false;
  }
  return true;
}

function _matchCriteriaEqual(a, b) {
  const aBuckets = _bucketConditionsByDimension(a);
  const bBuckets = _bucketConditionsByDimension(b);
  const dimensions = ["source", "destination", "identity", "app"];
  for (const dim of dimensions) {
    if (_canonicalConditionSet(aBuckets[dim]) !== _canonicalConditionSet(bBuckets[dim])) return false;
  }
  return true;
}

function _fullyCriticalEqual(a, b) {
  if (a.action !== b.action) return false;
  if (a.is_default !== b.is_default) return false;
  return _matchCriteriaEqual(a, b);
}
`;
vm.runInContext(helpersCode, sandbox);

// Now evaluate the check functions
const checkFns = `
function checkPermissive(rules) {
  const findings = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.action !== "allow") continue;
    const srcAny = JSON.stringify(rule.sources) === JSON.stringify(["any"]);
    const dstAny = JSON.stringify(rule.destinations) === JSON.stringify(["any"]);
    const appAny = rule.applications.length === 0 || JSON.stringify(rule.applications) === JSON.stringify(["any"]);
    const condEmpty = rule.conditions.length === 0;
    if (srcAny && dstAny && appAny && condEmpty) {
      findings.push({ checkId: "overly-permissive", severity: "critical", ruleId: rule.id, ruleName: rule.name, message: "Overly permissive" });
    }
  }
  return findings;
}

function checkShadowing(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];
  for (let i = 0; i < sorted.length; i++) {
    const rule = sorted[i];
    if (!rule.enabled) continue;
    if (rule.is_default) continue;
    for (let j = 0; j < i; j++) {
      const blocker = sorted[j];
      if (!blocker.enabled) continue;
      if (blocker.action === rule.action && _matchCriteriaBroadOrEqual(blocker, rule)) {
        findings.push({ checkId: "shadowing", severity: "high", ruleId: rule.id, ruleName: rule.name, blockerName: blocker.name });
        break;
      }
    }
  }
  return findings;
}

function checkConflicts(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];
  for (let i = 0; i < sorted.length; i++) {
    const ruleA = sorted[i];
    if (!ruleA.enabled) continue;
    for (let j = i + 1; j < sorted.length; j++) {
      const ruleB = sorted[j];
      if (!ruleB.enabled) continue;
      if (ruleA.is_default || ruleB.is_default) continue;
      if (_matchCriteriaEqual(ruleA, ruleB) && ruleA.action !== ruleB.action) {
        findings.push({ checkId: "conflicting-rules", severity: "high", ruleId: ruleA.id, ruleName: ruleA.name });
        findings.push({ checkId: "conflicting-rules", severity: "high", ruleId: ruleB.id, ruleName: ruleB.name });
      }
    }
  }
  return findings;
}

function checkDuplicates(rules) {
  const sorted = [...rules].sort(compareRulePriority);
  const findings = [];
  for (let i = 0; i < sorted.length; i++) {
    const ruleA = sorted[i];
    if (!ruleA.enabled) continue;
    for (let j = i + 1; j < sorted.length; j++) {
      const ruleB = sorted[j];
      if (!ruleB.enabled) continue;
      if (ruleB.is_default) continue;
      if (_fullyCriticalEqual(ruleA, ruleB)) {
        findings.push({ checkId: "duplicate-rule", severity: "low", ruleId: ruleB.id, ruleName: ruleB.name, duplicateOf: ruleA.name });
      }
    }
  }
  return findings;
}

function checkLogging(rules) {
  const findings = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.logging_enabled === false) {
      findings.push({ checkId: "logging-disabled", severity: "medium", ruleId: rule.id, ruleName: rule.name });
    }
  }
  return findings;
}

function checkInspection(rules) {
  const findings = [];
  const profileKeys = [{ field: "ips_enabled", label: "ips" }, { field: "amp_malware_enabled", label: "amp_malware" }, { field: "tls_decryption_enabled", label: "tls_decryption" }, { field: "dlp_enabled", label: "dlp" }];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.action !== "allow") continue;
    const buckets = _bucketConditionsByDimension(rule);
    const isBroad = _dimensionUnconstrained(buckets.source) || _dimensionUnconstrained(buckets.destination);
    if (!isBroad) continue;
    const sp = rule.security_profiles || {};
    const missing = profileKeys.filter(({ field }) => sp[field] === false).map(({ label }) => label);
    if (missing.length > 0) {
      findings.push({ checkId: "inspection-bypass", severity: "high", ruleId: rule.id, ruleName: rule.name, missing });
    }
  }
  return findings;
}
`;
vm.runInContext(checkFns, sandbox);

// ---------------------------------------------------------------------------
// Test framework
// ---------------------------------------------------------------------------
let passed = 0, failed = 0, total = 0;
function assert(cond, msg) {
  total++;
  if (cond) { passed++; } else { failed++; console.error(`  FAIL: ${msg}`); }
}
function find(findings, checkId, ruleName) {
  return findings.find(f => f.checkId === checkId && f.ruleName === ruleName);
}

function makeRule(id, name, opts = {}) {
  const conds = opts.conditions || [];
  const srcCatchAll = conds.some(c => c.attributeName === "umbrella.source.all" && c.attributeValue === true);
  const dstCatchAll = conds.some(c => c.attributeName === "umbrella.destination.all" && c.attributeValue === true);
  return {
    id, name, order: opts.priority || id,
    enabled: opts.enabled !== undefined ? opts.enabled : true,
    is_default: opts.isDefault || false,
    action: opts.action || "allow",
    sources: opts.sources || ["any"],
    destinations: opts.destinations || ["any"],
    applications: opts.applications || [],
    conditions: conds,
    logging_enabled: opts.logging !== undefined ? opts.logging : true,
    security_profiles: opts.security_profiles || { ips_enabled: true, amp_malware_enabled: true, tls_decryption_enabled: true, dlp_enabled: true },
  };
}
function cond(an, op, val) { return { attributeName: an, attributeOperator: op, attributeValue: val }; }

// ---------------------------------------------------------------------------
// Group 1: checkPermissive
// ---------------------------------------------------------------------------
console.log("\n=== Group 1: checkPermissive ===");
{
  // checkPermissive checks: sources=["any"], destinations=["any"], applications=[], conditions.length===0
  // NOTE: real API rules always have conditions (even catch-all rules have umbrella.source.all/destination.all),
  // so conditions.length===0 means this check only catches mock-shaped payloads.
  // This is a known limitation of the current checkPermissive implementation.
  const rules = [
    makeRule(1, "Wide open allow (mock shape)", { action: "allow", sources: ["any"], destinations: ["any"], applications: [], conditions: [] }),
    makeRule(2, "Restricted allow (has conditions)", { action: "allow", conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.source.identity_ids", "INTERSECT", [100])] }),
    makeRule(3, "Block rule", { action: "block", conditions: [] }),
  ];
  const findings = sandbox.checkPermissive(rules);
  assert(find(findings, "overly-permissive", "Wide open allow (mock shape)") !== undefined, "Permissive: wide open mock → critical finding");
  assert(find(findings, "overly-permissive", "Restricted allow (has conditions)") === undefined, "Permissive: has conditions → no finding");
  assert(find(findings, "overly-permissive", "Block rule") === undefined, "Permissive: block action → no finding");
}
{
  // Default rules should also be flagged if they're overly permissive
  const rules = [
    makeRule(100, "Default Allow", { action: "allow", isDefault: true, priority: 100, conditions: [] }),
  ];
  const findings = sandbox.checkPermissive(rules);
  assert(find(findings, "overly-permissive", "Default Allow") !== undefined, "Permissive: default rule → also flagged");
}

// ---------------------------------------------------------------------------
// Group 2: checkShadowing
// ---------------------------------------------------------------------------
console.log("\n=== Group 2: checkShadowing ===");
{
  // Rule 2 is shadowed by rule 1 (same action, broader or equal criteria)
  const rules = [
    makeRule(1, "Block all internet", { action: "block", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(2, "Block specific app", { action: "block", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [500])] }),
  ];
  const findings = sandbox.checkShadowing(rules);
  assert(find(findings, "shadowing", "Block specific app") !== undefined, "Shadowing: specific rule shadowed by broad rule");
  assert(find(findings, "shadowing", "Block all internet") === undefined, "Shadowing: first rule not flagged");
}
{
  // Different actions should NOT produce shadowing
  const rules = [
    makeRule(1, "Allow all", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(2, "Block specific", { action: "block", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [500])] }),
  ];
  const findings = sandbox.checkShadowing(rules);
  assert(find(findings, "shadowing", "Block specific") === undefined, "Shadowing: different actions → no shadowing");
}
{
  // Default rules should never be flagged as shadowed
  const rules = [
    makeRule(1, "Custom rule", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(100, "Default rule", { action: "allow", isDefault: true, priority: 100, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
  ];
  const findings = sandbox.checkShadowing(rules);
  assert(find(findings, "shadowing", "Default rule") === undefined, "Shadowing: default rules skipped");
}

// ---------------------------------------------------------------------------
// Group 3: checkConflicts
// ---------------------------------------------------------------------------
console.log("\n=== Group 3: checkConflicts ===");
{
  // Same criteria, different actions → conflict
  const rules = [
    makeRule(1, "Allow apps", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [100, 200])] }),
    makeRule(2, "Block apps", { action: "block", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [100, 200])] }),
  ];
  const findings = sandbox.checkConflicts(rules);
  assert(find(findings, "conflicting-rules", "Allow apps") !== undefined, "Conflict: allow vs block → both flagged");
  assert(find(findings, "conflicting-rules", "Block apps") !== undefined, "Conflict: both rules flagged");
}
{
  // Same criteria, same action → no conflict
  const rules = [
    makeRule(1, "Allow apps A", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [100])] }),
    makeRule(2, "Allow apps B", { action: "allow", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.destination.application_ids", "INTERSECT", [100])] }),
  ];
  const findings = sandbox.checkConflicts(rules);
  assert(findings.length === 0, "Conflict: same action → no conflict");
}
{
  // Custom vs default → should NOT be flagged
  const rules = [
    makeRule(1, "Custom block", { action: "block", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(100, "Default allow", { action: "allow", isDefault: true, priority: 100, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
  ];
  const findings = sandbox.checkConflicts(rules);
  assert(findings.length === 0, "Conflict: custom vs default → not flagged");
}

// ---------------------------------------------------------------------------
// Group 4: checkDuplicates
// ---------------------------------------------------------------------------
console.log("\n=== Group 4: checkDuplicates ===");
{
  // Exact same conditions + action → duplicate
  const rules = [
    makeRule(1, "Original", { action: "block", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.source.identity_ids", "INTERSECT", [100])] }),
    makeRule(2, "Clone", { action: "block", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true), cond("umbrella.source.identity_ids", "INTERSECT", [100])] }),
  ];
  const findings = sandbox.checkDuplicates(rules);
  assert(find(findings, "duplicate-rule", "Clone") !== undefined, "Duplicate: exact clone → flagged");
  assert(find(findings, "duplicate-rule", "Original") === undefined, "Duplicate: original not flagged");
}
{
  // Different actions → not a duplicate
  const rules = [
    makeRule(1, "Allow", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(2, "Block", { action: "block", priority: 2, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
  ];
  const findings = sandbox.checkDuplicates(rules);
  assert(findings.length === 0, "Duplicate: different actions → not flagged");
}
{
  // Default rule should not be flagged as duplicate of custom
  const rules = [
    makeRule(1, "Custom", { action: "allow", priority: 1, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
    makeRule(100, "Default", { action: "allow", isDefault: true, priority: 100, conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)] }),
  ];
  const findings = sandbox.checkDuplicates(rules);
  assert(find(findings, "duplicate-rule", "Default") === undefined, "Duplicate: default rule skipped");
}

// ---------------------------------------------------------------------------
// Group 5: checkLogging
// ---------------------------------------------------------------------------
console.log("\n=== Group 5: checkLogging ===");
{
  const rules = [
    makeRule(1, "Logged rule", { logging: true }),
    makeRule(2, "Unlogged rule", { logging: false }),
  ];
  const findings = sandbox.checkLogging(rules);
  assert(find(findings, "logging-disabled", "Logged rule") === undefined, "Logging: logged rule → no finding");
  assert(find(findings, "logging-disabled", "Unlogged rule") !== undefined, "Logging: unlogged rule → medium finding");
}

// ---------------------------------------------------------------------------
// Group 6: checkInspection
// ---------------------------------------------------------------------------
console.log("\n=== Group 6: checkInspection ===");
{
  // Broad allow with missing security profiles → inspection bypass
  const rules = [
    makeRule(1, "Broad allow", {
      action: "allow",
      conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)],
      security_profiles: { ips_enabled: false, amp_malware_enabled: false, tls_decryption_enabled: true, dlp_enabled: true },
    }),
  ];
  const findings = sandbox.checkInspection(rules);
  assert(find(findings, "inspection-bypass", "Broad allow") !== undefined, "Inspection: broad allow with missing profiles → flagged");
  assert(find(findings, "inspection-bypass", "Broad allow").missing.includes("ips"), "Inspection: IPS listed as missing");
  assert(find(findings, "inspection-bypass", "Broad allow").missing.includes("amp_malware"), "Inspection: AMP listed as missing");
}
{
  // Broad allow with all profiles enabled → no finding
  const rules = [
    makeRule(1, "Secure allow", {
      action: "allow",
      conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)],
      security_profiles: { ips_enabled: true, amp_malware_enabled: true, tls_decryption_enabled: true, dlp_enabled: true },
    }),
  ];
  const findings = sandbox.checkInspection(rules);
  assert(findings.length === 0, "Inspection: all profiles enabled → no finding");
}
{
  // Narrow allow (specific identity + specific dest) — source is still catch-all, so it IS broad
  const rules = [
    makeRule(1, "Broad source allow", {
      action: "allow",
      conditions: [
        cond("umbrella.source.all", "=", true),
        cond("umbrella.destination.all", "=", true),
        cond("umbrella.source.identity_ids", "INTERSECT", [100]),
        cond("umbrella.destination.application_ids", "INTERSECT", [200]),
      ],
      security_profiles: { ips_enabled: false, amp_malware_enabled: false, tls_decryption_enabled: false, dlp_enabled: false },
    }),
  ];
  const findings = sandbox.checkInspection(rules);
  assert(find(findings, "inspection-bypass", "Broad source allow") !== undefined, "Inspection: broad source (catch-all) with missing profiles → flagged");
}
{
  // Truly narrow: BOTH source AND destination have specific (non-catch-all) conditions
  const rules = [
    makeRule(1, "Truly narrow allow", {
      action: "allow",
      conditions: [
        cond("umbrella.source.composite_inline_ip", "IN", [{ ip: ["10.0.0.0/8"], port: ["0-65535"], protocol: "ANY" }]),
        cond("umbrella.destination.composite_inline_ip", "IN", [{ ip: ["10.0.0.0/8"], port: ["443"], protocol: "TCP" }]),
      ],
      security_profiles: { ips_enabled: false, amp_malware_enabled: false, tls_decryption_enabled: false, dlp_enabled: false },
    }),
  ];
  const findings = sandbox.checkInspection(rules);
  assert(findings.length === 0, "Inspection: truly narrow rule (specific source CIDR + specific dest CIDR) → skipped");
}
{
  // Block rule → skipped (only allow rules checked)
  const rules = [
    makeRule(1, "Broad block", {
      action: "block",
      conditions: [cond("umbrella.source.all", "=", true), cond("umbrella.destination.all", "=", true)],
      security_profiles: { ips_enabled: false, amp_malware_enabled: false, tls_decryption_enabled: false, dlp_enabled: false },
    }),
  ];
  const findings = sandbox.checkInspection(rules);
  assert(findings.length === 0, "Inspection: block rule → skipped");
}

// ---------------------------------------------------------------------------
// Group 7: Edge cases
// ---------------------------------------------------------------------------
console.log("\n=== Group 7: Edge cases ===");
{
  // Empty rule set → no findings from any check
  const empty = [];
  assert(sandbox.checkPermissive(empty).length === 0, "Empty: permissive → 0");
  assert(sandbox.checkShadowing(empty).length === 0, "Empty: shadowing → 0");
  assert(sandbox.checkConflicts(empty).length === 0, "Empty: conflicts → 0");
  assert(sandbox.checkDuplicates(empty).length === 0, "Empty: duplicates → 0");
  assert(sandbox.checkLogging(empty).length === 0, "Empty: logging → 0");
  assert(sandbox.checkInspection(empty).length === 0, "Empty: inspection → 0");
}
{
  // Disabled rules should be skipped by all checks
  const rules = [
    makeRule(1, "Disabled", { enabled: false, action: "allow", conditions: [] }),
  ];
  assert(sandbox.checkPermissive(rules).length === 0, "Disabled: permissive → skipped");
  assert(sandbox.checkLogging(rules).length === 0, "Disabled: logging → skipped");
}

// ---------------------------------------------------------------------------
// Group 8: Condition dimension classification
// ---------------------------------------------------------------------------
console.log("\n=== Group 8: Condition helpers ===");
{
  assert(sandbox._conditionDimension("umbrella.source.all") === "source");
  assert(sandbox._conditionDimension("umbrella.destination.all") === "destination");
  assert(sandbox._conditionDimension("umbrella.destination.composite_inline_ip") === "destination");
  assert(sandbox._conditionDimension("umbrella.source.identity_ids") === "identity");
  assert(sandbox._conditionDimension("umbrella.destination.application_ids") === "app");
  assert(sandbox._conditionDimension("umbrella.destination.category_ids") === "app");
  assert(sandbox._conditionDimension("umbrella.destination.destination_list_ids") === "destination");
  assert(sandbox._dimensionUnconstrained([]) === true, "empty = unconstrained");
  assert(sandbox._dimensionUnconstrained([cond("umbrella.source.all", "=", true)]) === true, "catch-all = unconstrained");
  assert(sandbox._dimensionUnconstrained([cond("umbrella.source.identity_ids", "INTERSECT", [1])]) === false, "specific = constrained");
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------
console.log(`\n${"=".repeat(60)}`);
console.log(`RESULTS: ${passed} passed, ${failed} failed, ${total} total`);
console.log(`${"=".repeat(60)}`);

if (failed > 0) { process.exit(1); } else { console.log("All tests passed!"); process.exit(0); }
