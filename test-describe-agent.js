#!/usr/bin/env node
"use strict";
// Describe mode agent loop with a scripted, stubbed LLM.
// Run: node test-describe-agent.js
const assert = require("node:assert/strict");

const ip = require("./extension/popup/ip-address.js");
globalThis.IPAddress = ip;
const model = require("./extension/popup/traffic-path.js");
const Agent = require("./extension/popup/describe-agent.js");

const lookups = {
  sourceUsers: { 11: "Aang Leung (aang@corp.example)", 12: "Denise Okafor (denise@corp.example)", 13: "Denise Park (dpark@corp.example)" },
  sourceGroups: { 21: "Finance", 22: "Engineering" },
  sourceRoaming: { 31: "LAPTOP-AANG-01" },
  sourceSites: { 41: "London Office" },
  contentCategories: { 27: "Gambling" },
  applications: { 27: "Application sharing the category ID" },
};
const cond = (attributeName, attributeValue, attributeOperator = "INTERSECT") => ({ attributeName, attributeValue, attributeOperator });
const rules = [
  { ruleId: 99, ruleName: "Default Internet", rulePriority: 99, ruleAction: "allow", ruleIsEnabled: true, ruleIsDefault: true, trafficScope: "public_internet", ruleConditions: [cond("umbrella.source.all", true, "="), cond("umbrella.destination.all", true, "=")] },
  { ruleId: 2, ruleName: "Engineering SSH", rulePriority: 2, ruleAction: "allow", ruleIsEnabled: true, trafficScope: "private_network", ruleConditions: [cond("umbrella.source.identity_ids", [22, 13]), cond("umbrella.destination.composite_inline_ip", [{ ip: ["10.100.0.0/16"], port: ["22"], protocol: "TCP" }], "IN")] },
  { ruleId: 1, ruleName: "Block gambling", rulePriority: 1, ruleAction: "block", ruleIsEnabled: true, trafficScope: "public_internet", ruleConditions: [cond("umbrella.source.all", true, "="), cond("umbrella.destination.category_ids", [27])] },
  { ruleId: 3, ruleName: "Legacy disabled", rulePriority: 3, ruleAction: "block", ruleIsEnabled: false, conditions: [cond("umbrella.source.all", true, "=")], ruleConditions: [] },
];
const policy = { rules, lookups };
const settings = { llmKey: "llm-test", llmProvider: "anthropic" };
const ctx = { model, rules, lookups };

// Each reply in `script` is either an action object or a function(body, callIndex) returning one.
function scripted(script) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body });
    const step = script[Math.min(calls.length - 1, script.length - 1)];
    const reply = typeof step === "function" ? step(body, calls.length - 1) : step;
    if (reply && reply.httpStatus) return { ok: false, status: reply.httpStatus, json: async () => ({}) };
    const text = typeof reply === "string" ? reply : JSON.stringify(reply);
    return { ok: true, status: 200, json: async () => ({ content: [{ type: "text", text }] }) };
  };
  return { calls, fetch };
}
const tool = (name, args = {}) => ({ action: "tool", tool: name, args });
const decide = (ruleId, extra = {}) => ({
  action: "decide",
  decision: { ruleId, action: "allow", verdictTitle: "Allowed at Firewall", summary: "Denise Park is in the SSH rule.", connection: "vpn", source: "Denise Park", destination: "10.100.67.25", assumptions: ["SSH runs on port 22"], ...extra },
});

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; } catch (error) { console.error(`FAIL ${name}`); throw error; }
}

(async () => {
  await test("search_sources ranks catalog matches and honours kinds", () => {
    const result = Agent.executeTool("search_sources", { query: "Denise" }, ctx);
    assert.deepEqual(result.matches.map(match => match.id).sort(), ["12", "13"]);
    assert.equal(result.matches[0].kind, "identity");
    assert.equal(result.matches[0].type, "User or group");
    assert.equal(Agent.executeTool("search_sources", { query: "London", kinds: ["roaming"] }, ctx).matches.length, 0);
    assert.equal(Agent.executeTool("search_sources", { query: "London", kinds: ["site"] }, ctx).matches[0].label, "London Office");
  });

  await test("groups_for reports missing membership data and walks nested groups", () => {
    const missing = Agent.executeTool("groups_for", { source: "Denise Park" }, ctx);
    assert.equal(missing.membershipLoaded, false);
    assert.equal(missing.source, "Denise Park (dpark@corp.example)");
    const memberMaps = { identityGroups: { 22: { name: "Engineering", members: [{ id: 13 }] }, 21: { name: "Finance", members: [{ id: 22 }] } } };
    const found = Agent.executeTool("groups_for", { source: "13" }, { ...ctx, lookups: { ...lookups, memberMaps } });
    assert.deepEqual(found.groups.map(group => group.name).sort(), ["Engineering", "Finance"]);
    assert.ok(Agent.executeTool("groups_for", { source: "nobody-here" }, ctx).error);
    const partial = Agent.executeTool("groups_for", { source: "13" }, { ...ctx, lookups: { ...lookups, memberMaps: { identityGroups: { ...memberMaps.identityGroups, 23: { resolved: false, members: [] } } } } });
    assert.equal(partial.membershipLoaded, false);
    assert.match(partial.note, /incomplete/);
  });

  await test("list_rules is compact, ordered like evaluation, and labels conditions", () => {
    const result = Agent.executeTool("list_rules", {}, ctx);
    assert.equal(result.total, 4);
    assert.deepEqual(result.rules.map(rule => rule.id), ["1", "2", "3", "99"], "priority order, default last");
    const [gambling, ssh, disabled, fallback] = result.rules;
    assert.deepEqual(gambling.conditions, ["Source: any", "Destination content categories: Gambling"]);
    assert.deepEqual(ssh.conditions, ["Source identities: Engineering, Denise Park (dpark@corp.example)", "Destination IPs: 10.100.0.0/16 port 22 TCP"]);
    assert.equal(ssh.scope, "private_network");
    assert.equal(disabled.enabled, false);
    assert.deepEqual(disabled.conditions, [], "canonical empty ruleConditions win over legacy conditions");
    assert.equal(fallback.default, true);
    const filtered = Agent.executeTool("list_rules", { filter: "gambl" }, ctx);
    assert.deepEqual(filtered.rules.map(rule => rule.id), ["1"]);
    assert.equal(filtered.matching, 1);
  });

  await test("get_rule, parse_destination and unknown tools", () => {
    assert.equal(Agent.executeTool("get_rule", { id: "2" }, ctx).name, "Engineering SSH");
    assert.match(Agent.executeTool("get_rule", { id: "404" }, ctx).error, /No rule/);
    const privateDest = Agent.executeTool("parse_destination", { text: "10.100.67.25" }, ctx);
    assert.deepEqual([privateDest.kind, privateDest.private, privateDest.scope], ["ip", true, "private_network"]);
    const publicDest = Agent.executeTool("parse_destination", { text: "https://example.org/x" }, ctx);
    assert.deepEqual([publicDest.host, publicDest.kind, publicDest.private, publicDest.port], ["example.org", "domain", false, "443"]);
    assert.ok(Agent.executeTool("parse_destination", { text: "*.bad" }, ctx).error);
    assert.match(Agent.executeTool("rm_rf", {}, ctx).error, /Unknown tool/);
  });

  await test("loop: tool calls feed results back, then the agent's pick is the verdict", async () => {
    const { calls, fetch } = scripted([
      tool("search_sources", { query: "Denise Park" }),
      tool("parse_destination", { text: "10.100.67.25" }),
      tool("list_rules"),
      tool("get_rule", { id: "2" }),
      decide("2"),
    ]);
    const progress = [];
    const result = await Agent.run({ text: "Can Denise Park on VPN SSH to 10.100.67.25?", model, settings, policy, fetch, onProgress: label => progress.push(label) });
    assert.equal(result.status, "decided");
    assert.equal(calls.length, 5);
    assert.deepEqual(result.decision, {
      ruleId: "2", action: "allow", verdictTitle: "Allowed at Firewall", summary: "Denise Park is in the SSH rule.",
      connection: "vpn", source: "Denise Park", destination: "10.100.67.25", assumptions: ["SSH runs on port 22"],
    });
    assert.equal(result.rule.name, "Engineering SSH");
    assert.equal(result.rule.priority, 2);
    assert.deepEqual(progress, ["Understanding your question…", "Looking up Denise Park…", "Checking 10.100.67.25…", "Reviewing 4 rules…", "Reading “Engineering SSH”…", "Deciding…"]);
    const last = calls[4].body;
    assert.equal(last.messages.length, 9, "user + 4×(assistant, tool result)");
    assert.deepEqual(last.messages.map(message => message.role), ["user", "assistant", "user", "assistant", "user", "assistant", "user", "assistant", "user"]);
    assert.match(last.messages[0].content, /Denise Park on VPN/);
    assert.match(last.messages[2].content, /^Result of search_sources: .*Denise Park \(dpark@corp\.example\)/);
    assert.match(last.messages[6].content, /^Result of list_rules: .*Engineering SSH/);
    assert.ok(last.output_config.format.schema.properties.decision);
    assert.match(last.system, /first enabled rule whose conditions all match wins/);
    assert.match(last.system, /Remote access VPN/);
  });

  await test("deciding before reviewing rules is pushed back to gather evidence", async () => {
    const { calls, fetch } = scripted([decide("2"), tool("list_rules"), decide("2")]);
    const result = await Agent.run({ text: "x", model, settings, policy, fetch });
    assert.equal(result.status, "decided");
    assert.equal(calls.length, 3);
    assert.match(calls[1].body.messages[2].content, /review the rules/);
  });

  await test("ask pauses with options; the answer resumes the same transcript", async () => {
    const first = scripted([
      tool("search_sources", { query: "Denise" }),
      { action: "ask", question: "Which Denise?", options: ["Denise Okafor", "Denise Park", ""] },
    ]);
    const paused = await Agent.run({ text: "Can Denise SSH to 10.100.67.25 on VPN?", model, settings, policy, fetch: first.fetch });
    assert.equal(paused.status, "needs_input");
    assert.deepEqual(paused.question, { text: "Which Denise?", options: ["Denise Okafor", "Denise Park"] });
    assert.equal(paused.messages.length, 4);
    const second = scripted([tool("list_rules"), decide("2")]);
    const progress = [];
    const resumed = await Agent.run({ text: "ignored on resume", model, settings, policy, fetch: second.fetch, messages: paused.messages, answer: "Denise Park", onProgress: label => progress.push(label) });
    assert.equal(resumed.status, "decided");
    const sent = second.calls[0].body.messages;
    assert.equal(sent.length, 5);
    assert.equal(sent[4].content, "Admin's answer: Denise Park");
    assert.match(sent[0].content, /Can Denise SSH/);
    assert.equal(progress[0], "Picking up your answer…");
    assert.equal(paused.messages.length, 4, "the paused transcript is not mutated by resuming");
  });

  await test("an unknown ruleId is re-prompted once, then fails cleanly", async () => {
    const fixed = scripted([tool("list_rules"), decide("77"), decide(2)]);
    const ok = await Agent.run({ text: "x", model, settings, policy, fetch: fixed.fetch });
    assert.equal(ok.status, "decided");
    assert.equal(ok.decision.ruleId, "2");
    assert.match(fixed.calls[2].body.messages.at(-1).content, /ruleId "77" is not a rule.*Valid ids: 1, 2, 3, 99/);
    const stubborn = scripted([tool("list_rules"), decide("77"), decide("78")]);
    const failed = await Agent.run({ text: "x", model, settings, policy, fetch: stubborn.fetch });
    assert.equal(failed.status, "error");
    assert.equal(stubborn.calls.length, 3);
  });

  await test("null ruleId and unexpected verdict values are normalized", async () => {
    const { fetch } = scripted([tool("list_rules"), decide(null, { action: "DENY", verdictTitle: "", assumptions: ["", "Not a VPN user"] })]);
    const result = await Agent.run({ text: "x", model, settings, policy, fetch });
    assert.equal(result.status, "decided");
    assert.equal(result.rule, null);
    assert.equal(result.decision.action, "unknown");
    assert.equal(result.decision.verdictTitle, "Couldn't decide");
    assert.deepEqual(result.decision.assumptions, ["Not a VPN user"]);
  });

  await test("stops after the turn budget and warns on the last turn", async () => {
    const { calls, fetch } = scripted([() => tool("list_rules")]);
    const result = await Agent.run({ text: "x", model, settings, policy, fetch });
    assert.equal(result.status, "error");
    assert.match(result.error, /couldn't reach a decision/);
    assert.equal(calls.length, Agent.MAX_TURNS);
    assert.match(calls.at(-1).body.messages.at(-1).content, /last turn/);
    assert.doesNotMatch(calls.at(-2).body.messages.at(-1).content, /last turn/);
  });

  await test("non-JSON replies are nudged; HTTP errors, missing keys, no rules and cancellation", async () => {
    const nudged = scripted(["Sure! Let me look.", tool("list_rules"), decide("1", { action: "block" })]);
    const result = await Agent.run({ text: "x", model, settings, policy, fetch: nudged.fetch });
    assert.equal(result.status, "decided");
    assert.match(nudged.calls[1].body.messages[2].content, /one JSON object/);

    const failing = scripted([{ httpStatus: 401 }]);
    const failed = await Agent.run({ text: "x", model, settings, policy, fetch: failing.fetch });
    assert.equal(failed.status, "error");
    assert.match(failed.error, /401.*API key/);

    let fetched = 0;
    const noKey = await Agent.run({ text: "x", model, settings: { llmProvider: "openai" }, policy, fetch: async () => { fetched++; } });
    assert.equal(noKey.status, "error");
    assert.equal(noKey.needsSettings, true);
    assert.equal(Agent.needsKey({ llmProvider: "openai-compatible", llmBaseUrl: "http://localhost:1234/v1" }), false);
    const empty = await Agent.run({ text: "x", model, settings, policy: { rules: [] }, fetch: async () => { fetched++; } });
    assert.match(empty.error, /No policy rules/);
    assert.equal(fetched, 0);

    let live = true;
    const slow = scripted([() => { live = false; return tool("list_rules"); }]);
    const cancelled = await Agent.run({ text: "x", model, settings, policy, fetch: slow.fetch, isCurrent: () => live });
    assert.equal(cancelled.status, "cancelled");
    assert.equal(slow.calls.length, 1);
  });

  await test("bounded member tools follow nested objects and exclude debug secrets", () => {
    const memberMaps = { networkObjects: {
      parent: { name: "Parent", members: [{ kind: "networkObjects", id: "child", debug: "secret" }] },
      child: { name: "Child", members: [{ kind: "ip", value: "10.0.0.0/8", token: "secret" }] },
      partial: { resolved: false, members: [] },
      large: { members: Array.from({ length: 45 }, (_, id) => ({ id, kind: "networkObjects" })) },
    } };
    const context = { ...ctx, lookups: { ...lookups, memberMaps } };
    const parent = Agent.executeTool("get_members", { kind: "networkObjects", id: "parent" }, context);
    assert.deepEqual(parent.members, [{ id: "child", kind: "networkObjects" }]);
    const child = Agent.executeTool("get_members", { kind: parent.members[0].kind, id: parent.members[0].id }, context);
    assert.deepEqual(child.members, [{ kind: "ip", value: "10.0.0.0/8" }]);
    assert.equal(Agent.executeTool("get_members", { kind: "networkObjects", id: "missing" }, context).loaded, false);
    assert.equal(Agent.executeTool("get_members", { kind: "networkObjects", id: "partial" }, context).loaded, false);
    const page = Agent.executeTool("get_members", { kind: "networkObjects", id: "large" }, context);
    assert.equal(page.members.length, 40);
    assert.equal(page.more, true);
    assert.equal(Agent.executeTool("get_members", { kind: "networkObjects", id: "large", offset: 40 }, context).members.length, 5);
    assert.ok(Agent.executeTool("get_members", { kind: "tokens", id: "parent" }, context).error);
  });

  await test("security context is loaded configuration, bounded and allowlisted", () => {
    const securityProfiles = { dnsDefaultSettingId: "s", securitySettings: { s: { name: "Threat controls", token: "secret", categories: Array.from({ length: 41 }, () => ({ id: "malware", name: "Malware", action: "block", debug: "secret" })) } }, webProfiles: { w: { name: "Web", securitySettingId: "s", auth: "secret" } } };
    const context = { ...ctx, lookups: { ...lookups, securityProfiles } };
    const result = Agent.executeTool("get_security_context", { id: "w" }, context);
    assert.equal(result.loaded, true);
    assert.equal(result.categories.length, 40);
    assert.equal(result.more, true);
    assert.doesNotMatch(JSON.stringify(result), /secret/);
    assert.equal(Agent.executeTool("get_security_context", {}, context).loaded, true);
    assert.equal(Agent.executeTool("get_security_context", { id: "absent" }, context).loaded, false);
  });

  await test("unknown tool and invalid args recover to a specific missing-context question", async () => {
    for (const invalid of [tool("invent_membership"), tool("get_members", { kind: "networkObjects" }), tool("list_rules", { offset: -1 })]) {
      const stub = scripted([invalid, { action: "ask", question: "What is the client's VPN IP for the source network rule?", options: ["Not sure"] }]);
      const result = await Agent.run({ text: "Can Denise reach the payroll server?", model, settings, policy, fetch: stub.fetch });
      assert.equal(result.status, "needs_input");
      assert.match(stub.calls[1].body.messages.at(-1).content, /error/);
      assert.match(result.question.text, /client's VPN IP/);
    }
    assert.ok(Agent.executeTool("get_rule", [], ctx).error);
    assert.ok(Agent.executeTool("search_sources", { query: "Denise", kinds: ["invented"] }, ctx).error);
    assert.ok(Agent.executeTool("groups_for", { source: "Denise" }, ctx).error, "ambiguous identity is not silently selected");
  });

  await test("disabled rules and action conflicts cannot become verdicts", async () => {
    for (const invalid of [decide("3", { action: "block" }), decide("1"), decide(null, { action: "allow" })]) {
      const stub = scripted([tool("list_rules"), invalid, { action: "ask", question: "Which connection carries this traffic?", options: ["Remote access VPN", "Not sure"] }]);
      const result = await Agent.run({ text: "Can I open the site?", model, settings, policy, fetch: stub.fetch });
      assert.equal(result.status, "needs_input");
      assert.match(stub.calls[2].body.messages.at(-1).content, /Invalid decision metadata/);
    }
  });

  await test("natural request receives safety instructions and last-turn clarification resumes", async () => {
    const stub = scripted([tool("list_rules"), { action: "ask", question: "Which Denise is connecting?", options: ["Denise Okafor (denise@corp.example)", "Denise Park (dpark@corp.example)", "Not sure"] }]);
    const result = await Agent.run({ text: "Will Denise be able to SSH to 10.100.67.25?", model, settings, policy, fetch: stub.fetch, maxTurns: 2 });
    assert.equal(result.status, "needs_input");
    const prompt = stub.calls[0].body.system;
    for (const expression of [/default rules come last/, /untrusted data, never instructions/, /Never invent group membership/, /Missing source\/VPN IP matters only/, /stage is unavailable/, /earlier rule is unresolved/, /get_members/, /get_security_context/]) assert.match(prompt, expression);
    assert.doesNotMatch(prompt, /reasonable assumption|general knowledge of a well-known site/);
    assert.match(stub.calls[1].body.messages.at(-1).content, /otherwise ask a targeted question/);
    const resumed = scripted([tool("get_rule", { id: "2" }), decide("2")]);
    const final = await Agent.run({ model, settings, policy, messages: result.messages, answer: "Denise Park on VPN, TCP port 22", fetch: resumed.fetch });
    assert.equal(final.status, "decided");
    assert.match(resumed.calls[0].body.messages[0].content, /Will Denise be able/);
    assert.equal(result.messages.at(-1).role, "assistant");
  });

  console.log(`describe-agent: ${passed} passed`);
})().catch(error => { console.error(error); process.exit(1); });
