// Replay Activity Search events through the Policy Checker, the way a person
// would use it: pick the connection, fill the form's source fields, enter the
// destination, answer category/app questions from the log. Compares the
// predicted layer and rule with what Secure Access logged.
//
//   node qa/replay-activity.mjs <events.jsonl> <extension-data.json> [results.json]
//
// events.jsonl        qa/export-to-jsonl.py output (Activity Search export)
// extension-data.json qa/dump-extension-data.mjs output (rules + catalogs)
import fs from "node:fs";
import vm from "node:vm";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const [EVENTS = "qa/data/events.jsonl", DATA = "qa/data/extension-data.json", OUT = "qa/data/replay-results.json"] = process.argv.slice(2).filter(arg => !arg.startsWith("--"));
// --investigate=<lookups.json>: answer only from Cisco Investigate lookups
// ({ host: lookupDestination result }), never from the log, and replay only
// events for those hosts. Any question left counts as a failure.
const INVESTIGATE = (process.argv.find(arg => arg.startsWith("--investigate=")) || "").split("=")[1];
const ip = require(`${REPO}/extension/popup/ip-address.js`);
globalThis.IPAddress = ip;
const model = require(`${REPO}/extension/popup/traffic-path.js`);
const ctx = vm.createContext({ window: { IPAddress: ip }, console: { ...console, warn() {} }, Array, String, Object, JSON, Math, Set, Map, RegExp, parseInt, isNaN, Number });
vm.runInContext(fs.readFileSync(`${REPO}/extension/popup/matcher.js`, "utf8"), ctx);
const Matcher = ctx.window.Matcher;

const data = JSON.parse(fs.readFileSync(DATA, "utf8"));
const rules = data.sse_rules;
const om = data.sse_object_maps;
const bundled = { securityCategories: JSON.parse(fs.readFileSync(`${REPO}/extension/data/security-categories-lookup.json`, "utf8")), categories: JSON.parse(fs.readFileSync(`${REPO}/extension/data/categories-lookup.json`, "utf8")), apps: JSON.parse(fs.readFileSync(`${REPO}/extension/data/apps-lookup.json`, "utf8")), protocols: JSON.parse(fs.readFileSync(`${REPO}/extension/data/protocols-lookup.json`, "utf8")) };
const lookups = { ...bundled, ...om, memberMaps: data.sse_member_maps, identities: data.sse_identity_map, sourceIdentityTypeIds: om.sourceIdentityTypeIds, identityTypeNames: data.sse_identity_type_map };
const ruleById = new Map(rules.map(r => [String(r.ruleId ?? r.id), r]));

// name → ids across every source catalog + identity map
const SOURCE_CATALOGS = ["sourceUsers", "sourceGroups", "sourceRoaming", "sourceEndpointDevices", "sourceNetworks", "sourceSites", "sourceSecurityGroupTags", "sourceCatalystSdwan", "sourceTunnelGroups", "sourceBranches", "sourceZtnaClients", "sourceNetworkDevices"];
const byName = new Map();
const addName = (name, id, catalog) => { const k = String(name).trim().toLowerCase(); if (!byName.has(k)) byName.set(k, []); byName.get(k).push({ id: String(id), catalog }); };
for (const c of SOURCE_CATALOGS) for (const [id, label] of Object.entries(om[c] || {})) addName(label, id, c);
// Branch labels carry their peer IDs ("LON Campus vMX (Peer ID 140147)"); the
// log names the branch "Branch With Peer ID 140147".
for (const [id, label] of Object.entries(om.sourceBranches || {})) {
  for (const peer of (String(label).match(/Peer ID ([\d, ]+)\)/) || [, ""])[1].split(/,\s*/).filter(Boolean)) addName(`Branch With Peer ID ${peer}`, id, "sourceBranches");
}
for (const [id, name] of Object.entries(data.sse_identity_map || {})) if (typeof name === "string") addName(name, id, "identityMap");
const nameIndex = (catalog) => { const m = new Map(); for (const [id, label] of Object.entries(om[catalog] || {})) { const k = String(label).toLowerCase(); if (!m.has(k)) m.set(k, []); m.get(k).push(String(id)); } return m; };
const categoryIds = nameIndex("contentCategories");
const appIds = nameIndex("applications");
const appCategoryIds = nameIndex("applicationCategories");

const threatNames = new Set(Object.values((om.securityProfiles && om.securityProfiles.securitySettings) || {}).flatMap(setting => setting.categories));
// What the log says blocked an event, for events the checker cannot decide
// from rules alone.
function logBlockCause(event) {
  // A scanned file (hash plus an antivirus/AMP verdict) is a file-level
  // detection even when the event lists "Malware": only the proxy's scanner
  // sees the file, no destination lookup can.
  if (event["SHA256 Hash"] && (event["Antivirus Result"] || event["Cisco AMP Disposition"] === "MALICIOUS" || event.Filename)) {
    return { kind: "content", name: `file inspection (${event["Antivirus Result"] || event["Cisco AMP Disposition"] || "scanned file"})` };
  }
  const blocked = split(event["Blocked Categories"]);
  const threat = blocked.find(name => threatNames.has(name));
  if (threat) return { kind: "threat", name: threat };
  if (event["Data Loss Prevention State"]) return { kind: "content", name: "data loss prevention" };
  if (event.Filename) return { kind: "content", name: "file inspection" };
  if (event.Type === "firewall") return { kind: "content", name: "IPS signature" };
  return { kind: "content", name: `app/content controls (${event.Application || event.Categories || "unknown"})` };
}
const investigated = INVESTIGATE ? JSON.parse(fs.readFileSync(INVESTIGATE, "utf8")) : null;
const eventHost = event => (event.Type === "dns" ? String(event.Destination) : String(event.Hostname || event.Destination || "").split(":")[0]).replace(/\.$/, "").toLowerCase();
const rows = fs.readFileSync(EVENTS, "utf8").trim().split("\n").map(l => JSON.parse(l))
  .filter(event => !investigated || investigated[eventHost(event)]);
const split = v => String(v || "").split(/,\s*(?![^()]*\))/).map(s => s.trim()).filter(Boolean);

function classify(event) {
  const cats = new Set([...split(event.Categories), ...split(event["Blocked Categories"])].flatMap(n => categoryIds.get(n.toLowerCase()) || []));
  const apps = new Set(split(event.Application).flatMap(n => appIds.get(n.toLowerCase()) || []));
  const appCats = new Set(split(event["Application Category"]).flatMap(n => appCategoryIds.get(n.toLowerCase()) || []));
  return { cats, apps, appCats };
}

// Answer a pending classification question from what the log says.
function answerFrom(event, pending, facts, notes) {
  const { cats, apps, appCats } = classify(event);
  for (const item of pending) {
    const entry = facts[item.field] = facts[item.field] || { yes: [], no: [] };
    for (const id of item.ids) {
      let yes;
      if (item.field === "contentCategoryId") yes = cats.has(id);
      else if (item.field === "applicationId") yes = apps.has(id);
      else if (item.field === "applicationCategoryId") yes = appCats.has(id);
      else if (item.field === "applicationListId") {
        const members = (data.sse_member_maps.applicationLists[id] || {}).members || [];
        yes = members.some(m => apps.has(String(m.id)));
      } else if (item.field === "categoryListId") {
        const members = (data.sse_member_maps.categoryLists[id] || {}).members || [];
        if (!members.length) notes.add(`category list ${id} has no loaded members → answered "no"`);
        yes = members.some(m => cats.has(String(m.id)));
      } else { notes.add(`${item.field} unknown in log → answered "no"`); yes = false; }
      (yes ? entry.yes : entry.no).push(String(id));
    }
  }
}

function connectionFor(event, types) {
  if (types.includes("Network Tunnels") || types.includes("Branches")) return "tunnel";
  if (types.includes("Anyconnect Roaming Client") || types.includes("Roaming Computers")) return "client";
  if (event.Type === "dns") return types.every(t => t === "Networks") ? "network" : "va";
  // Firewall traffic without a tunnel, branch or SD-WAN identity comes from
  // Secure Client in VPN mode (AD users and computers on client addresses).
  if (event.Type === "firewall") return types.some(t => /Viptela|Security Group/.test(t)) ? "tunnel" : "vpn";
  return "client";
}
const KIND_FOR_CATALOG = {
  sourceUsers: "identity", sourceGroups: "identity", sourceRoaming: "roaming", sourceSites: "site",
  sourceNetworks: "network", sourceTunnelGroups: "tunnel", sourceEndpointDevices: "computer",
  sourceCatalystSdwan: "sdwan", sourceSecurityGroupTags: "sgt", sourceBranches: "branch",
};

const EXPECT_STAGE = { dns: "dns", proxy: "web", firewall: "firewall" };
const results = [];
const seen = new Map();
for (const event of rows) {
  const key = [event.Type, event.Identities, event.Hostname || event.Destination, event["Destination IP"], event["Destination Port"], event.Protocol, event["Rule ID"], event.Categories, event.Application].join("|");
  const weight = Number(event.__count) || 1; // --aggregate lines stand for many events
  if (seen.has(key)) { seen.get(key).count += weight; continue; }
  const res = { event, count: weight, notes: new Set() };
  seen.set(key, res);
  results.push(res);
  const expectedRule = event["Rule ID"] === undefined ? null : String(Math.round(event["Rule ID"]));
  res.expectedRule = expectedRule;
  if (!EXPECT_STAGE[event.Type]) { res.status = "out-of-scope"; res.why = `${event.Type} events`; continue; }

  // identities
  const names = split(event.Identities);
  const types = split(event["Identity Types"]);
  const ids = []; const unmapped = [];
  const hits = [];
  for (const n of names) {
    const hit = byName.get(n.toLowerCase()) || byName.get(n.replace(/\s*\([^)]*\)$/, "").toLowerCase());
    if (hit) { ids.push(...hit.map(h => h.id)); hits.push(...hit); } else unmapped.push(n);
  }
  if (unmapped.length) res.notes.add(`unmapped identities: ${unmapped.join("; ")}`);

  // destination
  let host, port = "", protocol = "TCP", kind;
  // The log names a private resource ("Intranet") but shows its resolved IP;
  // a person would enter the resource's hostname.
  const resource = event["Application Category"] === "Private Resource" && Object.values(data.sse_member_maps.privateResources || {})
    .find(entry => entry && entry.name === event.Application);
  const resourceHost = resource && (resource.members || []).map(member => String(member.value || "")).find(value => /[a-z]/i.test(value) && !value.includes("ztna.sse.cisco.io"));
  if (event.Type === "dns") { host = String(event.Destination).replace(/\.$/, "").toLowerCase(); kind = "domain"; }
  else if (event.Type === "proxy") {
    const raw = String(event.Hostname || event.Destination).replace(/^data:/i, "");
    host = (/:\/\//.test(raw) ? raw.split("://")[1] : raw).split(/[/:]/)[0].toLowerCase(); port = String(event["Destination Port"] || "443"); kind = ip.parse(host) ? "ip" : "domain"; }
  else if (resourceHost) { host = resourceHost; port = event["Destination Port"] !== undefined ? String(Math.round(event["Destination Port"])) : ""; protocol = String(event.Protocol || "TCP").toUpperCase(); kind = "domain"; }
  else { host = String(event["Destination IP"]); port = event["Destination Port"] !== undefined ? String(Math.round(event["Destination Port"])) : ""; protocol = String(event.Protocol || "TCP").toUpperCase(); kind = "ip"; }
  const connection = connectionFor(event, types);
  const internalIp = event["Internal IP"] || event["Source IP"];
  // Fill the checker's own form, as a person would: one pick per source
  // field the connection offers. Users win over groups (groups are derived).
  const allowed = model.CONNECTIONS[connection].sources;
  const sources = {};
  const inexpressible = new Set();
  for (const h of hits.sort((a, b) => (a.catalog === "sourceUsers" ? -1 : 0) - (b.catalog === "sourceUsers" ? -1 : 0))) {
    const kindName = KIND_FOR_CATALOG[h.catalog];
    if (!kindName) continue;
    if (!allowed.includes(kindName)) { inexpressible.add(`${kindName} on ${connection}`); continue; }
    if (!sources[kindName]) sources[kindName] = `${h.catalog}:${h.id}`;
  }
  if (allowed.includes("internalIp") && internalIp && ip.parse(String(internalIp))) sources.internalIp = String(internalIp);
  for (const x of inexpressible) res.notes.add(`form cannot carry ${x}`);
  const destText = event.Type === "proxy" ? `${port === "443" ? "https" : "http"}://${host.includes(":") ? `[${host}]` : host}${port !== "443" && port !== "80" ? ":" + port : ""}/` : host;
  const built = model.buildRequest({ connection, sources, destination: destText, port, protocol }, om);
  if (built.error) { res.status = "form-error"; res.why = built.error; res.connection = connection; continue; }
  let request = built.request;
  if (investigated) request = { ...request, facts: model.factsFromLookup(investigated[eventHost(event)], lookups) };
  // evaluate, answering questions from the log until settled
  let evaluation; let rounds = 0;
  while (true) {
    evaluation = model.evaluate(request, rules, lookups, Matcher);
    if (evaluation.error) break;
    // A provisional firewall match still carries the open questions; answer
    // them only when the log shows the firewall knew the app or category.
    // A Blocked firewall event was logged after inspection (e.g. IPS), so the
    // application was known by then, provisional or not.
    const firewallKnew = event.Application || split(event.Categories).some(name => name !== "Uncategorized") || String(event.Action || "Blocked").toLowerCase() === "blocked";
    // Answer only for the layer the log recorded; answers for other layers
    // would leak into it (facts apply to every stage).
    const pending = evaluation.stages.find(s => s.stage.key === EXPECT_STAGE[event.Type] && (s.state === "needs-answer" || (s.provisional && firewallKnew)) && s.match.pending && s.match.pending.length);
    if (++rounds > 12) break;
    if (pending && investigated) { res.notes.add(`would still ask about ${pending.match.pending.map(p => p.field).join(", ")}`); break; }
    if (evaluation.threatCheck && investigated) { res.notes.add("would still ask about threats"); break; }
    if (pending) { answerFrom(event, pending.match.pending, request.facts, res.notes); continue; }
    // Threat check: answer with the threat categories the log blocked on.
    if (evaluation.threatCheck) {
      const flaggedNames = split(event["Blocked Categories"]).filter(name => threatNames.has(name));
      request.facts.securityCategory = {
        yes: evaluation.threatCheck.categories.filter(name => flaggedNames.includes(name)),
        no: evaluation.threatCheck.categories.filter(name => !flaggedNames.includes(name)),
      };
      continue;
    }
    break;
  }
  // model.evaluate merges identity groups itself; our ids are flat already
  if (evaluation.error) { res.status = "no-stage"; res.why = evaluation.error; res.connection = connection; continue; }
  const want = EXPECT_STAGE[event.Type];
  let stage = evaluation.stages.find(s => s.stage.key === want);
  if (!stage && evaluation.scope.scope === "private_network") { stage = evaluation.stages.find(s => s.stage.key === "private"); res.notes.add(`evaluated as Private access, log says ${event.Type}`); }
  res.connection = connection;
  if (!stage) { res.status = "no-stage"; res.why = `checker has no ${want} stage for ${connection}; planned ${evaluation.stages.map(s => s.stage.key + ":" + s.state).join(",")}`; continue; }
  res.stageState = stage.state;
  const got = stage.match && stage.match.rule ? String(stage.match.rule.ruleId ?? stage.match.rule.id) : null;
  res.gotRule = got;
  if (stage.state === "not-reached" || stage.state === "skipped") { res.status = "wrong-stage"; res.why = `${want} ${stage.state}: ${stage.reason}`; continue; }
  if (stage.state === "needs-answer") { res.status = "undetermined"; res.why = stage.match.reason; continue; }
  const loggedBlocked = String(event.Action || "Blocked").toLowerCase() === "blocked";
  if (got === expectedRule && !loggedBlocked) {
    // An allowed event: same rule, and the checker must not predict a block.
    if (stage.action === "block") { res.status = "over-blocked"; res.why = stage.security ? `predicted ${stage.security.category} block by ${stage.security.profile || stage.security.setting}` : "predicted a block"; }
    else res.status = "match-allowed";
  } else if (got === expectedRule) {
    // A blocked event: the prediction must say so too.
    if (stage.action === "block") res.status = stage.security ? `match-blocked-by-${stage.security.profile ? "web-security-profile" : "dns-security"}` : "match-blocked-by-rule";
    else {
      const cause = logBlockCause(event);
      res.status = cause.kind === "threat" ? "missed-threat-block" : "rule-ok-content-control";
      res.why = `rule matched and allows; log blocked by ${cause.name}`;
    }
  } else {
    res.status = "wrong-rule";
    const r = got && ruleById.get(got);
    res.why = `predicted ${got} (${r ? r.ruleName || r.name : "none"}) expected ${expectedRule} (${(ruleById.get(expectedRule) || {}).name || "?"})`;
  }
}

// ---- report ----
const total = rows.reduce((n, event) => n + (Number(event.__count) || 1), 0);
const sum = f => results.filter(f).reduce((n, r) => n + r.count, 0);
const byStatus = {};
for (const r of results) { byStatus[r.status] = byStatus[r.status] || { scenarios: 0, events: 0 }; byStatus[r.status].scenarios++; byStatus[r.status].events += r.count; }
console.log(`events ${total}, distinct scenarios ${results.length}\n`);
console.log("status".padEnd(28), "scenarios".padStart(9), "events".padStart(8));
for (const [k, v] of Object.entries(byStatus).sort((a, b) => b[1].events - a[1].events)) console.log(k.padEnd(28), String(v.scenarios).padStart(9), String(v.events).padStart(8));
const inScope = results.filter(r => r.status !== "out-of-scope");
const ruleOk = inScope.filter(r => r.status.startsWith("match") || r.status === "rule-ok-content-control");
const decided = r => r.status !== "out-of-scope" && r.status !== "rule-ok-content-control";
console.log(`\nrule + layer accuracy (in scope): ${sum(r => r.status.startsWith("match") || r.status === "rule-ok-content-control")}/${sum(r => r.status !== "out-of-scope")} events, ${ruleOk.length}/${inScope.length} scenarios`);
console.log(`final "Blocked" verdict (excluding content-level controls): ${sum(r => decided(r) && r.status.startsWith("match"))}/${sum(decided)} events`);
console.log("\nper logged type / rule:");
const groups = new Map();
for (const r of results) { const k = `${r.event.Type} rule ${r.expectedRule}`; const g = groups.get(k) || {}; g[r.status] = (g[r.status] || 0) + r.count; groups.set(k, g); }
for (const [k, g] of groups) console.log(" ", k.padEnd(24), JSON.stringify(g));
console.log("\nfailure reasons (by events):");
const reasons = new Map();
for (const r of results.filter(r => !r.status.startsWith("match") && r.status !== "out-of-scope" && r.status !== "rule-ok-content-control")) { const k = `${r.status}: ${r.why}`; reasons.set(k, (reasons.get(k) || 0) + r.count); }
for (const [k, v] of [...reasons].sort((a, b) => b[1] - a[1]).slice(0, 25)) console.log(String(v).padStart(7), k.slice(0, 220));
console.log("\nnotes (by events):");
const notes = new Map();
for (const r of results) for (const n of r.notes) notes.set(n, (notes.get(n) || 0) + r.count);
for (const [k, v] of [...notes].sort((a, b) => b[1] - a[1]).slice(0, 20)) console.log(String(v).padStart(7), k.slice(0, 200));
fs.writeFileSync(OUT, JSON.stringify(results.map(r => ({ status: r.status, why: r.why, count: r.count, connection: r.connection, expectedRule: r.expectedRule, gotRule: r.gotRule, notes: [...r.notes], event: { Type: r.event.Type, Identities: r.event.Identities, "Identity Types": r.event["Identity Types"], Destination: r.event.Destination, Hostname: r.event.Hostname, "Destination IP": r.event["Destination IP"], "Destination Port": r.event["Destination Port"], Protocol: r.event.Protocol, Categories: r.event.Categories, "Blocked Categories": r.event["Blocked Categories"], Application: r.event.Application } })), null, 1));
