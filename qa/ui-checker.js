"use strict";

const catalogs = {
  sourceUsers: { 7: "Denise Adams (denise.adams@example.org)", 8: "A user with a very long name (long.email.address@example.org)", 10: "Denise Park (denise.park@example.org)" },
  sourceGroups: { 3: "Infrastructure and Operations Team" },
  sourceRoaming: { 9: "Roaming computer" },
  sourceSites: { 21: "Carson City" },
  sourceNetworks: { 1: "Branch egress" },
  sourceTunnelGroups: { 33: "Branch tunnel" },
  sourceBranches: { 34: "Branch" },
  sourceCatalystSdwan: { 66: "SD-WAN VPN" },
  sourceSecurityGroupTags: { 77: "Finance" },
  sourceEndpointDevices: { 55: "Workstation" },
  contentCategories: { 27: "Gambling", 28: "Social Networking" },
  applications: { 27: "Application sharing the category ID" },
  sourceIdentityTypeIds: { 7: 7, 3: 3, 9: 9, 21: 21, 1: 1, 33: 40 },
  exclusions: [
    { id: "ex-1", domain: "ninjarmm.com", description: "Tom Testing NINJA bypass", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-2", domain: "ninjarmm.net", description: "Tom testing NINJARMM bypass", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-3", domain: "nvsc-ad.local", description: "Local Domain", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-4", domain: "scointranet.nv.gov", description: "Internal Executive Branch Resources", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-5", domain: "state.nv.us", description: "", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-6", domain: "thesource.jfs.ohio.gov", description: "", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-7", domain: "ts01-gyr-maverick.cloudsink.net", description: "", intent: "Bypass Secure Access", appliesTo: "All Devices, All Sites" },
    { id: "ex-8", domain: "*halcyon.ai", description: "New Instance CrowdStrike Agent - ZW 2026-06-25", intent: "Bypass Web Proxy", appliesTo: "Hosted PAC, AnyConnect" },
    { id: "ex-9", domain: "api.laggar.gcw.crowdstrike.com", description: "CrowdsStrike Agent. -ZW 2026-06-15", intent: "Bypass Web Proxy", appliesTo: "Hosted PAC, AnyConnect" },
    { id: "ex-10", domain: "api.us-2.crowdstrike.com", description: "New Instance CrowdStrike Agent - GS 2026-06-15", intent: "Bypass Web Proxy", appliesTo: "Hosted PAC, AnyConnect" }
  ],
};
const condition = (attributeName, attributeValue, attributeOperator = "INTERSECT") => ({ attributeName, attributeValue, attributeOperator });
const sourceAll = condition("umbrella.source.all", true, "=");
const destinationAll = condition("umbrella.destination.all", true, "=");
const rule = (ruleId, ruleName, ruleAction, ruleConditions, rulePriority = ruleId, trafficScope = "public_internet") => ({ ruleId, ruleName, rulePriority, ruleAction, ruleConditions, ruleIsEnabled: true, trafficScope });
const publicDefault = { ...rule(99, "Default Internet", "allow", [sourceAll, destinationAll]), ruleIsDefault: true };
const privateDefault = { ...rule(98, "Default Private", "block", [sourceAll, destinationAll], 98, "private_network"), ruleIsDefault: true };
const scenarios = {
  allow: [publicDefault, privateDefault],
  category: [rule(1, "Restricted destinations for this organization", "block", [sourceAll, condition("umbrella.destination.category_ids", [27]), condition("umbrella.destination.application_ids", [27])]), publicDefault, privateDefault],
  ip: [rule(2, "VPN client to internal network", "allow", [condition("umbrella.source.composite_inline_ip", [{ ip: ["10.141.195.0/24"], port: ["0-65535"], protocol: "ANY" }], "IN"), destinationAll], 2, "private_network"), publicDefault, privateDefault],
};
window.uiFixture = {
  scenario: "allow", delay: 0, fail: false, calls: [], pending: [],
  configure(next) { Object.assign(this, next); },
  release() { this.pending.splice(0).forEach(resolve => resolve()); },
};
window.checker = window.TrafficPathPanel.create(document.getElementById("checker"), catalogs, async (request, options) => {
  const fixture = window.uiFixture;
  fixture.calls.push({ request, options });
  const scenario = fixture.scenario;
  if (fixture.delay) await new Promise(resolve => fixture.pending.push(resolve));
  if (fixture.fail) throw new Error("Test lookup failed. Retry the check.");
  const lookup = options.autoLookup !== false && request.destination.kind === "domain"
    ? { ok: false, error: "Investigate returned 403" } : null;
  return { ...window.TrafficPath.evaluate(request, scenarios[scenario], catalogs, window.Matcher), lookups: catalogs, destinationLookup: lookup, facts: request.facts };
}, (targets, summary) => { window.uiFixture.highlight = { targets, summary }; }, {
  getPolicy: async () => ({ rules: scenarios[window.uiFixture.scenario], lookups: catalogs }),
});
window.checker.setData({ rulesCount: 2, catalogs, context: "dashboard" });
