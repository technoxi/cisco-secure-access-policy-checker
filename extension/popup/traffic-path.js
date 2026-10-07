// =============================================================================
// traffic-path.js — Policy Checker model.
//
// Predicts which access rule a request hits at each enforcement point, the
// way Umbrella's policy tester does, from four connection types:
//
//   Secure Client   roaming computer (+ logged-in user)          DNS → Web
//   On-prem VA      site, internal IP, AD user/computer, network  DNS only
//   Network DNS     registered network (public IP)                DNS only
//   S2S tunnel      tunnel, internal IP, AD user/computer,        Firewall → Web
//                   SD-WAN VPN, security group tag
//
// Identity kinds per connection follow what Activity Search logs for each
// path. Tunnel identities never appear in DNS events: branch DNS reaches
// Secure Access through a VA or a registered network, checked as its own
// connection. A request carries every identity its connection exposes; a rule's
// source matches if any of them (or a group they belong to) is listed. Stages
// run in traffic order; a firewall block stops later stages, while a DNS
// block leaves Web evaluated as a fallback (DNS may not know the user).
//
// Pure logic (no DOM, no extension APIs) so Node tests can drive it.
// =============================================================================
(function (root) {
  "use strict";

  const ip = root.IPAddress;

  const SOURCES = {
    roaming: { label: "Roaming computer", catalogs: ["sourceRoaming"], inputKey: "sourceRoamingId", placeholder: "Search roaming computers" },
    identity: { label: "User or group", catalogs: ["sourceUsers", "sourceGroups"], placeholder: "Search users and groups" },
    site: { label: "Site", catalogs: ["sourceSites"], inputKey: "sourceSiteId", placeholder: "Search sites" },
    network: { label: "Egress network (public IP)", catalogs: ["sourceNetworks"], inputKey: "sourceNetworkId", placeholder: "Search networks" },
    tunnel: { label: "Network tunnel", catalogs: ["sourceTunnelGroups"], inputKey: "sourceTunnelGroupId", placeholder: "Search network tunnels" },
    branch: { label: "SD-WAN branch", catalogs: ["sourceBranches"], inputKey: "sourceBranchId", placeholder: "Search branches" },
    computer: { label: "AD computer", catalogs: ["sourceEndpointDevices"], inputKey: "sourceEndpointDeviceId", placeholder: "Search AD computers" },
    sdwan: { label: "SD-WAN VPN", catalogs: ["sourceCatalystSdwan"], inputKey: "sourceCatalystSdwanId", placeholder: "Search SD-WAN VPNs" },
    sgt: { label: "Security group tag", catalogs: ["sourceSecurityGroupTags"], inputKey: "sourceSecurityGroupTagId", placeholder: "Search security group tags" },
    internalIp: { label: "Internal client IP", placeholder: "e.g. 10.1.20.15" },
  };

  const CATALOG_INPUT_KEY = {
    sourceUsers: "sourceUserId",
    sourceGroups: "sourceGroupId",
    sourceRoaming: "sourceRoamingId",
    sourceSites: "sourceSiteId",
    sourceNetworks: "sourceNetworkId",
    sourceTunnelGroups: "sourceTunnelGroupId",
    sourceBranches: "sourceBranchId",
    sourceEndpointDevices: "sourceEndpointDeviceId",
    sourceCatalystSdwan: "sourceCatalystSdwanId",
    sourceSecurityGroupTags: "sourceSecurityGroupTagId",
  };

  const CONNECTIONS = {
    client: {
      label: "Secure Client", layers: "DNS + Web",
      description: "A roaming computer with Secure Client. Traffic carries the computer and the signed-in user.",
      sources: ["roaming", "identity"],
    },
    va: {
      label: "On-prem VA", layers: "DNS only",
      description: "DNS forwarded by a virtual appliance. The VA reports its site, the client's internal IP, and the AD user or computer.",
      sources: ["site", "internalIp", "identity", "computer", "network"],
    },
    vpn: {
      label: "Remote access VPN", layers: "Firewall + Web",
      description: "Secure Client in VPN mode: all traffic goes to Secure Access. Traffic carries the AD user and computer and the VPN address.",
      sources: ["identity", "computer", "internalIp"],
    },
    network: {
      label: "Network DNS", layers: "DNS only",
      description: "DNS sent straight from a registered network's public IP. Secure Access sees only the network.",
      sources: ["network"],
    },
    tunnel: {
      label: "Site-to-site tunnel", layers: "Firewall + Web",
      description: "Branch traffic sent through an IPsec tunnel. Firewall traffic may carry the AD user or computer, SD-WAN VPN, and security group tag; user and computer identities are not always available at Web.",
      sources: ["tunnel", "branch", "internalIp", "identity", "computer", "sdwan", "sgt"],
    },
  };

  const STAGES = {
    dns: { key: "dns", label: "DNS" },
    firewall: { key: "firewall", label: "Firewall" },
    web: { key: "web", label: "Web" },
    private: { key: "private", label: "Private access" },
  };

  const DNS_ONLY = ["va", "network"];
  const NETWORK_TUNNELS_TYPE_ID = "40";
  const WEB_PORTS = ["80", "443"];
  const PROTOCOLS = ["TCP", "UDP", "ICMP"];

  // ---------------------------------------------------------------------------
  // Destination
  // ---------------------------------------------------------------------------

  function isHostname(value) {
    return /^(?=.{1,253}$)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i.test(value);
  }

  function parsePort(value) {
    const text = String(value || "").trim();
    if (!text) return "";
    if (!/^\d{1,5}$/.test(text) || Number(text) < 1 || Number(text) > 65535) return null;
    return String(Number(text));
  }

  // Accepts a domain, an http(s) URL, or an IPv4/IPv6 address with an optional
  // port ("10.0.0.5:445", "[2001:db8::1]:443").
  function parseDestination(text) {
    const value = String(text || "").trim();
    if (!value) return { error: "Enter a destination: a domain, URL, or IP address." };
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      // WebSockets (ws/wss) are web traffic on the same ports as http/https.
      if (!/^(https?|wss?):\/\//i.test(value)) return { error: "Only http(s):// and ws(s):// URLs can be checked." };
      let url;
      try { url = new URL(value.replace(/^ws(s?):/i, "http$1:")); } catch (_) { return { error: "That URL could not be read." }; }
      const host = url.hostname.replace(/^\[|\]$/g, "");
      const hostIsIp = !!ip.parse(host);
      if (!hostIsIp && !isHostname(host)) return { error: "The URL needs a domain or IP host." };
      const port = url.port || (url.protocol === "https:" ? "443" : "80");
      return { host, kind: hostIsIp ? "ip" : "domain", port, fromUrl: true };
    }
    const bracketed = value.match(/^\[([0-9a-f:.]+)\](?::(\d+))?$/i);
    if (bracketed && ip.parse(bracketed[1]) && ip.parse(bracketed[1]).version === 6) {
      const port = parsePort(bracketed[2]);
      if (port === null) return { error: "Ports run from 1 to 65535." };
      return { host: bracketed[1], kind: "ip", port };
    }
    if (ip.parse(value)) return { host: value, kind: "ip", port: "" };
    const v4Port = value.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
    if (v4Port && ip.parse(v4Port[1])) {
      const port = parsePort(v4Port[2]);
      if (port === null) return { error: "Ports run from 1 to 65535." };
      return { host: v4Port[1], kind: "ip", port };
    }
    if (ip.parseCidr(value)) return { error: "Enter a single IP address, not a range." };
    if (isHostname(value.replace(/\.$/, ""))) {
      if (value.startsWith("*.")) return { error: "Enter a specific domain, not a wildcard." };
      return { host: value.replace(/\.$/, "").toLowerCase(), kind: "domain", port: "" };
    }
    return { error: "Enter a domain (example.com), a URL (https://example.com/path), or an IP address." };
  }

  function isPrivateIp(value) {
    const parsed = ip.parse(value);
    if (!parsed) return false;
    const ranges = parsed.version === 4
      ? ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]
      : ["fc00::/7"];
    return ranges.some(range => ip.contains(value, range));
  }

  function addressMatches(host, address) {
    const target = String(address || "").trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
    if (!target) return false;
    if (ip.parse(host)) return ip.parseCidr(target) ? ip.contains(host, target) : false;
    const name = target.split("/")[0].split(":")[0];
    if (name.startsWith("*.")) return host === name.slice(2) || host.endsWith(name.slice(1));
    return host === name;
  }

  // Private Access applies when the destination is a configured private
  // resource; an internal (RFC 1918 / ULA) address is also private traffic.
  function resolveScope(host, lookups) {
    const memberMaps = (lookups && lookups.memberMaps) || {};
    const resources = memberMaps.privateResources || {};
    const addressesOf = (entry, seen) => {
      const out = [];
      for (const member of (entry && entry.members) || []) {
        if (member.value !== undefined) out.push(member.value);
        else if (member.kind === "networkObjects" && member.id !== undefined) {
          const key = `networkObjects:${member.id}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push(...addressesOf((memberMaps.networkObjects || {})[member.id], seen));
        }
      }
      return out;
    };
    const resourceIds = Object.keys(resources).filter(id => addressesOf(resources[id], new Set()).some(address => addressMatches(host, address)));
    const groupIds = Object.keys(memberMaps.privateResourceGroups || {}).filter(id => {
      const members = (memberMaps.privateResourceGroups[id] && memberMaps.privateResourceGroups[id].members) || [];
      return members.some(member => resourceIds.includes(String(member.id)));
    });
    if (resourceIds.length) {
      const names = resourceIds.map(id => (resources[id] && resources[id].name) || (lookups.privateResources && lookups.privateResources[id]) || `Resource ${id}`);
      return { scope: "private_network", privateResourceIds: resourceIds, privateResourceGroupIds: groupIds, resourceNames: names };
    }
    if (isPrivateIp(host)) return { scope: "private_network", privateResourceIds: [], privateResourceGroupIds: [], resourceNames: [] };
    return { scope: "public_internet", privateResourceIds: [], privateResourceGroupIds: [], resourceNames: [] };
  }

  // ---------------------------------------------------------------------------
  // Identities
  // ---------------------------------------------------------------------------

  // Every group that directly or transitively contains one of `ids`, from the
  // AD group membership the service worker prefetches for rule-referenced
  // groups. Returns [{ id, name }] so results can say "via group HR".
  function groupsContaining(ids, memberMaps) {
    const groups = (memberMaps && memberMaps.identityGroups) || {};
    const parents = {};
    for (const [groupId, entry] of Object.entries(groups)) {
      for (const member of (entry && entry.members) || []) {
        if (member && member.id !== undefined) (parents[String(member.id)] = parents[String(member.id)] || []).push(groupId);
      }
    }
    const found = new Map();
    const queue = ids.map(String);
    while (queue.length) {
      const id = queue.shift();
      for (const groupId of parents[id] || []) {
        if (found.has(groupId) || ids.map(String).includes(groupId)) continue;
        found.set(groupId, (groups[groupId] && groups[groupId].name) || `Group ${groupId}`);
        queue.push(groupId);
      }
    }
    return [...found].map(([id, name]) => ({ id, name }));
  }

  function catalogLabel(catalogs, key, id) {
    const entry = catalogs && catalogs[key] && catalogs[key][String(id)];
    if (!entry) return null;
    return typeof entry === "string" ? entry : entry.name || entry.label || entry.displayName || String(id);
  }

  // `form.sources` is { roaming, identity, site, network, tunnel } holding
  // "catalogKey:id" picks, plus { internalIp } as typed text.
  function buildRequest(form, catalogs) {
    const connection = CONNECTIONS[form.connection];
    if (!connection) return { error: "Choose how the traffic connects." };
    const sources = form.sources || {};
    const testInput = {};
    const identities = [];
    for (const kind of connection.sources) {
      const raw = String(sources[kind] || "").trim();
      if (!raw) continue;
      if ((kind === "roaming" || kind === "identity") && raw === `any:${kind}`) {
        testInput.identityTypeIds = [...(testInput.identityTypeIds || []), kind === "roaming" ? "9" : "7"];
        identities.push({ kind, label: kind === "roaming" ? "Any roaming computer" : "Any user" });
        continue;
      }
      if (kind === "internalIp") {
        if (ip.parseCidr(raw) && !ip.parse(raw)) return { error: "Enter one internal IP address, not a range." };
        if (!ip.parse(raw)) return { error: "The internal client IP is not a valid IPv4 or IPv6 address." };
        testInput.source = raw;
        identities.push({ kind, label: raw });
        continue;
      }
      const split = raw.indexOf(":");
      const catalogKey = raw.slice(0, split);
      const id = raw.slice(split + 1);
      if (!SOURCES[kind].catalogs.includes(catalogKey) || !id) return { error: `Pick a ${SOURCES[kind].label.toLowerCase()} from the list.` };
      const label = catalogLabel(catalogs, catalogKey, id);
      if (!label) return { error: `That ${SOURCES[kind].label.toLowerCase()} is no longer in the loaded catalog. Pick it again.` };
      testInput[CATALOG_INPUT_KEY[catalogKey]] = id;
      identities.push({ kind, catalogKey, id, label });
    }
    if (form.connection === "client" && !identities.some(identity => identity.kind === "roaming")) {
      identities.push({ kind: "roaming", label: "Any roaming computer" });
    }
    if (form.connection === "vpn" && !identities.length) {
      identities.push({ kind: "internalIp", label: "Any source" });
    }
    if (!identities.length) return { error: `Pick at least one source: ${connection.sources.map(kind => SOURCES[kind].label.toLowerCase()).join(", ")}.` };

    const destination = parseDestination(form.destination);
    if (destination.error) return destination;
    let port = destination.port;
    let protocol = "TCP";
    if (destination.kind === "ip" && !destination.fromUrl) {
      const typedPort = parsePort(form.port);
      if (typedPort === null) return { error: "Ports run from 1 to 65535." };
      port = destination.port || typedPort || "443";
      protocol = PROTOCOLS.includes(String(form.protocol || "").toUpperCase()) ? String(form.protocol).toUpperCase() : "TCP";
      if (protocol === "ICMP") port = "";
    }
    if (DNS_ONLY.includes(form.connection) && destination.kind === "ip") {
      return { error: `${connection.label} only sees DNS lookups. Enter the domain the client resolves.` };
    }
    return {
      request: {
        connection: form.connection,
        identities,
        testInput,
        destination: { ...destination, port: destination.kind === "domain" && !destination.fromUrl ? "443" : port, protocol },
        facts: form.facts || {},
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Stage plan
  // ---------------------------------------------------------------------------

  function planStages(request, scope) {
    const { connection, destination } = request;
    if (scope.scope === "private_network") {
      if (connection === "client") return {
        stages: [],
        unsupported: {
          stage: STAGES.private,
          label: "Private access unavailable",
          reason: "Standard Secure Client doesn’t route to private resources. Use Remote Access VPN or a site-to-site tunnel for this private destination.",
        },
      };
      if (DNS_ONLY.includes(connection)) return { stages: [], error: `Private Access is not reached through ${CONNECTIONS[connection].label}. Choose Secure Client or Site-to-site tunnel.` };
      // Branch traffic to an internal address or private resource is enforced
      // by the firewall (Activity Search logs it as a firewall event under the
      // private rules).
      if (connection === "tunnel" || connection === "vpn") return { stages: [{ ...STAGES.firewall }] };
      return { stages: [{ ...STAGES.private }] };
    }
    const isWebPort = destination.protocol === "TCP" && WEB_PORTS.includes(destination.port);
    const stages = [];
    const skipped = [];
    if (destination.kind === "domain" && connection !== "tunnel") stages.push({ ...STAGES.dns });
    if (connection === "tunnel" || connection === "vpn") {
      if (destination.kind === "ip") stages.push({ ...STAGES.firewall });
      else skipped.push({ ...STAGES.firewall, reason: "The firewall matches the destination IP. Enter the IP address to include it." });
    }
    if (connection === "client" || connection === "tunnel" || connection === "vpn") {
      if (isWebPort) stages.push({ ...STAGES.web });
      else if (connection === "client") skipped.push({ ...STAGES.web, reason: `Secure Client sends only web traffic (TCP 80/443) to the web proxy; ${destination.protocol} ${destination.port || ""} is not inspected.`.replace(/ ;/, ";") });
    }
    if (!stages.length) return { stages, skipped, error: "Nothing on this connection evaluates that destination. Try a domain or a web port." };
    return { stages, skipped };
  }

  // ---------------------------------------------------------------------------
  // Evaluation
  // ---------------------------------------------------------------------------

  function applyFacts(testInput, facts) {
    const out = { ...testInput, ruledOut: {}, ruledOutAll: [] };
    for (const [field, answer] of Object.entries(facts || {})) {
      if (answer.yes && answer.yes.length) out[field] = [...answer.yes];
      if (answer.no && answer.no.length) out.ruledOut[field] = [...answer.no];
      if (answer.all) out.ruledOutAll.push(field);
    }
    return out;
  }

  // Facts from a Cisco Investigate lookup ({ contentBits, securityBits, app },
  // see the service worker's lookupDestination). Each field is complete
  // (all: true): what Cisco does not list is a no. Category and application
  // lists follow from their members. lookups.categories and
  // lookups.securityCategories are the bundled bit-position lookups.
  function factsFromLookup(result, lookups) {
    if (!result || !result.ok) return {};
    lookups = lookups || {};
    const bits = lookups.categories || {};
    const securityBits = lookups.securityCategories || {};
    const memberMaps = lookups.memberMaps || {};
    const contentIds = result.contentBits.map(bit => bits[bit] && String(bits[bit].categoryId)).filter(Boolean);
    const threats = [...new Set([
      ...result.securityBits.map(bit => securityBits[bit] && securityBits[bit].name),
      ...(result.securityNames || []),
    ].filter(Boolean))];
    const listsWith = (kind, ids) => Object.entries(memberMaps[kind] || {})
      .filter(([, entry]) => ((entry && entry.members) || []).some(member => ids.includes(String(member.id))))
      .map(([id]) => String(id));
    const facts = {
      contentCategoryId: { yes: contentIds, no: [], all: true },
      categoryListId: { yes: listsWith("categoryLists", contentIds), no: [], all: true },
      securityCategory: { yes: threats, no: [], all: true, auto: true },
    };
    // CASI names the cloud app; match it to the org's application catalog.
    const appName = result.app && result.app.name.toLowerCase();
    const appIds = appName ? Object.entries(lookups.applications || {}).filter(([, name]) => String(name).toLowerCase() === appName).map(([id]) => String(id)) : [];
    if (!result.app || appIds.length) {
      facts.applicationId = { yes: appIds, no: [], all: true };
      facts.applicationListId = { yes: listsWith("applicationLists", appIds), no: [], all: true };
    }
    Object.values(facts).forEach(fact => { fact.auto = true; });
    return facts;
  }

  function stageInput(request, scope, groups, stage) {
    const base = applyFacts(request.testInput, request.facts);
    const input = {
      ...base,
      sourceIdentityIds: [...new Set([...(base.sourceIdentityIds || []).map(String), ...groups.map(group => group.id)])],
      destination: request.destination.host,
      destinationScope: scope.scope,
      trafficStage: stage.key === "private" ? "" : stage.key,
    };
    if (request.connection === "client") {
      input.identityTypeIds = [...new Set([...(base.identityTypeIds || []).map(String), "9"])];
    }
    // Everything on the tunnel connection arrives over a network tunnel, so
    // it carries the Network Tunnels identity type (40) even when only SD-WAN
    // VPN / security group identities are known. Activity Search logs such
    // flows (identities "IOT_OT (VPN-10), IOT_OT (SGT-100)") under a rule on
    // type 40.
    if (request.connection === "tunnel") {
      input.identityTypeIds = [...new Set([...(Array.isArray(base.identityTypeIds) ? base.identityTypeIds : base.identityTypeIds ? [base.identityTypeIds] : []).map(String), NETWORK_TUNNELS_TYPE_ID])];
    }
    if (scope.privateResourceIds.length) input.privateResourceId = scope.privateResourceIds;
    if (scope.privateResourceGroupIds.length) input.privateResourceGroupId = scope.privateResourceGroupIds;
    if (stage.key === "dns") {
      // A lookup reaches the resolver on UDP 53; rules scoped to other ports
      // are about the connection that follows, not the query.
      input.destinationPort = "53";
      input.destinationProtocol = "udp";
    } else if (stage.key === "web") {
      input.destinationPort = request.destination.port;
      input.destinationProtocol = "tcp";
    } else if (stage.key === "firewall" || stage.key === "private") {
      if (request.destination.port) input.destinationPort = request.destination.port;
      input.destinationProtocol = request.destination.protocol.toLowerCase();
    }
    return input;
  }

  function ruleAction(rule) {
    return String((rule && (rule.ruleAction || rule.action)) || "").trim().toLowerCase();
  }

  const ACTION_LABELS = { allow: "Allow", block: "Block", warn: "Warn", isolate: "Isolate" };

  function actionLabel(action) {
    return ACTION_LABELS[action] || (action ? action.charAt(0).toUpperCase() + action.slice(1) : "Unknown");
  }

  function webProfile(rule) {
    const settings = (rule && rule.raw && rule.raw.ruleSettings) || rule && rule.ruleSettings || [];
    const entry = Array.isArray(settings) && settings.find(setting => setting.settingName === "umbrella.posture.webProfileId");
    const value = entry && entry.settingValue;
    return value === undefined || value === null || value === "" ? null : String(value);
  }

  function hasDestinationGeoCondition(rule) {
    return (rule.ruleConditions || rule.conditions || []).some(condition => {
      const name = String(condition.attributeName || "").toLowerCase();
      return name.startsWith("umbrella.destination.") && name.includes("geolocations");
    });
  }

  function matchExclusion(host, exclusions) {
    if (!host || !Array.isArray(exclusions)) return null;
    const target = host.toLowerCase().trim();
    for (const ex of exclusions) {
      if (!ex || !ex.domain) continue;
      let pattern = ex.domain.toLowerCase().trim();
      if (pattern.startsWith("*.")) {
        const suffix = pattern.slice(2);
        if (target === suffix || target.endsWith("." + suffix)) return ex;
      } else if (pattern.startsWith("*")) {
        const suffix = pattern.slice(1);
        if (target === suffix || target.endsWith(suffix) || target.endsWith("." + suffix)) return ex;
      } else {
        if (target === pattern || target.endsWith("." + pattern)) return ex;
      }
    }
    return null;
  }

  // `matcher` is window.Matcher (or its Node equivalent).
  function evaluate(request, rules, lookups, matcher) {
    lookups = lookups || {};
    const scope = resolveScope(request.destination.host, lookups);
    const plan = planStages(request, scope);
    if (plan.error && !plan.stages.length) return { error: plan.error };
    if (plan.unsupported) {
      return {
        scope, groups: [],
        stages: [{ stage: plan.unsupported.stage, state: "unsupported", reason: plan.unsupported.reason }],
        outcome: { status: "unsupported", title: plan.unsupported.label, stage: plan.unsupported.stage.key, reason: plan.unsupported.reason },
        threatCheck: null,
      };
    }
    const directIds = request.identities.filter(identity => identity.id !== undefined).map(identity => identity.id);
    const groups = groupsContaining(directIds, lookups.memberMaps);
    const firewallInput = stageInput(request, scope, groups, STAGES.firewall);
    const orderedRules = (rules || []).filter(rule => !hasDestinationGeoCondition(rule)).sort((a, b) =>
      Number((a.ruleIsDefault ?? a.is_default) === true) - Number((b.ruleIsDefault ?? b.is_default) === true) ||
      (a.rulePriority ?? a.order) - (b.rulePriority ?? b.order));
    const knownMatch = matcher.matchPolicy(orderedRules, firewallInput, lookups);
    const winnerIndex = knownMatch.rule ? orderedRules.indexOf(knownMatch.rule) : orderedRules.length;
    const needsVpnClientIp = request.connection === "vpn" && scope.scope === "private_network" && !request.testInput.source && orderedRules.slice(0, winnerIndex).find(rule => {
      if (hasDestinationGeoCondition(rule)) return false;
      const privateScope = rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess);
      const originalConditions = rule.ruleConditions || rule.conditions || [];
      const sourceNetworks = originalConditions.filter(condition => {
        const name = String(condition.attributeName || "").toLowerCase();
        return name === "umbrella.source.composite_inline_ip" ||
          (name.startsWith("umbrella.source.") && name.includes("networkobject"));
      });
      if (privateScope !== "private_network" || !sourceNetworks.length) return false;
      const conditions = originalConditions.map(condition => sourceNetworks.includes(condition)
        ? { attributeName: "umbrella.source.all", attributeOperator: "=", attributeValue: true }
        : condition);
      return matcher.matchPolicy([{ ...rule, ruleConditions: conditions, conditions }], firewallInput, lookups).rule !== undefined;
    });
    if (needsVpnClientIp) {
      const reason = "This rule requires the VPN-assigned client IP to check its source-address constraints. VPN user/group checks alone do not require it.";
      return {
        scope, groups,
        stages: [{ stage: STAGES.firewall, state: "needs-answer", match: { rule: needsVpnClientIp, indeterminate: true, pending: [] }, reason }],
        outcome: { status: "pending", title: "Source IP needed for candidate rule", stage: STAGES.firewall.key, rule: needsVpnClientIp, reason },
        threatCheck: null,
      };
    }
    const exclusion = matchExclusion(request.destination.host, lookups.exclusions);
    const bypassDns = exclusion && exclusion.intent === "Bypass Secure Access";
    const bypassWeb = exclusion && (exclusion.intent === "Bypass Secure Access" || exclusion.intent === "Bypass Web Proxy");
    const results = [];
    let blockedAt = null;
    let uncertainBefore = null;
    const threats = threatContext(lookups);
    const threatAnswer = (request.facts && request.facts.securityCategory) || null;
    const flagged = new Set(threatAnswer ? threatAnswer.yes : []);
    const threatCategories = new Set();
    for (const stage of plan.stages) {
      if (stage.key === "dns" && bypassDns) {
        results.push({ stage, state: "bypassed", reason: `Bypasses Secure Access via Traffic Steering (${exclusion.domain})` });
        continue;
      }
      if (stage.key === "web" && bypassWeb) {
        results.push({ stage, state: "bypassed", reason: `${exclusion.intent} via Traffic Steering (${exclusion.domain})` });
        continue;
      }
      // A firewall block ends the connection. A DNS block usually does too,
      // but the client's DNS may not reach Secure Access, or DNS may not know
      // the user (their identity can exist only at the proxy), so Web is still
      // evaluated and shown as the fallback. Activity Search shows both: proxy
      // blocks for requests a DNS rule, or the DNS security setting, covers.
      if (blockedAt && blockedAt.key !== "dns") {
        results.push({ stage, state: "not-reached", reason: `Blocked at ${blockedAt.label} first.` });
        continue;
      }
      // DNS security settings apply before any rule (Activity Search logs
      // these as rule 0, "Block due to security setting").
      if (stage.key === "dns" && threats.dns) {
        threats.dns.categories.forEach(name => threatCategories.add(name));
        const hit = threats.dns.categories.find(name => flagged.has(name));
        if (hit) {
          results.push({ stage, state: "matched", action: "block", match: { rule: DNS_SECURITY_RULE, matchedConditions: [`${hit} is blocked by the DNS security setting "${threats.dns.name}"`] }, security: { category: hit, setting: threats.dns.name, source: "DNS security settings" } });
          blockedAt = stage;
          continue;
        }
      }
      const input = stageInput(request, scope, groups, stage);
      const eligibleRules = (rules || []).filter(rule => !hasDestinationGeoCondition(rule));
      const match = matcher.matchPolicy(eligibleRules, input, lookups);
      if (request.connection === "tunnel" && !request.testInput.sourceTunnelGroupId && !request.testInput.sourceBranchId &&
          !request.testInput.sourceCatalystSdwanId && !request.testInput.sourceSecurityGroupTagId) {
        const ordered = [...eligibleRules].sort((a, b) => {
          const defaultOf = rule => (rule.ruleIsDefault ?? rule.is_default) === true;
          return Number(defaultOf(a)) - Number(defaultOf(b)) || (a.rulePriority ?? a.order) - (b.rulePriority ?? b.order);
        });
        const winnerIndex = match.rule ? ordered.indexOf(match.rule) : ordered.length;
        const candidates = ordered.slice(0, winnerIndex).flatMap(rule => (rule.ruleConditions || rule.conditions || [])
          .filter(condition => String(condition.attributeName || "").toLowerCase() === "umbrella.source.identity_ids")
          .flatMap(condition => Array.isArray(condition.attributeValue) ? condition.attributeValue : [condition.attributeValue]))
          .map(String).filter(id => (lookups.sourceTunnelGroups || {})[id] || (lookups.sourceBranches || {})[id]);
        for (const id of new Set(candidates)) {
          const hypothetical = { ...input, sourceIdentityIds: [...new Set([...input.sourceIdentityIds, id, ...groupsContaining([...directIds, id], lookups.memberMaps).map(group => group.id)])] };
          const possible = matcher.matchPolicy(eligibleRules, hypothetical, lookups);
          if (possible.rule && ordered.indexOf(possible.rule) < winnerIndex) {
            return { error: "Select the network tunnel or branch: an earlier rule depends on that identity." };
          }
        }
      }
      // The firewall cannot classify the application or category from the
      // first packets: it lets the flow through under the first rule whose
      // source matches and decides once the application is identified.
      // Activity Search logs these as Allowed under that rule, even for Block
      // and Isolate rules (verified on a million-event export).
      // Only TCP: the handshake carries no payload, while the first UDP
      // packet already identifies the application (Activity Search: SD-WAN
      // DNS on UDP 53 was not logged under an app-list rule).
      if (match && match.indeterminate && stage.key === "firewall" && request.destination.protocol === "TCP" && match.pending && match.pending.length) {
        results.push({ stage, state: "matched", match, action: "allow", provisional: true, conditional: uncertainBefore, afterBlock: blockedAt || null });
        continue;
      }
      if (match && match.indeterminate) {
        results.push({ stage, state: "needs-answer", match, conditional: uncertainBefore, afterBlock: blockedAt || null });
        if (!uncertainBefore) uncertainBefore = stage;
        continue;
      }
      if (!match || match.noMatch || !match.rule) {
        results.push({ stage, state: "no-match", match, conditional: uncertainBefore, afterBlock: blockedAt || null });
        continue;
      }
      let action = ruleAction(match.rule);
      const profileId = stage.key === "web" ? webProfile(match.rule) : null;
      let security = null;
      // An Allow/Warn/Isolate rule still sends web traffic through its
      // security profile, which blocks flagged destinations.
      const profile = profileId && action !== "block" ? threats.profile(profileId) : null;
      if (profile) {
        profile.categories.forEach(name => threatCategories.add(name));
        const hit = profile.categories.find(name => flagged.has(name));
        if (hit) {
          security = { category: hit, setting: profile.settingName, profile: profile.name, source: "security profile" };
          action = "block";
        }
      }
      results.push({
        stage, state: "matched", match, action, security, conditional: uncertainBefore, afterBlock: blockedAt || null,
        webProfileId: profileId, webProfileName: profile ? profile.name : null,
        ipsProfileId: stage.key === "firewall" ? ruleSettingValue(match.rule, "umbrella.posture.ipsProfileId") : null,
      });
      if (action === "block" && !uncertainBefore && !blockedAt) blockedAt = stage;
    }
    for (const skipped of plan.skipped || []) results.push({ stage: skipped, state: "skipped", reason: skipped.reason });
    results.sort((a, b) => stageOrder(a.stage.key) - stageOrder(b.stage.key));
    const outcome = outcomeOf(results);
    // Threat categories in play and not yet answered: the result holds
    // "unless Cisco flags it", and the panel asks.
    const threatCheck = !threatAnswer && threatCategories.size && outcome.status !== "block" && outcome.status !== "pending" && outcome.status !== "unsupported"
      ? { categories: [...threatCategories].sort() }
      : null;
    if (threatCheck) outcome.unlessFlagged = true;
    return { scope, groups, stages: results, outcome, threatCheck };
  }

  const DNS_SECURITY_RULE = { ruleId: 0, ruleName: "DNS security settings", ruleAction: "block", security: true };

  function ruleSettingValue(rule, name) {
    const settings = (rule && rule.raw && rule.raw.ruleSettings) || (rule && rule.ruleSettings) || [];
    const entry = Array.isArray(settings) && settings.find(setting => setting.settingName === name);
    const value = entry && entry.settingValue;
    return value === undefined || value === null || value === "" || value === 0 || value === "0" ? null : String(value);
  }

  // lookups.securityProfiles = { securitySettings, webProfiles, dnsDefaultSettingId }
  function threatContext(lookups) {
    const data = (lookups && lookups.securityProfiles) || {};
    const settings = data.securitySettings || {};
    const dnsSetting = data.dnsDefaultSettingId && settings[data.dnsDefaultSettingId];
    return {
      dns: dnsSetting && dnsSetting.categories.length ? { name: dnsSetting.name, categories: dnsSetting.categories } : null,
      profile(profileId) {
        const profile = (data.webProfiles || {})[String(profileId)];
        const setting = profile && profile.securitySettingId && settings[profile.securitySettingId];
        return setting && setting.categories.length ? { name: profile.name, settingName: setting.name, categories: setting.categories } : null;
      },
    };
  }

  // The "is it flagged as a threat?" prompt, in the same shape as questionFor.
  function threatQuestion(evaluation, host) {
    if (!evaluation.threatCheck) return null;
    return {
      host,
      kind: "threat",
      prompt: `Is ${host} flagged as a security threat?`,
      groups: [{ field: "securityCategory", noun: "threat category", options: evaluation.threatCheck.categories.map(name => ({ id: name, label: name })) }],
    };
  }

  function stageOrder(key) {
    return ["dns", "firewall", "web", "private"].indexOf(key);
  }

  function outcomeOf(results) {
    const active = results.filter(result => result.state !== "skipped" && result.state !== "not-reached");
    const uncertain = active.find(result => result.state === "needs-answer" || result.state === "unsupported");
    const block = active.find(result => result.state === "matched" && result.action === "block");
    if (block && (!uncertain || stageOrder(block.stage.key) < stageOrder(uncertain.stage.key))) {
      return { status: "block", title: `Blocked at ${block.stage.label}`, stage: block.stage.key, rule: block.match.rule };
    }
    if (uncertain && uncertain.state === "unsupported") {
      return { status: "unsupported", title: "Cannot determine policy match", stage: uncertain.stage.key, rule: uncertain.match.rule, reason: uncertain.reason };
    }
    if (uncertain) return { status: "pending", title: "Needs one more detail", stage: uncertain.stage.key };
    if (active.some(result => result.state === "no-match")) return { status: "unknown", title: "No rule matched", stage: null };
    if (active.length && active.every(result => result.state === "bypassed")) {
      const bypassReason = active[0].reason || "Bypasses Secure Access via Traffic Steering";
      return { status: "bypassed", title: "Bypassed via Traffic Steering", stage: null, reason: bypassReason };
    }
    const last = active[active.length - 1];
    if (!last) return { status: "unknown", title: "Not evaluated", stage: null };
    if (last.state === "bypassed") {
      const evaluated = active.find(result => result.state === "matched");
      if (evaluated) {
        const status = ACTION_LABELS[evaluated.action] ? evaluated.action : "unknown";
        const title = status === "allow" ? "Allowed" : status === "warn" ? "Warned" : status === "isolate" ? "Isolated" : actionLabel(evaluated.action);
        return { status, title, stage: evaluated.stage.key, rule: evaluated.match.rule };
      }
      return { status: "bypassed", title: "Bypassed via Traffic Steering", stage: null, reason: last.reason };
    }
    const status = ACTION_LABELS[last.action] ? last.action : "unknown";
    const title = status === "allow" ? "Allowed" : status === "warn" ? "Warned" : status === "isolate" ? "Isolated" : actionLabel(last.action);
    return { status, title, stage: last.stage.key, rule: last.match.rule };
  }

  // ---------------------------------------------------------------------------
  // Questions — turn an indeterminate stage into a multiple-choice prompt
  // ---------------------------------------------------------------------------

  const QUESTION_FIELDS = {
    contentCategoryId: { noun: "content category", catalogs: ["contentCategories"] },
    applicationId: { noun: "application", catalogs: ["applications", "enterpriseApplications", "apps", "protocols"] },
    applicationCategoryId: { noun: "application category", catalogs: ["applicationCategories"] },
    applicationListId: { noun: "application list", catalogs: ["applicationLists"] },
    categoryListId: { noun: "category list", catalogs: ["categoryLists"] },
    destinationListId: { noun: "destination list", catalogs: ["destinationLists"] },
    appRiskProfileId: { noun: "app risk profile", catalogs: ["appRiskProfiles"] },
    geolocation: { noun: "location", catalogs: ["geolocations"] },
  };

  function valueLabel(field, id, lookups) {
    if (field === "securityCategory") return String(id);
    const config = QUESTION_FIELDS[field];
    for (const key of (config && config.catalogs) || []) {
      const label = catalogLabel(lookups, key, id);
      if (label) return label;
    }
    if (field === "contentCategoryId" && lookups.categories) {
      const entry = Object.values(lookups.categories).find(item => item && String(item.categoryId) === String(id));
      if (entry) return entry.name;
    }
    return `${config ? config.noun.charAt(0).toUpperCase() + config.noun.slice(1) : "Value"} ${id}`;
  }

  // A list's members, for a hint like "Gambling, Games, +3 more".
  function listPreview(field, id, lookups) {
    const kind = field === "categoryListId" ? "categoryLists" : field === "applicationListId" ? "applicationLists" : null;
    const entry = kind && lookups.memberMaps && lookups.memberMaps[kind] && lookups.memberMaps[kind][String(id)];
    if (!entry || !entry.members || !entry.members.length) return "";
    const memberField = kind === "categoryLists" ? "contentCategoryId" : "applicationId";
    const names = entry.members.slice(0, 3).map(member => member.name || valueLabel(memberField, member.id, lookups));
    return names.join(", ") + (entry.members.length > 3 ? `, +${entry.members.length - 3} more` : "");
  }

  function questionFor(result, host, lookups) {
    const pending = ((result.match && result.match.pending) || []).filter(item => item.field !== "geolocation");
    if (!pending.length) return null;
    const rule = result.match.rule;
    return {
      stage: result.stage.key,
      ruleName: rule.ruleName || rule.name || "Unnamed rule",
      host,
      prompt: `Is ${host} any of these?`,
      groups: pending.map(item => ({
        field: item.field,
        noun: (QUESTION_FIELDS[item.field] || { noun: "value" }).noun,
        options: item.ids.map(id => ({ id: String(id), label: valueLabel(item.field, id, lookups), hint: listPreview(item.field, id, lookups) })),
      })),
    };
  }

  // Merge an answer (the ids the user ticked) into the request's facts. Every
  // option offered and not ticked is recorded as ruled out.
  function answer(facts, question, pickedIds) {
    const next = JSON.parse(JSON.stringify(facts || {}));
    for (const group of question.groups) {
      const picked = new Set((pickedIds || []).filter(item => item && typeof item === "object"
        ? item.field === group.field
        : question.groups.length === 1).map(item => String(item && typeof item === "object" ? item.id : item)));
      const entry = next[group.field] = next[group.field] || { yes: [], no: [] };
      const offered = new Set(group.options.map(option => String(option.id)));
      entry.yes = (entry.yes || []).filter(id => !offered.has(String(id)));
      entry.no = (entry.no || []).filter(id => !offered.has(String(id)));
      for (const id of offered) (picked.has(id) ? entry.yes : entry.no).push(id);
      if (entry.yes.length) delete entry.all;
    }
    return next;
  }

  root.TrafficPath = {
    CONNECTIONS, SOURCES, STAGES, PROTOCOLS,
    parseDestination, resolveScope, groupsContaining, buildRequest, planStages,
    evaluate, questionFor, threatQuestion, answer, factsFromLookup, actionLabel, webProfile, catalogLabel, valueLabel,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.TrafficPath;
})(typeof window !== "undefined" ? window : globalThis);
