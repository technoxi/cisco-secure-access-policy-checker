// =============================================================================
// matcher.js — Policy Match Tester engine
// Exported via window.Matcher so popup.js and popup-sections.js can use it
// without a module bundler (plain <script> tags in popup.html).
//
// This file has NO browser-extension API calls.  Pure data-in / data-out.
//
// SCHEMA HISTORY (real Umbrella API captures):
//
//   Capture 1 — 2026-07-04 — default rules only:
//     attributeName: "umbrella.source.all"      attributeOperator: "="  attributeValue: true
//     attributeName: "umbrella.destination.all" attributeOperator: "="  attributeValue: true
//
//   Capture 2 — 2026-07-04 — first real custom rule:
//     attributeName: "umbrella.source.all"                 attributeOperator: "="   attributeValue: true
//     attributeName: "umbrella.destination.composite_inline_ip"
//                                                          attributeOperator: "IN"
//                                                          attributeValue: [
//                                                            { ip: ["93.184.216.0/24"],
//                                                              port: ["0-65535"],
//                                                              protocol: "ANY" }
//                                                          ]
//
//   Key learnings from capture 2:
//     - attributeValue can be an ARRAY OF OBJECTS (not just scalars).
//     - attributeOperator can be "IN" (not just "=").
//     - composite_inline_ip objects have { ip: string[], port: string[], protocol: string }.
//     - port/protocol are present but NOT matched by the tester (no UI fields for them yet).
//       They are included in matchedConditions output for visibility only.
//
// CONFIRMED attributeNames (from real captures):
//   umbrella.source.all                           (op "=",         value true)                   → source catch-all
//   umbrella.destination.all                      (op "=",         value true)                   → dest catch-all
//   umbrella.destination.composite_inline_ip      (op "IN",        value [{ip,port,protocol}])   → CIDR list for destination
//   umbrella.source.identity_ids                  (op "INTERSECT", value [numericIDs])           → source identity
//   umbrella.destination.application_category_ids (op "INTERSECT", value [numericIDs])           → destination app category
//   umbrella.destination.category_ids              (op "INTERSECT", value [numericIDs])           → destination app category
//                                                          (alias of application_category_ids — confirmed org 8416432 uses
//                                                           this shorter field name for the same concept; org 8415583 uses
//                                                           the longer one. attributeName is NOT universal across tenants.)
//   umbrella.destination.application_ids          (op "INTERSECT", value [numericIDs])           → destination app OR protocol
//                                                          (CONFIRMED via live API payload: this is the ONLY field used for
//                                                           both "Internet Application" and "Application Protocol" selections
//                                                           — there is NO separate umbrella.destination.protocol_ids field.
//                                                           e.g. ID 6500000 = "3com-amp3", a protocol, appearing under this
//                                                           same attributeName. Resolve against apps-lookup.json first, then
//                                                           protocols-lookup.json — see summarizeConditions() in
//                                                           popup-sections.js.)
//
// All other patterns are still UNCONFIRMED and marked with TODO.
// =============================================================================

(function (global) {
  "use strict";

  // ---------------------------------------------------------------------------
  // CIDR / IP helpers  (schema-independent)
  // ---------------------------------------------------------------------------

  function cidrMatch(ip, cidr) {
    return window.IPAddress.contains(ip, cidr);
  }

  /**
   * Return true if `value` matches `pattern`.
   * Pattern may be: plain FQDN / URL substring, leading-wildcard "*.example.com", or "*".
   * Matching is case-insensitive.
   *
   * @param {string} pattern
   * @param {string} value
   * @returns {boolean}
   */
  function fqdnMatch(pattern, value) {
    if (!pattern || !value) return false;
    const p = pattern.toLowerCase().trim();
    const v = value.toLowerCase().trim();
    if (p === "*") return true;
    if (window.IPAddress.parseCidr(p) || window.IPAddress.parseCidr(v)) return cidrMatch(v, p);
    if (p.startsWith("*.")) {
      const suffix = p.slice(2);
      return v === suffix || v.endsWith("." + suffix);
    }
    // A domain entry covers itself and its subdomains: "fo" matches "x.fo",
    // never "foodremit.com". An entry with a path ("reddit.com/r/cisco")
    // only covers that path, which a host alone cannot confirm.
    if (p.includes("/")) return v.includes("/") && (v === p || v.startsWith(p.replace(/\/+$/, "") + "/"));
    return v === p || v.endsWith("." + p);
  }

  // ===========================================================================
  // REAL SCHEMA — primary matching path (Umbrella API ruleConditions[])
  // ===========================================================================

  /**
   * Map a ruleCondition attributeName to a logical dimension:
   *   "source" | "destination" | "identity" | "app" | "unknown"
   *
   * Uses the Umbrella dotted-namespace convention (umbrella.<dim>.<type>).
   * Exact matches for confirmed names are listed first; prefix matches follow.
   *
   * @param {string} attributeName
   * @returns {"source"|"destination"|"identity"|"app"|"unknown"}
   */
  function conditionDimension(attributeName) {
    const an = attributeName.toLowerCase();

    // --- CONFIRMED from real captures ---
    if (an === "umbrella.source.all")                      return "source";
    if (an === "umbrella.destination.all")                 return "destination";
    if (an === "umbrella.destination.composite_inline_ip") return "destination"; // capture 2
    if (an === "umbrella.source.composite_inline_ip")      return "source";      // prepped

    // --- Fallbacks for identity/app (no exact pattern known yet) ---
    // umbrella.source.identity_ids / umbrella.source.identity_type_ids are
    // HAR-verified source conditions, not a separate "identity" dimension.
    // They match against testInput.sourceIdentityIds / sourceIdentityTypeIds.
    if (an.startsWith("umbrella.source.") && an.includes("networkobject")) return "source";
    if (an === "umbrella.source.identity_ids") return "source";
    if (an === "umbrella.source.identity_type_ids") return "source";
    // HAR-confirmed destination attributes are evaluated in the destination
    // bucket, even where their names contain application/category.
    if (
      an === "umbrella.destination.application_ids" ||
      an === "umbrella.destination.application_category_ids" ||
      an === "umbrella.destination.category_ids" ||
      an === "umbrella.destination.application_list_ids" ||
      an === "umbrella.destination.category_list_ids" ||
      an === "umbrella.destination.appriskprofileid" ||
      an === "umbrella.destination.private_resource_types"
    ) return "destination";
    // Remaining identity attributes (non-source-scoped) stay as "identity"
    if (an.includes("identity_type")) return "identity";
    if (an.includes("identity")) return "identity";

    if (an.includes("application_list")) return "destination";
    if (an.includes("category_list")) return "destination";
    if (an.includes("appriskprofile")) return "destination";

    // "category" covers both confirmed field-name variants for content/app
    // category matching: "application_category_ids" (org 8415583) and the
    // shorter "category_ids" (org 8416432) — same INTERSECT semantics, just
    // a different attributeName string per tenant.
    if (an.includes("application") || an.includes("app") || an.includes("protocol") || an.includes("category")) return "app";

    // CONFIRMED via live API payload (org 8176184): all destination-scoped —
    // same classification service-worker.js's _conditionDimension() already
    // uses for checkConflicts/checkShadowing/checkInspection (kept in sync
    // here rather than shared, since that file's a service worker context
    // and this one's a plain IIFE loaded into the popup — see that file's
    // comment for why they're duplicated instead of shared).
    //   - destination_list_ids / "geo"-style conditions (Geoblocking2, etc.)
    //   - private_resource_ids / private_resource_group_ids — which private
    //     app/resource group a Private Access rule's destination targets
    //   - networkObjectIds / serviceObjectGroupIds — named network/service
    //     object references (api.sse.cisco.com/policies/v2/objects/*)
    // None of these have a corresponding Policy Tester input field yet (no
    // "which private resource" or "which network object" field exists), so
    // classifying them correctly here stops them being silently miscounted
    // as "unknown" — but a rule with a real (non-catch-all) condition of
    // these types still can't be MATCHED through the tester today, only
    // correctly reported as such instead of via the wrong code path.
    if (
      an.includes("destination_list") ||
      an.includes("geo") ||
      an.includes("private_resource") ||
      an.includes("networkobject") ||
      an.includes("serviceobject")
    ) return "destination";

    console.warn("[matcher] Unrecognised attributeName pattern:", attributeName);
    return "unknown";
  }

  // ---------------------------------------------------------------------------
  // Composite value extractors — handle the object-array shape from capture 2
  // ---------------------------------------------------------------------------

  /**
   * Extract all IP/CIDR strings from a composite_inline_ip attributeValue array.
   *
   * Shape confirmed from capture 2:
   *   attributeValue: [{ ip: ["93.184.216.0/24"], port: ["0-65535"], protocol: "ANY" }]
   *
   * Each element's `ip` field is an array of CIDR strings.  We flatten all of
   * them into a single list so the caller can iterate and cidrMatch/fqdnMatch.
   *
   * Also returns a port/protocol summary string for display in matchedConditions
   * (not used for matching — the tester has no port/protocol input fields yet).
   *
   * @param {object[]} compositeArr  — attributeValue array of composite objects
   * @returns {{ cidrs: string[], portProtocolNote: string }}
   */
  function extractCompositeInlineIp(compositeArr) {
    const items = [];
    const notes = [];

    for (const entry of compositeArr) {
      if (typeof entry === "string") {
        if (entry.trim()) {
          items.push({ cidr: entry.trim(), ports: ["any"], protocol: "any" });
        }
        continue;
      }
      if (typeof entry === "object" && entry !== null) {
        let ports = ["any"];
        if (Array.isArray(entry.port) && entry.port.length > 0) {
          ports = entry.port.map(String);
        } else if (typeof entry.port === "string") {
          ports = [entry.port];
        } else if (typeof entry.port === "number") {
          ports = [String(entry.port)];
        }

        let entryCidrs = [];
        if (Array.isArray(entry.ip)) {
          for (const cidr of entry.ip) {
            if (typeof cidr === "string" && cidr.trim()) {
              entryCidrs.push(cidr.trim());
            }
          }
        } else if (typeof entry.ip === "string") {
          entryCidrs.push(entry.ip.trim());
        }
        
        const proto = typeof entry.protocol === "string" && entry.protocol.trim()
          ? entry.protocol.trim()
          : "any";
        for (const cidr of entryCidrs) {
          items.push({ cidr, ports, protocol: proto });
        }
        
        // port/protocol: include in note but do NOT use for matching
        const portStr     = Array.isArray(entry.port)    ? entry.port.join(", ")    : (entry.port    || "any");
        const protoStr    = typeof entry.protocol === "string" ? entry.protocol    : "any";
        notes.push(`port ${portStr}, protocol ${protoStr}`);
      }
    }

    return {
      items,
      cidrs: items.map(i => i.cidr),
      portProtocolNote: notes.length ? notes.join("; ") : "any port, any protocol",
    };
  }

  // ---------------------------------------------------------------------------
  // matchConditionValue — operator-aware, shape-aware condition evaluator
  // ---------------------------------------------------------------------------

  /**
   * Return whether a single ruleCondition matches the user-supplied testValue
   * for the given logical dimension.
   *
   * Branches first on attributeOperator ("=" / "IN" / unconfirmed others),
   * then on the shape of attributeValue (boolean / string / composite object array).
   *
   * Confirmed operators from real captures:
   *   "="  — equality / catch-all (attributeValue: true or a scalar)
   *   "IN" — membership (attributeValue: array of composite objects or scalars)
   *
   * @param {object} cond       — { attributeName, attributeOperator, attributeValue }
   * @param {string} dimension  — "source" | "destination" | "identity" | "app"
   * @param {string} testValue  — user-supplied field (non-empty, pre-trimmed)
   * @returns {{ matched: boolean, note: string }}
   */
  function portMatch(testPort, portRanges) {
    if (!testPort) return true;
    if (!portRanges || portRanges.length === 0) return true;
    const tp = parseInt(testPort, 10);
    if (isNaN(tp)) return false;

    for (const rangeStr of portRanges) {
      const r = String(rangeStr).toLowerCase().trim();
      if (r === "any" || r === "*") return true;
      if (r.includes("-")) {
        const [start, end] = r.split("-");
        const s = parseInt(start, 10);
        const e = parseInt(end, 10);
        if (!isNaN(s) && !isNaN(e) && tp >= s && tp <= e) return true;
      } else {
        const p = parseInt(r, 10);
        if (!isNaN(p) && p === tp) return true;
      }
    }
    return false;
  }

  // L4 protocol comparison for composite_inline_ip. Accepts the protocol names
  // the dashboard emits ("TCP"/"UDP"/"ANY") or a numeric IP protocol value.
  // A blank/`any` expected value never narrows the match.
  function protocolMatch(testProtocol, ruleProtocol) {
    const want = String(testProtocol || "").trim().toLowerCase();
    if (!want || want === "any") return true;
    const have = String(ruleProtocol || "").trim().toLowerCase();
    if (!have || have === "any" || have === "*") return true;
    if (have === want) return true;
    const NUMERIC = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58, esp: 50 };
    const wantNum = NUMERIC[want] !== undefined ? NUMERIC[want] : parseInt(want, 10);
    const haveNum = NUMERIC[have] !== undefined ? NUMERIC[have] : parseInt(have, 10);
    return !isNaN(wantNum) && !isNaN(haveNum) && wantNum === haveNum;
  }

  // ---------------------------------------------------------------------------
  // resolveDisplayValue — turns a raw identity/category/application ID into a
  // human-readable name for "MATCHED BECAUSE" reasoning text, the same
  // resolution popup-sections.js's summarizeConditions() already does for the
  // Rules tab's "What will usually match" section. Source/destination values
  // (IPs, CIDRs, FQDNs) are already human-readable and pass through
  // untouched — only identity/app-dimension numeric IDs need resolving.
  //
  // `lookups` is optional and defaults to {} so existing callers (and any
  // unit tests) that don't pass one keep working — falls back to showing the
  // raw ID in that case, same as an unresolved ID would.
  // ---------------------------------------------------------------------------
  function resolveDisplayValue(dimension, attributeName, id, lookups) {
    lookups = lookups || {};
    const an = (attributeName || "").toLowerCase();

    if (dimension === "identity") {
      const name = lookups.identities && lookups.identities[String(id)];
      const typeLabel = lookups.identityTypes && lookups.identityTypes[String(id)];
      return name || typeLabel || "Identity";
    }

    if (dimension === "app") {
      if (an.includes("category")) {
        const entry = lookups.categories && lookups.categories[id];
        if (entry) return typeof entry === "object" ? (entry.name || entry.label || "Content Category") : entry;
        return "Content Category";
      }
      if (an.includes("application")) {
        if (lookups.apps && lookups.apps[id] !== undefined) return lookups.apps[id];
        if (lookups.protocols && lookups.protocols[id] !== undefined) return lookups.protocols[id];
        return "Internet Application";
      }
    }

    if (dimension === "source" && an === "umbrella.source.identity_ids") {
      return (lookups.identities && lookups.identities[String(id)]) || `Identity ${id}`;
    }

    if (dimension === "destination" && an.includes("application_ids")) {
      return (lookups.apps && lookups.apps[String(id)]) ||
        (lookups.protocols && lookups.protocols[String(id)]) ||
        (lookups.enterpriseApplications && lookups.enterpriseApplications[String(id)]) ||
        `Application ${id}`;
    }

    if (dimension === "destination" && an.includes("application_category")) {
      return (lookups.applicationCategories && lookups.applicationCategories[String(id)]) || `Application Category ${id}`;
    }

    if (dimension === "destination" && an.endsWith(".category_ids")) {
      const entry = lookups.categories && lookups.categories[String(id)];
      return typeof entry === "object" ? (entry.name || entry.label || `Content Category ${id}`) : (entry || `Content Category ${id}`);
    }

    if (dimension === "destination" && an.includes("geolocations")) {
      return (lookups.geolocations && lookups.geolocations[String(id)]) || String(id);
    }

    if (dimension === "destination" && an.includes("appriskprofile")) {
      return (lookups.appRiskProfiles && lookups.appRiskProfiles[String(id)]) || `App Risk Profile ${id}`;
    }

    if (dimension === "destination" && an.includes("private_resource")) {
      const name = (lookups.privateResources && lookups.privateResources[String(id)]) || (lookups.objects && lookups.objects[String(id)]);
      return name || "Private Resource";
    }

    if (dimension === "destination" && an.includes("destination_list")) {
      const name = lookups.destinationLists && lookups.destinationLists[String(id)];
      return name || "Destination List";
    }

    if (dimension === "destination" && (an.includes("network_object") || an.includes("networkobject"))) {
      const name = lookups.networkObjects && lookups.networkObjects[String(id)];
      return name || "Network Object";
    }

    if (dimension === "destination" && (an.includes("service_object") || an.includes("serviceobject"))) {
      const name = lookups.serviceObjectGroups && lookups.serviceObjectGroups[String(id)];
      return name || "Service Object Group";
    }

    if (dimension === "destination" && an.includes("application_list")) {
      const name = lookups.applicationLists && lookups.applicationLists[String(id)];
      return name || "Application List";
    }

    if (dimension === "destination" && an.includes("category_list")) {
      const name = lookups.categoryLists && lookups.categoryLists[String(id)];
      return name || "Category List";
    }

    // IPs/CIDRs/FQDNs: return as-is if string containing domain/IP characters
    if (typeof id === "string" && (id.includes(".") || id.includes(":") || id.includes("/") || /[a-z]/i.test(id))) {
      return id;
    }

    return "Configured Destination";
  }

  // Same-field Cisco chips are OR: one or more IPs/FQDNs in From/To.
  function parseAddressList(value) {
    if (value == null || value === "") return [];
    if (Array.isArray(value)) {
      return value.flatMap(item => parseAddressList(item));
    }
    return String(value).split(/[\n,]+/).map(part => part.trim()).filter(Boolean);
  }

  function parseAddressToken(raw) {
    const value = String(raw || "").trim();
    if (!value) return { ipCidr: "", port: null };
    const portMatch = value.match(/^\[([0-9a-f:.]+)\]:(\d+)$/i);
    if (portMatch && window.IPAddress.parse(portMatch[1])?.version === 6) return { ipCidr: portMatch[1], port: portMatch[2] };
    if (window.IPAddress.parseCidr(value)?.version === 6) return { ipCidr: value, port: null };
    const trailingPort = value.match(/:(\d+)$/);
    if (!trailingPort) return { ipCidr: value, port: null };
    return {
      ipCidr: value.substring(0, value.length - trailingPort[0].length),
      port: trailingPort[1],
    };
  }

  function matchAnyAddress(raw, fallbackPort, matchOne) {
    const tokens = parseAddressList(raw);
    if (!tokens.length) return matchOne("", fallbackPort);
    let last = null;
    for (const token of tokens) {
      const parsed = parseAddressToken(token);
      last = matchOne(parsed.ipCidr, parsed.port || fallbackPort);
      if (last && last.matched) return last;
    }
    return last;
  }

  // Nested picker checkboxes can send one id or an array of ids per field.
  function flattenSelectedIds(values) {
    const out = [];
    (Array.isArray(values) ? values : [values]).forEach(value => {
      if (value === null || value === undefined || value === "") return;
      if (Array.isArray(value)) {
        flattenSelectedIds(value).forEach(id => out.push(id));
        return;
      }
      out.push(value);
    });
    return out;
  }

  // Rule conditions store content categories as bit positions, not category
  // IDs (umbrella.destination.category_ids [10] is Gambling, bit 10, not
  // categoryId 10). lookups.categories is data/categories-lookup.json, keyed
  // by bit position. Verified against Activity Search: a rule on [10] blocked
  // Gambling domains. Every other condition's values are used as-is.
  function conditionValues(cond, lookups) {
    const values = Array.isArray(cond.attributeValue) ? cond.attributeValue : [cond.attributeValue];
    if (!String(cond.attributeName || "").toLowerCase().endsWith(".category_ids")) return values;
    const bits = (lookups && lookups.categories) || {};
    return values.map(value => {
      const entry = bits[String(value)];
      return entry && typeof entry === "object" && entry.categoryId !== undefined ? entry.categoryId : value;
    });
  }

  function matchCatalogCondition(cond, testInput, lookups) {
    const an = (cond.attributeName || "").toLowerCase();
    const values = conditionValues(cond, lookups);
    let selected;
    if (an === "umbrella.source.identity_type_ids") {
      const typeMap = lookups.sourceIdentityTypeIds || {};
      const fromCatalogs = flattenSelectedIds([
        testInput.sourceIdentityIds,
        testInput.sourceUserId, testInput.sourceGsuiteUserId, testInput.sourceGsuiteOuId,
        testInput.sourceRoamingId, testInput.sourceGroupId,
        testInput.sourceEndpointDeviceId, testInput.sourceNetworkId, testInput.sourceSiteId,
        testInput.sourceSecurityGroupTagId, testInput.sourceCatalystSdwanId,
        testInput.sourceMobileDeviceId, testInput.sourceChromebookId,
        testInput.sourceZtnaClientId, testInput.sourceTunnelGroupId,
        testInput.sourceBranchId, testInput.sourceNetworkDeviceId,
      ]).map(id => id && typeMap[String(id)]).filter(Boolean);
      selected = fromCatalogs.concat(flattenSelectedIds(testInput.identityTypeIds));
    } else {
      selected =
        an === "umbrella.source.identity_ids" ? flattenSelectedIds([
          testInput.sourceIdentityIds,
          testInput.sourceUserId, testInput.sourceGsuiteUserId, testInput.sourceGsuiteOuId,
          testInput.sourceRoamingId, testInput.sourceGroupId,
          testInput.sourceEndpointDeviceId, testInput.sourceNetworkId, testInput.sourceSiteId,
          testInput.sourceSecurityGroupTagId, testInput.sourceCatalystSdwanId,
          testInput.sourceTunnelGroupId, testInput.sourceBranchId, testInput.sourceMobileDeviceId,
          testInput.sourceChromebookId, testInput.sourceZtnaClientId,
          testInput.sourceNetworkDeviceId
        ]) :
        an.includes("private_resource_group") ? flattenSelectedIds(testInput.privateResourceGroupId) :
        an.includes("private_resource_types") ? flattenSelectedIds(testInput.privateResourceType) :
        an.includes("private_resource") ? flattenSelectedIds(testInput.privateResourceId) :
        an.includes("destination_list") ? flattenSelectedIds(testInput.destinationListId) :
        an.includes("networkobjectgroup") ? flattenSelectedIds(an.startsWith("umbrella.source.") ? testInput.sourceNetworkObjectGroupId : testInput.networkObjectGroupId) :
        an.includes("networkobject") ? flattenSelectedIds(an.startsWith("umbrella.source.") ? testInput.sourceNetworkObjectId : testInput.networkObjectId) :
        an.includes("serviceobjectgroup") ? flattenSelectedIds(testInput.serviceObjectGroupId) :
        an.includes("serviceobject") ? flattenSelectedIds(testInput.serviceObjectId) :
        an.includes("application_list") ? flattenSelectedIds(testInput.applicationListId) :
        an.includes("category_list") ? flattenSelectedIds(testInput.categoryListId) :
        an.includes("application_category") ? flattenSelectedIds(testInput.applicationCategoryId) :
        an.endsWith(".category_ids") ? flattenSelectedIds(testInput.contentCategoryId) :
        an.includes("application_ids") ? flattenSelectedIds([
          testInput.applicationId, testInput.protocolId, testInput.enterpriseApplicationId
        ]) :
        an.includes("appriskprofile") ? flattenSelectedIds(testInput.appRiskProfileId) :
        an.includes("geolocations") ? flattenSelectedIds(testInput.geolocation) : null;
    }
    if (!selected) return null;
    const hit = selected.filter(v => v !== null && v !== undefined && v !== "")
      .find(v => values.some(candidate => String(candidate) === String(v)));
    if (hit === undefined) return { matched: false, note: `No selected value matches ${cond.attributeName}` };
    return { matched: true, note: `${cond.attributeName}: '${hit}' matched`, display: String(hit) };
  }

  function memberKindForAttribute(an) {
    if (an.includes("private_resource_group")) return "privateResourceGroups";
    if (an.includes("private_resource_types")) return null;
    if (an.includes("private_resource")) return "privateResources";
    if (an.includes("destination_list")) return "destinationLists";
    if (an.includes("networkobjectgroup")) return "networkObjectGroups";
    if (an.includes("networkobject")) return "networkObjects";
    if (an.includes("serviceobjectgroup")) return "serviceObjectGroups";
    if (an.includes("serviceobject")) return "serviceObjects";
    if (an.includes("application_list")) return "applicationLists";
    if (an.includes("category_list")) return "categoryLists";
    return null;
  }

  function collectMemberAddresses(kind, id, memberMaps, seen) {
    const out = [];
    if (!kind || id === undefined || id === null) return out;
    const key = `${kind}:${id}`;
    if (seen.has(key)) return out;
    seen.add(key);
    const entry = memberMaps && memberMaps[kind] && memberMaps[kind][String(id)];
    for (const member of (entry && entry.members) || []) {
      if (member && member.value) out.push(String(member.value));
      if (member && member.id !== undefined && member.kind && memberMaps[member.kind]) {
        collectMemberAddresses(member.kind, member.id, memberMaps, seen).forEach((v) => out.push(v));
      }
    }
    return out;
  }

  function addressMatchesToken(testValue, token) {
    if (!testValue || !token) return false;
    return cidrMatch(testValue, token) || fqdnMatch(token, testValue);
  }

  function matchNestedMemberAddress(cond, testValue, lookups) {
    const an = (cond.attributeName || "").toLowerCase();
    const kind = memberKindForAttribute(an);
    if (!kind || !testValue) return null;
    const memberMaps = lookups.memberMaps || {};
    const values = Array.isArray(cond.attributeValue) ? cond.attributeValue : [cond.attributeValue];
    for (const id of values) {
      if (id === undefined || id === null || id === "*" || String(id).toLowerCase() === "any") continue;
      const tokens = collectMemberAddresses(kind, id, memberMaps, new Set());
      const hit = tokens.find((token) => addressMatchesToken(testValue, token));
      if (hit) {
        return {
          matched: true,
          note: `${cond.attributeName}: '${testValue}' matched member ${hit}`,
          display: hit,
        };
      }
    }
    return null;
  }

  function matchConditionValue(cond, dimension, testValue, testPort = null, lookups = {}, testInput = {}) {
    const { attributeName, attributeOperator, attributeValue } = cond;
    const tvObj = typeof testValue === "object" && testValue !== null ? testValue : null;
    const tv  = tvObj ? "" : String(testValue).trim();
    const an  = attributeName.toLowerCase();
    const op  = (attributeOperator || "=").toUpperCase();

    // HAR-confirmed source and destination catalogs match by exact ID/code.
    // Do this before legacy generic operator paths, which are intentionally
    // not allowed to infer catalog membership from free-form text.
    const catalogResult = matchCatalogCondition(cond, testInput, lookups);
    if (catalogResult && catalogResult.matched) return catalogResult;
    const nestedAddress = matchNestedMemberAddress(cond, tv, lookups);
    if (nestedAddress) return nestedAddress;
    if (catalogResult) return catalogResult;

    // Extract all destination object IDs from testInput
    const { privateResourceId = null, destinationListId = null, networkObjectId = null,
            serviceObjectGroupId = null, applicationListId = null, categoryListId = null } = testInput;

    // =========================================================================
    // OPERATOR: "="
    // =========================================================================
    if (op === "=") {
      // -----------------------------------------------------------------------
      // CONFIRMED — catch-all: attributeValue === true AND name ends with ".all"
      // Both confirmed cases:  umbrella.source.all = true
      //                        umbrella.destination.all = true
      // -----------------------------------------------------------------------
      if (attributeValue === true && an.endsWith(".all")) {
        return {
          matched: true,
          note: `${dimension}: catch-all condition (${attributeName} = true)`,
          display: "Any",
        };
      }

      // -----------------------------------------------------------------------
      // CONFIRMED — "=" with a plain string value
      // -----------------------------------------------------------------------
      if (typeof attributeValue === "string") {
        const av = attributeValue.trim();
        if (dimension === "source" || dimension === "destination") {
          if (cidrMatch(tv, av)) {
            return { matched: true, note: `${dimension}: CIDR '${av}' contains ${tv} (${attributeName})`, display: av };
          }
          if (dimension === "destination" && fqdnMatch(av, tv)) {
            return { matched: true, note: `${dimension}: FQDN '${av}' matched '${tv}' (${attributeName})`, display: av };
          }
        }
        if (dimension === "identity" || dimension === "app") {
          const checkTv = tvObj ? String(tvObj.categoryId || tvObj.applicationId || tvObj.protocolId || "") : tv;
          if (av === checkTv) {
            return { matched: true, note: `${dimension}: exact value '${av}' matched (${attributeName})`, display: av };
          }
        }
      }

      // "=" with numeric ID for destination object types
      if (dimension === "destination" && (typeof attributeValue === "number" || typeof attributeValue === "string")) {
        const avNum = parseInt(attributeValue, 10);
        if (!isNaN(avNum)) {
          if (an.includes("destination_list") && destinationListId !== null) {
            if (parseInt(destinationListId, 10) === avNum) {
              return { matched: true, note: `${dimension}: destination list ${destinationListId} matched ${attributeName}`, display: resolveDisplayValue(dimension, attributeName, avNum, lookups) };
            }
          }
          if ((an.includes("network_object") || an.includes("networkobject")) && networkObjectId !== null) {
            if (parseInt(networkObjectId, 10) === avNum) {
              return { matched: true, note: `${dimension}: network object ${networkObjectId} matched ${attributeName}`, display: resolveDisplayValue(dimension, attributeName, avNum, lookups) };
            }
          }
          if ((an.includes("service_object") || an.includes("serviceobject")) && serviceObjectGroupId !== null) {
            if (parseInt(serviceObjectGroupId, 10) === avNum) {
              return { matched: true, note: `${dimension}: service object group ${serviceObjectGroupId} matched ${attributeName}`, display: resolveDisplayValue(dimension, attributeName, avNum, lookups) };
            }
          }
          if (an.includes("application_list") && applicationListId !== null) {
            if (parseInt(applicationListId, 10) === avNum) {
              return { matched: true, note: `${dimension}: application list ${applicationListId} matched ${attributeName}`, display: resolveDisplayValue(dimension, attributeName, avNum, lookups) };
            }
          }
          if (an.includes("category_list") && categoryListId !== null) {
            if (parseInt(categoryListId, 10) === avNum) {
              return { matched: true, note: `${dimension}: category list ${categoryListId} matched ${attributeName}`, display: resolveDisplayValue(dimension, attributeName, avNum, lookups) };
            }
          }
        }
      }

      // TODO: unconfirmed — "=" with numeric or boolean non-catch-all attributeValue
      return {
        matched: false,
        note: `${dimension}: no match for '${tv}' against '${JSON.stringify(attributeValue)}' (${attributeName} = ...)`,
      };
    }

    // =========================================================================
    // OPERATOR: "IN"
    // =========================================================================
    if (op === "IN") {

      if (!Array.isArray(attributeValue)) {
        // Malformed — "IN" should always have an array value
        console.warn("[matcher] 'IN' operator with non-array attributeValue:", cond);
        return {
          matched: false,
          note: `${dimension}: malformed IN condition (non-array value) for ${attributeName}`,
        };
      }

      // -----------------------------------------------------------------------
      // CONFIRMED — composite_inline_ip:
      //   attributeName: "umbrella.destination.composite_inline_ip"
      //   attributeOperator: "IN"
      //   attributeValue: [{ ip: string[], port: string[], protocol: string }]
      //
      // Extract all CIDR strings from the ip[] arrays and cidrMatch/fqdnMatch.
      // Port and protocol are noted for visibility but NOT used for matching.
      // -----------------------------------------------------------------------
      if (an.includes("composite_inline_ip")) {
        const { items, cidrs, portProtocolNote } = extractCompositeInlineIp(attributeValue);

        if (items.length === 0) {
          return {
            matched: false,
            note: `${dimension}: composite_inline_ip contained no IP/CIDR entries (${attributeName})`,
          };
        }

        const testProtocol = dimension === "destination"
          ? (testInput && testInput.destinationProtocol)
          : (testInput && testInput.sourceProtocol);

        let matchResult;
        for (const item of items) {
          const cidr = item.cidr;
          const ipMatched = cidrMatch(tv, cidr) || (dimension === "destination" && fqdnMatch(cidr, tv));
          
          if (ipMatched) {
            if (!protocolMatch(testProtocol, item.protocol)) {
               matchResult = {
                 matched: false,
                 note: `${dimension}: IP matched ${cidr} but protocol ${testProtocol} excluded by allowed protocol ${item.protocol} (${portProtocolNote})`,
               };
               continue;
            }
            if (portMatch(testPort, item.ports)) {
               matchResult = {
                 matched: true,
                 note: `${dimension}: matched CIDR/FQDN ${cidr} and port ${testPort || 'any'} (${portProtocolNote}) [${attributeName}]`,
                 display: `${cidr} — port ${testPort || 'any'}`,
               };
               break;
            } else {
               // IP matched but port didn't. Keep looping in case another rule item matches both.
               matchResult = {
                 matched: false,
                 note: `${dimension}: IP matched ${cidr} but port ${testPort} excluded by allowed ports [${item.ports.join(",")}] (${portProtocolNote})`
               };
            }
          }
        }

        if (!matchResult) {
          matchResult = {
            matched: false,
            note: `${dimension}: IP '${tv}' did not match any of [${cidrs.join(", ")}] (${portProtocolNote}) [${attributeName}]`,
          };
        }
        return matchResult;
      }

      // -----------------------------------------------------------------------
      // private_resource_ids / private_resource_group_ids, IF the real API
      // turns out to use "IN" rather than "INTERSECT" for this field — the
      // operator actually used here was never confirmed against a live
      // capture (unlike composite_inline_ip/identity_ids/application_ids,
      // which all were), so this branch is a defensive duplicate of the
      // INTERSECT-side handling below rather than a guess at which one is
      // "the" real operator. Whichever it turns out to be, privateResourceId
      // (from the Test Policy form's Private Resource / Resource Group
      // dropdown — see buildTesterPanel() in popup-sections.js) gets tested
      // as a plain membership check against attributeValue, same as the
      // INTERSECT path.
      // -----------------------------------------------------------------------
      if (dimension === "destination" && an.includes("private_resource")) {
        if (privateResourceId === null || privateResourceId === undefined || privateResourceId === "") {
          return {
            matched: false,
            note: `${dimension}: no Private Resource/Group selected for ${attributeName}`,
          };
        }
        const wanted = String(privateResourceId);
        const hit = attributeValue.find((entry) => String(entry) === wanted);
        if (hit !== undefined) {
          return {
            matched: true,
            note: `${dimension}: '${resolveDisplayValue(dimension, attributeName, hit, lookups)}' matched ${attributeName}`,
            display: resolveDisplayValue(dimension, attributeName, hit, lookups),
          };
        }
        return {
          matched: false,
          note: `${dimension}: selected resource not found IN ${attributeName}`,
        };
      }

      if (an.includes("network_object") || an.includes("networkobject")) {
        const wanted = String(networkObjectId !== null && networkObjectId !== undefined ? networkObjectId : "");
        if (wanted && attributeValue.some((e) => String(e) === wanted)) {
          return {
            matched: true,
            note: `${dimension}: network object ${wanted} matched ${attributeName}`,
            display: resolveDisplayValue(dimension, attributeName, wanted, lookups),
          };
        }
      }

      if (an.includes("service_object") || an.includes("serviceobject")) {
        const wanted = String(serviceObjectGroupId !== null && serviceObjectGroupId !== undefined ? serviceObjectGroupId : "");
        if (wanted && attributeValue.some((e) => String(e) === wanted)) {
          return {
            matched: true,
            note: `${dimension}: service object group ${wanted} matched ${attributeName}`,
            display: resolveDisplayValue(dimension, attributeName, wanted, lookups),
          };
        }
      }

      if (an.includes("application_list")) {
        const wanted = String(applicationListId !== null && applicationListId !== undefined ? applicationListId : "");
        if (wanted && attributeValue.some((e) => String(e) === wanted)) {
          return {
            matched: true,
            note: `${dimension}: application list ${wanted} matched ${attributeName}`,
            display: resolveDisplayValue(dimension, attributeName, wanted, lookups),
          };
        }
      }

      if (an.includes("category_list")) {
        const wanted = String(categoryListId !== null && categoryListId !== undefined ? categoryListId : "");
        if (wanted && attributeValue.some((e) => String(e) === wanted)) {
          return {
            matched: true,
            note: `${dimension}: category list ${wanted} matched ${attributeName}`,
            display: resolveDisplayValue(dimension, attributeName, wanted, lookups),
          };
        }
      }

      // -----------------------------------------------------------------------
      // "IN" with a plain array of scalars (string/number)
      // -----------------------------------------------------------------------
      const matchedEntry = attributeValue.find((entry) => {
        if (typeof entry !== "string" && typeof entry !== "number") return false;
        const ev = String(entry).toLowerCase().trim();
        const tvL = tv.toLowerCase().trim();
        if (dimension === "source" || dimension === "destination") {
          return cidrMatch(tv, String(entry)) || fqdnMatch(String(entry), tv) || ev === tvL;
        }
        return ev === tvL;
      });

      // Identity/app dimensions carry numeric IDs (group tags, branch IDs,
      // category/app IDs) that mean nothing to a human on their own — resolve
      // them to names for the "MATCHED BECAUSE" text. Source/destination
      // values are already human-readable IPs/CIDRs/FQDNs, left as-is.
      const displayValue = (v) =>
        dimension === "identity" || dimension === "app"
          ? resolveDisplayValue(dimension, attributeName, v, lookups)
          : v;

      if (matchedEntry !== undefined) {
        const shown = attributeValue.slice(0, 5).map(displayValue);
        return {
          matched: true,
          note: `${dimension}: value IN [${shown.join(", ")}${attributeValue.length > 5 ? "…" : ""}] matched '${tv}'`,
          display: displayValue(matchedEntry),
        };
      }

      const shown = attributeValue.slice(0, 3).map(displayValue);
      return {
        matched: false,
        note: `${dimension}: '${tv}' not found IN [${shown.join(", ")}${attributeValue.length > 3 ? "…" : ""}] (${attributeName})`,
      };
    }

    // =========================================================================
    // OPERATOR: "INTERSECT"
    // =========================================================================
    if (op === "INTERSECT") {
      if (!Array.isArray(attributeValue)) {
        console.warn("[matcher] 'INTERSECT' operator with non-array attributeValue:", cond);
        return {
          matched: false,
          note: `${dimension}: malformed INTERSECT condition (non-array value) for ${attributeName}`,
        };
      }

      // Parse testInput as comma-separated numeric IDs
      let testIds = [];
      if (an.includes("identity_type")) {
        const typeVal = (testInput && testInput.identityTypeId !== undefined && testInput.identityTypeId !== null)
          ? testInput.identityTypeId
          : (tvObj && tvObj.identityTypeId);
        flattenSelectedIds([typeVal, testInput && testInput.identityTypeIds]).forEach(id => {
          const parsed = parseInt(id, 10);
          if (!Number.isNaN(parsed)) testIds.push(parsed);
        });
      } else if (an.includes("private_resource")) {
        const prVal = (testInput && testInput.privateResourceId) !== undefined ? testInput.privateResourceId : privateResourceId;
        if (prVal !== null && prVal !== undefined && prVal !== "") {
          testIds.push(parseInt(prVal, 10));
        }
      } else if (an.includes("destination_list")) {
        const dlVal = (testInput && testInput.destinationListId) !== undefined ? testInput.destinationListId : destinationListId;
        if (dlVal !== null && dlVal !== undefined && dlVal !== "") {
          testIds.push(parseInt(dlVal, 10));
        }
      } else if (an.includes("network_object") || an.includes("networkobject")) {
        const netObjVal = (testInput && testInput.networkObjectId) !== undefined ? testInput.networkObjectId : networkObjectId;
        if (netObjVal !== null && netObjVal !== undefined && netObjVal !== "") {
          testIds.push(parseInt(netObjVal, 10));
        }
      } else if (an.includes("service_object") || an.includes("serviceobject")) {
        const svcObjVal = (testInput && testInput.serviceObjectGroupId) !== undefined ? testInput.serviceObjectGroupId : serviceObjectGroupId;
        if (svcObjVal !== null && svcObjVal !== undefined && svcObjVal !== "") {
          testIds.push(parseInt(svcObjVal, 10));
        }
      } else if (an.includes("application_list")) {
        const appListVal = (testInput && testInput.applicationListId) !== undefined ? testInput.applicationListId : applicationListId;
        if (appListVal !== null && appListVal !== undefined && appListVal !== "") {
          testIds.push(parseInt(appListVal, 10));
        }
      } else if (an.includes("category_list")) {
        const catListVal = (testInput && testInput.categoryListId) !== undefined ? testInput.categoryListId : categoryListId;
        if (catListVal !== null && catListVal !== undefined && catListVal !== "") {
          testIds.push(parseInt(catListVal, 10));
        }
      } else if (an.includes("category")) {
        const catVal = (tvObj && tvObj.categoryId) !== undefined ? tvObj.categoryId : (testInput && testInput.categoryId);
        if (catVal !== null && catVal !== undefined && catVal !== "") {
          testIds.push(parseInt(catVal, 10));
        }
      } else if (an.includes("application")) {
        const appVal = (tvObj && tvObj.applicationId) !== undefined ? tvObj.applicationId : (testInput && testInput.applicationId);
        const protoVal = (tvObj && tvObj.protocolId) !== undefined ? tvObj.protocolId : (testInput && testInput.protocolId);
        if (appVal !== null && appVal !== undefined && appVal !== "") testIds.push(parseInt(appVal, 10));
        if (protoVal !== null && protoVal !== undefined && protoVal !== "") testIds.push(parseInt(protoVal, 10));
      } else if (tvObj) {
        if (tvObj.applicationId) testIds.push(parseInt(tvObj.applicationId, 10));
        if (tvObj.protocolId) testIds.push(parseInt(tvObj.protocolId, 10));
      } else {
        testIds = tv.split(",").map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n));
      }
      
      if (testIds.length === 0) {
        // No recognised attribute type — cannot evaluate this INTERSECT
        // condition without a matching tester input field.
        return {
          matched: false,
          note: `${dimension}: INTERSECT condition for '${attributeName}' has no corresponding tester input — cannot evaluate`,
        };
      }

      // Match if there is ANY overlap
      const overlap = testIds.find((id) => attributeValue.includes(id));

      if (overlap !== undefined) {
        return {
          matched: true,
          note: `${dimension}: '${resolveDisplayValue(dimension, attributeName, overlap, lookups)}' matched ${attributeName}`,
          display: resolveDisplayValue(dimension, attributeName, overlap, lookups),
        };
      }

      const shownIds = attributeValue.slice(0, 5).map((id) => resolveDisplayValue(dimension, attributeName, id, lookups));
      return {
        matched: false,
        note: `${dimension}: no overlap with ${attributeName} [${shownIds.join(", ")}${attributeValue.length > 5 ? "…" : ""}]`,
      };
    }

    // =========================================================================
    // UNCONFIRMED OPERATORS
    // =========================================================================

    // TODO: unconfirmed operator "NOT IN" — invert the IN logic above
    // TODO: unconfirmed operator "CONTAINS" — substring / prefix match
    // TODO: unconfirmed operator "BETWEEN" — range match (e.g. port ranges)
    // TODO: unconfirmed operator "!=" — negation of "="

    console.warn("[matcher] Unrecognised attributeOperator:", op, "on condition:", cond);
    return {
      matched: false,
      note: `${dimension}: unrecognised operator '${op}' — cannot evaluate (${attributeName})`,
    };
  }

  // ---------------------------------------------------------------------------
  // matchesRule — REAL SCHEMA version
  // ---------------------------------------------------------------------------

  /**
   * Returns whether `rule` matches `testInput` and which conditions matched.
   *
   * Real API fields used:
   *   rule.ruleIsEnabled  — boolean (fallback: rule.enabled for mock)
   *   rule.ruleConditions — array of { attributeName, attributeOperator, attributeValue }
   *   rule.ruleAction     — string  (display only here)
   *   rule.rulePriority   — number  (used by matchPolicy for sort)
   *
   * Blank-field semantics:
   *   A blank tester field matches ONLY if the rule's own condition for that
   *   dimension is unconstrained (i.e. empty or a `.all` catch-all).
   *   If a rule has a specific constraint on a dimension, a blank test field
   *   for that dimension will FAIL the rule match.
   *   At least one field must be filled (enforced upstream in the form).
   *
   * AND semantics within a dimension:
   *   ALL conditions for a given dimension must pass.
   *   If a dimension has zero conditions it is treated as unrestricted.
   *
   * @param {object} rule
   * @param {{ source: string, identity: string, app: string, destination: string, privateResourceId?: string|number|null }} testInput
   * @param {{ identities?: object, categories?: object, apps?: object, protocols?: object }} [lookups]
   *   Optional — when provided, identity/app-dimension IDs in the returned
   *   matchedConditions notes are resolved to names instead of shown raw
   *   (see resolveDisplayValue() above). Omitting it just falls back to raw
   *   IDs, same as an unresolved ID would show.
   * @returns {{ matched: boolean, matchedConditions: string[] }}
   */
  function matchesRule(rule, testInput, lookups = {}) {
    const isEnabled = rule.ruleIsEnabled !== undefined ? rule.ruleIsEnabled : rule.enabled;
    if (isEnabled === false) {
      return {
        matched: false,
        matchedConditions: ["rule is disabled — skipped"],
        matchFields: null,
      };
    }

    // Cisco's rules are explicitly scoped to Internet or Private Access.
    // A public FQDN is an Internet destination, so allow a domain-only test to
    // fall through to the Internet default without forcing a redundant scope
    // selection. IP/CIDR inputs and empty destination tests stay ambiguous and
    // must still specify scope.
    const ruleScope = rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess) || null;
    const scopeText = String(flattenSelectedIds(testInput.destinationScope)[0] || testInput.destinationScope || "").trim().toLowerCase();
    // getValue() returns the catalog key after a menu click, but normalize the
    // visible labels too so a typed "Internet" / "Private Access" does not
    // turn a valid default-rule test into a false no-match.
    const explicitScope =
      scopeText === "internet" || scopeText === "public internet" || scopeText === "public_internet"
        ? "public_internet"
        : scopeText === "private access" || scopeText === "private_network"
          ? "private_network"
          : null;
    // A selected private catalog item is inherently Private Access. Cisco's
    // Internet application, category, list, geo, and risk-profile catalogs are
    // inherently Internet traffic, so a user should not have to repeat that
    // fact in Destination Scope. Destination and network lists stay ambiguous.
    const hasPrivateResource = [testInput.privateResourceId, testInput.privateResourceGroupId, testInput.privateResourceType]
      .some(value => flattenSelectedIds(value).length > 0);
    const hasInternetCatalog = [
      testInput.applicationId, testInput.protocolId, testInput.enterpriseApplicationId,
      testInput.applicationListId, testInput.applicationCategoryId, testInput.contentCategoryId,
      testInput.categoryListId, testInput.geolocation, testInput.appRiskProfileId,
    ].some(value => flattenSelectedIds(value).length > 0);
    const destinationValue = String(testInput.destination || "").trim();
    const inferredScope = explicitScope ||
      (hasPrivateResource ? "private_network" : null) ||
      (hasInternetCatalog ? "public_internet" : null) ||
      (destinationValue && !window.IPAddress.parseCidr(destinationValue) && /[a-z]/i.test(destinationValue)
        ? "public_internet"
        : null);
    if (ruleScope && (!inferredScope || ruleScope !== inferredScope)) {
      return { matched: false, matchedConditions: [`Scope: rule requires ${ruleScope}; test resolved to ${inferredScope || "none"}`], matchFields: null };
    }

    const { 
      source = "", 
      sourcePort = null,
      sourceUserId = null,
      identityTypeIds = null,
      sourceGsuiteUserId = null,
      sourceGsuiteOuId = null,
      sourceRoamingId = null,
      sourceGroupId = null,
      sourceEndpointDeviceId = null,
      sourceNetworkId = null,
      sourceSiteId = null,
      sourceSecurityGroupTagId = null,
      sourceCatalystSdwanId = null,
      sourceTunnelGroupId = null,
      sourceNetworkObjectId = null,
      sourceNetworkObjectGroupId = null,
      sourceMobileDeviceId = null,
      sourceChromebookId = null,
      sourceZtnaClientId = null,
      sourceNetworkDeviceId = null,
      destinationScope = null,
      privateResourceId = null,
      privateResourceGroupId = null,
      destinationListId = null,
      networkObjectId = null,
      networkObjectGroupId = null,
      serviceObjectId = null,
      serviceObjectGroupId = null,
      applicationId = null,
      protocolId = null,
      enterpriseApplicationId = null,
      applicationListId = null,
      applicationCategoryId = null,
      contentCategoryId = null,
      categoryListId = null,
      geolocation = null,
      appRiskProfileId = null,
      privateResourceType = null,
      destination = "",
      destinationPort = null,
      destinationProtocol = "",
    } = testInput;
    const hasSelected = (value) => flattenSelectedIds(value).length > 0;
    const hasSource = source.trim() !== "" || [
      testInput.sourceIdentityIds, testInput.sourceBranchId,
      sourceUserId, identityTypeIds, sourceGsuiteUserId, sourceGsuiteOuId, sourceRoamingId, sourceGroupId, sourceEndpointDeviceId,
      sourceNetworkId, sourceSiteId, sourceSecurityGroupTagId,
      sourceCatalystSdwanId, sourceTunnelGroupId,
      sourceNetworkObjectId, sourceNetworkObjectGroupId,
      sourceMobileDeviceId, sourceChromebookId, sourceZtnaClientId,
      sourceNetworkDeviceId,
    ].some(hasSelected);
    const hasDestination = destination.trim() !== "" || [
      destinationScope, privateResourceId, privateResourceGroupId,
      destinationListId, networkObjectId, networkObjectGroupId, serviceObjectId, serviceObjectGroupId, applicationId,
      protocolId, enterpriseApplicationId, applicationListId, applicationCategoryId, contentCategoryId, categoryListId, geolocation,
      appRiskProfileId, privateResourceType, destinationProtocol,
    ].some(hasSelected);

    const matchedConditions = [];
    // Structured, presentation-ready version of the same info as
    // matchedConditions (which stays as freeform text for backward compat —
    // content-script.js's hover popover still consumes it directly). This is
    // what the redesigned clean field-grid result panel renders instead of
    // parsing/guessing structure out of the "→ dimension: ..." text lines.
    const matchFields = {
      source:      { label: "Source",      constrained: false, display: "Any" },
      identity:    { label: "Identity",    constrained: false, display: "Any" },
      destination: { label: "Destination", constrained: false, display: "Any" },
      app:         { label: "App / Category / Protocol", constrained: false, display: "Any" },
    };

    // Partition ruleConditions into dimension buckets
    const conditions = rule.ruleConditions || rule.conditions || [];
    const byDim = { source: [], destination: [], identity: [], app: [], unknown: [] };
    for (const cond of conditions) {
      const dim = conditionDimension(cond.attributeName);
      byDim[dim].push(cond);
    }

    // Helper: returns true if the dimension array contains any non-catch-all condition
    function hasSpecificConditions(conds) {
      return conds.some((c) => !(c.attributeValue === true && c.attributeName.toLowerCase().endsWith(".all")));
    }

    const NO_MATCH = { matched: false, matchedConditions: [], matchFields: null };

    // ------------------------------------------------------------------
    // Source dimension
    // ------------------------------------------------------------------
    if (hasSource) {
      const srcConds = byDim.source;
      if (srcConds.length === 0) {
        matchedConditions.push("source: no source conditions on rule (unrestricted)");
      } else {
        const displays = [];
        for (const cond of srcConds) {
          const result = matchAnyAddress(source, sourcePort, (addr, port) => (
            matchConditionValue(cond, "source", addr, port, lookups, testInput)
          ));
          if (!result.matched) return {
            matched: false,
            matchedConditions: [...matchedConditions, result.note || `Source condition ${cond.attributeName} did not match`],
            matchFields: null,
          };
          matchedConditions.push(result.note);
          if (result.display) displays.push(result.display);
        }
        if (displays.length) {
          matchFields.source = { label: "Source", constrained: true, display: displays.join(", ") };
        }
      }
    } else {
      if (hasSpecificConditions(byDim.source)) return {
        matched: false,
        matchedConditions: ["Source is blank, but this rule requires a specific source identity or address"],
        matchFields: null,
      };
      matchedConditions.push("source: not constrained (field blank, rule has no specific conditions)");
    }

    // ------------------------------------------------------------------
    // Destination dimension
    // ------------------------------------------------------------------
    if (hasDestination) {
      const dstConds = byDim.destination;
      if (dstConds.length === 0) {
        matchedConditions.push("destination: no destination conditions on rule (unrestricted)");
      } else {
        const displays = [];
        const evaluate = (cond) => cond.__pscUnknownDestination
          ? { matched: true, note: `Destination classification is unresolved (${cond.attributeName})` }
          : matchAnyAddress(destination, destinationPort, (addr, port) => (
            matchConditionValue(cond, "destination", addr, port, lookups, testInput)
          ));
        // A rule's destinations are alternatives: the request matches if it
        // hits any one of them. Verified against Activity Search: one rule
        // with a category and an application list blocked both a
        // category-only domain and an app from the list; a rule with
        // resource groups, "all private apps" (private_resource_types) and a
        // CIDR matched via its resource group.
        const qualifiers = [];
        const isCatchAll = (cond) => cond.attributeValue === true && String(cond.attributeName || "").toLowerCase().endsWith(".all");
        let alternatives = dstConds.filter((cond) => !qualifiers.includes(cond));
        // "Any destination" only stands when it is the rule's only destination.
        if (alternatives.some((cond) => !isCatchAll(cond))) alternatives = alternatives.filter((cond) => !isCatchAll(cond));
        for (const cond of qualifiers) {
          const result = evaluate(cond);
          if (!result.matched) return {
            matched: false,
            matchedConditions: [...matchedConditions, result.note || `Destination condition ${cond.attributeName} did not match`],
            matchFields: null,
          };
          matchedConditions.push(result.note);
        }
        if (alternatives.length) {
          const misses = [];
          let hit = null;
          for (const cond of alternatives) {
            const result = evaluate(cond);
            if (result.matched) { hit = result; break; }
            misses.push(result.note || `Destination condition ${cond.attributeName} did not match`);
          }
          if (!hit) return { matched: false, matchedConditions: [...matchedConditions, ...misses], matchFields: null };
          matchedConditions.push(hit.note);
          if (hit.display) displays.push(hit.display);
        }
        if (displays.length) {
          matchFields.destination = { label: "Destination", constrained: true, display: displays.join(", ") };
        }
      }
    } else {
      if (hasSpecificConditions(byDim.destination)) return {
        matched: false,
        matchedConditions: ["Destination is blank, but this rule requires a specific destination, catalog object, or category"],
        matchFields: null,
      };
      matchedConditions.push("destination: not constrained (field blank, rule has no specific conditions)");
    }

    // This tester deliberately supports only the HAR-observed source and
    // destination condition set. Any other specific condition is unevaluable
    // and must fail closed rather than being ignored.
    if (hasSpecificConditions(byDim.identity) || hasSpecificConditions(byDim.app)) return {
      matched: false,
      matchedConditions: ["This rule has a specific unsupported identity/app condition and was not matched"],
      matchFields: null,
    };

    if (byDim.unknown && byDim.unknown.length > 0) {
      if (hasSpecificConditions(byDim.unknown)) return {
        matched: false,
        matchedConditions: ["This rule has a specific unsupported condition and was not matched"],
        matchFields: null,
      };
    }

    return { matched: true, matchedConditions, matchFields };
  }

  // ---------------------------------------------------------------------------
  // matchPolicy — first-match-wins walk sorted by rulePriority ascending
  // ---------------------------------------------------------------------------

  /**
   * Sort rules by rulePriority ascending (fallback: rule.order for mock).
   * Lower number = evaluated first (standard firewall priority convention).
   *
   * Default/catch-all rules (ruleIsDefault / is_default) always sort LAST
   * regardless of their rulePriority value — they're only meant to apply
   * when no custom rule matched, which is a policy invariant independent of
   * whatever priority number the API assigns them (unconfirmed whether that
   * number is even meaningful for default rules).
   *
   * Returns the first rule that matches testInput, or null.
   *
   * @param {object[]} rules
   * @param {{ source: string, identity: string, app: string, destination: string, privateResourceId?: string|number|null }} testInput
   * @param {{ identities?: object, categories?: object, apps?: object, protocols?: object }} [lookups]
   *   Optional — forwarded to matchesRule() so matchedConditions notes show
   *   resolved names instead of raw IDs. See resolveDisplayValue() above.
   * @returns {{ rule: object, matchedConditions: string[], matchFields: object } | null}
   */
  function needsTransportContext(rule, testInput, lookups) {
    if (!testInput.trafficStage || rule.ruleIsEnabled === false || rule.enabled === false) return false;
    const conditions = rule.ruleConditions || rule.conditions || [];
    const specific = conditions.filter(cond => {
      if (String(cond.attributeName || "").toLowerCase() !== "umbrella.destination.composite_inline_ip") return false;
      const items = extractCompositeInlineIp(Array.isArray(cond.attributeValue) ? cond.attributeValue : []).items;
      return items.some(item =>
        (!testInput.destinationPort && item.ports.some(port => !["any", "*", "0-65535"].includes(String(port).toLowerCase()))) ||
        (!testInput.destinationProtocol && !["any", "*"].includes(String(item.protocol).toLowerCase())));
    });
    if (!specific.length) return false;
    const other = conditions.filter(cond => !specific.includes(cond));
    if (!matchesRule({ ...rule, ruleConditions: other, conditions: other }, testInput, lookups).matched) return false;
    return specific.some(cond => extractCompositeInlineIp(cond.attributeValue).items.some(item =>
      cidrMatch(testInput.destination, item.cidr) || fqdnMatch(item.cidr, testInput.destination)));
  }

  // Destination facts a domain/IP alone does not reveal (its content
  // category, application, geolocation, ...). The traffic-path checker asks
  // the user about the exact values a higher-priority rule depends on:
  // confirmed values go in the normal testInput field, rejected ones in
  // testInput.ruledOut[field]. A value in neither set is still unknown.
  function classificationField(attributeName) {
    const name = String(attributeName || "").toLowerCase();
    return name.includes("application_list") ? "applicationListId" :
      name.includes("application_ids") ? "applicationId" :
      name.includes("application_category") ? "applicationCategoryId" :
      name.endsWith(".category_ids") ? "contentCategoryId" :
      name.includes("category_list") ? "categoryListId" :
      name.includes("appriskprofile") ? "appRiskProfileId" :
      name.startsWith("umbrella.destination.") && name.includes("geolocations") ? "geolocation" : null;
  }

  function confirmedValues(testInput, field) {
    const values = field === "applicationId"
      ? [testInput.applicationId, testInput.protocolId, testInput.enterpriseApplicationId]
      : testInput[field];
    return flattenSelectedIds(values).map(String);
  }

  function unresolvedClassification(rule, testInput, lookups) {
    const stage = testInput.trafficStage;
    if (stage !== "dns" && stage !== "web" && stage !== "firewall") return [];
    const ruledOut = testInput.ruledOut || {};
    const pending = [];
    // At the firewall, a destination list with URL paths cannot be checked
    // until the request is inspected. Plain domain entries are decided right
    // away (Activity Search: lists with "reddit.com/r/cisco" or
    // "bazaar.abuse.ch/browse" were logged provisionally on unrelated IPs; a
    // list of "fo" and "aq" never was).
    const firewallIp = stage === "firewall" && window.IPAddress.parse(String(testInput.destination || ""));
    const memberMaps = (lookups && lookups.memberMaps) || {};
    for (const cond of rule.ruleConditions || rule.conditions || []) {
      let field = classificationField(cond.attributeName);
      if (!field && firewallIp && /destination_list/i.test(cond.attributeName || "")) {
        const lists = (Array.isArray(cond.attributeValue) ? cond.attributeValue : [cond.attributeValue]).map(String);
        const hasPaths = lists.some(id => ((memberMaps.destinationLists || {})[id] || { members: [] }).members
          .some(member => /^[^/]+\/./.test(String(member.value || "")) && !window.IPAddress.parseCidr(String(member.value || ""))));
        if (hasPaths) field = "destinationListId";
      }
      if (!field) continue;
      const values = conditionValues(cond, lookups).map(String);
      const yes = confirmedValues(testInput, field);
      if (values.some(value => yes.includes(value))) continue;
      // The confirmed list is complete (e.g. from Cisco Investigate):
      // anything not on it is a no, so nothing is left to ask.
      if (flattenSelectedIds(testInput.ruledOutAll).includes(field)) continue;
      const no = flattenSelectedIds(ruledOut[field]).map(String);
      const open = values.filter(value => !no.includes(value));
      if (open.length) pending.push({ attributeName: cond.attributeName, field, ids: open, cond });
    }
    return pending;
  }

  function needsDestinationClassification(rule, testInput, lookups) {
    if (rule.ruleIsEnabled === false || rule.enabled === false) return null;
    const pending = unresolvedClassification(rule, testInput, lookups);
    if (!pending.length) return null;
    // Would the rule match if the unknown conditions turned out true? They
    // stand in as "any destination" (destinations are alternatives).
    const unknown = pending.map(item => item.cond);
    const conditions = (rule.ruleConditions || rule.conditions || []).map(cond => unknown.includes(cond)
      ? { ...cond, __pscUnknownDestination: true }
      : cond);
    if (!matchesRule({ ...rule, ruleConditions: conditions, conditions }, testInput, lookups).matched) return null;
    return pending.map(({ attributeName, field, ids }) => ({ attributeName, field, ids }));
  }

  function matchPolicy(rules, testInput, lookups = {}) {
    const sorted = [...rules].sort((a, b) => {
      const aDefault = (a.ruleIsDefault !== undefined ? a.ruleIsDefault : a.is_default) === true;
      const bDefault = (b.ruleIsDefault !== undefined ? b.ruleIsDefault : b.is_default) === true;
      if (aDefault !== bDefault) return aDefault ? 1 : -1;

      const pa = a.rulePriority !== undefined ? a.rulePriority : a.order;
      const pb = b.rulePriority !== undefined ? b.rulePriority : b.order;
      return pa - pb;
    });

    // Cisco's "Warn Isolate" card covers both isolate and warn rule actions
    // observed in org 8176184 (isolate + one warn). Allow/block stay exact.
    function actionsMatch(preferred, actual) {
      if (preferred === actual) return true;
      return preferred === "isolate" && (actual === "isolate" || actual === "warn");
    }

    const preferredAction = String(testInput.preferredAction || "").trim().toLowerCase();
    const rejected = [];
    for (const rule of sorted) {
      const result = matchesRule(rule, testInput, lookups);
      if (needsTransportContext(rule, testInput, lookups)) {
        return {
          indeterminate: true, reason: "A higher-priority rule depends on the traffic port or protocol.",
          rule, pending: [],
        };
      }
      const pending = !result.matched && needsDestinationClassification(rule, testInput, lookups);
      if (pending) {
        return {
          indeterminate: true, reason: "A higher-priority rule depends on what the destination is (category, application, or location).",
          rule, pending,
        };
      }
      if (result.matched) {
        const ruleAction = String(rule.ruleAction || rule.action || "").toLowerCase();
        if (preferredAction && ruleAction && !actionsMatch(preferredAction, ruleAction)) {
          rejected.push({
            ruleId: rule.ruleId !== undefined ? rule.ruleId : rule.id,
            ruleName: rule.ruleName || rule.name || "Unnamed Rule",
            scope: rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess) || null,
            reason: `rule action ${ruleAction} does not match requested ${preferredAction}`,
          });
          continue;
        }
        return { rule, matchedConditions: result.matchedConditions, matchFields: result.matchFields };
      }
      rejected.push({
        ruleId: rule.ruleId !== undefined ? rule.ruleId : rule.id,
        ruleName: rule.ruleName || rule.name || "Unnamed Rule",
        scope: rule.trafficScope || rule.ruleAccess || (rule.raw && rule.raw.ruleAccess) || null,
        reason: (result.matchedConditions || []).join("; ") || "Rule conditions did not match",
      });
    }

    return { noMatch: true, rejected };
  }

  // ---------------------------------------------------------------------------
  // getCleanRules — rules with zero findings across all 6 checks
  // ---------------------------------------------------------------------------

  /**
   * Return rules not referenced by any finding.
   * Uses String() coercion so numeric ruleId 2741542 === string "2741542".
   *
   * @param {object[]} rules
   * @param {object[]} findings
   * @returns {object[]}
   */
  function getCleanRules(rules, findings) {
    const dirtyIds = new Set(findings.map((f) => String(f.ruleId)));
    return rules.filter((r) => {
      const rid = r.ruleId !== undefined ? String(r.ruleId) : String(r.id);
      return !dirtyIds.has(rid);
    });
  }

  // ---------------------------------------------------------------------------
  // getIdentityOptions — unique identity values for the combobox datalist
  // ---------------------------------------------------------------------------

  /**
   * Scan ruleConditions for identity-dimension attributes and collect values.
   * Falls back to rule.sources[] prefix scan for mock schema rules.
   *
   * @param {object[]} rules
   * @returns {string[]}
   */
  function getIdentityOptions(rules) {
    const seen = new Set();
    for (const rule of rules) {
      if (Array.isArray(rule.ruleConditions || rule.conditions)) {
        for (const cond of (rule.ruleConditions || rule.conditions)) {
          if (/^umbrella\.source\.identity(?:_|\.|$)/i.test(cond.attributeName || "")) {
            if (typeof cond.attributeValue === "string" && cond.attributeValue) {
              seen.add(cond.attributeValue);
            }
            if (typeof cond.attributeValue === "number" && cond.attributeValue) {
              seen.add(String(cond.attributeValue));
            }
            if (Array.isArray(cond.attributeValue)) {
              for (const v of cond.attributeValue) {
                if (typeof v === "string" && v) seen.add(v);
                if (typeof v === "number" && v) seen.add(String(v));
              }
            }
          }
        }
        continue;
      }
      // MOCK_SCHEMA_LEGACY fallback
      const mockPrefixes = ["group:", "user:", "network:", "site:"];
      for (const src of rule.sources || []) {
        if (mockPrefixes.some((p) => src.toLowerCase().startsWith(p))) seen.add(src);
      }
    }
    return [...seen].sort();
  }

  // ===========================================================================
  // Public API
  // ===========================================================================
  //
  // The mock-schema matching helpers that used to live here
  // (identityMatch/appMatch/matchSourceEntry/matchDestEntry/matchesRule, all
  // suffixed _LEGACY and exposed only as window.Matcher._legacy.* "for
  // reference during real API integration") were never called by the
  // primary matchesRule()/matchPolicy() path and had no other callers
  // anywhere in the extension — removed now that the real API schema is
  // fully confirmed and implemented above, instead of keeping ~100 lines of
  // provably-dead code around indefinitely.

  global.Matcher = {
    // Low-level helpers (schema-independent)
    cidrMatch,
    fqdnMatch,
    conditionDimension,
    extractCompositeInlineIp,   // exposed for unit testing

    // Primary API — REAL schema
    matchesRule,
    matchPolicy,
    getCleanRules,
    getIdentityOptions,
    collectMemberAddresses,
    memberKindForAttribute,
    classificationField,
  };
})(window);
