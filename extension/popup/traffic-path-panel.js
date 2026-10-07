// =============================================================================
// traffic-path-panel.js — Policy Checker UI (window.TrafficPathPanel).
//
// Connection first; the source fields then narrow to what that connection
// actually exposes; destination last. Results show one row per enforcement
// stage (DNS → Firewall → Web, or Private access) with the matched rule, and
// turn "a higher rule depends on the destination's category" into a
// multiple-choice question instead of a dead end.
// =============================================================================
(function (root) {
  "use strict";

  const DRAFT_KEY = "psc.policyChecker.draft.v2";

  // Static inline icons (constant strings, never user data).
  const ICONS = {
    client: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="5" width="16" height="10.5" rx="1.5"/><path d="M2.5 18.5h19"/></svg>',
    va: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="4" width="16" height="6.5" rx="1.2"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.2"/><path d="M7.5 7.25h.01M7.5 16.75h.01"/></svg>',
    vpn: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10.5" width="14" height="9.5" rx="1.5"/><path d="M8.5 10.5V8a3.5 3.5 0 0 1 7 0v2.5"/></svg>',
    tunnel: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="2.5" y="8.5" width="6" height="7" rx="1.2"/><rect x="15.5" y="8.5" width="6" height="7" rx="1.2"/><path d="M8.5 10.5h7M8.5 13.5h7" stroke-dasharray="1.6 1.6"/></svg>',
    network: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.4 2.3 3.6 5.1 3.6 8.5s-1.2 6.2-3.6 8.5c-2.4-2.3-3.6-5.1-3.6-8.5s1.2-6.2 3.6-8.5z"/></svg>',
    check: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
    block: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M6.5 17.5l11-11"/></svg>',
    warn: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4.5l8.5 15h-17z"/><path d="M12 10v4M12 16.8h.01"/></svg>',
    question: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 16.8h.01"/></svg>',
    reset: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3.5 12a8.5 8.5 0 1 0 2.5-6L3.5 8.5M3.5 3.5v5h5"/></svg>',
  };
  const LAYER_LABELS = { client: ["DNS", "Web"], va: ["DNS"], vpn: ["Firewall", "Web"], network: ["DNS"], tunnel: ["Firewall", "Web"] };
  const SOURCE_NOUNS = {
    roaming: "roaming computers", identity: "users or groups", site: "sites", network: "networks", tunnel: "network tunnels",
    computer: "AD computers", sdwan: "SD-WAN VPNs", sgt: "security group tags", branch: "branches",
  };

  function icon(name, className) {
    const span = node("span", className || "tp-icon");
    span.innerHTML = ICONS[name] || "";
    return span;
  }

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }

  // ---------------------------------------------------------------------------
  // Searchable picker over one or more catalogs
  // ---------------------------------------------------------------------------
  // Catalog labels often look like "Carol Freeman (carol.freeman@corp.org)";
  // show the name first and the detail muted underneath.
  function splitLabel(label) {
    const match = String(label).match(/^(.*\S)\s+\(([^()]+)\)$/);
    return match ? { primary: match[1], secondary: match[2] } : { primary: String(label), secondary: "" };
  }

  // getStatus() → { state: "loading" | "ready", noun: "roaming computers" }
  function createPicker({ id, placeholder, getOptions, getStatus, onChange }) {
    const MAX_VISIBLE = 60;
    const wrap = node("div", "tp-picker");
    const input = node("input", "tp-input tp-picker-input");
    input.id = id;
    input.type = "text";
    input.placeholder = placeholder;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-expanded", "false");
    const clear = node("button", "tp-picker-clear", "×");
    clear.type = "button";
    const sourceNoun = SOURCE_NOUNS[id.replace(/^tp-src-/, "")] || getStatus().noun;
    clear.setAttribute("aria-label", `Clear ${sourceNoun} selection`);
    clear.hidden = true;
    const list = node("ul", "tp-picker-list");
    list.id = `${id}-list`;
    list.setAttribute("role", "listbox");
    list.setAttribute("aria-label", `${sourceNoun} options`);
    list.hidden = true;
    input.setAttribute("aria-controls", list.id);
    wrap.append(input, clear, list);

    let value = "";
    let selectedLabel = "";
    let active = -1;
    let shown = [];

    function setOpen(open) {
      list.hidden = !open;
      input.setAttribute("aria-expanded", String(open));
      if (!open) {
        active = -1;
        input.removeAttribute("aria-activedescendant");
      }
    }
    function render() {
      const query = input.value.trim().toLowerCase();
      const all = getOptions();
      const filtered = query && query !== selectedLabel.toLowerCase()
        ? all.filter(option => option.label.toLowerCase().includes(query))
        : all;
      shown = filtered.slice(0, MAX_VISIBLE);
      if (active >= shown.length) active = -1;
      list.replaceChildren();
      const status = getStatus();
      if (!all.length && status.state === "loading") {
        const loading = node("li", "tp-picker-loading");
        loading.setAttribute("role", "status");
        loading.append(node("span", "tp-spinner"), node("span", "", `Loading ${status.noun}…`));
        list.append(loading);
        for (let i = 0; i < 3; i++) list.append(node("li", "tp-picker-skeleton"));
      } else if (!all.length) {
        list.append(node("li", "tp-picker-empty", `No ${status.noun} in this organization.`));
      } else if (!shown.length) {
        list.append(node("li", "tp-picker-empty", `No ${status.noun} match “${input.value.trim()}”.`));
      }
      shown.forEach((option, index) => {
        const item = node("li", "tp-picker-option");
        item.id = `${id}-opt-${index}`;
        item.setAttribute("role", "option");
        item.setAttribute("aria-selected", String(option.value === value));
        if (index === active) item.classList.add("is-active");
        const parts = splitLabel(option.label);
        const text = node("span", "tp-picker-text");
        text.append(node("span", "tp-picker-label", parts.primary));
        if (parts.secondary) text.append(node("span", "tp-picker-detail", parts.secondary));
        item.append(text);
        if (option.badge) item.append(node("span", "tp-picker-badge", option.badge));
        item.addEventListener("mousedown", event => {
          event.preventDefault();
          choose(option);
        });
        list.append(item);
      });
      if (filtered.length > shown.length) list.append(node("li", "tp-picker-empty", `${filtered.length - shown.length} more — keep typing to narrow`));
      if (active >= 0) input.setAttribute("aria-activedescendant", `${id}-opt-${active}`);
      else input.removeAttribute("aria-activedescendant");
    }
    function choose(option, silent) {
      value = option ? option.value : "";
      selectedLabel = option ? option.label : "";
      input.value = selectedLabel;
      clear.hidden = !value;
      setOpen(false);
      if (!silent) onChange(value);
    }
    function reconcileTypedValue() {
      const text = input.value.trim();
      if (text === selectedLabel) return;
      if (!text && value) { choose(null); return; }
      const exact = getOptions().filter(option => option.label.toLowerCase() === text.toLowerCase());
      if (exact.length === 1) choose(exact[0]);
      else input.value = selectedLabel;
    }
    input.addEventListener("focus", () => { active = -1; render(); setOpen(true); });
    input.addEventListener("input", () => { active = -1; render(); setOpen(true); });
    input.addEventListener("blur", () => { reconcileTypedValue(); setOpen(false); });
    input.addEventListener("keydown", event => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        if (list.hidden) { render(); setOpen(true); }
        if (!shown.length) return;
        active = event.key === "ArrowDown" ? Math.min(shown.length - 1, active + 1) : Math.max(0, active - 1);
        render();
        const current = list.querySelector(".is-active");
        if (current) current.scrollIntoView({ block: "nearest" });
      } else if (event.key === "Enter" && !list.hidden) {
        event.preventDefault();
        if (active < 0 && value && input.value.trim() === selectedLabel) setOpen(false);
        else {
          const pick = shown[active >= 0 ? active : 0];
          if (pick) choose(pick);
        }
      } else if (event.key === "Tab") {
        reconcileTypedValue();
        setOpen(false);
      } else if (event.key === "Escape" && !list.hidden) {
        event.preventDefault();
        setOpen(false);
      }
    });
    clear.addEventListener("mousedown", event => event.preventDefault());
    clear.addEventListener("click", () => { choose(null); input.focus(); });

    return {
      element: wrap,
      input,
      get value() { return value; },
      set(nextValue) {
        const option = getOptions().find(item => item.value === nextValue);
        choose(option || null, true);
      },
      refresh() {
        if (value) {
          const option = getOptions().find(item => item.value === value);
          if (option) {
            const unchanged = input.value === selectedLabel;
            selectedLabel = option.label;
            if (unchanged || document.activeElement !== input) input.value = option.label;
          } else if (getStatus().state === "ready") choose(null);
        }
        if (!list.hidden) render();
      },
    };
  }

  // ---------------------------------------------------------------------------
  // Panel
  // ---------------------------------------------------------------------------
  // options.getPolicy(): { rules, lookups } for Describe mode's agent.
  function createConfirmation(panel) {
    const toast = node("div", "tp-confirmation");
    toast.setAttribute("role", "status");
    toast.setAttribute("aria-live", "polite");
    toast.setAttribute("aria-atomic", "true");
    panel.append(toast);
    let timer = null;
    let lastResult = null;
    function clear(forget = true) {
      clearTimeout(timer);
      timer = null;
      toast.classList.remove("is-visible");
      toast.textContent = "";
      if (forget) lastResult = null;
    }
    function show(status, result) {
      if (result === lastResult) return;
      clear(false);
      lastResult = result;
      if (status !== "allow" && status !== "block") return;
      toast.dataset.status = status;
      toast.textContent = status === "allow" ? "ALLOWED" : "BLOCKED";
      toast.classList.add("is-visible");
      timer = setTimeout(() => {
        toast.classList.remove("is-visible");
        timer = setTimeout(() => { toast.textContent = ""; timer = null; }, 180);
      }, 2000);
    }
    return { show, clear };
  }

  function create(container, catalogs, onRun, onHighlight, options = {}) {
    const model = root.TrafficPath;
    let activeCatalogs = catalogs || {};
    let catalogRevision = JSON.stringify(activeCatalogs);
    let busy = false;
    let connection = "";
    let facts = {};
    let factsFor = "";
    let manualFor = "";
    let lastEvaluation = null;
    let runSeq = 0;

    const panel = node("section", "tp-panel");
    panel.id = "tp-panel";
    const confirmation = createConfirmation(panel);
    const header = node("header", "tp-header");
    header.append(node("p", "tp-subtitle", "Check this path against loaded rules."));
    panel.append(header);
    const reset = node("button", "tp-reset");
    reset.type = "button";
    reset.setAttribute("title", "Reset inputs to defaults");
    reset.append(icon("reset", "tp-reset-icon"), node("span", "tp-reset-text", "Reset"));

    // Policy data status: shown until rules and catalogs are in.
    const dataStatus = node("div", "tp-data-status");
    dataStatus.setAttribute("role", "status");
    dataStatus.hidden = true;
    panel.append(dataStatus);
    let dataState = { rulesCount: null, loading: true, stalled: false, context: "dashboard" };

    const MODE_KEY = "psc.policyChecker.mode.v1";
    const modes = node("div", "tp-modes");
    modes.setAttribute("role", "tablist");
    modes.setAttribute("aria-label", "How to enter the check");
    const modeButtons = {};
    for (const [key, text] of [["form", "Form"], ["describe", "Describe"]]) {
      const button = node("button", "tp-mode", text);
      button.type = "button";
      button.id = `tp-mode-${key}`;
      button.setAttribute("role", "tab");
      button.addEventListener("click", () => setMode(key, true));
      modeButtons[key] = button;
      modes.append(button);
    }
    modes.addEventListener("keydown", event => {
      if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
      const next = mode === "form" ? "describe" : "form";
      setMode(next, true);
      modeButtons[next].focus();
    });
    let mode = "form";
    const describe = root.DescribePanel && root.DescribePanel.create({
      model,
      getCatalogs: () => activeCatalogs,
      isReady: () => !!dataState.rulesCount,
      getPolicy: async () => (options.getPolicy ? options.getPolicy() : { rules: [], lookups: activeCatalogs }),
      clearResults: () => invalidate(),
      showResult(element, status, result) {
        invalidate(false);
        results.append(element);
        confirmation.show(status, result);
      },
      highlight: onHighlight ? (targets, summary) => onHighlight(targets, summary) : null,
    });
    if (describe) {
      describe.element.setAttribute("role", "tabpanel");
      describe.element.setAttribute("aria-labelledby", "tp-mode-describe");
      panel.append(modes, describe.element);
    }

    function setMode(next, userAction) {
      if (!describe) next = "form";
      if (next !== mode) {
        confirmation.clear();
        runSeq++;
        busy = false;
        syncRunButton();
        if (describe) describe.cancel(false);
      }
      mode = next;
      for (const [key, button] of Object.entries(modeButtons)) {
        button.setAttribute("aria-selected", String(key === mode));
        button.tabIndex = key === mode ? 0 : -1;
        button.classList.toggle("is-active", key === mode);
      }
      form.hidden = mode !== "form";
      if (describe) describe.element.hidden = mode !== "describe";
      try { sessionStorage.setItem(MODE_KEY, mode); } catch (_) {}
      if (userAction && mode === "describe") describe.focus();
    }

    const form = node("form", "tp-form");
    form.noValidate = true;

    // 1. Connection -------------------------------------------------------
    const connectionStep = node("fieldset", "tp-step");
    connectionStep.append(stepLegend("1", "Connection"));
    const cards = node("div", "tp-connection-cards");
    const radios = {};
    for (const [key, config] of Object.entries(model.CONNECTIONS)) {
      const label = node("label", "tp-connection");
      const radio = node("input", "tp-connection-radio");
      radio.type = "radio";
      radio.name = "tp-connection";
      radio.value = key;
      radios[key] = radio;
      const body = node("span", "tp-connection-body");
      const top = node("span", "tp-connection-top");
      top.append(icon(key, "tp-connection-icon"), icon("check", "tp-connection-check"));
      const layers = node("span", "tp-connection-layers");
      (LAYER_LABELS[key] || []).forEach(layer => layers.append(node("span", "tp-layer", layer)));
      body.append(top, node("span", "tp-connection-name", config.label), layers);
      label.append(radio, body);
      cards.append(label);
      radio.addEventListener("change", () => setConnection(key, true));
    }
    const connectionHint = node("p", "tp-hint tp-connection-hint", "Choose how the traffic reaches Secure Access.");
    connectionStep.append(cards, connectionHint);

    // 2. Source ------------------------------------------------------------
    const sourceStep = node("fieldset", "tp-step");
    sourceStep.append(stepLegend("2", "Source"));
    const sourceFields = node("div", "tp-source-fields");
    const sourceHint = node("p", "tp-hint", "Add known sources. Missing details can leave a check pending.");
    sourceStep.append(sourceFields, sourceHint);

    const pickers = {};
    const fieldWraps = {};
    function catalogOptions(kind) {
      const source = model.SOURCES[kind];
      const options = [];
      for (const catalogKey of source.catalogs) {
        const items = activeCatalogs[catalogKey] || {};
        const badge = source.catalogs.length > 1 ? (catalogKey === "sourceGroups" ? "Group" : "User") : "";
        for (const id of Object.keys(items)) {
          const label = model.catalogLabel(activeCatalogs, catalogKey, id);
          if (label) options.push({ value: `${catalogKey}:${id}`, label, badge });
        }
      }
      options.sort((a, b) => a.label.localeCompare(b.label));
      if (kind === "roaming" || kind === "identity") {
        options.unshift({ value: `any:${kind}`, label: kind === "roaming" ? "Any roaming computer" : "Any user", badge: "" });
      }
      return options;
    }
    for (const [kind, source] of Object.entries(model.SOURCES)) {
      const field = node("div", `tp-field tp-field-${kind}`);
      const label = node("label", "tp-label", source.label);
      label.htmlFor = `tp-src-${kind}`;
      field.append(label);
      if (kind === "internalIp") {
        const input = node("input", "tp-input");
        input.id = `tp-src-${kind}`;
        input.placeholder = source.placeholder;
        input.autocomplete = "off";
        input.spellcheck = false;
        input.addEventListener("input", changed);
        pickers[kind] = { element: input, input, get value() { return input.value.trim(); }, set(v) { input.value = v || ""; }, refresh() {} };
        field.append(input);
      } else {
        const picker = createPicker({
          id: `tp-src-${kind}`, placeholder: source.placeholder, onChange: changed,
          getOptions: () => catalogOptions(kind),
          getStatus: () => ({
            noun: SOURCE_NOUNS[kind] || "items",
            state: source.catalogs.some(key => !Object.prototype.hasOwnProperty.call(activeCatalogs, key)) && !dataState.stalled ? "loading" : "ready",
          }),
        });
        pickers[kind] = picker;
        picker.input.addEventListener("input", changed);
        field.append(picker.element);
      }
      fieldWraps[kind] = field;
      field.hidden = true;
      sourceFields.append(field);
    }

    // 3. Destination -------------------------------------------------------
    const destinationStep = node("fieldset", "tp-step");
    destinationStep.append(stepLegend("3", "Destination"));
    const destinationLabel = node("label", "tp-label", "Domain, URL, or IP address");
    destinationLabel.htmlFor = "tp-destination";
    const destination = node("input", "tp-input");
    destination.id = "tp-destination";
    destination.placeholder = "example.com · https://example.com/login · 203.0.113.10";
    destination.autocomplete = "off";
    destination.spellcheck = false;
    const transport = node("div", "tp-transport");
    transport.hidden = true;
    const portField = node("div", "tp-field");
    const portLabel = node("label", "tp-label", "Port");
    portLabel.htmlFor = "tp-port";
    const port = node("input", "tp-input");
    port.id = "tp-port";
    port.inputMode = "numeric";
    port.placeholder = "443";
    portField.append(portLabel, port);
    const protocolField = node("div", "tp-field");
    const protocolLabel = node("label", "tp-label", "Protocol");
    protocolLabel.htmlFor = "tp-protocol";
    const protocol = node("select", "tp-input");
    protocol.id = "tp-protocol";
    model.PROTOCOLS.forEach(name => {
      const option = node("option", "", name);
      option.value = name;
      protocol.append(option);
    });
    protocolField.append(protocolLabel, protocol);
    transport.append(portField, protocolField);
    const destinationHint = node("p", "tp-hint");
    destinationStep.append(destinationLabel, destination, transport, destinationHint);

    const error = node("p", "tp-error");
    error.id = "tp-validation-error";
    error.setAttribute("role", "alert");
    const actions = node("div", "tp-actions");
    const run = node("button", "tp-primary", "Check policy");
    run.type = "submit";
    actions.append(reset, run);
    form.append(connectionStep, sourceStep, destinationStep, error, actions);
    form.setAttribute("role", "tabpanel");
    form.setAttribute("aria-labelledby", "tp-mode-form");
    panel.append(form);

    const results = node("section", "tp-results");
    results.setAttribute("aria-live", "polite");
    results.setAttribute("aria-label", "Policy check result");
    panel.append(results);
    container.append(panel);

    function stepLegend(number, text) {
      const legend = node("legend", "tp-step-legend");
      legend.append(node("span", "tp-step-number", number), node("span", "", text));
      return legend;
    }

    // State ----------------------------------------------------------------
    function setConnection(key, userAction) {
      connection = key;
      if (radios[key]) radios[key].checked = true;
      const config = model.CONNECTIONS[key];
      connectionHint.textContent = config ? config.description : "Choose how the traffic reaches Secure Access.";
      for (const [kind, field] of Object.entries(fieldWraps)) field.hidden = !config || !config.sources.includes(kind);
      fieldWraps.internalIp.querySelector("label").textContent = key === "vpn" ? "VPN-assigned client IP (optional)" : model.SOURCES.internalIp.label;
      // Order the visible fields the way the connection lists them.
      if (config) config.sources.forEach(kind => sourceFields.append(fieldWraps[kind]));
      sourceStep.disabled = !config;
      destinationStep.disabled = !config;
      sourceStep.classList.toggle("is-waiting", !config);
      destinationStep.classList.toggle("is-waiting", !config);
      updateDestinationHint();
      if (userAction) changed();
    }

    function updateDestinationHint() {
      const parsed = destination.value.trim() ? model.parseDestination(destination.value) : null;
      const showTransport = !!parsed && !parsed.error && parsed.kind === "ip" && !parsed.fromUrl && connection !== "va" && connection !== "network";
      transport.hidden = !showTransport;
      port.disabled = protocol.value === "ICMP";
      if (!connection) destinationHint.textContent = "";
      else if (connection === "va" || connection === "network") destinationHint.textContent = "This path only carries DNS, so enter the domain being looked up.";
      else if (connection === "vpn") destinationHint.textContent = "Enter an IP address to include the firewall. A domain checks Web (HTTPS).";
      else if (connection === "tunnel") destinationHint.textContent = "Enter an IP address to include the firewall. Branch DNS goes through a VA or registered network; check it with that connection.";
      else destinationHint.textContent = "A domain checks DNS then Web (HTTPS). A URL uses its own port.";
    }

    function currentForm() {
      const sources = {};
      for (const kind of Object.keys(model.SOURCES)) sources[kind] = pickers[kind].value;
      return { connection, sources, destination: destination.value, port: port.value, protocol: protocol.value };
    }

    function persist() {
      try { sessionStorage.setItem(DRAFT_KEY, JSON.stringify(currentForm())); } catch (_) {}
    }

    function invalidate(forgetConfirmation = true) {
      confirmation.clear(forgetConfirmation);
      runSeq++;
      busy = false;
      error.textContent = "";
      for (const input of [...Object.values(radios), ...Object.values(pickers).map(picker => picker.input), destination, port, protocol]) {
        input.removeAttribute("aria-invalid");
        input.removeAttribute("aria-describedby");
      }
      results.replaceChildren();
      lastEvaluation = null;
      syncRunButton();
    }

    function changed() {
      invalidate();
      persist();
    }

    function showValidation(message, draft) {
      error.textContent = message;
      const config = model.CONNECTIONS[draft.connection];
      let inputs;
      if (!config) inputs = Object.values(radios);
      else if (/internal.*IP/i.test(message)) inputs = [pickers.internalIp.input];
      else if (/at least one source/i.test(message)) inputs = config.sources.map(kind => pickers[kind].input);
      else {
        const kind = config.sources.find(kind => message.toLowerCase().includes(model.SOURCES[kind].label.toLowerCase()));
        inputs = kind ? [pickers[kind].input]
          : /^Ports run/.test(message) && !model.parseDestination(draft.destination).error ? [port]
            : [destination];
      }
      for (const input of inputs) {
        input.setAttribute("aria-invalid", "true");
        input.setAttribute("aria-describedby", error.id);
      }
      if (inputs[0]) inputs[0].focus();
    }

    destination.addEventListener("input", () => { updateDestinationHint(); changed(); });
    port.addEventListener("input", changed);
    protocol.addEventListener("change", () => { updateDestinationHint(); changed(); });

    // Run -----------------------------------------------------------------
    form.addEventListener("submit", event => {
      event.preventDefault();
      check();
    });

    async function check() {
      invalidate();
      const seq = runSeq;
      const draft = currentForm();
      const key = `${draft.destination.trim().toLowerCase()}|${draft.port}|${draft.protocol}`;
      if (key !== factsFor) { facts = {}; factsFor = key; }
      const built = model.buildRequest({ ...draft, facts }, activeCatalogs);
      if (built.error) {
        showValidation(built.error, draft);
        return;
      }
      if (!dataState.rulesCount) return;
      busy = true;
      syncRunButton();
      try {
        const evaluation = await onRun(built.request, { autoLookup: manualFor !== factsFor });
        if (seq !== runSeq) return;
        if (evaluation.error) {
          error.textContent = evaluation.error;
          results.replaceChildren();
          return;
        }
        lastEvaluation = { request: built.request, evaluation };
        renderResult(built.request, evaluation);
      } catch (cause) {
        if (seq === runSeq) error.textContent = `Could not check policies: ${cause && cause.message ? cause.message : cause}`;
      } finally {
        if (seq === runSeq) {
          busy = false;
          syncRunButton();
        }
      }
    }

    // Results ---------------------------------------------------------------
    function ruleActionOf(rule) {
      return String(rule.ruleAction || rule.action || "").toLowerCase();
    }
    function ruleTitle(rule) {
      return rule.ruleName || rule.name || "Unnamed rule";
    }
    function rulePriority(rule) {
      const priority = rule.rulePriority !== undefined ? rule.rulePriority : rule.order;
      const isDefault = (rule.ruleIsDefault !== undefined ? rule.ruleIsDefault : rule.is_default) === true;
      return isDefault ? "" : priority !== undefined && priority !== null ? `Priority ${priority}` : "";
    }

    function renderResult(request, evaluation) {
      results.replaceChildren();
      const { outcome, stages, scope, groups } = evaluation;
      confirmation.show(outcome.status, evaluation);
      const hostLabel = request.destination.host;

      const pending = stages.find(result => result.state === "needs-answer");
      const question = pending && model.questionFor(pending, hostLabel, evaluation.lookups || activeCatalogs);
      const pendingReason = pending && (pending.reason || pending.match.reason || outcome.reason || "This rule needs request details that have not been provided.");
      const banner = node("div", `tp-outcome tp-outcome-${outcome.status}`);
      const bannerCopy = node("div", "tp-outcome-copy");
      bannerCopy.append(node("strong", "tp-outcome-title", outcome.title));
      const blockedBy = stages.find(result => result.security && result.stage.key === outcome.stage);
      const summary = blockedBy
        ? `${blockedBy.security.category} · ${blockedBy.security.profile ? `security profile “${blockedBy.security.profile}” on ${ruleTitle(outcome.rule)}` : `DNS security setting “${blockedBy.security.setting}”`}`
        : outcome.reason ? `${outcome.rule ? ruleTitle(outcome.rule) : "Connection path"} · ${outcome.reason}`
        : outcome.rule
        ? `${[ruleTitle(outcome.rule), rulePriority(outcome.rule)].filter(Boolean).join(" · ")}${outcome.unlessFlagged ? " · unless flagged as a threat" : ""}`
        : outcome.status === "pending" ? (question ? "Answer the question below to finish the check." : pendingReason) : "Default rules should always match. Refresh the dashboard data and try again.";
      bannerCopy.append(node("span", "tp-outcome-rule", summary));
      const outcomeIcon = { allow: "check", block: "block", warn: "warn", isolate: "warn", pending: "question", bypassed: "check" }[outcome.status] || "question";
      banner.append(icon(outcomeIcon, "tp-outcome-icon"), bannerCopy);
      const highlightable = outcome.status === "unsupported" ? [] : stages.filter(result => result.state === "matched" && !result.afterBlock && !result.match.rule.security);
      if (highlightable.length) {
        const show = node("button", "tp-secondary", "Show on page");
        show.type = "button";
        show.addEventListener("click", () => onHighlight(highlightTargets(highlightable), summaryFor(request, evaluation)));
        banner.append(show);
      }
      const lookup = evaluation.destinationLookup;
      if (question && lookup && !lookup.ok && lookup.error !== "not a domain" && !Object.keys(facts).length) {
        const until = lookup.retryAt ? new Date(lookup.retryAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "";
        const reason = until
          ? `Cisco Investigate refused the last lookup; retry after ${until}.`
          : lookup.error === "no token" ? "No dashboard authorization is available for the lookup. Refresh the Secure Access dashboard."
            : lookup.error === "timeout" ? "The destination lookup timed out."
              : /^Investigate returned \d+$/.test(lookup.error || "") ? `Cisco Investigate returned ${lookup.error.split(" ").pop()}.`
                : "The destination lookup could not finish.";
        results.append(node("p", "tp-note tp-note-lookup", `${reason} You can answer below instead.`));
      }
      // With a question to answer, the question itself is the headline.
      if (question && outcome.status === "pending") results.append(questionCard(question, pending.match.rule));
      else {
        results.append(banner);
        if (question) results.append(questionCard(question, pending.match.rule));
        else if (pending && request.connection === "vpn" && /VPN-assigned client IP/i.test(pendingReason)) {
          const focusSource = node("button", "tp-secondary", "Enter VPN client IP");
          focusSource.type = "button";
          focusSource.addEventListener("click", () => {
            pickers.internalIp.input.focus();
            pickers.internalIp.input.scrollIntoView({ block: "center" });
          });
          results.append(focusSource);
        }
      }
      const answers = answersStrip(hostLabel, evaluation);
      if (answers) results.append(answers);

      const flow = node("ol", "tp-flow");
      flow.setAttribute("aria-label", "Enforcement stages");
      for (const result of stages) flow.append(stageRow(result));
      results.append(flow);

      const threat = !question && model.threatQuestion(evaluation, hostLabel);
      if (threat) results.append(questionCard(threat, null));

      const details = node("details", "tp-details");
      details.append(node("summary", "", "What was checked"));
      const body = node("dl", "tp-details-body");
      const addRow = (term, value) => { body.append(node("dt", "", term), node("dd", "", value)); };
      addRow("Connection", model.CONNECTIONS[request.connection].label);
      addRow("Identities", request.identities.map(identity => identity.label).join(", "));
      if (groups.length) addRow("Via groups", groups.map(group => group.name).join(", "));
      const dest = request.destination;
      addRow("Destination", `${dest.host}${dest.kind === "ip" && dest.port ? ` · ${dest.protocol} ${dest.port}` : dest.fromUrl ? ` · port ${dest.port}` : ""}`);
      addRow("Scope", scope.scope === "private_network"
        ? `Private Access${scope.resourceNames.length ? ` · ${scope.resourceNames.join(", ")}` : " · internal address"}`
        : "Internet");
      if (dest.kind === "domain" && !dest.fromUrl && stages.some(result => result.stage.key === "web")) addRow("Assumed", "Web request over HTTPS (TCP 443)");
      const labelsFor = key => Object.entries(facts).flatMap(([field, value]) => value[key].map(id => model.valueLabel(field, id, evaluation.lookups || activeCatalogs)));
      const isList = labelsFor("yes");
      const notList = labelsFor("no");
      if (isList.length) addRow("You said it is", isList.join(", "));
      if (notList.length) addRow("You said it isn't", notList.join(", "));
      details.append(body);
      for (const result of stages.filter(item => item.state === "matched")) {
        const reasons = node("div", "tp-reasons");
        reasons.append(node("strong", "", `${result.stage.label}: why ${ruleTitle(result.match.rule)} matched`));
        const list = node("ul", "");
        (result.match.matchedConditions || []).forEach(condition => list.append(node("li", "", readableReason(String(condition), evaluation))));
        reasons.append(list);
        details.append(reasons);
      }
      results.append(details);
      results.classList.remove("tp-enter");
      void results.offsetWidth;
      results.classList.add("tp-enter");
    }

    // Matcher reasons are written for debugging ("umbrella.destination.
    // category_ids: '27' matched"); name the value where we can.
    function readableReason(text, evaluation) {
      const lookups = evaluation.lookups || activeCatalogs;
      if (/^source: catch-all/.test(text)) return "Source: any";
      if (/^destination: catch-all/.test(text)) return "Destination: any";
      if (/^source: not constrained/.test(text)) return "Source: not restricted by this rule";
      const hit = text.match(/^(umbrella\.[a-z_.]+): '([^']+)' matched(?: member (.+))?$/i);
      if (!hit) return text;
      const [, attribute, value, member] = hit;
      const name = attribute.toLowerCase();
      if (name === "umbrella.source.identity_ids") {
        const group = evaluation.groups.find(item => item.id === value);
        if (group) return `Source: group ${group.name}`;
        for (const key of ["sourceUsers", "sourceGroups", "sourceRoaming", "sourceSites", "sourceNetworks", "sourceTunnelGroups"]) {
          const label = model.catalogLabel(lookups, key, value);
          if (label) return `Source: ${label}`;
        }
        return `Source: identity ${value}`;
      }
      if (name === "umbrella.source.identity_type_ids") {
        const typeName = lookups.identityTypeNames && lookups.identityTypeNames[value];
        return `Source: all ${typeName ? (typeof typeName === "string" ? typeName : typeName.name || typeName.label) : `identities of type ${value}`}`;
      }
      const field = root.Matcher && root.Matcher.classificationField(attribute);
      if (field) return `Destination: ${model.valueLabel(field, value, lookups)}`;
      if (member) return `Destination: ${member} (in a list on this rule)`;
      return `Destination: ${value}`;
    }

    function stageRow(result) {
      const row = node("li", `tp-stage tp-stage-${result.state}${result.state === "matched" ? ` tp-stage-${result.action}` : ""}${result.afterBlock ? " tp-stage-after" : ""}`);
      const markerIcon = result.state === "matched"
        ? ({ allow: "check", block: "block", warn: "warn", isolate: "warn" }[result.action] || "question")
        : result.state === "bypassed" ? "check"
        : result.state === "needs-answer" || result.state === "unsupported" ? "question" : null;
      const marker = markerIcon ? icon(markerIcon, "tp-stage-marker") : node("span", "tp-stage-marker");
      row.append(marker, node("span", "tp-stage-name", result.stage.label));
      const body = node("div", "tp-stage-body");
      if (result.state === "matched") {
        const rule = result.match.rule;
        const head = node("div", "tp-stage-head");
        head.append(node("span", `tp-action tp-action-${result.action}`, model.actionLabel(result.action)), node("span", "tp-stage-rule", ruleTitle(rule)));
        body.append(head);
        if (result.security) {
          body.append(node("span", "tp-stage-meta tp-stage-security", result.security.profile
            ? `${result.security.category}: blocked by security profile “${result.security.profile}”, although the rule allows it`
            : `${result.security.category}: blocked by the DNS security setting “${result.security.setting}” before any rule`));
        }
        if (result.provisional) {
          body.append(node("span", "tp-stage-meta", `Allowed while the firewall identifies the application; ${ruleTitle(rule)} (${model.actionLabel(ruleActionOf(rule))}) decides once it knows.`));
        }
        const meta = [rulePriority(rule)];
        if (result.afterBlock) meta.push(`only if the ${result.afterBlock.label} block doesn't apply (e.g. ${result.afterBlock.label} doesn't see this user)`);
        else if (result.conditional) meta.push(`if ${result.conditional.label} lets it through`);
        body.append(node("span", "tp-stage-meta", meta.filter(Boolean).join(" · ")));
        if (result.webProfileId && !result.security) body.append(node("span", "tp-stage-meta", `${result.webProfileName ? `Security profile “${result.webProfileName}”` : "The rule's security profile"} can still block by file type, data loss prevention, or app controls.`));
        if (result.ipsProfileId) body.append(node("span", "tp-stage-meta", "IPS on this rule can still block by signature."));
      } else {
        const text = result.state === "unsupported"
          ? ["Unsupported path", result.reason]
          : result.state === "needs-answer"
            ? [model.questionFor(result, "", activeCatalogs) ? "Waiting on your answer" : "More detail needed", result.match.pending && result.match.pending.length
              ? `Decided by ${ruleTitle(result.match.rule)} (${rulePriority(result.match.rule)}) or a later rule.`
              : result.reason || result.match.reason || `${ruleTitle(result.match.rule)} (${rulePriority(result.match.rule)}) needs more request details.`]
          : result.state === "bypassed" ? ["Bypassed", result.reason || "Bypasses Secure Access via Traffic Steering"]
          : result.state === "no-match" ? ["No rule matched", "No loaded rule covers this stage."]
            : result.state === "not-reached" ? ["Not reached", result.reason]
              : ["Not evaluated", result.reason || ""];
        const head = node("div", "tp-stage-head");
        head.append(node("span", `tp-action tp-action-${result.state}`, text[0]));
        body.append(head, node("span", "tp-stage-meta", text[1]));
      }
      row.append(body);
      return row;
    }

    function questionCard(question, rule) {
      const card = node("form", "tp-question");
      card.setAttribute("aria-labelledby", "tp-question-title");
      const head = node("div", "tp-question-head");
      const title = node("strong", "tp-question-title", question.prompt);
      title.id = "tp-question-title";
      head.append(icon("question", "tp-question-icon"), title);
      card.append(head);
      const why = node("p", "tp-question-why");
      if (question.kind === "threat") {
        why.textContent = "The security settings in this path block these threat categories even when a rule allows the traffic. Pick any Cisco flags it as.";
      } else {
        why.append(node("b", "", ruleTitle(rule)), document.createTextNode(` (${rulePriority(rule)}) comes first and only applies if it's one of these. Pick all that apply.`));
      }
      card.append(why);
      const boxes = [];
      for (const group of question.groups) {
        const set = node("fieldset", "tp-question-group");
        if (question.groups.length > 1) set.append(node("legend", "", group.noun.charAt(0).toUpperCase() + group.noun.slice(1)));
        else set.setAttribute("aria-label", group.noun);
        const chips = node("div", "tp-choice-list");
        for (const option of group.options) {
          const label = node("label", "tp-choice");
          const box = node("input", "tp-choice-box");
          box.type = "checkbox";
          box.value = option.id;
          box.dataset.field = group.field;
          boxes.push(box);
          const copy = node("span", "tp-choice-copy");
          copy.append(node("span", "tp-choice-label", option.label));
          if (option.hint) copy.append(node("span", "tp-choice-hint", option.hint));
          label.append(box, icon("check", "tp-choice-check"), copy);
          chips.append(label);
        }
        set.append(chips);
        card.append(set);
      }
      const actions = node("div", "tp-question-actions");
      const submit = node("button", "tp-primary", "None of these");
      submit.type = "submit";
      const hint = node("span", "tp-question-hint", question.kind === "threat" ? "Not flagged? Leave everything unticked." : "Leave everything unticked if none apply.");
      const sync = () => {
        const count = boxes.filter(box => box.checked).length;
        submit.textContent = count ? `Continue with ${count} selected` : "None of these";
        hint.hidden = count > 0;
      };
      boxes.forEach(box => box.addEventListener("change", sync));
      actions.append(submit, hint);
      card.append(actions);
      card.addEventListener("submit", event => {
        event.preventDefault();
        const picked = boxes.filter(box => box.checked).map(box => ({ field: box.dataset.field, id: box.value }));
        facts = model.answer(facts, question, picked);
        check();
      });
      return card;
    }

    // What Cisco Investigate says the destination is (so nothing is asked),
    // or what the user told us, with a way to change it.
    function answersStrip(hostLabel, evaluation) {
      const lookups = evaluation.lookups || activeCatalogs;
      const found = evaluation.destinationLookup;
      if (found && found.ok && !Object.keys(facts).length) {
        const strip = node("div", "tp-answers");
        strip.append(node("span", "tp-answers-lead", `Cisco Investigate: ${hostLabel} is`));
        const list = node("span", "tp-answers-list");
        const threatNames = [...new Set([
          ...found.securityBits.map(bit => lookups.securityCategories && lookups.securityCategories[bit] && lookups.securityCategories[bit].name),
          ...(found.securityNames || []),
        ].filter(Boolean))];
        const names = [
          ...threatNames,
          ...(found.app ? [found.app.name] : []),
          ...found.contentBits.map(bit => lookups.categories && lookups.categories[bit] && lookups.categories[bit].name),
        ].filter(Boolean);
        if (!names.length) names.push("uncategorized");
        const threats = new Set(threatNames);
        names.forEach(name => {
          const chip = node("span", `tp-answer ${threats.has(name) ? "is-threat" : "is-yes"}`, name);
          list.append(chip);
        });
        const change = node("button", "tp-link", "Change");
        change.type = "button";
        change.title = "Answer the category and threat questions yourself";
        change.addEventListener("click", () => { manualFor = factsFor; facts = {}; check(); });
        strip.append(list, change);
        return strip;
      }
      const items = Object.entries(facts).flatMap(([field, value]) => [
        ...value.yes.map(id => ({ yes: true, label: model.valueLabel(field, id, lookups) })),
        ...value.no.map(id => ({ yes: false, label: model.valueLabel(field, id, lookups) })),
      ]);
      const manual = manualFor === factsFor;
      if (!items.length && !manual) return null;
      const strip = node("div", "tp-answers");
      strip.append(node("span", "tp-answers-lead", items.length ? `You said ${hostLabel}` : `Manual classification for ${hostLabel}`));
      const list = node("span", "tp-answers-list");
      const chip = (yes, text, title) => {
        const element = node("span", `tp-answer ${yes ? "is-yes" : "is-no"}`);
        element.append(node("span", "tp-answer-verb", yes ? "is" : "isn't"), document.createTextNode(` ${text}`));
        if (title) element.title = title;
        list.append(element);
      };
      items.filter(item => item.yes).forEach(item => chip(true, item.label));
      const no = items.filter(item => !item.yes).map(item => item.label);
      if (no.length > 2) chip(false, `${no.length} others`, no.join(", "));
      else no.forEach(label => chip(false, label));
      const change = node("button", "tp-link", "Change");
      change.type = "button";
      change.addEventListener("click", () => { facts = {}; check(); });
      strip.append(list);
      if (items.length) strip.append(change);
      if (manual) {
        const automatic = node("button", "tp-link", "Use automatic lookup");
        automatic.type = "button";
        automatic.addEventListener("click", () => { manualFor = ""; facts = {}; check(); });
        strip.append(automatic);
      }
      return strip;
    }

    function highlightTargets(matched) {
      const byRule = new Map();
      for (const result of matched) {
        const name = ruleTitle(result.match.rule);
        const entry = byRule.get(name) || { ruleName: name, stages: [], action: result.action, matchedConditions: result.match.matchedConditions };
        entry.stages.push(result.stage.label);
        byRule.set(name, entry);
      }
      return [...byRule.values()];
    }

    function summaryFor(request, evaluation) {
      return {
        title: evaluation.outcome.title,
        status: evaluation.outcome.status,
        destination: request.destination.host,
        stages: evaluation.stages.map(result => ({
          label: result.stage.label,
          state: result.state,
          action: result.state === "matched" ? model.actionLabel(result.action) + (result.afterBlock ? ` if ${result.afterBlock.label} misses` : "") : "",
          rule: result.match && result.match.rule ? ruleTitle(result.match.rule) : "",
        })),
      };
    }

    // Reset / restore -------------------------------------------------------
    reset.addEventListener("click", () => {
      for (const picker of Object.values(pickers)) picker.set("");
      Object.values(radios).forEach(radio => { radio.checked = false; });
      destination.value = "";
      port.value = "";
      protocol.value = "TCP";
      facts = {};
      factsFor = "";
      manualFor = "";
      setConnection("", false);
      changed();
      try { sessionStorage.removeItem(DRAFT_KEY); } catch (_) {}
      if (describe) describe.reset();
    });

    function applyDraft(draft) {
      for (const kind of Object.keys(model.SOURCES)) pickers[kind].set((draft.sources && draft.sources[kind]) || "");
      destination.value = draft.destination || "";
      port.value = draft.port || "";
      protocol.value = model.PROTOCOLS.includes(draft.protocol) ? draft.protocol : "TCP";
      setConnection(model.CONNECTIONS[draft.connection] ? draft.connection : "", false);
    }

    function restore() {
      let draft = null;
      try { draft = JSON.parse(sessionStorage.getItem(DRAFT_KEY) || "null"); } catch (_) {}
      if (draft) applyDraft(draft);
      else setConnection("", false);
      let savedMode = "form";
      try { savedMode = sessionStorage.getItem(MODE_KEY) || "form"; } catch (_) {}
      setMode(savedMode === "describe" ? "describe" : "form", false);
    }
    restore();

    // Data readiness -------------------------------------------------------
    function syncRunButton() {
      run.disabled = busy || !dataState.rulesCount;
      run.textContent = busy ? "Checking…" : "Check policy";
      run.title = dataState.rulesCount ? "" : "Waiting for policy rules to load";
    }

    function renderDataStatus() {
      const missing = Object.values(model.SOURCES).flatMap(source => source.catalogs || [])
        .filter(key => !Object.prototype.hasOwnProperty.call(activeCatalogs, key));
      dataStatus.replaceChildren();
      dataStatus.className = "tp-data-status";
      let title = "";
      let detail = "";
      if (dataState.stalled && !dataState.rulesCount) {
        dataStatus.classList.add("is-stalled");
        title = "Policy data hasn't loaded";
        detail = dataState.context === "dashboard"
          ? "The checker reads your rules with the dashboard's sign-in. Reload the policy page; if it keeps happening, sign in again."
          : "Open the Secure Access dashboard's policy page so the checker can read your rules.";
      } else if (!dataState.rulesCount) {
        title = "Loading your policy…";
        detail = "Reading rules and identities from the dashboard. You can fill in the form meanwhile.";
      } else if (missing.length && !dataState.stalled) {
        title = `Loaded ${dataState.rulesCount} rules`;
        detail = "Still loading identity lists. Pickers fill in as they arrive.";
        dataStatus.classList.add("is-quiet");
      }
      dataStatus.hidden = !title;
      if (title) {
        if (!dataState.stalled) dataStatus.append(node("span", "tp-spinner"));
        const copy = node("span", "tp-data-copy");
        copy.append(node("strong", "", title), node("span", "", detail));
        dataStatus.append(copy);
      }
      syncRunButton();
    }

    // { rulesCount, catalogs, stalled, context: "dashboard" | "toolbar" }
    function setData(next) {
      if (["rulesCount", "revision"].some(key => Object.prototype.hasOwnProperty.call(next, key) && next[key] !== dataState[key])) invalidate();
      dataState = { ...dataState, ...next };
      if (next.catalogs) updateCatalogs(next.catalogs);
      else renderDataStatus();
    }

    function updateCatalogs(nextCatalogs) {
      const revision = JSON.stringify(nextCatalogs || {});
      if (revision !== catalogRevision) invalidate();
      catalogRevision = revision;
      activeCatalogs = nextCatalogs || {};
      let draft = null;
      try { draft = JSON.parse(sessionStorage.getItem(DRAFT_KEY) || "null"); } catch (_) {}
      for (const [kind, picker] of Object.entries(pickers)) {
        if (!picker.value && draft && draft.sources && draft.sources[kind]) picker.set(draft.sources[kind]);
        else picker.refresh();
      }
      renderDataStatus();
    }
    renderDataStatus();

    return { panel, invalidate, updateCatalogs, setData, get lastEvaluation() { return lastEvaluation; } };
  }

  root.TrafficPathPanel = { create };
})(window);
