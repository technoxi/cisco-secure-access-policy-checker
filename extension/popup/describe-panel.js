// Describe mode UI: free text or voice in; the agent reviews the policy and
// its chosen rule is the verdict.
(function (root) {
  "use strict";

  const STATE_KEY = "psc.policyChecker.describe.v1";
  const SVG = {
    mic: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="3.5" width="6" height="11" rx="3"/><path d="M5.5 11.5a6.5 6.5 0 0 0 13 0M12 18v2.5"/></svg>',
    stop: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="7" y="7" width="10" height="10" rx="1.5"/></svg>',
    gear: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1.2l2-1.5-2-3.4-2.3.9a7 7 0 0 0-2-1.2L14.2 3h-4.4l-.4 2.6a7 7 0 0 0-2 1.2l-2.3-.9-2 3.4 2 1.5a7 7 0 0 0 0 2.4l-2 1.5 2 3.4 2.3-.9a7 7 0 0 0 2 1.2l.4 2.6h4.4l.4-2.6a7 7 0 0 0 2-1.2l2.3.9 2-3.4-2-1.5c.1-.4.1-.8.1-1.2z"/></svg>',
    spark: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3.5l1.9 5.1 5.1 1.9-5.1 1.9L12 17.5l-1.9-5.1L5 10.5l5.1-1.9z"/><path d="M18.5 16l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z"/></svg>',
  };
  const OUTCOME = {
    allow: { status: "allow", icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>' },
    block: { status: "block", icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8"/><path d="M6.5 17.5l11-11"/></svg>' },
    warn: { status: "warn", icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 4.5l8.5 15h-17z"/><path d="M12 10v4M12 16.8h.01"/></svg>' },
    unknown: { status: "pending", icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M9.6 9.6a2.5 2.5 0 1 1 3.4 2.3c-.6.3-1 .8-1 1.5v.4M12 16.8h.01"/></svg>' },
  };
  OUTCOME.isolate = { ...OUTCOME.warn };

  function node(tag, className, text) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function svg(name, className) {
    const span = node("span", className || "tp-icon");
    span.innerHTML = SVG[name];
    return span;
  }

  // host: { model, getCatalogs, isReady, getPolicy, clearResults, showResult(element), highlight(targets, summary)? }
  function create(host) {
    const Agent = root.DescribeAgent;
    const model = host.model;
    let generation = 0;
    let transcript = null;
    let retry = null;
    let settings = { ...Agent.DEFAULTS };
    let recognition = null;
    let listening = false;
    let voice = null;
    let voiceRun = 0;
    const Llm = root.LlmProviders;
    const Stt = root.SpeechProviders;
    const settingsReady = Agent.loadSettings().then(value => { settings = value; renderKeyNotice(); syncMic(); }).catch(() => {});

    const section = node("section", "tp-describe");
    section.setAttribute("aria-label", "Describe traffic");

    const box = node("div", "tp-describe-box");
    const label = node("label", "tp-label", "Describe the traffic");
    label.htmlFor = "tp-describe-text";
    const text = node("textarea", "tp-input tp-describe-text");
    text.id = "tp-describe-text";
    text.rows = 3;
    text.placeholder = "e.g. Can Aang on the VPN reach 10.100.67.25 over SSH?";
    text.spellcheck = true;
    const tools = node("div", "tp-describe-tools");
    const mic = node("button", "tp-describe-mic");
    mic.type = "button";
    mic.append(svg("mic"), node("span", "tp-describe-mic-text", "Speak"));
    mic.setAttribute("aria-pressed", "false");
    const listenState = node("span", "tp-describe-listening", "");
    listenState.setAttribute("aria-live", "polite");
    const gear = node("button", "tp-describe-gear");
    gear.type = "button";
    gear.title = "Describe settings";
    gear.setAttribute("aria-label", "Describe settings");
    gear.setAttribute("aria-expanded", "false");
    gear.append(svg("gear"));
    box.append(label, text, tools);

    const keyNotice = node("p", "tp-describe-notice");
    keyNotice.hidden = true;

    const actions = node("div", "tp-actions tp-describe-actions");
    const go = node("button", "tp-primary");
    go.type = "button";
    go.append(svg("spark", "tp-icon tp-describe-go-icon"), node("span", "", "Check"));
    actions.append(go);

    const error = node("p", "tp-error");
    error.id = "tp-describe-error";
    error.setAttribute("role", "alert");
    const trace = node("ol", "tp-agent-steps");
    trace.setAttribute("aria-live", "polite");
    trace.setAttribute("aria-label", "Progress");
    const understood = node("div", "tp-understood");
    understood.hidden = true;
    const clarify = node("div", "tp-clarify");
    clarify.hidden = true;

    const popoverWrap = node("div", "tp-popover-anchor");
    const settingsForm = buildSettings();
    popoverWrap.append(gear, settingsForm);
    tools.append(mic, listenState, popoverWrap);
    section.append(box, keyNotice, actions, error, trace, understood, clarify);

    // Settings ------------------------------------------------------------
    function buildSettings() {
      const wrap = node("form", "tp-describe-settings");
      wrap.hidden = true;
      wrap.noValidate = true;
      wrap.setAttribute("aria-label", "Describe settings");
      const headerBar = node("div", "tp-describe-settings-header");
      const title = node("h3", "tp-describe-settings-title", "Model & Voice Configuration");
      const closeBtn = node("button", "tp-describe-settings-close");
      closeBtn.type = "button";
      closeBtn.setAttribute("aria-label", "Close settings menu");
      closeBtn.title = "Close menu";
      closeBtn.textContent = "×";
      closeBtn.addEventListener("click", () => toggleSettings(false));
      headerBar.append(title, closeBtn);
      const fields = {};
      const add = (key, labelText, type, extra) => {
        const field = node("div", "tp-field");
        const fieldLabel = node("label", "tp-label", labelText);
        fieldLabel.htmlFor = `tp-describe-${key}`;
        let input;
        if (type === "select") {
          input = node("select", "tp-input");
          for (const [value, text] of extra) { const option = node("option", "", text); option.value = value; input.append(option); }
        } else {
          input = node("input", "tp-input");
          input.type = type;
          input.autocomplete = "off";
          input.spellcheck = false;
          if (extra) input.placeholder = extra;
        }
        input.id = `tp-describe-${key}`;
        field.append(fieldLabel, input);
        fields[key] = input;
        return field;
      };
      const llmGroup = node("fieldset", "tp-describe-group");
      llmGroup.append(
        node("legend", "tp-describe-group-title", "Language model"),
        add("llmProvider", "Provider", "select", Object.entries(Llm.PROVIDERS).map(([id, provider]) => [id, provider.label])),
        add("llmKey", "API key", "password", "Required"),
        add("llmModel", "Model", "text", ""),
        add("llmBaseUrl", "Base URL (optional)", "url", "Provider default"),
      );
      const sttGroup = node("fieldset", "tp-describe-group tp-describe-voice-group");
      const sttKeyFields = {};
      sttGroup.append(
        node("legend", "tp-describe-group-title", "Voice input (speech to text)"),
        add("sttProvider", "Provider", "select", Object.entries(Stt.PROVIDERS).map(([id, provider]) => [id, provider.label])),
      );
      for (const [id, provider] of Object.entries(Stt.PROVIDERS)) {
        if (!provider.keyField) continue;
        sttKeyFields[id] = add(provider.keyField, `${provider.label.replace(/\s*\(.*\)$/, "")} API key`, "password", "");
        sttKeyFields[id].classList.add("tp-describe-stt-key");
        sttGroup.append(sttKeyFields[id]);
      }
      const sttModelField = add("sttModel", "Model", "text", "");
      const sttHint = node("p", "tp-hint tp-describe-stt-hint");
      sttGroup.append(sttModelField, sttHint);
      const note = node("p", "tp-hint", "Keys stay in this browser's extension storage and are sent only to the provider you set. Your description, the loaded policy rules and matching names are sent to the language model.");
      const row = node("div", "tp-actions");
      const save = node("button", "tp-primary", "Save");
      save.type = "submit";
      const cancel = node("button", "tp-link", "Cancel");
      cancel.type = "button";
      const saved = node("span", "tp-describe-saved");
      saved.setAttribute("role", "status");
      row.append(save, cancel, saved);
      wrap.append(headerBar, llmGroup, sttGroup, note, row);

      const syncModelPlaceholder = () => {
        const provider = Llm.PROVIDERS[fields.llmProvider.value];
        fields.llmModel.placeholder = provider.defaultModel;
        fields.llmBaseUrl.placeholder = provider.defaultBase;
        syncStt();
      };
      const syncStt = () => {
        const id = fields.sttProvider.value;
        const provider = Stt.PROVIDERS[id];
        for (const [keyId, field] of Object.entries(sttKeyFields)) field.hidden = keyId !== id;
        sttModelField.hidden = !provider.keyField;
        fields.sttModel.placeholder = provider.defaultModel;
        const sharesLlmKey = provider.vendor && Llm.PROVIDERS[fields.llmProvider.value].vendor === provider.vendor;
        if (provider.keyField) fields[provider.keyField].placeholder = sharesLlmKey ? "Blank uses the language model key" : "Required for this provider";
        sttHint.textContent = provider.keyField
          ? `Your recording is sent to ${provider.label.replace(/\s*\(.*\)$/, "")} for transcription.`
          : "Uses the browser's own speech recognition; no key needed.";
      };
      fields.llmProvider.addEventListener("change", syncModelPlaceholder);
      fields.sttProvider.addEventListener("change", syncStt);
      wrap.fill = () => {
        for (const [key, input] of Object.entries(fields)) input.value = settings[key] || "";
        if (settings.llmModel === Agent.LLM_DEFAULT_MODELS[settings.llmProvider]) fields.llmModel.value = "";
        syncModelPlaceholder();
        saved.textContent = "";
      };
      cancel.addEventListener("click", () => toggleSettings(false));
      wrap.addEventListener("submit", async event => {
        event.preventDefault();
        const next = {};
        for (const [key, input] of Object.entries(fields)) next[key] = input.value.trim();
        next.llmModel = next.llmModel || Agent.LLM_DEFAULT_MODELS[next.llmProvider];
        if (next.llmBaseUrl && !(await allowHost(next.llmBaseUrl))) {
          saved.textContent = "Permission for that base URL was declined.";
          return;
        }
        settings = await Agent.saveSettings(next);
        renderKeyNotice();
        syncMic();
        saved.textContent = "Saved";
        setTimeout(() => toggleSettings(false), 500);
      });
      return wrap;
    }

    async function allowHost(url) {
      let origin;
      try { origin = new URL(url).origin; } catch (_) { return false; }
      const permissions = root.chrome && root.chrome.permissions;
      if (!permissions || !permissions.request) return true;
      try { return await permissions.request({ origins: [`${origin}/*`] }); } catch (_) { return false; }
    }

    function toggleSettings(open) {
      const next = open === undefined ? settingsForm.hidden : open;
      if (next) settingsForm.fill();
      settingsForm.hidden = !next;
      gear.setAttribute("aria-expanded", String(next));
      gear.classList.toggle("is-active", next);
      if (next) {
        positionSettings();
        const firstField = settingsForm.querySelector("input, select");
        if (firstField) firstField.focus();
      } else {
        gear.focus();
      }
    }
    document.addEventListener("pointerdown", event => {
      if (!settingsForm.hidden && !popoverWrap.contains(event.target)) {
        toggleSettings(false);
      }
    });
    function positionSettings() {
      if (settingsForm.hidden) return;
      const viewport = root.visualViewport;
      const left = viewport ? viewport.offsetLeft : 0;
      const top = viewport ? viewport.offsetTop : 0;
      const width = viewport ? viewport.width : root.innerWidth;
      const height = viewport ? viewport.height : root.innerHeight;
      const anchor = gear.getBoundingClientRect();
      const below = Math.max(0, top + height - anchor.bottom - 16);
      const above = Math.max(0, anchor.top - top - 16);
      const flip = below < Math.min(430, settingsForm.scrollHeight) && above > below;
      const available = flip ? above : below;
      settingsForm.style.width = `${Math.max(0, Math.min(390, width - 32))}px`;
      settingsForm.style.maxHeight = `${Math.min(430, available)}px`;
      settingsForm.style.left = `${Math.max(left + 16, Math.min(anchor.right - settingsForm.offsetWidth, left + width - settingsForm.offsetWidth - 16))}px`;
      settingsForm.style.top = `${flip ? anchor.top - 8 - settingsForm.offsetHeight : Math.max(top + 8, anchor.bottom + 8)}px`;
    }
    root.addEventListener("resize", positionSettings);
    document.addEventListener("scroll", positionSettings, true);
    if (root.visualViewport) {
      root.visualViewport.addEventListener("resize", positionSettings);
      root.visualViewport.addEventListener("scroll", positionSettings);
    }
    document.addEventListener("keydown", event => {
      if (event.key === "Escape" && !settingsForm.hidden) {
        event.preventDefault();
        event.stopPropagation();
        toggleSettings(false);
      }
    }, true);
    gear.addEventListener("click", () => toggleSettings());

    function renderKeyNotice() {
      keyNotice.replaceChildren();
      if (!Agent.needsKey(settings)) { keyNotice.hidden = true; return; }
      keyNotice.hidden = false;
      const open = node("button", "tp-link", "Add a language model API key");
      open.type = "button";
      open.addEventListener("click", () => toggleSettings(true));
      keyNotice.append(open, document.createTextNode(" to use Describe mode."));
    }

    // Voice ---------------------------------------------------------------
    const Speech = root.SpeechRecognition || root.webkitSpeechRecognition;
    let transcribing = false;
    const sttProvider = () => Stt.providerId(settings.sttProvider);
    function syncMic() {
      const browserOnly = sttProvider() === "browser";
      const supported = browserOnly ? !!Speech : !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
      mic.disabled = transcribing || !supported;
      mic.title = supported ? "" : "Voice input isn't available in this browser";
    }
    let spokenBase = "";
    const withSpoken = words => [spokenBase, words].filter(Boolean).join(" ");
    function setListening(on, message) {
      listening = on;
      mic.classList.toggle("is-listening", on);
      mic.classList.toggle("is-transcribing", transcribing);
      mic.setAttribute("aria-pressed", String(on));
      mic.replaceChildren(svg(on ? "stop" : "mic"), node("span", "tp-describe-mic-text", on ? "Stop" : "Speak"));
      listenState.textContent = message || (on ? "Listening…" : "");
      listenState.classList.toggle("is-on", on);
      listenState.classList.toggle("is-busy", transcribing);
      syncMic();
    }
    function haltVoice() {
      voiceRun++;
      if (recognition) {
        recognition.onresult = recognition.onerror = recognition.onend = null;
        recognition.abort();
        recognition = null;
      }
      if (voice) voice.cancel();
      stopTracks();
      voice = null;
      voiceStarting = false;
      transcribing = false;
      setListening(false);
    }
    syncMic();
    mic.addEventListener("click", () => {
      if (transcribing) return;
      if (listening) {
        if (voice) finishApiVoice();
        else if (voiceStarting) haltVoice();
        else if (recognition) recognition.stop();
        return;
      }
      error.textContent = "";
      if (sttProvider() !== "browser") { startApiVoice(); return; }
      if (!Speech) return;
      recognition = new Speech();
      const run = ++voiceRun;
      recognition.lang = navigator.language || "en-US";
      recognition.interimResults = true;
      recognition.continuous = false;
      spokenBase = text.value.trim();
      let finalText = "";
      let failed = false;
      recognition.onresult = event => {
        if (run !== voiceRun) return;
        let interim = "";
        finalText = "";
        for (const result of event.results) (result.isFinal ? (finalText += result[0].transcript) : (interim += result[0].transcript));
        text.value = withSpoken(finalText || interim);
        textChanged();
      };
      recognition.onerror = event => {
        if (run !== voiceRun) return;
        failed = true;
        if (event.error === "not-allowed" || event.error === "service-not-allowed") showMicHelp();
        else setListening(false, event.error === "no-speech" ? "Didn't catch that" : "Voice input stopped");
      };
      recognition.onend = () => {
        if (failed || run !== voiceRun) return;
        setListening(false);
        if (finalText.trim()) submit();
      };
      try { recognition.start(); setListening(true); } catch (_) { setListening(false, "Voice input couldn't start"); }
    });

    // Vendor STT: record (or stream, for AssemblyAI) the mic, then fill and submit.
    let micStream = null;
    let voiceTimer = 0;
    let voiceStarting = false;
    function stopTracks() {
      clearTimeout(voiceTimer);
      if (micStream) micStream.getTracks().forEach(track => track.stop());
      micStream = null;
    }
    async function startApiVoice() {
      const id = sttProvider();
      const provider = Stt.PROVIDERS[id];
      if (!Stt.sttKey(settings)) {
        error.textContent = `Add your ${provider.label.replace(/\s*\(.*\)$/, "")} key for voice input.`;
        toggleSettings(true);
        return;
      }
      const run = ++voiceRun;
      spokenBase = text.value.trim();
      voiceStarting = true;
      setListening(true, "Starting microphone…");
      try {
        micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
      } catch (failure) {
        if (run !== voiceRun) return;
        voiceStarting = false;
        const name = failure && failure.name;
        if (name === "NotAllowedError" || name === "SecurityError") showMicHelp();
        else setListening(false, name === "NotFoundError" ? "No microphone found" : "Microphone unavailable");
        return;
      }
      if (run !== voiceRun) { stopTracks(); return; }
      try {
        voice = provider.streaming
          ? await Stt.startAssemblyStream({
            settings, stream: micStream,
            onText: words => { if (run === voiceRun) { text.value = withSpoken(words); textChanged(); } },
          })
          : Stt.startRecording(micStream);
      } catch (failure) {
        if (run !== voiceRun) return;
        voiceStarting = false;
        stopTracks();
        setListening(false, "");
        error.textContent = failure && failure.message ? failure.message : "Voice input couldn't start.";
        return;
      }
      if (run !== voiceRun) { voice.cancel(); voice = null; stopTracks(); return; }
      voiceStarting = false;
      setListening(true, provider.streaming ? "Listening…" : "Recording…");
      voiceTimer = setTimeout(() => { if (run === voiceRun && voice) finishApiVoice(); }, Stt.MAX_RECORDING_MS);
    }

    async function finishApiVoice() {
      const run = voiceRun;
      const active = voice;
      voice = null;
      clearTimeout(voiceTimer);
      transcribing = true;
      setListening(false, "Transcribing…");
      let words = "";
      let problem = "";
      try {
        words = Stt.PROVIDERS[sttProvider()].streaming
          ? await active.stop()
          : await Stt.transcribe(settings, await active.stop(), root.fetch.bind(root));
      } catch (failure) {
        problem = failure && failure.message ? failure.message : "Transcription failed.";
      }
      if (run !== voiceRun) return;
      stopTracks();
      transcribing = false;
      if (problem) { setListening(false, ""); error.textContent = problem; return; }
      if (!words) { setListening(false, "Didn't catch that"); return; }
      text.value = withSpoken(words);
      textChanged();
      setListening(false);
      submit();
    }

    function showMicHelp() {
      setListening(false, "");
      error.replaceChildren(document.createTextNode("Microphone access is blocked. "));
      const runtime = root.chrome && root.chrome.runtime;
      if (runtime && runtime.getURL) {
        const allow = node("button", "tp-link", "Allow microphone");
        allow.type = "button";
        allow.addEventListener("click", () => root.open(runtime.getURL("popup/mic-permission.html"), "_blank", "noopener"));
        error.append(allow);
      }
    }

    // Run -----------------------------------------------------------------
    function persist() {
      try { sessionStorage.setItem(STATE_KEY, JSON.stringify({ text: text.value })); } catch (_) {}
    }
    function textChanged() {
      transcript = null;
      retry = null;
      trace.replaceChildren();
      understood.hidden = true;
      clarify.hidden = true;
      clarify.replaceChildren();
      persist();
    }
    text.addEventListener("input", () => { textChanged(); cancel(); });
    text.addEventListener("keydown", event => {
      if (event.key === "Enter" && !event.shiftKey && !event.isComposing) { event.preventDefault(); submit(); }
    });
    go.addEventListener("click", () => submit());

    function cancel(clearResults = true) {
      generation++;
      haltVoice();
      if (clearResults && host.clearResults) host.clearResults();
      go.disabled = false;
      section.classList.remove("is-running");
      error.textContent = "";
    }

    // One plain-language line: only the current step is shown.
    function setProgress(label, state) {
      const item = node("li", `tp-agent-step is-${state || "active"}`);
      item.append(node("span", "tp-agent-dot"), node("span", "tp-agent-label", label));
      trace.replaceChildren(item);
    }

    function connectionLabel(value) {
      const config = value && model.CONNECTIONS[value];
      return config ? config.label : value;
    }

    function renderUnderstood(decision) {
      understood.replaceChildren();
      const items = [["Connection", connectionLabel(decision.connection)], ["Source", decision.source], ["Destination", decision.destination]].filter(([, value]) => value);
      understood.hidden = !items.length;
      if (!items.length) return;
      understood.append(node("p", "tp-understood-title", "Understood as"));
      const list = node("dl", "tp-understood-list");
      items.forEach(([name, value], index) => {
        const row = node("div", "tp-understood-row");
        row.style.setProperty("--tp-i", index);
        const dd = node("dd", "");
        dd.append(node("span", "tp-understood-value", value));
        row.append(node("dt", "", name), dd);
        list.append(row);
      });
      understood.append(list);
    }

    function priorityText(rule) {
      if (rule.default) return "";
      return rule.priority !== null && rule.priority !== undefined ? `Priority ${rule.priority}` : "";
    }

    function renderVerdict(decision, rule) {
      const look = OUTCOME[decision.action] || OUTCOME.unknown;
      const card = node("div", `tp-outcome tp-outcome-${look.status} tp-describe-verdict`);
      const iconSpan = node("span", "tp-outcome-icon");
      iconSpan.innerHTML = look.icon;
      const copy = node("div", "tp-outcome-copy");
      copy.append(node("strong", "tp-outcome-title", decision.verdictTitle));
      const ruleLine = rule ? [rule.name, priorityText(rule)].filter(Boolean).join(" · ") : "No matching rule";
      copy.append(node("span", "tp-outcome-rule", ruleLine));
      if (decision.summary) copy.append(node("p", "tp-outcome-summary", decision.summary));
      if (decision.assumptions.length) {
        const assumed = node("div", "tp-describe-assumptions");
        const list = node("ul", "");
        for (const item of decision.assumptions) list.append(node("li", "", item));
        assumed.append(node("span", "tp-describe-assumptions-title", "Assumed:"), list);
        copy.append(assumed);
      }
      card.append(iconSpan, copy);
      if (rule && host.highlight) {
        const show = node("button", "tp-secondary", "Show on page");
        show.type = "button";
        show.addEventListener("click", () => host.highlight(
          [{ ruleName: rule.name, stages: [], action: decision.action, matchedConditions: decision.summary ? [decision.summary] : [] }],
          { title: decision.verdictTitle, status: look.status, destination: decision.destination || "", stages: [] },
        ));
        card.append(show);
      }
      host.showResult(card, look.status, decision);
    }

    function renderQuestion(question) {
      clarify.replaceChildren();
      clarify.hidden = false;
      const title = node("p", "tp-clarify-text", question.text);
      title.id = "tp-clarify-text";
      clarify.append(svg("spark", "tp-icon tp-clarify-icon"), title);
      if (question.options.length) {
        const options = node("div", "tp-clarify-options");
        options.setAttribute("role", "group");
        options.setAttribute("aria-labelledby", title.id);
        question.options.forEach((option, index) => {
          const button = node("button", "tp-clarify-option", option);
          button.type = "button";
          button.style.setProperty("--tp-i", index);
          button.addEventListener("click", () => respond(option));
          options.append(button);
        });
        clarify.append(options);
      }
      const reply = node("form", "tp-clarify-reply");
      const input = node("input", "tp-input");
      input.setAttribute("aria-labelledby", title.id);
      input.placeholder = question.options.length ? "Or type your answer" : "Type your answer";
      const send = node("button", "tp-secondary", "Answer");
      send.type = "submit";
      reply.append(input, send);
      reply.addEventListener("submit", event => {
        event.preventDefault();
        if (input.value.trim()) respond(input.value.trim());
      });
      clarify.append(reply);
      const first = clarify.querySelector(".tp-clarify-option") || input;
      first.focus({ preventScroll: true });
    }

    function respond(answer) {
      if (!transcript) { submit(); return; }
      execute({ messages: transcript, answer });
    }

    function submit() {
      if (retry) return execute(retry);
      transcript = null;
      return execute({});
    }

    async function execute(resume) {
      haltVoice();
      cancel();
      const mine = generation;
      const current = () => mine === generation;
      trace.replaceChildren();
      understood.hidden = true;
      clarify.hidden = true;
      if (!text.value.trim()) { error.textContent = "Describe the traffic to check."; text.focus(); return; }
      if (!host.isReady()) { error.textContent = "Policy rules are still loading. Try again in a moment."; return; }
      await settingsReady;
      if (!current()) return;
      if (Agent.needsKey(settings)) {
        renderKeyNotice();
        toggleSettings(true);
        return;
      }
      go.disabled = true;
      section.classList.add("is-running");
      setProgress(resume.answer !== undefined ? "Picking up your answer…" : "Understanding your question…");
      let result;
      try {
        const policy = await host.getPolicy();
        if (!current()) return;
        result = await Agent.run({
          text: text.value, model, settings, policy, messages: resume.messages, answer: resume.answer,
          isCurrent: current, onProgress: label => { if (current()) setProgress(label); },
        });
      } catch (failure) {
        result = { status: "error", error: failure && failure.message ? failure.message : "The assistant couldn't finish." };
      }
      if (!current()) return;
      go.disabled = false;
      section.classList.remove("is-running");
      if (result.status === "cancelled") return;
      if (result.status === "error") {
        retry = result.messages ? { messages: result.messages } : resume;
        transcript = result.messages || resume.messages || transcript;
        trace.replaceChildren();
        error.textContent = result.error;
        const retryButton = node("button", "tp-link", "Retry");
        retryButton.type = "button";
        retryButton.addEventListener("click", () => submit());
        error.append(document.createTextNode(" "), retryButton);
        if (result.needsSettings) toggleSettings(true);
        return;
      }
      retry = null;
      transcript = result.messages || null;
      if (result.status === "needs_input") {
        setProgress("Needs one more detail", "done");
        renderQuestion(result.question);
        return;
      }
      trace.replaceChildren();
      renderUnderstood(result.decision);
      renderVerdict(result.decision, result.rule);
    }

    function reset() {
      cancel();
      haltVoice();
      text.value = "";
      transcript = null;
      retry = null;
      trace.replaceChildren();
      understood.hidden = true;
      clarify.hidden = true;
      toggleSettings(false);
      persist();
    }

    try { text.value = (JSON.parse(sessionStorage.getItem(STATE_KEY) || "null") || {}).text || ""; } catch (_) {}

    return { element: section, reset, cancel, focus: () => text.focus(), submit, toggleSettings };
  }

  root.DescribePanel = { create };
})(window);
