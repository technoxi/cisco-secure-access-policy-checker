"use strict";
// QA only: scripted fake LLM agent (Anthropic, OpenAI Responses, Gemini, OpenAI-compatible)
// and STT (Gemini, OpenAI, AssemblyAI streaming) so Describe mode runs end to end without keys.
(function () {
  const realFetch = window.fetch.bind(window);
  const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
  const json = body => ({ ok: true, status: 200, json: async () => body });
  window.describeStub = { llmDelay: 350, sttDelay: 600, transcript: "Can Denise on the VPN reach 10.100.67.25 over SSH?", calls: [] };
  try {
    localStorage.setItem("psc.describe.settings.v1", JSON.stringify({ llmKey: "stub-llm", llmProvider: "anthropic", llmModel: "claude-haiku-4-5" }));
  } catch (_) {}

  function connectionFrom(text) {
    if (/\bvpn\b/i.test(text)) return "vpn";
    if (/secure client|roaming|laptop/i.test(text)) return "client";
    if (/tunnel|branch/i.test(text)) return "tunnel";
    if (/\bva\b|virtual appliance/i.test(text)) return "va";
    return null;
  }

  // Normalized transcript [{ role: "user" | "assistant", content }] from any provider body.
  function transcriptOf(target, body) {
    if (target.includes("api.anthropic.com")) return body.messages;
    if (target.endsWith("/responses")) return typeof body.input === "string" ? [{ role: "user", content: body.input }] : body.input;
    if (target.includes(":generateContent")) return body.contents.map(item => ({ role: item.role === "model" ? "assistant" : "user", content: item.parts.map(part => part.text || "").join("") }));
    return body.messages.filter(message => message.role !== "system");
  }

  function llmReply(target, payload) {
    const text = JSON.stringify(payload);
    if (target.includes("api.anthropic.com")) return { content: [{ type: "text", text }] };
    if (target.endsWith("/responses")) return { output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text }] }] };
    if (target.includes(":generateContent")) return { candidates: [{ content: { role: "model", parts: [{ text }] } }] };
    return { choices: [{ message: { role: "assistant", content: text } }] };
  }

  const NativeSocket = window.WebSocket;
  class FakeAssemblySocket {
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      window.describeStub.calls.push({ to: "stt-stream", url: String(url).replace(/token=[^&]+/, "token=…") });
      setTimeout(() => {
        this.readyState = 1;
        if (this.onopen) this.onopen({});
        this.emit({ type: "Begin", id: "stub-session" });
        this.partial = setTimeout(() => this.emit({ type: "Turn", turn_order: 0, transcript: window.describeStub.transcript.split(" ").slice(0, 3).join(" "), end_of_turn: false }), 400);
      }, 50);
    }
    emit(message) { if (this.onmessage) this.onmessage({ data: JSON.stringify(message) }); }
    send(data) {
      if (typeof data !== "string" || JSON.parse(data).type !== "Terminate") return;
      clearTimeout(this.partial);
      setTimeout(() => {
        this.emit({ type: "Turn", turn_order: 0, transcript: window.describeStub.transcript, end_of_turn: true });
        this.emit({ type: "Termination" });
        this.readyState = 3;
        if (this.onclose) this.onclose({ code: 1000 });
      }, 150);
    }
    close() { this.readyState = 3; }
  }
  window.WebSocket = function (url, protocols) {
    return String(url).startsWith("wss://streaming.assemblyai.com/") ? new FakeAssemblySocket(url) : new NativeSocket(url, protocols);
  };

  const action = (tool, args) => ({ action: "tool", tool, args: { query: null, kinds: null, source: null, filter: null, offset: null, id: null, text: null, ...args }, question: null, options: null, decision: null });

  // Mimics a careful agent: look up the source, parse the destination, review rules, decide.
  function fakeAgent(messages) {
    const description = ((messages[0].content.match(/"""([\s\S]*?)"""/) || [])[1] || "").trim();
    const results = {};
    let answer = "";
    for (const message of messages.slice(1)) {
      if (message.role !== "user") continue;
      const result = message.content.match(/^Result of (\w+): ([\s\S]*)$/);
      if (result) results[result[1]] = JSON.parse(result[2].split("\n\nThis is your last turn")[0]);
      const reply = message.content.match(/^Admin's answer: (.*)$/);
      if (reply) answer = reply[1];
    }
    const name = (description.match(/\b(Denise(?: Adams| Park)?|Infrastructure|Carson City|Branch tunnel|Finance)\b/i) || [])[1];
    if (name && !results.search_sources) return action("search_sources", { query: name });
    const matches = (results.search_sources && results.search_sources.matches) || [];
    const exact = name && /\s/.test(name) && matches.find(match => match.label.toLowerCase().startsWith(name.toLowerCase()));
    const picked = answer ? matches.find(match => match.label.startsWith(answer)) : exact || (matches.length === 1 ? matches[0] : null);
    if (matches.length > 1 && !picked) {
      return { action: "ask", tool: null, args: null, question: `Which ${name} do you mean?`, options: matches.map(match => match.label.split(" (")[0]), decision: null };
    }
    const hostPattern = /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/i;
    const destination = (description.replace(/\bfrom\s+\S+/gi, " ").match(hostPattern) || [])[0];
    if (destination && !results.parse_destination) return action("parse_destination", { text: destination });
    if (!results.list_rules) return action("list_rules", {});
    const dest = results.parse_destination || {};
    const scope = dest.scope || "public_internet";
    const lower = description.toLowerCase();
    const matchesCondition = condition => /: any$/.test(condition) || condition.split(": ")[1].split(", ").some(label => {
      const cidr = label.match(/^(\d+\.\d+\.\d+)\.\d+\/\d+/);
      return cidr ? lower.includes(cidr[1] + ".") : lower.includes(label.toLowerCase());
    });
    const rule = results.list_rules.rules.find(item => item.enabled && (!item.scope || item.scope === scope) && item.conditions.every(matchesCondition));
    const connection = connectionFrom(description);
    const verb = { allow: "Allowed", block: "Blocked", warn: "Warned", isolate: "Isolated" }[rule ? rule.action : ""] || "Couldn't decide";
    const stage = scope === "private_network" ? (connection === "vpn" || connection === "tunnel" ? "Firewall" : "Private access") : connection === "vpn" ? "Firewall" : "DNS";
    const assumptions = [];
    if (!connection) assumptions.push("Traffic comes from Secure Client");
    if (!picked && !name) assumptions.push("Any user; no specific identity rules apply");
    return {
      action: "decide", tool: null, args: null, question: null, options: null,
      decision: {
        ruleId: rule ? rule.id : null,
        action: rule ? rule.action : "unknown",
        verdictTitle: rule ? `${verb} at ${stage}` : verb,
        summary: rule
          ? `${rule.name} is the first enabled rule whose conditions all match this ${scope === "private_network" ? "private" : "internet"} traffic.`
          : "No rule in this policy matches.",
        connection: connection || "client",
        source: picked ? picked.label.split(" (")[0] : name || "Any user",
        destination: dest.host || destination || "",
        assumptions,
      },
    };
  }

  window.fetch = async (url, init) => {
    const target = String(url);
    if (target === "https://api.openai.com/v1/audio/transcriptions") {
      window.describeStub.calls.push({ to: "stt", provider: "openai", model: init.body.get("model") });
      await wait(window.describeStub.sttDelay);
      return json({ text: window.describeStub.transcript });
    }
    if (target.startsWith("https://streaming.assemblyai.com/v3/token")) {
      window.describeStub.calls.push({ to: "stt-token", provider: "assemblyai" });
      return json({ token: "stub-temporary-token", expires_in_seconds: 60 });
    }
    const llmHost = /^https:\/\/(api\.anthropic\.com|api\.openai\.com|generativelanguage\.googleapis\.com)\//.test(target)
      || (window.describeStub.customLlmBase && target.startsWith(window.describeStub.customLlmBase));
    if (llmHost) {
      const body = JSON.parse(init.body);
      const audio = target.includes(":generateContent") && body.contents[0].parts.find(part => part.inlineData);
      if (audio) {
        window.describeStub.calls.push({ to: "stt", provider: "gemini", mimeType: audio.inlineData.mimeType, bytes: audio.inlineData.data.length });
        await wait(window.describeStub.sttDelay);
        return json({ candidates: [{ content: { role: "model", parts: [{ text: window.describeStub.transcript }] } }] });
      }
      window.describeStub.calls.push({ to: "llm", url: target, body });
      await wait(window.describeStub.llmDelay);
      const reply = fakeAgent(transcriptOf(target, body));
      window.describeStub.calls[window.describeStub.calls.length - 1].reply = reply;
      return json(llmReply(target, reply));
    }
    return realFetch(url, init);
  };
})();
