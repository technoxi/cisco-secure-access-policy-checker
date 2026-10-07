#!/usr/bin/env node
"use strict";
// Describe mode vendor adapters: LLM and speech-to-text request shapes and
// response parsing with stubbed fetch / MediaRecorder / WebSocket.
// Run: node test-describe-providers.js
const assert = require("node:assert/strict");

globalThis.IPAddress = require("./extension/popup/ip-address.js");
const model = require("./extension/popup/traffic-path.js");
const Llm = require("./extension/popup/llm-providers.js");
const Stt = require("./extension/popup/speech-providers.js");
const Agent = require("./extension/popup/describe-agent.js");

const reply = { connection: "vpn", sources: [{ kind: "identity", mention: "Aang" }], destination: "example.org", port: "22", protocol: "TCP", internalIp: "", question: "" };
const ok = body => ({ ok: true, status: 200, json: async () => body });
const VENDOR_HOSTS = { anthropic: "api.anthropic.com", openai: "api.openai.com", gemini: "generativelanguage.googleapis.com", assemblyai: "streaming.assemblyai.com" };

function headerValues(init) {
  return Object.values((init && init.headers) || {}).map(String);
}
// Every secret must only appear on requests to its own vendor's host.
function assertKeyIsolation(calls, keysByHost) {
  for (const call of calls) {
    const host = new URL(call.url).host;
    const sent = headerValues(call.init).join(" ") + " " + call.url;
    for (const [keyHost, key] of Object.entries(keysByHost)) {
      if (keyHost !== host) assert.ok(!sent.includes(key), `key for ${keyHost} leaked to ${host}`);
    }
  }
}

let passed = 0;
async function test(name, fn) {
  try { await fn(); passed++; } catch (error) { console.error(`FAIL ${name}`); throw error; }
}

(async () => {
  await test("anthropic: Messages API with browser header and JSON schema", async () => {
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, init }); return ok({ content: [{ type: "text", text: JSON.stringify(reply) }] }); };
    const text = await Llm.call({ llmProvider: "anthropic", llmKey: "sk-ant" }, "SYS", "USER", fetch, Agent.ACTION_SCHEMA);
    assert.deepEqual(JSON.parse(text), reply);
    const [{ url, init }] = calls;
    assert.equal(url, "https://api.anthropic.com/v1/messages");
    assert.equal(init.headers["x-api-key"], "sk-ant");
    assert.equal(init.headers["anthropic-version"], "2023-06-01");
    assert.equal(init.headers["anthropic-dangerous-direct-browser-access"], "true");
    const body = JSON.parse(init.body);
    assert.equal(body.model, "claude-haiku-4-5");
    assert.equal(body.system, "SYS");
    assert.deepEqual(body.messages, [{ role: "user", content: "USER" }]);
    assert.equal(body.output_config.format.type, "json_schema");
    assert.equal(body.output_config.format.schema.additionalProperties, false);
  });

  await test("openai: Responses API with strict json_schema; output parsed from output items", async () => {
    const calls = [];
    const fetch = async (url, init) => {
      calls.push({ url, init });
      return ok({ output: [{ type: "reasoning", summary: [] }, { type: "message", role: "assistant", content: [{ type: "output_text", text: JSON.stringify(reply) }] }] });
    };
    const text = await Llm.call({ llmProvider: "openai", llmKey: "sk-oa" }, "SYS", "USER", fetch, Agent.ACTION_SCHEMA);
    assert.deepEqual(JSON.parse(text), reply);
    const [{ url, init }] = calls;
    assert.equal(url, "https://api.openai.com/v1/responses");
    assert.equal(init.headers.authorization, "Bearer sk-oa");
    const body = JSON.parse(init.body);
    assert.equal(body.model, "gpt-6-luna");
    assert.equal(body.instructions, "SYS");
    assert.equal(body.input, "USER");
    assert.equal(body.store, false);
    assert.deepEqual(body.reasoning, { effort: "low" });
    assert.equal(body.text.format.type, "json_schema");
    assert.equal(body.text.format.strict, true);
    assert.equal(body.text.format.name, "traffic_check");
    assert.ok(body.text.format.schema.required.includes("decision"));
    assert.equal(body.text.format.schema.properties.args.additionalProperties, false);
    assert.equal(body.text.format.schema.properties.decision.additionalProperties, false);
    assert.equal("temperature" in body, false);
    await assert.rejects(
      Llm.call({ llmProvider: "openai", llmKey: "k" }, "s", "u", async () => ok({ output: [{ type: "message", content: [{ type: "refusal", refusal: "no" }] }] })),
      /declined/,
    );
    assert.equal(Llm.readText("openai", { output_text: "{\"a\":1}" }), "{\"a\":1}");
  });

  await test("gemini: generateContent with x-goog-api-key and OpenAPI responseSchema", async () => {
    const calls = [];
    const fetch = async (url, init) => {
      calls.push({ url, init });
      return ok({ candidates: [{ content: { role: "model", parts: [{ text: "thinking", thought: true }, { text: JSON.stringify(reply) }] } }] });
    };
    const text = await Llm.call({ llmProvider: "gemini", llmKey: "AIza-g" }, "SYS", "USER", fetch, Agent.ACTION_SCHEMA);
    assert.deepEqual(JSON.parse(text), reply);
    const [{ url, init }] = calls;
    assert.equal(url, "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-flash-lite:generateContent");
    assert.equal(init.headers["x-goog-api-key"], "AIza-g");
    assert.ok(!url.includes("AIza-g"), "key never goes in the URL");
    const body = JSON.parse(init.body);
    assert.deepEqual(body.systemInstruction, { parts: [{ text: "SYS" }] });
    assert.deepEqual(body.contents, [{ role: "user", parts: [{ text: "USER" }] }]);
    assert.equal(body.generationConfig.responseMimeType, "application/json");
    const schema = body.generationConfig.responseSchema;
    assert.equal(schema.type, "OBJECT");
    assert.equal(schema.properties.tool.type, "STRING");
    assert.equal(schema.properties.tool.nullable, true);
    assert.equal(schema.properties.args.type, "OBJECT");
    assert.equal(schema.properties.args.nullable, true);
    assert.equal(schema.properties.args.properties.kinds.type, "ARRAY");
    assert.deepEqual(schema.properties.action.enum, ["tool", "ask", "decide"]);
    assert.deepEqual(schema.properties.decision.properties.action.enum, ["allow", "block", "warn", "isolate", "unknown"]);
    assert.equal(Llm.toGeminiSchema({ type: "string", enum: ["A", ""] }).enum, undefined, "'' can't be a Gemini enum value");
    assert.equal("additionalProperties" in schema, false);
  });

  await test("openai-compatible: chat/completions on a custom base URL", async () => {
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, init }); return ok({ choices: [{ message: { content: JSON.stringify(reply) } }] }); };
    const settings = { llmProvider: "openai-compatible", llmKey: "local", llmBaseUrl: "https://llm.example.net/v1/", llmModel: "qwen" };
    assert.deepEqual(JSON.parse(await Llm.call(settings, "SYS", "USER", fetch, Agent.ACTION_SCHEMA)), reply);
    assert.equal(calls[0].url, "https://llm.example.net/v1/chat/completions");
    const body = JSON.parse(calls[0].init.body);
    assert.equal(body.model, "qwen");
    assert.deepEqual(body.response_format, { type: "json_object" });
    assert.deepEqual(body.messages.map(m => m.role), ["system", "user"]);
  });

  await test("model and base URL overrides; HTTP errors hint at the key", async () => {
    const { url, init } = Llm.buildRequest({ llmProvider: "gemini", llmKey: "k", llmModel: "gemini-3.8-flash", llmBaseUrl: "https://proxy.example/v1beta" }, "s", "u");
    assert.equal(url, "https://proxy.example/v1beta/models/gemini-3.8-flash:generateContent");
    assert.equal(JSON.parse(init.body).generationConfig.responseSchema, undefined);
    const anthropic = Llm.buildRequest({ llmProvider: "anthropic", llmKey: "k", llmModel: "claude-sonnet-5-5" }, "s", "u");
    assert.equal(JSON.parse(anthropic.init.body).model, "claude-sonnet-5-5");
    assert.equal(JSON.parse(Llm.buildRequest({ llmProvider: "openai", llmKey: "k", llmModel: "gpt-4.1-mini" }, "s", "u").init.body).reasoning, undefined);
    await assert.rejects(Llm.call({ llmProvider: "openai", llmKey: "bad" }, "s", "u", async () => ({ ok: false, status: 401 })), /401\).*API key/);
  });

  const conversation = [
    { role: "user", content: "U1" },
    { role: "assistant", content: "A1" },
    { role: "user", content: "U2" },
  ];

  await test("multi-turn: every provider carries the transcript in its own message format", () => {
    const anthropic = JSON.parse(Llm.buildRequest({ llmProvider: "anthropic", llmKey: "k" }, "SYS", conversation).init.body);
    assert.equal(anthropic.system, "SYS");
    assert.deepEqual(anthropic.messages, conversation);
    const openai = JSON.parse(Llm.buildRequest({ llmProvider: "openai", llmKey: "k" }, "SYS", conversation).init.body);
    assert.equal(openai.instructions, "SYS");
    assert.deepEqual(openai.input, conversation);
    const gemini = JSON.parse(Llm.buildRequest({ llmProvider: "gemini", llmKey: "k" }, "SYS", conversation).init.body);
    assert.deepEqual(gemini.contents, [
      { role: "user", parts: [{ text: "U1" }] },
      { role: "model", parts: [{ text: "A1" }] },
      { role: "user", parts: [{ text: "U2" }] },
    ]);
    const compatible = JSON.parse(Llm.buildRequest({ llmProvider: "openai-compatible", llmKey: "k" }, "SYS", conversation).init.body);
    assert.deepEqual(compatible.messages, [{ role: "system", content: "SYS" }, ...conversation]);
    assert.deepEqual(Llm.toMessages([{ role: "system", content: 3 }]), [{ role: "user", content: "3" }]);
  });

  await test("agent loop runs end-to-end through every provider without leaking keys", async () => {
    const policy = {
      rules: [
        { ruleId: 5, ruleName: "Block SSH for contractors", rulePriority: 1, ruleAction: "block", ruleIsEnabled: true, trafficScope: "private_network", ruleConditions: [{ attributeName: "umbrella.source.identity_ids", attributeValue: [11], attributeOperator: "INTERSECT" }, { attributeName: "umbrella.destination.all", attributeValue: true, attributeOperator: "=" }] },
        { ruleId: 9, ruleName: "Default", rulePriority: 9, ruleAction: "allow", ruleIsDefault: true, ruleConditions: [] },
      ],
      lookups: { sourceUsers: { 11: "Aang Leung (aang@corp.example)" } },
    };
    const script = [
      { action: "tool", tool: "search_sources", args: { query: "Aang" } },
      { action: "tool", tool: "list_rules", args: {} },
      { action: "decide", decision: { ruleId: "5", action: "block", verdictTitle: "Blocked at Firewall", summary: "Aang is named in the SSH block rule.", connection: "vpn", source: "Aang Leung", destination: "10.1.1.1", assumptions: [] } },
    ];
    const wrap = (provider, json) => provider === "anthropic" ? { content: [{ type: "text", text: json }] }
      : provider === "openai" ? { output_text: json }
        : provider === "gemini" ? { candidates: [{ content: { parts: [{ text: json }] } }] }
          : { choices: [{ message: { content: json } }] };
    for (const llmProvider of ["anthropic", "openai", "gemini", "openai-compatible"]) {
      const calls = [];
      const fetch = async (url, init) => { calls.push({ url, init }); return ok(wrap(llmProvider, JSON.stringify(script[calls.length - 1]))); };
      const settings = { llmKey: `${llmProvider}-secret`, llmProvider, llmModel: "", llmBaseUrl: llmProvider === "openai-compatible" ? "https://llm.example.net/v1" : "" };
      const result = await Agent.run({ text: "Can Aang on the VPN reach 10.1.1.1 over SSH?", policy, model, fetch, settings });
      assert.equal(result.status, "decided", llmProvider);
      assert.equal(result.decision.ruleId, "5");
      assert.equal(result.rule.name, "Block SSH for contractors");
      assert.equal(calls.length, 3);
      const last = JSON.parse(calls[2].init.body);
      const turns = last.messages || last.input || last.contents;
      assert.equal(turns.filter(turn => turn.role !== "system").length, 5, `${llmProvider} sends the whole transcript`);
      if (VENDOR_HOSTS[llmProvider]) assertKeyIsolation(calls, { [VENDOR_HOSTS[llmProvider]]: `${llmProvider}-secret`, "api.anthropic.com": "anthropic-secret" });
    }
  });

  await test("settings migration: legacy OpenAI-compatible and retired default model", () => {
    const custom = Agent.migrateSettings({ ...Agent.DEFAULTS, llmProvider: "openai", llmBaseUrl: "https://llm.example.net/v1", llmModel: "gpt-4.1-mini" });
    assert.equal(custom.llmProvider, "openai-compatible");
    assert.equal(custom.llmModel, "gpt-4.1-mini");
    const official = Agent.migrateSettings({ ...Agent.DEFAULTS, llmProvider: "openai", llmBaseUrl: "", llmModel: "gpt-4.1-mini" });
    assert.equal(official.llmProvider, "openai");
    assert.equal(official.llmModel, "gpt-6-luna");
    assert.equal(Agent.migrateSettings({ ...Agent.DEFAULTS, llmProvider: "bogus", llmModel: "" }).llmProvider, "anthropic");
    const legacy = Agent.migrateSettings({ ...Agent.DEFAULTS, jevKey: "old", jevModel: "jev-latest" });
    assert.ok(!("jevKey" in legacy) && !("jevModel" in legacy), "retired Jev settings are dropped");
    assert.equal(Agent.DEFAULTS.sttProvider, "browser");
  });

  await test("stt keys: dedicated key wins, same-vendor LLM key is reused, others are not", () => {
    assert.equal(Stt.sttKey({ sttProvider: "browser", llmProvider: "openai", llmKey: "x" }), "");
    assert.equal(Stt.sttKey({ sttProvider: "openai", llmProvider: "openai", llmKey: "llm" }), "llm");
    assert.equal(Stt.sttKey({ sttProvider: "openai", llmProvider: "openai", llmKey: "llm", sttKeyOpenai: "own" }), "own");
    assert.equal(Stt.sttKey({ sttProvider: "gemini", llmProvider: "anthropic", llmKey: "ant" }), "");
    assert.equal(Stt.sttKey({ sttProvider: "openai", llmProvider: "openai-compatible", llmKey: "local" }), "", "custom endpoints aren't OpenAI");
    assert.equal(Stt.sttKey({ sttProvider: "assemblyai", llmProvider: "gemini", llmKey: "g", sttKeyAssemblyai: "aai" }), "aai");
    assert.equal(Stt.sttModel({ sttProvider: "gemini" }), "gemini-3.5-transcribe");
    assert.equal(Stt.sttModel({ sttProvider: "openai", sttModel: "whisper-1" }), "whisper-1");
  });

  await test("stt gemini: inline base64 audio to generateContent on the transcribe model", async () => {
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, init }); return ok({ candidates: [{ content: { parts: [{ text: " Can Aang reach example.org? " }] } }] }); };
    const blob = new Blob([Uint8Array.from([1, 2, 3, 250])], { type: "audio/webm;codecs=opus" });
    const settings = { sttProvider: "gemini", llmProvider: "gemini", llmKey: "gem-key" };
    assert.equal(await Stt.transcribe(settings, blob, fetch), "Can Aang reach example.org?");
    const [{ url, init }] = calls;
    assert.equal(url, "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.5-transcribe:generateContent");
    assert.equal(init.headers["x-goog-api-key"], "gem-key");
    const parts = JSON.parse(init.body).contents[0].parts;
    assert.equal(parts.length, 1, "dedicated transcribe model needs no prompt");
    assert.deepEqual(parts[0].inlineData, { mimeType: "audio/webm", data: Buffer.from([1, 2, 3, 250]).toString("base64") });
    const general = Stt.buildTranscriptionRequest({ ...settings, sttModel: "gemini-3.8-flash" }, { mimeType: "audio/webm", base64: "AA==" });
    assert.match(JSON.parse(general.init.body).contents[0].parts[0].text, /Transcribe/);
  });

  await test("stt openai: multipart file + gpt-transcribe to /v1/audio/transcriptions", async () => {
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, init }); return ok({ text: "vpn to cisco.com", languages: [{ code: "en" }] }); };
    const blob = new Blob(["abc"], { type: "audio/webm" });
    assert.equal(await Stt.transcribe({ sttProvider: "openai", sttKeyOpenai: "sk-stt", llmProvider: "anthropic", llmKey: "sk-ant" }, blob, fetch), "vpn to cisco.com");
    const [{ url, init }] = calls;
    assert.equal(url, "https://api.openai.com/v1/audio/transcriptions");
    assert.equal(init.method, "POST");
    assert.equal(init.headers.authorization, "Bearer sk-stt");
    assert.equal("content-type" in init.headers, false, "fetch sets the multipart boundary");
    assert.ok(init.body instanceof FormData);
    assert.equal(init.body.get("model"), "gpt-transcribe");
    const file = init.body.get("file");
    assert.equal(file.name, "speech.webm");
    assert.equal(await file.text(), "abc");
    assertKeyIsolation(calls, { "api.anthropic.com": "sk-ant" });
    assert.equal(Stt.fileName("audio/mp4"), "speech.m4a");
    await assert.rejects(Stt.transcribe({ sttProvider: "openai" }, blob, fetch), /Add your OpenAI key/);
    await assert.rejects(Stt.transcribe({ sttProvider: "openai", sttKeyOpenai: "bad" }, blob, async () => ({ ok: false, status: 401 })), /401\).*voice key/);
  });

  await test("stt assemblyai: temporary token over HTTPS, key never in the socket URL", () => {
    const settings = { sttProvider: "assemblyai", sttKeyAssemblyai: "aai-key" };
    const { url, init } = Stt.assemblyTokenRequest(settings);
    const parsed = new URL(url);
    assert.equal(parsed.origin + parsed.pathname, "https://streaming.assemblyai.com/v3/token");
    assert.equal(parsed.searchParams.get("expires_in_seconds"), "60");
    assert.equal(parsed.searchParams.get("max_session_duration_seconds"), "90");
    assert.equal(init.method, "GET");
    assert.equal(init.headers.authorization, "aai-key", "no Bearer prefix");
    const ws = new URL(Stt.assemblyStreamUrl("tmp-token", Stt.sttModel(settings), 16000));
    assert.equal(ws.origin + ws.pathname, "wss://streaming.assemblyai.com/v3/ws");
    assert.deepEqual(Object.fromEntries(ws.searchParams), { token: "tmp-token", speech_model: "universal-3-6-pro", sample_rate: "16000", encoding: "pcm_s16le" });
    assert.deepEqual([...Stt.floatToPcm16(Float32Array.from([0, 1, -1, 2, 0.5]))], [0, 32767, -32768, 32767, 16383]);
    const turns = Stt.turnCollector();
    turns.apply({ type: "Turn", turn_order: 0, transcript: "can aang", end_of_turn: false });
    turns.apply({ type: "Turn", turn_order: 0, transcript: "Can Aang reach", end_of_turn: true });
    turns.apply({ type: "Turn", turn_order: 1, transcript: "example.org?", end_of_turn: true });
    assert.equal(turns.apply({ type: "Begin", id: "x" }), false);
    assert.equal(turns.text(), "Can Aang reach example.org?");
  });

  await test("stt assemblyai: stream sends PCM16 chunks, terminates, returns turns", async () => {
    const sockets = [];
    class FakeSocket {
      constructor(url) { this.url = url; this.readyState = 0; this.sent = []; sockets.push(this); setTimeout(() => { this.readyState = 1; this.onopen(); }, 0); }
      send(data) {
        this.sent.push(data);
        if (typeof data === "string" && JSON.parse(data).type === "Terminate") {
          setTimeout(() => {
            this.onmessage({ data: JSON.stringify({ type: "Turn", turn_order: 0, transcript: "VPN to cisco.com", end_of_turn: true }) });
            this.onmessage({ data: JSON.stringify({ type: "Termination" }) });
            this.readyState = 3;
            this.onclose({ code: 1000 });
          }, 0);
        }
      }
      close() { this.readyState = 3; }
    }
    let worklet;
    const modules = [];
    globalThis.AudioWorkletNode = class { constructor(ctx, name) { this.name = name; this.port = {}; worklet = this; } connect() {} disconnect() {} };
    class FakeContext {
      constructor(options) { this.sampleRate = options.sampleRate; this.destination = {}; this.closed = false; this.audioWorklet = { addModule: async url => modules.push(url) }; }
      createMediaStreamSource() { return { connect() {}, disconnect() {} }; }
      close() { this.closed = true; }
    }
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, init }); return ok({ token: "tmp-123" }); };
    const partials = [];
    const session = await Stt.startAssemblyStream({
      settings: { sttProvider: "assemblyai", sttKeyAssemblyai: "aai-secret" }, stream: {}, fetch,
      WebSocket: FakeSocket, AudioContext: FakeContext, workletUrl: "chrome-extension://x/popup/pcm-capture-worklet.js",
      onText: value => partials.push(value),
    });
    assert.equal(worklet.name, "pcm-capture");
    assert.deepEqual(modules, ["chrome-extension://x/popup/pcm-capture-worklet.js"]);
    const socket = sockets[0];
    assert.ok(socket.url.includes("token=tmp-123"));
    assert.ok(!socket.url.includes("aai-secret"));
    worklet.port.onmessage({ data: new Float32Array(400).fill(0.5) });
    assert.equal(socket.sent.length, 0, "buffers until 50 ms");
    worklet.port.onmessage({ data: new Float32Array(400).fill(0.5) });
    assert.equal(socket.sent.length, 1);
    assert.equal(socket.sent[0].byteLength, 800 * 2);
    worklet.port.onmessage({ data: new Float32Array(100) });
    const text = await session.stop();
    assert.equal(text, "VPN to cisco.com");
    assert.equal(socket.sent[1].byteLength, 200, "remaining audio flushed before Terminate");
    assert.deepEqual(JSON.parse(socket.sent[2]), { type: "Terminate" });
    assert.deepEqual(partials, ["VPN to cisco.com"]);
    assert.equal(calls.length, 1);
    await assert.rejects(
      Stt.startAssemblyStream({ settings: { sttProvider: "assemblyai", sttKeyAssemblyai: "bad" }, stream: {}, fetch: async () => ({ ok: false, status: 401 }), WebSocket: FakeSocket, AudioContext: FakeContext }),
      /token request failed \(401\)/,
    );
    delete globalThis.AudioWorkletNode;
  });

  await test("recorder: MediaRecorder chunks become one typed Blob", async () => {
    class FakeRecorder {
      static isTypeSupported(type) { return type === "audio/webm;codecs=opus"; }
      constructor(stream, options) { this.mimeType = options.mimeType; this.state = "inactive"; }
      start() { this.state = "recording"; }
      stop() {
        this.state = "inactive";
        this.ondataavailable({ data: new Blob(["ab"]) });
        this.ondataavailable({ data: new Blob(["cd"]) });
        this.onstop();
      }
    }
    const recording = Stt.startRecording({}, { MediaRecorder: FakeRecorder });
    const blob = await recording.stop();
    assert.equal(blob.type, "audio/webm;codecs=opus");
    assert.equal(await blob.text(), "abcd");
  });

  console.log(`describe-providers: ${passed} passed`);
})().catch(error => { console.error(error); process.exit(1); });
