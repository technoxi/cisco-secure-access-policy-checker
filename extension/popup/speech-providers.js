// Speech-to-text for Describe mode. "browser" is the Web Speech API (handled in
// the panel); the others record or stream the mic straight to the vendor.
(function (root) {
  "use strict";

  const Llm = root.LlmProviders || (typeof require === "function" ? require("./llm-providers.js") : null);
  const PROVIDERS = {
    browser: { label: "Browser built-in (free)", vendor: null, defaultModel: "" },
    gemini: { label: "Google Gemini", vendor: "gemini", defaultModel: "gemini-3.5-transcribe", keyField: "sttKeyGemini" },
    openai: { label: "OpenAI", vendor: "openai", defaultModel: "gpt-transcribe", keyField: "sttKeyOpenai" },
    assemblyai: { label: "AssemblyAI (live)", vendor: "assemblyai", defaultModel: "universal-3-6-pro", keyField: "sttKeyAssemblyai", streaming: true },
  };
  const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta";
  const OPENAI_BASE = "https://api.openai.com/v1";
  const ASSEMBLY_TOKEN_URL = "https://streaming.assemblyai.com/v3/token";
  const ASSEMBLY_WS_URL = "wss://streaming.assemblyai.com/v3/ws";
  const MAX_RECORDING_MS = 60000;
  const STREAM_CHUNK_MS = 50;
  const scriptUrl = (() => { try { return root.document && root.document.currentScript && root.document.currentScript.src; } catch (_) { return ""; } })();

  function providerId(value) {
    return Object.prototype.hasOwnProperty.call(PROVIDERS, value) ? value : "browser";
  }

  // A dedicated STT key wins; otherwise reuse the LLM key when it belongs to the same vendor.
  function sttKey(settings) {
    const id = providerId(settings.sttProvider);
    const provider = PROVIDERS[id];
    if (!provider.keyField) return "";
    if (settings[provider.keyField]) return settings[provider.keyField];
    const llm = Llm && Llm.PROVIDERS[settings.llmProvider];
    return llm && llm.vendor === provider.vendor ? settings.llmKey || "" : "";
  }

  function sttModel(settings) {
    return settings.sttModel || PROVIDERS[providerId(settings.sttProvider)].defaultModel;
  }

  function baseMime(mimeType) {
    return String(mimeType || "audio/webm").split(";")[0].trim().toLowerCase() || "audio/webm";
  }

  function fileName(mimeType) {
    const ext = { "audio/webm": "webm", "audio/ogg": "ogg", "audio/mp4": "m4a", "audio/mpeg": "mp3", "audio/wav": "wav", "audio/x-wav": "wav" }[baseMime(mimeType)];
    return `speech.${ext || "webm"}`;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return root.btoa(binary);
  }

  // audio: { blob, mimeType, base64 } (base64 only needed for Gemini)
  function buildTranscriptionRequest(settings, audio) {
    const id = providerId(settings.sttProvider);
    const key = sttKey(settings);
    const model = sttModel(settings);
    if (id === "gemini") {
      const parts = [{ inlineData: { mimeType: baseMime(audio.mimeType), data: audio.base64 } }];
      if (!/transcribe/i.test(model)) parts.unshift({ text: "Transcribe this speech verbatim. Reply with the transcript only." });
      return {
        url: `${GEMINI_BASE}/models/${encodeURIComponent(model)}:generateContent`,
        init: {
          method: "POST",
          headers: { "content-type": "application/json", "x-goog-api-key": key },
          body: JSON.stringify({ contents: [{ role: "user", parts }] }),
        },
      };
    }
    if (id === "openai") {
      const form = new root.FormData();
      form.append("file", audio.blob, fileName(audio.mimeType));
      form.append("model", model);
      return { url: `${OPENAI_BASE}/audio/transcriptions`, init: { method: "POST", headers: { authorization: `Bearer ${key}` }, body: form } };
    }
    throw new Error(`${PROVIDERS[id].label} doesn't transcribe recordings.`);
  }

  function readTranscription(providerValue, body) {
    const id = providerId(providerValue);
    body = body || {};
    if (id === "gemini") return Llm.readText("gemini", body).trim();
    if (id === "openai") return String(body.text || "").trim();
    return "";
  }

  async function transcribe(settings, blob, fetchImpl) {
    const id = providerId(settings.sttProvider);
    if (!sttKey(settings)) throw new Error(`Add your ${PROVIDERS[id].label} key for voice input in Describe settings.`);
    const mimeType = blob.type || "audio/webm";
    const audio = { blob, mimeType };
    if (id === "gemini") audio.base64 = bytesToBase64(new Uint8Array(await blob.arrayBuffer()));
    const { url, init } = buildTranscriptionRequest(settings, audio);
    const response = await fetchImpl(url, init);
    if (!response.ok) throw new Error(requestError("Transcription", response.status));
    return readTranscription(id, await response.json());
  }

  function requestError(what, status) {
    const hint = status === 401 || status === 403 ? " Check the voice key in Describe settings." : "";
    return `${what} request failed (${status}).${hint}`;
  }

  // AssemblyAI streaming: browsers can't set WebSocket headers, so the key only
  // mints a short-lived token over HTTPS and the socket authenticates with that.
  function assemblyTokenRequest(settings) {
    const query = new URLSearchParams({ expires_in_seconds: "60", max_session_duration_seconds: "90" });
    return { url: `${ASSEMBLY_TOKEN_URL}?${query}`, init: { method: "GET", headers: { authorization: sttKey(settings) } } };
  }

  function assemblyStreamUrl(token, model, sampleRate) {
    const query = new URLSearchParams({ token, speech_model: model, sample_rate: String(sampleRate), encoding: "pcm_s16le" });
    return `${ASSEMBLY_WS_URL}?${query}`;
  }

  function floatToPcm16(samples) {
    const out = new Int16Array(samples.length);
    for (let i = 0; i < samples.length; i++) {
      const value = Math.max(-1, Math.min(1, samples[i]));
      out[i] = value < 0 ? value * 0x8000 : value * 0x7fff;
    }
    return out;
  }

  function turnCollector() {
    const turns = new Map();
    return {
      apply(message) {
        if (!message || message.type !== "Turn") return false;
        turns.set(Number(message.turn_order) || 0, String(message.transcript || ""));
        return true;
      },
      text() { return [...turns.entries()].sort((a, b) => a[0] - b[0]).map(entry => entry[1].trim()).filter(Boolean).join(" "); },
    };
  }

  // Browser only. Returns { stop(): Promise<Blob>, cancel() }.
  function startRecording(stream, options) {
    const Recorder = (options && options.MediaRecorder) || root.MediaRecorder;
    if (!Recorder) throw new Error("Recording isn't available in this browser.");
    const preferred = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4"].find(type => !Recorder.isTypeSupported || Recorder.isTypeSupported(type));
    const recorder = new Recorder(stream, preferred ? { mimeType: preferred } : undefined);
    const chunks = [];
    recorder.ondataavailable = event => { if (event.data && event.data.size) chunks.push(event.data); };
    const done = new Promise((resolve, reject) => {
      recorder.onstop = () => resolve(new Blob(chunks, { type: recorder.mimeType || preferred || "audio/webm" }));
      recorder.onerror = event => reject(new Error((event && event.error && event.error.message) || "Recording failed."));
    });
    recorder.start();
    return {
      stop() { if (recorder.state !== "inactive") recorder.stop(); return done; },
      cancel() { recorder.ondataavailable = null; if (recorder.state !== "inactive") recorder.stop(); },
    };
  }

  // Browser only. Returns { stop(): Promise<string>, cancel() }; onText gets live partials.
  async function startAssemblyStream(options) {
    const { settings, stream, onText } = options;
    const fetchImpl = options.fetch || root.fetch.bind(root);
    const Socket = options.WebSocket || root.WebSocket;
    const Context = options.AudioContext || root.AudioContext || root.webkitAudioContext;
    if (!sttKey(settings)) throw new Error("Add your AssemblyAI key for voice input in Describe settings.");
    const { url, init } = assemblyTokenRequest(settings);
    const response = await fetchImpl(url, init);
    if (!response.ok) throw new Error(requestError("AssemblyAI token", response.status));
    const { token } = await response.json();
    if (!token) throw new Error("AssemblyAI didn't return a streaming token.");

    const context = new Context({ sampleRate: 16000 });
    const cleanup = () => {
      try { source && source.disconnect(); } catch (_) {}
      try { worklet && worklet.disconnect(); } catch (_) {}
      try { context.close(); } catch (_) {}
      try { if (socket.readyState <= 1) socket.close(); } catch (_) {}
    };
    let source = null;
    let worklet = null;
    try {
      await context.audioWorklet.addModule(options.workletUrl || new URL("pcm-capture-worklet.js", scriptUrl || root.location.href).href);
    } catch (error) { try { context.close(); } catch (_) {} throw error; }
    const socket = new Socket(assemblyStreamUrl(token, sttModel(settings), context.sampleRate));
    socket.binaryType = "arraybuffer";
    const collector = turnCollector();
    let failure = "";
    let finish;
    const finished = new Promise(resolve => { finish = resolve; });
    socket.onmessage = event => {
      let message;
      try { message = JSON.parse(event.data); } catch (_) { return; }
      if (collector.apply(message)) { if (onText) onText(collector.text()); return; }
      if (message.type === "Termination") finish();
      else if (message.error) failure = String(message.error);
    };
    socket.onclose = event => {
      if (event && event.code && event.code !== 1000 && !failure) failure = event.reason || `AssemblyAI closed the stream (${event.code}).`;
      finish();
    };
    try {
      await new Promise((resolve, reject) => {
        socket.onopen = resolve;
        socket.onerror = () => reject(new Error("Couldn't connect to AssemblyAI."));
      });
    } catch (error) { cleanup(); throw error; }

    const chunkSamples = Math.round(context.sampleRate * STREAM_CHUNK_MS / 1000);
    let pending = [];
    let pendingLength = 0;
    const flush = () => {
      if (!pendingLength || socket.readyState !== 1) return;
      const merged = new Float32Array(pendingLength);
      let offset = 0;
      for (const part of pending) { merged.set(part, offset); offset += part.length; }
      pending = [];
      pendingLength = 0;
      socket.send(floatToPcm16(merged).buffer);
    };
    source = context.createMediaStreamSource(stream);
    worklet = new root.AudioWorkletNode(context, "pcm-capture");
    worklet.port.onmessage = event => {
      pending.push(event.data);
      pendingLength += event.data.length;
      if (pendingLength >= chunkSamples) flush();
    };
    source.connect(worklet);
    worklet.connect(context.destination);

    return {
      async stop() {
        worklet.port.onmessage = null;
        flush();
        if (socket.readyState === 1) socket.send(JSON.stringify({ type: "Terminate" }));
        await Promise.race([finished, new Promise(resolve => setTimeout(resolve, 4000))]);
        cleanup();
        const text = collector.text();
        if (!text && failure) throw new Error(failure);
        return text;
      },
      cancel() {
        worklet.port.onmessage = null;
        try { if (socket.readyState === 1) socket.send(JSON.stringify({ type: "Terminate" })); } catch (_) {}
        cleanup();
      },
    };
  }

  root.SpeechProviders = {
    PROVIDERS, MAX_RECORDING_MS, providerId, sttKey, sttModel, fileName, bytesToBase64,
    buildTranscriptionRequest, readTranscription, transcribe,
    assemblyTokenRequest, assemblyStreamUrl, floatToPcm16, turnCollector,
    startRecording, startAssemblyStream,
  };
  if (typeof module !== "undefined" && module.exports) module.exports = root.SpeechProviders;
})(typeof window !== "undefined" ? window : globalThis);
