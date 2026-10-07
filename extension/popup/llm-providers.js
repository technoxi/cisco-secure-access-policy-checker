// LLM vendor adapters for Describe mode: one request builder and one response
// reader per vendor, so the agent stays vendor-neutral and tests can check shapes.
(function (root) {
  "use strict";

  const PROVIDERS = {
    anthropic: { label: "Anthropic", vendor: "anthropic", defaultModel: "claude-haiku-4-5", defaultBase: "https://api.anthropic.com" },
    openai: { label: "OpenAI", vendor: "openai", defaultModel: "gpt-6-luna", defaultBase: "https://api.openai.com/v1" },
    gemini: { label: "Google Gemini", vendor: "gemini", defaultModel: "gemini-3.5-flash-lite", defaultBase: "https://generativelanguage.googleapis.com/v1beta" },
    "openai-compatible": { label: "OpenAI-compatible (custom URL)", vendor: null, defaultModel: "gpt-6-luna", defaultBase: "https://api.openai.com/v1" },
  };
  const DEFAULT_MODELS = Object.fromEntries(Object.entries(PROVIDERS).map(([id, p]) => [id, p.defaultModel]));
  const MAX_TOKENS = 1200;

  function providerId(value) {
    return Object.prototype.hasOwnProperty.call(PROVIDERS, value) ? value : "anthropic";
  }

  function baseUrl(settings, id) {
    return String(settings.llmBaseUrl || PROVIDERS[id].defaultBase).trim().replace(/\/+$/, "");
  }

  // Gemini responseSchema is an OpenAPI subset: uppercase types, `nullable` instead of type arrays.
  function toGeminiSchema(schema) {
    if (!schema || typeof schema !== "object") return schema;
    const out = {};
    let type = schema.type;
    if (Array.isArray(type)) {
      if (type.includes("null")) out.nullable = true;
      type = type.find(item => item !== "null");
    }
    if (type) out.type = String(type).toUpperCase();
    // Gemini enums can't express "none" as ""; leave the field free and let code validate.
    if (schema.enum && !schema.enum.includes("")) out.enum = schema.enum;
    if (schema.description) out.description = schema.description;
    if (schema.properties) {
      out.properties = Object.fromEntries(Object.entries(schema.properties).map(([key, value]) => [key, toGeminiSchema(value)]));
      out.propertyOrdering = Object.keys(schema.properties);
    }
    if (schema.required) out.required = schema.required;
    if (schema.items) out.items = toGeminiSchema(schema.items);
    return out;
  }

  // `conversation` is a single user string or [{ role: "user" | "assistant", content }].
  function toMessages(conversation) {
    if (!Array.isArray(conversation)) return [{ role: "user", content: String(conversation || "") }];
    return conversation.map(message => ({ role: message.role === "assistant" ? "assistant" : "user", content: String(message.content || "") }));
  }

  function buildRequest(settings, system, conversation, schema) {
    const messages = toMessages(conversation);
    const id = providerId(settings.llmProvider);
    const model = settings.llmModel || PROVIDERS[id].defaultModel;
    const key = settings.llmKey;
    const base = baseUrl(settings, id);
    const json = { "content-type": "application/json" };
    if (id === "anthropic") {
      const body = { model, max_tokens: MAX_TOKENS, system, messages };
      if (schema) body.output_config = { format: { type: "json_schema", schema } };
      return {
        url: `${base}/v1/messages`,
        init: {
          method: "POST",
          headers: { ...json, "x-api-key": key, "anthropic-version": "2023-06-01", "anthropic-dangerous-direct-browser-access": "true" },
          body: JSON.stringify(body),
        },
      };
    }
    if (id === "openai") {
      const body = {
        model, instructions: system, store: false, max_output_tokens: 3000,
        input: Array.isArray(conversation) ? messages : messages[0].content,
        text: { format: schema ? { type: "json_schema", name: "traffic_check", strict: true, schema } : { type: "json_object" } },
      };
      // Reasoning models spend latency on thinking by default; extraction doesn't need it.
      if (/^(gpt-[5-9]|o\d)/i.test(model)) body.reasoning = { effort: "low" };
      return {
        url: `${base}/responses`,
        init: { method: "POST", headers: { ...json, authorization: `Bearer ${key}` }, body: JSON.stringify(body) },
      };
    }
    if (id === "gemini") {
      const generationConfig = { responseMimeType: "application/json" };
      if (schema) generationConfig.responseSchema = toGeminiSchema(schema);
      return {
        url: `${base}/models/${encodeURIComponent(model)}:generateContent`,
        init: {
          method: "POST",
          headers: { ...json, "x-goog-api-key": key },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: system }] },
            contents: messages.map(message => ({ role: message.role === "assistant" ? "model" : "user", parts: [{ text: message.content }] })),
            generationConfig,
          }),
        },
      };
    }
    return {
      url: `${base}/chat/completions`,
      init: {
        method: "POST",
        headers: { ...json, authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model, temperature: 0, response_format: { type: "json_object" },
          messages: [{ role: "system", content: system }, ...messages],
        }),
      },
    };
  }

  function readText(providerValue, body) {
    const id = providerId(providerValue);
    body = body || {};
    if (id === "anthropic") return ((body.content || []).find(part => part.type === "text") || {}).text || "";
    if (id === "openai") {
      if (typeof body.output_text === "string") return body.output_text;
      const parts = [];
      for (const item of body.output || []) {
        if (item.type !== "message") continue;
        for (const part of item.content || []) {
          if (part.type === "refusal") throw new Error("The language model declined the request.");
          if (part.type === "output_text") parts.push(part.text);
        }
      }
      return parts.join("");
    }
    if (id === "gemini") {
      const candidate = (body.candidates || [])[0];
      const parts = (candidate && candidate.content && candidate.content.parts) || [];
      return parts.filter(part => typeof part.text === "string" && !part.thought).map(part => part.text).join("");
    }
    const choice = body.choices && body.choices[0];
    return (choice && choice.message && choice.message.content) || "";
  }

  async function call(settings, system, conversation, fetchImpl, schema) {
    const { url, init } = buildRequest(settings, system, conversation, schema);
    const response = await fetchImpl(url, init);
    if (!response.ok) {
      const hint = response.status === 401 || response.status === 403 ? " Check the API key in Describe settings." : "";
      throw new Error(`Language model request failed (${response.status}).${hint}`);
    }
    return readText(settings.llmProvider, await response.json());
  }

  root.LlmProviders = { PROVIDERS, DEFAULT_MODELS, providerId, buildRequest, readText, call, toGeminiSchema, toMessages };
  if (typeof module !== "undefined" && module.exports) module.exports = root.LlmProviders;
})(typeof window !== "undefined" ? window : globalThis);
