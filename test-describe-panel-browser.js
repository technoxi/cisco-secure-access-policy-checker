'use strict';
const assert = require('node:assert/strict');
async function main() {
  const targets = await (await fetch('http://127.0.0.1:9333/json/list')).json();
  const target = targets.find(t => t.type === 'page' && t.url.includes('/qa/ui-checker.html'));
  assert.ok(target, 'existing checker fixture on CDP9333');
  const socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise(resolve => socket.addEventListener('open', resolve, { once: true }));
  let seq = 0;
  const pending = new Map();
  socket.addEventListener('message', event => {
    const msg = JSON.parse(event.data);
    if (pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
  });
  const call = (method, params) => new Promise(resolve => { const id = ++seq; pending.set(id, resolve); socket.send(JSON.stringify({ id, method, params })); });
  try {
    await call('Emulation.setDeviceMetricsOverride', { width: 420, height: 320, deviceScaleFactor: 1, mobile: false });
    const result = await call('Runtime.evaluate', { awaitPromise: true, returnByValue: true, expression: `(${browserTests.toString()})(${JSON.stringify(require('node:fs').readFileSync('extension/popup/describe-panel.js', 'utf8'))}, ${JSON.stringify(require('node:fs').readFileSync('extension/popup/traffic-path.css', 'utf8').match(/\.tp-describe-settings \{[^}]+\}/)[0])})` });
    assert.ok(!result.result.exceptionDetails, JSON.stringify(result.result.exceptionDetails));
    console.log(result.result.result.value);
  } finally { await call('Emulation.clearDeviceMetricsOverride', {}); socket.close(); }
}
async function browserTests(source, settingsCss) {
  const check = (ok, label) => { if (!ok) throw new Error(label); };
  const tick = () => new Promise(resolve => setTimeout(resolve, 0));
  (0, eval)(source);
  const original = { agent: window.DescribeAgent, speech: window.SpeechRecognition, stt: window.SpeechProviders };
  const sttMethods = { sttKey: original.stt.sttKey, startRecording: original.stt.startRecording, transcribe: original.stt.transcribe };
  const mount = document.createElement('div');
  mount.style.cssText = 'position:fixed;top:0;left:0;width:400px;z-index:9999';
  const style = document.createElement('style');
  style.textContent = settingsCss;
  document.head.append(style);
  document.body.append(mount);
  let speech, calls = [], fail = false, deferred, recordingCancelled = 0, tracksStopped = 0;
  const settings = { ...original.agent.DEFAULTS, sttProvider: 'browser' };
  window.SpeechRecognition = class {
    constructor() { speech = this; }
    start() {}
    abort() { this.aborted = true; }
  };
  window.DescribeAgent = {
    ...original.agent, loadSettings: async () => settings, needsKey: () => false,
    run: async args => {
      calls.push(args);
      if (!args.messages) return { status: 'needs_input', messages: [{ role: 'assistant', content: 'question' }], question: { text: 'Which source?', options: [] } };
      if (fail) return { status: 'error', error: 'Provider failed', messages: [...args.messages, { role: 'user', content: "Admin's answer: Alice" }] };
      return { status: 'needs_input', messages: args.messages, question: { text: 'Next detail?', options: [] } };
    },
  };
  const panel = window.DescribePanel.create({ model: { CONNECTIONS: {} }, isReady: () => true, getPolicy: async () => ({}), clearResults() {}, showResult() {} });
  mount.append(panel.element);
  const q = selector => panel.element.querySelector(selector);
  try {
    await tick();
    panel.toggleSettings(true);
    q('textarea').focus();
    q('textarea').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    check(q('.tp-describe-settings').hidden, 'Escape with outside focus');
    panel.toggleSettings(true);
    const rect = q('.tp-describe-settings').getBoundingClientRect();
    check(rect.top >= 0 && rect.bottom <= innerHeight && rect.left >= 0 && rect.right <= innerWidth, 'settings viewport bounds');
    panel.toggleSettings(false);
    mount.style.top = 'auto'; mount.style.bottom = '0';
    panel.toggleSettings(true);
    await new Promise(resolve => setTimeout(resolve, 200));
    const flipped = q('.tp-describe-settings').getBoundingClientRect();
    check(flipped.top >= 0 && flipped.bottom <= innerHeight && flipped.bottom <= q('.tp-describe-gear').getBoundingClientRect().top, 'settings flips above low anchor');
    panel.toggleSettings(false);
    mount.style.bottom = 'auto'; mount.style.top = '0';
    q('textarea').value = 'Traffic';
    await panel.submit();
    check(!q('.tp-clarify').hidden, 'clarification shown');
    q('textarea').dispatchEvent(new Event('input', { bubbles: true }));
    check(q('.tp-clarify').hidden && !q('.tp-agent-steps').children.length, 'input clears obsolete UI');
    await panel.submit();
    fail = true;
    q('.tp-clarify-reply input').value = 'Alice';
    q('.tp-clarify-reply').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    await tick();
    check(calls.at(-1).answer === 'Alice', 'answer submitted');
    fail = false;
    q('.tp-error button').click();
    await tick();
    check(calls.at(-1).answer === undefined && calls.at(-1).messages.at(-1).content === "Admin's answer: Alice", 'retry preserves answer without duplication');
    q('.tp-describe-mic').click();
    const lateResult = speech.onresult, lateEnd = speech.onend, count = calls.length;
    panel.cancel(false);
    lateResult({ results: [{ isFinal: true, 0: { transcript: 'late words' } }] });
    lateEnd();
    await tick();
    check(speech.aborted && calls.length === count && !q('textarea').value.includes('late words'), 'mode cancellation stops browser voice and auto-submit');
    settings.sttProvider = 'openai';
    window.SpeechProviders = original.stt;
    original.stt.sttKey = () => 'fixture';
    original.stt.startRecording = () => ({ cancel() { recordingCancelled++; }, stop: async () => new Blob(['audio']) });
    original.stt.transcribe = () => new Promise(resolve => { deferred = resolve; });
    const media = navigator.mediaDevices.getUserMedia;
    navigator.mediaDevices.getUserMedia = async () => ({ getTracks: () => [{ stop() { tracksStopped++; } }] });
    try {
      q('.tp-describe-mic').click(); await tick();
      panel.cancel(false);
      check(recordingCancelled === 1 && tracksStopped > 0, 'mode cancellation stops recording and tracks');
      q('.tp-describe-mic').click(); await tick();
      q('.tp-describe-mic').click(); await tick();
      check(!!deferred, 'transcription pending');
      const before = calls.length;
      panel.cancel(false);
      deferred('late transcription'); await tick();
      check(calls.length === before && !q('textarea').value.includes('late transcription') && !q('.tp-describe-mic').disabled, 'cancel transcription prevents submit and clears busy state');
    } finally { navigator.mediaDevices.getUserMedia = media; }
    return 'PASS real Describe handlers: Escape, viewport bounds, input invalidation, answer retry, browser voice, recording and transcription cancellation';
  } finally {
    panel.reset(); mount.remove(); style.remove();
    window.DescribeAgent = original.agent;
    window.SpeechRecognition = original.speech;
    Object.assign(original.stt, sttMethods);
    window.SpeechProviders = original.stt;
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
