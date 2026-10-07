"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");

async function main() {
  const list = await (await fetch("http://127.0.0.1:9333/json/list")).json();
  const page = list.find(p => p.type === "page" && p.url.includes("/qa/ui-checker.html"));
  assert.ok(page, "fixture page found on CDP 9333");
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise(r => ws.onopen = r);

  let seq = 1;
  const pending = new Map();
  ws.onmessage = (e) => {
    const msg = JSON.parse(e.data);
    if (pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  };

  const call = (method, params = {}) => new Promise(res => {
    const id = seq++;
    pending.set(id, res);
    ws.send(JSON.stringify({ id, method, params }));
  });

  // Reload the page so modified qa/ui-checker.js is loaded
  await call("Page.reload");
  await new Promise(r => setTimeout(r, 1000));

  const evaluate = async (expr) => {
    const r = await call("Runtime.evaluate", {
      expression: expr,
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.result.exceptionDetails) {
      throw new Error(`Eval error: ${JSON.stringify(r.result.exceptionDetails)}`);
    }
    return r.result.result.value;
  };

  const screenshot = async (filename) => {
    const shot = await call("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(filename, Buffer.from(shot.result.data, "base64"));
  };

  console.log("=== Testing Flow 1: Blank source on Secure Client ===");
  const flow1 = await evaluate(`(async () => {
    // Select Secure Client connection
    document.querySelector('input[name="tp-connection"][value="client"]').click();
    // Fill destination only
    const destInput = document.querySelector('#tp-destination');
    destInput.value = "example.com";
    destInput.dispatchEvent(new Event("input", { bubbles: true }));
    // Submit form
    document.querySelector('form.tp-form').dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 500));
    const title = document.querySelector('.tp-outcome-title')?.innerText;
    const stages = Array.from(document.querySelectorAll('.tp-stage')).map(s => ({
      name: s.querySelector('.tp-stage-name')?.innerText,
      state: s.className,
      action: s.querySelector('.tp-action')?.innerText,
      rule: s.querySelector('.tp-stage-rule')?.innerText,
    }));
    return { title, stages };
  })()`);
  console.log("Flow 1 result:", JSON.stringify(flow1, null, 2));
  assert.equal(flow1.title, "Allowed");
  assert.equal(flow1.stages.length, 2);
  assert.equal(flow1.stages[0].action, "Allow");

  console.log("=== Testing Flow 2: User-only on Secure Client ===");
  const flow2 = await evaluate(`(async () => {
    // Set user only, roaming blank
    const userPicker = document.querySelector('#tp-src-identity');
    userPicker.focus();
    userPicker.value = "Denise Adams (denise.adams@example.org)";
    userPicker.dispatchEvent(new Event("input", { bubbles: true }));
    userPicker.dispatchEvent(new Event("blur", { bubbles: true }));
    document.querySelector('form.tp-form').dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 500));
    const title = document.querySelector('.tp-outcome-title')?.innerText;
    const summary = document.querySelector('.tp-outcome-rule')?.innerText;
    return { title, summary };
  })()`);
  console.log("Flow 2 result:", JSON.stringify(flow2, null, 2));
  assert.equal(flow2.title, "Allowed");

  console.log("=== Testing Flow 3: Remote Access VPN with blank source ===");
  const flow3 = await evaluate(`(async () => {
    document.querySelector('input[name="tp-connection"][value="vpn"]').click();
    // Clear user picker
    const userPicker = document.querySelector('#tp-src-identity');
    userPicker.value = "";
    userPicker.dispatchEvent(new Event("input", { bubbles: true }));
    userPicker.dispatchEvent(new Event("blur", { bubbles: true }));
    const destInput = document.querySelector('#tp-destination');
    destInput.value = "10.141.46.1";
    destInput.dispatchEvent(new Event("input", { bubbles: true }));
    const portInput = document.querySelector('#tp-port');
    if (portInput) {
      portInput.value = "443";
      portInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    document.querySelector('form.tp-form').dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 500));
    const error = document.querySelector('.tp-error')?.innerText;
    const title = document.querySelector('.tp-outcome-title')?.innerText;
    const stages = Array.from(document.querySelectorAll('.tp-stage')).map(s => ({
      name: s.querySelector('.tp-stage-name')?.innerText,
      state: s.className,
      action: s.querySelector('.tp-action')?.innerText,
    }));
    return { error, title, stages };
  })()`);
  console.log("Flow 3 result:", JSON.stringify(flow3, null, 2));
  assert.equal(flow3.error || "", "");
  assert.ok(flow3.title, "Should produce an outcome title");

  console.log("=== Testing Flow 4: Exclusion - Bypass Secure Access (ninjarmm.com) ===");
  const flow4 = await evaluate(`(async () => {
    document.querySelector('input[name="tp-connection"][value="client"]').click();
    const destInput = document.querySelector('#tp-destination');
    destInput.value = "ninjarmm.com";
    destInput.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector('form.tp-form').dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 500));
    const title = document.querySelector('.tp-outcome-title')?.innerText;
    const summary = document.querySelector('.tp-outcome-rule')?.innerText;
    const stages = Array.from(document.querySelectorAll('.tp-stage')).map(s => ({
      name: s.querySelector('.tp-stage-name')?.innerText,
      action: s.querySelector('.tp-action')?.innerText,
      meta: s.querySelector('.tp-stage-meta')?.innerText,
    }));
    return { title, summary, stages };
  })()`);
  console.log("Flow 4 result:", JSON.stringify(flow4, null, 2));
  assert.equal(flow4.title, "Bypassed via Traffic Steering");
  assert.equal(flow4.stages[0].action, "Bypassed");
  assert.equal(flow4.stages[1].action, "Bypassed");

  console.log("=== Testing Flow 5: Exclusion - Bypass Web Proxy (api.us-2.crowdstrike.com) ===");
  const flow5 = await evaluate(`(async () => {
    const destInput = document.querySelector('#tp-destination');
    destInput.value = "api.us-2.crowdstrike.com";
    destInput.dispatchEvent(new Event("input", { bubbles: true }));
    document.querySelector('form.tp-form').dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise(r => setTimeout(r, 500));
    const title = document.querySelector('.tp-outcome-title')?.innerText;
    const stages = Array.from(document.querySelectorAll('.tp-stage')).map(s => ({
      name: s.querySelector('.tp-stage-name')?.innerText,
      action: s.querySelector('.tp-action')?.innerText,
      meta: s.querySelector('.tp-stage-meta')?.innerText,
    }));
    return { title, stages };
  })()`);
  console.log("Flow 5 result:", JSON.stringify(flow5, null, 2));
  assert.equal(flow5.title, "Allowed");
  assert.equal(flow5.stages[0].action, "Allow");
  assert.equal(flow5.stages[1].action, "Bypassed");
  assert.match(flow5.stages[1].meta, /Bypass Web Proxy/);

  console.log("=== Testing Flow 6: Font weights max 400 ===");
  const weights = await evaluate(`(() => {
    const elements = Array.from(document.querySelectorAll('#checker *'));
    const bad = [];
    for (const el of elements) {
      const w = window.getComputedStyle(el).fontWeight;
      if (Number(w) > 400) {
        bad.push({ tag: el.tagName, class: el.className, weight: w });
      }
    }
    return bad;
  })()`);
  console.log("Font weights > 400 count:", weights.length);
  if (weights.length > 0) {
    console.log("Sample elements exceeding 400:", weights.slice(0, 5));
  }
  assert.equal(weights.length, 0, "No element should have font weight > 400");

  await screenshot("qa/sandbox-flow-success.png");
  console.log("Saved screenshot to qa/sandbox-flow-success.png");

  ws.close();
  console.log("ALL SANDBOX FLOWS VERIFIED SUCCESSFULLY!");
}

main().catch(err => {
  console.error("FAIL:", err);
  process.exit(1);
});
