import { execSync } from "node:child_process";
const BASE = "http://127.0.0.1:9222";
export const sleep = ms => new Promise(r => setTimeout(r, ms));
export const SPEED = +(process.env.SPEED || 1);
export const pause = ms => sleep(ms * SPEED);
const list = () => JSON.parse(execSync(`curl -sS ${BASE}/json/list`).toString());

async function open(t) {
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let seq = 0; const pend = new Map();
  ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); } };
  const send = (method, params = {}) => new Promise((res, rej) => {
    const i = ++seq; pend.set(i, m => m.error ? rej(new Error(method + " " + JSON.stringify(m.error))) : res(m.result));
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  const ev = async (expr) => {
    const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails).slice(0, 400));
    return r.result.value;
  };
  return { send, ev, close: () => ws.close() };
}

let page, panel;
export async function init() {
  page = await open(list().find(t => t.type === "page" && /sse\.cisco\.com/.test(t.url)));
  await page.ev(`(() => {
    if (!document.getElementById("v8-cursor")) {
      const c = document.createElement("div"); c.id = "v8-cursor";
      c.style.cssText = "position:fixed;top:0;left:0;z-index:2147483647;pointer-events:none;will-change:transform;transform:translate3d(1000px,600px,0)";
      c.innerHTML = '<svg width="30" height="30" viewBox="0 0 24 24" style="filter:drop-shadow(0 2px 4px rgba(0,0,0,.45))"><path d="M3.5 2.5L10.5 21.5L13.8 13.8L21.5 10.5L3.5 2.5Z" fill="#fff" stroke="#0F172A" stroke-width="1.5" stroke-linejoin="round"/></svg><div id="v8-ring" style="position:absolute;left:-2px;top:-2px;width:34px;height:34px;margin:-17px 0 0 -17px;border-radius:50%;border:3px solid #2563EB;opacity:0;transform:scale(.3)"></div>';
      document.body.appendChild(c);
      window.__vc = (x, y) => { window.__vcpos = [x, y]; c.style.transform = "translate3d(" + x + "px," + y + "px,0)"; };
      window.__vclick = () => { const r = document.getElementById("v8-ring"); r.animate([{opacity:.95,transform:"scale(.3)"},{opacity:0,transform:"scale(1.5)"}],{duration:450,easing:"ease-out"}); };
      setInterval(() => { [...document.querySelectorAll("button")].filter(b => /^(OK|Stay signed in|Continue)$/i.test(b.innerText.trim()) && b.closest("[role=dialog],[class*=modal],[class*=Modal]")).forEach(b => b.click()); }, 3000);
    }
  })()`);
  await page.ev(`(() => { const strip = () => document.querySelectorAll('[title="Secure Access Policy Checker"]').forEach(e => e.removeAttribute("title")); strip(); if (!window.__vstrip) window.__vstrip = setInterval(strip, 300); })()`);
  const pos = await page.ev("window.__vcpos || null");
  if (pos) { cx = pos[0]; cy = pos[1]; }
  await refreshPanel();
}
export async function refreshPanel() {
  const t = list().find(t => t.type === "iframe" && /popup\.html/.test(t.url));
  if (!t) { panel = null; return null; }
  try { panel?.close(); } catch {}
  panel = await open(t);
  return panel;
}
export const P = () => page;
export const Q = () => panel;

let cx = 1000, cy = 600;
const ease = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
export async function move(x, y, ms = 650) {
  const x0 = cx, y0 = cy, dist = Math.hypot(x - x0, y - y0);
  ms = SPEED * Math.max(220, Math.min(ms, 250 + dist * 0.9)); ms = Math.max(ms, 130);
  const n = Math.round(ms / 16);
  const nx = -(y - y0) / (dist || 1), ny = (x - x0) / (dist || 1), arc = Math.min(40, dist * 0.06);
  for (let i = 1; i <= n; i++) {
    const t = ease(i / n), bend = Math.sin(Math.PI * t) * arc;
    const px = x0 + (x - x0) * t + nx * bend, py = y0 + (y - y0) * t + ny * bend;
    await Promise.all([
      page.send("Input.dispatchMouseEvent", { type: "mouseMoved", x: px, y: py }),
      page.ev(`__vc(${px},${py})`),
    ]);
    await sleep(16);
  }
  cx = x; cy = y;
}
export async function click(x, y) {
  await move(x, y);
  await pause(120);
  await page.ev("__vclick()");
  await page.send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
  await pause(70);
  await page.send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
  await pause(250);
}
export async function key(k, mods = 0) {
  const map = { Backspace: 8, Enter: 13, Tab: 9, Escape: 27, a: 65 };
  await page.send("Input.dispatchKeyEvent", { type: "rawKeyDown", key: k, windowsVirtualKeyCode: map[k] || 0, modifiers: mods });
  await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: k, windowsVirtualKeyCode: map[k] || 0, modifiers: mods });
}
export async function typeText(text, ms = 70) {
  for (const ch of text) {
    await page.send("Input.dispatchKeyEvent", { type: "keyDown", text: ch, key: ch, unmodifiedText: ch });
    await page.send("Input.dispatchKeyEvent", { type: "keyUp", key: ch });
    await pause(ms + Math.random() * 40);
  }
}

async function panelOrigin() {
  return page.ev(`(() => { const f = document.querySelector("#sec-embed-panel iframe"); const r = (f || document.getElementById("sec-embed-panel")).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`);
}
// Centre of a panel element, in page coordinates; fn is a JS expression returning the element.
export async function panelPoint(expr, scroll = true) {
  if (scroll) {
    await panel.ev(`(() => { const el = (${expr}); if (el) el.scrollIntoView({ block: "center", behavior: "smooth" }); })()`);
    await pause(450);
  }
  const r = await panel.ev(`(() => { const el = (${expr}); if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  if (!r) throw new Error("panel element not found: " + expr);
  const o = await panelOrigin();
  return { x: o.x + r.x, y: o.y + r.y };
}
export async function pageRect(expr, scroll = "center") {
  if (scroll) { await page.ev(`(() => { const el = (${expr}); if (el) el.scrollIntoView({ block: "${scroll}", behavior: "smooth" }); })()`); await pause(700); }
  const r = await page.ev(`(() => { const el = (${expr}); if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height, l: r.left, t: r.top }; })()`);
  if (!r) throw new Error("page element not found: " + expr);
  return r;
}
export async function clickPanel(expr) { const p = await panelPoint(expr); await click(p.x, p.y); }
export async function typeInto(inputId, text, ms = 70) {
  const p = await panelPoint(`document.getElementById("${inputId}")`);
  await click(p.x, p.y);
  await pause(150);
  await typeText(text, ms);
  await pause(300);
}
export async function pick(inputId, query, label, ms = 80) {
  await typeInto(inputId, query, ms);
  await pause(500);
  const expr = `[...document.querySelectorAll("#${inputId}")[0].closest(".tp-picker").querySelectorAll("[role=option], .tp-picker-option")].sort((a, b) => 0).find(o => o.innerText.toLowerCase().trim().startsWith(${JSON.stringify(label.toLowerCase())})) || [...document.querySelectorAll("#${inputId}")[0].closest(".tp-picker").querySelectorAll("[role=option], .tp-picker-option")].find(o => o.innerText.toLowerCase().includes(${JSON.stringify(label.toLowerCase())}))`;
  const p = await panelPoint(expr, false);
  await move(p.x, p.y, 500);
  await pause(350);
  await click(p.x, p.y);
  await pause(500);
}
export async function resetPanel() {
  await panel.ev(`(() => { ["psc.policyChecker.draft.v2","psc.policyChecker.mode.v1","psc.policyChecker.describe.v1"].forEach(k => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch (_) {} }); [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Reset")?.click(); })()`);
  await pause(600);
}
export async function card(kicker, title, sub, ms = 3000, step) {
  const dots = step ? [1, 2, 3, 4].map(n => `<span style="width:${n === step ? 34 : 10}px;height:10px;border-radius:5px;background:${n === step ? "#3B82F6" : "rgba(255,255,255,.28)"};display:inline-block;margin-right:8px;transition:all .4s"></span>`).join("") : "";
  await page.ev(`(() => {
    document.getElementById("v8-card")?.remove();
    if (!document.getElementById("v8-anim")) { const st = document.createElement("style"); st.id = "v8-anim"; st.textContent = "@keyframes v8up{from{opacity:0;transform:translateY(26px);filter:blur(6px)}to{opacity:1;transform:none;filter:none}}@keyframes v8left{from{opacity:0;transform:translateX(-24px)}to{opacity:1;transform:none}}@keyframes v8bar{from{transform:scaleY(0)}to{transform:scaleY(1)}}@keyframes v8cap{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}"; document.head.appendChild(st); }
    const o = document.createElement("div"); o.id = "v8-card";
    o.style.cssText = "position:fixed;inset:0;z-index:2147483646;display:flex;align-items:center;justify-content:center;background:radial-gradient(ellipse at 30% 40%,rgba(30,58,138,.55),rgba(8,15,30,.96) 70%);backdrop-filter:blur(10px);opacity:0;transition:opacity .4s ease;font-family:Inter,system-ui,sans-serif";
    o.innerHTML = '<div style="display:flex;gap:34px;max-width:1180px;padding:0 60px"><div style="width:8px;border-radius:4px;background:linear-gradient(#60A5FA,#2563EB);transform-origin:top;animation:v8bar .5s .05s both cubic-bezier(.2,.8,.2,1)"></div><div><div style="color:#60A5FA;font-size:22px;font-weight:700;letter-spacing:.16em;text-transform:uppercase;margin-bottom:20px;animation:v8left .45s .15s both cubic-bezier(.2,.8,.2,1)"></div><div id="v8-t" style="color:#fff;font-size:76px;font-weight:650;letter-spacing:-.025em;line-height:1.08;animation:v8up .6s .25s both cubic-bezier(.2,.8,.2,1)"></div><div id="v8-s" style="color:#CBD5E1;font-size:30px;line-height:1.4;margin-top:26px;max-width:960px;animation:v8up .55s .5s both cubic-bezier(.2,.8,.2,1)"></div><div id="v8-d" style="margin-top:44px;animation:v8up .5s .75s both"></div></div></div>';
    o.children[0].children[1].children[0].textContent = ${JSON.stringify(kicker)};
    o.querySelector("#v8-t").textContent = ${JSON.stringify(title)};
    o.querySelector("#v8-s").textContent = ${JSON.stringify(sub)};
    o.querySelector("#v8-d").innerHTML = ${JSON.stringify(dots)};
    document.body.appendChild(o); requestAnimationFrame(() => o.style.opacity = "1");
  })()`);
  await sleep(ms);
  await page.ev(`(() => { const o = document.getElementById("v8-card"); if (o) { o.style.transition = "opacity .45s ease"; o.style.opacity = "0"; setTimeout(() => o.remove(), 500); } })()`);
  await sleep(450);
}
export async function pulse() {
  await panel.ev(`(() => { if (!document.getElementById("v8-pulse")) { const st = document.createElement("style"); st.id = "v8-pulse"; st.textContent = "@keyframes v8ring{0%{box-shadow:0 0 0 0 rgba(37,99,235,.6)}100%{box-shadow:0 0 0 22px rgba(37,99,235,0)}}.tp-outcome.v8p{animation:v8ring .9s ease-out 2}"; document.head.appendChild(st); } const o = document.querySelector(".tp-outcome"); if (o) { o.classList.remove("v8p"); void o.offsetWidth; o.classList.add("v8p"); } })()`);
}
export async function setPanel(open) {
  const isOpen = await page.ev(`document.getElementById("sec-embed-panel")?.classList.contains("sec-embed-open")`);
  if (!!isOpen !== open) { await page.ev(`document.getElementById("sec-embed-toggle").click()`); await pause(900); }
  if (open) await refreshPanel();
}

export async function scrollTable(rowIdx, ms = 700) {
  await page.ev(`(() => {
    const pg = document.querySelector(".css-ye96qv"); if (pg) pg.scrollTo({ top: 0, behavior: "smooth" });
    const cell = document.querySelectorAll('[data-testid="policy-source-column"]')[${rowIdx}];
    const row = cell.closest("tr"); const box = row.closest(".cds-table-container_dadfe42e78dea468fe45") || row.closest("[class*=cds-table-container]");
    const head = box.querySelector("thead")?.getBoundingClientRect().height || 40;
    const top = row.offsetTop - (box.clientHeight - head) / 2 + head / 2;
    box.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
  })()`);
  await pause(ms);
}
export async function dismissOverlays() {
  await page.send("Input.dispatchMouseEvent", { type: "mousePressed", x: 500, y: 960, button: "left", clickCount: 1 });
  await page.send("Input.dispatchMouseEvent", { type: "mouseReleased", x: 500, y: 960, button: "left", clickCount: 1 });
}

export async function waitPanel(expr, timeout = 15000) {
  const t0 = Date.now();
  while (Date.now() - t0 < timeout) { if (await panel.ev(`!!(${expr})`)) return true; await sleep(250); }
  throw new Error("timeout waiting: " + expr);
}
export async function fresh() {
  await page.ev(`(() => {
    document.querySelector(".css-ye96qv")?.scrollTo({ top: 0 });
    document.getElementById("sec-result-dock")?.remove();
    document.querySelectorAll(".sec-member-panel").forEach(e => e.remove());
    const s = document.getElementById("policy-search"); if (s && s.value) { s.value = ""; s.dispatchEvent(new Event("input", { bubbles: true })); }
  })()`);
  await setPanel(false);
  await refreshPanel();
  if (panel) await resetPanel();
  await page.ev(`document.querySelector("[class*=cds-table-container]")?.scrollTo({ top: 0 })`);
  await pause(500);
}
export async function openPanelClick() {
  const r = await pageRect(`document.getElementById("sec-embed-toggle")`, null);
  await click(r.x, r.y);
  await pause(1100);
  await refreshPanel();
}
async function stableRect(expr) {
  let prev = null;
  for (let i = 0; i < 20; i++) {
    const r = await pageRect(expr, null);
    if (prev && Math.abs(r.x - prev.x) < 0.5 && Math.abs(r.y - prev.y) < 0.5) return r;
    prev = r; await pause(160);
  }
  return prev;
}
export async function hoverCell(expr, ms = 500, left = false) {
  const r = await stableRect(expr);
  await move(left ? r.l + 28 : r.x, r.y, ms);
  await pause(900);
}
export async function parkCursor(x = 560, y = 980) { await move(x, y, 500); await pause(500); }

export async function prep() {
  await page.send("Page.navigate", { url: "https://dashboard.sse.cisco.com/org/8176184/secure/policy" });
  await pause(4000);
  for (let i = 0; i < 40; i++) {
    const ok = await page.ev(`!!document.getElementById("sec-embed-toggle") && document.querySelectorAll('[data-testid="policy-source-column"]').length > 30`).catch(() => false);
    if (ok) break; await pause(500);
  }
  await pause(6000);
  await page.ev(`(() => { ["psc.policyChecker.draft.v2","psc.policyChecker.mode.v1","psc.policyChecker.describe.v1"].forEach(k => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch (_) {} }); })()`);
}

export async function caption(head, sub) {
  const H = JSON.stringify(head || ""), S = JSON.stringify(sub || "");
  await page.ev(`(() => { const head = ${H}, sub = ${S}; if (!document.getElementById("v8-anim")) { const st = document.createElement("style"); st.id = "v8-anim"; st.textContent = "@keyframes v8up{from{opacity:0;transform:translateY(26px);filter:blur(6px)}to{opacity:1;transform:none;filter:none}}@keyframes v8left{from{opacity:0;transform:translateX(-24px)}to{opacity:1;transform:none}}@keyframes v8bar{from{transform:scaleY(0)}to{transform:scaleY(1)}}@keyframes v8cap{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:none}}"; document.head.appendChild(st); } let c = document.getElementById("v8-cap"); if (!head) { if (c) c.style.opacity = "0"; return; } if (!c) { c = document.createElement("div"); c.id = "v8-cap"; c.style.cssText = "position:fixed;left:32px;bottom:34px;z-index:2147483640;width:640px;padding:14px 20px;border-radius:12px;background:rgba(15,23,42,.94);color:#fff;font-family:Inter,system-ui,sans-serif;border-left:6px solid #3B82F6;box-shadow:0 10px 30px rgba(0,0,0,.35);transition:opacity .25s;opacity:0"; document.body.appendChild(c); } c.innerHTML = '<div style="font:700 24px/1.25 Inter,system-ui,sans-serif"></div><div style="font:400 19px/1.4 Inter,system-ui,sans-serif;color:#CBD5E1;margin-top:4px"></div>'; c.children[0].textContent = head; c.children[1].textContent = sub; c.children[1].style.display = sub ? "block" : "none"; c.style.animation = "none"; void c.offsetWidth; c.style.animation = "v8cap .45s cubic-bezier(.2,.8,.2,1) both"; c.style.opacity = "1"; })()`);
}
export async function clearPicker(inputId) {
  const expr = `document.getElementById("${inputId}").closest(".tp-picker").querySelector("button")`;
  const has = await panel.ev(`!!(${expr})`);
  if (has) await clickPanel(expr);
}
export async function runPageNav(url, wait = 9000) {
  await page.send("Page.navigate", { url });
  await sleep(wait);
}

export async function blackCard(text, ms = 2500) {
  await page.ev(`(() => {
    document.getElementById("v8-black")?.remove();
    if (!document.getElementById("v8-anim")) { const st = document.createElement("style"); st.id = "v8-anim"; st.textContent = "@keyframes v8up{from{opacity:0;transform:translateY(26px);filter:blur(6px)}to{opacity:1;transform:none;filter:none}}"; document.head.appendChild(st); }
    const o = document.createElement("div"); o.id = "v8-black";
    o.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:#000;display:flex;align-items:center;justify-content:center;font-family:Inter,system-ui,sans-serif";
    const t = document.createElement("div");
    t.style.cssText = "color:#fff;font-size:72px;font-weight:600;letter-spacing:-.02em;animation:v8up .8s .3s both cubic-bezier(.2,.8,.2,1)";
    t.textContent = ${JSON.stringify(text)};
    o.appendChild(t); document.body.appendChild(o);
  })()`);
  await sleep(ms);
  await page.ev(`(() => { const o = document.getElementById("v8-black"); if (o) { o.style.transition = "opacity .5s ease"; o.style.opacity = "0"; setTimeout(() => o.remove(), 600); } })()`);
}
