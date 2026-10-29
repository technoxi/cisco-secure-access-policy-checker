import { execSync } from "node:child_process";
const BASE = "http://127.0.0.1:9222";
export const sleep = ms => new Promise(r => setTimeout(r, ms));
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
  ms = Math.max(220, Math.min(ms, 250 + dist * 0.9));
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
  await sleep(120);
  await page.ev("__vclick()");
  await page.send("Input.dispatchMouseEvent", { type: "mousePressed", x, y, button: "left", clickCount: 1 });
  await sleep(70);
  await page.send("Input.dispatchMouseEvent", { type: "mouseReleased", x, y, button: "left", clickCount: 1 });
  await sleep(250);
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
    await sleep(ms + Math.random() * 40);
  }
}

async function panelOrigin() {
  return page.ev(`(() => { const f = document.querySelector("#sec-embed-panel iframe"); const r = (f || document.getElementById("sec-embed-panel")).getBoundingClientRect(); return { x: r.left, y: r.top }; })()`);
}
// Centre of a panel element, in page coordinates; fn is a JS expression returning the element.
export async function panelPoint(expr, scroll = true) {
  if (scroll) {
    await panel.ev(`(() => { const el = (${expr}); if (el) el.scrollIntoView({ block: "center", behavior: "smooth" }); })()`);
    await sleep(450);
  }
  const r = await panel.ev(`(() => { const el = (${expr}); if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
  if (!r) throw new Error("panel element not found: " + expr);
  const o = await panelOrigin();
  return { x: o.x + r.x, y: o.y + r.y };
}
export async function pageRect(expr, scroll = "center") {
  if (scroll) { await page.ev(`(() => { const el = (${expr}); if (el) el.scrollIntoView({ block: "${scroll}", behavior: "smooth" }); })()`); await sleep(700); }
  const r = await page.ev(`(() => { const el = (${expr}); if (!el) return null; const r = el.getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, w: r.width, h: r.height, l: r.left, t: r.top }; })()`);
  if (!r) throw new Error("page element not found: " + expr);
  return r;
}
export async function clickPanel(expr) { const p = await panelPoint(expr); await click(p.x, p.y); }
export async function typeInto(inputId, text, ms = 70) {
  const p = await panelPoint(`document.getElementById("${inputId}")`);
  await click(p.x, p.y);
  await sleep(150);
  await typeText(text, ms);
  await sleep(300);
}
export async function pick(inputId, query, label, ms = 80) {
  await typeInto(inputId, query, ms);
  await sleep(500);
  const expr = `[...document.querySelectorAll("#${inputId}")[0].closest(".tp-picker").querySelectorAll("[role=option], .tp-picker-option")].sort((a, b) => 0).find(o => o.innerText.toLowerCase().trim().startsWith(${JSON.stringify(label.toLowerCase())})) || [...document.querySelectorAll("#${inputId}")[0].closest(".tp-picker").querySelectorAll("[role=option], .tp-picker-option")].find(o => o.innerText.toLowerCase().includes(${JSON.stringify(label.toLowerCase())}))`;
  const p = await panelPoint(expr, false);
  await move(p.x, p.y, 500);
  await sleep(350);
  await click(p.x, p.y);
  await sleep(500);
}
export async function resetPanel() {
  await panel.ev(`(() => { ["psc.policyChecker.draft.v2","psc.policyChecker.mode.v1","psc.policyChecker.describe.v1"].forEach(k => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch (_) {} }); [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Reset")?.click(); })()`);
  await sleep(600);
}
export async function card(kicker, title, sub, ms = 3000) {
  await page.ev(`(() => {
    let o = document.getElementById("v8-card"); if (o) o.remove();
    o = document.createElement("div"); o.id = "v8-card";
    o.style.cssText = "position:fixed;inset:0;z-index:2147483646;display:flex;align-items:center;justify-content:center;background:rgba(8,15,30,.86);backdrop-filter:blur(6px);opacity:0;transition:opacity .45s ease;font-family:Inter,system-ui,sans-serif";
    o.innerHTML = '<div style="max-width:980px;padding:0 40px"><div style="color:#60A5FA;font-size:20px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;margin-bottom:18px">' + ${JSON.stringify(kicker)} + '</div><div style="color:#fff;font-size:64px;font-weight:650;letter-spacing:-.02em;line-height:1.1">' + ${JSON.stringify(title)} + '</div><div style="color:#CBD5E1;font-size:28px;line-height:1.4;margin-top:22px">' + ${JSON.stringify(sub)} + '</div></div>';
    document.body.appendChild(o); requestAnimationFrame(() => o.style.opacity = "1");
  })()`);
  await sleep(ms);
  await page.ev(`(() => { const o = document.getElementById("v8-card"); if (o) { o.style.opacity = "0"; setTimeout(() => o.remove(), 500); } })()`);
  await sleep(550);
}
export async function setPanel(open) {
  const isOpen = await page.ev(`document.getElementById("sec-embed-panel")?.classList.contains("sec-embed-open")`);
  if (!!isOpen !== open) { await page.ev(`document.getElementById("sec-embed-toggle").click()`); await sleep(900); }
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
  await sleep(ms);
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
  await sleep(500);
}
export async function openPanelClick() {
  const r = await pageRect(`document.getElementById("sec-embed-toggle")`, null);
  await click(r.x, r.y);
  await sleep(1100);
  await refreshPanel();
}
async function stableRect(expr) {
  let prev = null;
  for (let i = 0; i < 20; i++) {
    const r = await pageRect(expr, null);
    if (prev && Math.abs(r.x - prev.x) < 0.5 && Math.abs(r.y - prev.y) < 0.5) return r;
    prev = r; await sleep(160);
  }
  return prev;
}
export async function hoverCell(expr, ms = 500, left = false) {
  const r = await stableRect(expr);
  await move(left ? r.l + 28 : r.x, r.y, ms);
  await sleep(900);
}
export async function parkCursor(x = 560, y = 980) { await move(x, y, 500); await sleep(500); }

export async function prep() {
  await page.send("Page.reload");
  await sleep(4000);
  for (let i = 0; i < 40; i++) {
    const ok = await page.ev(`!!document.getElementById("sec-embed-toggle") && document.querySelectorAll('[data-testid="policy-source-column"]').length > 30`).catch(() => false);
    if (ok) break; await sleep(500);
  }
  await sleep(6000);
  await page.ev(`(() => { ["psc.policyChecker.draft.v2","psc.policyChecker.mode.v1","psc.policyChecker.describe.v1"].forEach(k => { try { sessionStorage.removeItem(k); localStorage.removeItem(k); } catch (_) {} }); })()`);
}
