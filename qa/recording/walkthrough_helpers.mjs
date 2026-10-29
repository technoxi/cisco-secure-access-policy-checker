import { execSync } from "node:child_process";

const BASE = "http://127.0.0.1:9222";
export function targets() { return JSON.parse(execSync(`curl -sS ${BASE}/json/list`).toString()); }
export function pageTarget() { return targets().find(t => t.type === "page" && /sse\.cisco\.com/.test(t.url)); }
export function panelTarget() { return targets().find(t => t.type === "iframe" && /popup\.html/.test(t.url)); }

export async function connect(t) {
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
  let seq = 0; const pend = new Map();
  ws.onmessage = ev => {
    const m = JSON.parse(ev.data);
    if (m.id && pend.has(m.id)) { pend.get(m.id)(m); pend.delete(m.id); }
  };
  const send = (method, params = {}) => new Promise((res, rej) => {
    const i = ++seq;
    pend.set(i, m => m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result));
    ws.send(JSON.stringify({ id: i, method, params }));
  });
  return { send, close: () => ws.close() };
}

export const sleep = ms => new Promise(r => setTimeout(r, ms));

export async function initVirtualCursor(cPage) {
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      let cur = document.getElementById("sec-vcursor");
      if (!cur) {
        cur = document.createElement("div");
        cur.id = "sec-vcursor";
        cur.innerHTML = \`
          <svg width="26" height="26" viewBox="0 0 24 24" fill="none" style="filter: drop-shadow(0 2px 6px rgba(0,0,0,0.5)); transform-origin: 0 0;">
            <path d="M3.5 2.5L10.5 21.5L13.8 13.8L21.5 10.5L3.5 2.5Z" fill="#FFFFFF" stroke="#0F172A" stroke-width="1.6" stroke-linejoin="round"/>
          </svg>
          <div id="sec-vcursor-pulse" style="position: absolute; top: 0; left: 0; width: 26px; height: 26px; border-radius: 50%; border: 2.5px solid #3B82F6; transform: translate(-50%, -50%) scale(0); opacity: 0; pointer-events: none; transition: transform 0.25s ease-out, opacity 0.25s ease-out;"></div>
        \`;
        cur.style.cssText = "position: fixed; top: 0; left: 0; z-index: 2147483647; pointer-events: none; transition: transform 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); transform: translate3d(960px, 540px, 0);";
        document.body.appendChild(cur);
      }
      return true;
    })()`
  });
}

export async function moveCursorTo(cPage, x, y, durationMs = 300) {
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const cur = document.getElementById("sec-vcursor");
      if (cur) {
        cur.style.transition = "transform ${durationMs}ms cubic-bezier(0.2, 0.8, 0.2, 1)";
        cur.style.transform = "translate3d(${Math.round(x)}px, ${Math.round(y)}px, 0)";
      }
      return true;
    })()`
  });
  await sleep(durationMs + 20);
}

export async function pulseCursor(cPage) {
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const p = document.getElementById("sec-vcursor-pulse");
      if (p) {
        p.style.transform = "translate(-50%, -50%) scale(1.8)";
        p.style.opacity = "0.9";
        setTimeout(() => {
          p.style.transform = "translate(-50%, -50%) scale(0)";
          p.style.opacity = "0";
        }, 220);
      }
      return true;
    })()`
  });
  await sleep(120);
}

export async function showSectionIntro(cPage, badge, title, subtitle, durationMs = 2600) {
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      let intro = document.getElementById("sec-section-intro");
      if (!intro) {
        intro = document.createElement("div");
        intro.id = "sec-section-intro";
        intro.style.cssText = "position: fixed; bottom: 32px; left: 50%; transform: translateX(-50%) translateY(0); z-index: 2147483645; background: #0F172A; border: 1px solid rgba(255, 255, 255, 0.15); border-left: 4px solid #3B82F6; border-radius: 8px; padding: 12px 22px; box-shadow: 0 16px 36px rgba(0, 0, 0, 0.45); font-family: Inter, system-ui, sans-serif; color: #F8FAFC; display: flex; flex-direction: column; gap: 3px; min-width: 440px; pointer-events: none; transition: opacity 0.3s ease, transform 0.3s ease; opacity: 0;";
        document.body.appendChild(intro);
      }
      intro.innerHTML = \`
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px;">
          <span style="font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #60A5FA;">\${${JSON.stringify(badge)}}</span>
          <span style="font-size: 11px; font-weight: 500; color: #94A3B8;">Secure Access Policy Checker</span>
        </div>
        <div style="font-size: 15px; font-weight: 650; color: #FFFFFF; letter-spacing: -0.01em;">
          \${${JSON.stringify(title)}}
        </div>
        <div style="font-size: 12.5px; color: #CBD5E1; line-height: 1.35;">
          \${${JSON.stringify(subtitle)}}
        </div>
      \`;
      requestAnimationFrame(() => {
        intro.style.opacity = "1";
        intro.style.transform = "translateX(-50%) translateY(0)";
      });
      return true;
    })()`
  });
  await sleep(durationMs);
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const intro = document.getElementById("sec-section-intro");
      if (intro) {
        intro.style.opacity = "0";
        intro.style.transform = "translateX(-50%) translateY(8px)";
      }
      return true;
    })()`
  });
  await sleep(300);
}

export async function moveCursorToPanelElement(cPage, cPanel, exprOrSelector, durationMs = 320) {
  const panelBox = await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const p = document.getElementById("sec-embed-panel");
      if (!p) return { x: 0, y: 0 };
      const r = p.getBoundingClientRect();
      return { x: r.left, y: r.top };
    })()`,
    returnByValue: true
  });
  const elBox = await cPanel.send("Runtime.evaluate", {
    expression: typeof exprOrSelector === "function" ? `(${exprOrSelector.toString()})()` : `(() => {
      const el = typeof ${JSON.stringify(exprOrSelector)} === "string" ? document.querySelector(${JSON.stringify(exprOrSelector)}) : null;
      if (!el) return null;
      const r = el.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`,
    returnByValue: true
  });
  const pOrigin = panelBox.result?.value || { x: 0, y: 0 };
  const pt = elBox.result?.value;
  if (pt) {
    const globalX = pOrigin.x + pt.x;
    const globalY = pOrigin.y + pt.y;
    await moveCursorTo(cPage, globalX, globalY, durationMs);
    return { x: globalX, y: globalY };
  }
  return null;
}

export async function clickPanelElement(cPage, cPanel, exprOrSelector) {
  await moveCursorToPanelElement(cPage, cPanel, exprOrSelector);
  await pulseCursor(cPage);
  await cPanel.send("Runtime.evaluate", {
    expression: typeof exprOrSelector === "function" ? `(() => { const el = (${exprOrSelector.toString()})(); if (el) { el.click(); } })()` : `(() => {
      const el = document.querySelector(${JSON.stringify(exprOrSelector)});
      if (el) {
        el.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
        el.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true }));
        el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      }
    })()`
  });
}

export async function typeIntoPanelInput(cPage, cPanel, inputId, text, speedMs = 50) {
  await moveCursorToPanelElement(cPage, cPanel, `#${inputId}`);
  await pulseCursor(cPage);
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const el = document.getElementById(${JSON.stringify(inputId)});
      if (!el) return false;
      el.focus();
      Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set.call(el, "");
      el.dispatchEvent(new Event("input", { bubbles: true }));
      return true;
    })()`
  });
  await sleep(150);

  let cur = "";
  for (const ch of text) {
    cur += ch;
    await cPanel.send("Runtime.evaluate", {
      expression: `(() => {
        const el = document.getElementById(${JSON.stringify(inputId)});
        if (!el) return false;
        Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value").set.call(el, ${JSON.stringify(cur)});
        el.dispatchEvent(new Event("input", { bubbles: true }));
        return true;
      })()`
    });
    await sleep(speedMs);
  }
  await sleep(250);
}

export async function pickPanelDropdown(cPage, cPanel, inputId, queryText, targetLabel) {
  await typeIntoPanelInput(cPage, cPanel, inputId, queryText, 70);
  await sleep(450);

  // Find option coordinates and move cursor onto it
  const optCoord = await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const input = document.getElementById(${JSON.stringify(inputId)});
      const wrap = input?.closest(".tp-picker");
      const opts = [...(wrap || document).querySelectorAll("[role=option], .tp-picker-option")].filter(o => getComputedStyle(o).display !== "none");
      const opt = opts.find(o => o.innerText.toLowerCase().includes(${JSON.stringify(targetLabel.toLowerCase())}));
      if (!opt) return null;
      opts.forEach(o => o.classList.remove("is-active"));
      opt.classList.add("is-active");
      const r = opt.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`,
    returnByValue: true
  });

  if (optCoord.result?.value) {
    const panelBox = await cPage.send("Runtime.evaluate", {
      expression: `(() => {
        const p = document.getElementById("sec-embed-panel");
        const r = p ? p.getBoundingClientRect() : { x: 0, y: 0 };
        return { x: r.left, y: r.top };
      })()`,
      returnByValue: true
    });
    const pOrigin = panelBox.result?.value || { x: 0, y: 0 };
    const pt = optCoord.result.value;
    await moveCursorTo(cPage, pOrigin.x + pt.x, pOrigin.y + pt.y, 250);
    await pulseCursor(cPage);
  }

  // Commit click via mousedown + mouseup + click
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const input = document.getElementById(${JSON.stringify(inputId)});
      const wrap = input?.closest(".tp-picker");
      const opts = [...(wrap || document).querySelectorAll("[role=option], .tp-picker-option")].filter(o => getComputedStyle(o).display !== "none");
      const opt = opts.find(o => o.innerText.toLowerCase().includes(${JSON.stringify(targetLabel.toLowerCase())}));
      if (!opt) return false;
      opt.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true }));
      opt.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true }));
      opt.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      return true;
    })()`
  });
  await sleep(400);
}
