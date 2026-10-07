// Read the extension's stored policy data out of a signed-in Chrome over the
// DevTools protocol. Login tokens are never read out.
//
// 1. Launch Chrome with the extension and a debugging port, e.g.
//      chrome --remote-debugging-port=9444 --remote-allow-origins='*' \
//        --load-extension=extension --disable-extensions-except=extension
// 2. Sign in to the Secure Access dashboard and open the policy page
//    (or: node qa/dump-extension-data.mjs 9444 goto about:blank <dashboard URL>).
// 3. Once the extension has fetched (about a minute):
//      node qa/dump-extension-data.mjs 9444 dump qa/data/extension-data.json
//
// Commands: url | goto <tab-url-substring|new> <url> | dump <out.json>
//   goto <url-substr-of-tab|new> <url>   navigate (or open) a tab
//   url                                   list page targets
//   dump <out.json>                       read extension storage from the service worker (tokens excluded)
const [port, cmd, ...args] = process.argv.slice(2);
const fs = await import("node:fs");
const list = async () => (await (await fetch(`http://127.0.0.1:${port}/json/list`)).json());
function session(wsUrl) {
  const ws = new WebSocket(wsUrl);
  let id = 0; const pending = new Map();
  ws.addEventListener("message", e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } });
  const ready = new Promise(r => ws.addEventListener("open", r, { once: true }));
  return { ready, send: (method, params = {}) => new Promise(r => { const i = ++id; pending.set(i, r); ws.send(JSON.stringify({ id: i, method, params })); }), close: () => ws.close() };
}
if (cmd === "url") {
  for (const t of await list()) console.log(t.type, "|", t.url.slice(0, 140));
} else if (cmd === "goto") {
  const [match, url] = args;
  let target = match === "new" ? null : (await list()).find(t => t.type === "page" && t.url.includes(match));
  if (!target) target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
  const s = session(target.webSocketDebuggerUrl); await s.ready;
  await s.send("Page.enable"); await s.send("Page.navigate", { url });
  s.close(); console.log("navigating", target.id);
} else if (cmd === "dump") {
  const sw = (await list()).find(t => t.type === "service_worker" && t.url.includes("background/service-worker.js"));
  if (!sw) { console.log("no extension service worker"); process.exit(1); }
  const s = session(sw.webSocketDebuggerUrl); await s.ready;
  const expr = `chrome.storage.local.get(null).then(all => {
    const keep = ["sse_rules","sse_object_maps","sse_member_maps","sse_identity_map","sse_identity_type_map","sse_rule_fetch_status","cached_org_id"];
    const out = {}; for (const k of keep) if (k in all) out[k] = all[k];
    out.__keys = Object.keys(all).filter(k => !/token/i.test(k));
    return JSON.stringify(out);
  })`;
  const r = await s.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true });
  s.close();
  const text = r.result && r.result.result && r.result.result.value;
  if (!text) { console.log("evaluate failed", JSON.stringify(r).slice(0, 400)); process.exit(1); }
  fs.writeFileSync(args[0], text);
  const d = JSON.parse(text);
  console.log("keys:", d.__keys.join(", "));
  console.log("rules:", (d.sse_rules || []).length, "org:", d.cached_org_id);
  console.log("catalogs:", Object.entries(d.sse_object_maps || {}).map(([k, v]) => `${k}=${Object.keys(v || {}).length}`).join(" "));
  console.log("member kinds:", Object.entries(d.sse_member_maps || {}).map(([k, v]) => `${k}=${Object.keys(v || {}).length}`).join(" "));
}
