import * as d from "./drive.mjs";
const { sleep, pause } = d;
const Q = () => d.Q(); const P = () => d.P();
const POLICY = "https://dashboard.sse.cisco.com/org/8176184/secure/policy";
const STEER = "https://dashboard.sse.cisco.com/org/8176184/connect/user-connectivity/internet-security";
const TYPE = 22;

const srcCell = i => `document.querySelectorAll("tbody tr")[${i}].querySelector('[data-testid="policy-source-column"]')`;
const dstItem = (i, k = 0) => `document.querySelectorAll("tbody tr")[${i}].querySelectorAll('[data-testid="policy-destination-item"]')[${k}]`;
const pop = `document.getElementById("sec-hover-popover")`;
const expChip = k => `${pop}.querySelectorAll(".sec-hp-expandable")[${k}]`;
const btn = t => `[...document.querySelectorAll("button")].find(b => b.innerText.trim() === "${t}")`;

async function snapshot() { return Q().ev(`(()=>{const b=document.body.innerText; const i=b.lastIndexOf("Check policy"); return b.slice(i+12).slice(0,400)})()`); }

let current = { computer: null, user: null };
async function runCase(o) {
  if (o.caption) await d.caption(o.caption[0], o.caption[1]);
  if (o.computer && o.computer !== current.computer) { if (current.computer) await d.clearPicker("tp-src-roaming"); await d.pick("tp-src-roaming", o.computer, o.computer, TYPE); current.computer = o.computer; }
  if (o.user && o.user !== current.user) { if (current.user) await d.clearPicker("tp-src-identity"); await d.pick("tp-src-identity", o.user.split(" ")[0].toLowerCase(), o.user, TYPE); current.user = o.user; }
  const before = await snapshot();
  await Q().ev(`(()=>{const el=document.getElementById("tp-destination"); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(el,""); el.dispatchEvent(new Event("input",{bubbles:true}));})()`);
  await d.typeInto("tp-destination", o.dest, TYPE);
  await d.clickPanel(btn("Check policy"));
  const t0 = Date.now();
  for (;;) {
    await sleep(300);
    const now = await snapshot();
    if (now && now !== before && /Allowed|Blocked|Bypassed|Isolated|Warn|Waiting on your answer/.test(now)) break;
    if (Date.now() - t0 > 40000) throw new Error("no verdict for " + o.dest);
  }
  await sleep(350);
  await d.pulse();
  const v = (await snapshot()).replace(/\n+/g, " | ").slice(0, 140);
  console.log("VERDICT", o.dest, "::", v);
  await Q().ev(`(${btn("Check policy")})?.scrollIntoView({ block: "start", behavior: "smooth" })`);
  await sleep(o.hold || 1900);
  if (o.show) {
    await d.clickPanel(btn("Show on page"));
    await sleep(2200);
    await d.caption("");
    const clr = await d.pageRect(`[...document.querySelectorAll("#sec-result-dock button")].find(b => /Clear highlights/.test(b.innerText))`, null).catch(() => null);
    if (clr) await d.click(clr.x, clr.y);
    await d.openPanelClick();
  }
}

async function ensureOpen() { if (!(await Q()?.ev("1").catch(() => 0))) await d.openPanelClick(); }

const scenes = {
  async s1() {
    await d.card("Secure Access Policy Checker", "Who can reach what, and why", "Live on a real Secure Access tenant", 2000);
    await d.card("Feature 1 of 4", "See inside any rule", "Hover groups, categories and nested objects right on the Access Policy table", 2700, 1);
    await d.scrollTable(17, 700);
    await d.caption("Rule 18 \u00b7 Finance Content Blocks", "Blocks the Finance group from restricted categories");
    await d.hoverCell(srcCell(17), 450, true); await sleep(700);
    await d.hoverCell(expChip(0), 350); await sleep(1500);
    await d.hoverCell(dstItem(17, 0), 450); await sleep(700);
    await d.hoverCell(expChip(0), 350); await sleep(2300);
    await d.parkCursor(); await d.caption("");
  },
  async s2() {
    await Promise.all([d.card("Feature 2 of 4", "Check any request", "Allowed, blocked or isolated, and the exact rule that decided it", 2700, 2), d.fresh()]);
    await d.openPanelClick();
    await d.clickPanel(`document.querySelector('input.tp-connection-radio[value="client"]').closest("label")`);
    await runCase({ computer: "wkst1", user: "Carol Freeman", dest: "github.com", caption: ["Allowed", "Carol Freeman on wkst1 reaches github.com. Rule 2 matches first."] });
    await runCase({ dest: "internetbadguys.com", caption: ["Blocked at DNS", "internetbadguys.com is categorised Phishing, so the DNS security setting stops it for everyone."] });
    await runCase({ computer: "rwkst1", user: "Paul Cole", dest: "playboy.com", caption: ["Blocked \u00b7 Rule 18", "Paul Cole (Finance) on playboy.com: Adult Themes is a restricted category."], show: true });
    await runCase({ user: "Anna Mariano", dest: "playboy.com", caption: ["Allowed \u00b7 Rule 34", "Same site, but Anna Mariano is in HR, so the Finance rule does not apply."] });
    await runCase({ user: "Paul Cole", dest: "pastebin.com", caption: ["Isolated \u00b7 Rule 15", "pastebin.com opens in a remote browser instead of being blocked outright."] });
    await d.caption(""); await d.parkCursor(700, 960);
  },
  async s3() {
    await d.card("Feature 3 of 4", "Traffic steering exclusions", "Destinations configured to bypass Secure Access entirely", 2700, 3);
    await d.caption("Traffic Steering list", "dl.duosecurity.com is set to bypass Secure Access and the web proxy.");
    const r = await d.pageRect(`[...document.querySelectorAll("tr")].find(t => /dl\\.duosecurity\\.com/.test(t.innerText) && /Bypass Secure Access/.test(t.innerText))`, null);
    await P().ev(`(() => { [...document.querySelectorAll("tr")].filter(t => /dl\\.duosecurity\\.com/.test(t.innerText)).forEach(t => { t.style.outline = "3px solid #2563EB"; t.style.outlineOffset = "-3px"; t.style.background = "rgba(37,99,235,.08)"; }); })()`);
    await d.move(r.x, r.y, 600); await sleep(2800);
    await d.caption(""); await d.parkCursor(700, 960);
  },
  async s4() {
    await d.openPanelClick();
    await runCase({ dest: "dl.duosecurity.com", caption: ["Bypassed", "The checker honours the exclusion: dl.duosecurity.com skips policy and goes direct."], hold: 2300 });
    await d.caption("");
  },
  async s5() {
    await Promise.all([d.card("Feature 4 of 4", "Remote access VPN and firewall", "A private IP, port and protocol checked against firewall rules", 2700, 4), d.fresh()]);
    await d.openPanelClick();
    await d.caption("Remote access VPN", "Paul Cole to 10.141.46.1 on TCP 443 falls to the default For all private access block.");
    await d.clickPanel(`document.querySelector('input.tp-connection-radio[value="vpn"]').closest("label")`);
    await d.pick("tp-src-identity", "paul", "Paul Cole", TYPE);
    await d.pick("tp-src-computer", "rwkst1", "rwkst1", TYPE);
    await d.typeInto("tp-src-internalIp", "10.141.46.1", TYPE);
    await d.typeInto("tp-destination", "10.141.46.1", TYPE);
    await d.typeInto("tp-port", "443", TYPE);
    const p = await d.panelPoint(`document.getElementById("tp-protocol")`);
    await d.click(p.x, p.y);
    await Q().ev(`(() => { const s = document.getElementById("tp-protocol"); s.value = "TCP"; s.dispatchEvent(new Event("change", { bubbles: true })); })()`);
    await d.key("Escape");
    await d.clickPanel(btn("Check policy"));
    await d.waitPanel(`/Blocked|Allowed/.test(document.body.innerText.slice(document.body.innerText.lastIndexOf("Check policy")))`, 40000);
    await sleep(600);
    await d.pulse();
    await Q().ev(`(${btn("Check policy")})?.scrollIntoView({ block: "start", behavior: "smooth" })`);
    await sleep(2200);
    await d.caption("");
  },
};

const name = process.argv[2];
await d.init();
if (name === "prep") await d.prep();
else if (name === "toSteer") { await d.runPageNav(STEER, 9000); await d.init(); await P().ev(`(() => { const h = [...document.querySelectorAll("*")].find(e => e.children.length === 0 && /^Traffic Steering$/.test((e.textContent || "").trim())); h?.scrollIntoView({ block: "start", behavior: "instant" }); })()`); await sleep(800); }
else if (name === "toPolicy") { await d.runPageNav(POLICY, 12000); await d.init(); }
else await scenes[name]();
console.log("SCENE DONE", name);
process.exit(0);
