import * as d from "./drive.mjs";
const { sleep } = d;
const P = () => d.P();

const srcCell = i => `document.querySelectorAll("tbody tr")[${i}].querySelector('[data-testid="policy-source-column"]')`;
const dstItem = (i, k = 0) => `document.querySelectorAll("tbody tr")[${i}].querySelectorAll('[data-testid="policy-destination-item"]')[${k}]`;
const pop = `document.getElementById("sec-hover-popover")`;
const expChip = k => `${pop}.querySelectorAll(".sec-hp-expandable")[${k}]`;

async function hover(kind, row, hold = 2600, k = 0) {
  await d.scrollTable(row - 1, 750);
  await d.hoverCell(kind === "src" ? srcCell(row - 1) : dstItem(row - 1, k), 500, kind === "src");
  await sleep(hold);
}
async function intoChip(k, hold = 2600) {
  await d.hoverCell(expChip(k), 450);
  await sleep(hold);
}

const scenes = {
  async hover() {
    await d.fresh();
    await d.card("Chapter 1", "Hover any rule", "Groups, IP objects and nested resources resolve right on the Access Policy table", 3200);
    await d.scrollTable(0, 800);
    await hover("src", 2, 2600);
    await d.parkCursor(); 
    await hover("src", 9, 1400);
    await intoChip(0, 3000);
    await intoChip(1, 3000);
    await d.parkCursor();
    await hover("dst", 4, 1600);
    await intoChip(0, 3000);
    await d.parkCursor();
    await hover("dst", 25, 1400);
    await intoChip(0, 1800);
    await d.hoverCell(`document.querySelector(".sec-member-panel .sec-mp-expandable")`, 450);
    await sleep(3500);
    await d.parkCursor();
    await d.scrollTable(0, 900);
    await sleep(600);
  },
  async secureClient() { await check({ kicker: "Chapter 2", title: "Check a request: Secure Client", sub: "Carol Freeman on wkst1 to example.com", conn: "client",
    steps: [["pick", "tp-src-roaming", "wkst1", "wkst1"], ["pick", "tp-src-identity", "carol", "Carol Freeman"], ["type", "tp-destination", "example.com"]] }); },
  async bypass() { await check({ kicker: "Chapter 3", title: "Traffic steering exclusions", sub: "A cloud endpoint that bypasses Secure Access entirely", conn: "client",
    steps: [["pick", "tp-src-roaming", "wkst1", "wkst1"], ["pick", "tp-src-identity", "carol", "Carol Freeman"], ["type", "tp-destination", "api.us-2.crowdstrike.com"]] }); },
  async ravpn() { await check({ kicker: "Chapter 4", title: "Remote access VPN and the firewall", sub: "A private IP, port and protocol checked against firewall rules", conn: "vpn",
    steps: [["pick", "tp-src-identity", "paul", "Paul Cole"], ["pick", "tp-src-computer", "rwkst1", "rwkst1"], ["type", "tp-src-internalIp", "10.141.46.1"], ["type", "tp-destination", "10.141.46.1"], ["type", "tp-port", "443"], ["select", "tp-protocol", "TCP"]] }); },
  async va() { await check({ kicker: "Chapter 5", title: "Branch office: virtual appliance", sub: "A site and internal client IP, then a Network DNS location", conn: "va",
    steps: [["pick", "tp-src-site", "Default", "Default Site"], ["type", "tp-src-internalIp", "192.168.1.105"], ["pick", "tp-src-identity", "anna", "Anna Mariano"], ["type", "tp-destination", "example.com"]] }); },
  async netdns() { await check({ kicker: "Chapter 5b", title: "Network DNS location", sub: "London 1 to example.com", conn: "network", skipCard: true,
    steps: [["pick", "tp-src-network", "London", "London 1"], ["type", "tp-destination", "example.com"]] }); },
  async audit() {
    await d.fresh();
    await d.card("Chapter 6", "Rules and audit", "Shadowed, duplicate and over-permissive rules found automatically", 3000);
    await d.openPanelClick();
    const tab = `[...document.querySelectorAll("button")].find(x => x.getAttribute("data-target") === "tab-rules")`;
    await d.clickPanel(tab);
    await sleep(4500);
    await d.Q().ev(`document.getElementById("rules-root")?.scrollIntoView({ behavior: "smooth", block: "start" })`);
    await sleep(4500);
    await d.Q().ev(`(document.querySelector("#tab-rules") || document.body).scrollTo?.({ top: 700, behavior: "smooth" })`);
    await sleep(3500);
  },
};

async function check(o) {
  await d.fresh();
  if (!o.skipCard) await d.card(o.kicker, o.title, o.sub, 3000);
  await d.openPanelClick();
  await sleep(500);
  await d.clickPanel(`document.querySelector('input.tp-connection-radio[value="${o.conn}"]').closest("label")`);
  await sleep(700);
  for (const [kind, id, a, b] of o.steps) {
    if (kind === "pick") await d.pick(id, a, b);
    else if (kind === "type") await d.typeInto(id, a, 85);
    else if (kind === "select") {
      const p = await d.panelPoint(`document.getElementById("${id}")`);
      await d.click(p.x, p.y);
      await d.Q().ev(`(() => { const s = document.getElementById("${id}"); s.value = "${a}"; s.dispatchEvent(new Event("change", { bubbles: true })); })()`);
      await d.key("Escape");
      await sleep(500);
    }
    await sleep(350);
  }
  await sleep(900);
  await d.clickPanel(`[...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy")`);
  await d.waitPanel(`/Allowed|Blocked|Bypass|Pending|Waiting/.test(document.body.innerText)`);
  await sleep(1200);
  await d.Q().ev(`document.querySelector("button.tp-show-on-page, [data-action=show-on-page]")?.scrollIntoView({ block: "center", behavior: "smooth" })`);
  await sleep(500);
  const verdict = await d.Q().ev(`document.body.innerText.match(/(Allowed|Blocked|Bypasses[^\\n]*|Pending[^\\n]*)\\n[^\\n]*/)?.[0] || ""`);
  console.log("VERDICT:", verdict.replace(/\n/g, " | "));
  await sleep(4500);
  const show = `[...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page")`;
  if (await d.Q().ev(`!!(${show})`)) {
    await d.clickPanel(show);
    await sleep(4800);
  }
  await d.parkCursor(700, 960);
  await sleep(800);
}

const name = process.argv[2];
await d.init();
if (name === "prep") await d.prep(); else await scenes[name]();
console.log("SCENE DONE", name);
process.exit(0);
