import * as d from "./drive.mjs";
const { sleep } = d;
await d.init(); await d.prep(); await d.init(); await d.fresh();
await d.openPanelClick();
await d.clickPanel(`document.querySelector('input.tp-connection-radio[value="client"]').closest("label")`);
const comp = process.argv[3] || "wkst1";
await d.pick("tp-src-roaming",comp,comp,15);
const cases = JSON.parse(process.argv[2]);
let curUser = null;
for (const [user, dest] of cases) {
  if (user !== curUser) {
    await d.Q().ev(`(()=>{const b=document.querySelector("#tp-src-identity")?.closest(".tp-picker")?.querySelector("button[aria-label*=Clear],.tp-picker-clear"); b?.click();})()`);
    await d.pick("tp-src-identity", user.split(" ")[0].toLowerCase(), user, 15); curUser = user;
  }
  await d.Q().ev(`(()=>{const el=document.getElementById("tp-destination"); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value").set.call(el,""); el.dispatchEvent(new Event("input",{bubbles:true}));})()`);
  await d.typeInto("tp-destination", dest, 8);
  await d.clickPanel(`[...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy")`);
  await sleep(5500);
  const t = await d.Q().ev(`(()=>{const b=document.body.innerText; const i=b.lastIndexOf("Check policy"); return b.slice(i+12).replace(/\\n+/g," | ").slice(0,260)})()`);
  console.log(user, "->", dest, "::", t);
}
process.exit(0);
