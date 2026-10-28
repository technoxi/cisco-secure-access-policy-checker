import { pageTarget, panelTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, moveCursorToPanelElement, clickPanelElement, typeIntoPanelInput, pickPanelDropdown, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 4: RAVPN Case Starting ===");
  const cPage = await connect(pageTarget());
  const cPanel = await connect(panelTarget());
  await initVirtualCursor(cPage);

  // Section 4 Intro Banner
  await showSectionIntro(
    cPage,
    "SECTION 4 OF 6",
    "Remote Access VPN & Private Access Firewall",
    "Private IP destination evaluated against Firewall rules -> Blocked Verdict",
    2800
  );

  // Re-open panel if collapsed
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const p = document.getElementById("sec-embed-panel");
      if (p && !p.classList.contains("sec-embed-open")) {
        const t = document.getElementById("sec-embed-toggle");
        if (t) t.click();
      }
      return true;
    })()`
  });
  await sleep(600);

  // 1. Select Remote access VPN
  console.log("Selecting Remote access VPN...");
  await clickPanelElement(cPage, cPanel, () => document.querySelector("input.tp-connection-radio[value=\"vpn\"]")?.closest("label") || document.querySelector("input.tp-connection-radio[value=\"vpn\"]"));
  await sleep(700);

  // 2. User Paul Cole
  console.log("Picking Paul Cole...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-identity", "Paul", "Paul Cole");
  await sleep(500);

  // 3. Computer rwkst1
  console.log("Picking rwkst1...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-computer", "wkst1", "rwkst1");
  await sleep(500);

  // 4. VPN Client IP 10.141.46.1
  console.log("Typing internal client IP...");
  await typeIntoPanelInput(cPage, cPanel, "tp-src-internalIp", "10.141.46.1", 50);
  await sleep(400);

  // 5. Destination IP 10.141.46.1
  console.log("Typing destination IP...");
  await typeIntoPanelInput(cPage, cPanel, "tp-destination", "10.141.46.1", 50);
  await sleep(400);

  // 6. Port 443
  console.log("Typing port 443...");
  await typeIntoPanelInput(cPage, cPanel, "tp-port", "443", 60);
  await sleep(300);

  // 7. Protocol TCP
  console.log("Selecting TCP...");
  await clickPanelElement(cPage, cPanel, "#tp-protocol");
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const el = document.getElementById("tp-protocol");
      if (el) { el.value = "TCP"; el.dispatchEvent(new Event("change", { bubbles: true })); }
      return true;
    })()`
  });
  await sleep(1500); // show all filled fields

  // 8. Click Check policy
  console.log("Clicking Check policy...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy"));
  
  // Evaluation wait
  await sleep(3800);

  // 9. Scroll to results
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const r = document.querySelector(".tp-results");
      if (r) r.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3500); // view Blocked at Firewall

  // 10. Click Show on page
  console.log("Clicking Show on page...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page"));
  await sleep(1500);

  // 11. Scroll highlight ring into view
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const hit = document.querySelector(".sec-hit-ring");
      if (hit) hit.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3500);

  cPage.close();
  cPanel.close();
  console.log("=== Clip 4 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
