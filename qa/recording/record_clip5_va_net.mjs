import { pageTarget, panelTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, moveCursorToPanelElement, clickPanelElement, typeIntoPanelInput, pickPanelDropdown, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 5: VA & Network DNS Starting ===");
  const cPage = await connect(pageTarget());
  const cPanel = await connect(panelTarget());
  await initVirtualCursor(cPage);

  // Section 5 Intro Banner
  await showSectionIntro(
    cPage,
    "SECTION 5 OF 6",
    "Branch Office: Virtual Appliance & Network DNS",
    "Evaluating Site + internal client IP, and Network DNS location policies",
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

  // --- Case 4: On-prem VA ---
  console.log("Selecting On-prem VA...");
  await clickPanelElement(cPage, cPanel, () => document.querySelector("input.tp-connection-radio[value=\"va\"]")?.closest("label") || document.querySelector("input.tp-connection-radio[value=\"va\"]"));
  await sleep(600);

  console.log("Picking Default Site...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-site", "Default", "Default Site");
  await sleep(400);

  console.log("Typing internal IP...");
  await typeIntoPanelInput(cPage, cPanel, "tp-src-internalIp", "192.168.1.105", 50);
  await sleep(400);

  console.log("Picking Anna Mariano...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-identity", "Anna", "Anna Mariano");
  await sleep(400);

  console.log("Typing destination...");
  await typeIntoPanelInput(cPage, cPanel, "tp-destination", "example.com", 50);
  await sleep(1000);

  console.log("Clicking Check policy (VA)...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy"));
  await sleep(3800); // evaluation

  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const r = document.querySelector(".tp-results");
      if (r) r.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3000); // inspect Allowed DNS verdict

  console.log("Clicking Show on page...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page"));
  await sleep(2500);

  // --- Case 5: Network DNS ---
  console.log("Re-opening panel for Case 5...");
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

  console.log("Selecting Network DNS...");
  await clickPanelElement(cPage, cPanel, () => document.querySelector("input.tp-connection-radio[value=\"network\"]")?.closest("label") || document.querySelector("input.tp-connection-radio[value=\"network\"]"));
  await sleep(600);

  console.log("Picking London 1 network...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-network", "London", "London 1");
  await sleep(400);

  console.log("Typing destination...");
  await typeIntoPanelInput(cPage, cPanel, "tp-destination", "example.com", 50);
  await sleep(1000);

  console.log("Clicking Check policy (Network DNS)...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy"));
  await sleep(3800);

  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const r = document.querySelector(".tp-results");
      if (r) r.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3000);

  console.log("Clicking Show on page...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page"));
  await sleep(2500);

  cPage.close();
  cPanel.close();
  console.log("=== Clip 5 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
