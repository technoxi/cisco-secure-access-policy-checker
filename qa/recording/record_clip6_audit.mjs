import { pageTarget, panelTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, moveCursorToPanelElement, clickPanelElement, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 6: Rules & Audit Tab Starting ===");
  const cPage = await connect(pageTarget());
  const cPanel = await connect(panelTarget());
  await initVirtualCursor(cPage);

  // Section 6 Intro Banner
  await showSectionIntro(
    cPage,
    "SECTION 6 OF 6",
    "Policy Audit & Shadowed Rules Engine",
    "Automated detection of shadowed rules, duplicates, and over-permissive bypasses",
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

  // Move cursor to Rules & audit tab button and click
  console.log("Switching to Rules & audit tab...");
  await clickPanelElement(cPage, cPanel, () => {
    const btn = [...document.querySelectorAll("button")].find(x => x.getAttribute("data-target") === "tab-rules");
    const tab = document.getElementById("tab-rules");
    if (btn) btn.removeAttribute("hidden");
    if (tab) tab.removeAttribute("hidden");
    return btn;
  });
  await sleep(4000); // inspect summary metrics

  // Scroll down through findings
  console.log("Scrolling through audit findings...");
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const root = document.getElementById("rules-root");
      if (root) root.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(4500); // inspect shadowed & duplicate rules

  // Scroll back to top
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const btn = [...document.querySelectorAll("button")].find(x => x.getAttribute("data-target") === "tab-rules");
      if (btn) btn.scrollIntoView({ behavior: "smooth", block: "start" });
      return true;
    })()`
  });
  await sleep(2000);

  // Switch back to Check a request
  console.log("Switching back to Check a request...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.getAttribute("data-target") === "tab-tester"));
  await sleep(2500);

  cPage.close();
  cPanel.close();
  console.log("=== Clip 6 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
