import { pageTarget, panelTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, moveCursorToPanelElement, clickPanelElement, typeIntoPanelInput, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 3: Traffic Steering Bypass Starting ===");
  const cPage = await connect(pageTarget());
  const cPanel = await connect(panelTarget());
  await initVirtualCursor(cPage);

  // Section 3 Intro Banner
  await showSectionIntro(
    cPage,
    "SECTION 3 OF 6",
    "Traffic Steering Exclusions",
    "Direct cloud endpoint routing -> Allowed (Bypasses Web Proxy)",
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
  await sleep(800);

  // 1. Move to destination field and type api.us-2.crowdstrike.com
  console.log("Typing steering exclusion destination...");
  await typeIntoPanelInput(cPage, cPanel, "tp-destination", "api.us-2.crowdstrike.com", 50);
  await sleep(1000);

  // 2. Click Check policy
  console.log("Clicking Check policy...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy"));
  
  // Evaluation wait
  await sleep(3800);

  // 3. Scroll to results
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const r = document.querySelector(".tp-results");
      if (r) r.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3500);

  // 4. Click Show on page
  console.log("Clicking Show on page...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page"));
  await sleep(1500);

  // 5. Scroll highlight into view
  await cPage.send("Runtime.evaluate", {
    expression: `(() => {
      const hit = document.querySelector(".sec-hit-ring");
      if (hit) hit.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3000);

  cPage.close();
  cPanel.close();
  console.log("=== Clip 3 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
