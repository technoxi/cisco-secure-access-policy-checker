import { pageTarget, panelTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, moveCursorToPanelElement, clickPanelElement, typeIntoPanelInput, pickPanelDropdown, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 2: Case 1 Starting ===");
  const cPage = await connect(pageTarget());
  const cPanel = await connect(panelTarget());
  await initVirtualCursor(cPage);

  // Reset any saved drafts or form content in storage to guarantee clean initial state
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      try { sessionStorage.removeItem("psc.policyChecker.draft.v2"); } catch (_) {}
      try { sessionStorage.removeItem("psc.policyChecker.mode.v1"); } catch (_) {}
      try { sessionStorage.removeItem("psc.policyChecker.describe.v1"); } catch (_) {}
      try { localStorage.removeItem("psc.policyChecker.draft.v2"); } catch (_) {}
      try { localStorage.removeItem("psc.policyChecker.mode.v1"); } catch (_) {}
      try { localStorage.removeItem("psc.policyChecker.describe.v1"); } catch (_) {}
      const btn = [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Reset");
      if (btn) btn.click();
      return true;
    })()`
  });
  await sleep(600);

  // Section 2 Intro Banner
  await showSectionIntro(
    cPage,
    "SECTION 2 OF 6",
    "Policy Matching Engine: Secure Client",
    "Evaluating AD User (Carol Freeman) + wkst1 (Posture) to example.com -> Allowed",
    2800
  );

  // 1. Move cursor to Secure Client connection card and select
  console.log("Selecting Secure Client connection...");
  await clickPanelElement(cPage, cPanel, () => document.querySelector("input.tp-connection-radio[value=\"client\"]")?.closest("label") || document.querySelector("input.tp-connection-radio[value=\"client\"]"));
  await sleep(900);

  // 2. Pick wkst1 posture with visible typing and selection
  console.log("Picking wkst1 posture...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-roaming", "wkst1", "wkst1");
  await sleep(700);

  // 3. Pick Carol Freeman AD User with visible typing and selection
  console.log("Picking Carol Freeman...");
  await pickPanelDropdown(cPage, cPanel, "tp-src-identity", "carol", "Carol Freeman");
  await sleep(700);

  // 4. Type destination example.com character by character at natural human pace
  console.log("Typing destination...");
  await typeIntoPanelInput(cPage, cPanel, "tp-destination", "example.com", 70);
  await sleep(1500);

  // 5. Move cursor to Check policy button and click
  console.log("Clicking Check policy...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(b => b.innerText.trim() === "Check policy"));
  
  // Evaluation wait (tightened to 4s)
  await sleep(4000);

  // 6. Scroll down in panel to inspect verdict
  await cPanel.send("Runtime.evaluate", {
    expression: `(() => {
      const r = document.querySelector(".tp-results");
      if (r) r.scrollIntoView({ behavior: "smooth", block: "center" });
      return true;
    })()`
  });
  await sleep(3500);

  // 7. Click Show on page
  console.log("Clicking Show on page...");
  await clickPanelElement(cPage, cPanel, () => [...document.querySelectorAll("button")].find(x => x.innerText.trim() === "Show on page"));
  await sleep(1500);

  // 8. Smooth scroll to highlight ring on main policy table
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
  console.log("=== Clip 2 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
