import { pageTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 1: Table Hover & Nested Identifiers Starting ===");
  const c = await connect(pageTarget());
  await initVirtualCursor(c);

  // Clean initial state: panel closed, dock/layers removed
  await c.send("Runtime.evaluate", {
    expression: `(() => {
      const p = document.getElementById("sec-embed-panel");
      if (p) p.classList.remove("sec-embed-open");
      const d = document.getElementById("sec-result-dock"); if (d) d.remove();
      const l = document.getElementById("sec-hit-layer"); if (l) l.remove();
      const pop = document.getElementById("sec-hover-popover"); if (pop) pop.classList.remove("sec-hover-visible");
      return true;
    })()`
  });
  await sleep(800);

  // Section Intro Banner
  await showSectionIntro(
    c,
    "SECTION 1 OF 6",
    "Interactive Table Hover & Nested Identifiers",
    "Resolving Active Directory users, groups, posture, and composite destinations",
    2800
  );

  // Helper to hover on an element with the virtual cursor
  async function hoverOn(selector, index, hoverMs = 3200) {
    // 1. Scroll the element into view and center it before any cursor movement
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const els = document.querySelectorAll(${JSON.stringify(selector)});
        const el = els[${index}];
        if (el) {
          el.scrollIntoView({ behavior: "smooth", block: "center" });
        }
        return true;
      })()`
    });
    // Wait for the smooth scroll to settle so the row is solidly centered in view
    await sleep(450);

    const coords = await c.send("Runtime.evaluate", {
      expression: `(() => {
        const els = document.querySelectorAll(${JSON.stringify(selector)});
        const el = els[${index}];
        if (!el) return null;
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2, text: el.innerText.trim() };
      })()`,
      returnByValue: true
    });
    const pt = coords.result?.value;
    if (!pt) {
      console.log("Element not found:", selector, index);
      return;
    }
    console.log("Hovering on:", pt.text, "at", pt.x, pt.y);
    await moveCursorTo(c, pt.x, pt.y, 400);

    // Trigger hover popover via mouseenter only after the row is present and centered
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const els = document.querySelectorAll(${JSON.stringify(selector)});
        const el = els[${index}];
        if (el) {
          el.dispatchEvent(new MouseEvent("mouseenter", {
            bubbles: true,
            cancelable: true,
            clientX: ${pt.x},
            clientY: ${pt.y}
          }));
        }
        return true;
      })()`
    });
    await sleep(hoverMs);

    // Leave
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const els = document.querySelectorAll(${JSON.stringify(selector)});
        const el = els[${index}];
        if (el) el.dispatchEvent(new MouseEvent("mouseleave", { bubbles: true, cancelable: true }));
        return true;
      })()`
    });
    await sleep(400);
  }

  // 1. Hover on Rule 2: Carol Freeman... +1 (AD User + Posture)
  console.log("Hover 1: Carol Freeman... +1");
  await hoverOn("[data-testid=\"policy-source-column\"]", 1, 3200);

  // 2. Hover on Rule 6: Finance +4 (Nested Active Directory Groups)
  console.log("Hover 2: Finance +4 (Nested Groups)");
  await hoverOn("[data-testid=\"policy-source-column\"]", 5, 3400);

  // 3. Hover on Rule 9: HR (d1.pseudoco.org) +1 (Nested Groups)
  console.log("Hover 3: Block Telnet & SSH (HR + Finance)");
  await hoverOn("[data-testid=\"policy-source-column\"]", 8, 3000);

  // 4. Hover on Rule 4: Composite Destination (Private Resource Groups + CIDR + Ports)
  console.log("Hover 4: Composite Destination 1 IP Address/CIDR +5");
  await hoverOn("[data-testid=\"policy-destination-item\"]", 3, 3400);

  // 5. Hover on Rule 3: Single Private Resource (PseudoCo HR)
  console.log("Hover 5: Destination PseudoCo HR");
  await hoverOn("[data-testid=\"policy-destination-item\"]", 2, 2800);

  // 6. Glide cursor to Policy Checker launcher button in bottom-right and click
  console.log("Opening Policy Checker panel via launcher");
  const btnCoords = await c.send("Runtime.evaluate", {
    expression: `(() => {
      const b = document.getElementById("sec-embed-toggle");
      if (!b) return null;
      const r = b.getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`,
    returnByValue: true
  });
  if (btnCoords.result?.value) {
    const pt = btnCoords.result.value;
    await moveCursorTo(c, pt.x, pt.y, 400);
    await pulseCursor(c);
    await c.send("Runtime.evaluate", {
      expression: `document.getElementById("sec-embed-toggle").click()`
    });
  }
  await sleep(1800);

  c.close();
  console.log("=== Clip 1 Complete ===");
}

main().catch(e => { console.error("FATAL", e); process.exit(1); });
