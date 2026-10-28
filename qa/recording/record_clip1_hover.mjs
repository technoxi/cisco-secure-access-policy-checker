import { pageTarget, connect, initVirtualCursor, moveCursorTo, pulseCursor, showSectionIntro, sleep } from "./walkthrough_helpers.mjs";

async function main() {
  console.log("=== Clip 1: Table Hover & Nested Identifiers Starting ===");
  const c = await connect(pageTarget());
  await initVirtualCursor(c);

  // 1. Pre-demo Filter Reset: Ensure dashboard search and filters are completely clear
  console.log("Resetting pre-demo filters and search state...");
  await c.send("Runtime.evaluate", {
    expression: `(() => {
      // Clear policy search input
      const searchInput = document.getElementById("policy-search");
      if (searchInput && searchInput.value) {
        searchInput.value = "";
        searchInput.dispatchEvent(new Event("input", { bubbles: true }));
        searchInput.dispatchEvent(new Event("change", { bubbles: true }));
      }
      // Click any filter clear/reset buttons on the dashboard
      const clearBtns = [...document.querySelectorAll("button")].filter(b =>
        /clear (all|filter)|reset filter/i.test(b.innerText || b.getAttribute("aria-label") || "")
      );
      clearBtns.forEach(b => b.click());

      // Scroll page and table cleanly to top
      window.scrollTo({ top: 0, behavior: "instant" });
      const tbl = document.querySelector("table");
      if (tbl) tbl.scrollIntoView({ block: "start", behavior: "instant" });

      // Clean initial overlays, popovers, and cascade panels
      const p = document.getElementById("sec-embed-panel");
      if (p) p.classList.remove("sec-embed-open");
      const d = document.getElementById("sec-result-dock"); if (d) d.remove();
      const l = document.getElementById("sec-hit-layer"); if (l) l.remove();
      const pop = document.getElementById("sec-hover-popover"); if (pop) pop.classList.remove("sec-hover-visible");
      document.querySelectorAll(".sec-member-panel").forEach(mp => mp.remove());
      return true;
    })()`
  });
  await sleep(1000);

  // Section Intro Banner
  await showSectionIntro(
    c,
    "SECTION 1 OF 6",
    "Interactive Table Hover & Nested Identifiers",
    "Multi-level resolution of Active Directory users, groups, and composite destinations",
    2800
  );

  // Helper to hover on an element with the virtual cursor
  async function hoverOn(selector, index, hoverMs = 2800) {
    // Scroll element into view and center it
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

    // Trigger hover popover via mouseenter
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
        const pop = document.getElementById("sec-hover-popover");
        if (pop) pop.classList.remove("sec-hover-visible");
        document.querySelectorAll(".sec-member-panel").forEach(mp => mp.remove());
        return true;
      })()`
    });
    await sleep(400);
  }

  // 1. Hover on Rule 2: Carol Freeman... +1 (AD User + Posture)
  console.log("Hover 1: Carol Freeman... +1");
  await hoverOn("[data-testid=\"policy-source-column\"]", 1, 2800);

  // 2. Hover on Rule 6: Finance +4 (Nested Active Directory Groups) -> Cascade Flyout
  console.log("Hover 2: Finance +4 with multi-level group cascade");
  await (async () => {
    // Center row 6
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const els = document.querySelectorAll('[data-testid="policy-source-column"]');
        if (els[5]) els[5].scrollIntoView({ behavior: "smooth", block: "center" });
        return true;
      })()`
    });
    await sleep(450);

    const cellPt = await c.send("Runtime.evaluate", {
      expression: `(() => {
        const el = document.querySelectorAll('[data-testid="policy-source-column"]')[5];
        const r = el.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2, text: el.innerText.trim() };
      })()`,
      returnByValue: true
    });
    const pt = cellPt.result.value;
    await moveCursorTo(c, pt.x, pt.y, 400);

    // Open popover
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const el = document.querySelectorAll('[data-testid="policy-source-column"]')[5];
        el.dispatchEvent(new MouseEvent("mouseenter", {
          bubbles: true, cancelable: true, clientX: ${pt.x}, clientY: ${pt.y}
        }));
        return true;
      })()`
    });
    await sleep(1000);

    // Glide into expandable chip inside popover
    const chipPt = await c.send("Runtime.evaluate", {
      expression: `(() => {
        const pop = document.getElementById("sec-hover-popover");
        const exp = pop?.querySelector(".sec-hp-chip.sec-hp-expandable");
        if (!exp) return null;
        const r = exp.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`,
      returnByValue: true
    });
    if (chipPt.result.value) {
      const cpt = chipPt.result.value;
      console.log("Gliding to expandable group chip in popover:", cpt);
      await moveCursorTo(c, cpt.x, cpt.y, 400);
      await pulseCursor(c);
      await c.send("Runtime.evaluate", {
        expression: `(() => {
          const pop = document.getElementById("sec-hover-popover");
          const exp = pop?.querySelector(".sec-hp-chip.sec-hp-expandable");
          if (exp) {
            exp.dispatchEvent(new MouseEvent("mouseenter", {
              bubbles: true, cancelable: true, clientX: ${cpt.x}, clientY: ${cpt.y}
            }));
          }
          return true;
        })()`
      });
      await sleep(1600);
    }

    // Dismiss
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const pop = document.getElementById("sec-hover-popover");
        if (pop) pop.classList.remove("sec-hover-visible");
        document.querySelectorAll(".sec-member-panel").forEach(mp => mp.remove());
        return true;
      })()`
    });
    await sleep(400);
  })();

  // 3. Hover on Rule 25: All Employees Apps -> Multi-Level Cascade to Intranet FQDNs
  console.log("Hover 3: All Employees Apps (Multi-Level Destination Cascade)");
  await (async () => {
    // Find and center row 25
    await c.send("Runtime.evaluate", {
      expression: `(() => {
        const rows = [...document.querySelectorAll("table tr")];
        const match = rows.find(r => r.innerText.includes("All Employees Apps"));
        if (match) match.scrollIntoView({ behavior: "smooth", block: "center" });
        return true;
      })()`
    });
    await sleep(450);

    const destPt = await c.send("Runtime.evaluate", {
      expression: `(() => {
        const rows = [...document.querySelectorAll("table tr")];
        const match = rows.find(r => r.innerText.includes("All Employees Apps"));
        const destChip = match?.querySelector('[data-testid="policy-destination-item"]');
        if (!destChip) return null;
        const r = destChip.getBoundingClientRect();
        return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
      })()`,
      returnByValue: true
    });
    if (destPt.result.value) {
      const dpt = destPt.result.value;
      await moveCursorTo(c, dpt.x, dpt.y, 400);
      // Trigger popover
      await c.send("Runtime.evaluate", {
        expression: `(() => {
          const rows = [...document.querySelectorAll("table tr")];
          const match = rows.find(r => r.innerText.includes("All Employees Apps"));
          const destChip = match?.querySelector('[data-testid="policy-destination-item"]');
          if (destChip) {
            destChip.dispatchEvent(new MouseEvent("mouseenter", {
              bubbles: true, cancelable: true, clientX: ${dpt.x}, clientY: ${dpt.y}
            }));
          }
          return true;
        })()`
      });
      await sleep(1000);

      // Glide into Level 1 expandable chip (Private Resource Group)
      const expPt = await c.send("Runtime.evaluate", {
        expression: `(() => {
          const pop = document.getElementById("sec-hover-popover");
          const chip = pop?.querySelector(".sec-hp-chip.sec-hp-expandable");
          if (!chip) return null;
          const r = chip.getBoundingClientRect();
          return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
        })()`,
        returnByValue: true
      });
      if (expPt.result.value) {
        const ept = expPt.result.value;
        console.log("Gliding to Private Resource Group chip:", ept);
        await moveCursorTo(c, ept.x, ept.y, 400);
        await pulseCursor(c);
        // Open Level 1 panel
        await c.send("Runtime.evaluate", {
          expression: `(() => {
            const pop = document.getElementById("sec-hover-popover");
            const chip = pop?.querySelector(".sec-hp-chip.sec-hp-expandable");
            if (chip) {
              chip.dispatchEvent(new MouseEvent("mouseenter", {
                bubbles: true, cancelable: true, clientX: ${ept.x}, clientY: ${ept.y}
              }));
            }
            return true;
          })()`
        });
        await sleep(900);

        // Glide into Level 1 panel expandable row (Intranet Resource) -> opens Level 2 panel
        const l1Pt = await c.send("Runtime.evaluate", {
          expression: `(() => {
            const panels = [...document.querySelectorAll(".sec-member-panel")];
            if (!panels.length) return null;
            const expRow = panels[0].querySelector(".sec-mp-row.sec-mp-expandable");
            if (!expRow) return null;
            const r = expRow.getBoundingClientRect();
            return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
          })()`,
          returnByValue: true
        });
        if (l1Pt.result.value) {
          const lpt = l1Pt.result.value;
          console.log("Gliding to Intranet Resource in Level 1 panel:", lpt);
          await moveCursorTo(c, lpt.x, lpt.y, 450);
          await pulseCursor(c);
          // Open Level 2 panel
          await c.send("Runtime.evaluate", {
            expression: `(() => {
              const panels = [...document.querySelectorAll(".sec-member-panel")];
              const expRow = panels[0]?.querySelector(".sec-mp-row.sec-mp-expandable");
              if (expRow) {
                expRow.dispatchEvent(new MouseEvent("mouseenter", {
                  bubbles: true, cancelable: true, clientX: ${lpt.x}, clientY: ${lpt.y}
                }));
              }
              return true;
            })()`
          });
          await sleep(2200); // Hold so viewer clearly sees 3-level cascade!
        }
      }

      // Dismiss
      await c.send("Runtime.evaluate", {
        expression: `(() => {
          const pop = document.getElementById("sec-hover-popover");
          if (pop) pop.classList.remove("sec-hover-visible");
          document.querySelectorAll(".sec-member-panel").forEach(mp => mp.remove());
          return true;
        })()`
      });
      await sleep(400);
    }
  })();

  // 4. Hover on Rule 4: Composite Destination (Private Resource Groups + CIDR + Ports)
  console.log("Hover 4: Composite Destination 1 IP Address/CIDR +5");
  await hoverOn("[data-testid=\"policy-destination-item\"]", 3, 2600);

  // 5. Hover on Rule 3: Single Private Resource (PseudoCo HR)
  console.log("Hover 5: Destination PseudoCo HR");
  await hoverOn("[data-testid=\"policy-destination-item\"]", 2, 2200);

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
