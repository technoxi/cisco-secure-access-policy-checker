import * as d from "./drive.mjs";
await d.init(); const P=d.P();
await d.setPanel(false);
for (const col of ["policy-source-column","policy-destination-column"]) {
 for (let i=0;i<34;i++){
  await d.scrollTable(i,350);
  const sel = `document.querySelectorAll('[data-testid="${col}"]')[${i}]`;
  let r; try { r = await d.pageRect(sel,null);} catch(e){ console.log(col,i,"nocell"); continue; }
  await d.move(r.l+10, r.y, 350); await d.sleep(500);
  const info = await P.ev(`(() => { const p=document.getElementById("sec-hover-popover"); if(!p||!p.classList.contains("sec-hover-visible")) return "nopop"; const ex=p.querySelectorAll(".sec-hp-expandable").length; return "chips="+p.querySelectorAll(".sec-hp-chip").length+" expandable="+ex+" | "+[...p.querySelectorAll(".sec-hp-section")].map(s=>s.innerText.replace(/\\n+/g,'; ').slice(0,110)).join(' || '); })()`);
  console.log(col.replace("policy-","").replace("-column",""), i+1, info);
 }
}
process.exit(0);
