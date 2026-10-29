import * as d from "./drive.mjs"; await d.init();
await d.click(+process.argv[2], +process.argv[3]); await d.sleep(1500);
console.log(await d.P().ev(`location.href+"\\n"+[...document.querySelectorAll("a[href*='/org/']")].map(a=>a.innerText.trim().replace(/\\n/g," ")+" -> "+a.getAttribute("href")).filter((v,i,a)=>a.indexOf(v)===i).slice(0,40).join("\\n")`));
process.exit(0);
