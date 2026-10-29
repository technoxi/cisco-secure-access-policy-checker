import { execSync } from "node:child_process";
const t = JSON.parse(execSync("curl -sS http://127.0.0.1:9222/json/list").toString()).find(t=>t.type==="service_worker");
const ws=new WebSocket(t.webSocketDebuggerUrl); await new Promise(r=>ws.onopen=r);
let i=0;const pend={};ws.onmessage=e=>{const m=JSON.parse(e.data);pend[m.id]?.(m)};
const send=(method,params={})=>new Promise(r=>{pend[++i]=r;ws.send(JSON.stringify({id:i,method,params}))});
const r=await send("Runtime.evaluate",{expression:process.argv[2],returnByValue:true,awaitPromise:true});
console.log(JSON.stringify(r.result.result?.value ?? r.result.exceptionDetails).slice(0,3000));
process.exit(0);
