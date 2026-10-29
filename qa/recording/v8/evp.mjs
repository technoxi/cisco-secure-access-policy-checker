import * as d from "./drive.mjs"; await d.init();
console.log(JSON.stringify(await d.P().ev(process.argv[2])));
process.exit(0);
