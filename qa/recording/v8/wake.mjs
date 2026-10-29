import * as d from "./drive.mjs"; await d.init(); await d.setPanel(true); await d.sleep(1500); await d.setPanel(false); process.exit(0);
