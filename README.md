# Cisco Secure Access Policy Checker

A Chrome extension for **Cisco Secure Access (SSE)** that evaluates and explains policy verdicts in real time. It overlays directly onto the Secure Access dashboard to test traffic paths (DNS, Web, Firewall, Private Access), inspect rule evaluations, resolve names, and verify exclusions and traffic steering.

---

## Quick Start & Installation

### Option 1: Download ZIP (Recommended)
1. Click the green **Code** button at the top of the repository and choose **Download ZIP** (or [click here to download](https://github.com/technoxi/cisco-secure-access-policy-checker/archive/refs/heads/main.zip)).
2. Unzip the downloaded archive.
3. Open Google Chrome and navigate to `chrome://extensions`.
4. Turn on **Developer mode** in the top-right corner.
5. Click **Load unpacked** and select the `extension/` folder inside the unzipped repository.

### Option 2: Clone with Git
```bash
git clone https://github.com/technoxi/cisco-secure-access-policy-checker.git
```
Then load the `extension/` directory into `chrome://extensions` via **Load unpacked**.

---

## How to Use

1. **Sign in to Cisco Secure Access**: Open [dashboard.sse.cisco.com](https://dashboard.sse.cisco.com) in Chrome.
2. **Navigate to Policy Rules**: Open **Secure > Policy > Rules** (or your access rules page).
3. **Open the Policy Checker**: Click the floating shield button in the bottom corner of the page, or click the extension icon in the Chrome toolbar.
4. **Simulate a Request**:
   - Choose your **Connection** method (Secure Client, Remote Access VPN, Site-to-site tunnel, On-prem VA, or Network DNS).
   - Pick or search your **Source identities** (Roaming Computer, User, AD Group, or Site).
   - Enter your **Destination** (e.g. `example.com`, an internal IP like `10.141.46.1`, or an excluded domain like `api.us-2.crowdstrike.com`).
   - Click **Check destination**.

---

## Key Features

### 1. Accurate Multi-Stage Pipeline Evaluation
Simulates the actual Cisco Secure Access enforcement order based on connection type:

| Connection Type | Supported Sources | Enforcement Pipeline |
|---|---|---|
| **Secure Client** | Roaming computer, user or group | DNS → Web |
| **Remote Access VPN** | User or group, AD computer, VPN client IP | Firewall → Web |
| **Site-to-site Tunnel** | Network tunnel, SD-WAN branch, internal IP, user/group | Firewall → Web |
| **On-prem VA** | Site, internal IP, user or group, AD computer | DNS |
| **Network DNS** | Registered network (public IP) | DNS |

### 2. Traffic Steering & Exclusion Support
- **Bypass Secure Access**: Full bypass of both DNS and Web proxy stages for traffic-steered domains.
- **Bypass Web Proxy**: Preserves DNS policy evaluation while automatically bypassing Web proxy inspection (e.g. for endpoint agent APIs like `api.us-2.crowdstrike.com` and `*halcyon.ai`).
- **Internal Domains**: Automatically honors organization-configured internal domains and steering lists alongside fallback entries.

### 3. Automated Cisco Investigate Intelligence
- Queries Cisco Investigate using your active dashboard session to classify domains into content categories, threat categories (Malware, Phishing, etc.), and cloud application signatures.
- Prompts for clarification only when additional destination facts are needed.

### 4. Direct Dashboard Integration
- **Show on page**: Highlights matching policy rules directly in the dashboard's rule table.
- **Result Dock**: Docks a compact verdict widget when the checker panel is minimized.
- **Rules Audit**: Detects shadowed rules, duplicate definitions, and overly permissive catch-all rules.

---

## Understanding Verdicts

- **Allowed**: Connection is permitted through all applicable enforcement points.
- **Allowed (Bypasses Web Proxy)**: Permitted by DNS policy, while the Web proxy stage is bypassed via Traffic Steering.
- **Bypassed via Traffic Steering**: Connection completely bypasses Secure Access inspection.
- **Blocked**: Identifies which enforcement stage (DNS, Web, or Firewall) and rule blocked the connection.
- **Provisional Allow**: Initial TCP flow allowed while the firewall identifies the application signature.

> *Note*: Verdicts reflect rule configurations. Upstream security profile blocks (file inspection, DLP, tenant controls, IPS) can still apply to observed traffic.

## QA against Activity Search

Replays a real Activity Search export through the checker (form, model and matcher) against the tenant's live rules, and compares the predicted layer and rule with what was logged. Tenant data stays in `qa/data/`, which is git-ignored.

```
python3 qa/export-to-jsonl.py export.xlsx              # → qa/data/events.jsonl
node qa/dump-extension-data.mjs 9444 dump qa/data/extension-data.json   # from a signed-in Chrome, see the file header
node qa/replay-activity.mjs                            # prints accuracy per layer and rule
```

By default the replay answers category, app and threat questions from what the log recorded. `--investigate=<lookups.json>` answers them only from Cisco Investigate lookups (`{ host: lookupDestination result }`, collected from the extension's service worker) to measure the fully automatic path. Blocks the log attributes to a scanned file, DLP, app controls or IPS are counted separately: they depend on content, not on the destination.

## Tests

```
node test-traffic-path.js      # Policy Checker model through the real matcher
node test-matcher.js
node test-policy-regressions.js
node test-checks.js
node test-membership.js
```

## Repo structure

```
extension/
├── manifest.json              # MV3 manifest
├── background/
│   └── service-worker.js      # Token capture, API fetching, data resolution
├── content/
│   ├── content-script.js      # Dashboard overlay: panel, hover cards, rule highlight, result card
│   ├── token-sniffer.js       # Intercepts auth tokens from dashboard responses
│   ├── styles.css             # Dashboard overlay styles
│   └── token-relay.js         # Relays captured tokens to the service worker
├── popup/
│   ├── popup.html             # Extension popup UI (also embedded in the dashboard panel)
│   ├── popup.js               # Popup logic, reads from chrome.storage
│   ├── traffic-path.js        # Policy Checker model: connections, stages, evaluation
│   ├── traffic-path-panel.js  # Policy Checker UI
│   ├── traffic-path.css       # Policy Checker styles
│   ├── matcher.js             # Rule condition matching and label resolution
│   ├── ip-address.js          # IPv4/IPv6 and CIDR parsing
│   └── popup-sections.js      # Rules & Audit tab
├── lib/
│   └── debug-log.js           # Persistent debug logging
└── data/
    ├── apps-lookup.json        # Application ID → name mappings
    ├── categories-lookup.json  # Content category bit position → category ID and name
    └── protocols-lookup.json   # Protocol number → name mappings
qa/
├── export-to-jsonl.py         # Activity Search export (.xlsx/.csv) → JSON Lines
├── dump-extension-data.mjs    # Read rules + catalogs from a signed-in Chrome
└── replay-activity.mjs        # Replay events through the checker, report mismatches
```
