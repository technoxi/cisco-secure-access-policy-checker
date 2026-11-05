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

## Replaying Activity Search exports

`tools/replay/` replays a real Activity Search export through the checker (form, model and matcher) against the tenant's live rules, and compares the predicted layer and rule with what was logged. Tenant data stays in `tools/replay/data/`, which is git-ignored.

```
python3 tools/replay/export-to-jsonl.py export.xlsx                           # -> tools/replay/data/events.jsonl
node tools/replay/dump-extension-data.mjs 9444 dump tools/replay/data/extension-data.json   # from a signed-in Chrome, see the file header
node tools/replay/replay-activity.mjs                                         # prints accuracy per layer and rule
```

By default the replay answers category, app and threat questions from what the log recorded. `--investigate=<lookups.json>` answers them only from Cisco Investigate lookups (`{ host: lookupDestination result }`, collected from the extension's service worker) to measure the fully automatic path. Blocks the log attributes to a scanned file, DLP, app controls or IPS are counted separately, because they depend on content and not on the destination.

## Development

Requires Node.js 20 or later. There are no dependencies.

```
npm test                 # all headless tests in test/
npm run test:browser     # optional, needs Chrome with --remote-debugging-port=9333
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and [SECURITY.md](SECURITY.md) for what the extension stores and how to report a vulnerability.

## Repo structure

```
extension/                     # MV3 extension (load this folder unpacked)
test/                          # Headless tests, run with npm test
  browser/                     # Optional Chrome DevTools protocol tests and UI fixture
  fixtures/                    # Rule data used by tests
tools/replay/                  # Optional Activity Search replay tooling
scripts/run-tests.js           # Test runner
```

Inside `extension/`:

```
manifest.json                  # MV3 manifest
background/service-worker.js   # Token capture, API fetching, data resolution
content/                       # Dashboard overlay, token sniffer and relay, styles
popup/                         # Panel UI, rule matcher, traffic-path model, IP parsing, Describe mode
lib/debug-log.js               # Persistent debug logging
data/                          # Bundled app, category, protocol and exclusion lookups
```

## Disclaimer

This project is not affiliated with or endorsed by Cisco. Cisco, Cisco Secure Access and Umbrella are trademarks of Cisco Systems, Inc. Released under the [MIT License](LICENSE).
