# Contributing

Thank you for your interest in improving the Secure Access Policy Checker.

## Getting started

1. Fork and clone the repository.
2. Load the `extension/` directory in Chrome via `chrome://extensions` (Developer mode, **Load unpacked**).
3. Run the tests with Node.js 20 or later. There are no dependencies to install:

   ```
   npm test
   ```

## Project layout

- `extension/` is the Manifest V3 extension. The rule matcher (`popup/matcher.js`) and the traffic-path model (`popup/traffic-path.js`) are plain scripts that also load under Node, which is how they are tested.
- `test/` holds the headless tests. Each file runs on its own with `node test/<name>.js`.
- `test/browser/` holds tests that drive a real Chrome over the DevTools protocol. They are optional and run with `npm run test:browser` against a Chrome started with `--remote-debugging-port=9333`.
- `tools/replay/` holds an optional tool that replays an Activity Search export against a tenant's rules to measure accuracy.

## Making a change

- Keep changes focused, and add or update a test for any change to matching or evaluation behaviour.
- Policy semantics should be based on observed Cisco Secure Access behaviour. Where a behaviour is unconfirmed, say so in the code and in the pull request instead of guessing.
- Match the existing style: plain JavaScript, no build step, no runtime dependencies.
- Use British spelling in documentation.

## Never commit tenant data

Rule exports, Activity Search exports, HAR files, screenshots of a real tenant, tokens and API keys must not appear in commits, issues or pull requests. Redact organisation names, user names, IP addresses and IDs from anything you share. `tools/replay/data/` is git-ignored for this reason.

## Pull requests

Open a pull request against `main` with a short description of the problem, the change and how you tested it. Continuous integration must pass.
