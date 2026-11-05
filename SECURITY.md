# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting for this repository ("Security" tab, "Report a vulnerability"). Include steps to reproduce and the affected version. We aim to acknowledge reports within a few working days.

## What the extension handles

Understanding this is useful when reviewing the code or assessing risk:

- **Cisco session tokens.** The extension observes authentication tokens issued to the Secure Access dashboard and uses them only to call Cisco Secure Access, Umbrella and Investigate APIs on the signed-in user's behalf. Tokens are held in `chrome.storage.local`, which is not encrypted at rest within the browser profile.
- **Policy data.** Rules and catalogues are fetched into `chrome.storage.local` for the active organisation and are never sent to any third party by the extension itself.
- **Describe mode (optional).** If you enter an API key for an LLM or speech provider (Anthropic, OpenAI, Google, AssemblyAI), your typed or spoken request and relevant policy context are sent to that provider. Keys are stored in `chrome.storage.local`. The mode is off until you configure a provider.
- **Debug log.** A local log may record events and redacted token metadata. Review it before sharing.

The extension is not affiliated with or endorsed by Cisco. Verdicts are predictions based on rule configuration and do not replace testing against real traffic.
