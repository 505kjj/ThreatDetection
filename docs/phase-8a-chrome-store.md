# Chrome Web Store submission materials

## Listing draft

**Name:** ThreatDetection

**Short description:** Blocks known threats with local rules and warns about possible financial impersonation.

**Category and language:** Privacy and Security, English. Confirm the category choice in the Developer Dashboard.

**Description**

ThreatDetection helps you review suspicious sign-ins and avoid known malicious destinations. It applies locally installed Chrome blocking rules using the current reputation snapshot from your configured backend. A separate financial protection advisory explains possible lookalike domains and credential-form evidence when present.

Use the extension popup to review available protection and see why it took an action. Known malware is blocked without bypass. Eligible phishing warnings support a limited, one-time bypass.

Configure an authorized backend and a browser-scoped token to receive its current reputation data. The extension can send bounded activity signals for configured sites. Reporting is optional and requires separate consent. Authorized operators can review classified reports without browsing URLs or page contents in the monitoring data.

## Permission and data declarations

| Permission or access | Justification |
| --- | --- |
| `storage` | Stores user configuration, active snapshot state and minimal extension session state. |
| `alarms` | Periodic snapshot refresh and opted-in reporting heartbeat. |
| `webNavigation` | Main-frame navigation lifecycle and state boundaries for protection. |
| `declarativeNetRequest` | Exact local reputation blocks and narrowly bound eligible bypass. |
| HTTP and HTTPS content-script matching | Reads bounded navigation and page structure for user-facing protection on eligible pages. It does not read typed values or raw cookie values. |
| Loopback hosts | Connects to an operator-run local backend for controlled installation. |
| Optional HTTPS host access | Requests the concrete configured backend host after a user action. |

The MV3 manifest uses Chrome's default extension-pages CSP. JavaScript, Inter and vendored domain parsing dependencies are bundled. Data refreshes receive JSON and do not load remote executable code. The included package retains logo and extension icons plus vendor license notices.

Declare the handling of browsing activity, page structure and user activity, including local-only processing. Configured site activity analysis can transmit a hostname and bounded behavior counters to the operator backend. Optional monitoring transmits classification, action, event ID, event time and protection availability. Treat the issued browser bearer as authentication information and disclose its configured service use. Use the [public privacy policy build](../website/pages.mjs) for the published `/privacy/` URL and review actual dashboard declarations with the publisher. Do not declare access to passwords, OTPs, raw cookie values, screenshots, files or credential form content values. The item's final privacy practices and the operator's retention, access and service disclosures must agree. [User data practices](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq) · [Chrome Web Store policies](https://developer.chrome.com/docs/webstore/program-policies/policies)

## Package and graphics

From the repository root:

```powershell
python scripts/package-extension.py <fresh-private-output-directory>
node scripts/render-store-assets.cjs <direct-Chromium-capture-directory> <store-graphics-output>
```

The ZIP has `manifest.json` at its root and contains only the allowlisted production runtime, icons, fonts and licenses. The Chromium smoke can run against an extracted ZIP by setting `THREAT_SMOKE_EXTENSION_DIR`. Review package content and record the SHA-256 before distributing or uploading it. The graphics renderer uses the actual on-device popup, confirmed warning, advisory and scoped synthetic dashboard from the Chromium exercise. It creates four 1280×800 RGB screenshots and a 440×280 RGB promo tile. Take the 128×128 icon from `extension/icons/icon128.png`. [Listing graphics requirements](https://developer.chrome.com/docs/webstore/cws-dashboard-listing)

## Submission checklist

- [ ] Approve the verified ZIP and release version. Load the extracted folder in a fresh Chrome profile and repeat the consent, exact-host grant, CORS, outage, warning and bypass checks using the HTTPS staging backend.
- [ ] Confirm developer account and branding, category, coverage disclosure, support route, required graphics and any listing video required by the final dashboard form.
- [ ] Approve and publish the website's privacy policy and support contact before using their links in Store submissions.
- [ ] Record the Store-issued extension ID. Limit backend CORS to the approved extension ID and make synthetic reviewer setup available using separately issued short-lived or rotated credentials.
- [ ] Review all privacy practice entries, single-purpose statement, data-use certification, role grants and reviewer instructions.
- [ ] Obtain explicit approval before paying a developer account fee, uploading a ZIP to the Store, submitting for review or publishing. [Developer registration](https://developer.chrome.com/docs/webstore/register)
