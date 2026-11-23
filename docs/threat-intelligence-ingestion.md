# Threat intelligence ingestion

## Provider comparison

| Provider | Commercial use, pricing, cadence, and limits | Privacy, distribution, and India fit |
| --- | --- | --- |
| **CERT Polska Warning List** | The [data policy](https://cert.pl/en/warning-list/#data-usage-policy) permits commercial use. The public v2 export is keyless, and the operator guidance asks integrations to update every five minutes. The [v2 specification](https://hole.cert.pl/schema/certpl_lista_ostrzezen_api_v2.pdf) defines the TSV format and removal semantics. | A scheduled batch pull sends no customer browsing information. The provider focuses on campaigns targeting Poland. This implementation uses the list for server-side matching and leaves browser distribution disabled until that specific use is authorized. |
| **OpenPhish Premium or Platinum** | Five-minute paid phishing feeds with quote-based pricing. The community feed is noncommercial. Limits, retention, attribution, and rights are subject to the commercial agreement. [Feed plans](https://openphish.com/phishing_feeds.html) · [Terms](https://openphish.com/terms.html) | Batch ingestion avoids sending customer lookups, and targeted-brand metadata is useful for evaluating Indian bank and payment-brand coverage. The public terms require written consent for commercial use and for third-party distribution or derivative data. |
| **URLhaus / commercial abuse.ch** | Malware feeds. Community exports use an authentication key, follow fair-use terms, and generally publish every five minutes. Commercial users may need a paid subscription. Confirm commercial quotas, costs, and client redistribution separately. [URLhaus API and policy](https://urlhaus.abuse.ch/api/) · [Commercial feed documentation](https://docs.spamhaus.com/real-time-feeds/docs/source/01-intro/what-is-the-real-time-feed.html) | Batch downloads avoid browsing lookups. Malware URLs are complementary to phishing intelligence. Shared-site URL entries should remain path-scoped. |
| **Google Cloud Web Risk Update and Lookup** | Commercial service. List diffs are free under published pricing. The cited USD pricing lists $50 per 1,000 hash confirmations. Published per-project limits are 600 diff and 6,000 hash-search requests per minute. Update clients must respect cache and wait instructions. [Pricing](https://cloud.google.com/web-risk/pricing) · [Quotas](https://docs.cloud.google.com/web-risk/quotas) · [Request frequency](https://docs.cloud.google.com/web-risk/docs/request-frequency) | Update supports a local prefix list with remote confirmation. Lookup sends the URL. Google prohibits redistribution of returned Web Risk information under its public documentation, so this product cannot republish its data through the snapshot endpoint on those terms. [Overview and restrictions](https://docs.cloud.google.com/web-risk/docs/overview) |
| **PhishTank** | Its terms allow commercial use of the defined data without charge. Downloads update hourly, and automated consumers should register a key. Unkeyed downloads are limited to a few per day. [Terms](https://phishtank.org/terms.php) · [Developer information](https://phishtank.org/developer_info.php) | Batch downloads avoid individual lookups. Confirm any intended end-user redistribution separately. Hourly refresh and measured India-specific coverage matter before adopting this as a primary source. |
| **India I4C Suspect Repository** | The public UI is a lookup and reporting portal with CAPTCHA and a disclaimer on complaint accuracy. This review did not find a published commercial bulk endpoint or a redistribution grant. [I4C search and disclaimer](https://cybercrime.gov.in/Webform/suspect_search_websites.aspx) | Useful as a reference for permitted partner workflows. Source reports require independent verification before they become confirmed indicators. |

For an India-focused pilot, evaluate a paid OpenPhish trial against a timestamped set of confirmed impersonations of Indian banks, UPI and wallet brands, and common financial scams. Combine it with authorized, independently verified input from local financial partners. Consider a commercial malware feed if the trial shows a separate malware coverage gap. CERT Polska is the implemented supplementary source. Its coverage of Indian financial scams is unmeasured.

## Managed pipeline and browser distribution

The backend uses the fixed CERT Polska v2 HTTPS TSV URL, with redirect rejection, TLS certificate verification, timeouts, and a 64 MiB response ceiling. Polling sends no credentials, customer identifiers, or browsing destinations. The parser validates UTF-8, TSV structure and timestamps, normalizes valid DNS indicators to lower-case ASCII, deduplicates registrations, and honors removals. It ranks active records by insertion time and registration ID and keeps the newest 20,000. There is no suffix expansion to parent domains or subdomains. The cap matches the Phase 2A browser contract.

The file envelope contains format version `1`, the source, a SHA-256 content version, a base64 snapshot payload, and an HMAC-SHA-256 over the payload and a fixed version/source prefix. HMAC covers local publication integrity. HTTPS authenticates the upstream transport. The publisher writes and flushes a temporary file beside the destination, then atomically replaces the destination. Filesystems without atomic replacement cause publication to fail, preserving the previous file. A verified newer publication replaces the reader's previous in-memory version. A failed poll or damaged file leaves the last verified snapshot usable only until its original expiry.

The **maximum data age is 15 minutes from the upstream file's `Last-Modified` time**, with HTTP cache age allowed to shorten it. A successful fetch of the same version does not extend its expiry. The backend rejects expiring or stale data when serving requests, and Chrome already expires an approved snapshot locally. A five-minute polling interval allows recovery from transient fetch failures while keeping a bounded expiry.

**Managed browser distribution defaults to off.** The browser snapshot route returns `503` in managed mode unless `BROWSER_DISTRIBUTION_APPROVED` is explicitly enabled. Keep it off until the rights holder expressly authorizes the exact client distribution model. The managed feed remains available for authenticated server-side analysis. Repository and extension packages contain implementation and synthetic fixtures only.

The repository's existing operator-supplied Phase 2A file mode remains available with managed ingestion disabled. That mode expects the previous JSON format and keeps its validation behavior. Use it only with data you are authorized to supply to browsers.

## Configure a private instance

Run a single managed publisher for a dedicated snapshot file. Use a private directory outside the source tree on an atomic-rename-capable volume. Give the backend service account write access and restrict access to its signing key and artifacts. Use a secret manager for persistent installations. Restart after rotation and fetch a fresh signed snapshot. Outbound DNS and HTTPS access to `hole.cert.pl` and a synchronized system clock are required. Continue to use the existing Phase 1 bearer tokens and exact CORS rules.

| Environment setting | Value |
| --- | --- |
| `THREAT_REPUTATION_INGESTION_ENABLED` | `true` to opt into scheduled CERT Polska ingestion. Default `false`. |
| `THREAT_REPUTATION_SNAPSHOT_PATH` | Absolute file path under an existing private directory. In managed mode this is the signed envelope. |
| `THREAT_REPUTATION_INGESTION_SIGNING_KEY` | Random 32 bytes encoded as 64 hexadecimal characters. Set only in the backend service. |
| `THREAT_REPUTATION_INGESTION_POLL_INTERVAL` | ISO duration, default `PT5M`. Shorter intervals are rejected. |
| `THREAT_REPUTATION_INGESTION_INITIAL_DELAY` | ISO duration, default `PT0S`. Set a startup delay if needed to avoid overlapping fetches during restarts. |
| `THREAT_REPUTATION_INGESTION_BROWSER_DISTRIBUTION_APPROVED` | Default `false`. Requires verified client distribution rights. |

Use an admin bearer token to read `GET /api/threat/reputation/feed-status`. It returns the source, poll state, feed availability, current or stale data state, last attempt and success, original expiry, indicator counts, and content version. It omits indicators, source credentials, and keys. Alert from this endpoint on `FEED_FAILED`, `PUBLISH_FAILED`, `MISSING`, or `STALE`. A provider outage can coexist with `CURRENT` data during its remaining valid window. Poll counters reset on restart. Backend logs record aggregate status and counts. External alert delivery and durable monitoring storage are operational work.

## Verification

- Run the standard backend Maven suite and extension tests from the root README. The managed backend tests use synthetic TSV and cover authentication, publication, rollback rejection, corrupt artifacts, provider failure, and expiry. The Chromium smoke test exercises the existing browser contract with synthetic data.
- To verify the live source, build the backend JAR and run this from the repository root in PowerShell. Respect the five-minute interval between live feed requests.

```powershell
$env:THREAT_RUN_LIVE_FEED_TEST = '1'
node backend/tools/verify-cert-polska.cjs
Remove-Item Env:THREAT_RUN_LIVE_FEED_TEST
```

The live test starts a disposable loopback backend, fetches the official feed, verifies the persisted checksum and HMAC independently, tests a listed hostname only through the local analysis API, and confirms that browser distribution is disabled. It reports counts and timestamps and removes the temporary snapshot. It never visits any listed hostname.

Moving from engineering verification to an India pilot still requires approved distribution rights for each feed, an India-relevant benchmark, production HTTPS and credential management, and monitored provider coverage and removals.
