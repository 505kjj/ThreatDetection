# URL reputation operations

For scheduled upstream ingestion, signed snapshots, and the current commercial provider comparison, see [threat intelligence ingestion](threat-intelligence-ingestion.md). This page describes the browser contract and the legacy operator-file mode.

## How detection works

The Spring Boot service reads an operator-published threat snapshot through the `ReputationProvider` interface. The Chrome service worker downloads the same snapshot for every authenticated browser. The request has no destination, body, referrer, cookies, or query parameters. It does not call a vendor when a user visits a page. The worker checks committed HTTP(S) documents in Chrome using exact hostnames and whole SHA-256 digests of canonical URLs with the query and fragment removed. It keeps only the downloaded indicators in the reputation cache, in trusted extension session storage. Browsing destinations and computed lookup hashes are not written to that cache.

On opted-in activity sites, the existing API can still receive the hostname at registration and bounded activity metadata during analysis. A positive local reputation match stops that activity path for the matched document. The backend can apply exact host reputation to authenticated sessions. Path-level matching stays in Chrome. Browsing on a non-opted-in site performs a reputation check locally without registering a session.

| Extension result | Behavior |
| --- | --- |
| **Known malicious website** | Chrome can block an exact host or explicit path rule before the request. A private extension page explains the match. Hash-only, uninstalled rules, and same-document matches use a separately labeled post-navigation warning. |
| **Suspicious activity, unconfirmed** | Shows an advisory on opted-in sites when behavior exceeds the Phase 1 warning threshold and local reputation has no match. |
| **No known threat match** | Shows a neutral result and states that the website may still be unsafe. |
| **Protection unavailable** | Shows when credentials, host permission, or a current snapshot are missing. If an opted-in activity check fails, that tab also reports unavailable unless local reputation has a confirmed match. |

See [browser protection](browser-protection.md) for Chrome rule coverage, warning isolation, fallback behavior, and one-time exceptions. Financial and behavior-only advisories continue to allow navigation.

## Provider evaluation

Use a provider contract that expressly permits commercial customer protection **and distribution to end-user extensions** of the exact derivative data and scope being published. Paying for access, obtaining an API key, or hashing an indicator does not itself grant distribution rights. Managed ingestion is optional and includes its own browser distribution gate.

| Candidate | Commercial terms and limits | Privacy and integration fit |
| --- | --- | --- |
| **OpenPhish Premium or Platinum** | The paid phishing feeds advertise a five-minute update cadence and quote-based pricing. The public terms require written permission for commercial use and for distribution or derivative data. Confirm polling limits, attribution, retention, and extension redistribution in the paid agreement. The Community feed is noncommercial. [Feed plans](https://openphish.com/phishing_feeds.html) · [Terms](https://openphish.com/terms.html) | Batch ingestion can avoid submitting customer destinations to the vendor. Use licensed path scopes and retain a host indicator only when there is evidence for the whole hostname. |
| **URLhaus commercial abuse.ch feed** | Malware source. The community service is subject to fair-use terms and may require a commercial subscription. Community dumps and RPZ are generated every five minutes, and the documented dataset pulls should follow that cadence. Obtain the commercial plan's limits and rights for client distribution in writing. [URLhaus feed options](https://urlhaus.abuse.ch/api/) · [Spamhaus commercial-feed documentation](https://docs.spamhaus.com/real-time-feeds/docs/source/01-intro/what-is-the-real-time-feed.html) | Batch ingestion avoids browsing lookups at the vendor. Malware URLs on shared sites should stay path-scoped. An independently vetted host-level feed can supply whole-host entries. |
| **Google Cloud Web Risk Update** | Google's commercial option. Its public documentation prohibits redistribution of returned information. The published project limits are 600 list-diff and 6,000 hash-search calls per minute. The published USD price is $50 per 1,000 hash confirmations, with list diffs free. Honor provider cache and wait instructions and recheck terms and prices before procurement. [Terms and API overview](https://docs.cloud.google.com/web-risk/docs/overview) · [Quotas](https://docs.cloud.google.com/web-risk/quotas) · [Pricing](https://cloud.google.com/web-risk/pricing) · [Request frequency](https://docs.cloud.google.com/web-risk/docs/request-frequency) | Update supports local prefix matching with remote confirmation on candidate hits. This would need a separately licensed integration and the provider's canonicalization and cache rules. Its list cannot be republished with this snapshot adapter under the ordinary published terms. Web Risk Lookup sends the full URL. |
| **Google Safe Browsing** | The public API is noncommercial absent a separate agreement. [Usage restrictions](https://developers.google.com/safe-browsing/v4/usage-limits) · [Terms](https://developers.google.com/safe-browsing/terms) | Excluded from the commercial plan. |

The recommended starting point is a paid OpenPhish agreement for phishing and a commercial abuse.ch agreement for malware. Proceed with vendor data only when the agreements expressly allow the planned customer delivery of derivative exact-host and full-hash entries. An independently verified, internally owned list can use the same file adapter where those rights are already established. Keep provider ingestion credentials outside the app and source repository.

## Snapshot format

Set `threat.reputation.snapshot-path` or the environment variable `THREAT_REPUTATION_SNAPSHOT_PATH` to an absolute path readable by the backend service. The default reload interval is 30 seconds. Override it with `THREAT_REPUTATION_RELOAD_INTERVAL` using an ISO-8601 duration such as `PT30S`. Publish by replacing the file atomically on the same volume. When no snapshot has been configured, the file cannot be read, validation fails, or the snapshot is expired, the authenticated endpoint returns HTTP `503`. It never returns an empty success as a substitute for missing data.

The two dates are UTC ISO-8601 strings. The lifetime must be greater than zero and at most 24 hours. Limit a file to 3 MiB and 20,000 unique indicators. Keep expiry no later than the upstream data's validity. Replacing the file with invalid data clears the backend's current snapshot. An empty list with real provenance and current coverage metadata can express a valid empty snapshot. Never stamp old upstream data as newly issued.

```json
{
  "generatedAt": "2026-11-23T12:00:00Z",
  "expiresAt": "2026-11-23T12:15:00Z",
  "entries": [
    { "kind": "HOST", "value": "known-phish.example.test", "threat": "PHISHING" }
  ]
}
```

- `HOST` is a lowercase ASCII DNS name or Punycode, with no wildcard, dot suffix, scheme, port, or path. It matches that exact host only. Do not derive a host entry by discarding the path of a URL indicator.
- `URL_SHA256` is 64 lowercase hexadecimal characters. Hash UTF-8 bytes of `destinationFor(url).key` from [reputation.mjs](../extension/reputation.mjs). It uses the WHATWG browser URL parser, the scheme, canonical ASCII hostname with any nondefault port, and the serialized pathname with percent-escape hex uppercased. It excludes userinfo, query, and fragment. It is a project-specific key and is not a vendor's native hash format.
- `URL_PATH` is an optional Phase 2C indicator containing a canonical HTTP(S) scheme, lowercase ASCII hostname, optional nondefault port, and a path made from ASCII letters, digits, slash, dot, underscore, tilde or hyphen. The complete indicator is limited to 512 characters. It carries no credentials, query, fragment, encoded path or wildcard. Use only publisher-owned or expressly redistributable indicator paths with no sensitive content. Phase 2B and earlier extensions reject snapshots with this new kind.
- Supported categories are `PHISHING` and `MALWARE`. Omit query- or fragment-dependent indicators. Removing their distinguishing component would broaden the match. Keep input and intermediate artifacts in the trusted publisher pipeline.

The Chrome smoke test generates fresh fixture timestamps, maps reserved example hostnames to loopback, and covers both a local URL hash and an explicit path. It never contacts a real phishing or malware site.

## Release operations and limitations

- Serve the snapshot endpoint through the Phase 1 HTTPS and exact-origin policy. Keep a distinct browser credential per installation. The endpoint is restricted to the browser role and performs no database writes. Restrict write access to the publisher and monitor validity, loader failures, indicator counts, and feed age.
- The worker refreshes on demand and schedules an alarm for the next poll or expiry. Its cache backs off for 15 seconds on an unavailable response. A transport outage may reuse the previously verified snapshot until its original expiry. An explicit server rejection or invalid response discards it on refresh. A revoked indicator can persist on an offline browser until expiry.
- Authenticated clients can inspect the distributed hashes and host indicators. Hashes are not anonymization or an entitlement control. Publish only data authorized for distribution. The backend learns that a browser requested a refresh, and it still sees opt-in activity data. Per-visit reputation destinations do not leave the browser.
- Exact matching does not cover unknown or newly registered domains, URL schemes outside HTTP(S), URLs where a query or fragment changes the threat, or scam content hosted at an unlisted destination. Reputation misses give no assurance. A confirmed match means a match to current vetted indicators, which can still contain mistakes.
- The operational gate for a public pilot includes signed commercial and redistribution rights, a trustworthy publisher and revocation process, production HTTPS and credential management, and measured feed coverage, false warnings, and latency. The synthetic test run does not establish vendor latency, coverage, or live-feed availability.
