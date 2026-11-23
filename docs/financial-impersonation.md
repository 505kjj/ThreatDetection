# Financial website impersonation

## Verified registry

The starter registry records domain scopes and name aliases for four organizations. Sources were checked on 23 November 2026. A scope suppresses name-based hints for its own brand. The documented co-branded HDFC and Razorpay hostname also suppresses HDFC name hints on that exact host. A current exact reputation match on any of these hosts still produces the existing known-threat warning.

| Organization | Verified scopes | Official sources |
| --- | --- | --- |
| State Bank of India | `sbi.bank.in`, `bank.sbi`, `onlinesbi.sbi` | [Corporate site migration](https://sbi.bank.in/redirect/) · [Official internet banking guidance](https://sbi.bank.in/web/personal-banking/digital/internet-banking) · [SBI launch of bank.sbi](https://sbi.bank.in/documents/39129/52199/gTLD.pdf) |
| HDFC Bank | `hdfc.bank.in`, `hdfcbank.com` | [Current website](https://www.hdfc.bank.in/important-messages/all-new-website) · [Current NetBanking](https://www.hdfc.bank.in/now-hdfc-bank) · [HDFC guidance naming the legacy domain](https://v.hdfc.bank.in/htdocs/common/insider/index.html) |
| National Payments Corporation of India | `npci.org.in` | [NPCI UPI information](https://www.npci.org.in/what-we-do/upi/faqs) |
| Razorpay | `razorpay.com`, `rzp.io` | [Razorpay payment-link documentation](https://razorpay.com/docs/api/payments/payment-links/create-standard) · [Razorpay documentation for a co-branded HDFC flow](https://hdfcbank-collectnow-docs.razorpay.com/api/payments/payment-links/create-standard/) |

The RBI's [.bank.in migration notice](https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=12837&Mode=0) identifies the official banking namespace. The registry limits suppression to the domains attributed above. Recheck migration notices and provider documentation before expanding or retaining legacy scopes. The evaluation also includes [Google](https://developers.google.com/identity/openid-connect/openid-connect) and [Microsoft](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) authorization hosts as benign controls. Neither service receives a special reputation exemption.

## Architecture and rules

The Manifest V3 service worker uses the top-level hostname supplied by Chrome. [tldts](https://github.com/remusao/tldts) uses the Public Suffix List, including private suffixes, to identify the registrable domain. For instance, it recognizes `hdfc.bank.in` and treats tenants under `github.io` as separate registration boundaries. The detector skips IPs, local names, and unrecognized suffixes.

1. A known official domain embedded in an unrelated hostname yields a structural warning. The comparison respects DNS label boundaries and excludes the actual suffix.
2. A verified brand alias can appear in the registrant label or in a misleading subdomain. Literal aliases of four or fewer characters also require a financial token such as `login` or `payment`, unless a complete official address is embedded. Common payment terms on their own never count as brand evidence.
3. The registrant label can match a longer alias after one insertion, deletion, substitution, or adjacent swap. Typos are checked only against aliases of at least seven characters.
4. Internationalized labels are decoded from Punycode and checked with Unicode [UTS #39 confusable mappings](https://www.unicode.org/reports/tr39/). The check compares their skeleton against the ASCII brand aliases. The alert distinguishes registered-domain homographs from homographs in subdomains.

The checked-in modules run without a third-party request. The detector receives no form fields, page contents, URL paths, query strings, cookies, or referrers, and its evidence stays in the extension. Existing opt-in activity monitoring still uses the established hostname-only session and bounded activity metadata.

## Decision policy

| Current reputation evidence | Local address evidence | Browser behavior |
| --- | --- | --- |
| Exact known phishing or malware match | Any | Existing red `STOP` badge and known-threat warning. Include address clues when present. |
| Current snapshot, no match | Address clue | Amber `!`, an in-page caution, and the specific explanation in the toolbar popup. Browsing continues. |
| Current snapshot, no match | None | Existing no-match or opted-in activity verdict. |
| Reputation unavailable | Address clue | Popup still reports **Protection unavailable** and shows the local clue separately. The in-page caution identifies the outage. |
| Reputation unavailable | None | Existing unavailable state. |
| Monitoring paused | Any | Checks and warnings stop. |

Fuzzy spelling, Unicode similarity, brand tokens, and domain structure all derive from the same hostname. They never add up to a high-risk verdict. There is no new heuristic high-risk classification or blocking action. Exact threat-feed evidence remains an independent input, and the existing confirmed reputation behavior takes precedence. This change provides no new feed redistribution rights. A managed Phase 2A.1 backend that disallows browser distribution still produces the unavailable reputation state in the browser.

## Evaluation

The deterministic fixture report from `node --test extension/tests/*.test.mjs` measures hostnames only. It contacts none of the listed hosts.

| Fixture group | Address cautions | Rate |
| --- | ---: | ---: |
| Official banking, payment, and authentication hosts | 0 of 18 | 0% false cautions |
| All labeled benign fixtures, including official and synthetic | 2 of 35 | 5.7% false cautions |
| Synthetic impersonation cases | 18 of 18 | 100% fixture detection |

The two false cautions were reserved synthetic help/documentation subdomains that use a financial brand as a label. Both stayed unconfirmed and could not block. The Chromium smoke test exercises loopback-only fixtures for the caution, explanation, exact reputation override, authentication, privacy, pause, and outage paths. Population false-positive rates, current real-world threat recall, and brand coverage in India remain unmeasured. The module also cannot detect copies on unrelated names, path-only deception, page-content impersonation, or abuse inside a verified domain without independent evidence. A page can interfere with the in-page banner. The extension toolbar popup displays the evidence independently of the page.

## Vendored data and maintenance

- `extension/vendor/tldts.mjs` comes from the browser ESM build of [tldts 7.5.5](https://www.npmjs.com/package/tldts/v/7.5.5). The source-map reference was removed. The directory includes the MIT notice and the MPL 2.0 license for the [Public Suffix List source](https://github.com/publicsuffix/list).
- `extension/vendor/punycode.mjs` is the upstream ESM source of [Punycode.js 2.3.1](https://www.npmjs.com/package/punycode/v/2.3.1), under the included MIT license.
- Reproduce the Unicode 17.0.0 ASCII-brand confusables table with `node extension/tools/generate-confusables.mjs <downloaded-confusables.txt>`. The generator checks the SHA-256 of the [versioned Unicode source](https://www.unicode.org/Public/17.0.0/security/confusables.txt). The [Unicode license](https://www.unicode.org/license.txt) is included.

Update the static parser and Unicode artifacts as part of reviewed extension releases. Rerun the fixture and Chromium tests when changing registry scopes, data versions, or rule thresholds.
