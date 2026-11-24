# Financial website and credential-form advisories

Phase 4C adds hostname scopes and bounded, browser-only evidence to the existing financial impersonation advisory. It builds on Phase 2B’s rules, Phase 2C’s reputation interstitial, and Phase 4A/4B’s opt-in, fixed-code dashboard events. The offline Phase 3F and 3G research is independent. Phase 3F had zero verified financial phishing positives, and Phase 3G reproduced poor general archive transfer. Their models, features, and scores are not inputs to this browser decision.

## Registry provenance

Sources checked 24 November 2026. Current and explicitly documented legacy scopes suppress name-based hints for the corresponding brand only. Legacy scopes are retained as false-positive controls rather than recommended destinations. No whole banking namespace or unrelated hosting platform is exempt.

| Addition | Scope and evidence |
| --- | --- |
| Axis Bank | `axis.bank.in` is the current official scope. The bank explicitly attributes legacy `axisbank.com` and `axisbank.co.in` addresses. [Axis fraud guidance](https://application.axis.bank.in/Webforms/Axis-Support/Blogs/identify_genuine.aspx) · [Axis disclosure](https://www.axis.bank.in/docs/default-source/stock-information/debt/debentures/sr-08-genera-information-document-05-09-24.pdf) · [Axis sustainability report](https://www.axis.bank.in/Sustainability-Reports/2021-2022/pdfs/Fostering%20Strong%20Corporate%20Governance.pdf) |
| Bank of Baroda | The bank's migration guidance identifies `bankofbaroda.bank.in` and `bankofbaroda.in`. The bank documents `bobibanking.com` as its earlier internet banking portal. [Bank of Baroda migration guidance](https://bankofbaroda.bank.in/hi-in/banking-mantra/recent-trends-in-banking/articles/what-is-bank-in-domain) · [Bank of Baroda net banking guidance](https://bankofbaroda.bank.in/hi-in/banking-mantra/digital/articles/what-is-net-banking) |
| BHIM | NPCI publishes its product under `npci.org.in` and explicitly attributes `bhimupi.org.in` to BHIM. [NPCI BHIM product page](https://www.npci.org.in/product/bhim) · [NPCI launch announcement](https://www.npci.org.in/PDF/npci/press-releases/2017/NPCI-launches-a-dedicated-website-for-BHIM.pdf) |
| PhonePe | PhonePe owns and documents `phonepe.com` for its payment services. [PhonePe terms](https://www.phonepe.com/en/terms_general.html) · [PhonePe help](https://www.phonepe.com/how_to_pay/index.html) |

RBI documents the introduction of `.bank.in`. PSL boundaries are applied to individual verified bank names, including private suffix boundaries for hosting tenants. [RBI publication](https://www.rbi.org.in/Scripts/PublicationsView.aspx?id=23638)

Recognized form destinations use HTTPS on the default port. The identity-provider exceptions are exactly `accounts.google.com` and `login.microsoftonline.com`. Verified bank, payment, and documented co-brand scopes are also recognized. These exceptions suppress added form evidence for the destination only. They do not suppress an existing hostname advisory or override reputation. [Google OpenID Connect reference](https://developers.google.com/identity/openid-connect/reference) · [Microsoft OpenID Connect documentation](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)

## Decision policy

| Signal | Decision | Evidence shown |
| --- | --- | --- |
| Current confirmed reputation indicator | Existing block or extension interstitial, according to the existing policy | Confirmed reputation match. Existing tab-scoped bypass eligibility stays in that policy. |
| Financial-domain lookalike | **GO** for amber advice | Official address embedded under a different operator, contextual brand name, a Unicode confusable, or a narrow typo. Subdomain typo checks require an alias of at least eight characters and a financial term. |
| Visible password field or card form on a financial lookalike | **GO** for amber enrichment | A visible enabled editable password field or a visible card-number field plus an expiry or security-code field. |
| Declared unrelated action plus strong hostname evidence | **GO** for amber enrichment | The form declares an HTTP(S) action on another registrable domain outside recognized providers. A submitter override, ambiguous action, recognized provider, or same site does not qualify. |
| Redirect preceding a credential form on a lookalike | **GO** for explanatory context. **NO-GO** as a signal on its own. | Chromium observed a client or server redirect before the page. The detector cannot observe or judge the full chain. |
| Form, redirect, or cross-origin authentication alone | **NO-GO** for a phishing advisory or block | Insufficient evidence. Verified address scope and absence of a warning do not establish that a page is safe. |
| ML-based warnings or blocking | **NO-GO** | Phase 4C uses the reputation and local rule paths only. |

A form action describes a declaration. JavaScript submission handlers, nested frames, workers and later navigation can send data somewhere else. The extension does not execute or inspect submitted data. It never requests a declared destination. Protection unavailable remains visible when there is no usable snapshot; the local amber evidence can still appear. Reputation retains precedence.

## Privacy, performance, and reporting

The service worker asks the isolated top-frame content script to inspect forms only after the existing hostname rule finds evidence. Verified financial and payment hosts skip form inspection even when a different brand yields an address clue. A scan examines at most 20 forms, 32 controls per form, and returns at most four observations. It runs after configuration, on a bounded retry for delayed markup, and on relevant trusted input focus. The worker binds observations to the active tab, document and navigation and accepts at most eight per navigation. There is no whole-page observer, new permission, request interception, or navigation delay for this advisory.

The content script reads control metadata and reduces a declared action to its origin before any extension message. The worker uses that transient origin only for comparison. The dashboard gets fixed codes, never the destination or page hostname, DOM content, paths, queries, fragments, cookies or field values. Detection codes remain in the existing financial-impersonation category at CAUTION severity. An opted-in advisory event is recorded once per document; the browser allows a short window for early context and can show later observations locally. During a backend outage, unsolicited events are not queued. Synthetic scope remains assigned by the configured browser identity.

Visible ordinary HTML forms are the supported surface. Custom JavaScript controls, closed shadow trees, framed flows, delayed forms outside the bounded checks, unregistered brands, and credential forms hosted on unrelated names can fall outside coverage. A site can interfere with the in-page banner; the extension popup independently displays the observed reasons while the current worker has them.

## Evaluation

Run `node --test extension/tests/*.test.mjs` and the two Playwright modes in the [local verification guide](windows-local-setup.md#verify-in-chromium). The hostname tests use strings and perform no DNS lookups. The browser tests use loopback fixtures, never submit a form and never navigate to its declared action.

| Fixture set | Outcome |
| --- | ---: |
| Official banking, payment, and sign-in hostname controls | 0 false cautions / 28 |
| All benign hostname controls | 2 false cautions / 48 (4.2%) |
| Synthetic lookalike hostname cases | 25 cautions / 25 |
| Benign or baseline-only structural controls | 0 added form advisories / 12 |
| Synthetic credential-form scenarios | 8 detected / 8 |

The two hostname false cautions are previously documented synthetic brand-named documentation or integration subdomains. The pass rates apply only to these labeled fixtures. The evaluation provides no independent estimate of financial phishing recall, population false positives, or authorized cross-origin flow coverage.
