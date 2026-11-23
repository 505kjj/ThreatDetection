# Browser-level threat protection

## Decision policy

| Evidence | Browser behavior |
| --- | --- |
| Exact host or permitted explicit `URL_PATH` with a current installed rule | Manifest V3 `declarativeNetRequest` blocks the main-frame request, including matching redirect targets. A Chrome navigation error for a confirmed destination opens the extension-owned warning. |
| Hash-only match, rule beyond quota, or an HTTP(S) document that reaches the browser without a matching network rule | Check locally on commit or a History API navigation. If still the current document, move the tab to the extension warning and explain that the page may have loaded. |
| Financial hostname clues with no exact reputation match | Preserve the amber advisory and its explanation. |
| Missing or expired reputation | Display **Protection unavailable**. Local financial clues can still be shown. |
| Monitoring paused | Clear network and exception rules. |

The warning uses a private `chrome-extension://` page with an opaque fragment. Its sender, tab, top-level document and per-tab nonce must match before evidence or actions are returned. The warning displays the hostname, matched indicator scope, threat category, and any financial address clues. **Leave this site** opens a blank page. Users can choose a trusted bookmark or official app separately. The warning page is excluded from web-accessible resources and uses packaged scripts and styles.

## One-time exception

Chrome offers an exception only for a current pre-request phishing warning. Review and confirm from the private warning page. For a hostname match, the extension opens the clean origin root. For an explicit path, it opens the publisher's canonical path. The navigation excludes the original query, fragment, credentials, request body, and private browsing path. Malware and hash-only matches offer no exception.

The higher-priority `allow` rule is limited to the same tab, one exact clean GET address, a main-frame request, and the extension's initiator origin. It is consumed on commit and revoked on a failed or different navigation, snapshot/settings change, tab close, worker recovery, or after at most 20 seconds under normal browser scheduling. The warning page also verifies the deadline just before dispatching the request. A subsequent navigation is evaluated normally.

## Freshness and scope

- Session-scoped Chrome rules survive service-worker suspension and are reconciled with the current local snapshot. Browser shutdown or extension update clears the rules and session data. A valid last-good snapshot continues protecting an offline browser until its original expiry. A server rejection invalidates it at the next refresh.
- Chrome rules have no built-in expiry timestamp. A wake-up or alarms delayed by browser suspension can briefly leave a previous rule installed. The worker rechecks expiry before labeling a threat or granting an exception and removes expired rules when it resumes. A navigation caught in that window might receive a generic Chrome error and need a retry.
- Chrome 120 is the minimum version. The session rule budget reserves up to 800 bounded host regex groups, 160 explicit path rules, and 32 exception slots within Chrome's 1,000-regex limit. Indicator ordering determines which entries get a network rule when the budget is exhausted. The full snapshot remains available for local post-navigation checks.
- Pre-request blocking applies to main-frame requests processed by Chrome's network stack. A hash cannot be compiled into a request rule. Same-document changes and responses a website service worker serves directly can only be checked after navigation begins. Session rules have to be installed before the browser can apply them. These fallback checks do not guarantee that a script or resource was prevented from loading. [Manifest V3 rule limits and service-worker behavior](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest#rules-and-rulesets)

## Permissions, privacy, and distribution

This phase adds `declarativeNetRequest` for block and allow rules. It uses the existing navigation, storage, and alarms permissions and adds no broad host permissions, web-accessible resources, debugging permission, or traffic interception. Browser-owned rules execute independently of page scripts. A website can imitate the visual design but cannot obtain the extension origin, dismiss a browser rule, or approve an exception.

No browsing destination is included in the snapshot request or sent to the provider. The warning keeps minimal evidence in trusted extension session storage. It stores a hostname and an indicator identity, plus the clean publisher path or host root when eligible for an exception. User-supplied paths, query values, fragments, form data, request bodies, authentication cookies, and payment details are excluded. Existing opt-in behavior monitoring still follows its previously documented hostname and metadata contract.

The Chrome Web Store requires narrowly scoped permissions and disclosure of locally processed browsing data. Document the block feature and its permission in the submission, publish a privacy policy covering local and opt-in server processing, and use HTTPS for a production backend. This repository has no Web Store approval. No third-party feed was added to the browser snapshot. The Phase 2A.1 redistribution gate stays in force. [Permissions policy](https://developer.chrome.com/docs/webstore/program-policies/permissions) · [User data and privacy disclosures](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq)

## Verification

Run the Maven build and the extension tests from the README. The real Chromium smoke test uses a loopback server that counts requests separately by target and path. A tested network block requires zero hits on the protected destination. Host, exact-path, and redirect tests use synthetic feed indicators only.
