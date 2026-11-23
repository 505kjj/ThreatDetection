# Phase 3E independent financial phishing validation

**Partial research result.** Four original Phase 3D artifacts were tested on independently held-out, verified legitimate Indian financial controls. No eligible phishing URLs or independent time-valid reputation snapshots were obtained. The control comparison measures false warnings and runtime on the supplied URLs. It leaves phishing recall, incremental protection and a production false-positive rate unresolved.

## Sources and eligibility

| Source | Access, permission and evidence | Decision |
| --- | --- | --- |
| Official Indian financial sources | Public factual URL locators and service ownership verified against published first-party guidance on 24 November 2026. The private ledger records each URL, date, source, legitimate label and scope of use. The run extracts numeric features without copying or redistributing the providers’ pages or using a customer session. [ICICI Net Banking guidance](https://www.icici.bank.in/personal-banking/iplay/how-to-login-internet-banking), [Axis Internet Banking guidance](https://application.axis.bank.in/webforms/axis-support/sub-issues/digibkg-IB-retail-firstimeuser-1.aspx), [Kotak security guidance](https://www.kotak.bank.in/en/digital-banking/ways-to-bank/net-banking/security.html), [PayU Hosted Checkout](https://docs.payu.in/docs/prebuilt-checkout-page-integration) | Used for legitimate-only controls. |
| PhishVN V5 | Thai Nguyen Vu’s open metadata archive is CC BY 4.0. The publisher distinguishes verified Vietnamese NCSC records, trusted-organization controls, Tranco-derived benign records and a lower-confidence bronze tier. The study target is Indian, so Vietnamese records could only support a separate external transfer check. The public file listing supplied the size and SHA-256 pin. Repeated official downloads returned HTTP 502, with an additional HTTP 403 on a metadata request. No complete archive matching the publisher pin was obtained. The author’s public adjudication sheets lacked per-record observation dates and mostly lacked full absolute URLs. [PhishVN V5](https://data.mendeley.com/datasets/b97hxbxtpd/5), [published methodology](https://doi.org/10.1016/j.dib.2026.113195), [pinned audit sheets](https://github.com/vuthainguyen1602/phishvn/tree/e1f87f7a6ba3a2945eed5e3b0916a2a5a8c21ddf/docs/verify) | Scored zero rows. The optional adapter would admit only dated gold NCSC positives and dated gold trusted-organization negatives. It excludes bronze, Tranco and gated captures. The adapter was tested with a synthetic archive. |
| Cisco Talos PhishTank | API data terms explicitly permit commercial use and the official feed describes community verification times and optional target names. The development JSON and CSV downloads contained zero records and the production endpoints returned HTTP 429. The public online-valid feed is a current availability product, and a licensed historical target-verified export would still be needed for the intended evaluation. [Terms](https://phishtank.org/terms.php), [feed schema](https://data.dev.phishtank.com/developer_info.php) | Scored zero rows. |
| OpenPhish | The searchable explicitly historical product is the provider’s database. This work has no licensed dated brand-attributed export from it. [Database](https://www.openphish.com/phishing_database.html), [terms](https://www.openphish.com/terms.html) | Excluded. |
| RBI and I4C | RBI published a specific 2018 impersonation advisory. Its public notice predates this holdout window and identifies a bare address without confirmed scheme. The I4C public suspect lookup does not supply a rights-cleared, independently adjudicated dated archive with campaign IDs. [RBI advisory](https://www.rbi.org.in/commonPerson/english/Scripts/PressReleases.aspx?Id=2628), [I4C suspect repository](https://cybercrime.gov.in/Webform/suspect_search_repository.aspx) | Neither was converted to positive dataset rows. An official warning about lookalikes does not establish that every mentioned URL is phishing. |
| CERT Polska and HKMA | CERT Polska permits Warning List data processing but publishes domain-level abuse indicators with different geography, no reliable matched full-URL labels and no eligible hard-negative URLs. HKMA's standard terms restrict reuse to non-commercial use under conditions and do not establish commercial-product research rights for its alerts here. [CERT Polska specification](https://github.com/CERT-Polska/phishing-api/blob/master/SPECIFICATION.md), [HKMA terms](https://www.hkma.gov.hk/eng/other-information/terms-and-conditions-of-use/) | Audited and excluded. |

Official documentation, login or account service URLs covered ICICI Bank, Axis Bank, Kotak Mahindra Bank and PayU. This includes official login and remittance paths and a documented PayU hosted checkout endpoint. These are public address controls. No customer login or payment was attempted. SBI, HDFC, NPCI and Razorpay addresses were checked during acquisition and dropped due to prior domain overlap. No verified target labels were obtained for SBI, HDFC, ICICI, Axis, UPI, NPCI or Razorpay phishing. [Prior registry and evidence](../../financial-impersonation.md), [SBI Internet Banking](https://sbi.bank.in/web/personal-banking/digital/internet-banking), [HDFC Bank NetBanking](https://www.hdfc.bank.in/now-hdfc-bank), [NPCI UPI FAQ](https://www.npci.org.in/what-we-do/upi/faqs), [Razorpay documentation](https://razorpay.com/docs/api/payments/payment-links/create-standard)

## Frozen protocol and split

| Cohort | Phishing URLs | Legitimate URLs | Registrable domains |
| --- | ---: | ---: | ---: |
| New development or calibration | 0 | 0 | 0 |
| Independent phishing efficacy holdout | 0 | 0 | 0 |
| Official Indian controls | 0 | 10 | 4 |

The 15 candidate controls lost five rows to earlier domain overlap. The final control count is five ICICI, two Axis, one Kotak and two PayU. The projection verified the original Phase 3B partition manifests, the Phase 3C and 3D partition digests and counts, and the earlier official control scope. It excluded 454,404 previous domain identities and 179,806 Phase 3D lexical-family identities. By using the same registrable-domain parser, any canonical exact-URL overlap would also fail the domain exclusion. A lexical family remains a heuristic for rebranded registrants. These sources do not support a verified campaign-disjoint or representative-traffic claim.

The frozen [protocol](../../../research/phase3e/protocol.json) fixes the window after the Phase 3D test dates, the candidate set, the source policy and the original Phase 3D thresholds. The primary operating point uses the original target of 0.1% legitimate-domain FPR and the secondary uses 1%. Protocol, source metadata, projected test vectors, model reports and artifact hashes were checked before inference. The holdout was opened once. No training, weighting, calibration, feature or threshold adjustment was performed. Projection and ordered feature schema were subsequently checked without rescoring. The benchmark records test collection outcomes rather than measuring real browsing prevalence.

## Frozen single model versus fusion

At both frozen cutoffs every candidate produced TN = 10 and FP = 0. There were no phishing rows. AP, precision, recall and F1 are unavailable. Domain FPR observed on these four control domains was 0/4. The one-sided exact 95% upper bound is **52.71%**, assuming domains are independent. The two-sided exact URL interval is approximately **0–30.85%**, treating URLs as independent for illustration. These controls are clustered by institution, so the URL interval is not evidence for the 0.1% operational target.

| Frozen candidate | Primary cutoff | False warnings | Model storage | p50 / p95 inference | Mean CPU per row | Python-traced peak for the 10-row batch |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Hostname + path Random Forest | 0.961056 | 0 of 10 | 324,894 B | 1.832 / 3.345 ms | 1.831 ms | 14,864 B |
| Two-model weighted average | 0.966665 | 0 of 10 | 263,785 B | 2.368 / 2.961 ms | 2.075 ms | 19,084 B |
| Four-model calibrated average | 0.961997 | 0 of 10 | 271,472 B | 3.110 / 4.419 ms | 3.296 ms | 18,037 B |
| Four-model stack | 0.970732 | 0 of 10 | 271,349 B | 3.162 / 5.118 ms | 3.418 ms | 18,037 B |

Latency used 128 warmed single-row predictions per candidate over the same control set. Artifact size is compressed local storage. Allocation peaks do not include native allocations or process-wide RSS. The stack took about **1.73×** the selected Forest’s median time on these controls. The earlier 3.2× figure was for a different single-model reference and cohort. The frozen Forest uses 12 hostname/path features and the ensembles use eight hostname features. This compares the existing frozen candidates as used, so it cannot isolate the causal effect of ensembling from the differences in training data and features.

There were zero threshold disagreements and zero shared classification errors in the controls. Error correlation is undefined because every error indicator is constant. There were no added false-positive cases at either threshold, and the private case-difference file was empty. The zero-positive cohort provides no basis for identifying attacks detected only by fusion or judging its effect on missed phishing. The [saved results](summary.json) report those support limits and preserve all thresholds and model hashes.

## Existing protection and incremental lift

Financial-brand advisory rules produced **0 of 10** amber cautions. Combining those advisory flags with frozen ML scores added **0 of 10** false warnings in this control set. The union is an offline research calculation. It does not replace or downgrade known reputation matches.

The repository and available research inputs did not contain eligible independent reputation snapshots valid at the supplied observation times. The existing replay tests check that the evaluator excludes future, expired and same-lineage intelligence. Reputation-only performance, incremental recall over reputation plus brand, and added false positives for the full protection stack are all **unsupported**. Contemporary threat lookups cannot fill those historical gaps.

## Laptop measurements

Projection and inference ran sequentially on the Lenovo Windows 11 laptop, CPU-only with affinity to two logical processors and below-normal priority. The published guard enforces an 8,000,000,000-byte Windows Job Object commit limit and monitors a reduced 4,000,000,000-byte experiment target. It samples host CPU on two-second intervals and stops on sustained overload. No resource stop fired. Row-level Python measurements above complement the process-tree measurements below.

| Stage | Worker wall time | Job CPU time | Peak job commit |
| --- | ---: | ---: | ---: |
| Projection | 1.50 s | 1.44 s | 331.3 MiB |
| Scoring and timing | 2.94 s | 2.64 s | 132.6 MiB |

Scoring recorded one host utilization sample of **9.43%**. Projection finished before its first sample. These timings do not estimate all-day laptop or browser overhead. [Resource records](resources.json)

## Decision

**Recommend no ML integration yet.** Phase 3E is a **NO-GO for offline efficacy sign-off and for controlled browser integration**. Continue offline work once a dated, rights-cleared, independently adjudicated Indian cohort is available. Include legitimate payment and authentication traffic, independently identified phishing campaigns, enough legitimate domains for the operating-point bound, and date-valid reputation snapshots from another lineage. Freeze the evaluation design again before opening that cohort. Retain the single Forest as the lightweight reference and the three fusion artifacts as comparisons.

## Verify and reproduce

Phase 3D entered main through [PR #11](https://github.com/505kjj/ThreatDetection/pull/11) after all 37 previous artifact and calibration checksums, three private partition digests, the public report and chart, and the prior security checks were confirmed. Phase 3E keeps the backend, browser and production protection rules unchanged. Run the existing backend, extension and Chromium test procedures along with the Python Phase 3E suite. The official controls projection reproduced byte for byte. No raw dataset, evidence ledger, credentials, browsing record or model binary is in Git. [Project verification](../../../README.md)

| Verification suite | Passed | Failed |
| --- | ---: | ---: |
| Spring Boot clean verify | 53 | 0 |
| Extension and Phase 3C–3E Node regressions | 28 | 0 |
| Offline evaluation | 8 | 0 |
| Existing and Phase 3D–3E Python research | 13 | 0 |
| Real Chromium integration smoke | 1 | 0 |
| **Total** | **103** | **0** |

Real Chromium verified authenticated and allowlisted requests, request-level synthetic host and redirect blocking, tab-scoped exceptions, advisories, pause, backend recovery and expired-snapshot handling. Gitleaks and a Git file inventory checked reachable history and staged changes.

The [research CPU environment](../../../research/README.md) is unchanged. From the repository root in PowerShell, supply existing private directory paths for the three original numeric datasets and a JSON Lines ledger of authorized public controls. Each ledger row records the exact URL, stable ID, label 0, observation day, source "official-india", cohort "india-control", verified brand, an authoritative evidence URL and scope of use. The local ledger and any open PhishVN archive must stay outside Git.

~~~powershell
npm ci --prefix evaluation --ignore-scripts
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/prepare.json" -- python research/phase3e/cohort.py --uci $uci --phase3c $phase3c --phase3d $phase3d --controls $controls --output "$run/cohort"
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/score.json" -- python research/phase3e/score.py --cohort "$run/cohort" --models $phase3dCandidates --output "$run/score"
~~~

Use the official PhishVN open archive with `--archive` only if the file matches the pinned SHA-256 and meets the source policy. Scoring is one-time per output directory and checks the data and protocol digests before opening it. The saved JSON is sufficient to inspect the completed controls run. The private case-difference file preserves local evidence IDs when cases exist.
