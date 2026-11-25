# Phase 5G independent validation and model selection

**Decision: continue offline research. Hold controlled shadow testing, browser warnings and blocking.** This phase froze eight candidates and verified their development receipts. It scored zero independently eligible URL or paired-page records and established no production winner.

## Candidate freeze and replay

The registry locks the original character TF-IDF, CNN, XGBoost, Phase 5D TF-IDF/XGBoost blend, and source-balanced TF-IDF. It also locks the Phase 5F fixed URL+DOM blend, logistic stack, and adaptive comparator. It records checkpoint sizes and SHA-256 hashes, preprocessing pins, runtime versions, source manifests, training memberships, fusion parameters, and the original operating thresholds. Phase 5F has no supported 0.1% cutoff. The source-balanced model retains its UCI calibration. [Frozen registry](frozen-models.json)

The preflight checked all seven Phase 5F checkpoints and the fusion artifact against the guarded experiment receipt. It verified the original Phase 5C and 5D input manifests, the Phase 5E projection receipts and checksums, and the four Phase 5F grouped memberships. Fixed fusion, stacking and adaptive fusion reproduced their published evaluation metrics on all 5,011 development validation rows. All eight frozen candidates reproduced their scores and decisions on the eight existing diagnostic fixtures. [Aggregate preflight](preflight.json)

## Independent evidence

PhishVN v5 passed publisher, license, version and archive checksum checks. It failed the registered forward-test chronology and does not supply record-level credential-phishing adjudication or dated benign page ownership at the required scope. Only public documentation members were read. Protected record tables remained sealed, with zero labels opened, zero rows admitted and zero rows scored. The open archive contains no paired HTML. [Eligibility, rights and custody](independent-data.md)

| Cohort | Independently scored | Remaining requirement |
| --- | ---: | --- |
| General URL phishing and benign | 0 | Dated credential-phishing and verified legitimate records admitted by an independent custodian |
| Paired URL and DOM | 0 | Independently held, authorized aligned captures and separation by domain and template family |
| Indian financial positives | 0 | Independent institution attribution, dated evidence and use rights |
| Non-Indian financial positives | 0 | Independent institution attribution, dated evidence and use rights |
| Fresh financial and authentication controls | 0 | Dated, rights-cleared page captures held outside model development |

The historical exclusion index verified 518,088 exact URL, 516,399 alias, 455,670 domain and 311,217 lexical-family digests. It used known historical exclusions and canonical development, calibration, prior evaluation and publisher-holdout exclusion views. It contained zero independently verified campaign IDs. A lexical-family match can flag potential overlap. Verified campaign separation also needs independent source-lineage and campaign evidence. No PhishVN records were compared to this index because the release failed the cohort-level gate first.

## Historical financial URL controls

The Phase 3E official ledger supplied 15 previously observed legitimate URLs across eight domains and eight providers, dated 2026-11-24. Its permissions cover internal analysis of factual URL locators. Every row lacked paired HTML. The deterministic financial-impersonation rules were replayed as URL diagnostics in the same comparison. [Earlier evaluation](../phase3e/README.md)

| URL candidate | Alerts at 0.5 | Alerts at original 1% cutoff | Alerts at original 0.1% cutoff |
| --- | ---: | ---: | ---: |
| Character TF-IDF | 3/15 | 0/15 | 0/15 |
| Character CNN | 5/15 | 0/15 | 0/15 |
| XGBoost | 0/15 | 0/15 | 0/15 |
| Phase 5D URL fusion | 3/15 | 0/15 | 0/15 |
| Source-balanced TF-IDF | 6/15 | 12/15 | 7/15 |
| Financial impersonation rules | 0/15 | — | — |

Zero alerts among eight domains still allows a one-sided 95% upper bound of 31.23%, assuming independent domains. The source-balanced model alerted on six of eight domains at its original 1% point and four at its original 0.1% point. Phase 5F's URL fallback alerted on zero controls at each of the three original 1% fusion cutoffs. The fallback is a separate URL-only outcome. Reports omit ranking and recall for this negative-only set and include its confusion matrices, observed URL and domain FPRs, confidence intervals and paired disagreement. [Aggregate preflight](preflight.json)

No eligible time-valid, independently sourced reputation snapshots were available for the intended independent cohorts. The historical brand-rule diagnostic measures false cautions on those official URLs. Incremental detection over the combined protection stack, time-valid reputation performance and independent phishing recall remain unmeasured.

## Registered decision framework

Use the original candidate cutoffs on the same eligible records. Report URL and domain FPR and both observed values and confidence bounds. Evaluate paired recall against the existing protection baseline and relevant frozen URL comparators. Treat a candidate as provisionally useful only when the paired recall increase is supported, benign authentication and payment errors are acceptable, and separate temporal and cross-source results support generalization. At the primary 0.1% domain target, even zero errors require at least 2,995 independent benign domains for a one-sided 95% upper bound of 0.1%. The registered scorer leaves unavailable thresholds and unsupported population estimates empty. [Protocol](../../../research/phase5g/protocol.json)

The scoring report projects precision from the **URL** recall and FPR at stated phishing prevalence scenarios of 0.01%, 0.1%, and 1%. These are sensitivity scenarios, not measured deployment prevalence. There are no valid inputs for this phase's estimates, so historical-control precision scenarios remain empty. When available, read the scenario estimates with the underlying FPR confidence interval and independence assumptions.

Retain standalone character TF-IDF as the provisional lightweight URL reference and Phase 5D URL fusion as a comparator. Retain Phase 5F fixed fusion as the provisional multimodal research candidate because it improved retrospective recall at matched calibration false-alert counts. Its external benefit and operating FPR are unknown. The stack and adaptive variants remain comparisons. The source-balanced model's historical control alerts are a concrete reason to withhold promotion. Phase 5F's matched estimates put standalone TF-IDF at 1.27/1.79 ms median/p95 and fixed fusion at 7.78/52.54 ms, including an estimated parser stage. End-to-end external latency, browser privacy and compatibility still need independent review. [Phase 5F comparison](../phase5f/README.md)

| Decision | Result |
| --- | --- |
| Further offline research | **GO** for independent custody, rights-cleared captures and frozen comparisons |
| Controlled shadow testing | **NO-GO** pending independent efficacy, operational controls and privacy review |
| Browser warnings | **NO-GO** pending low-FPR evidence and incremental protection |
| Browser blocking | **NO-GO** pending all warning gates and a separate blocking safety evaluation |

The Windows Job Object preflight took 11.22 seconds and peaked at 1,160,245,248 committed bytes with two logical CPUs and zero resource violations. The overlap-index verification took 10.17 seconds and peaked at 397,860,864 bytes. All 43 JavaScript and 25 guarded Python tests passed, including custody signature tamper detection and the existing browser protection regression suite. The parser dependency audit reported zero known vulnerabilities. [Preflight guard receipt](resources.json), [overlap-index guard receipt](overlap-resources.json)
