# Phase 3F financial phishing data and validation

**Partial result.** We obtained 2,000 eligible historical general phishing URLs from distinct registered domains and 29 new Indian financial legitimate URLs from ten domains. There are zero verified Indian or non-Indian financial phishing URLs in the scored cohorts. Four frozen candidates were scored offline. The best archive recall at the strict cutoff was 4.35%. No candidate warned on the India controls, whose small domain count leaves false-positive risk uncertain.

## Acquisition and cohort support

[Source audit and permissions](source-audit.md) records the attempted interfaces, license conditions, available evidence, and reasons for exclusion. [Behind the Bait](https://doi.org/10.1016/j.dib.2023.109959) by Yasin, Fatima, Khan and Afzal supplied the eligible archived records through its [CC BY 4.0 Zenodo release](https://doi.org/10.5281/zenodo.8371046). Two original workbooks were downloaded from the publisher. Both matched the publisher’s sizes and MD5 digests. The accepted workbook also matched the local SHA-256 pin in the [protocol](../../../research/phase3f/protocol.json). Workbook 20 had a row-specific PhishTank identifier, full observed URL, submission date and explicit valid-phish status. Workbook 1 lacked a per-row valid-phish flag and was excluded after checking its schema. The projection omitted names, user links, other metadata unrelated to evaluation and all unneeded URL components. No phishing destination was fetched, resolved or executed.

| Cohort | Phishing URLs | Legitimate URLs | Registered domains | Documented campaigns |
| --- | ---: | ---: | ---: | ---: |
| Verified Indian financial phishing | 0 | 0 | 0 | 0 |
| Verified non-Indian financial phishing | 0 | 0 | 0 | 0 |
| General archive transfer, 12 January–21 February 2014 | 2,000 | 0 | 2,000 | 0 |
| Indian financial legitimate controls, observed 24 November 2026 | 0 | 29 | 10 | Not applicable |

No milestone was met as a paired evaluation. General positive support reached the largest planning count of 2,000. Legitimate support remained below the initial 300-URL target and verified financial positives remained unavailable. The cohorts stay separate because they differ in class, observation date and selection process.

The 29 controls include five login URLs, one verification URL, eight payment-related endpoints or instructions, six security pages and nine banking pages. They cover PNB, IDFC FIRST, Bank of Baroda, Union Bank, Indian Bank, Bank of India, Federal Bank, Cashfree and PhonePe. Different paths on the same registered domain are correlated. Only authorized public locators were used. No customer session, form value or payment transaction was collected. [Official sources](source-audit.md#indian-financial-sources)

## Eligibility, leakage and freeze

- Workbook 20 held 34,814 populated URL rows. Three failed the strict provider-reference or full-URL check, leaving 34,811 source-verified records before normalization. “Verified” means the archived source explicitly marked each row valid. An independent second reviewer, a separate verification timestamp, original browser content and trusted target identity were unavailable. A submission day is a historical report time and no missing date was filled.
- Domain exclusions were built from **454,408** previous domain identities, including four Phase 3E groups, and **179,806** previous lexical families. The input digest and record counts for each preceding cohort were verified while extracting only identity fields. The original held-out datasets were preserved and were never rescored. Under the shared canonical parser, a repeated exact URL would also share a previous domain.
- Projection discarded 3,717 unusable URL records, 871 prior-domain rows, 78 prior lexical-family rows and 9,671 duplicate canonical URLs. Another 11,567 shared an already represented registered domain and 132 shared an already represented lexical family. Of 8,775 remaining representatives, deterministic hash ordering admitted 2,000 to the fixed cap. The resulting archive cohort had 1,375 identifiable lexical families plus rows without a family proxy. Lexical grouping cannot establish campaign independence. PhishTank lineage may still overlap older datasets at the provider level.
- The 53 Indian candidates included all 15 previously reviewed Phase 3E candidates. Earlier domain overlap excluded 15 rows and earlier lexical-family overlap excluded nine. The surviving official controls do not form a prevalence sample.
- The evaluator checked both published references, all four local artifact SHA-256 hashes, the ordered URL feature schema and the Phase 3E cutoff equality before creating a one-time scoring receipt. The primary and secondary points are the original Phase 3D cutoffs calibrated to 0.1% and 1% domain FPR, respectively. Those labels describe the old calibration objective. Neither rate was assumed to transfer. Models, ensemble weights and thresholds were held fixed. Each candidate scored the same eligible rows once.

## General archival recall and disagreement

| Frozen candidate | Primary detections | Primary recall, exact 95% interval | Extra / lost phishing vs. RF | Secondary detections | Secondary recall |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hostname-plus-path Random Forest | 9 of 2,000 | 0.45% (0.21–0.85%) | — | 58 | 2.90% |
| Two-model weighted fusion | 16 of 2,000 | 0.80% (0.46–1.30%) | 15 / 8 | 230 | 11.50% |
| Four-model calibrated average | 87 of 2,000 | 4.35% (3.50–5.34%) | 80 / 2 | 208 | 10.40% |
| Four-model stack | 15 of 2,000 | 0.75% (0.42–1.23%) | 14 / 8 | 212 | 10.60% |

The four-model average gained **78 net detections** at the primary point, or **3.90 percentage points** of archive recall. The paired registered-domain bootstrap 95% interval was **+3.02 to +4.60 points**. At the primary point, 1,904 URLs were missed by all candidates, 87 were found only by at least one fusion model, and two were found only by the Random Forest. The four-model average and Random Forest disagreed on 82 rows and shared 1,911 missed detections. Their binary error correlation was 0.242. The paired case ledger preserves source evidence IDs locally. No raw URLs or case-level scores were published.

The secondary point favored two-model fusion on this sample. The point estimates describe dated archived reporting behavior, host/path patterns and selection biases in one source. Exact recall intervals and the domain bootstrap cannot account fully for unlabelled campaign dependence. The Forest uses 12 features and the fusion candidates use eight hostname features, with different Phase 3D training procedures and cutoffs. The comparison measures the frozen candidates as configured. It does not isolate a causal ensemble advantage. Average precision, precision and F1 are unsupported because the cohorts each contain one class.

## Indian controls and incremental protection

Each candidate had 29 true negative controls and zero false warnings at both original cutoffs. The domain false-positive observation was **0 of 10**. The one-sided exact 95% upper domain bound was **25.89%**, assuming independence. The two-sided exact URL upper limit was **11.94%** under a row-independence assumption that does not hold fully when domains repeat. The frozen protocol requires at least 2,995 independent legitimate domains even to potentially bound a 0.1% rate with zero observed false alerts. No 0.1% operational claim is supported.

| Existing protection comparison | Archived positives | Indian legitimate controls |
| --- | --- | --- |
| Financial-brand rules only | 0 amber advisories | 0 amber advisories |
| Financial-brand rules plus each frozen model | Extra detections at the primary point were 9, 16, 87 and 15 for the four models in table order | 0 extra warnings observed for each candidate |
| Reputation only or reputation plus brand | Unsupported | Unsupported |
| Full protection plus Random Forest or any fusion candidate | Incremental lift unsupported | Incremental false warnings unsupported |

Historical replay requires an independent snapshot valid at each original observation date. No such snapshot was available. Current threat intelligence and the PhishTank label archive cannot substitute for that evidence. The brand-only union is an offline comparison against the existing India-specific heuristic. General archive target labels are unknown, so zero advisories does not estimate financial-rule recall. No ML result overrode a known reputation match.

## Resource measurements

| Frozen candidate | Compressed artifact | p50 / p95 CPU inference | Mean CPU per row | Traced Python peak for 256-row prediction |
| --- | ---: | ---: | ---: | ---: |
| Random Forest | 324,894 B | 3.846 / 4.457 ms | 3.784 ms | 36,458 B |
| Two-model fusion | 263,785 B | 5.073 / 6.385 ms | 5.127 ms | 39,108 B |
| Four-model average | 271,472 B | 6.665 / 7.246 ms | 6.348 ms | 70,410 B |
| Four-model stack | 271,349 B | 6.006 / 7.144 ms | 5.981 ms | 70,332 B |

Each timed candidate used 128 warmed single-row predictions. Python-traced allocation excludes native allocations and total process memory. The archive projection, preparation and scoring steps took 1.83, 4.19 and 6.73 seconds, respectively. The primary run peaked at **362.3 MiB** of worker-tree committed memory during preparation and **139.5 MiB** during scoring. Including the reproducibility check, peak committed memory was **365.5 MiB** and the highest sampled host CPU was **18.83%**. Guarded jobs ran sequentially on the Lenovo at below-normal priority with two logical CPUs, a 4 GB monitored target, and an enforced 8 GB worker-tree commit ceiling. None tripped a resource stop. [Resource measurements](resources.json)

## Research decisions

| Decision | Result |
| --- | --- |
| Dataset suitability | **GO** for archival transfer and official-control feasibility only. **NO-GO** as an independent financial phishing dataset. |
| Offline model efficacy | **GO** for the reported conditional archive recall comparison. **NO-GO** for financial phishing efficacy, a deployable cutoff, or choosing a winner from these data. |
| Incremental protection evidence | **NO-GO** for full product lift. Only the explicit brand-advisory comparison is supported. |
| Controlled browser shadow testing | **NO-GO** until a contemporary independent financial cohort and time-valid reputation replay support it. |
| ML warning or blocking | **NO-GO**. Keep existing rule-based protection and the single Forest as the reference for the next offline comparison. |

The next evidence to obtain is a rights-cleared bank, payment provider or CERT export containing verified targets and campaign IDs, with dated independently maintained reputation snapshots and more legitimate registered domains. Use a fresh period and hold out complete campaign groups before scoring. A few archived extra detections cannot justify integration or show low false-positive risk.

## Reproduction and verification

Phase 3E entered main through [PR #12](https://github.com/505kjj/ThreatDetection/pull/12) after the prior aggregate, cohort, case and artifact checksums were verified. Use the pinned [CPU research environment](../../../research/README.md) and the [archival and scoring protocol](../../../research/phase3f/protocol.json). The research tools parse XLSX XML with the Python standard library and launch no spreadsheet code. Keep the private datasets, evidence and model bundles outside all Git worktrees.

Download only the explicitly approved workbook from the [publisher file API](https://zenodo.org/api/records/8371046/files/Valid_Phishes_Offline%2020.xlsx/content). Match the published MD5 and pinned SHA-256 before use. Supply a private JSON Lines control ledger with the exact public URL, stable ID, original observation day, label 0, source "official-india", cohort "india-control", institution, kind, authoritative evidence URL and use scope. The recorded SHA-256 values live in the [aggregate manifest and results](summary.json).

~~~powershell
npm ci --prefix evaluation --ignore-scripts
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/archive.json" -- python research/phase3f/archive.py --output "$run/archive" $workbook
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/prepare.json" -- node --max-old-space-size=2700 research/phase3f/prepare.mjs $phase3b $phase3c $phase3d $phase3eRows $controls "$run/archive" "$run/cohort"
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/score.json" -- python research/phase3f/evaluate.py --cohort "$run/cohort" --models $phase3dCandidates --output "$run/results"
~~~

The final command opens the private cohort once and creates a receipt in the cohort directory. Inspect saved aggregates to reproduce the report without reopening the holdout. The class-separated confusions, paired counts, original cutoffs, confidence bounds, sizes and snapshot abstentions are in [summary.json](summary.json).

| Verification suite | Passed | Failed |
| --- | ---: | ---: |
| Extension regressions and Phase 3C–3F Node research regressions | 30 | 0 |
| Offline dataset evaluation | 8 | 0 |
| Python research regressions through Phase 3F | 17 | 0 |
| **Total** | **55** | **0** |

The archive ledger, numeric cohort and metadata reproduced byte for byte without rescoring. Backend and browser-facing code, production thresholds and prior reports are identical to the Phase 3E merge base. A new backend build and Chromium smoke test therefore were outside this research-only change. Gitleaks and the Git inventory checked history and the staged files.
