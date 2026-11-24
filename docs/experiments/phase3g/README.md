# Phase 3G frozen-model failure analysis

**Finding.** The low Phase 3F recall reproduced with the original data, features, model artifacts and cutoffs. The archived positives had different URL-feature and score distributions from the Phase 3D development positives. None of the four candidates used the scheme or an explicit TLD category. The experiment does not establish whether the difference came from collection practices, population mix, age, or a combination.

## Architecture and dependency

The current Chrome extension uses local reputation and financial-brand advisories, with browser session rules for confirmed matches. The Spring Boot service manages authenticated reputation access and updates. The Phase 3A–3G research pipeline runs separately and offline. Phase 3G changes research tooling and documentation only. [Browser protection](../../browser-protection.md), [backend and extension overview](../../../README.md)

| Phase | Relevant result |
| --- | --- |
| [3A](../../dataset-evaluation.md) | Added URL normalization, data provenance checks, offline reputation replay and domain-disjoint evaluation. |
| [3B](../phiusiil/README.md) | Benchmarked four URL classifiers on one retrospective UCI corpus with a frozen holdout. |
| [3C](../phase3c/README.md) | Measured external transfer and feature sensitivity on PhreshPhish, and found poor cutoff transfer. |
| [3D](../phase3d/README.md) | Trained the archived Random Forest and three fusion candidates and froze their cutoff definitions. |
| [3E](../phase3e/README.md) | Tested those original artifacts on Indian financial controls. No eligible financial phishing positives were found. |
| [3F](../phase3f/README.md) | Added a dated general-phishing transfer cohort and separate official Indian controls. The cohort and source restrictions remain unchanged. [Acquisition and licensing](../phase3f/source-audit.md) |

At verification, GitHub main included 3A–3E and did not include Phase 3F commit `1dc373f4dbefc4a5754b15cf5937493b4ee0533b`. Phase 3G starts from that exact commit. Its review stacks on the existing Phase 3F branch while Phase 3F is outside main.

## Reproduction and scoring audit

- A fresh Windows checkout converted the checksum-pinned Phase 3F protocol file from LF to CRLF and the evaluator correctly rejected it before inference. The tracked Git attribute now preserves its original LF bytes. The protocol and datasets were never repinned.
- Rerunning the existing Phase 3F evaluator on a private copy reproduced both cohorts, thresholds, confusion counts, intervals, pair comparisons and the private disagreement digest. Model digests and sizes matched. Timing varies by run. The initial copy and the original scoring receipts stayed separate.
- The archive ledger was read offline, and all **2,000** archived rows reproduced the frozen 14-element URL vectors exactly. The Phase 3D preparation function rebuilt the original training and calibration arrays from their pinned inputs. Feature values, labels and domain-group identities matched the saved arrays. The original Phase 3D final holdout was not reopened.
- The artifacts preserved feature order, positive class `1`, the fitted scaling steps for Logistic Regression and MLP where present, fusion weights and stacking. Independent arithmetic reconstruction differed from the shared scorer by at most **1.12 × 10⁻¹⁶** over the archive. Phase 3D calibration class counts and false-alert domain counts also reproduced at both original cutoffs. No scoring error was found by these checks.
- The archive comprises **2,000 distinct grouping keys**. That is **1,903 registrable domains and 97 literal IP addresses**. The Phase 3F `domains` aggregate counts both types. Campaign IDs remain unknown. The private ledger stores the candidates that detected each evidence ID at each cutoff. The published JSON contains aggregates only.

## False negatives and disagreements

Both cutoff labels refer to the original Phase 3D calibration targets. They do not establish the false-positive rate in this phishing-only archive. Exact intervals below assume independent observations. Domain-level resampling also cannot account fully for unknown shared campaigns.

| Frozen candidate | Strict recall, 95% CI | Strict false negatives | Secondary recall | Secondary false negatives |
| --- | ---: | ---: | ---: | ---: |
| Random Forest | 0.45% (0.21–0.85%) | 1,991 | 2.90% | 1,942 |
| Two-model weighted fusion | 0.80% (0.46–1.30%) | 1,984 | 11.50% | 1,770 |
| Four-model calibrated average | 4.35% (3.50–5.34%) | 1,913 | 10.40% | 1,792 |
| Four-model stack | 0.75% (0.42–1.23%) | 1,985 | 10.60% | 1,788 |

At the strict cutoff, **1,904** rows were missed by all four candidates and **one** was detected by all four. Seventy were detected only by the four-model average. Compared with the Forest, that average detected 80 additional cases and missed two the Forest detected. It detected **75 of 97** literal-IP cases versus **7 of 97** for the Forest. Among DNS-name cases it detected **12 of 1,903** versus **2 of 1,903**. The literal-IP group accounts for **68 of the 78** net additional detections. At the secondary cutoff, the two-model candidate detected 230 and the four-model average 208. The ordering depends on the frozen cutoff and cohort composition. [Complete pairwise counts and intervals](analysis.json)

## Feature groups and transfer

The analysis groups canonical URL length, hostname length, subdomains, host/path digits, path length, path punctuation, host hyphens, percent escapes and the most common top-level domains. Removed userinfo, query and fragment data never enter these summaries. The canonical URL includes the scheme. IP literals have a separate bucket. Smaller and unrecognized TLD buckets share “other”.

| Archived group at the strict cutoff | Count | Forest hits | Two-model hits | Four-model average hits | Stack hits |
| --- | ---: | ---: | ---: | ---: | ---: |
| Canonical URL length 40–79 | 1,644 | 1 | 16 | 73 | 15 |
| Hostname length 16–24 | 909 | 1 | 0 | 0 | 0 |
| One subdomain label | 848 | 0 | 1 | 3 | 2 |
| Two or more subdomain labels | 164 | 0 | 12 | 7 | 10 |
| Non-root path of 40–79 characters | 655 | 0 | 0 | 39 | 0 |
| Any path punctuation beyond slashes | 1,701 | 1 | 13 | 74 | 12 |
| Hostname contains a hyphen | 292 | 0 | 7 | 6 | 8 |
| .com | 894 | 0 | 7 | 3 | 5 |
| .org | 87 | 2 | 3 | 2 | 3 |

| Feature among phishing-labeled rows | Archive | Forest training | Fusion training | Phase 3D calibration |
| --- | ---: | ---: | ---: | ---: |
| Median hostname length | 18 | 25 | 24 | 20 |
| Median path length | 31 | 0 | 0 | 0 |
| Median path depth | 3 | 0 | 0 | 0 |
| Has subdomains | 50.60% | 18.58% | 39.97% | 27.32% |
| Has host digits | 15.00% | 23.83% | 28.47% | 25.14% |
| Has host hyphens | 14.60% | 46.85% | 37.91% | 33.81% |
| Has path digits | 31.80% | 8.50% | 7.94% | 14.03% |

Archive versus Forest-training empirical CDF distances were **0.716** for path depth and **0.684** for path length. Those are descriptive distances on a 0–1 scale. The archive was also predominantly non-HTTPS, but both the scheme and non-default-port columns were excluded by every candidate. TLD strings and path punctuation counts are diagnostic groups, not explicit inputs. The Forest used eight host features and four path features. All fusion variants used only the eight host features. Correlation between path groups and their fusion scores therefore cannot show a path effect.

| Candidate | Archive median score | Calibration-positive median score | Strict cutoff | Archive scores within 0.05 below strict cutoff |
| --- | ---: | ---: | ---: | ---: |
| Random Forest | 0.184 | 0.569 | 0.961 | 8 |
| Two-model fusion | 0.454 | 0.764 | 0.967 | 263 |
| Four-model average | 0.452 | 0.752 | 0.962 | 144 |
| Stack | 0.455 | 0.784 | 0.971 | 242 |

**Supported interpretation.** Substantial input shift and reduced positive scores are observable under the same preprocessing and cutoff arithmetic. The operating point matters, especially for two-model fusion and the stack, where many archive scores cluster below the strict cutoff. The Forest has few near misses and a much lower median, so proximity to the cutoff does not account for most of its misses. Neither result establishes the false-positive cost of lowering a cutoff. No threshold was tuned.

**Unresolved hypotheses.** Archived URL selection could favor specific hosting infrastructure, path conventions, or campaigns. Era and source are confounded, so dataset age cannot be isolated. URL counts omit page text and visual or behavioral evidence, independently verified financial targets and time-valid reputation. Their incremental contribution cannot be measured here. The archive cannot estimate precision, F1, real browsing prevalence, or Indian financial effectiveness. The 29 Phase 3F current controls remain a separate cohort.

## Dataset readiness and next decision

The [offline validator and schema guide](validator.md) check URL validity, verified-label and financial-target evidence fields, dates, rights, duplicates and related domains, literal IPs, and campaign leakage across proposed splits. It produces a SHA-256-pinned readiness report without visiting or publishing URLs. It checks explicit declarations and evidence locators offline. Authenticity, legal authority and evidentiary sufficiency still require independent review.

The validator was exercised on the 2,000 Phase 3F archive rows using their existing evidence. All were ineligible as new financial validation rows. None had verified financial target metadata and all overlapped the Phase 3F holdout. No campaign IDs or verification timestamps were invented. [Saved eligibility check](validator-summary.json)

**GO for preparing and vetting a fresh authorized financial dataset offline. NO-GO for selecting a model, tuning cutoffs, browser shadow testing, warnings or blocking.** A useful next evaluation needs independently verified banking or payment targets, campaign and source provenance, current hard negatives from enough distinct domains, and independent time-valid reputation snapshots. Freeze that study before opening its final cohort.

## Reproduce

Use the existing [pinned CPU environment](../../../research/README.md), Node.js and the shared Windows [resource guard](../../../research/phase3d/resource_guard.py). All input and output directories below are private outside Git. Use a new run directory with a separate copy of the Phase 3F cohort's `manifest.json` and `numeric.jsonl` only. Keep the original cohort and its receipt intact.

~~~powershell
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/reproduction.json" -- python research/phase3f/evaluate.py --cohort "$run/reproduction-cohort" --models "$phase3d/candidates" --output "$run/reproduction"
python research/phase3d/resource_guard.py --memory-target 4000000000 --metrics "$run/analysis-resources.json" -- python research/phase3g/analyze.py --cohort "$phase3f/cohort" --ledger "$phase3f/approved-archive/archive-ledger.jsonl" --reproduction "$run/reproduction" --uci "$phase3b/dataset" --phase3d $phase3d --models "$phase3d/candidates" --output "$run/analysis"
~~~

The existing scorer reproduces Phase 3F before the analysis CLI accepts saved results. The analysis verifies its inputs and emits a sanitized aggregate and a private case-outcome ledger. No program loads a page, fits a model, modifies production logic or applies changed cutoffs. [Recorded resource usage](resources.json)

| Test suite | Passed | Failed |
| --- | ---: | ---: |
| Extension and Node research regressions through Phase 3G | 36 | 0 |
| Offline dataset evaluation regressions | 8 | 0 |
| Python research regressions through Phase 3G | 21 | 0 |
| **Total** | **65** | **0** |

The table includes six new Node and four new Python tests. The end-to-end Phase 3F reproduction, full frozen scorer audit and historical-index validator check ran separately. No backend or browser-facing files changed. The new worktree protocol checkout was checked against the original SHA-256. Gitleaks and a Git file inventory checked history and the proposed changes.

The guarded runs used two logical CPUs at below-normal Windows priority and the existing 4 GB target and 8 GB enforced process-tree limit. Successful frozen reproduction took 6.0 seconds, analysis took 22.73 seconds, and the final validator pass took 2.69 seconds. Peak committed worker-tree memory was **528.8 MiB** during analysis. The highest sampled host CPU across the recorded jobs was **22.04%**. No resource stop fired.
