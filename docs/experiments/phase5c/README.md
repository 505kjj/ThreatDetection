# Phase 5C URL sequence experiments

Run on 2026-11-24 using the private `phase5c-development-v1` snapshot.
The Phase 5B membership replay was exact. The full PhreshPhish publisher
test exclusions revealed overlap in the replayed cohorts, so Phase 5C
refit all five models on a new matched development cohort.

## Acquisition and exact replay

| Source | Release pin | Acquisition |
| --- | --- | --- |
| PhreshPhish by Dalton et al. | v1.0.1 at `eca603e0ecd4f698f8d4d226c088659e72681239` | 498,255 train rows over 56 projected shards. The six requested development columns transferred 37,862,497 bytes and occupied 109,488,700 bytes as private JSONL. |
| PhreshPhish publisher test exclusion service | Same revision, 21 shards | 168,060 publisher IDs. The separate custody worker projected only IDs and URLs. It transferred 12,508,784 bytes on the successful pass and retained 58,450,209 bytes of hash-only exclusions. |
| UCI PhiUSIIL by Prasad and Chandra | UCI dataset 967. CSV SHA-256 `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` | 15,376,007-byte official ZIP with SHA-256 `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a`. The custody worker exported only the 198,808 reconstructed development rows. |

Local experiment storage, the available download caches and Phase 3A–5B
preparation code contained numerical TSVs, manifests and prior reports.
The original two source releases had to be reacquired. PhreshPhish ranges
used the publisher's immutable revision and
[shard checksum list](../../../research/phase5c/source-pins.json).
The runner checks the list against publisher LFS metadata and computes a
separate digest over each retained development projection. Range payload
counts exclude HTTP overhead. Three earlier custody passes also transferred
the projected ranges and stopped on an input stream closure error.
The successful pass used explicit byte framing. Both projections requested
metadata columns only. The publisher confirms that the URL and label
license covers anti-phishing training. [PhreshPhish dataset card](https://huggingface.co/datasets/phreshphish/phreshphish),
[publisher clarification](https://huggingface.co/datasets/phreshphish/phreshphish/discussions/14),
[UCI dataset 967](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset).

The replay recomputed legacy features from the original URLs in source order.
It used the Phase 3A domain split for UCI and the Phase 3D exclusions,
date boundaries and deduplication for PhreshPhish. The replay matched all
four historical TSV SHA-256 values and every ordered feature and label row.
The seed-143 selection recovered the 20,000-row UCI, 20,000-row PhreshPhish
and 20,000-row mixed Phase 5B training samples. The mixed sample included
10,000 rows from each source.

| Phase 5B view | Train sample rows | Validation rows | Train overlap with the full PhreshPhish publisher test | Validation overlap |
| --- | ---: | ---: | ---: | ---: |
| PhreshPhish | 20,000 | 51,059 | 55 | 280 |
| UCI | 20,000 | 37,269 | 579 | 4,079 |

The audit used publisher record ID, domain and lexical-family hashes
available in each legacy export. The UCI legacy figures reflect domain
overlap. This wider custody check motivated the new cohort and rules
out reusing the old models in the matched Phase 5C comparison.

## Cohort and leakage audit

The model pipeline accepted 179,023 PhreshPhish rows and excluded 319,232.
The mutually exclusive reasons were 217,416 publisher-test overlaps,
87,924 other historical or cross-source overlaps, 4,956 invalid URLs or
dates, 8,934 near-duplicate alias variants and two conflicting-label rows.
The exact-duplicate rejection count after the earlier exclusions was zero.
Overlap counts before the mutually exclusive exclusions include 295,435 rows
matching the historical index and 92,939 matching UCI development domains.
UCI development matched 1,160 normalized URLs and 1,291 aliases. Ten
PhreshPhish rows matched a UCI development alias with a conflicting label.

The Phase 5A identity and connected-component logic isolates domain, alias,
lexical family and available campaign IDs. The data supplied no campaign IDs.
The lexical family is a proxy and has no verified campaign coverage.
This check groups protocol, leading `www`, query and fragment variants using
the portable Phase 5A alias. Phase 3C–3F historical cohorts contributed
verified hashes with the granularity available in their exports.
The publisher test exclusion filter also checked record and normalized
URL hashes. The new retrospective development split hashes connected
components into nominal 70/10/10/10 proportions across training, tuning,
calibration and validation. Collection dates remain available for a
future chronological experiment.

| Partition | Rows | Phishing | Legitimate | Domain groups |
| --- | ---: | ---: | ---: | ---: |
| PhreshPhish training pool | 125,422 | 90,137 | 35,285 | 96,958 |
| PhreshPhish tuning | 17,930 | 12,981 | 4,949 | 13,727 |
| PhreshPhish calibration | 17,645 | 12,876 | 4,769 | 13,654 |
| PhreshPhish validation | 18,026 | 12,944 | 5,082 | 13,677 |
| UCI retrospective validation | 32,608 | 13,733 | 18,875 | 28,552 |

The UCI transfer cohort comes from the historical development validation
partition. Exclusions removed 4,226 publisher-test overlaps, one invalid
URL, 132 cross-source aliases, 292 near-duplicate variants and ten
conflicting-label rows. All five models used that same retrospective UCI
cohort. The build verified zero shared domains, lexical families and aliases
across the retained partitions. The canonical outputs occupied 168,905,881
bytes outside Git.

## Indian financial targets

The full PhreshPhish train target review found nine candidates and zero
independently supported Indian financial phishing records. The candidates
were three ambiguous `sbi` tags, two Reserve Bank of India tags, three YES
Securities (India) tags and one National Payments Corporation of India tag.
The separate review expanded the initial cohort report's allowlist, which
matched only the three `sbi` rows. The publisher target names alone give
no independent evidence about a row's phishing intent or country. URL
handling stayed offline throughout the investigation.

The review omitted 366 rows whose target name matches SBI Securities
Co., Ltd. in Tokyo. Official sources confirm the organization names and
NPCI's role operating UPI. [SBI Securities corporate profile](https://www.sbigroup.co.jp/english/company/group/sbisec),
[YES Securities corporate profile](https://yesinvest.in/about-us),
[Reserve Bank of India payments overview](https://www.rbi.org.in/scripts/FS_Overview.aspx?fn=9).

## Matched 20,000-row results

All models trained on the same 10,000 phishing and 10,000 legitimate rows.
PR-AUC uses average precision. Classification metrics and confusion
matrices use threshold 0.5. Validation and UCI retain their measured class
proportions.

### PhreshPhish validation

| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | URL FPR | TN / FP / FN / TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Numerical LR | 0.9726 | 0.9351 | 94.35% | 79.26% | 86.15% | 12.08% | 4468 / 614 / 2685 / 10259 |
| Random forest | 0.9829 | 0.9559 | 95.38% | 86.95% | 90.97% | 10.72% | 4537 / 545 / 1689 / 11255 |
| XGBoost | 0.9837 | 0.9586 | 96.77% | 85.93% | 91.03% | 7.30% | 4711 / 371 / 1821 / 11123 |
| Character TF-IDF LR | 0.9952 | 0.9873 | 98.72% | 91.25% | 94.84% | 3.01% | 4929 / 153 / 1133 / 11811 |
| Character CNN | 0.9933 | 0.9825 | 98.11% | 90.89% | 94.36% | 4.47% | 4855 / 227 / 1179 / 11765 |

### UCI retrospective transfer

| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | URL FPR | TN / FP / FN / TP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Numerical LR | 0.9327 | 0.9051 | 90.33% | 85.81% | 88.01% | 6.68% | 17614 / 1261 / 1949 / 11784 |
| Random forest | 0.8902 | 0.8548 | 52.34% | 87.40% | 65.47% | 57.91% | 7944 / 10931 / 1730 / 12003 |
| XGBoost | 0.9197 | 0.8841 | 74.28% | 85.33% | 79.43% | 21.49% | 14818 / 4057 / 2014 / 11719 |
| Character TF-IDF LR | 0.9936 | 0.9939 | 99.93% | 71.67% | 83.48% | 0.04% | 18868 / 7 / 3890 / 9843 |
| Character CNN | 0.9755 | 0.9739 | 98.13% | 83.08% | 89.98% | 1.15% | 18658 / 217 / 2323 / 11410 |

### Calibrated low false-positive rates

The 1% and 0.1% caps apply to the maximum score per negative domain. The
Phase 3D binomial calibration used 5% risk on the separate PhreshPhish
calibration partition. The observed rates below come from the evaluation
partitions. UCI used the same locked thresholds.

| Model | Evaluation | Recall at 1% cap | Observed domain FPR | Recall at 0.1% cap | Observed domain FPR |
| --- | ---: | ---: | ---: | ---: | ---: |
| Numerical LR | PhreshPhish | 36.67% | 0.49% | 1.26% | 0.00% |
| Numerical LR | UCI | 26.31% | 0.04% | 2.25% | 0.00% |
| Random forest | PhreshPhish | 60.25% | 0.66% | 4.79% | 0.00% |
| Random forest | UCI | 40.24% | 0.02% | 0.36% | 0.00% |
| XGBoost | PhreshPhish | 57.65% | 0.59% | 1.51% | 0.00% |
| XGBoost | UCI | 34.86% | 0.00% | 0.61% | 0.00% |
| Character TF-IDF LR | PhreshPhish | 82.32% | 0.75% | 39.39% | 0.02% |
| Character TF-IDF LR | UCI | 45.53% | 0.00% | 5.80% | 0.00% |
| Character CNN | PhreshPhish | 78.45% | 0.75% | 53.04% | 0.05% |
| Character CNN | UCI | 42.83% | 0.02% | 10.79% | 0.00% |

### Runtime and model size

Latency measures warmed single-row prediction on 300 matched PhreshPhish
validation examples. It includes TF-IDF transformation or CNN tokenization
and uses precomputed numerical features for the three baselines. Peak worker
commit covers the model worker and its subprocesses.

| Model | Fit (s) | Worker wall (s) | Peak commit (MiB) | Model bytes | Median (ms) | p95 (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Numerical LR | 0.02 | 4.56 | 590.2 | 1,192 | 0.202 | 0.461 |
| Random forest | 0.19 | 9.08 | 528.4 | 311,240 | 12.694 | 14.108 |
| XGBoost | 0.20 | 5.98 | 527.1 | 20,794 | 0.477 | 0.709 |
| Character TF-IDF LR | 4.03 | 15.76 | 697.3 | 1,611,706 | 0.798 | 1.296 |
| Character CNN | 38.40 | 49.69 | 859.0 | 24,994 | 0.603 | 1.060 |

The CNN has 5,489 trainable parameters. The 20,000-row
CNN selected epoch 8 on tuning average precision.
Cohort preparation took 27.61 seconds and peaked at 1,382,178,816 committed bytes.

## Learning curves

All five models passed the 1,000-row preflight with development evaluation
partitions capped at 1,000 rows each. The 20,000- and 50,000-row experiments
used nested balanced training views and identical full evaluation sets.
The PhreshPhish training pool contains 35,285 legitimate rows, which caps
balanced training at 70,570. A balanced 100,000-row run is unavailable.

| Model | 20k PhreshPhish PR-AUC | 50k PhreshPhish PR-AUC | 50k UCI PR-AUC | 50k fit (s) | 50k peak commit (MiB) |
| --- | ---: | ---: | ---: | ---: | ---: |
| Numerical LR | 0.9726 | 0.9729 | 0.9314 | 0.06 | 686.2 |
| Random forest | 0.9829 | 0.9835 | 0.9141 | 0.42 | 625.5 |
| XGBoost | 0.9837 | 0.9842 | 0.9250 | 0.20 | 624.5 |
| Character TF-IDF LR | 0.9952 | 0.9962 | 0.9923 | 7.50 | 1011.4 |
| Character CNN | 0.9933 | 0.9951 | 0.9826 | 85.38 | 958.8 |

[Aggregate metrics](metrics.json) include every scale, the cohort fingerprints,
confusion matrices, runtime receipts, thresholds and achieved rates.

## Verification

The run passed 33 Node.js tests across the offline evaluation and Phase 3C–5C
preparation suites, plus 14 Python tests across Phase 3D, 3G, 5B and 5C. The
Phase 5C tests cover ordered recovery verification, custody input framing,
duplicate and conflict handling, group isolation, representation alignment,
the financial allowlist and deterministic CNN checkpoint inference. All
15 model workers completed with two-CPU affinity and zero guard violations.
