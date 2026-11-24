# Phase 5E website-content intelligence

This offline experiment compares URL and webpage structure on the
same checksummed records. It starts from the verified
[Phase 5D results](https://github.com/505kjj/ThreatDetection/pull/20).

## Independent URL validation

The Phase 5D candidate freeze covers character TF-IDF, CNN and
XGBoost, the 75:25 TF-IDF/XGBoost blend and its original probability
scales, the source-balanced TF-IDF model, and the 20,000-row Transformer
comparator. It records the checkpoint and preprocessing digests and
original development operating thresholds. The source-balanced model
keeps the thresholds calibrated on the separate UCI development view.

A qualifying external evaluation cohort was unavailable. The 2026
PhiShark release has dated observations and specifies restricted
academic access, manual eligibility review and an executed data-use
agreement. This project has no approved copy. PhishTrap has dated
records, proxy negatives based on popularity ranks, and unresolved
upstream permissions for the OpenPhish component. The inspected
Zenodo multimodal release lacked row-level observation dates in its
CSV headers. These sources supply neither a cleared, independent
cohort nor verified financial records for this run.
[PhiShark access policy](https://phishark2026dataset.com/#access),
[PhishTrap dataset card](https://huggingface.co/datasets/saidutta69/PhishTrap),
[OpenPhish terms](https://openphish.com/terms.html),
[Zenodo release](https://zenodo.org/records/23477065).

PhishVN v5 is a rights-cleared URL release. Phase 3E's archive
acquisition failed, so it scored zero PhishVN rows. Phase 5E confirmed
the official 6,697,259-byte file listing. Both the direct open ZIP
and the publisher's aggregate ZIP returned HTTP 403 on download,
with no archive obtained or labels opened. Its other tiers include
broader abuse labels and popularity-list controls.
CompPhish v4 supplies older paired snapshots covering September 2024
through August 2025, which overlaps the PhreshPhish collection period,
and combines PhishTank and OpenPhish positives. PhishIntention's
artifact catalog contains archived research snapshots and earlier
benchmark subsets. It does not supply a new timestamped external
cohort with the required independent negatives. PhreshPhish provided
the paired development coverage used here.
[PhishVN v5](https://data.mendeley.com/datasets/b97hxbxtpd/5),
[PhishVN data article](https://doi.org/10.1016/j.dib.2026.113195),
[CompPhish v4](https://data.mendeley.com/datasets/fmbs4kp9wz/4),
[PhishIntention artifacts](https://sites.google.com/view/phishintention/experiment-structure).

PhreshPhish's publisher test is a same-source test. The earlier Phase
3C and 3D preparation already projected labels from that release and
scored test subsets. The project has no custodian receipt certifying an
untouched partition. Phase 5E used its existing label-free exclusion
receipt and opened zero publisher test labels. The independently
supported Indian financial-positive count remains zero.
[Phase 3D experiment record](../phase3d/README.md)

## Acquisition and safe parsing

The HTML source is the official PhreshPhish v1.0.1 training release at
`eca603e0ecd4f698f8d4d226c088659e72681239`. The publisher releases
the dataset under CC BY 4.0 for anti-phishing research. The run uses
captured pages privately and publishes aggregate results.
[Pinned PhreshPhish release](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eca603e0ecd4f698f8d4d226c088659e72681239/README.md),
[publisher clarification on URLs and labels](https://huggingface.co/datasets/phreshphish/phreshphish/discussions/14).

The projection requests only publisher IDs and HTML, checks the
publisher ID at every decoded row offset against the pinned metadata,
and joins selected records to the Phase 5C partition manifest. It
decodes batches of 16 and processes one document at a time. The probed
shards have one row group and lack a page-offset index, which limits
read-time filtering to the group. The range client bounds every read
and counts payload bytes. Only aggregate counters and per-record
numeric feature rows are written privately.

The inert parse5 worker has no browser, script engine for supplied
content, resource loader or form submission path. It drops value
attributes, comments, script and textarea text, and iframe document
bodies from the parsed representation. A document may use up to 1 MiB
and at most 16,000 element allocations and 128 element levels. Recoverable
malformed documents retain their structural features. Null or empty
documents, apparent interrupted tokens, oversized input and exhausted
structure budgets receive explicit unusable statuses. HTML that ends
at a legal token boundary can still be incomplete.

## Static feature schema and models

The [schema](../../../research/phase5e/feature-schema.json) groups
features into document structure, credential and payment form metadata,
declared resources, and title metadata. An origin is compared in memory
and recorded only as a count. Title text is used for bounded numeric
and lexical indicators. Source, brand labels, capture metadata, parse
errors, availability and elapsed time are absent from model inputs.

These features describe the static snapshot. In a browser they can
describe the current DOM from an extension content script. Declared
cross-origin actions and iframe origins do not establish where requests
ultimately go, or whether a page is malicious. Runtime event handlers,
CSS-computed visibility, shadow trees and cross-origin frame contents
require separately scoped observations.

The matched comparison refits URL TF-IDF and lexical XGBoost and
applies the Phase 5D 75:25 recipe using probability scales fitted on
the matched tuning view. The frozen Phase 5D artifacts remain separate.
The DOM models are scaled logistic regression, random forest and XGBoost.
The combined XGBoost appends 14 URL features to the DOM vector. Four
ablations each remove one DOM feature group. Independent numeric
calibration uses the existing domain-level threshold policy. Confidence
intervals reuse domain resampling and exact domain-FPR bounds from
Phase 5D. The largest usable balanced train view preserves original
group-disjoint tuning, calibration and evaluation partitions.

The [runbook](../../../research/phase5e/README.md) lists commands and
the Windows Job Object resource controls.

## Acquisition preflight

Three development shards supplied 4,056 exact canonical matches.
Of these, 3,950 were usable, including 178 recovered after parser
diagnostics. The worker rejected 105 documents over the size cap and
one over the structural bounds. The final pilot transferred 582,235,159
bytes, took 211.36 seconds and peaked at 2,234,064,896 committed bytes.
Earlier pilot attempts exposed an HTML parser location-tracking issue
when text nodes were stripped. Empty placeholders corrected that
issue without retaining page text. The initial comparison also exposed
a scoring-wrapper mismatch between canonical rows and model-ready
inputs. The successful comparison converted every URL view before
scoring. Both corrections preceded scaling.

An optimistic shard inventory sorted by eligible legitimate training
records per byte needs about 7.49 GB across 17 shards for a balanced
20,000-row sample. Reaching 50,000 would require about 19.05 GB across
40 shards even if every eligible document passed preprocessing. The
estimated 50,000-row transfer exceeds the bounded 14 GB scale allocation
and covers about 70% of the publisher's compressed training corpus.
The experiment prioritizes the 20,000-row comparison under that
allocation. Derived output storage is much smaller than transfer.

Shards are prioritized by the number of eligible legitimate training
records per compressed byte. The usable snapshot gate can also have
different acceptance rates by class. Each matched comparison shares
the same record IDs across models and reports the retained coverage.
The two scales have different validation memberships, so their scores
do not measure a learning curve or establish performance on the full
publisher distribution.

## Matched coverage

The 20,000-row experiment used 17 publisher training shards, 7,490,146,249 projected payload bytes and 41,668,217 bytes of derived storage. It aligned 50,962 canonical records. The successful projection receipts contain 49,901 usable documents. Status counts are recorded by partition and class in the aggregate results. The worker rejected 0 missing, 1,056 oversized, 0 apparently truncated, 5 structure-limited and 0 other parser-error rows. 2,049 usable documents produced recoverable parser diagnostics. The published cutoff and dates use release metadata.

| Partition | Pilot usable | Pilot phishing | 20k usable | 20k phishing |
| --- | --- | --- | --- | --- |
| train | 2,782 | 1,893 | 34,991 | 24,945 |
| tuning | 379 | 265 | 4,969 | 3,589 |
| calibration | 403 | 275 | 4,930 | 3,614 |
| validation | 386 | 267 | 5,011 | 3,655 |

The train pool was reduced to a class-balanced 1,000- or 20,000-row sample in each run. The 20k validation set had 1,321 rows sharing their entire numeric DOM vector with a sampled train row. That check identifies representation collisions and does not establish byte-identical HTML or documented campaign overlap.

### Unseen DOM-vector sensitivity

Excluding the 1,321 validation rows that shared a complete numeric DOM vector with training retained 3,690 rows, including 2,352 phishing labels. At the separately calibrated 1% target, URL TF-IDF recalled 80.99% at 0.89% observed domain FPR. The URL + DOM blend recalled 83.08% at 0.81% observed domain FPR. The paired recall difference was +2.08 percentage points, with a domain-resampled 95% interval of -0.53 to +4.41 points. This is a dependence sensitivity analysis within the same publisher snapshot, not independent validation.

## Measured model comparison

The pilot URL + DOM XGBoost reached 0.9927 PR-AUC on 386 development validation rows. Its calibration partition was too small to estimate the 1% domain-FPR cutoff. The larger comparison below uses the shared checksummed evaluation IDs. Point classification metrics use 0.5. The last column reports recall and observed domain FPR at the threshold fitted in the separate calibration partition.

| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | URL FPR | Domain FPR | 1% target recall / FPR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| URL TF-IDF | 0.9955 | 0.9874 | 98.82% | 91.44% | 94.98% | 2.95% | 3.20% | 83.12% / 0.88% |
| URL XGBoost | 0.9834 | 0.9555 | 96.69% | 86.27% | 91.18% | 7.96% | 8.65% | 60.82% / 0.80% |
| URL blend | 0.9955 | 0.9879 | 96.34% | 97.32% | 96.83% | 9.96% | 10.57% | 82.30% / 0.80% |
| DOM logistic regression | 0.9599 | 0.9170 | 92.29% | 92.01% | 92.15% | 20.72% | 19.54% | 9.19% / 0.48% |
| DOM random forest | 0.9916 | 0.9778 | 97.38% | 91.41% | 94.30% | 6.64% | 6.73% | 59.59% / 0.24% |
| DOM XGBoost | 0.9910 | 0.9766 | 96.79% | 92.45% | 94.57% | 8.26% | 8.49% | 55.81% / 0.24% |
| URL + DOM XGBoost | 0.9955 | 0.9883 | 98.08% | 93.43% | 95.70% | 4.94% | 5.36% | 79.97% / 0.64% |
| URL TF-IDF + DOM blend | 0.9973 | 0.9926 | 96.73% | 97.98% | 97.35% | 8.92% | 9.61% | 86.16% / 0.80% |

PR-AUC uses average precision. The aggregate results include all confusion matrices, domain-block confidence intervals and exact domain-FPR confidence bounds.

### DOM ablation

| Removed group | PR-AUC | Change | 1% target recall / domain FPR |
| --- | --- | --- | --- |
| structure | 0.9891 | -0.0020 | 48.13% / 0.24% |
| credential | 0.9887 | -0.0023 | 50.23% / 0.56% |
| resources | 0.9817 | -0.0093 | 45.28% / 0.24% |
| title | 0.9901 | -0.0009 | 48.02% / 0.16% |

### Incremental detection

| URL reference | Content candidate | Additional phishing caught | Phishing lost | Net recall change | Paired 95% CI (pp) |
| --- | --- | --- | --- | --- | --- |
| URL TF-IDF | DOM XGBoost | 150 | 1148 | -27.31 pp | -29.74 to -24.88 |
| URL TF-IDF | URL + DOM XGBoost | 235 | 350 | -3.15 pp | -5.65 to -1.05 |
| URL TF-IDF | URL TF-IDF + DOM blend | 200 | 89 | +3.04 pp | +0.84 to +4.65 |
| URL XGBoost | DOM XGBoost | 604 | 787 | -5.01 pp | -8.02 to -1.64 |
| URL XGBoost | URL + DOM XGBoost | 790 | 90 | +19.15 pp | +16.56 to +22.09 |
| URL XGBoost | URL TF-IDF + DOM blend | 1007 | 81 | +25.34 pp | +22.40 to +28.02 |
| URL blend | DOM XGBoost | 156 | 1124 | -26.48 pp | -29.04 to -24.28 |
| URL blend | URL + DOM XGBoost | 208 | 293 | -2.33 pp | -4.80 to -0.13 |
| URL blend | URL TF-IDF + DOM blend | 240 | 99 | +3.86 pp | +1.52 to +5.70 |

## Browser feasibility and operational controls

An isolated Chromium 159.0.8154.6 fixture extension used the current MV3 `document_idle` content-script timing. All seven synthetic pages returned identical vectors from the native DOM and the offline parser. The dynamic fixture changed from zero to one password field after a trusted local script inserted a form. The static capture continued to represent the earlier state. Synthetic fixture requests were fulfilled in-process, and no external resource request was allowed.

| Fabricated control | Pilot DOM XGBoost score | 20k DOM XGBoost score | 20k alert at 1% target |
| --- | --- | --- | --- |
| banking-login | 0.8398 | 0.9697 | true |
| payment-gateway | 0.9620 | 0.9715 | true |
| oauth-sso | 0.9396 | 0.9826 | true |
| cross-origin-form | 0.9376 | 0.9810 | true |
| ordinary-password | 0.8624 | 0.9679 | true |
| embedded-payment-auth | 0.4924 | 0.9367 | true |
| dynamic-login | 0.8563 | 0.9440 | true |
| dynamic-login-materialized | 0.8063 | 0.9679 | true |

The parser-to-model replay of these small controls with the 20k checkpoint measured 1.099 ms median and 2.897 ms p95 across 300 analyses. These fixtures exercise ordinary banking, payment and authentication patterns as functional controls. They cannot establish population false-positive performance. The aggregate results also contain released-benign validation strata with password fields, external form actions, payment metadata and frames.

## Resource benchmarks

Latency uses warmed single-row predictions. The captured-page end-to-end estimate adds the measured parser round trip for each validation row to its timed representation and model prediction. It excludes publisher transfer and URL lexical precomputation. The fabricated-control replay above measures a contiguous parse-to-score call.

| Model | Fit seconds | Saved bytes | Parse ms | Extract ms | Inference ms | Paired end-to-end ms |
| --- | --- | --- | --- | --- | --- | --- |
| URL TF-IDF | 6.14 | 1,610,474 | — | — | 1.159 / 1.517 | — |
| URL XGBoost | 0.18 | 20,775 | — | — | 0.462 / 0.687 | — |
| DOM logistic regression | 0.08 | 1,831 | 3.718 / 31.154 | 0.230 / 3.752 | 0.462 / 0.667 | 6.420 / 57.156 |
| DOM random forest | 0.77 | 343,961 | 3.718 / 31.154 | 0.230 / 3.752 | 15.574 / 21.856 | 21.787 / 72.919 |
| DOM XGBoost | 0.30 | 21,433 | 3.718 / 31.154 | 0.230 / 3.752 | 0.471 / 0.610 | 6.381 / 57.188 |
| URL + DOM XGBoost | 0.46 | 21,385 | 3.718 / 31.154 | 0.230 / 3.752 | 0.502 / 0.689 | 6.456 / 57.209 |
| URL blend | 0.75 | 1,631,249 | — | — | 2.425 / 3.156 | — |
| URL TF-IDF + DOM blend | 0.78 | 1,631,907 | 3.718 / 31.154 | 0.230 / 3.752 | 2.390 / 2.917 | 8.515 / 59.452 |

Latency columns show median / p95. Blend sizes sum their required checkpoints.

| Guarded worker | Elapsed seconds | Peak committed MiB | CPU affinity |
| --- | --- | --- | --- |
| projectionPilot | 211.36 | 2130.6 | 2 |
| modelPilot | 21.28 | 843.3 | 2 |
| projection20k | 2331.19 | 2936.6 | 2 |
| model20k | 43.67 | 1117.8 | 2 |
| browser | 6.23 | 526.2 | 2 |
| controls | 8.22 | 360.8 | 2 |
| controls20k | 8.25 | 361.5 | 2 |
| sensitivity | 14.91 | 885.4 | 2 |
| freeze | 7.11 | 227.9 | 2 |
| pythonTests | 20.98 | 99.6 | 2 |

The Node.js and extension regression checks passed 43 tests. The guarded Python suite passed four tests. The pinned parser dependency audit reported zero known vulnerabilities.

## Decision and Phase 5F handoff

This is a research-only result, not an approval to deploy static content scoring or browser alerts. The matched retrospective comparison is same-source and same-snapshot, no independently cleared URL evaluation cohort was available, and all eight fabricated benign banking, payment and authentication controls alerted at the 1% domain-FPR operating point. The static DOM blend may remain an offline research comparator, but it must not affect extension blocking, warnings or telemetry.

Phase 5F can reopen the decision only with a custodian-scored independent, timestamped cohort, documented domain and family exclusions, a rights-cleared benign financial and authentication set, and operational false-positive evaluation against those benign controls. The present data do not support an India-specific efficacy claim.

[Aggregate results](results.json) include the source receipts, structural control strata, confidence intervals and matched model fingerprints.
