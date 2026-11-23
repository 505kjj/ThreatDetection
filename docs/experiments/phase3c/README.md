# Phase 3C cross-dataset phishing research

**Review decision.** Keep ML out of browser warnings and blocking. Use the compact single URL model as the reference for the next research phase. Four-model fusion delivered a small strict-cutoff recall gain and substantially increased inference cost. **The 0.1% false-positive target was not reliably validated.**

## Datasets and licensing

| Dataset | Published size, content and rights | Use in this experiment |
| --- | --- | --- |
| UCI PhiUSIIL | 235,795 rows (100,945 phishing and 134,850 legitimate), CC BY 4.0. URLs and URL/HTML-derived attributes, with no per-row observation dates. The publisher uses 0 for phishing and 1 for legitimate. [UCI source](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | Existing normalized UCI training partition supplied hostname features. Published engineered predictors were excluded. Phase 3B retained 232,429 rows after invalid inputs, 2,575 normalized duplicates and one conflict were removed. |
| PhreshPhish v1.0.1 | 498,255 published train rows and 168,060 test rows (76,800 phishing and 91,260 benign). URLs, dates, author labels and HTML. Authors identify CC BY 4.0 for anti-phishing use and confirm commercial use with attribution and coverage of URL and label data. [Pinned card](https://huggingface.co/datasets/phreshphish/phreshphish/blob/eca603e0ecd4f698f8d4d226c088659e72681239/README.md), [maintainer clarification](https://huggingface.co/datasets/phreshphish/phreshphish/discussions/14) | Used a bounded eight-shard URL/date/label projection from revision `eca603e0ecd4f698f8d4d226c088659e72681239`. HTML was excluded and destination pages were never visited. |
| LegitPhish v2 | Mendeley lists CC BY 4.0 and 101,219 records. The listed class counts, 63,678 legitimate and 37,540 phishing, sum to 101,218. Contains URLs and lexical features. Comparable per-row observation timestamps and page content were unverified. The paper identifies shared sources including UCI, PhishTank and URLhaus. [Dataset](https://data.mendeley.com/datasets/hx4m73v2sf/2), [paper](https://doi.org/10.1016/j.dib.2025.111972), [URLhaus terms](https://urlhaus.abuse.ch/api/) | Audited only. Resolve the count discrepancy, upstream commercial reuse rights and exact/domain overlap before using it as an independent benchmark. |
| CIC-Trap4Phish 2025 | UNB publishes 1,048,576 URL strings (614,656 malicious and 433,918 benign), 20,000 HTML samples (10,000 per class) and QR/document material. UNB asks users to cite the dataset. Observation dates, feed lineage and label comparability with financial phishing were unverified. [Publisher](https://www.unb.ca/cic/datasets/trap4phish2025.html), [UNB dataset policy](https://www.unb.ca/cic/datasets/index.html), [paper](https://arxiv.org/abs/2602.09015) | Audited only. Confirm applicable terms, shared-feed and URL/domain overlap, and label mapping before using the URL subset. |
| Indian financial phishing | I4C offers a suspect lookup based on publicly reported indicators. The service does not establish adjudication, a dated representative cohort or rights for bulk ML reuse. [I4C suspect repository](https://cybercrime.gov.in/Webform/suspect_search_repository.aspx) | No rights-cleared, independently adjudicated Indian financial corpus was verified or used. |

The projection read 45,619 rows from train shards 000, 018, 037 and 055 and test shards 000, 007, 014 and 020. It rejected 445 invalid rows and removed 9,302 rows in 2,553 registrable-domain groups shared with any of the 197,285 UCI groups across train, validation and holdout. Among the rest it removed 231 canonical URL duplicates and found zero conflicting URL labels. The resulting 35,641 rows were independent of UCI's domain groups. Calendar and domain rules excluded a further 3,892 development rows. Retained rows cannot share an exact canonical URL with UCI because the matching domain would already have been excluded. Exact URL overlap before this filter was unmeasured. The projection and feature normalization described here are modifications for this research. [Prasad and Chandra, PhiUSIIL](https://doi.org/10.1016/j.cose.2023.103545), [PhreshPhish dataset paper](https://arxiv.org/abs/2507.10854)

| Retained PhreshPhish cohort | Observation dates | Phishing | Legitimate | Total | Domains |
| --- | --- | ---: | ---: | ---: | ---: |
| Train | 2024-07-02 to 2025-04-23 | 5,713 | 3,469 | 9,182 | 8,450 |
| Calibration | 2025-06-05 to 2025-09-07 | 1,254 | 1,743 | 2,997 | 2,701 |
| External test | 2025-09-08 to 2025-12-16 | 8,569 | 11,001 | 19,570 | 14,005 |

The final cohorts are chronological and domain-disjoint. The pipeline maps labels to 1 for phishing and 0 for legitimate. Private intermediate partitions retain numeric features, labels, domain-group digests and a separate brand indicator. Published [partition metadata and results](research.json) hold counts and SHA-256 digests only, with no raw URLs, host lists, query strings, fragments or HTML.

The original 33,621-row Phase 3B holdout matched its published file digest. Phase 3C used only the domain-group column for overlap exclusion. The original results and opening marker were preserved, and the holdout was never scored or used to fit models or select thresholds for Phase 3C. All four frozen artifacts matched their published digests. [Original Phase 3B report](../phiusiil/README.md)

## Frozen Phase 3B external transfer

All four frozen models were scored on the external PhreshPhish cohort before fitting Phase 3C models. The first five metrics use threshold 0.5. The last column is the external **URL** false-positive rate (FPR) with the original UCI threshold calibrated for **0.1% domain FPR**. Those thresholds failed to transfer.

| Frozen model | AP | Precision | Recall | F1 | URL FPR | URL FPR at old 0.1% domain cutoff |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 0.7819 | 63.67% | 79.22% | 70.59% | 35.21% | 1.90% |
| Random Forest | 0.6108 | 65.07% | 83.10% | 72.99% | 34.75% | 26.11% |
| XGBoost | 0.6358 | 64.99% | 79.32% | 71.44% | 33.29% | 26.69% |
| Small MLP | 0.7753 | 65.08% | 89.40% | 75.33% | 37.37% | 26.30% |

[Frozen external results, confusion counts and cutoffs](frozen-transfer.json)

## Matched training and expanded URL features

The three compact Random Forest regimes each used 5,000 examples, 2,500 per class, with at most one row per domain per class. The equal mixture used half of each class from each source. UCI contributed from its training partition only. All used seed 137, 24 trees, depth 7, a minimum of five rows per leaf and one model/BLAS worker. Fit and scoring took 0.107, 0.086, 0.084 and 0.127 seconds for UCI-only, PhreshPhish-only, mixed and path ablation respectively, excluding data projection and loading.

The baseline uses eight pre-navigation numeric hostname features from `url-lexical-v1`. They cover IP hosts, IDN labels, the hostname and its labels, digits, hyphens, registrant length and subdomain label count. The PhreshPhish ablation adds path length, depth, digit count and percent-escape count. Scheme, port, raw query and fragment, raw identities and dataset IDs were excluded as predictors. Existing official-domain similarity and misleading-subdomain rules supplied a separate financial-brand signal. Keyword, visual impersonation and infrastructure features were not assessed as model inputs.

| Random Forest training data | AP | Precision | Recall | F1 | URL FPR | Recall at calibrated 1% target | Test domain FPR 95% upper limit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| UCI only, hostname | 0.5562 | 65.81% | 72.74% | 69.10% | 29.43% | 0.00% | 0.041% |
| PhreshPhish only, hostname | 0.8212 | 89.67% | 43.87% | 58.91% | 3.94% | 26.08% | 0.997% |
| Mixed, hostname | 0.8082 | 84.21% | 54.15% | 65.91% | 7.91% | 25.00% | 0.662% |
| PhreshPhish only, hostname and path | 0.8715 | 82.97% | 66.67% | 73.93% | 10.66% | 34.53% | 1.087% |

AP is average precision. The first five metrics use threshold 0.5. The final two use a cutoff selected from the calibration cohort only. A domain counts as a false alert if any legitimate URL in it is flagged. One-sided exact binomial bounds assume independent domains. The external test had 7,344 domains with legitimate examples and calibration had 1,699. Even with zero false alerts, a one-sided 95% bound of 0.1% needs at least 2,995 independent legitimate domains. No Phase 3C 0.1% operating point is reported. The path ablation improved AP, while its strict-cutoff upper bound exceeded 1% in the external test.

## Model fusion and agreement

Three stratified, group-disjoint folds of mixed hostname training data produced out-of-fold predictions. These were used to rank the base models, fit per-model sigmoid calibrators and fit a Logistic Regression stack. Scaling was fitted inside the relevant training runs. Out-of-fold AP for Logistic Regression, Random Forest, XGBoost and MLP was 0.8628, 0.8760, 0.8778 and 0.8776. The top two were XGBoost and MLP. Weighted blends use normalized out-of-fold AP above training prevalence. External test scores did not select models, weights or cutoffs.

| Mixed hostname model or fusion | AP | Precision | Recall | F1 | URL FPR | Recall at calibrated 1% target | Test domain FPR 95% upper limit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| XGBoost alone | 0.8053 | 79.82% | 54.46% | 64.75% | 10.73% | 25.43% | 0.906% |
| Two calibrated models, weighted | 0.8189 | 77.41% | 61.99% | 68.85% | 14.09% | 26.51% | 0.739% |
| Majority, 3 of 4 votes | 0.7131 | 83.81% | 54.11% | 65.76% | 8.14% | 0.00% | 0.041% |
| Four calibrated models, weighted | 0.8252 | 76.91% | 62.07% | 68.70% | 14.52% | 27.96% | 0.997% |
| Logistic stack on four models | 0.8213 | 76.72% | 61.89% | 68.51% | 14.63% | 27.38% | 0.997% |

Default cutoffs are 0.5 or three affirmative votes for majority. At the strict cutoff, conservative handling of tied majority scores suppressed all alerts. Base models disagreed on 699–1,945 of 19,570 rows across model pairs. Error correlations ranged from 0.734 to 0.899. Logistic Regression and MLP shared 4,160 errors (correlation 0.899). Forest and XGBoost shared 4,525 (0.888). Four-model weighting added 2.53 percentage points of recall over XGBoost at the calibrated 1% target. [Full confusion counts, thresholds, settings and pairwise results](research.json)

## Architecture and performance

| Candidate | Detection evidence | Runtime scope |
| --- | --- | --- |
| A. Existing rules | Offline financial-brand rules issued zero alerts. Reputation could not be replayed without independent date-valid snapshots. | Real Chromium with the existing extension. Blocking, advisories and outages were verified separately with synthetic integration fixtures. |
| B. Rules plus one URL model | Offline max of brand and XGBoost scores. Results equal the single-model result because brand issued no external alerts. | Python CPU only. |
| C. Rules plus two URL models | Offline results match the two-model blend for the same reason. | Python CPU only. |
| D. Rules plus four-model fusion | Offline results match the four-model weighted blend for the same reason. | Python CPU only. |
| E. Rules, URL model and selective page checks | Detection quality was untested. A toy DOM probe checked field presence and cross-origin action without reading field values. | Synthetic DOM microbenchmark only. |

| Offline Python CPU benchmark | Single XGBoost | Two-model blend | Four-model blend |
| --- | ---: | ---: | ---: |
| Serialized bytes, uncompressed / compressed | 61,324 / 11,774 | 74,051 / 19,555 | 275,587 / 80,464 |
| Median compressed load | 1.648 ms | 5.448 ms | 7.141 ms |
| Warm inference p50 / p95 | 0.360 / 0.593 ms | 1.546 / 2.386 ms | 5.260 / 6.769 ms |
| Mean process CPU per prediction | 0.469 ms | 1.563 ms | 4.844 ms |
| Traced Python peak allocation during 256-row scoring | 9,668 bytes | 49,644 bytes | 63,959 bytes |

Measured on Windows 11 with an Intel Core Ultra 7 155H, about 31.4 GiB RAM, one CPU worker, five in-memory bundle loads and 100 single-row predictions. Traced memory covers Python allocations and does not capture total model RSS. Four-model fusion took 14.6 times the single-model median inference time. Compression was measured using in-memory bundles. Pruning, quantization, distillation and actual browser inference or WASM/ONNX performance are untested.

| Real Chromium, median of three fresh sessions per condition | Extension disabled | Existing extension enabled |
| --- | ---: | ---: |
| Browser launch | 454.4 ms | 420.6 ms |
| Launch to service worker observed ready | — | 425.2 ms |
| Process-tree private memory after local navigation | 311.0 MiB | 339.4 MiB |
| Process-tree cumulative CPU at that snapshot | 4.58 s | 4.75 s |

This browser benchmark used a local fixture with no backend snapshot. The process-tree memory difference was 28.4 MiB in this sample. CPU values are cumulative measurements for the entire Chromium process tree. The small sample and overlapping launch ranges cannot establish extension-only overhead or a startup speedup. The extension-page advisory microbenchmark took 49.6 ms to import modules, 19.93 µs uncached and 3.95 µs with memoization on six repeated fixtures. Node URL feature extraction averaged 12.07 µs. The toy DOM probe took 9.0 µs with the extension and 11.3 µs without it. No browser model ran and these measurements do not establish page-analysis quality or production cache benefits. The loopback benchmark scored a synthetic vector at 0.434 ms direct Python p50 and 1.377 ms local HTTP p50, excluding TLS, WAN and production backend overhead. [Browser measurements](browser.json), [loopback measurements](loopback.json)

## Leakage, limits and next experiments

- Domain exclusion and chronological PhreshPhish splits reduce direct leakage. They do not establish separation by campaign, shared hosting infrastructure or upstream feed lineage. UCI dates are absent. URL paths and source-specific URL granularity can act as label shortcuts. The selected shards and their class prevalence do not establish real-world precision, coverage in India or webpage-content accuracy. The external cohort has now been used for comparison and should not be reused as a future final test.
- Reserve a fresh chronological, domain- and campaign-disjoint test set. Include independently reviewed Indian bank, UPI and wallet phishing alongside normal payment handoffs, authentication redirects and shared-host hard negatives. Confirm use rights and obtain enough independent legitimate domains for the 0.1% target. Replay time-valid reputation snapshots to measure incremental lift over the actual product.
- Keep local reputation and DNR in the first stage and brand rules for unconfirmed advisories. Start the next experiment with one compact URL model in offline or isolated shadow evaluation. If it shows incremental lift, profile lazy initialization and service-worker restarts in a measured browser runtime. Use a bounded hostname cache with model and snapshot versions and expiry. Avoid delaying navigation for a network score.
- Evaluate selective post-navigation DOM booleans only against separately licensed and labeled content and hard negatives. Keep field values, raw text, credentials, cookies and payment details out of the features and off the wire. Consider a two-model blend only if its lift replicates at an acceptable CPU and memory cost.

## Verification and reproduction

The [research setup](../../../research/README.md) pins the Python CPU environment and Node parser dependencies. The [projection lock](../../../research/phase3c/requirements-projection-win-x64-py311.lock) adds Parquet support for Windows x64 CPython 3.11. The [projection script](../../../research/phase3c/project_phresh.py) reads private UCI partitions and writes a new private cohort. The [benchmark script](../../../research/phase3c/benchmark.py) takes that cohort, the existing UCI development input, trusted local frozen artifacts and a new output directory. Check artifacts against their reported SHA-256 before loading. Running the benchmark fits the Phase 3C models again, so it was not executed during closeout.

The closeout checked dataset and frozen-artifact SHA-256 values, partition classes and dates, saved confusion matrices, and the original Phase 3B reports. The published aggregates preserve numeric measurements. The browser report calls its metadata field `playwrightVersion` because 1.65.1 identified the Playwright package.

| Closeout verification | Passed | Failed |
| --- | ---: | ---: |
| Spring Boot clean build and verification | 53 | 0 |
| Chrome extension regression tests | 23 | 0 |
| Phase 3C projection and privacy regression test | 1 | 0 |
| Offline evaluation regression tests | 8 | 0 |
| Python research regression tests | 7 | 0 |
| Full Chromium integration smoke script | 1 | 0 |
| **Total** | **93** | **0** |

The Chromium script verified that host, exact-path and redirect blocks prevented the request from reaching synthetic protected destinations. It also verified authenticated allowlisted telemetry, advisory behavior, one-time exceptions, backend outage and recovery, pause, and rejection of invalid or expired snapshots. See the [backend, extension and Chromium test procedure](../../../README.md) and the [evaluation tests](../../dataset-evaluation.md). No production thresholds, backend policy or browser runtime changed.
