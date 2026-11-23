# Phase 3A dataset and evaluation

## Sources, rights, and label quality

| Source | Intended use and terms |
| --- | --- |
| **PhiUSIIL (UCI 967), used** | Prasad and Chandra (2024), *PhiUSIIL Phishing URL (Website)*, UCI Machine Learning Repository, DOI `10.1016/j.cose.2023.103545`. UCI publishes the dataset under CC BY 4.0. Attribute the authors and identify our normalization changes. The CSV contains an author label and URL but no per-record observation date. This run uses medium-confidence author labels for a retrospective comparison. The source does not identify an Indian financial target cohort. [UCI dataset and license](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) |
| **PhishTank, candidate for dated positives** | Its terms make defined API data available for commercial use. The official verified/online export documents submission and verification timestamps and optional target metadata. Use authorized export access, record the archive capture time and label availability, and confirm distribution rights before sharing rows. The online-only list is subject to survival and target-reporting biases. [Terms](https://phishtank.org/terms.php) · [Developer guide](https://phishtank.org/developer_info.php) |
| **CERT Polska, candidate replay input** | Its usage policy permits commercial use. The warning list mainly targets Poland. Preserve dated, independently obtained snapshots for replay and keep the existing browser distribution gate. A list used as the detector must not also serve as the ground truth for that comparison. No CERT observations or snapshots were used in the real run. [Warning List and usage policy](https://cert.pl/en/warning-list/) |
| **Chrome UX Report and official institution sites, candidate controls** | Google's CrUX data is CC BY 4.0 with attribution. Origin popularity is a sampling frame. Establish legitimacy and observation time through separate review. The Phase 2B official registry and documented third-party payment and authentication hosts can seed a separately dated hard-negative cohort. [CrUX license](https://developer.chrome.com/docs/crux/methodology#license) · [Official financial registry sources](financial-impersonation.md#verified-registry) |
| **Tranco default and Cloudflare Radar** | Default Tranco uses upstream sources subject to different terms. Radar's API and direct datasets are CC BY-NC 4.0. Excluded from this commercial-development benchmark. Confirm the rights for a specific custom or separately licensed source before using it. [Tranco attribution](https://tranco-list.eu/) · [Cloudflare licensing](https://radar.cloudflare.com/about) |
| **Indian financial phishing** | I4C's public repository is a CAPTCHA-gated complaint lookup. Its disclaimer says the reports are unverified. This review found no commercially cleared, independently adjudicated, dated corpus of Indian bank, wallet, UPI, and merchant impersonation to ingest. For a future cohort, obtain rights and verified timestamps from Indian financial or incident-response partners, or contract for a paid feed with verified target metadata and explicit internal ML rights. OpenPhish's academic program is noncommercial. [I4C repository](https://cybercrime.gov.in/Webform/suspect_search_repository.aspx) · [I4C website suspect reporting](https://cybercrime.gov.in/webform/cyber_suspect.aspx) · [OpenPhish academic use](https://www.openphish.com/academic_use.html) |

The real manifest pins the exact UCI CSV SHA-256, release date, acquisition timestamp, lineage, attribution, and license. It captures **no row observation date**. The synthetic test data uses reserved hostnames and original fixture labels. A manifest accepts only one dataset kind. All snapshots must match that kind. No real rows, URLs, or third-party browser indicators are checked into this branch.

## Pipeline and leakage controls

1. The Node.js evaluator opens local manifest-listed files only. It verifies bounded files against SHA-256, validates format and confidence, and normalizes HTTP(S) destinations with the extension's canonicalization. Invalid observations and labels are counted. The UCI adapter reads only its URL and label columns. Reviewed JSONL input requires independently assigned `kind`, `url`, `label`, `observedAt`, `confidence`, and `cohort` on each row.
2. Canonical identity uses scheme, host, port, and path. The evaluator discards credentials, queries, and fragments before scoring or extracting features. Duplicates converge on the earliest known observation. Contradictory labels on the same canonical identity are excluded. Observations that depend on a query for their label are unsuitable for this representation.
3. Chronological assignment uses two fixed UTC cutoffs and Public Suffix List registrable domains, including private suffixes. A domain is reserved to its first eligible window. Later-window rows from that domain are withheld. Undated data is excluded from this view. The separate retrospective view assigns whole domains using a fixed seed and 70/15/15 hash buckets. Ratios apply to domain assignment and may differ by row count.
4. Reputation is scored only if a pinned snapshot was captured strictly before the label observation and remained valid at that time. The evaluator skips snapshots sharing the adjudicated record's declared source lineage. Undated labels, missing snapshots, and expired snapshots produce abstentions. Declared lineage cannot establish independence between sources with undisclosed upstream overlap.
5. Impersonation runs the existing four-brand browser detector offline. Combined scoring counts an exact reputation alert or an amber impersonation alert. If reputation is unavailable and the hostname yields no advisory, combined scoring abstains. This measures alert quality. It does not replay Chrome rule quotas or measure how many pages were blocked before loading.

Precision, recall, F1 and false-positive rate are calculated on scored records. Decision coverage is scored records divided by all eligible holdout records. Phishing alert coverage is true positives divided by **all** labeled phishing holdout records, including abstentions. A zero denominator is reported as `null`. Low coverage can make conditional metrics unrepresentative.

## Executed benchmarks

### Real UCI PhiUSIIL retrospective domain-disjoint holdout

| Stage | Phishing | Legitimate | Total |
| --- | ---: | ---: | ---: |
| Source | 100,945 | 134,850 | 235,795 |
| Retained | 97,580 | 134,849 | 232,429 |
| Train partition | 67,270 | 94,269 | 161,539 |
| Validation partition | 16,980 | 20,289 | 37,269 |
| Test partition | 13,330 | 20,291 | 33,621 |

Ingestion excluded 790 rows that the extension's URL scheme/host parsing and PSL grouping could not accept, 2,575 duplicate rows, and one conflicting canonical identity. The test partition had 29,745 registrable-domain groups. All 232,429 retained rows lacked dates and were withheld from the chronological split. There were zero verified Indian financial positives in this run.

| Baseline | TP / FP / TN / FN | Precision | Recall | F1 | False-positive rate | Decision coverage | Phishing alert coverage |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Reputation only | 0 / 0 / 0 / 0 | — | — | — | — | 0% | 0% |
| Impersonation only | 0 / 0 / 20,291 / 13,330 | — | 0% | 0% | 0% | 100% | 0% |
| Combined | 0 / 0 / 0 / 0 | — | — | — | — | 0% | 0% |

The impersonation detector issued no alerts on this holdout, so its 0% false-positive rate came with 0% recall. Reputation and combined metrics are undefined because both abstained on every row. A modern feed replayed against undated labels from the 2024 release would not establish historical performance. [Aggregate report](../evaluation/reports/phiusiil-uci-967.json)

### Synthetic chronological and domain-disjoint holdout

Twenty fixture rows yielded 15 retained records (8 phishing, 7 legitimate). The chronological holdout had 10 records (6 phishing, 4 legitimate). One later row for a training domain was withheld.

| Baseline | TP / FP / TN / FN | Precision | Recall | F1 | False-positive rate | Decision coverage | Phishing alert coverage |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Reputation only | 3 / 1 / 2 / 2 | 75.0% | 60.0% | 66.7% | 33.3% | 80.0% | 50.0% |
| Impersonation only | 2 / 1 / 3 / 4 | 66.7% | 33.3% | 44.4% | 25.0% | 100% | 33.3% |
| Combined | 5 / 2 / 1 / 1 | 71.4% | 83.3% | 76.9% | 66.7% | 90.0% | 83.3% |

The fixtures deliberately contain misses, false alerts, and an expired snapshot. The combined run produced four confirmed alerts and three advisory-only alerts. These counts validate the evaluator's decisions. [Aggregate report](../evaluation/reports/synthetic.json)

## Feature interface

`evaluation/features.mjs` emits the ordered `url-lexical-v1` numeric vector. It includes protocol/port flags, IP and IDN indicators, sizes and counts in the host and validated path, and no domain strings or raw text. The CLI's optional feature export emits only feature version, split, label and numeric vector, and refuses undated datasets with no chronologically eligible rows. Account values, query tokens, credentials, URL hashes, hostname IDs, and browsing URLs are absent from the export. Never include labels, detection outputs, source IDs, or split identifiers as classifier inputs. No model was trained.

## Reproduce locally

Use Node.js 24. The benchmarks ran on 24.14.1 and the real report reproduced byte for byte. The only new dependency is pinned `csv-parse` 7.0.3 (MIT) for offline CSV ingestion. The evaluator does no network requests and never resolves or visits indicators.

```powershell
npm ci --prefix evaluation --ignore-scripts
npm test --prefix evaluation
node evaluation/run.mjs --manifest evaluation/manifests/synthetic.json --input-dir evaluation/fixtures
```

For the real benchmark, download the [original ZIP from UCI](https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip) and extract the single `PhiUSIIL_Phishing_URL_Dataset.csv` file to a private folder. The archive SHA-256 is `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a`. The evaluator checks the CSV digest in its manifest. From the repository root, point `$datasetFolder` to that folder.

```powershell
node evaluation/run.mjs --manifest evaluation/manifests/phiusiil-uci-967.json --input-dir $datasetFolder
```

Use optional `--report` for a new aggregate JSON file. Keep input corpora and any feature exports outside the release tree. Use the manifests as templates for additional reviewed batches. If a source requires license acceptance or separate procurement, secure those rights before adding it.

## Phase 3B gate

**NO-GO for ML training.** Obtain independently adjudicated, dated positive and hard-negative data with explicitly authorized training rights. Include Indian financial targets, known legitimate payment handoffs, and a frozen independent threat snapshot history. Measure rule baselines on an untouched chronological holdout before setting an ML target. The global retrospective set and synthetic fixtures cannot establish current India-specific accuracy.
