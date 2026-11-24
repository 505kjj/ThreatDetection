# Phase 5A — Financial Phishing Dataset Improvement

Status: **completed as a data-readiness phase; NO-GO for financial ML claims**.

This phase adds an offline, provenance-first preparation pipeline. It does not
train models, change production detection, visit URLs, or open the protected
Phase 3B/3F holdouts. Private inputs and generated reports are stored under
`C:\Users\kj\threat-detection-experiments\phase-5a-v1` and are intentionally
outside Git.

## What was actually acquired

No suitable, independently verified Indian financial-phishing corpus was
acquired in this phase. A single, non-retrying request to the PhishTank online
feed on 2026-11-24 returned HTTP 429 and zero bytes; no records were imported.
OpenPhish academic data is restricted to accredited, non-commercial research
and cannot be treated as a commercial product feed without written permission.
APWG eCX access requires membership. CERT-In provides a contact route for
collaboration, but no bulk feed was provided to this project. The acquisition
status and licensing dispositions are recorded in
[`source-audit.md`](source-audit.md).

The existing UCI PhiUSIIL and PhreshPhish data remain useful licensed **general
phishing** research sources, but their preserved manifests do not establish
Indian financial targets, campaign IDs, or verification timestamps for every
row. The 2,000-row Phase 3F archive is a previously used general-phishing
evaluation record, not an independent financial corpus, and is not reused for
training or tuning.

## Reusable implementation

- [`research/phase5a/prepare.mjs`](../../../research/phase5a/prepare.mjs) validates manifests and row evidence, normalizes URLs through the existing PSL-aware feature extractor, records missing metadata, applies historical-overlap checks, and creates natural/balanced views.
- [`research/phase5a/profile.mjs`](../../../research/phase5a/profile.mjs) produces class, domain/IP, TLD, timestamp, campaign and feature-distribution summaries.
- [`research/phase5a/run.mjs`](../../../research/phase5a/run.mjs) pins input checksums, writes restrictive private files, and custody-separates the final test profile.
- [`research/phase5a/compare.mjs`](../../../research/phase5a/compare.mjs) reuses the pinned Phase 3B/3D development exports without reading raw final-test rows.
- [`research/phase5a/control-inventory.mjs`](../../../research/phase5a/control-inventory.mjs) records a small RBI-referenced Indian financial control set without polling the listed sites.
- [`research/phase5a/prepare.test.mjs`](../../../research/phase5a/prepare.test.mjs) covers deterministic partitions, transitive overlap, duplicate/conflict quarantine, chronology, rights, target corroboration and filesystem protections.

The only code change outside Phase 5A is the export of reusable helpers from
[`research/phase3g/validate.mjs`](../../../research/phase3g/validate.mjs); its
validation behavior is unchanged.

## Data and licensing inventory

| Source | Evidence available to this project | Phase 5A disposition |
| --- | --- | --- |
| UCI PhiUSIIL (UCI dataset 967) | Existing pinned development exports: 161,539 train and 37,269 validation rows; CC BY 4.0 source record | Historical general-phishing reference only; no financial labels inferred |
| PhreshPhish | Existing pinned train/validation exports: 160,016 and 51,059 rows; source card identifies CC BY 4.0 | Historical general-phishing reference only; HTML excluded |
| Phase 3F archived cohort | 2,000 previously evaluated general-phishing URLs; no verified financial positives | Protected historical evaluation; excluded from training and model selection |
| RBI official bank listings | Six public URL references in [`official-control-sources.json`](official-control-sources.json) | Legitimate negative-control metadata only; no site visits |
| PhishTank | Feed documentation reviewed; live request returned HTTP 429/zero bytes | No records used; retry/access automation not added |
| OpenPhish | Academic/non-commercial terms reviewed | Not used for commercial claims; written permission required |
| APWG / CERT-In | Membership/contact routes reviewed; no feed obtained | Acquisition remains blocked pending authorization |

The six RBI-referenced controls are not a phishing dataset. They are an
auditable negative-control inventory: 6 candidate rows, 6 usable rows, 6
registrable domains, all classified legitimate by official-control evidence,
with campaign IDs correctly recorded as missing.

## Cleaning and split policy

1. Parse only `http`/`https` URLs; reject credentials, malformed hosts and
   invalid labels. Query strings and fragments are never exported.
2. Preserve source, observation date, independent verification date, evidence
   method, optional campaign and optional financial target. Missing values are
   counted, never fabricated.
3. Group by PSL-derived registrable domain, normalized URL alias, lexical family
   and documented campaign using a transitive union-find. Conflicting labels,
   exact duplicates and historical overlaps are quarantined.
4. Apply explicit UTC-day boundaries: dates before `validationFrom` are train,
   dates before `testFrom` are validation, and later dates are the final test.
   A verification event must precede the next split boundary. Training rows
   require both the source and independent verification source to permit model
   training.
5. Emit natural-prevalence and deterministic balanced ID views. The final test
   output is written separately and marked custody-separated; it is not used by
   this phase for selection.

## Measured mismatch retained from Phase 3G

The existing aggregate analysis, reused by `compare.mjs`, contains 2,000
archived phishing URLs. Their median path length is 31 and median path depth is
3, while the frozen Random Forest positive training sample has median path
length/depth of 0. The archived-vs-training KS distances are 0.684 (path
length) and 0.716 (path depth); the frozen forest median score falls from 0.569
on calibration phishing to 0.184 on the archive. These are measurable shifts,
not proof that age caused the failure. The Phase 5A comparison also confirms
that the four prior development projections are domain-disjoint with 342,342
combined grouping keys. TLD, campaign and verification-time comparisons are
not available in the prior numeric exports and are reported as unavailable.

## Reproduction evidence

Executed on branch `feature/phase-5a-ml-dataset-improvement` from base commit
`506e9ef5c1620021736e95c06bfca5a7595ca7ed`:

- Phase 5A Node tests: **7 passed, 0 failed**.
- Combined evaluation, Phase 3G and Phase 5A Node suites: **21 passed, 0 failed**.
- Existing extension regression suite: **23 passed, 0 failed**.
- Existing Spring Boot suite: **53 passed, 0 failed** (Surefire reports).
- Existing Phase 3G Python tests were attempted but could not import because
  SciPy is not installed in the execution environment; no Python assertions
  were run.
- Synthetic fixture: **14 input rows, 8 usable rows**; missing-date, late-
  verification, cross-window and normalized-duplicate cases were quarantined.
- RBI control inventory: **6 candidate / 6 usable / 6 domains**.
- Historical development comparison: **342,342 combined distinct grouping keys**
  across the four pinned train/validation projections.
- No model training command was run and no ML warning/blocking code changed.

## Phase 5B decision

**NO-GO for financial-phishing model training or commercial financial coverage.**
The required independently verified financial-phishing positives were not
acquired, and the six official controls are negative controls only.

**Conditional GO for a clearly labelled nonfinancial research experiment** using
the already licensed UCI/PhreshPhish general-phishing data, with the protected
test policy above, strict false-positive reporting, and no production or browser
blocking integration. Phase 5B should not claim Indian financial performance
until an authorized, independently verified cohort contains target evidence,
timestamps and deduplicated campaigns.

## Planned Phase 5B protocol (not executed here)

Use the frozen feature schema `url-lexical-v1` first for Logistic Regression,
Random Forest and XGBoost baselines, then evaluate character-level features as a
separate experiment. Fit preprocessing within each training fold, group folds
by registrable domain/campaign, preserve natural and balanced views, and report
precision, recall, F1, PR-AUC, ROC-AUC, false-positive rate, calibration,
inference latency and model size. Resource limits and software versions must be
recorded before training. Do not enable ML decisions in the extension.
