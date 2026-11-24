# Phase 5B — Controlled retraining results

Status: nine offline model fits completed. Research only; no model was integrated
into the extension. The results are general URL phishing results and provide no
financial phishing validation.

## Protocol and custody

The script at `research/phase5b/train.py` reuses the Phase 3D loader, source
manifests, URL feature order and estimator configurations. It verified SHA-256
for UCI train/validation and PhreshPhish train/validation, matching 14 shared
URL lexical features (plus the Phase 3D padding column), labels 0=legitimate and
1=phishing, declared row counts and registrable-domain group IDs. IDs and model
files remained under `C:\Users\kj\threat-detection-experiments\phase-5b-v1`.

Each source has a deterministic, domain-deduplicated, balanced 20,000 row
training cohort. The mixed cohort contains 10,000 rows per source. Cross-source
training/evaluation domain intersections were checked and equal zero. The
within-source validations are the existing UCI development validation and
PhreshPhish chronological validation cohorts. Both had prior use in Phase 3A–3D;
therefore these results are reproducible exploratory comparisons, not untouched
final-test estimates. PhreshPhish final test and the Phase 3F archive were not
opened by the script. Phase 3F/3G frozen models and reports were preserved.

The run used the Phase 3D fixed CPU settings: Logistic Regression with
standardization, Random Forest (48 trees, depth 8, leaf 5), and CPU histogram
XGBoost (96 trees, depth 3, learning rate .10). Seed 143. Two-thread limits and
CUDA disablement were applied. This entrypoint records fit wall time, serialized
model size and batch inference time. It did not sample peak process memory or
use the Phase 3D Windows Job Object guard; peak memory is **not measured** and
must be captured before scaling up.

## Results

Values below show PR-AUC / ROC-AUC, then precision, recall, F1 and URL false
positive rate at score 0.5. `UCI→Phresh` means UCI-only training evaluated on
PhreshPhish validation; `Phresh→UCI` is the reverse. Cross-source validation
was previously examined in Phase 3D and is not an independent test.

| Training cohort | Model | Evaluation | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR | Recall @ calibrated 1% / 0.1% domain FPR | Fit s | Size B | Inference ms/URL |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| UCI 20k | Logistic | UCI val | .9959 | .9939 | .9955 | .9648 | .9799 | .0036 | .9872 / .8732 | .06 | 1,202 | .0001 |
| UCI 20k | Forest | UCI val | .9938 | .9930 | .9975 | .9314 | .9634 | .0019 | .9462 / .9233 | .12 | 85,297 | .0007 |
| UCI 20k | XGBoost | UCI val | .9946 | .9936 | .9969 | .9401 | .9677 | .0024 | .9547 / .9333 | .06 | 17,404 | .0004 |
| UCI 20k | Logistic | Phresh val | .3910 | .4760 | .4191 | .9265 | .5771 | .8954 | .9430 / .7427 | .06 | 1,202 | .0001 |
| UCI 20k | Forest | Phresh val | .4333 | .5253 | .4176 | .9206 | .5746 | .8950 | .9292 / .9141 | .12 | 85,297 | .0007 |
| UCI 20k | XGBoost | Phresh val | .6294 | .7058 | .4172 | .9199 | .5741 | .8957 | .9341 / .9165 | .06 | 17,404 | .0004 |
| Phresh 20k | Logistic | Phresh val | .8858 | .9039 | .8580 | .7210 | .7836 | .0832 | .3396 / .0776 | .03 | 1,224 | .0001 |
| Phresh 20k | Forest | Phresh val | .8969 | .9155 | .8880 | .6660 | .7611 | .0586 | .4630 / .1338 | .12 | 278,289 | .0011 |
| Phresh 20k | XGBoost | Phresh val | .9000 | .9195 | .8992 | .6655 | .7649 | .0520 | .4522 / .1367 | .07 | 20,884 | .0004 |
| Mixed 20k | Logistic | Phresh val | .8721 | .8944 | .8384 | .7231 | .7765 | .0972 | .3567 / .0687 | .03 | 1,203 | .0001 |
| Mixed 20k | Forest | Phresh val | .8932 | .9059 | .8762 | .6893 | .7716 | .0679 | .4475 / .1614 | .15 | 256,683 | .0013 |
| Mixed 20k | XGBoost | Phresh val | .8930 | .9081 | .8519 | .7276 | .7849 | .0882 | .4666 / .1114 | .08 | 20,796 | .0004 |

The full precision, recall, F1, URL FPR and confusion matrices at score .5
for all runs are summarized below. Confusion matrix order is TN, FP, FN, TP.

| Cohort / model | UCI validation ROC-AUC; confusion | Phresh validation ROC-AUC; confusion |
|---|---|---|
| UCI Logistic | .9939; 20,215 / 74 / 597 / 16,383 | .4760; 3,148 / 26,938 / 1,542 / 19,431 |
| UCI Forest | .9930; 20,250 / 39 / 1,164 / 15,816 | .5253; 3,160 / 26,926 / 1,666 / 19,307 |
| UCI XGBoost | .9936; 20,240 / 49 / 1,017 / 15,963 | .7058; 3,137 / 26,949 / 1,680 / 19,293 |
| Phresh Logistic | .8791; 19,796 / 493 / 3,992 / 12,988 | .9039; 27,583 / 2,503 / 5,851 / 15,122 |
| Phresh Forest | .8318; 16,848 / 3,441 / 3,633 / 13,347 | .9155; 28,324 / 1,762 / 7,006 / 13,967 |
| Phresh XGBoost | .8623; 19,167 / 1,122 / 3,152 / 13,828 | .9195; 28,522 / 1,564 / 7,016 / 13,957 |
| Mixed Logistic | .9358; 20,179 / 110 / 2,974 / 14,006 | .8944; 27,163 / 2,923 / 5,808 / 15,165 |
| Mixed Forest | .9276; 20,219 / 70 / 3,396 / 13,584 | .9059; 28,044 / 2,042 / 6,516 / 14,457 |
| Mixed XGBoost | .9513; 20,207 / 82 / 2,973 / 14,007 | .9081; 27,433 / 2,653 / 5,712 / 15,261 |

Complete score quantiles and calibrated threshold details remain in private
`results.json`; model files and raw cohorts are not in Git.

## Interpretation

Source transfer is sharply asymmetric. UCI models maintain high UCI validation
scores but have only .391–.629 PR-AUC and about 89.5% URL FPR on PhreshPhish
validation at .5. Phresh-trained models reach .886–.900 PR-AUC on their own
validation; transfer to UCI gives .884–.920 AP. This is evidence of substantial
source/label/distribution shift, not evidence that an individual feature caused
the shift. Mixing data does not consistently improve Phresh validation over
Phresh-only training. XGBoost is the strongest Phresh-only AP candidate here,
but no selected frozen final test was run.

The strict false-alert cutoffs were calibrated on each training source's
validation cohort with a domain-level binomial rule at 5% calibration risk.
Their “recall at 0.1%” values are exploratory and do not establish a production
false-positive guarantee. Validation data have prior experimental exposure.

The report does not include confidence intervals or peak memory. These are
limitations, not zero-valued measurements. Inference is Python `predict_proba`
time on the full validation arrays and excludes URL parsing/browser costs.

## Verification and next phase

- Phase 3G Python tests: 4 passed, 0 failed after installing pinned SciPy.
- Phase 5B data-contract tests: run with the private Phase 5B venv.
- No active detection behavior changed; no ML warnings/blocking or telemetry.
- Phase 5C recommendation: **NO-GO for browser experiments or financial claims**.
  **Conditional GO for additional offline general-phishing work** after capturing
  peak memory under the existing Job Object guard, repeated-seed uncertainty,
  fresh rights-cleared independent cohorts, calibration/error analysis, and
  reconciled full metrics. Character-level CNN belongs to that later phase.

Reproduce the run with the hash-pinned `research/requirements-win-x64-py311.lock`
environment, then invoke the script as shown in `research/phase5b/README.md`.
