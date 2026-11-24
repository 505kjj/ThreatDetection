# Phase 5F adaptive multimodal fusion

**Phase 5G decision: NO-GO for deployment.** Fixed fusion improved recall in one grouped retrospective experiment. The adaptive and selectively routed variants did not improve over the stronger standalone TF-IDF comparator, and the project still lacks independently scored positives and rights-cleared authentication and payment captures. Browser warnings, blocking, and production shadow testing remain disabled.

## Frozen Phase 5E replay

The run verified all 12 Phase 5E model checkpoints or fusion recipes, the 20,000-row training membership, the exact 5,011-row validation membership, and the separate calibration cuts. Reported evaluation values replayed within an absolute tolerance of `1e-7`. The Phase 5E URL+DOM blend recalled 86.16% at 0.80% observed domain FPR, versus 83.12% recall at 0.88% domain FPR for its TF-IDF baseline. On the 3,690 unseen-vector rows, the recall gain fell to 2.08 percentage points, with a domain-resampled 95% interval of −0.53 to +4.41 points. [Phase 5E report](../phase5e/README.md)

The 1,321 validation matches represented 529 exact vectors across 1,067 validation domains. They comprised 1,303 phishing and 18 benign rows. Only same-label training peers appeared for 1,282 matches, while 39 had an opposite-label peer. The most frequent matching vector appeared 211 times in sampled training. Among the matched validation rows, 292 had at most 20 elements and 329 had password fields. Equality of this compact representation establishes neither raw HTML equality nor a verified campaign identity.

## Structural grouping and calibration

The new split joins existing domain, URL alias, exact URL and campaign-family exclusions with numeric template proxies. A proxy uses the non-title DOM features, with small counts exact, larger counts logarithmically binned, and link ratios in eighths. Near-neighbor edges require one adjacent bin on a size axis (elements, depth, links or scripts), with all other coordinates fixed and nonzero bins on both sides. Transitive components stay in one view. Conflicts are quarantined in priority order of validation, calibration, fusion fitting and base training, preserving the original validation membership.

This yielded 18,022 components from 21,356 numeric template signatures. The largest component held 17,391 rows, so the proxy can merge unrelated pages through chains. Quarantine removed 20,160 positive and 403 negative rows from the eligible training pool. The grouped experiment fit on 9,570 balanced training rows, with 2,109 fusion-fitting rows, 2,104 calibration rows, and 5,011 validation rows. URL and content models were refit on the same grouped memberships. Reported uncertainty includes resampling by original domain and by structural component.

All grouped candidates generated six alerts among 1,200 benign calibration domains at the 1% target. Their validation FPRs differ. The one-sided calibration policy needs at least 2,995 benign domains even with zero false alerts for the 0.1% target. That point is unsupported here. The tuning-selected URL blend had higher tuning recall, while standalone TF-IDF had higher validation recall. Both serve as documented comparators, with no threshold changes on validation. The domain-level binomial bounds assume separate domains are independent, which shared capture and template properties can weaken.

## Grouped model comparison

PR-AUC is average precision. Precision, recall, F1 and FPR below use the locked 1% target threshold. The last column counts alerts on the eight historical diagnostic fixtures at that threshold. The [aggregate receipt](results.json) records each fixture, fixed-threshold metrics, domain and URL confidence intervals, calibration error, disagreement, model size and latency.

| Model | PR-AUC | ROC-AUC | Recall | Domain FPR | Fixture alerts |
| --- | ---: | ---: | ---: | ---: | ---: |
| TF-IDF | 0.9931 | 0.9815 | 76.55% | 0.96% | 0/8 |
| URL XGBoost | 0.9781 | 0.9432 | 40.03% | 0.40% | 0/8 |
| URL blend | 0.9934 | 0.9826 | 68.67% | 0.48% | 0/8 |
| DOM full | 0.9705 | 0.9434 | 32.75% | 1.52% | 8/8 |
| DOM reduced | 0.9567 | 0.9175 | 7.06% | 0.48% | 5/8 |
| DOM regularized | 0.9752 | 0.9539 | 26.62% | 1.04% | 8/8 |
| DOM context | 0.9768 | 0.9555 | 32.59% | 1.36% | 8/8 |
| DOM context with benign reweighting | 0.9800 | 0.9603 | 25.03% | 0.72% | 7/8 |
| Fixed URL+DOM blend | 0.9959 | 0.9892 | 81.50% | 0.88% | 0/8 |
| Logistic stack | 0.9964 | 0.9903 | 80.36% | 1.04% | 1/8 |
| Adaptive fusion | 0.9947 | 0.9866 | 76.53% | 0.88% | 0/8 |
| Selectively routed adaptive fusion | 0.9930 | 0.9817 | 76.53% | 0.88% | 0/8 |

Fixed fusion increased recall by 4.95 points over TF-IDF, with 95% intervals of +3.74 to +6.09 points by domain and +2.95 to +6.82 by structural component. Its precision was 99.63%, F1 was 89.66% and URL FPR was 0.81%. TF-IDF measured 99.57%, 86.56% and 0.88%, respectively. Fixed fusion's observed domain FPR interval was 0.44%–1.57%. Adaptive and selective fusion both differed from TF-IDF by −0.03 points, with a domain interval of −1.10 to +0.95. Logistic stacking improved calibration (Brier 0.0326, ECE 0.0259) but its component-resampled recall interval crossed zero and it had the higher observed domain FPR.

The fixed blend uses 75% tuning-calibrated TF-IDF and 25% tuning-calibrated weighted DOM. The regularized stack uses the component log-odds, an authentication-context indicator and its interaction with DOM log-odds. Adaptive fusion caps DOM weight at 0.15 in authentication-like contexts and 0.35 otherwise. It reduces it on major score disagreement and suppresses it when two numeric features exceed their training bounds. All adaptive and fused scores fall back to calibrated URL evidence for missing content. Fixed, stacked and gated candidates use development predictions for the fusion scales. The eight fixtures were scored after fitting and cutoff selection.

## Benign controls and false-positive analysis

The fixture score matrix covers six upstream frozen URL candidates, all 12 Phase 5E candidates and all 12 grouped candidates. At the Phase 5E 1% point, TF-IDF, URL XGBoost, the URL-only blend and URL+DOM XGBoost each alerted on zero fixtures. The URL+DOM blend alerted on one, DOM logistic regression on three, and the DOM forest and DOM XGBoost on all eight. Upstream source-balanced TF-IDF alerted on all eight at its frozen UCI-calibrated 1% point. These are diagnostic checks using reserved `.test` origins and the same synthetic markup as Phase 5E.

On the original benign validation strata at score 0.5, Phase 5E DOM XGBoost alerted on 33 of 224 password rows, 8 of 163 cross-origin-action rows, 12 of 599 external-frame rows, 48 of 1,202 rows with external links, 107 of 1,351 rows with scripts, and all seven small DOMs. Removing credentials in a separately fitted ablation lowered cross-origin-action alerts from 8 to 5 and small-DOM alerts from 7 to 5, but raised password-row alerts from 33 to 37. Removing the resource group raised external-frame alerts from 12 to 29. At the calibrated operating point, the credential ablation reduced diagnostic fixture alerts from eight to three. These ablations change associations across features and how the model ranks pages.

The controlled Phase 5F reweighting increased the influence of 2,820 published-benign training records with password, payment, external-action or external-frame features, preserving the same total negative class weight. Relative to the same regularized context model, reweighting decreased observed domain FPR from 1.36% to 0.72%, diagnostic alerts from eight to seven and recall from 32.59% to 25.03%. At the calibrated points, weighted DOM alerted on 1/224 password, 0/163 cross-origin-form, and 1/599 external-frame rows. Fixed fusion alerted on 2/224, 0/163 and 2/599 respectively. One benign payment-metadata row and five benign meta-refresh rows provide too little support for operational claims.

Aggregate TreeSHAP on the nine weighted-DOM false-positive URLs found the largest mean positive log-odds contributions from script count (+1.09), link count (+0.83) and external link share (+0.39). Feature contributions on the comparison rows had different signs. TF-IDF contribution totals are published by n-gram length, with literal n-grams omitted. The stack coefficient on DOM log-odds fell from 0.874 to 0.249 in authentication-like contexts. These are model associations. The saved representations describe static declarations and counts, so actual redirects, processor ownership, runtime behavior and measurement artifacts cannot be attributed from them. Structural collisions and DOM-size effects motivate a capture-artifact check with externally sourced pages. Both labels in this run share one publisher, preventing a controlled cross-source balancing test.

## Selective processing and abstention

A URL-only gate opened within 0.20 of a tuning-derived score center. It routed 3,245 of 5,011 matched rows (64.76%) to the adaptive stage, with zero prediction differences at the locked 1% point between always-on and selective adaptive fusion. Median and p95 processing estimates fell from 7.79/59.32 ms to 4.35/27.70 ms. TF-IDF alone took 1.27/1.79 ms, and fixed fusion took 7.78/52.54 ms. Estimates add each record’s original parser round trip only when content is routed and include measured single-row model prediction. They exclude page acquisition and URL feature precomputation. The aggregate validates equivalence between bulk scores and the timed conditional path.

The inclusive analysis includes 106 oversized documents and one structure-limit record. Of 3,277 routed requests, 32 had unavailable content. With abstention for these rows, overall recall was 75.62%, coverage 99.37%, and observed domain FPR 0.84%. Adding a 0.025 uncertainty buffer reduced recall to 70.72% and domain FPR to 0.54%, with 93.49% coverage. At a 0.05 buffer, coverage was 84.21%, recall 60.91%, and domain FPR 0.31%. Abstained phishing contributes to missed detections. These scores do not represent population prevalence or real-world coverage.

The guarded worker ran for 53.25 seconds with two logical CPUs and 1,181,913,088 peak committed bytes. The fixed, stacked, adaptive and selective candidates each require 1,571,262 bytes of base checkpoints, plus the shared 513-byte fusion artifact. [Resource receipt](resources.json)

Verification passed 43 JavaScript tests and 15 guarded Python tests across Phases 5D–5F. The locked parser dependency audit reported zero known vulnerabilities.

## External evidence and follow-up

The checksum-verified PhishVN v5 open URL archive was acquired and held sealed. The candidate provider inventory covers all eight requested benign categories. A custodian must still verify label eligibility, chronology and overlap and score the frozen models. Authorized page captures are also needed to measure false positives on independently verified banking, payment and authentication traffic. The current no-deployment decision remains in force. [Acquisition and custody record](independent-data.md)
