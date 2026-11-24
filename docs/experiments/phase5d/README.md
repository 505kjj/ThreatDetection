# Phase 5D Transformer and generalization

Exploratory offline development research based on the exact
[Phase 5C commit](https://github.com/505kjj/ThreatDetection/pull/19/commits/c7beefc8b8421dfd42b18e48cbd47fbc4c0831be).
The matched validation and UCI results are retrospective. The
chronological experiment rearranges the same development observations
under a newly frozen protocol.

## Experimental protocol

The Transformer uses the Phase 5C character vocabulary, an 80-character
prefix, 24-wide trainable character and position embeddings, a learned
classification token, and two batch-first encoder layers. Each layer
uses four attention heads, a 48-wide GELU feed-forward sublayer and
0.15 dropout. The classification token attends to nonpadding input;
the binary head uses its contextual representation. The 1,000-row
preflight compared AdamW learning rates of 0.001 and 0.003 using two
epochs per candidate. Larger runs used the winning rate, seed 143,
batch size 192 and a five-epoch cap with patience two on tuning
average precision. The tuning view uses the first 4,096 stable-ranked
rows for larger fits. The architecture is trained from scratch.

The [frozen protocol](../../../research/phase5d/protocol.json) defines
the chronological windows, adaptation split, fusion search and domain
false-positive targets. The chronological cutoffs were selected using
month-level support before model scoring. A connected component shares
registrable domain, alias, lexical family or a documented campaign
identifier. If a component spans windows, its earlier records are
withheld and its latest window keeps its original timestamps.
Verified campaign IDs were unavailable. The lexical proxy can merge
unrelated domains and miss related campaigns.

UCI adaptation uses only original UCI development-training rows with
zero overlap by domain, lexical family or URL alias with the canonical
views. Publisher-test overlaps are also excluded. The target-training
and threshold-calibration views are separately grouped. The mixed
TF-IDF run holds the label balance and total training sample
size constant at 20,000, drawing 10,000 rows from each source.
Recalibration locks target-domain operating thresholds on the dedicated
UCI calibration view and scores on the existing UCI validation view.

Fusion fitting uses a 10,000-row balanced view of previously unsampled Phase 5C training components
that share no domain or lexical-family component with the matched
20,000-row training sample. It fits Platt probability scales, records
pairwise disagreements, and considers a partner only when it catches
at least 1% exclusive positives at the fitting 1% domain-FPR threshold.
The fitting view ranks a fixed grid of three blend weights by recall and
then average precision. A separate calibration view locks operating
thresholds for the selected blend. The evaluation sets remain outside
probability-scale fitting, weight choice and cutoff estimation. The
initial ID-prefix fitting view had only phishing rows. The preparation
check caught it before scoring. The balanced rebuild kept the
chronological partitions byte-identical.

The domain FPR uses the maximum score among each domain's negative URLs.
The existing binomial calibration uses 5% risk. Intervals for ranking
metrics, URL precision, recall, F1 and URL FPR resample domains with 200 seeded
replicates. Domain FPR intervals are two-sided exact binomial
intervals and assume independent domain outcomes. PR-AUC is average
precision. ECE uses ten equal-width bins and is summarized alongside
the Brier score. Single-row latency includes representation conversion
and uses 300 warmed examples on the same two logical CPUs.

## Independent evaluation and financial evidence

The recent PhishTrap publisher release has row timestamps and feed
provenance, but Tranco supplies proxy negatives and a positive may
come from a single feed. The published MIT tag does not establish
redistribution rights for its OpenPhish component. CompPhish v3's
September 2024 to August 2025 collection period overlaps PhreshPhish
development and includes OpenPhish. Zenodo's October 2026 multimodal
release lists PhishTank and Tranco sources. A bounded range read
transferred 3,036,372 bytes of archive directory and CSV header data.
Both CSV headers include URLs and labels and lack observation dates
and row-level verification fields. These
checks did not establish a fresh cohort with both verified labels and
source independence at the required operating point.
[PhishTrap publisher card](https://huggingface.co/datasets/saidutta69/PhishTrap),
[OpenPhish terms](https://openphish.com/terms.html),
[CompPhish v3](https://data.mendeley.com/datasets/fmbs4kp9wz/3),
[Zenodo multimodal release v2](https://zenodo.org/records/23477065).

Phase 5C recorded nine Indian financial target candidates and zero
independently supported positives. This phase found no additional
independent financial record evidence. Candidate tags stay outside the
evaluation labels. The research uses inert URL strings and private
checkpoints.

## Reproduction

The [runbook](../../../research/phase5d/README.md) uses the pinned
private Python environment and sequential Windows Job Object workers.
The job receipts record logical affinity, elapsed wall time and peak
worker-tree committed memory. The reused Phase 5C model checkpoints and
their original experiment records remain in place.

## Verified inputs

The canonical audit verified 211,631 rows in five partitions, pin metadata for 56 train shards and 21 publisher test shards, and 168,060 label-free test exclusion IDs. It found 0 publisher-test matches in the canonical views and 0 historical exclusion matches in the canonical PhreshPhish development views.
The normalized protocol SHA-256 is `544f9b999075ef97fea30e33f35867d39616c1e233c04c68107a9f950f97b04c`.

## Matched Phase 5C comparison

All five Phase 5C model families replayed from hash-verified checksums at 20,000 and 50,000 rows. The replay checked the exact evaluation IDs and confusion matrices, ranking metrics to a tolerance of 0.000001, and recorded low-FPR differences in the aggregate results. The 20,000-row results below report recall / observed domain FPR at each calibration target.

Replay returned zero differences for PR-AUC, ROC-AUC, and recall and
domain FPR at both locked operating points across the ten archived
checkpoints and both evaluation sets. At 50,000 rows, TF-IDF led PhreshPhish PR-AUC at 0.9962 and the CNN
led standalone recall at the 0.1% target with 53.31%. The Transformer
reached 0.9884 and 15.37%, respectively.

| Model | Phresh PR-AUC | Phresh ROC-AUC | UCI PR-AUC | UCI ROC-AUC | Phresh at 1% | Phresh at 0.1% |
| --- | --- | --- | --- | --- | --- | --- |
| Numerical LR | 0.9726 | 0.9351 | 0.9327 | 0.9051 | 36.67% / 0.49% | 1.26% / 0.00% |
| Random forest | 0.9829 | 0.9559 | 0.8902 | 0.8548 | 60.25% / 0.66% | 4.79% / 0.00% |
| XGBoost | 0.9837 | 0.9586 | 0.9197 | 0.8841 | 57.65% / 0.59% | 1.51% / 0.00% |
| Character TF-IDF LR | 0.9952 | 0.9873 | 0.9936 | 0.9939 | 82.32% / 0.75% | 39.39% / 0.02% |
| Character CNN | 0.9933 | 0.9825 | 0.9755 | 0.9739 | 78.45% / 0.75% | 53.04% / 0.05% |
| Transformer | 0.9849 | 0.9645 | 0.9840 | 0.9809 | 48.84% / 0.61% | 10.16% / 0.05% |

## Transformer scaling and resource use

| Fit rows | Phresh PR-AUC | Phresh ROC-AUC | UCI PR-AUC | Phresh at 0.1% | Epoch | Fit seconds | Worker seconds | Peak MiB | Median / p95 ms | Model bytes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1,000 | 0.9093 | 0.8052 | - | Unsupported | 2 | 15.31 | 26.42 | 977.5 | 2.324 / 3.076 | 65,085 |
| 20,000 | 0.9849 | 0.9645 | 0.9840 | 10.16% / 0.05% | 5 | 209.25 | 220.91 | 1004.7 | 2.242 / 2.651 | 65,085 |
| 50,000 | 0.9884 | 0.9713 | 0.9812 | 15.37% / 0.00% | 5 | 518.04 | 529.28 | 1027.0 | 2.210 / 2.755 | 65,085 |
| 70,570 | 0.9892 | 0.9732 | 0.9744 | 14.17% / 0.00% | 5 | 683.13 | 694.73 | 1039.8 | 2.270 / 2.734 | 65,085 |

The architecture has 14,065 trainable parameters. The preflight scored the first 1,000 validation rows and the larger runs used the full retrospective validation. All scales use nested balanced sampling from the same training pool.

## Chronological generalization

The chronological build withheld 11,818 earlier rows from components represented in later windows and excluded 0 unusable dates. The same balanced older sample was used for each temporal model, and checkpoint and threshold hashes were written before either evaluation window was opened.

| Window | Observed bounds | Rows | Phishing | Legitimate | Domains |
| --- | --- | --- | --- | --- | --- |
| train | 2024-07-02 through 2024-08-31 | 62,477 | 41,883 | 20,594 | 54,906 |
| tuning | 2024-09-01 through 2024-09-14 | 16,185 | 5,634 | 10,551 | 15,185 |
| calibration | 2024-09-15 through 2024-09-30 | 22,348 | 14,123 | 8,225 | 20,623 |
| near | 2024-10-01 through 2024-10-31 | 19,633 | 15,580 | 4,053 | 14,652 |
| far | 2024-11-01 through 2025-09-08 | 46,562 | 45,407 | 1,155 | 31,166 |

| Model | Near PR-AUC / ROC-AUC | Far PR-AUC / ROC-AUC | Near at 1% | Far at 1% | Near at 0.1% | Far at 0.1% |
| --- | --- | --- | --- | --- | --- | --- |
| Transformer | 0.9881 / 0.9595 | 0.9977 / 0.9270 | 43.25% / 0.43% | 42.30% / 1.77% | 11.55% / 0.00% | 13.02% / 0.18% |
| Character TF-IDF LR | 0.9961 / 0.9855 | 0.9992 / 0.9690 | 76.60% / 0.85% | 64.90% / 0.35% | 40.69% / 0.05% | 39.46% / 0.00% |
| Character CNN | 0.9943 / 0.9788 | 0.9986 / 0.9519 | 69.93% / 0.68% | 60.52% / 1.77% | 26.63% / 0.00% | 31.76% / 0.00% |
| XGBoost | 0.9824 / 0.9388 | 0.9977 / 0.9242 | 48.20% / 0.83% | 44.90% / 0.71% | 8.86% / 0.00% | 6.49% / 0.00% |

The late window has a different class mix. Average precision must be read with the window counts, and the observed domain false-positive rates have wider intervals when negative support is small.

ROC-AUC fell for all four models from the near to the far window, even
as average precision rose with the phishing-heavy label mix. At the
1% calibration target, the Transformer and CNN both reached 1.77%
observed far-window domain FPR. TF-IDF had the strongest far ranking
and 39.46% recall at the stricter calibration target. Its zero observed
far alerts across 564 negative domains imply a two-sided 95% upper
bound of 0.65%.

## UCI adaptation

Target-only threshold fitting used 43,118 separate UCI development rows. Transfer evaluation used the same 32,608 UCI validation rows for each method. The 50:50 mix changed the TF-IDF training composition at fixed size and used the same UCI threshold view.

| Model | UCI PR-AUC | Brier | ECE | Source at 1% | Target at 1% | Source at 0.1% | Target at 0.1% |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Character TF-IDF LR | 0.9936 | 0.0766 | 0.1444 | 45.53% / 0.00% | 93.02% / 0.84% | 5.80% / 0.00% | 74.93% / 0.04% |
| Character CNN | 0.9755 | 0.0627 | 0.0725 | 42.83% / 0.02% | 79.97% / 0.84% | 10.79% / 0.00% | 45.74% / 0.03% |
| XGBoost | 0.9197 | 0.1520 | 0.2553 | 34.86% / 0.00% | 75.77% / 0.75% | 0.61% / 0.00% | 52.65% / 0.00% |
| Transformer | 0.9840 | 0.0570 | 0.0773 | 22.50% / 0.00% | 90.64% / 0.91% | 2.79% / 0.00% | 76.25% / 0.07% |
| 50:50 mixed TF-IDF LR | 0.9981 | 0.0197 | 0.0652 | - | 99.02% / 0.87% | - | 97.98% / 0.06% |

For unchanged TF-IDF scores, target calibration changed strict-cap recall by +69.13 percentage points (95% CI +64.90 to +73.37).

## Model complementarity and fusion

The group-disjoint fitting view contained 10,000 examples. It selected Character TF-IDF LR and XGBoost, with weights 0.75 and 0.25. The partner uniquely caught 2.34% of fitting positives at the 1% target.

| Evaluation | PR-AUC | ROC-AUC | At 1% | At 0.1% | Brier | ECE |
| --- | --- | --- | --- | --- | --- | --- |
| validation | 0.9957 | 0.9888 | 84.70% / 0.87% | 57.98% / 0.07% | 0.0462 | 0.0560 |
| uci-validation | 0.9894 | 0.9856 | 56.45% / 0.00% | 24.42% / 0.00% | 0.0616 | 0.1391 |

At the strict PhreshPhish target, fusion changed recall versus the CNN by +4.94 percentage points (95% CI +3.57 to +6.14). The change versus TF-IDF was +18.60 percentage points (95% CI +16.96 to +20.40). Fusion median / p95 single-row latency was 2.702 / 3.535 ms. Component checkpoints total 1,632,500 bytes, and selecting the blend from precomputed scores took 0.22 seconds.

## Evidence and limits

The [aggregate results](results.json) include threshold-specific recall,
precision, F1, URL and domain FPR, confusion counts and confidence intervals,
paired recall changes, pairwise disagreement, error overlap, and per-model
job receipts. The 0.01% target was unsupported. Matched, temporal and
UCI calibration had 4,166, 8,021 and 26,327 negative domains respectively.
The calibration rule needs at least 29,956 even with zero calibration
alerts.

The Node.js offline evaluation and pipeline suites passed 36 tests. The guarded Phase 5D Python suite passed seven tests covering the shared tokenizer, mask behavior, deterministic training and inference, calibration support, paired resampling and fusion selection.

## Phase 5E decisions

- **GO for independent validation of the two simpler candidates.** Freeze
  the 75:25 TF-IDF/XGBoost blend and the source-balanced TF-IDF model
  before obtaining a dated, explicitly licensed cohort with independently
  supported labels. Use standalone TF-IDF and CNN as reference models
  and reserve disjoint target calibration and evaluation groups.
- **Keep the fusion conditional on measured cost and FPR.** Its 4.94-point
  recall gain over the CNN on retrospective PhreshPhish came with 3.535 ms
  p95 latency and a 95% domain-FPR interval of 0.014% to 0.205%. The
  UCI ranking was lower than standalone TF-IDF. An independent comparison
  should check both tradeoffs before adopting the blend.
- **Prioritize target calibration and source mixing for transfer.** At
  the 0.1% target, UCI recall rose from 5.80% to 74.93% with unchanged
  TF-IDF scores and target-calibrated thresholds. The balanced mix
  reached 97.98% recall with 0.059% observed domain FPR and a 95% interval
  of 0.029% to 0.105%. These results warrant confirmation on a fresh target.
- **NO-GO for a Transformer lead model or deployment.** The larger model
  runs increased PhreshPhish average precision while UCI average precision
  declined and strict PhreshPhish recall peaked at 50,000 rows. The
  Transformer lagged both leading standalone models at matched sizes.
  Keep these checkpoints for offline comparison.
