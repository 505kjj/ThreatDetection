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

Fusion fitting uses previously unsampled Phase 5C training components
that share no domain or lexical-family component with the matched
20,000-row training sample. It fits Platt probability scales, records
pairwise disagreements, and considers a partner only when it catches
at least 1% exclusive positives at the fitting 1% domain-FPR threshold.
The fitting view ranks a fixed grid of three blend weights by recall and
then average precision. A separate calibration view locks operating
thresholds for the selected blend. The evaluation sets remain outside
probability-scale fitting, weight choice and cutoff estimation.

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
