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
