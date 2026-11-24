# Phase 5G guarded preflight and custodian evaluation

The preflight restores the frozen artifacts, reads only public documentation from the pinned PhishVN ZIP, replays earlier results and writes aggregate diagnostics. The custodian executable is separate. Only a designated independent operator with approved archival evidence and private storage should run it. It rejects the specific ineligible PhishVN release.

## Preflight

Run from the repository root with the pinned Phase 5B CPython environment and Phase 3C packages.

```powershell
$p = 'C:/Users/kj/threat-detection-experiments'
$py = "$p/phase-5b-v1/venv/Scripts/python.exe"
$env:PYTHONPATH = "$p/phase-3c-v1/packages"
$guard = 'research/phase3d/resource_guard.py'
$out = "$p/phase-5g-rerun"
New-Item -ItemType Directory $out
npm ci --prefix evaluation --ignore-scripts
npm ci --prefix research/phase5e --ignore-scripts
& $py $guard --metrics "$out/preflight-resources.json" -- $py research/phase5g/preflight.py $p "$out/preflight"
& $py $guard --metrics "$out/tests-resources.json" -- $py -m unittest discover -s research/phase5g -p 'test*.py'
```

## Independent intake and scoring

1. Assign a custodian outside model development. Review prior access, source lineage, every included label and the collection rights. Keep an evidence register with source-record attestation, observation and adjudication times, target evidence, provenance, and rights. For campaign evidence use a documented common namespace and include known upstream aliases in the review. Transport an approved, bounded archival file or licensed subset to private custody. Treat source independence as a substantive evidence check and document unknown overlap.
2. Within custody, create a private JSON Lines ledger. Keep original, evidence-supported absolute URLs and use opaque SHA-256 digests to point to entries in the evidence register. Supply `cohort`, integer `label`, `observedDay`, `verifiedDay`, `sourceRecordSha256`, `verificationEvidenceSha256`, `rightsEvidenceSha256`, and `evidenceClass`. The cohorts are `general-phishing`, `india-financial`, `non-india-financial`, and the negative-only `benign-auth-payment`. Use `verified-credential-phishing` with a verified campaign digest for positives and `verified-legitimate` with `ownershipEvidenceSha256` for negatives. Financial positives also require `verifiedInstitutionId`, `verifiedTargetCountry`, `financialTargetEvidenceSha256`, and a UTC `observedAt` timestamp. Retain institution names and evidence in custody.
3. If page captures are authorized, keep unnamed user data out of the collection. Each optional `capture` object supplies `sha256`, UTC `capturedAt`, `urlDigest` from the frozen canonicalizer, `rightsEvidenceSha256`, and `templateEvidenceSha256`. The local capture filename is its digest followed by `.html`. Each capture must be aligned to the same observation day. Establish and document authentic template-family exclusions in intake. The runner also excludes capture vectors with exact or adjacent numeric structural matches in Phase 5E. It parses eligible captures in the existing inert worker.
4. Copy the published frozen registry to custody. Prepare a JSON receipt with the protocol `schema`, `reviewedDay`, `registrySha256`, `protocolSha256`, `sourceArtifactSha256`, `ledgerSha256`, `evidenceRegisterSha256`, and `checks`. Use LF-normalized SHA-256 for the registry and protocol and exact byte hashes for the other artifacts. Each check must be `true` after external review: `independentCustody`, `authorizedResearchAndAggregates`, `labelAdjudication`, `sourceLineageReview`, `campaignOverlapReview`, and `priorEvaluationExposureReview`. An independently trusted public key is provisioned under the `phase5g-custodian` principal in the OpenSSH allowed-signers file. The custodian signs the receipt under namespace `threat-detection-phase5g`. Keep the signing key in custody. Reviewers establish the allowed signing authority through a separate trusted channel.
5. Run the scorer in a private workspace with the state directory controlled by the same custodian. It creates an exclusive source-digest attempt marker immediately before scoring. Preserve that marker, including when scoring is interrupted. Release only aggregate results after privacy review. Changing the registry, labeling, or thresholds after viewing independent results requires new independent evidence.

```powershell
& $py $guard --metrics "$custody/guard.json" -- $py research/phase5g/custodian.py `
  --experiments $p --registry "$custody/frozen-models.json" `
  --receipt "$custody/receipt.json" --signature "$custody/receipt.json.sig" `
  --signers "$custody/allowed-signers" --ledger "$custody/ledger.jsonl" `
  --release "$custody/source.bin" --evidence "$custody/evidence.json" --state "$custody/state"
```

Add `--captures` only for a directory of approved captures. The report keeps full URL results, complete-pair results and URL-only fallback distinct. Campaign digests in earlier project views are unavailable, so the verified campaign separation claim depends on the independent lineage review and its evidence. [Phase 5G findings](../../docs/experiments/phase5g/README.md)
