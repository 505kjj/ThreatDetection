# Offline financial phishing dataset validator

Run the validator on data that the operator is authorized to hold. The tool checks evidence fields and permissions against a private manifest. It neither fetches evidence URLs nor adjudicates whether the declared evidence is true. Prefer signed permission documents, independently reviewed target identities, and evidence immutable by digest.

## Inputs

The private JSON manifest has `schemaVersion: 1`, `kind: "real"` or `"synthetic"`, an explicit RFC 3339 review time in `asOf`, and the lowercase SHA-256 of the exact JSON Lines bytes in `recordsSha256`. Registry IDs are lowercase hyphenated identifiers.

| Registry | Required fields |
| --- | --- |
| `sources[]` | `id`, `publisher`, `provenance`, `license` and `permission` with `internalResearch: true`, `aggregateReporting: true` and `evidence`. |
| `targets[]` | `id`, `name`, `kind` of `financial-institution` or `payment-provider`, `reviewed: true`, and authority `evidence`. |

Each file line holds one JSON object.

| Record field | Accepted data |
| --- | --- |
| `url`, `label`, `split` | Full HTTP(S) URL with no userinfo, explicit `phishing` or `legitimate` label, and `development`, `calibration` or `test`. The canonical duplicate check removes query and fragment. |
| `observedAt` | Actual observed or collected date at the source's precision. Use `YYYY-MM-DD` if only the day is known, or a timestamp with explicit UTC offset. No future observations or invented times. |
| `sourceId`, `sourceRecord` | Approved source ID and locator of original provenance. |
| `target` | Registry `id`, `verified: true`, and record-specific target `evidence`. A spelling or keyword match cannot substitute for declared verification. For legitimate controls, it describes the verified provider relationship. |
| `verification` | `status: "verified"`, matching `label`, approved `sourceId`, and `evidence` of the decision. An optional `verifiedAt` is preserved as supplied if available. |
| `campaign` | Optional `namespace`, `id`, and `evidence`. Missing phishing campaign metadata yields an explicit warning. The tool never fabricates an ID. |

Evidence locators are credential-free HTTPS URLs or `sha256:<64 lowercase hex digits>` references to privately held documents. Original URLs, dates, regulator records, bank attestations, and data licensing documents remain in private storage. Do not use the public repository as a raw dataset store.

## Check and review

~~~powershell
node research/phase3g/validate.mjs $manifest $records $output $phase3bDataset $phase3cProjection $phase3dProjection $phase3eNumeric $phase3fNumeric
~~~

Supply the last five arguments to verify historical overlap against the saved Phase 3B–3F manifests. The Phase 3E and 3F arguments are the existing private `numeric.jsonl` files. Omitting all historical arguments allows a local schema check, with historically unchecked status. The output should be a new private directory. The CLI accepts at most 64 MiB and 100,000 rows. For the same Windows laptop limits as the completed study, place the command after `--` in the shared guard with `--memory-target 4000000000`.

The report verifies the manifest and data digests. It counts normalized duplicates and conflicts, marks historical registered-domain, literal-IP and lexical-family overlap, and rejects groups crossing proposed splits by those identities or by a supplied campaign ID. Multiple URLs on one domain within a split can remain eligible and are counted once for support. Lexical families are a conservative approximation and do not establish campaign equivalence. Previous datasets lack comparable documented campaign IDs.

`summary.json` contains only aggregate results, including class and distinct domain support by split. `private-issues.json` contains row numbers and issue codes. A current data reviewer must still check external provenance and the scope of the research permission. Passing these checks does not establish sufficient class, campaign or domain support for deployment. Exit 0 indicates the supplied checks passed, exit 2 indicates reported exclusions or incomplete metadata, and exit 1 indicates a fatal file, manifest, digest or historical check. Synthetic fixtures are always excluded from readiness.
