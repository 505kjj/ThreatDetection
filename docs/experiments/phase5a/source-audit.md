# Phase 5A Source and Licensing Audit

This audit records what was reviewed and what was actually available on
2026-11-24. A terms page or a public URL is not treated as proof that a usable
financial-phishing corpus was acquired.

| Source | Access/licensing finding | Evidence and operational decision |
| --- | --- | --- |
| [UCI PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset) | Dataset page states CC BY 4.0. | Existing pinned numeric exports are retained as general-phishing research data with attribution. The source does not provide a verified Indian-financial target label for each row, so no such label is inferred. |
| PhreshPhish | Dataset card reviewed in Phase 3B–3D; the project records CC BY 4.0 and an author clarification for URL/label anti-phishing use with attribution. | Existing private numeric projections are used only for historical distribution comparison. HTML/content is not imported. |
| [PhishTank developer information](https://phishtank.org/developer_info.php) / [terms](https://phishtank.org/terms.php) | Documentation describes a verified online feed and API/download limits; terms distinguish API data from site content. | One descriptive, non-retrying request was made during this phase and returned **HTTP 429, zero bytes**. No rows, URLs or feed snapshot entered the repository. Written operational approval and rate-limit handling are still required before ingestion. |
| [OpenPhish academic program](https://www.openphish.com/academic_use.html) / terms | Academic program is restricted to accredited, non-commercial use and limits redistribution; commercial use requires permission. | Not used. It is not a commercially permissible source for this product without written consent. |
| [APWG membership](https://apwg.org/membership) | eCrime Exchange access is membership-controlled and subject to dues/terms. | No feed acquired. Do not scrape or redistribute membership data. |
| CERT-In | Official contact routes for coordination/feed requests were reviewed; no public bulk dataset was supplied. | No records acquired. Pursue a written data-use agreement before any import. |
| [RBI bank complaint/listing pages](https://www.rbi.org.in/Scripts/ComplaintBank.aspx) | Public authoritative references to Indian regulated-bank domains. | Six references are recorded as project-authored legitimate controls in [`official-control-sources.json`](official-control-sources.json). The endpoints were not crawled or visited; this is not proof of page safety or a phishing corpus. |

## Acquisition safeguards

- No active phishing URL was opened or executed.
- No private service was scraped and no access restriction was bypassed.
- Raw feeds, archives, model binaries and private manifests stay outside Git.
- The pipeline requires a source record, explicit verification status, separate
  observation and verification times, and permissions before a row can enter a
  training partition.
- Target/brand evidence must cite an independent source. A URL merely containing
  a bank name is not assigned a financial label.

## Blocking evidence

At closeout, there is **no independently verified Indian banking, UPI or
payment-service phishing-positive cohort** available to this project. The
financial evaluation status is therefore `not_ready`; the six RBI controls are
legitimate-only controls and cannot support recall, precision or coverage
claims.
