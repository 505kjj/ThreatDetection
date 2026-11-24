# Phase 6A visual financial-brand research

**GO for offline research. NO-GO for controlled shadow testing, browser warnings, blocking, and visual telemetry.** The prototype measures similarity between supplied logo crops and a small reference bank. It has no automatic logo locator and no independently labeled visual phishing cases.

## Reviewed dependencies

The product line and the research line branch from the Phase 3E integration point. Phase 4C commit `b9b4addf54ec3cae200e7b87dc05a4e5b57cd770` remains outside the ancestry of Phase 5G commit `ebe0f4f323950cb5349f7555b6682f1490f9d809`. The reviewed remote main tip incorporates Phase 5E. Mixing the full Phase 4 product diff into Phase 5G would change the earlier frozen evaluation's financial-domain and impersonation files. Phase 6A uses Phase 5G as its parent, consumes the checksum-pinned Phase 4C registry as a research dependency, and leaves both production files and the Phase 5G freeze intact. [Phase 4C design](https://github.com/505kjj/ThreatDetection/blob/b9b4addf54ec3cae200e7b87dc05a4e5b57cd770/docs/financial-login-protection.md), [Phase 5G freeze](../phase5g/frozen-models.json)

Phase 4C uses domain-bound local rules, limited form metadata, and existing reputation precedence. Phase 5E established the inert captured-page parsing path. Phase 5F supplied exploratory fixed URL+DOM gains on a grouped retrospective sample. Phase 5G froze the URL and DOM candidates and established independent custody requirements. Phase 6A adds a separate visual signal. Existing evidence, cutoff decisions, and exclusions still apply. [Phase 5E](../phase5e/README.md), [Phase 5F](../phase5f/README.md), [Phase 5G](../phase5g/README.md)

## References and preprocessing

Three historical logo renditions were admitted for private descriptive analysis based on the documented official identity, provenance, and specific Commons public-domain text-logo designation. The trademarks remain with their owners. The asset ledger records each rendition, exact source, stated basis, date, and image digest. The registry attaches the verified Phase 4C scopes by identity. ICICI was absent from that registry and was excluded. [Reference inventory](references.md), [Asset manifest](../../../research/phase6a/assets.json)

The decoder permits one static PNG or JPEG with at most 2 MiB encoded, 2 million pixels and 2,048 pixels per side. It verifies the container, applies orientation, discards metadata, crops fully transparent padding and alpha-composites onto white. It preserves aspect ratio with a 224 × 224 letterbox. SVG, animations, invalid bytes and images without usable visual structure are rejected. Reference admission verifies the byte checksum before decoding. The input contract accepts local crops only and contains no HTML execution or network fetching path.

The duplicate check compares encoded and normalized-pixel SHA-256 and screens near copies with a Hamming distance of four pHash bits. There were zero exact or near duplicate pairs among the three originals. Among same-family transforms, 3/18 reproduced identical normalized pixels and 12/18 fell within four bits. All transforms remain in their source family. One real original per brand gives no family-disjoint train/test contrast for a Siamese model, so no new model was trained.

## Visual similarity benchmark

The three methods use fixed score floors and runner-up margins set before the run. pHash uses a 63-bit low-frequency DCT comparison. ORB compares up to 256 binary descriptors with reciprocal Hamming ratio matches and returns unavailable on sparse inputs. MobileNetV3 Small uses the official timm ImageNet-1K safetensors weights with its classifier removed, ImageNet channel normalization and cosine similarity over 1,024-dimensional unit vectors. These thresholds are engineering probes with no external calibration. [Architecture and licensing review](literature.md)

| Method | Correct matches out of 18 same-family transforms | False matches out of 3 unrelated invented crops | End-to-end median / p95 | Reference data for 3 crops |
| --- | ---: | ---: | ---: | ---: |
| pHash | 16 | 0 | 2.29 / 5.09 ms | 24 bytes |
| ORB | 17 | 0 | 7.21 / 10.42 ms | 24,576 bytes |
| MobileNetV3 | 17 | 1 | 11.46 / 15.34 ms | 12,288 bytes |

All three methods recovered all three resized and JPEG-quality-30 examples. pHash abstained on two crops. ORB left one colored-background probe unrecognized, and MobileNetV3 returned one ambiguous brand on that condition. On a separate all-fictional mark set, pHash, ORB and MobileNetV3 recognized 11, 16 and 15 of 18 same-family transforms. ORB and MobileNetV3 each falsely matched the single deliberately similar fictional mark. These tiny controls measure behavior on known crops and transformations. Independent recognition accuracy and operational false-positive rates remain unknown. [Aggregate results](results.json)

The context interpreter distinguishes recognizable evidence on a verified scope, recognizable evidence on an unverified scope, ambiguity, an unrecognized brand, and missing evidence. It keeps shared-host exceptions exact and prevents suffix lookalikes from inheriting a verified scope. The synthetic merchant case demonstrates that a known benign logo use can produce the unverified-scope outcome. Two supplied logo candidates yielded ambiguity. Candidate extraction from a full page is outside the evaluated boundary. Legitimate merchants, news, documentation and payment providers can display financial logos, so a recognized mark on an unverified host requires corroboration before any future advisory.

## Isolated Manifest V3 feasibility

The isolated extension loaded the exported model through ONNX Runtime Web 1.23.2 using one WebAssembly thread and packaged assets. It declared zero extension or host permissions, and its extension-page policy allowed self-hosted WebAssembly with no remote connections. Over 24 warmed synthetic trials, canvas extraction measured **1.25 / 2.92 ms median/p95**, and model inference measured **8.35 / 15.18 ms**. Combined median/p95 was **9.80 / 18.17 ms**. Session initialization took 427.60 ms. The ONNX graph was 6,078,504 bytes and the required runtime files added 11,975,718 bytes. The V8 heap observation was 20,421,547 bytes and excludes WASM/native memory. The process-tree memory measurement is below. [Browser receipt](browser.json), [MV3 CSP](https://developer.chrome.com/docs/extensions/reference/manifest/content-security-policy), [ORT Web deployment](https://onnxruntime.ai/docs/tutorials/web/deploy.html)

Identical normalized synthetic pixels reached cosine 0.99999994 or higher between the browser and offline models. Native canvas preprocessing reached only 0.96819 on the lowest case, below the 0.97 parity gate. Chromium allowed same-origin canvas readback and denied readback of a cross-origin image without CORS. A delayed fixture element appeared only on the later observation. The cross-origin iframe document was inaccessible from the top page. The measured model feasibility applies to packaged, readable crops. A production design would need to resolve preprocessing parity and authorization and decide how to handle unavailable evidence. The prototype used no screenshot APIs, collection persistence, backend uploads or active-page interaction. [Canvas access constraints](https://developer.mozilla.org/en-US/docs/Web/HTML/How_to/CORS_enabled_image)

## Independent evidence and next decision

Zero rights-cleared, independently verified paired URL/HTML/image cases were available. The frozen TF-IDF, URL ensemble, Phase 5F fixed URL+DOM and financial rules were kept intact. Incremental visual efficacy was deferred. An admitted evaluation must apply Phase 5G's date, provenance, label, domain, lexical-family, campaign and custody checks plus logo asset-family and page-template exclusions. It must include legitimate third-party uses of logos and preserve a matched set of positive and negative records across candidate methods. [Phase 5G custody](../phase5g/independent-data.md)

Proceed with ORB and pHash as lightweight comparisons and keep MobileNetV3 as a pretrained research comparator. One false match on the tiny unrelated-control set, missing independent evidence, and failed native-canvas parity preclude moving any visual evidence into production. Two request drafts are ready for the research owner to review. [Unsent data requests](data-request-drafts.md)

## Verification and resources

The Windows Job Object run used two logical CPUs. The 6.56-second CPU worker peaked at 395,403,264 committed bytes. The 2.83-second Chromium job peaked at 614,076,416 committed bytes across the browser and driver. Both had zero guard violations. Six visual Python tests, 43 inherited JavaScript tests, and 29 Phase 4C product-branch tests passed. The production and Phase 5G experiment paths matched the Phase 5G parent. [CPU receipt](cpu-resources.json), [Browser resource receipt](browser-resources.json)
