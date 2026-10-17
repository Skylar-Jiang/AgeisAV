# Stage E R4 — 2026-10-17 (partial research delivery)

## Status and actual data

Production models, rules, thresholds, reference hashes, fusion, workers and Linen remain unchanged. Credential configuration and guest containment acceptance were not repeated.

Fifteen new exact-SHA primary technical-evidence candidates from four research organizations and six reported families were frozen before product scores: all probable, independent human review pending. Four primary pages were fetched, their SHA associations checked and source digests retained. No API request this round, no new malicious raw PE and no new high-confidence/final cases: VM startup is blocked by the existing10GiB host memory gate, not by a tested source availability failure. Do not include these unattempted cases in a retrieval failure rate.

Thirteen new unique presumed-benign PE were actually acquired without execution from four official projects: archivers, a PDF reader, an HTTP client and a text editor. Downloads41,336,652bytes; raw PE42,748,725bytes; 11Win64/2Win32. Signature statuses8Valid/2NotSigned/3UnknownError; the latter is an untrusted curl CA, not a modified trust store or fabricated validity. Published package hashes were checked where provided. Retained source-review corrections supersede two metadata fields in the immutable acquisition manifest; no candidate re-selection.

Local Win64 fit/validation/test SHA membership matches0/0/0 for all28 candidates; full author-training and near-training overlap remain unknown. No new exact overlap in13 benign candidates. Current-only screening12clusters; including observed current/prior edges11components, with3previously linked files. Remaining10files form9screening components. Full prior/prior connectivity was not re-audited. None is a formal final unit.

## Concrete missed-case findings

The same frozen reference artifact contains4records, only2malicious fuzzy references. Saved-case metadata shows no exact reference, closest TLSH454 versus threshold40, bestSSDeep0 versus80. Native self-checks0/100 are consistent; existing positive-match regressions pass. This supports inadequate reference coverage for this case, not a license to lower thresholds or backfill its hash. It does not prove every implementation path correct.

The frozen rule corpus has246rules,212from ransomware source paths, one family rule containing14hex patterns originating in a Win32 implementation. Its actual pattern presence in the Win64 raw case has not been measured this round. Architecture mismatch alone is not proof of a rule's impossibility to match.

Apparent Windows/Linux artifact mismatch was reproduced without malware: platform Path sort order yields c86b0a888539baf5 versus55ccec8463af1166 for identical rule bytes and metadata. The Linux value exactly matches R3. No deployed-rule omission is established by that version difference; no production fingerprint migration was made.

PE structure, upstream full-vector equality, model-specific TreeSHAP raw-margin groups and ClamAV-specific signature causes still require the offline raw case. Prepared diagnosis binds all baseline model/feature/threshold versions and refuses a normal explanation on mismatch. Contributions describe model associations, not causal malware behavior or calibrated probabilities. It has not run in the guest.

## Separate rule experiment: evidence and limit

Seven Emotet research rules from pinned Elastic revision955723319e62a7e4095d256355b095a7594ff48c compiled and scanned the same13new benign candidates:0positive signals,0timeouts, wall63ms. This is a YARA-only warm local experiment, not five-engine throughput or formal FPR. Raw malicious-case coverage is untested; added detection gain is unknown. The zero-of13 illustrative one-sided95% IID binomial upper bound is20.58%, even before proxy-label/correlation limitations. No low-FPR claim is supported.

Elastic License2.0 assets/license remain private for internal research; the experiment does not authorize a hosted product deployment. They are not copied into production rules or the public source snapshot. Exact rule selection was made before any new malicious product results. No final test data used.

## Engineering, tests and remaining work

Collector R4 handles up to30 frozen candidates; explicitly records non-PE and existing2MiB worker-FSIZE exclusions before download. These are limited intake coverage, not completed negatives. Reports with results mark observed development status. Original R3 source/inputs remain frozen in the guest. The new static diagnosis is prepared under the existing guarded process boundary, with source identity and baseline mismatch checks; no new guest execution acceptance is claimed.

259passed/6skipped/1existing anyio warning; focused18passed, independent review18passed. Original VM remains off, no account/key/snapshot/RAM changes, no malicious PE on Windows/WSL. Last captured startup check7.33GiB available versus10GiB required; later spot check6.88GiB. C27.07GiB/D101.46GiB free. No other project stopped, no rejected cache cleanup retried, formal artifacts preserved. No Worker performance claim or replacement this round.

Next executable work: resource-safe original VM startup; offline old-case structural/feature/pattern diagnosis; NAT encrypted intake using the persistent LoadCredential store, cold Offline switch and bounded acquisition; individual label/family review; paired five-engine scans of obtainable cases and the13new benign PE; then fixed-version shadow ablation. Human label review, complete training independence and final-set admission remain outstanding. R4 is not complete and no Recall/FPR/Precision/F1/AUC is asserted.
