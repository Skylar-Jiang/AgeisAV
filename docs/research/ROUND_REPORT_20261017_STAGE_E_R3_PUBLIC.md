# Stage E R3 — 2026-10-17 (public aggregate)

## Actual outcome

The user completed human credential input. Guest systemd LoadCredential authenticated actual MalwareBazaar metadata/download requests; Windows API-key DPAPI was not read. A guest-only root:root 0600 store under a 0700 directory persists across normal boots; operator cannot read the source. No API key or sample is in this publication.

Five previously reviewed primary-evidence candidates were queried with frozen admission rules: four unavailable, one encrypted download, one intact raw PE acquired offline. Six API requests total (five metadata, one download), local shared cap400/day and spacing>=5s; these are conservative local controls, not the vendor's official quota. All unavailable records remain failures, not negative detections.

One case entered the operational high-confidence tier; independent human review remains pending. Final independent eligible count remains zero: temporal OOD and full author-training overlap are not cleared. No exact overlap or near link to 1,927 previous fingerprint records at frozen TLSH<=40 / SSDeep>=80 screening boundaries. This screen does not prove full training independence.

## Detection and cost

Five engines completed on the same raw PE: SHA-256, TLSH/SSDeep, YARA-X, ClamAV and general LightGBM all no_match; zero engine errors, timeouts or abstentions. Fusion remains **undetermined**, never benign. No model, rule, reference hash or threshold was tuned or backfilled.

Task-file elapsed3.937s; orchestration row3.968s; whole scan wrapper4.061s. Whole scan cgroup peak365.18MiB (2GiB cap), separate clamd peak1.255GiB (2.5GiB cap), zero OOM events. Engine durations overlap and cannot be summed as serial time. Single-file measurements are not a latency distribution or benchmark gain.

Frozen optional Win64 profile shadow study: the same case plus65 previously scanned official presumed-benign PE, 66/66 completed, zero errors/abstentions, all no_match. Complete feature digest/schema/implementation parity66/66; general fallback score/threshold parity29/29. **No additional detection gain.** Production routing unchanged. ML-only wall84.154s, cgroup peak226.28MiB; fresh guarded per-file workers, warm OS cache. This is not a Worker reuse performance comparison.

Recall/FPR/Precision/F1/ROC-AUC/PR-AUC and low-FPR Recall are not reported as population metrics. One old case plus proxy benign labels cannot establish those claims, especially FPR<=0.1%. The archive/development evidence remains exploratory.

## Safety, failures and next work

Original VM only; cold Offline switch and in-guest isolation verified before extraction and scans. Final analysis startup met the original10GiB host gate. Earlier trusted credential/network preparation used explicitly bounded low-memory exceptions; VM RAM unchanged. No malicious execution or host extraction. Six snapshots preserved, no deletion or restore. ClamAV and owned services stopped, VM soft-shut down. Final free disks: C27.35GiB/D102.01GiB; host available9.70GiB.

A stale collector dependency initially failed before any API request. The collector now verifies the exact version and hashes before reading the runtime credential. That failure, four unavailable cases and all pending reviews are retained. Source dependencies, immutable assets and checkpoints remain bound to experimental identities.

Next: human review of operational labels; additional technically analyzed obtainable PE across families/times; broader officially sourced benign PE; keep development and final cohorts separate. Diagnose coverage on validation data before changing any frozen policy. No product/UI redesign or production Worker replacement in this round.

See ../benchmarks/stage_e3_summary_20261017.json. Private sample manifests, per-file labels, exact scores and technical case identifiers are excluded. Public export uses generic credential/private-hash/content checks and reviewed changes without reading secret values; it explicitly makes no exact-secret-value comparison claim for new blobs.

## Local verification

247 passed,6 skipped,1 existing anyio deprecation warning (20.03s). Nine public content gate tests include rejected private keys, PE bytes, oversized payloads, private sample hashes and JSON credentials. Python compile checks passed. Experimental source bytes are preserved with -text attributes because deployed identity digests include line endings. Production backend/models/rules/UI remain unchanged.

## Version verification scope

Collection dependencies are imported from root-owned immutable directories in a fresh guarded process. Hash checks reject stale dependency versions before the explicit runtime credential read; they do not sandbox import-time code or make writable/untrusted Python module paths safe. Root-owned deployment and controlled module search paths are required.

Shadow and measurement wrappers were transferred separately from the v4 intake archive. Host source digests are in the aggregate tested_source_sha256 field. The shadow result JSON did not record a self-hash and no independent guest copy digest was exported; this is a reproducibility limitation. Do not treat the intake archive digest as covering those wrappers. Retain this exploratory result; a future confirmatory run must bind the deployed wrapper digest in its output.
