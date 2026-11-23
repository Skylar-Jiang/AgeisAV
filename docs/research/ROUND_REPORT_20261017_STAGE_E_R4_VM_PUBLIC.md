# Stage E R4 — approved 6 GiB VM execution (2026-10-17)

## Delivered and preserved

The user explicitly approved changing only the original VM memsize from8192 to6144MiB. The 2GiB host reserve is unchanged: every subsequent cold boot required at least8GiB available. CPU, disks, accounts, credentials and six snapshots were retained. The VM is now normally powered off in Offline configuration. No production model, rule, threshold, reference fingerprint, fusion, Worker or Linen change.

The guest reported about5.79GiB MemTotal and5.37GiB initially available, with no swap. Harmless official PE scanning and the new diagnostic's full-vector/score parity passed before reading malware in this run. Actual guest isolation passed after each offline boot: loopback only, no routes, hgfs disabled; corpus mount noexec/nodev/nosuid. Analysis used operator UID1001, existing pidfd-supervised disposable parsers,2GiB total cgroup, no swap, OOMPolicy=kill, bounded tasks/time, and serial execution. Clamd retained its separate2.5GiB cap. Guest6GiB is validated for these measured workloads, not a guarantee against worst-case parser/daemon peaks or permission to increase concurrency.

## Actual intake and label quality

The previously frozen15primary-evidence candidates were queried without using AegisAV scores to select files.18API requests (15metadata+3downloads), >=5second spacing, shared400/day budget.5metadata available,10hash_not_found. Two available PE exceeded the existing2MiB bounded acquisition writer limit and were explicitly excluded; no raw parsing or truncation of those files. All3eligible encrypted archives downloaded and were unpacked only after normal poweroff/cold Offline boot and actual guest isolation confirmation. No PE was executed; neither archives nor raw malicious bytes entered Windows/WSL.

Three new raw PE passed exact-SHA integrity and strict PE checks: two Win64 StealC V2 and one Win32 Amadey, all linked to a previously reviewed technical source. This obtained subset covers one research organization/two families, narrower than the four-organization/six-family candidate pool. Source family versus MB tag agrees at family level (StealC V2 versus Stealc; MB does not independently establish the V2 variant). The acquisition window's failure/exclusion records remain intact.

Operational admission-v1 high-confidence3 means verified raw plus explicit primary technical evidence and accepted automated review. Independent human review0; formal final eligible0. These are observed development-error-analysis cases. Local Win64 fit/validation/test SHA overlap remains0 from the prior frozen candidate audit; complete author training and near-training independence remain unknown. New3against1941existing/control fingerprints:0exact,0prior near links,1internal TLSH edge (distance19); two screening components. Screening components do not establish statistical independence or rule out uncomputed prior/prior bridges. No final test sample is being promoted from observed development data.

## Same-file paired evidence

All16PE (3new malicious development cases+13official presumed-benign controls) have the same known engine/artifact versions: reference279d0104511d2850; YARA-X1.20.0 /55ccec8463af1166; ClamAV1.5.4 /28148; frozen general ML registry13f35d8… / LightGBM4.6.0 EMBER2024v3. Official controls cover7-Zip,SumatraPDF,curl,Notepad++;11Win64/2Win32. Publisher provenance remains presumed benign, not absolute truth; prior signature/overlap caveats remain.

| Frozen detector / policy | New malicious development positive | Official presumed-benign positive |
| --- | ---: | ---: |
| SHA-256 | 0/3 | 0/13 |
| TLSH/SSDeep | 0/3 | 0/13 |
| YARA-X | 0/3 | 0/13 |
| ClamAV | 2/3 | 0/13 |
| General LightGBM | 3/3 | 2/13 |
| Five-engine positive OR | 3/3 | 2/13 |
| Existing frozen Win64 profile with general fallback (research) | 3/3 | 1/13 |

One StealC file is ML-only positive. ClamAV adds no positive beyond general ML in these three; its two hits include the near sibling and Amadey. Production fusion says suspicious for the positive cases and undetermined for the other controls, never certified benign. All16paired scans completed;0scanner failures/engine abstentions. Twelve intake candidates remain unscanned (10unavailable+2size exclusions), not negatives.

The two general-model control positives are official7-Zip x64/x86 installers, scores0.929037/0.910720 at0.5. They are retained as potential false-positive evidence. The previously frozen Win64 profile uses0.9831222501, with general fallback for Win32. In a separate16-file guarded shadow study, all feature digests matched baseline and all3fallback scores/thresholds matched. The x64 control ceases to be positive (score0.903488), while the x86 fallback remains positive; the three new malicious positive signals remain. This is one changed control on an observed development cohort, not a proven population FPR improvement or selection of a new threshold. Production activation remains false.

Formal Recall, FPR, Precision, F1, AUC and fixed-low-FPR Recall remain unavailable: no independently admitted final set and inadequate benign denominator/correlation control. Even0/13has an illustrative one-sided95% IID binomial upper bound20.58%, before proxy-label and related-sample limitations. Do not call3/3a formal Recall or2/13a validated deployment FPR. No final-test feedback used for tuning.

## Concrete old missed-case diagnosis

The old Emotet-linked657408byte Win64 DLL has12sections,46imported functions,11exports,one parser warning and a636416byte resource section. High resource proportion is observed, not proof of packing/maliciousness. Full2568-vector equality with upstream, feature digest, implementation/schema, model artifact/version, score and threshold all match the saved R3 baseline. Thus this case's scoring is reproducible; no feature-semantic/model-version mismatch was found.

General score0.414265at0.5 and Win64 score0.707153at0.983122 remain unchanged. TreeSHAP grouped raw-margin header contributions are -2.472795/general and -1.845450/Win64; positive string/authenticode groups are insufficient to overcome the total margins. Sum-of-contributions and logistic-score assertions passed. These are model associations, neither causal behavior explanations nor calibrated probabilities. The7-Zip x64 control has general header contribution+1.898186; this contrast motivates independently validated feature/model error analysis, not ad hoc deletion of header features.

All14hex probes from the frozen Emotet rule are absent in the raw case; the complete246-rule corpus does not match. The7preselected Elastic internal research rules also do not match this raw case (and gave0/13control positives): measured added detection0, no timeout. Their ELv2 assets remain private/internal and were not activated or redistributed. Mere rule count expansion did not solve this miss.

References still contain4records/two malicious fuzzy references, no exact case record; nearestTLSH454vs40 and bestSSDeep0vs80. Self checks0/100 agree. This supports insufficient reference similarity coverage; no SHA backfill or threshold reduction. ClamAV's engine/database were operational, but a specific missing signature or content-level failure mechanism has not been proven. The exact ClamAV root cause remains unresolved.

## Costs, resource evidence and failures

Version-confirmed new3file task P50=2.531s/P95=3.678s(linear quantile), total8.818s; wrapper8.927s. Full scan tree peak371.62MiB, clamd separately1.263GiB. Acquisition tree56.25MiB. Official13task P50=4.945s/P95=9.709s, total67.629s; unit wall68.278s, scan tree349.19MiB. Engines overlap, so summing their elapsed times does not reconstruct task wall. Data size/type and cache/daemon readiness differ; these are observed workloads, no controlled pre/post performance claim.

Frozen-profile ML-only16files:35.865s,231.86MiB. No Worker replacement or new62%claim; earlier batch result is not revalidated here. Scan cgroup memory.events showed0OOM/kill/max; no kernel OOM entries in the checked analysis boot.267production release assets verified. Both initial paired SQLite stores and the later confirmation store quick_check=ok. Corpus about10.79GiB available, OS root about48.15GiB. Only redundant, verified transport archives were removed (31,015,973bytes); formal data/results/models and six snapshots retained.

Initial harmless unit mistakenly blocked loopback ClamAV with IPAddressDeny=any: interrupted before any completed file, original checkpoint/DB preserved. New result directory with IPAddressAllow=localhost passed, while external network remained absent/denied. Unsupported MemoryOOMGroup property was rejected before starting; OOMPolicy=kill was used and memory.oom.group=1verified. Script quoting/CRLF issues occurred before usable scans and were corrected.

The first initial malicious scan returned no_match with ClamAV version unknown because readiness probe raced daemon startup. This was not accepted as version-comparable evidence: preserved original, then explicitly waited for exact1.5.4/28148 and rescanned all3in a fresh SQLite/result set. All16final paired records have known identical versions. All3decisions and ML scores/full feature identities were unchanged. The faster confirmation is affected by daemon/file cache state, not evidence of a Worker optimization. The no-kernel-entries journal grep returned1; this was a check-wrapper exit, not a failed scan.

## Code, tests and next work

Only research runner changes: new bounded source/work arguments preserve old defaults; source/manifest digests bind checkpoints; orphan SQLite is rejected before opening old reports, and the initial checkpoint is durable before first DB creation.6focused tests and independent read-only review passed; full local265passed/6skipped/1existing anyio warning. Production backend/model/rule/frontend source remains unchanged.

Next: independent label review and final admission, obtain diverse raw technical cases beyond the currently available source/families, retain size exclusions or separately validate a versioned larger-file intake boundary, and test the frozen profile tradeoff on independent validation data. Keep an unseen frozen final cohort before further model/rule/fusion choices. Rule gain is negative here; no production detection improvement is claimed. R4 research progressed; formal Stage E accuracy acceptance remains open.
