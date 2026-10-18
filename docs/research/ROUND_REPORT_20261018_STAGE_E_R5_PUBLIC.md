# Stage E R5 — actual data, false-positive diagnosis and bounded acquisition

Date: 2026-10-18. Production backend, models, thresholds, references, rules, fusion, Worker and Linen remain unchanged. Research progressed; formal independent low-FPR/generalization acceptance remains open. Machine-readable aggregate: `../benchmarks/stage_e5_summary_20261018.json`. Private sample identities, review packets, source manifests and execution records are excluded from the public export.

## 1. Two 7-Zip decisions reproduced, provenance verified

Both previously observed installers were re-fetched from the publisher release linked by the [official download page](https://www.7-zip.org/download.html). Fresh bytes equal the R4 files and their [published release digests](https://github.com/ip7z/7zip/releases/expanded_assets/26.04). Both are Authenticode **NotSigned**, rather than signature-verified. These are confirmed publisher artifacts and operational false positives under the publisher-provenance label; independent human final admission is still pending. No claim of absolute benign truth is made.

| Diagnostic | x64 installer | x86 installer |
| --- | ---: | ---: |
| General score, frozen threshold 0.5 | 0.929037 | 0.910720 |
| Overlay bytes | 1,618,514 | 1,325,339 |
| Overlay/file proportion | 97.2617% | 97.3304% |
| Header-group TreeSHAP raw-margin contribution | +1.898186 | +1.732511 |
| Full 2,568-vector equality with upstream | yes | yes |
| Feature/artifact/version/score equality with saved baseline | yes | yes |

Both have zero parser warnings. No feature implementation, model-version or score-reproduction mismatch was found. The large self-extracting overlay and positive header associations motivate model-distribution investigation; they do not establish a causal feature defect. The diagnostic now respects Win32/Win64 applicability and never evaluates the Win64 model for the x86 file. Its general fallback remains positive. The observed 7-Zip cases are development evidence only, not independent validation of a new policy. No whitelist or threshold adjustment.

The old Emotet-linked case was **not rescanned in R5**: preserved R4 results remain general 0.414265/0.5 and Win64 0.707153/0.983122. Its negative header associations contrast with these installers, but do not justify deleting features or changing thresholds. Its ClamAV signature-level miss remains unresolved. No new Emotet detection gain is claimed.

## 2. Candidate availability and labels

Thirteen candidates were frozen before API/scoring: two R4 size exclusions and eleven new exact-SHA technical cases. Candidate evidence covers six research organizations/six reported families; the **obtained subset covers only two organizations/two families**. Sources include [G DATA](https://blog.gdatasoftware.com/2025/03/38154-lummastealer-fake-recaptcha), [Elastic](https://www.elastic.co/security-labs/threat-command/formbook-adopts-cab-less-approach), [Kaspersky](https://securelist.com/ghostcontainer/116953/), [eSentire](https://www.esentire.com/blog/ghost-crypt-powers-purerat-with-hypnosis), [FortiGuard](https://www.fortinet.com/blog/threat-research/deconstructing-an-evasive-formbook-campaign-leveraging-covid-19-themes) and the prior [Zscaler case analysis](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc). Exact associations and primary IOC locators are retained privately; detector votes were not the label basis.

Actual requests: **16 = 13 metadata + 3 encrypted downloads**, at least five seconds apart, using the existing conservative shared 400/day budget. Three available, ten `hash_not_found`; zero eligible download failures. The ten unavailable candidates are not negatives. Three raw PE passed exact-SHA and strict-PE verification only after cold Offline boot: two Win64 StealC V2 (2,442,240 and 2,529,280 bytes) and one Win32 FormBook (626,688 bytes). Both former size exclusions are resolved. No archive/raw malicious bytes entered Windows/WSL and no PE was executed.

All three meet operational admission-v1 high-confidence through raw integrity, explicit primary technical evidence and accepted **automated** source review. Independent human review is **0**, strict independent validation eligibility **0**, final eligibility **0**. Current/prior fingerprint screening found no edges for these three, yielding three screening components; campaign/statistical independence and full author-training overlap are not established. Local Win64 fit/validation/test exact overlap is zero. New FormBook is older material, not established time-out-of-training evidence.

Two source-date inputs were corrected in an append-only record after checking primary publication metadata: Elastic publication is 2022-06-07; FortiGuard is 2020-04-21. Original approximate campaign/date inputs were preserved and are not used for temporal admission. MalwareBazaar first_seen is provider observation, not a global first-seen guarantee.

## 3. Diverse official controls and strict role boundaries

**19 new official PE / six projects**: PuTTY, SQLite, Python, Rufus, Inno Setup and WinSCP. Categories include installers, portable GUI, CLI and runtime DLL/PYD, with Win32 and Win64. Fifteen signatures are Valid, four SQLite files NotSigned. Published PuTTY SHA-256, SQLite SHA3-256 package digest and WinSCP SHA-256 are verified; complete URLs, versions and signature evidence remain private. Publisher provenance/signatures support `presumed_benign`, not absolute truth. Some projects also occur in prior cohorts, so six projects does not mean six globally new vendors.

The original eighteen were audited before scoring against 1,944 prior fingerprints: zero prior exact matches, six prior-near-linked files, fifteen screening components. Roles were frozen as nine validation candidates, three development candidates and **six unscored quarantine files**. Components linked to prior data cannot automatically enter a future final set. The WinSCP extension has no screened exact/near-prior edge; its local training membership check happened **after baseline scanning**, so it is exploratory rather than independently admitted validation. Nineteen current controls form sixteen screening components; prior/prior transitive bridges and near-training leakage remain unresolved.

Thirteen controls were scanned; all six quarantine files remain without engine/shadow predictions. Human review and strict independent validation/final admission remain zero. Initial WinSCP HTML download wrapper was rejected as non-PE; a later official CDN artifact passed publisher checksum/signature. No difficult sample was silently dropped.

## 4. Same-file frozen-engine comparison

All sixteen paired PE have identical known versions: reference `279d0104511d2850`, YARA-X 1.20.0 / rule artifact `55ccec8463af1166`, ClamAV 1.5.4 / database 28148, LightGBM 4.6.0 / EMBER2024v3 / unchanged general registry. ClamAV readiness is checked before constructing task execution; no unknown-version result is accepted as comparable.

| Frozen detector/policy | New malicious development positives | New presumed-benign positives |
| --- | ---: | ---: |
| SHA-256 | 0/3 | 0/13 |
| TLSH/SSDeep | 0/3 | 0/13 |
| YARA-X | 0/3 | 0/13 |
| ClamAV | 2/3 | 0/13 |
| General LightGBM | 3/3 | 2/13 |
| Five-engine positive OR | 3/3 | 2/13 |
| Existing frozen Win64 profile + general fallback, research only | 3/3 | 0/13 |

Both StealC files are ClamAV+ML positive; FormBook is ML-only. ClamAV adds no signal beyond ML in this subset. The two new control positives are SQLite `sqldiff.exe` (0.642289) and `sqlite3_rsync.exe` (0.680258); they remain potential operational false positives, not discarded controls. WinSCP is 0.498505 at threshold 0.5 and was not used to adjust it.

Separate frozen-profile study: sixteen feature digests equal baseline, all five general fallback scores/thresholds equal, zero errors. Existing Win64 threshold 0.9831222501035356 reduces SQLite scores to 0.222882/0.257205, removing two control positives while preserving three malicious positive signals. **Zero new thresholds tried, zero models trained, activation false.** This demonstrates a reproducible exploratory tradeoff, not an independently validated FPR improvement or new malicious coverage. Previously observed 7-Zip x86 and old Emotet problems remain.

All sixteen baseline scans completed, zero engine abstentions/failures. Intake status is three completed, two withheld-unavailable and eight other unavailable errors; unavailable/withheld are never negative. Formal Recall, FPR, Precision, F1, AUC and fixed-low-FPR Recall remain unavailable because labels/independence, sample size and representative benign denominator are insufficient. A small zero-positive subset cannot establish FPR <=0.1%.

## 5. Larger-file intake safely separated from scanner reports

The old limit was the acquisition writer inheriting the scanner's **2 MiB regular-file RLIMIT_FSIZE**, not a cgroup filesystem-size quota or the scanner's 16 MiB input budget. It correctly rejected files instead of silently truncating accepted input. Production report cap stays 2 MiB and production input cap stays 16 MiB.

New acquisition-only `bounded-acquisition-v2-16mib`: real/effective UID1001 required (root refused), supervised Linux process, <=512 MiB address space, CPU30s, 64 descriptors, no core, umask077, **16 MiB regular-file cap**, outer 2 GiB cgroup and deadline. Single-member ZIP, path/size/password/SHA checks and atomic commit remain; exact source/policy digests bind resume identity. Root-owned nonwritable prescore freeze is read once and SHA-bound before model submission; quarantine is checked before raw read. Whole freeze ancestor chain ownership/modes were actually verified in guest.

**15/15 actual harmless guest fixtures passed**: old 2 MiB rejection; 3/16 MiB success; oversized/truncated/hash/password/path/extra-member rejection; resume; 1 GiB allocation refusal within bounded address space; 16 MiB writer refusal; crash marker/recovery; timeout with verified child start and disappearance. Review caught and fixed startup-error false-pass hazards: a crash must leave the exact harmless partial marker; timeout must show ScanStopped, child PID and cleanup. A fake ImportError now fails both regression checks. Initial v1 fixture records remain archived; final acceptance uses the corrected, actually rerun v2.

## 6. Costs, resources and tests

| Workload | P50 file task | P95 file task | Sum file tasks |
| --- | ---: | ---: | ---: |
| Three new malicious PE | 3.287 s | 4.463 s | 10.411 s |
| Thirteen official controls | 3.286 s | 11.442 s | 62.999 s |

Linear quantiles on these small observed workloads, not controlled pre/post speedups. Raw scan wrapper 20.448s includes daemon readiness; full scan tree peak 378.71MiB, separately clamd peak 1.261GiB. Acquisition tree peak 66.93MiB. Shadow study wall33.207s / peak286.82MiB. Benign scan tree peak was not captured and is not invented. No Worker replacement or renewed 62% batch claim.

Original VM remains 6 GiB, serial, >=8 GiB host startup gate and 2 GiB host reserve. Offline guest check: only loopback, no external routes, hgfs disabled, corpus noexec/nodev/nosuid; sharing/clipboard/drag-drop remain disabled. Scan cgroup OOM/max counters zero; no kernel OOM entries in the checked final analysis boot. Three result SQLite stores pass quick_check. Final guest available RAM 5,747,802,112 bytes, root/corpus available approximately48.10/10.77GiB. Removed only 116,262,453 bytes of reproducible harmless fixtures/trusted transfer duplicates; retained raw data, archives, results, models and all six snapshots. Guest unlink does not imply host VMDK shrink. VM is normally powered off.

Full local tests: **282 passed, 6 skipped, 1 pre-existing anyio deprecation warning**. New regression tests cover writer privilege/bounds, archive handling, diagnostic scope and fixture false-pass prevention. Guest fixture and actual data experiments are separate from host pytest. Public-export tests/publication evidence are recorded at closeout.

## Next

Independent human review of the prepared private evidence packet and full generic-training/time/near-training audit remain the main admission gates. Continue finding obtainable cross-family primary cases and broader independent controls while preserving all unscored quarantine. Study header/distribution ablation only on training and separately admitted validation, not these observed 7-Zip/SQLite cases. Keep frozen production settings until evidence supports a versioned improvement. Formal Stage E low-FPR/generalization acceptance remains open.
