# Stage E R6 — substantial unscored data and concrete human admission

Date: 2026-10-18. This is a data-growth and operational-exploration milestone, **not formal Stage E accuracy acceptance**. Production backend, models, thresholds, rules, references, fusion, Worker, authentication, SQLite and Linen are unchanged. Safe aggregate: `../benchmarks/stage_e6_summary_20261018.json`; policy: `../DATASET_ADMISSION_R6.md`.

## Actual raw control growth

**368 new distinct official PE**, versus R5's nineteen-file increment. All seventeen downloaded packages match publisher metadata digests; retained file SHA/size/PE scope independently rechecked368/368. Windows Authenticode observations:346Valid,22NotSigned. Labels remain automated publisher-provenance operational evidence, not absolute or human-reviewed truth. After user-authorized exploration260were scored;108remain unscored, as detailed below.

| Official project | New PE |
| --- | ---: |
| .NET SDK | 250 |
| WinMerge | 96 |
| CMake | 8 |
| Notepad++ | 7 |
| ripgrep | 2 |
| fd | 2 |
| jq | 2 |
| 7-Zip standalone tool | 1 |

Eight publisher/project identities include commercial and community publishers, not eight independently established corporate vendors. Categories:2installers/SFX,5desktop GUI,95native DLL,47CLI,219managed DLL. Architecture:77native Win32,69native/architecture-specific Win64,222managed AnyCPU. PE32 does not automatically mean native x86 semantics for managed assemblies.

Downloads519,778,798bytes; retained candidate bytes277,062,580. Package success17/17, zero package transfer failures. Exclusions retained:6prior exact duplicates,15current duplicates,6over16MiB,8ARM64 outside scope,3,460members excluded by the predefined SDK cap. The eight scope exclusions are not parser corruption. Additional PeaZip metadata discovery encountered GitHub public API rate limiting; it was not retried and contributed no installer/raw file. This failed supplementary path is separate from the seventeen successful packages.

Sources and checksum evidence are saved privately: [Microsoft .NET](https://dotnet.microsoft.com/en-us/download/dotnet/10.0), [WinMerge](https://github.com/WinMerge/winmerge/releases), [CMake](https://github.com/Kitware/CMake/releases), [Notepad++](https://github.com/notepad-plus-plus/notepad-plus-plus/releases), [ripgrep](https://github.com/BurntSushi/ripgrep/releases), [fd](https://github.com/sharkdp/fd/releases), [jq](https://github.com/jqlang/jq/releases), [7-Zip](https://www.7-zip.org/download.html). Source package digests bind extracted members; each member does not thereby have an independently published upstream checksum. Transient signed download-query URLs were removed from reviewed manifests.

## Global independence audit and sealed roles

The initial acquisition exact audit covered1,747identities/eleven manifests. Follow-up audit includes1,966prior fingerprints plus368new files, and **all available prior/prior fuzzy bridges**:797total edges,691prior/prior edges. New-vs-prior exact0/near0. New files form316TLSH<=40/SSDeep>=80 screening components; available fingerprint coverage complete. This is stronger connectivity coverage than prior new-to-old-only screens, but these components are not316independent statistical draws.

Local Win64 fit480,000/validation40,000/test119,993 SHA inventories: zero candidate overlap. A conservative2735-identity prior metadata audit and explicit four-record reference audit also find zero candidate exact overlap. Complete generic-author membership and near-training fingerprints remain unavailable. These are residual risks, **not marked cleared**. Binary first global appearance/temporal novelty is not established by version, acquisition, timestamp or publisher release alone.

The initial checksum-bound prescore freeze has368files:358proposed candidates in five project/release parent groups, two source-held files sealed as source-held final **candidates**, eight new Notepad++/7-Zip release siblings retained development because the release groups were already observed. R5's six official quarantine files remain outside this collection and protected. User steering then authorized operational exploration, explicitly **not** strict358admission. Before predictions a second source-group split assigned260(.NET SDK,CMake,fd)to exploration and retained98from two other project/release groupsunscored. All260are now permanently observed development, recorded in a superseding observation ledger rather than rewriting the historical freeze. No available fuzzy component bridges these260to the98reserved files or sealed candidates. Two source-held candidates are not admitted final data or scoring authorization.

The SDK and WinMerge supply346/368files, about94%. This collection solves raw candidate growth, not population representativeness. Parent project/release groups and higher-level publisher strata must accompany file counts. Five validation parents cannot support extreme low-FPR inference even with hundreds of assemblies.

## Human review is actionable, not fabricated

Private ten-case packet v4 supplies precise SHA, external technical/publisher locator, raw verification, suggested label, caveats and blank decisions. Four old malicious cases are permanently development for these comparisons. One source-held example is sealed label-only; five examples represent the five proposed validation release groups. The complete358member list and concrete audit/freeze digests are attached.

The initial request separated individual labels and optional strict source-group use. The user explicitly declined independent signatures and did not approve358strict validation; instead, they authorized reproducible automatic auditing and operational/proxy exploration without repeated per-file signoff. That trusted instruction is recorded separately, never as human-reviewed truth. Reviewer/time/label-acceptance fields remain blank. Human reviewed0; strict source-group authorization0; qualified validation admitted0; formal final admitted0. Ordinary source checks and experiments continue automatically; strict human admission is reserved for the genuinely independent/final stage. The old358request is not a continuing prerequisite or a currently eligible unseen cohort after260have been observed.

V4 supplements the initial frozen audit with explicit reference-inventory coverage; the earlier identities/roles/policies and packet versions are retained as historical preparation. The later operational split and observation ledger control current observation status. No approval is inferred from a draft, label example, elapsed time or the user's exploration authorization. Public exports exclude filled identities and private packets.

## Malware strategy changed; actual availability not yet measured

Instead of only querying old report hashes, R6 assembled pinned primary IOC metadata from four authored repositories: [Unit42](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel), [eSentire](https://github.com/eSentire/iocs), [ThreatLabz](https://github.com/ThreatLabz/iocs), [ESET](https://github.com/eset/malware-ioc). **626text/license blobs** passed both fetchedSHA256 and GitblobSHA1 checks. Broad catalog8,651unique64hex identities; these include unreviewed certificate/decoy/nonPE/legitimate-host roles. A separately curated17payload candidates from seven case texts/two publishers retain behavior and role context, with human/raw/PE/overlap gates pending. Thirty excluded-role occurrences and nine malformed-token occurrences are recorded.

Extracted related article URLs are **not counted as exact-hash reports**. No generic IOC match becomes high-confidence truth. Repository licenses/provenance were recorded; unlicensed eSentire source material remains private metadata, not redistributed. One Windows-invalid source path was recovered under a hash filename with its failed attempt preserved.

Proposed availability-first path queries documented [MalwareBazaar filetype metadata](https://bazaar.abuse.ch/api/), excludes known identities and nonPE/oversize input, then selects at most96files / at most8per family proxy independently of AegisAV scores. Current availability is checked before committing a large technical-hash query budget; primary IOC matches are reviewed separately. Proxy and unknown labels stay separate from technical high-confidence cases. This selector passed outcome/order-independence and boundary tests. The acquisition-only guest runner reuses pinned encrypted-download, shared400/day/>=5second budgeting, 16MiB supervised operator writer, strict ZIP/SHA/PE and offline guard; **it has not been guest-deployed/accepted or activated**.

Actual R6 MalwareBazaar requests **0**, new malicious raw PE **0**, new acquired families/organizations **0**. Current metadata/download success rates and raw validity rates are unmeasured. A historical191identity metadata catalog had zero intersection with the new broad source catalog; this does not establish present availability. R5 obtained3/13technical candidates; R6 cannot yet claim a superior malware acquisition rate. The route is prepared, not empirically proven. No API key was read on the host or requested again.

## Actual operational same-file model study

Predefined comparisons and uncertainty rules are frozen with the candidate scope: general0.5; existing Win64 threshold0.9831222501035356 plus general Win32 fallback; known-version single engines/OR; explicitly defined evidence/review/undetermined/abstention categories. Group and file results, family/category strata, conservative abstention treatment and cost are required. No arbitrary score weighting or signature/publisher unconditional allow rule.

The260file source-verified operational study is complete using bounded Windows jobs and the actual production inference function, with the **same frozen model registry as R5**, no new threshold/model/whitelist and no product activation. Exact executing research source and its digest are retained in the private reproduction ledger; the case-specific allocation and held-source membership are not exported. All260feature digests equal between profiles; all241general-fallback scores/thresholds equal. Dedicated Win64 actually applies to19files, not to managed.NET/Win32 merely because of a filename or package architecture.

| Automatically source-verified control group | Files | General positive | Frozen routed positive |
| --- | ---: | ---: | ---: |
| .NET SDK | 250 | 1 | 0 |
| CMake | 8 | 0 | 0 |
| fd | 2 | 0 | 0 |
| Total | 260 | 1 | 0 |

The new positive is official SDK `singlefilehost.exe`: general0.703215at0.5; dedicated Win64 score0.413887at0.9831222501. This is potential operational false-alert evidence for a legitimate publisher development template, not proof of a causal feature defect. Managed AnyCPU222files produce0general/routed positives; native/architecture-specific x6425files produce1/0; x8613produce0/0. Category counts:CLI37(1/0),managedDLL219(0/0),nativeDLL4(0/0). Three parent software groups and SDK250/260dominance severely limit population inference.

SHA-256, TLSH/SSDeep and local YARA-X each completed260/260with0positive/0abstention. **ClamAV was not executed for260files**, never counted negative. Host YARA-X1.20.0 uses existing246-rule artifact`c86b0a888539baf5`, which differs from old guest artifact`55ccec8463af1166`; no cross-cohort version equivalence is claimed and no rule asset was changed. Reference artifact remains`279d0104511d2850`. Thus partial four-engine positive OR is1/260general versus0/260routed, **not a complete five-engine experiment**. Model comparison is same-file/same-runtime and frozen-registry; historical guest YARA results are not merged into it.

No process/file scan error or available-engine abstention in this study. The98reserved controls, two sealed candidatesand R5quarantine6have no prediction rows; all260observed identities are excluded from future unseen evaluation. New strict independent validation predictions0; thresholds/models/whitelists tried0. **No independently supported improvement** for7-Zip,SQLite orEmotet yet, and no new malicious coverage evidence. Formal Recall/FPR/Precision/F1/AUC/fixed-low-FPR Recall remain unavailable. Operational control-positive differences are not deployment FPR. At zero FP even2,995IID draws are required for a one-sided95%upper bound0.1%, with sampling/correlation limits separately justified.

## Resource and verification closeout

Original VM remains off/Offline,6144MiB, startup gate8GiB available and2GiB host reserve; no settings/accounts/credentials/snapshots changed. Final readiness captured5,863,493,632bytes available versus8,589,934,592required. WSL contains another compiler-project Codex session around300MiBRSS; it was not terminated and would not close this gap. No new customer isolation/Worker validation is claimed. No raw malware/encrypted archive touched Windows/WSL or malicious PE executed.

Retained packages/raw official controls, private manifests, label packet, catalog and reproducibility source. Host C/D free at capture29,077,467,136/104,095,240,192bytes. No formal data/model/snapshot deletion. Full collection peak memory was not captured; an intermediate collector observation is not reported as a full-run peak. Global near audit491.48s is an audit cost, not detector throughput. The host exploratory jobs were serial, at most4known official files per disposable research job, ML tree cap1.5GiB / other tree512MiB, CPU/job120s and wall deadline110s per phase. All owned research workers exited with confirmed cleanup; actual full-tree peak was not captured. Study wall404.266s; two-profile ML per-file phase P50/P95=0.250/1.393s, three other engines0.016/0.205s. These phase costs exclude some batch startup/IPC and are not service latency or a controlled performance improvement. No production Worker replacement.

Local tests **285passed/6skipped/one existing anyio warning**. New selector3tests cover bounded prior/type/size/family exclusions and score/order independence; checksum368/368, package17/17, sourceblob626/626 and global audit are actual separate data evidence. A requested read-only reviewer failed due its usage limit; no successful independent code-review or guest-run claim is substituted. Research intake remains unactivated. Public-export tests and remote verification are recorded in publication evidence.

Next: continue automatic operational/proxy research without routine signoff; current availability discovery and raw intake once the existing startup gate is met; broaden unseen cross-family evidence and retain the98unobserved controls. Independent human admission is needed only for strict evaluation/final use. Version-confirm the guest rule/Clam assets for a future fully paired cohort. R6 delivers substantial raw control growth and an actual broader model tradeoff experiment; VM intake, strict admission and formal low-FPR acceptance remain open.
