# Prospective Windows operational controls, 2026-10-22

The candidate will be assessed on the complete 33-PE inventory in the previously
GPG-verified official ClamAV 1.5.4 Windows archive. These are prospective new
operational presumed-benign controls. They are not a strict independent final
cohort or a deployment false-positive-rate estimate. Legitimate prior execution
of clamd/freshclam is disclosed; no detector has scored these input files before
this study. The single release includes third-party components and does not
establish source independence. Full upstream model training membership and
near-training relationships remain unknown.

Before any score, `--prepare-only` verifies every `.exe`/`.dll` against the pinned
archive's extracted runtime manifest, freezes all 33 identities and the size
gate, and retains four files exceeding the product's 16 MiB limit as exclusions.
Within-release exact duplicates and exact matches in available historical R7,
the old 600+300+600 benign reports, and local FIT/validation SHA metadata are
retained in the manifest and excluded from prospective scoring. Missing audit
sources remain explicit. No final metadata, feature or prediction arrays, raw
protected data, or the 151 protected controls are opened. SHA metadata loading is
restricted to the literal development names `meta_fit.npz` and
`meta_validation.npz`; only their `sha` member is read.

The private freeze records source/rule/native DLL digests, the external frozen
model registry and assets, runner and measurement-helper identities, and the
general profile's fixed 0.5 threshold. The scoring command requires this exact
unchanged freeze. No threshold, model, rule or candidate selection is performed.
Inputs are read statically and never executed by this study.

Preparation is authorized before the compute slot; scoring is prohibited until
the parent coordinator grants COMPUTE GO after paired performance measurement:

```powershell
.venv-ml\Scripts\python.exe -B -m experiments.evaluate_windows_controls --source-root artifacts\native-ssdeep-rc-20261022\source --prepare-only
# Only after the coordinator grants COMPUTE GO; use its current owned clamd PID:
.venv-ml\Scripts\python.exe -B -m experiments.evaluate_windows_controls --source-root artifacts\native-ssdeep-rc-20261022\source --compute-go --clam-pid <owned-pid>
```

The controller uses the psutil-enabled ML environment, while the actual static
scanner runs under the ordinary disposable Windows Job using the core Python
environment. Only the explicitly frozen native provider is selected. Each
eligible file receives one scan with the existing general model, actual loopback
ClamAV and frozen rules. Previous harmless scans warmed ClamAV. Input bytes are
loaded before timing; this is process-worker latency through cleanup, without
HTTP upload, repetitions or a warmup exclusion. P50/P95 use the existing nearest
rank helper. Throughput includes successful report timings only; failed attempt
times remain separate in private rows. This is not a paired performance claim.

Freeze and per-attempt checkpoints remain under
`artifacts/native-ssdeep-rc-20261022/windows-controls/`. Every attempt is saved,
including exceptions. Unconfirmed worker cleanup stops subsequent scoring.
Automatic resume/retry is refused to preserve the original prospective pass.
Each input's full identity is verified again before scoring. Engine errors,
timeouts, unavailability and missing output remain abstentions, separate from
matched status and risk-signal alerts. Fusion suspicious-or-malicious and
malicious-only counts are distinct; no alert does not establish a clean verdict.

The public `docs/benchmarks/windows_controls_20261022.json` contains aggregates
only: cohort/exclusion counts, exact-audit coverage, engine status/matched/alert
counts, fusion alerts, failures/abstentions, completed latency and throughput,
and sampled memory. Private paths, raw-input SHA identities, reports and errors
are not published. ClamAV process memory is sampled after each attempt and
reported separately from the scanner's sampled owned process tree; maxima are
not summed and short-lived peaks may be missed. The daemon's reported peak
working set can include earlier work. The study neither stops nor updates the
owned daemon. Independent accuracy, recall and population FPR remain unmeasured.

## Actual prospective pass, 2026-10-23

The study/protocol identifier and aggregate's `date` retain 2026-10-22; the
private manifest was frozen at 2026-10-23T00:30:18.652281Z and scoring occurred
after the paired healthy-sidecar HTTP study on 2026-10-23. All seven exact-audit
sources were available. Four files exceeded16MiB; one additional size-eligible
VC runtime DLL had an exact local FIT match and was excluded before scoring.
Thus33 inventory files yielded28 prospective operational controls, not29.

All28 completed. Every one of the five engines returned `no_match` on all28;
fusion suspicious-or-malicious alerts0, malicious-only verdicts0, engine
abstentions0, failed attempts0, cleanup failures0. These are observed control
counts, not a measured population FPR or an independent final result.
No new malware recall was measured. No input was executed by this study.

Single-pass worker-through-cleanup P50/P95=3.009/4.074s, throughput0.2948
completed files/s. Sampled owned-tree maximum359,366,656B, separate clamd
sampled maximum1,011,130,368B and reported peak working set1,258,913,792B.
The maxima have different scopes and are not summed. The native RC summary
also derives PE architecture/type counts from the frozen control headers.
The single publisher release and remaining unknown upstream training/near-copy
membership severely limit representation; zero observed alerts does not close
the low-FPR course acceptance gap.
