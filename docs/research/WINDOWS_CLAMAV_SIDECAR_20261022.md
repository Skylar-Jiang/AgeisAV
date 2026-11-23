# Optional Windows ClamAV sidecar, 2026-10-22

This experiment uses a separate, owned foreground Windows process on
`127.0.0.1:3310`. It creates no Windows service, firewall rule, global installation,
or VM. The optional runtime and signatures live only under `artifacts/clamav` and
are not part of the portable application release. Only harmless fixtures and
installed benign files may be scanned on this host.

## Provenance

The [official download page](https://www.clamav.net/downloads) lists 1.5.4 as the
latest release and 1.4.6 as LTS on the observation date. The existing
`artifacts/clamav/clamav-1.5.4.win.x64.zip` is 225,774,978 bytes with SHA-256
`0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395`.
Its [official detached signature](https://www.clamav.net/downloads/production/clamav-1.5.4.win.x64.zip.sig)
was checked using Git's GPG and an isolated experiment keyring, following the
[official verification instructions](https://docs.clamav.net/manual/Installing.html#verifying-clamavnet-downloads-with-gpg).
`GOODSIG` and `VALIDSIG` identify Talos key fingerprint
`5BADCA2665EF59DCF8A23D8B707F0DB480836771`, loaded from the
[official public key](https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg).
The user keyring was not used. File digests and verification output are retained
in `artifacts/clamav/windows-sidecar-provenance.json` and
`artifacts/clamav/archive-verification.txt`.

The ZIP has 214 entries totaling 939,657,665 expanded bytes and contains no virus
databases. The helper extracts 51 runtime/config/license files totaling
135,136,933 bytes, omitting PDBs, import libraries, headers, and the HTML manual.
Every extracted file's SHA-256 and size are recorded in `runtime-manifest.json`.
The extracted `clamd.exe`, invoked with the explicit local configuration, reports
`ClamAV 1.5.4`. A focused check found no existing host daemon, 3310 listener,
default ClamAV install/registry entry, or usable host database. Existing guest
measurements were not reused as Windows results.

## Run locally

The helper pins the verified ZIP digest; a different release needs a new official
verification and deliberate update. Run from the repository with its Python:

```powershell
.venv\Scripts\python.exe experiments\windows_clamav_sidecar.py prepare --archive artifacts\clamav\clamav-1.5.4.win.x64.zip --root artifacts\clamav\windows-1.5.4
.venv\Scripts\python.exe experiments\windows_clamav_sidecar.py update --root artifacts\clamav\windows-1.5.4 --seconds 1200
.venv\Scripts\python.exe experiments\windows_clamav_sidecar.py run --root artifacts\clamav\windows-1.5.4 --seconds 1800
```

`prepare` refuses to overwrite a runtime directory. `update` invokes official
FreshClam once, with signature database load testing enabled. Initial acquisition
requires network access and a substantial download. Preserve the databases for
incremental updates. Inspect its log and verify each CVD using both
`sigtool --info=...` and `sigtool --verify <CVD> --cvdcertsdir=<runtime>\certs`
before starting the daemon. Do not run updates during paired measurements.

`run` refuses an occupied 3310 port, writes `ready.json` only after VERSION
responds, and owns only its child process. It stops that child on Ctrl+C, timeout,
or low available memory, and removes the ready marker. Logs remain in `logs/`.
The core adapter uses VERSION and INSTREAM on this existing endpoint. Missing or
stopped ClamAV must still be reported as unavailable, never as a negative result.

The configuration fixes `MaxThreads 2`, `MaxQueue 4`,
`ConcurrentDatabaseReload no`, `StreamMaxLength 64M`, `MaxFileSize 64M`,
`MaxScanSize 128M`, `MaxEmbeddedPE 64M`, `PCREMaxFileSize 64M`, and
`AlertExceedsMax yes`. These budgets cover the application's 16 MiB upload limit;
the existing adapter treats limit alerts as errors. Other scan settings retain
the upstream defaults. TCP has no built-in authentication, so the explicit
loopback binding is required; see the [official scanning guide](https://docs.clamav.net/manual/Usage/Scanning.html).

## Resource boundary and interpretation

Initial host available RAM was 8.40 GiB, with 61.85 GiB free on D:. The helper
samples available physical RAM every 0.5 seconds and terminates its owned child
if less than 2 GiB remains. This is a sampled guard, not a hard process memory
limit. The [official resource guidance](https://docs.clamav.net/manual/Installing/Docker.html#memory-ram-requirements)
recommends 3 GiB minimum and 4 GiB preferred; a concurrent signature reload can
temporarily double engine memory. The updater stays stopped during measurements.

## Observed healthy smoke

FreshClam completed with exit code 0. The updater's sampled minimum available RAM
was 5,848,494,080 bytes. The frozen database contains main 63, daily 28161, and
bytecode 339. All three embedded CVD signatures and all three detached `.sign`
certificate signatures verified successfully. Seven database/state files total
112,825,365 bytes; SHA-256 values are retained in `database-manifest.json` and
verification output in `database-verification.txt`. Runtime plus database files
total 247,962,298 bytes, excluding configurations and logs.

The owned Windows daemon answered VERSION after one observed 24.078-second
startup. This is not a controlled startup benchmark. The existing Python adapter
then returned `no_match` for the installed 360,448-byte System32 notepad file and
`matched` / `Eicar-Test-Signature` for a harmless 68-byte EICAR control constructed
only in memory. Its JSON is retained in `adapter-smoke.json`. No fixture program
was executed. These two calls warm the daemon and must be disclosed by any later
warm-cache measurement. The daemon's port and available memory were checked
after startup; it listened on loopback only.

This sidecar supplies actual Windows engine availability for the separately
recorded paired tests. Availability, startup time, and harmless scan outcomes
cannot establish malware recall or false-positive rate. No protected cohort,
model, production threshold, rule, stable release, or VM was changed here.
