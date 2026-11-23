# Windows交付、依赖与故障排除

## 发行内容及版本

稳定包0.2.0、独立候选0.2.1rc1，目标Windows11 x64；当前封板与回退边界见 [发布状态](RELEASE_STATUS.md)。独立 CPython 3.12.15 来自 Astral python-build-standalone 的固定20261013发行，下载按其SHA256SUMS校验；运行时不读取用户Python注册表、PYTHONPATH或user-site。应用依赖从当前固定环境按安装RECORD逐文件校验，完整版本/来源/许可见包内 `SBOM.json`、分发元数据与 `licenses`。

内含源码、编译前端、SHA/TLSH/SSDeep、YARA-X1.20.0、现有246规则、两条Sigma规则及其来源/许可。保留静态阈值和策略。模型权重/ML环境、ClamAV及病毒库不在包内，不含真实恶意样本、密钥、本地数据库或私有研究标签。

第三方遵循各自许可（包括Python/第三方运行时、BSD/MIT/Apache、规则DRL）。AegisAV自身尚未新增统一开源许可证；公开可见不等于统一MIT授权，若要另行授予公共再分发许可应由作者决定。此包供本项目已授权试用/课程交付。

## 外部ML组件（可选）

核心即使无模型也能扫描并明确弃权。若已有本项目校验通过的冻结registry和隔离ML Python：

```powershell
.\runtime\python.exe -I -B -m aegisav.desktop configure --model-dir "<absolute existing model directory>" --ml-python "<absolute ML Python exe>"
```

配置只保存在包外私有目录，不复制权重，不改变原文件或阈值。停止再启动后生效。需要原锁定LightGBM4.6.0、numpy及特征实现等ML依赖；目录必须包含完整registry及其所有文件。资产核验失败/特征适配器不符会弃权。删除私有config前先备份，不在启动时静默改模型。

## ClamAV（可选）

由用户通过ClamAV官方渠道安装Windows版本、接受其开源许可并使用合法病毒库。按官方文档配置clamd只监听127.0.0.1:3310，启用INSTREAM，大小限额至少覆盖本产品16MiB上传，并预留相应内存。需要freshclam的有效数据库及版本核验。

本包不会自动下载安装/修改/停止系统ClamAV、不会复制VM病毒库，也不会让缺少它时伪装阴性。它必须作为外部可信服务运行；缺失时UI明确unavailable。本轮宿主的可用性以验收报告实测为准，不沿用旧VM的版本作为该宿主证据。

## 常见问题

- 端口占用：没有停止其他应用。用 `Start-AegisAV.cmd --port 3419` 选择空闲回环端口；Access-Key沿用同一私有目录，Stop脚本自动读取已登记端口。
- 启动内存/磁盘不足：先自行释放确定闲置资源，不降低门槛或关闭其他项目；不会替你终止WSL/VM/Agent。
- 文件完整性失败：不要修改包内代码、依赖或添加配置。重新解压已核验ZIP到新目录；私有报告留在外面。校验不能替代可信发行源或代码签名。
- 连接失败：核对浏览器地址、此包的私有密钥和服务状态。密钥不必重申请，只由本地应用创建；不要发送到聊天或日志。`Access-Key.cmd`仅在本机记事本打开它。
- 管理员启动被拒绝：使用普通用户双击，解析器禁止提权。不要以管理员身份修复这个检查。
- 数据库锁：同一私有目录只允许一个实例，不删除锁文件强行绕过。先用对应版本Stop脚本正常退出。
- 数据库损坏/未来schema：保存私有目录、不要覆盖或自动降级；从已停止服务时制作的备份恢复。找不到原始上传不会假装续扫。
- 模型缺失/错误：先看资产页与弃权原因；不能因模型分数空白就判断安全。不要回填待测SHA或调低阈值。
- 行为导入422/413/504：检查UTF-8和规范格式、4MiB/1,000事件上限，适当分割日志。原生EVTX先可信导出，超时无结论。
- Windows安全提示：此项目脚本/ZIP没有商业代码签名。先从可信来源核对摘要，不要求关闭Defender/SmartScreen，也不提供执行策略绕过。若系统阻止，保留提示并人工核查。

服务日志在私有目录 `service.log`（滚动上限约两份1MiB），不要公开包含私人路径的完整日志。关闭浏览器不退出服务；Stop脚本没有按进程名强杀的回退。

## 构建复现

先从当前公开分支筛选源码，安装开发固定依赖并构建前端；取得 `distribution/runtime-lock.json` 指定的运行时归档并核对SHA。

```powershell
.\.venv\Scripts\python.exe -m experiments.build_windows_delivery --source "<reviewed source export>" --frontend frontend/out --runtime "<pinned runtime archive>" --runtime-lock distribution/runtime-lock.json --output artifacts/my-windows-delivery
```

构建不会执行归档内容、不会复制整个工作区。依赖复制仅取闭包中已校验的分发文件，排除本地路径元数据、开发缓存和未审核启动钩子。ZIP路径/时间戳固定，可用同输入重复构建校验字节一致。包外 `.sha256` 用 `Get-FileHash -Algorithm SHA256` 核对；再用Verify脚本核对解压文件。

无害验收（开发环境，不要求最终用户安装Playwright）：设置 `AEGISAV_DELIVERY_ZIP` 为绝对ZIP路径，`AEGISAV_PLAYWRIGHT_MODULE` 为已安装Playwright模块路径，再运行 `node frontend/scripts/check-delivery.cjs`。可选 `AEGISAV_TEST_EXISTING_ML=1` 仅复用本项目已有私有模型路径，不打包资产。故障验收使用 `python -m experiments.check_windows_delivery_faults --package <extracted-package> --output artifacts/new-fault-evidence`，明确使用无害停滞/异常夹具，不是正常检测性能。所有测试只清理自身创建的临时目录。

备份/升级/回滚见用户手册。真正干净OS兼容性和完整native依赖法律审计不能由一个临时目录验证取代；本轮报告应明确实测Windows版本、隔离运行时及组件状态，不夸称全Windows兼容或完整SBOM法律认证。


外置模型路由和特征版本以 [ML 集成](ML_INTEGRATION.md) 为准；源码首次安装见 [根 README](../README.md)。

## 受控 Windows ClamAV sidecar（2026-10-22 历史方案）

This experiment uses a separate, owned foreground Windows process on
`127.0.0.1:3310`. It creates no Windows service, firewall rule, global installation,
or VM. The optional runtime and signatures live only under `artifacts/clamav` and
are not part of the portable application release. Only harmless fixtures and
installed benign files may be scanned on this host.

### Provenance

The [official download page](https://www.clamav.net/downloads) listed 1.5.4 and 1.4.6 LTS on 2026-10-22; these are historical pins, not a current-version recommendation. The existing
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

### Run locally

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

### Resource boundary and interpretation

Initial host available RAM was 8.40 GiB, with 61.85 GiB free on D:. The helper
samples available physical RAM every 0.5 seconds and terminates its owned child
if less than 2 GiB remains. This is a sampled guard, not a hard process memory
limit. The [official resource guidance](https://docs.clamav.net/manual/Installing/Docker.html#memory-ram-requirements)
recommends 3 GiB minimum and 4 GiB preferred; a concurrent signature reload can
temporarily double engine memory. The updater stays stopped during measurements.

### Observed healthy smoke

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
