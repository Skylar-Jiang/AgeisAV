# Windows交付、依赖与故障排除

## 发行内容及版本

稳定包0.2.0、独立候选0.2.1rc1，目标Windows11 x64；当前封板与回退边界见 [发布状态](#release)。独立 CPython 3.12.15 来自 Astral python-build-standalone 的固定20261013发行，下载按其SHA256SUMS校验；运行时不读取用户Python注册表、PYTHONPATH或user-site。应用依赖从当前固定环境按安装RECORD逐文件校验，完整版本/来源/许可见包内 `SBOM.json`、分发元数据与 `licenses`。

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

源码目录须保持清单绑定的原始字节。Windows 的自动 CRLF 转换可能让工作树与 Git 内容不同；
从已提交且审核过的公开提交导出到新目录，再将该目录作为 `--source`，不放宽摘要检查：

```powershell
git archive --format=zip --output "<new source ZIP path>" HEAD
Expand-Archive -LiteralPath "<new source ZIP path>" -DestinationPath "<new reviewed source directory>"
```

```powershell
.\.venv\Scripts\python.exe -m experiments.build_windows_delivery --source "<reviewed source export>" --frontend frontend/out --runtime "<pinned runtime archive>" --runtime-lock distribution/runtime-lock.json --output artifacts/my-windows-delivery
```

构建不会执行归档内容、不会复制整个工作区。依赖复制仅取闭包中已校验的分发文件，排除本地路径元数据、开发缓存和未审核启动钩子。ZIP路径/时间戳固定，可用同输入重复构建校验字节一致。包外 `.sha256` 用 `Get-FileHash -Algorithm SHA256` 核对；再用Verify脚本核对解压文件。

无害验收（开发环境，不要求最终用户安装Playwright）：设置 `AEGISAV_DELIVERY_ZIP` 为绝对ZIP路径，`AEGISAV_PLAYWRIGHT_MODULE` 为已安装Playwright模块路径，再运行 `node frontend/scripts/check-delivery.cjs`。可选 `AEGISAV_TEST_EXISTING_ML=1` 仅复用本项目已有私有模型路径，不打包资产。故障验收使用 `python -m experiments.check_windows_delivery_faults --package <extracted-package> --output artifacts/new-fault-evidence`，明确使用无害停滞/异常夹具，不是正常检测性能。所有测试只清理自身创建的临时目录。

备份/升级/回滚见用户手册。真正干净OS兼容性和完整native依赖法律审计不能由一个临时目录验证取代；本轮报告应明确实测Windows版本、隔离运行时及组件状态，不夸称全Windows兼容或完整SBOM法律认证。


外置模型路由和特征版本以 [ML 集成](#ml) 为准；源码首次安装见 [根 README](../README.md)。

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

<a id="ml"></a>

## 外置 ML 集成与冻结路由

整理日期：2026-11-22。当前 API 有认证；以下配置沿用冻结模型，不引入新权重或阈值。

### 选择策略

| 策略 | 原生 Win32 / .NET | 原生 x64 PE | 其他 PE 架构 |
| --- | --- | --- | --- |
| 默认 `general` | 官方通用 PE，阈值 0.5 | 官方通用 PE，阈值 0.5 | `not_applicable` |
| 可选 `win64_low_fpr` | 官方通用 PE，阈值 0.5 | 本地 Win64，阈值 0.9831222501035356 | `not_applicable` |

同时检查 Machine、PE32/PE32+ Magic 和 COM Descriptor。托管 x64 走通用模型；
ARM64/ARM64EC 不因 PE32+ 就套用 Win64。这是训练域的保守范围。
默认策略未自动换成 Win64；可选阈值沿用冻结验证周，不来自本轮良性样本或
已观察最终测试。两种策略都没有部署 FPR 保证，通用模型未独立校准低 FPR。

### 版本与特征接口

`experiments/build_ml_bundle.py` 仅组装已经取得并核对摘要的固定上游提取器、
warning 清单、官方通用权重和本地 Win64 权重，不打包 PE，不使用 pickle。
`models/ember2024/registry.json` 记录完整 SHA-256、2568 维特征、上游和数据修订、
模型版本、适用范围、阈值及来源。注册清单摘要加策略名构成 ML artifact ID，进入缓存键。
装载、缓存复用前、推理前及子进程都核对资产。变更需发布新清单并重启 API。
摘要校验不是发布者签名；正式部署需管理员安装、API 用户不可写的资产。
本轮 VM 功能验证使用单独非特权测试目录，未改变运行中评测的 root 代码。

特征接口接受字节，返回分数、schema 摘要、float32 向量摘要和提取/预测耗时，
不返回完整特征或文件内容。固定校验 LightGBM 4.6.0、NumPy 2.2.6、
scikit-learn 1.6.1、pefile 2024.8.26、signify 0.7.1。完整依赖及 Linux OpenSSL 3
所需既有 oscrypto 修订沿用安装和来源记录。

### 失败、并发和融合

- 每文件使用可丢弃子进程，最多两个并发；默认 60 秒推理预算包含排队、
  启动和模型加载。超时清理另有最多 4 秒预算。Windows 清理 worker 进程树，
  覆盖 venv 启动器创建的第二个 Python；清理无法确认则返回错误并禁用 ML，需重启。
- Linux 子进程限制 1.5 GiB 地址空间、60 秒 CPU、64 KiB 输出文件，禁止 core。
  输出使用短期临时文件，输入 PE 只经 stdin 传递。进程边界不构成恶意文件安全沙箱。
- 不适用为 `not_applicable`；缺资产/依赖为 `unavailable`；解析、维数、有限值、
  完整性和推理异常为 `error`；超时为 `timeout`。缺分数不当 0，不缓存失败，
  不把失败当良性，不返回原始异常文本。
- `fusion.policy_id=evidence-or-v1` 列出阳性与弃权引擎，每引擎保留证据。
  审定恶意 SHA 可裁决恶意，其他阳性形成可疑证据；可信良性 SHA 不能覆盖阳性。
  全阴性仍不等于已证实良性。ML 分数不是已校准的部署恶意概率。

### 源码服务配置

先取得合法授权的 registry、全部权重及匹配的独立 ML Python；公开仓库不提供这些私有资产。

```powershell
$env:AEGISAV_MODEL_DIR = '<absolute model directory containing registry.json>'
$env:AEGISAV_ML_PYTHON = '<absolute ML Python executable>'
$env:AEGISAV_ML_PROFILE = 'general'
.\.venv\Scripts\python.exe -m experiments.serve_local
```

通过已认证 `GET /v1/engines` 核对可用性，再用良性文件验证；状态探测不能代替真实 Worker 依赖检查。
也可安装固定 `.[ml]` 依赖，但必须匹配 registry 所记录实现，不能混用不同 EMBER 特征版本。
便携包用 `aegisav.desktop configure` 写包外配置，见 [部署](DELIVERY_RUNBOOK.md)。
旧 VM root 只读部署过程属于历史研究，不作为 Windows 安装命令；见 Git 历史中的部署运行说明。
Windows/WSL 只用良性控制，真实恶意 PE 仅留既有隔离 Ubuntu VM 静态分析。

<a id="release"></a>

## 发布状态与 0.2.1 封板要求

整理日期：2026-11-22；以下包完整性和回退核验来自 2026-10-23，不代表本次重新验收。

保留独立 `0.2.1rc1`，原稳定 `0.2.0` ZIP 保持原字节。现有证据足以支持受控课程演示和进入正式版封板准备；**当前还不是已验收的正式 `0.2.1`**。本次只复核实际资产、做轻量无害回放和分目录回退演练，没有重跑重型性能实验，没有改版本、原生实现、生产模型、阈值、融合或规则。

课程版可以明确承诺“便携核心 + 可选外置五引擎组件 + 离线行为证据”。如果承诺“首次解压即完整五引擎”或独立恶意准确率，当前证据不满足。严格未观察的恶意/良性原始 PE 准入仍是另一项研究目标，不能用工程验收替代；也不应把该研究目标混作一个范围明确的课程核心包能否发布的唯一判据。

### 本次实际完整性核验

读取现存 ZIP、包清单及原始研究 JSON，而非仅依赖文字报告：

| 项目 | 0.2.0 稳定包 | 0.2.1rc1 候选 |
| --- | ---: | ---: |
| ZIP 字节 | 31,507,698 | 31,547,622 |
| 展开字节 | 97,532,602 | 97,616,916 |
| 文件数 | 3,920 | 3,932 |
| 固定运行时 | CPython 3.12.15 | CPython 3.12.15 |
| SSDeep 后端 | Python | 显式原生候选 |

压缩体积增加 39,924 B（0.127%），展开增加 84,314 B（0.086%），文件数增加 12。仅比较核心包，不包含外置模型、ML Python 环境或 ClamAV 签名库的磁盘/下载成本。

- RC ZIP：`b4ae9d64f6fa27a2d4ff97a024771603f1e9d7d6022f71b6e99f0708036b9b04`，与旁置摘要、build-summary、ACCEPTANCE 一致。
- 稳定 ZIP：`caba52afdbcfb9bc597447b7cb8ac75eb025972b400639a389d3565cf15c6e43`，与原旁置摘要一致；回退演练后再次一致。
- 使用既有 `aegisav.desktop.verify_package` 检查 RC 解包目录成功：清单列出 3,931 文件，另加清单本身；未发现多余/缺失/摘要不符文件。逐项读取实际 RC ZIP 的同一清单，3,931 项全部一致，ZIP 无多余项，合计 3,932 文件、97,616,916 B。
- 包内 DLL 为 15,872 B，SHA-256 `675e31d72a853ed1eefd95bf0103d34f7d253fee0a1e58c449bc951f3c2421aa`；与研究汇总和原生清单一致。
- RC 清单版本仍为 `0.2.1rc1`，打包源码提交 `4172afe1b3a3faa95965a453b3d68259b785cd88`、后端 `native`、策略 `evidence-or-v1`。后续证据提交和当前工作树不能自动替代这个已冻结 ZIP 的身份。

原件位于 `artifacts/windows-delivery-20261019-release` 和 `artifacts/windows-delivery-20261022-rc1`。本次没有覆盖或重新生成这两个 ZIP。

### 已有证据逐项对照

| 验收项 | 可核对的实际证据 | 结论及边界 |
| --- | --- | --- |
| 首次安装/便携运行 | `artifacts/native-ssdeep-rc-20261022/browser/check.json`，28 项无失败，含 Unicode/空格目录、宿主 Python 污染隔离、无 Node、认证、篡改拒绝、受控卸载和私有报告保留 | 核心便携路径已验；初次测量中的 ClamAV 有现存 sidecar，不等于 ZIP 内置该组件 |
| 健康五引擎 | `reports-healthy-complete.json`：22 行、11 对完整报告，`pairs_equal=11`、`completed=true`、清理确认；浏览器外置模型配置后五引擎均实际调用 | 是可选外置组件的集成和报告等价证据；11 对中 LightGBM 对 2 个良性开发文件 matched，不能说所有控制都阴性，更不能说零误报 |
| 原生一致性 | `parity-final.json`：235 项、全部 equal、completed；范围 0–16 MiB，另有并发/超限检查 | 原生哈希回归证据充分；不等于恶意识别准确率或任意新平台 ABI 兼容性 |
| HTTP 配对成本 | `http-healthy.json`、`http-unavailable-complete.json` 均 completed；每层 18 次观察（9 对任务），完整报告一致、SQLite 重开一致、自有服务/Worker 关闭 | 各自包内 Python/Worker，共同控制器；不是两套独立桌面服务启动全周期的随机化对照 |
| 原生故障隔离 | `faults/check.json`：ABI 错误、崩溃、超时、运行中取消、96 MiB Job 拒绝 256 MiB 申请，5 项清理及后续 Worker 恢复 | 无害故障注入；错误/弃权保留，不生成阴性报告 |
| 交付故障 | `delivery-faults/check.json`：5 通过、0 失败，含取消、解析失败、服务强退/Job 清理/SQLite 恢复、队列 429、注入截止 | 正常检测与故障测试分开；不借故障测试声称检出能力 |
| 回退 | 旧证据仅显示 RC 自身 Stop/Start；本次新增实际 RC 停止 → 同一空闲端口启动旧 ZIP 的演练，见下节 | 分包、分配置可回退已实际核验；共享配置/数据库跨版本迁移未测，也不需要让课程默认采用共享配置 |

完整历史方法和保留失败见 [原生 RC 研究报告](PERFORMANCE.md)，聚合数值见 [机器可读汇总](benchmarks/native_rc_20261023.json)。本次没有把历史完整回归 `357 passed / 8 skipped` 写成本轮重新执行；新增课堂脚本的验证单独记录。

### 性能收益和首次运行成本分开报告

以下来自已有交替 3 轮 HTTP 包内 Worker 实验，本次仅复核原始完成标记与报告配对。P95 实际为小样本最大观察值，不能当生产尾延迟保证。

| ClamAV | 场景 | 旧 → RC P50（秒） | 解释 |
| --- | --- | ---: | --- |
| 健康 | 小文件 | 3.380 → 3.406 | 轻微变慢 0.8% |
| 健康 | 大文件 | 25.537 → 12.595 | 降低 50.7% |
| 健康 | 混合批次 | 11.271 → 10.666 | 降低 5.4%；4 个提交项含一次正常重复复用 |
| 不可用/弃权 | 小文件 | 6.864 → 6.354 | P50 改善，但 P95 10.674 → 14.601；平均吞吐下降 12.1% |
| 不可用/弃权 | 大文件 | 24.235 → 14.136 | 降低 41.7% |
| 不可用/弃权 | 混合批次 | 22.711 → 19.778 | 降低 12.9% |

大文件收益明确；不能声称全场景加速。服务/Worker 的采样 RSS、外置 clamd 和 ML 内存不能将不同时刻的最大值直接相加当总峰值。浏览器验收中的 RC 解压约 43.5 秒、启动约 18.1 秒、重启约 19.8 秒；旧包历史约 5.9/10.5/12.7 秒，但记录并非同期配对，RC 浏览器验收部分还与训练并行，**不能据此推导 RC 安装/启动性能退化比例**。外置 ClamAV 的单次初始加载约 20–24 秒也应单列。

### 本轮新增的无害回退演练

在源码仓库外新建独立目录，清理客户端继承的 AEGISAV/Python 配置，实际使用各包自带 Python 和原有桌面控制器。旧 ZIP 经路径检查后解压到新的目录；原稳定目录和 ZIP 均未改。选择一个当时未占用的回环端口，顺序执行：

1. RC `verify → start`，新私有配置目录，上传已安装 notepad 的字节进行扫描，确认报告包含原生 SSDeep 版本；`stop` 后确认端口释放。
2. 同一端口启动全新解压的旧 `0.2.0`，另一个新私有配置目录；上传同样字节，确认 Python SSDeep 版本；`stop` 后确认端口释放。
3. 两个包的全部清单文件摘要在运行后仍一致；再次验证原稳定 ZIP 摘要。

两轮任务均为 completed，SHA256/fuzzy/YARA-X 均 no_match，ClamAV 与 LightGBM 均明确 unavailable。没有启动扫描目标 PE、clamd、VM 或任何攻击命令。此次实际冷配置结果进一步确认：核心包可以完成扫描流程，但首次解压并无开箱完整五引擎。没有配置外置模型，不应把 unavailable 解释成安全结果。

执行脚本和 JSON 证据保留于仓库外 `D:\2026fall\badcode\aegisav-course-release-audit-20261023\rollback_check.py`、`rollback.json`；私有配置及报告留在同目录独立子目录，不公开访问密钥或扫描对象摘要。本次测试的是课程推荐的**分目录回退**，没有声称验证共享 profile 迁移或跨机器部署。

### 正式 0.2.1 尚需什么

| 待办 | 当前状态 | 可核验的封板要求 |
| --- | --- | --- |
| 确认交付承诺 | 目前为核心包 + 可选外置组件 | README/启动说明明确缺组件时弃权；若要求开箱五引擎，须另做有许可和资产准入的完整分发及干净安装验收 |
| 正式包身份 | 只有 RC，源码项目版本仍 0.2.0；不在本任务中改 | 在获准发布时冻结正式 0.2.1 源码/运行时/原生来源，产生新的独立 ZIP、清单和摘要；不把 RC 改名冒充新构建 |
| 正式字节验收 | RC 已有完整功能/故障证据 | 对新的正式 ZIP 做包完整性、干净首次运行、组件缺失/健康、取消恢复、持久化和分目录回退检查；只重跑因新字节而必要的验收，不盲目重做既有重型研究 |
| 目标课程电脑 | 当前主要一台 Windows x64 主机，3 轮成本样本 | 在实际教学电脑至少一次标准用户首次运行/小文件/停启检查；记录企业策略对未签名 DLL 的拒绝；没有此证据时限定已测平台承诺 |
| 性能表述 | 大文件改善，小文件波动/部分尾延迟退化 | 保留完整表和分层，不宣传“所有场景提速”；跨机器改善若要成为卖点，应先补配对数据 |
| 准确率表述 | 历史开发控制、操作性代理及少量新增 Windows 控制 | 不宣传独立泛化准确率/总体 FPR/20 万原始 PE 完成；此目标继续按训练重叠、来源/家族、时间与标签审计补齐 |

DLL 未做发行商代码签名；它是目标机器策略验收事项，不把“未签名”自动写成所有课堂环境都无法运行。现有两条 Sigma 足够完成 [无害课堂实验](COURSE_GUIDE.md)，不应为了正式版本数量而仓促扩大规则或修改检测阈值。

建议的当前状态：**RC 保留、可演示、正式版待封板；旧稳定包随时可用**。后续发布须创建新正式制品并针对该制品验收，不能直接覆盖旧稳定交付。
