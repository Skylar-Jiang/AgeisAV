# Windows交付、依赖与故障排除

## 发行内容及版本

版本0.2.0，目标Windows11 x64。独立 CPython 3.12.15 来自 Astral python-build-standalone 的固定20261013发行，下载按其SHA256SUMS校验；运行时不读取用户Python注册表、PYTHONPATH或user-site。应用依赖从当前固定环境按安装RECORD逐文件校验，完整版本/来源/许可见包内 `SBOM.json`、分发元数据与 `licenses`。

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
