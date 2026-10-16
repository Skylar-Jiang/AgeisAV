# Stage E 首轮：资源门槛、独立性审计与冻结结果分层（2026-10-16）

记录日期采用UTC 2026-10-16；收尾时本地上海已为2026-10-17。

## 范围与结论

以公开 `d434f49` 及保留私有资产的当前工作副本为基础。本轮完成 E2/E3 的保存证据重算与来源研究，E4 完成成本归因准备；E1 客户机验收仍未完成。没有新增原始恶意 PE，没有启动 VM，没有变更模型、规则、阈值、任务层或 Linen。

材料来源是既有静态报告、冻结采集清单、采集前近重复审计及公开原始研究报告。数值重算已验证；原始 PE 未重新扫描。历史扫描使用 release `c699902f19640593`，不能作为 C/D 新进程层的运行验收。

## E1：资源与安全

只读 `vm/Get-TaskGuardReadiness.ps1` 于 2026-10-16 15:47:27 UTC 返回：

- VM 8192 MiB，宿主机可用 6,881,472,512 B（6.41 GiB），要求 10 GiB，差 3.59 GiB。
- `deferred_memory`，VMX 离线配置检查通过；客户机未启动、未验证。共享/剪贴板/拖放的宿主机配置不替代客户机隔离检查。
- 未发现可明确安全关闭的闲置 AegisAV Worker。其他项目机器人、用户 Chrome、WSL 和 Codex 工具进程均未终止。上一轮预览 PID 已退出，本轮不宣称预览服务仍在运行。
- C 盘/D 盘本轮开始可用约 26.79/100.39 GiB。未删快照、模型、正式数据或缓存目录。

历史 61 个每 5 秒 cgroup 记录中，60 个同时具有 scan 与 clamd 的 MemoryCurrent，1 个缺失。两服务同一采样时刻合计最大 **1,816,391,680 B（1.69 GiB）**；此前分别峰值不是同时总量。监控开始晚于任务，采样可能漏峰；不包含客户机 OS、当前 API 与新 pidfd 监护层。RLIMIT_AS 是虚拟地址空间上限，不能直接当作 RAM 预算。

因此本轮没有依据推荐缩小 VM RAM，也未改配置。8+2 GiB 门槛保留。待主机资源满足后，先以无害夹具验证 pidfd/进程组、取消/超时/服务崩溃、SQLite/权限、模型完整性、cgroup 总内存/OOM、隔离及 ClamAV，再允许新进程层读取真实 PE。

## E2：数据规模和独立性

| 证据层 | 当前数量 | 限制 |
| --- | ---: | --- |
| MalwareBazaar 两批去重候选 | 120 | 首批29 + 第二批91；不计第二批原100中的9个首批重叠 |
| 已保存五引擎扫描的不同 PE | 104 | 首批24 + 第二批80，SHA集合交集0 |
| 第二批未扫描 | 11 | 下载失败继续保留，不算阴性 |
| 两批独立可信恶意真值 | 0 | MB 来源与引擎共识不自动升级标签 |
| 新官方良性候选 | 149 | 单一 Sysinternals 来源，全部 presumed_benign，未做完整五引擎配对 |
| 既有良性代理扫描 | 1500，去已知训练重叠后1450 | 旧开发数据，不能作为新最终集 |
| 本轮新增主要案例证据候选 | 2 | 仅报告元数据；原始文件0、标签升级0 |
| 新有效独立最终测试 PE | 0 | 未冻结出可验收的独立真值集 |

第二批80 PE：Win64 36、Win32 22、.NET 22；24个非空来源家族名、18个未报告家族。来源日期为2026-10-12/13，不能当作全球首次发现日期。Phorphiex/Phorpiex 保留原始拼写，没有凭名称擅自合并。PrintSpoofer、CoinMiner 等还存在工具用途/策略定义问题，不能看到来源标签就认作已确认恶意。

近重复固定筛查 TLSH≤40 / SSDeep≥80：80文件形成61个簇，大小为51×1、8×2、1×4、1×9；6个簇的11个文件关联既有观察数据。筛查簇不是被证实独立的样本，更不是自动成立的置信区间单位。

149个官方良性候选：有效发布者签名149；可靠全球首次发现时间0；本地 Win64 fit/validation/test SHA 重叠均0，但完整上游模型训练成员尚未核实。301条近重复边形成81个簇，与既有数据筛查近重复0。单一工具套件和簇相关性限制代表性；81不是认证独立数量。不得把149次签名验证当作149份独立良性真值。

### 来源研究与具体后续候选

- [DikeDataset](https://github.com/iosifache/DikeDataset)：包含原始PE/OLE，但恶意度来自加权VirusTotal票数；不能替代独立真值。原PE来源标注CC BY4.0，实际使用仍需核对具体文件来源/条款。
- [SOREL-20M](https://github.com/sophos-ai/SOREL-20M)：作者说明恶意PE的Machine/Subsystem被置零，良性原文件不公开。不能将改写文件冒充相同原始PE的五引擎配对；使用前另须核对数据条款。本轮未下载。
- [BODMAS](https://github.com/whyisyoung/BODMAS)：官方README明确为disarmed malware，不是获得未改写原始PE的直接替代方案；另有访问要求与历史时间/训练重叠问题。此前仅描述“研究者申请”不足以说明原始文件可比性，本轮补正。
- [capa-testfiles](https://github.com/mandiant/capa-testfiles)：混合能力测试夹具，不是统一恶意真值集；不在Windows克隆含原始样本的仓库。
- 两个新的个案候选来自 [Unit 42 HazyBeacon技术报告](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/) 与 [SAP NetWeaver后续载荷分析](https://unit42.paloaltonetworks.com/threat-brief-sap-netweaver-cve-2025-31324/)。分别有精确SHA关联的后门行为与Win64 reverse HTTP stager技术证据，优先级高于单纯来源标签。仅登记私有候选：仍需合法可用性、原始SHA/PE校验、训练重叠/近重复和复核；未加入哈希检测库，未宣称新增可评测真值。

最终集保持空且未暴露检测结果。已观察的两批104 PE继续是开发分析集。没有用它们调规则、模型或融合阈值。

## E3：同文件、同版本的实际保存结果

| 引擎/策略 | 阳性信号/80可扫描PE | 91项中未完成 |
| --- | ---: | ---: |
| SHA-256 | 0 | 11 |
| TLSH/SSDeep | 0 | 11 |
| YARA-X | 0 | 11 |
| ClamAV | 20 | 11 |
| LightGBM | 76 | 11 |
| 五引擎OR | 76 | 11 |
| 诊断性 signature AND ML | 20 | 11 |

80个已扫描文件各引擎均完成；上述11项是未取得原文件。ML独有56、Clam独有0、四者签名联合独有0、全部阴性4。“独有”仅在五引擎都完成的文件上定义。

| 架构 | 文件 | Clam阳性 | ML阳性 | ML独有 |
| --- | ---: | ---: | ---: | ---: |
| .NET | 22 | 7 | 22 | 15 |
| Win32 | 22 | 5 | 21 | 16 |
| Win64 | 36 | 8 | 33 | 25 |

来源家族信号例如 Formbook 7项ML7/Clam0、Vidar 8项ML8/Clam2、NanoCore 4项ML4/Clam4、WannaCry 4项ML4/Clam4。全阴性的来源类别为DonutLoader、GuLoader、PrintSpoofer及未报告家族各1；仅为需复核案例，不能直接称为4个漏报。

排除11个历史近重复关联文件后的敏感性分析：69可扫描+11未完成，ML65/Clam12/OR65、ML独有53。没有把此后验子集重新包装成最终集，也不选择新的融合策略。

覆盖原因核查：哈希库仅4个StealC恶意参考，TLSH/SSDeep各2个参考；第二批无同名StealC来源类别。246个YARA规则文件中212个description含ransomware；Formbook/Vidar/AsyncRAT/NanoCore/GuLoader未见同名文件或description，WannaCry有1个。名称核查不是适用性证明，也不能证明运行错误；历史matched/no_match说明引擎完成，既有无害匹配测试仍负责实现正确性。本轮未通过回填待测SHA或宽泛规则制造命中。

所有恶意来源标签仍unknown；**Recall、Precision、F1、ROC/PR-AUC、固定低FPR Recall均不报告**。旧1450良性代理上OR为0阳性、1弃权（1449完成），其保存Wilson区间上界约0.2644%，且代理标签和近重复使独立二项假设存疑。不能据此宣布FPR≤0.1%。即使理想独立可信良性且零误报，单侧95%精确上界≤0.1%也至少需要2995个完成样本；真实部署还需代表性和相关性审计。

## E4：成本定位，尚未部署复用优化

第二批80文件历史冷应用缓存、逐文件Worker的墙钟P50/P95 **3.126/7.375秒**，总323.14秒约0.248文件/秒；不与新Guard或不同文件集做提速比较。

| 引擎/阶段 | P50 ms | P95 ms |
| --- | ---: | ---: |
| SHA | 1.182 | 13.920 |
| fuzzy | 177.246 | 2798.265 |
| YARA-X | 12.467 | 43.792 |
| ClamAV | 544.444 | 2810.574 |
| ML含边界开销 | 1407.643 | 3575.709 |
| ML特征 | 159.271 | 2333.826 |
| ML推理 | 0.534 | 0.989 |
| ML逐文件未归因残差 | 1222.240 | 1348.139 |

残差逐文件计算后取分位数，不是拿不同阶段P50相减。它包含完整性校验、作用域解析、Python导入、模型加载、通信及退出等，不等于冷启动单项，也不是可直接节省的复用时间。引擎计时有重叠，不相加为pipeline。所有80残差非负，独立审查重算一致。

下一次VM允许的无害实验应先细分这些成本，再比较每文件新进程与受限可杀死复用Worker。必须同时复验取消、超时、进程树/cgroup清理和完整特征/模型分数，未证实收益前不改生产实现。

## 实现、验证与失败记录

新增 `experiments/expansion_diagnostics.py`：严格匹配冻结传输清单字节哈希、采集/扫描release、SHA/大小、无应用缓存、引擎资产及完成ML契约；输出聚合架构/来源家族/大小/日期、近重复关联敏感性、弃权及成本。没有原始PE读取路径。

首次运行被来源哈希检查拒绝：误传100项研究JSONL。定位到`artifacts/collection-expansion-candidates.json`冻结传输91项JSON后，哈希与采集和扫描记录完全一致；保留原始记录，未放宽检查。

新增20项测试，覆盖重复/遗漏/错SHA、清单字节变化、版本/阈值/模型契约、缓存模式、空/重叠/遗漏簇、NaN成本、超时无分数仍弃权、公开聚合无成员SHA。审查发现3项校验缺口，新增反例先复现后修复，并加ML engine_version反例。复查通过。

全套 **212 passed / 6 skipped / 1既有anyio弃用warning，17.86秒**；本轮未执行浏览器或VM测试（没有改变UI/运行任务层），不能沿用其旧验收来声称E1已完成。

研究统计误用11项检查已执行：选择/幸存者/后验路径/基率与簇相关性列为限制；没有因果、显著性或正式低FPR宣称。数值状态为保存证据重算验证，客户机和新独立实验状态为未执行。

### 复现（私有输入保留本地/VM）

```powershell
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m experiments.expansion_diagnostics --scan docs/benchmarks/collection_expansionscan_20261013.json --manifest artifacts/collection-expansion-candidates.json --acquisition docs/benchmarks/collection_acquisition_audit_20261014.json --output artifacts/expansion-diagnostics-replay.json
./vm/Get-TaskGuardReadiness.ps1
```

公开摘要：`docs/benchmarks/expansion_diagnostics_20261016.json`、`stage_e_evidence_audit_20261016.json`。逐文件标签候选及冻结成员清单不公开；公开源码副本无私有输入时不能执行真实数据重放，但可以运行全部无害单测。

收尾复核：宿主机可用RAM 7.22 GiB，仍低于10 GiB门槛；C/D可用28,771,364,864 / 107,786,694,656 B，项目扫描Worker 0。相较开始磁盘约C下降3.67MB、D下降4.69MB，包含测试及系统/其他应用活动，不能全部归因于本轮；未执行目录删除或强清缓存。

## 下一步

1. E1仍以资源和客户机验证为硬门槛，保持原VM关闭；资源足够时先完成无害pidfd/cgroup/OOM/ClamAV验收。
2. E2优先主要案例证据驱动的原PE采集与标签复核，149官方工具候选补完整训练/时间/用途审核，再扩展独立官方软件来源；不再以增加unknown样本数量充当进展。
3. E3按家族/架构和可信验证集决定有版本的规则改进，继续保留原策略和最终集边界。
4. E4只在相同无害固定文件集、验证完整安全清理后实验模型Worker复用；尚无实测提速或检测增益可报告。
