# 课程验收与实验指南

整理日期：2026-11-22。以下实际结果来自 2026-10-23 的私有证据盘点与无害实验；本次合并文档没有重新执行恶意样本检测或平台查询。
以五样本静态报告、教师 100 条 SHA-256 的 VT 报告、YARA 和 Sigma 实验为交付范围。
详细查询接口见 [VT 查询](COURSE_HASH_QUERY.md)，检测效果与数据边界见 [评测](EVALUATION.md)。

## 逐项验收与证据

本轮验收对象是老师的 **5 个 PE 基本静态分析报告、100 条 SHA-256 的平台报告，以及 YARA / Sigma 实验**。已经找到这两组历史教学材料；不需要把旧 MalwareBazaar 120 条候选当作老师的 100 条输入，也不以“20 万个独立原始 PE”阻塞这两章的功能交付。

本次盘点没有读取恶意 PE 或压缩包，没有执行样本、访问第三方 API、读取凭据或更改 VM。以下“历史已有”只表示材料可以复核，不能改写为本轮重新检测成功。

### 验收矩阵

| 项目 | 已有材料与本轮核验 | 当前结论 / 仍缺什么 |
| --- | --- | --- |
| 老师 5 个 PE 的身份与静态章节 | 找到原教学报告 `sections/part2.tex`；本轮实际导入为 5 份 Markdown + JSON，保留原文、历史字段和证据来源 | 五份历史证据报告已生成；未在本轮重新解析原始 PE，真实检测引擎保持 `not_observed` |
| PE Header、Sections、Imports、Strings、资源/Overlay | 五章共引用 107 个 PNG，逐项检查存在，生成图片字节摘要；保留完整原文片段 | 已有人工工具证据；图片不是本轮解析得到的机器字段 |
| Defender 原始检测证据 | 五个样本均引用既有 Defender 截图；包括 3 个告警和 2 个本地未检出 | 证据可附录；没有发现原始 Defender 事件导出，裁剪图的身份绑定有局限 |
| SSDeep / TLSH | 五个样本均有 CVERC 基本属性 / 模糊哈希截图引用 | 历史平台字段证据已有；本轮未重新计算数值或相似度，不能把图片字段当成当地计算结果 |
| 老师 100 条 SHA-256 输入 | 历史 `group-b-sha256.txt`：100 行、100 有效、100 唯一；与 B 组结果身份集合完全相同 | 输入已找到，不能再列为“待老师提供” |
| 100 条 VirusTotal 报告 | B 组 100 条全部 `completed`、VT `success`；100 份缓存及 100 份打包明细存在；本轮离线 CLI 实际生成 100/100 `cached_report`，续跑仍为 0 请求 | 历史查询与本轮离线报告重建完成，无新增平台检测 |
| 100 条 CVERC 报告 | B 组历史状态全部为 `not_supported`；本轮实际输出 100 条 `blocked_no_documented_api`，0 请求 | 未完成；五个 PE 的网页截图不能补成这 100 条报告。需已获授权的官方查询或真实人工导入材料 |
| YARA 课程实验 | 默认规则包 246 条；已有来源、编译、良性控制及隔离环境阳性记录 | 使用既有规则和真实历史结果；不能把规则总数、无害夹具或开发命中率当成独立恶意检出率 |
| Sigma 课程实验 | 离线有界 Worker 的 8 个合成案例：8/8；含两条规则阳性、良性对照、字段缺失、无进程事件、传感器失败及进程链 | 功能实验已完成；合成日志不是实际攻击执行或恶意检出准确率 |

平台账号方面：历史VT查询与平台截图说明当时可用，本轮不读取凭据或冒认新的注册。当前账号状态/邮箱验证须本人确认；CVERC接口、授权和配额未获可验证说明，不抓取未公开接口。

### 五个静态案例的历史证据

下表数值来自原教学章节，未通过本轮 PE 字节重算。平台比例属于各自历史页面，不能相加，也不代表同一时点的引擎集合。

| 案例 | 大小 / B | 入口点 RVA / 节数 | Imports 模块 / 函数 | Defender 历史记录 | VT / CVERC 历史页面 |
| --- | ---: | --- | --- | --- | --- |
| 1-WannaCrypt0r | 3,514,368 | 0x77BA / 4 | 4 / 114 | Ransom:Win32/WannaCrypt!pz | 67/71；25/27 |
| 2-hrtg | 41,771,008 | 0xB7484 / 4 | 12 / 442 | 此次自定义扫描 0 个威胁 | 43/71；15/28 |
| 3-BUG32 | 3,192,320 | 0x1000 / 5 | 9 / 153 | Trojan:Win32/Malgent!MSR | 64/71；15/18 |
| 4-yhzll | 2,527,232 | 0x6FD32 / 4 | 14 / 431 | 此次自定义扫描 0 个威胁 | 60/72；12/28 |
| 5-BossDaMajor | 2,014,208 | 0x1000 / 5 | 9 / 153 | Trojan:Win32/CryptInject | 62/71；20/28 |

hrtg 的原章节横向表仍写“待按原截图核对”，本次人工查看 `p2_045.png` 可读到 43/71；这是对既有图片的转录，不是新增 VT 请求。BUG32 的 SHA-256 没有写入章节正文，位于 `p2_066.png` 的平台属性图片；机器导入清单将正文缺失身份明确留空，不自动 OCR 补成已验证哈希。

Defender 图片定位为：WannaCrypt0r `p2_023/024`，hrtg `p2_044`，BUG32 `p2_064`，yhzll `p2_080`，BossDaMajor `p2_095/096`。其中阴性裁剪图没有同时显示样本名/哈希；当前关联依据是原报告章节顺序，不能声称有独立的逐文件 Defender 事件证明。报告应保留“历史来源声明”“本轮机器计算”“尚未验证”三种字段来源，且保留原始截图。

五个 CVERC 模糊哈希页面分别为 `p2_033`、`p2_051`、`p2_066`、`p2_082_focus`、`p2_098`。图片中出现 SSDeep / TLSH 不等于已计算任意两份文件的相似度，更不等于本机重新计算过这些值。

### 输入与证据来源

本地私有证据索引保存在忽略目录 `artifacts/course-acceptance-20261023/`，不纳入公开包。公开文档不包含原始哈希清单、凭据、恶意文件或私有绝对路径。

| 来源 | 可核对的原文件 | 证据作用 |
| --- | --- | --- |
| 既有教学报告 | `sections/part2.tex`、`images/p2_*.png` | 五个 PE 的原分析文字与图像；保留来源，不生成新的扫描结论 |
| 历史 B 组输入与查询 | `results/experiment-3/group-b-sha256.txt`、`group-b-results.json`、`execution-summary.json` | 老师 100 条输入身份、成功数、请求次数及逐条结果 |
| 历史 VT 原响应 | `data/reports/virustotal/` 与报告附件 `evidence/details/hash_query/` | 两处均覆盖同一 100 条 B 组身份；文件存在核验不代替 JSON 内容校验 |
| 历史实验说明 | `docs/experiment-audit.md`、`results/experiment-3/实验报告.md` | 明确 B 组来自老师；2026-09-26 已完成 100 次哈希查询；国家平台请求 0 次 |
| 本轮私有机器索引 | `teaching_evidence_manifest_private.json`、`course_inventory_private.json`、`filename_discovery_private.json` | 原文片段、逐图摘要、身份绑定限制、100 条集合对账及发现范围 |
| 项目研究证据 | [课程历史评测](EVALUATION.md)、[原生 SSDeep RC](PERFORMANCE.md) | 复用既有工程/研究结果；不把历史测量改写成本轮测试 |

在这个范围内，**没有按文件名找到这五个原始教学 PE，也没有找到 B 组 100 条完整 CVERC 原响应集或 Defender 原事件导出**。这不表示其他磁盘、老师原包或隔离 VM 中不存在；本轮没有为“寻找”而开启 VM 或解包。已找到的教学报告和 B 组 100 条清单不能继续写成缺失。

### 数据角色必须保留

| 数据 | 角色 | 不能替代什么 |
| --- | --- | --- |
| 老师五个 PE 的历史静态材料 | 当前静态章节验收案例 | 不能自动变成独立最终准确率样本 |
| 老师 B 组 100 条 SHA-256 与 VT 报告 | 当前平台批量查询验收 | 只有哈希不等于持有文件；查询旧报告不等于重新扫描 |
| 历史 A 组 116 可读文件 / 115 唯一身份 | 另一组既有文件上传/查询实验 | 不能混成 B 组分母，不能凭文件名推断老师五个 PE 全部包含在内 |
| MalwareBazaar 29/91 次历史采集尝试 | 独立来源的采集/开发记录 | 不能冒充老师 100 条 SHA-256 |
| EMBER FIT 480,000 行 | 训练特征 | 不能替代原始 PE 的完整多引擎扫描 |
| 重复用于选型的开发验证 40,000 行 | 阈值/模型选择 | 不能称为新的独立验证或最终集 |
| 已观察历史最终特征 119,993 行 | 历史库存 | 不能再次作为未观察最终集 |
| R7 298 个不同身份 | 已观察开发案例；286 操作性良性控制、10 恶意代理、2 unknown | 不能给课程两个小实验添加独立泛化结论 |

严格独立原始 PE 的恶意 10 万 + 良性 10 万研究目标仍未完成，旧报告中的这一限制保留；它属于后续大规模研究目标，**不是本轮两章已明确材料的前置硬门槛**。速度、召回和误报只能引用各自版本、平台、数据角色及测量边界，不能跨研究相乘或混池。

### 离线复现与缺口关闭

所有命令从项目根目录运行。以下变量必须指向本机已有私有输入，公开文档不给出该机器路径；若包尚未安装，仅为当前进程设置 `PYTHONPATH=backend`。

```powershell
$LegacyReportRoot = '<已有教学报告根目录，含 sections/ 与 images/>'
$StaticOutput = '<新建五样本私有输出目录>'
.\.venv\Scripts\python.exe -B -m aegisav.teaching_cli import --manifest artifacts/course-acceptance-20261023/teaching_evidence_manifest_private.json --source-root $LegacyReportRoot --output $StaticOutput
```

本轮实际输出 `artifacts/course-acceptance-20261023/five-sample-workbook-final/`：5 个样本、107 个引用图片副本校验通过，每例保存 Markdown、JSON 及原始章节文字；BUG32 的正文缺失 SHA-256 仍为 `null`。这是历史证据适配器的实际运行结果，不能冒称对五个恶意 PE 完成了本轮检测。新的有界原始 PE 分析入口、无害控制验证和字段含义见 [基本静态分析说明](#static-analysis)。

```powershell
$Teacher100 = '<已有 group-b-sha256.txt>'
$VirusTotalCache = '<已有 data/reports/virustotal 目录>'
$QueryOutput = '<新建私有输出目录>'
.\.venv\Scripts\python.exe -B -m aegisav.hash_query vt --input $Teacher100 --cache-dir $VirusTotalCache --output "$QueryOutput/teacher100-vt"
```

默认不加 `--live`，离线使用缓存；重建输出逐条校验原响应身份并保留原 JSON 与报告。本轮实跑及续跑均为 100/100 `cached_report`、新增请求 0；私有输出为 `output/course-query/teacher100-vt/manifest.json`。缓存缺失/无效必须记为缺口，不能用历史汇总文字补成成功。

```powershell
.\.venv\Scripts\python.exe -B -m aegisav.hash_query cverc --input $Teacher100 --output "$QueryOutput/teacher100-cverc"
```

没有已授权 CVERC 实时实现或真实导入报告时，阻塞状态/非零退出是预期结果；本轮实跑 100 条均为 `blocked_no_documented_api`、新增请求 0，退出码 1，私有清单为 `output/course-query/teacher100-cverc/manifest.json`。真实人工导入使用 `--imports '<人工证据索引.json>'`，须保存报告身份、时间、来源与正文；接口手册、占位文字和 VT 结果均不能冒充 CVERC 记录。细节见 [哈希查询说明](COURSE_HASH_QUERY.md)。

YARA 现有规则来源和历史实扫见 [规则来源审计](benchmarks/upstream_windows_rule_audit_20261003.json)；有针对性的无害离线验证可运行：

```powershell
.\.venv\Scripts\python.exe -B -m pytest backend/tests/test_bundled_yara_rules.py backend/tests/test_reviewed_yara.py backend/tests/test_yara_rules.py -q
.\.venv\Scripts\python.exe -B -m experiments.course_sigma_demo '<全新私有输出目录>'
```

Sigma 案例覆盖、输入字段限制与输出解释见 [课程 Sigma 实验](#sigma-lab)。真实 Windows 进程创建 / Event 1 规则匹配与其他 Sysmon 时间线证据应分别说明；`incomplete` / `not_observed` 不表示安全。[发布就绪盘点](DELIVERY_RUNBOOK.md) 另列 RC、便携运行与尚未完成的发布步骤。

### 本轮完整验证

后端实际完整回归394passed/8skipped，一个既有AnyIO弃用警告。新增无害notepad静态导出成功：315条导入、0导出；SHA/模糊/YARA/ML均no_match，ClamAV明确unavailable。它是已安装良性控制，不是教师恶意样本或独立准确率验证。证据目录为artifacts/course-acceptance-20261023/benign-notepad-fresh。源码课程CLI尚未写入冻结0.2.1rc1 ZIP，便携包不被悄悄更新。

<a id="static-analysis"></a>

## 静态分析导出操作

历史导入命令及身份绑定限制见上节；新输出不得覆盖既有报告。索引上限 1 MiB，最多五样本，单件证据 16 MiB、合计 128 MiB，拒绝可执行附件与路径越界。

### 新输入与实际静态分析

没有教师材料时可创建明确未填写的五槽模板；本项目已找到材料，无需把模板当作实际结果。

```powershell
.venv\Scripts\python.exe -m aegisav.teaching_cli template --output artifacts/teacher-five-empty.json
.venv\Scripts\python.exe -m aegisav.teaching_cli analyze C:/Windows/System32/notepad.exe --benign-control --source "installed Windows benign control" --output artifacts/teaching-notepad-fresh
```

新解析复用现有ProcessScanner进程限制与生产扫描器，提取PE头、节/熵、最多2048条导入和2048条导出、最多128条ASCII可疑字符串线索（明确不是裁决），输出SHA/TLSH/SSDeep和五引擎真实报告。超时/解析失败不补阴性。
无效PE、超16MiB和已有输出拒绝；hrtg约39.84MiB超出既有产品限制，本轮只整理历史证据，不扩大生产限制或截断PE进行伪扫描。

真实恶意PE仅能在既有隔离Ubuntu VM中静态处理，不能复制到Windows/WSL：

```bash
python -m aegisav.teaching_cli analyze /existing/vm/path/teacher.exe --existing-isolated-ubuntu-vm --source 'teacher original; document provenance' --output /private/new-teaching-report
```

该选项记录操作者对既有隔离环境的声明，并拒绝Windows/WSL；不是VM身份的远程证明。
未启动、创建、修改VM或快照。未导入Defender原始证据时明确保持未提供；不会启动Defender、上传样本或调用任何PE。
雨课堂提交由用户在确认真实证据及未完成项后进行，本轮没有自动提交或冒认已提交。

<a id="sigma-lab"></a>

## Sigma 离线实验

2026-10-23：现有两条规则足够讲清“日志字段 → 条件匹配 → 可追溯信号 → 不完整证据”的最小实验；不足以代表完整动态检测能力或恶意检出率。这里实际运行的是日志回放，未执行日志里的命令，也没有搭建动态执行沙箱。

### 已有能力和边界

`backend/aegisav/behavior.py` 校验 `rules/sigma/manifest.json` 中的原文件 SHA-256，使用固定 `sigma-offline-v1`、SigmaHQ 提交 `b7920ed31356fb7f6a9275b34737d8604c65bac3` 的两条原始规则，保留作者和 DRL-1.1 许可：

| 规则 | ID | 实验中要观察的条件 |
| --- | --- | --- |
| Suspicious Download Via Certutil.EXE | `19b08b1c-861d-4e75-a1ef-ea0c1baf202b` | 程序映像或 OriginalFileName + 下载参数 + `http` 字符串同时成立 |
| Group Membership Reconnaissance Via Whoami.EXE | `bd8b828d-0dca-48e1-8a63-8a58ecf2644f` | whoami 身份 + groups 参数同时成立 |

两条上游状态均为 `test`。匹配的是文本条件，合法管理员操作也可能命中，不能据此判为恶意。来源为 [Certutil 原规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_certutil_download.yml) 和 [Whoami 原规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_whoami_groups_discovery.yml)。

现有规则执行只映射 Windows `process_creation` 到 Sysmon Event 1；1/3/5/11/12/13/14/22/23/26/255 可作为时间线证据，**解析这些事件不等于给它们配置了 Sigma 检测规则**。支持 AND/OR/NOT、all/1 of、字符串通配符、contains/startswith/endswith/all 和字段缺失三值语义。正则、base64、数值比较、多事件 correlation、时间窗及其他 logsource 未实现；EVTX 和任意 JSONL 不能直接输入。完整输入与资源限制见 [行为分析契约](BEHAVIOR_ANALYSIS.md)。

[Microsoft Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)说明 Event 1 提供进程命令行与进程标识，Event 3 网络记录默认关闭。因此，没有网络事件不能证明没有联网；也不能仅凭进程名建立可靠父子关系。Sigma 的条件与规则状态定义参见 [官方规范](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)。本项目仅实现上述子集。

### 实际可复现的八组无害回放

在仓库根目录，使用现有依赖环境运行；选择一个**不存在、位于源码仓库外**的目录。脚本只生成合成 JSON 并启动固定的 `aegisav.behavior_cli`；该 CLI 使用原有受限 Worker，20 秒截止、256 MiB 进程预算。没有网络下载，不执行 certutil/whoami，不更改系统配置、规则或静态融合。

```powershell
.\.venv\Scripts\python.exe -B -m experiments.course_sigma_demo D:\2026fall\badcode\aegisav-course-sigma-new
.\.venv\Scripts\python.exe -B -m pytest backend/tests/test_course_sigma_demo.py -q
```

脚本与 CLI 均拒绝覆盖既有报告；重复实验请换新的目录。每组产生 `<名称>.json` 和 `<名称>.report.json`，`summary.json` 写入预先固定的期待、实际规则状态、输入 SHA-256 和核验结果；期待与实际不一致时退出非零。

| 名称 | 输入 | 预期总状态 | 两规则结果（Certutil / Whoami） |
| --- | --- | --- | --- |
| certutil_download | 合成 Certutil 下载描述 | matched | matched / no_match |
| whoami_groups | 合成 whoami groups 描述 | matched | no_match / matched |
| benign_controls | Certutil 本地哈希、whoami user 描述 | no_match | no_match / no_match |
| missing_command | Certutil 创建事件缺 CommandLine | incomplete | field_incompatible / no_match |
| no_process_create | 只有 DNS 事件 | not_observed | not_observed / not_observed |
| sensor_error | 合成 Event 255 | incomplete | not_observed / not_observed |
| unsupported_event | Event 7，本项目不支持其语义 | incomplete | not_observed / not_observed |
| chain | 8 事件、3 进程，包含网络/文件/注册表/终止/DNS | matched | matched / matched |

2026-10-23 实际输出 `{"cases":8,"passed":8}`，保留在仓库外 `D:\2026fall\badcode\aegisav-course-sigma-20261023`。新增 2 项测试覆盖真实 CLI、两规则、状态边界及不覆盖既有输出；连同 `test_behavior.py`、`test_behavior_cli.py` 实际运行合计 23 项通过。此处八个固定期待是功能验证，不能计为八个独立恶意/良性样本，也不能计算泛化准确率。

课堂可将 `chain.json` 导入 `/linen/behavior/`，查看两个规则的作者、来源、资产摘要和事件 ID，再追踪三进程与时间线。CLI 报告中 `static_link.status=not_linked`，`static_policy_modified=false`，`coverage.completeness_proven=false`；不编造静态关联、执行真实性或完整采集证明。教师可先让学生预测各组状态，再解释 `no_match`、`not_observed` 和 `incomplete` 的区别。

### 现有公开日志回放的用途

`experiments/behavior_public_replay.py` 已固定 OTRF 提交 `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` 的 IE 注册表查询日志。复核现存 `artifacts/stage-f-public-replay-20261019-v2/summary.json`：原始 68 条中 59 条 Sysmon、9 条明确排除；无解析错误，1 个进程，两条规则均 no_match；包含不支持的 Event 7/9/10，故总状态为 incomplete。Worker 清理成功。它说明真实公开日志的格式归一化和覆盖边界，**不是两条规则的真实阳性验证**。本次未重复下载或运行此历史回放。

如需单独重现已有公开回放（会下载日志 ZIP，仅读取受限 JSON 成员），在仓库根目录使用新的 artifacts 子目录：

```powershell
.\.venv\Scripts\python.exe -B -m experiments.behavior_public_replay artifacts/course-public-replay-new
```

上游 [OTRF 固定数据](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip) 与 [该提交 MIT 许可](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE)可核对；不要把上游主分支的许可说明代替已固定版本。真实日志的主机名、用户、命令行按私有报告处理。

### 适度扩展建议，尚未接入

先维持两条规则完成课堂验收。后续最多先增加以下两条教学候选；本次没有下载到规则目录、修改 manifest 或改变生产规则：

| 候选 | 官方固定来源与可行性 | 准入要求 |
| --- | --- | --- |
| Security Privileges Enumeration Via Whoami.EXE，`97a80ec7-0e2f-4d05-9ef4-65760e634f6b` | [SigmaHQ 固定规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_whoami_priv_discovery.yml)；已有 Event 1、endswith/contains/all of 可表达 | 原始 YAML、作者/许可/摘要；priv 阳性、user 阴性、缺字段和合法管理员对照 |
| Suspicious Execution of Systeminfo，`0ef56343-059e-4cb6-adc1-4c3c967c5e46` | [SigmaHQ 固定规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_systeminfo_execution.yml)；仅映像或 OriginalFileName 条件，现有子集可表达 | systeminfo 阳性、其他映像阴性、字段缺失；强调合法资产盘点也会命中 |

可先用合成事件验证语义，再从具有明确许可和来源的公开 Sysmon 日志中挑选确实包含所需字段/行为的记录，记录来源版本、原始/转换后摘要、排除事件、预期匹配和合法活动对照。没有现成对应日志就保留“仅合成验证”，不为了阳性而运行下载/持久化/攻击命令。当前不建议一次导入大规则集、放宽不支持语义，或把 Sigma 信号加入静态恶意阈值。

## 课堂演示顺序

先在 Linen 展示真实引擎状态，再上传已安装良性 PE，检查任务、逐引擎证据与 JSON 导出。
随后展示五份历史工作簿的来源、Defender 截图和缺项；离线重建教师 100 条 VT 报告时明确新增请求为 0。
最后导入无害 `chain.json`，解释规则信号、进程链和不完整日志。`/linen/demo/` 只用于明确标示的合成界面演示。
雨课堂提交、账号状态和历史证据身份由本人最终核对；没有原始证据的字段保持缺失。
