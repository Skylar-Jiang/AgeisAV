# 当前两章课程验收：证据盘点（2026-10-23）

本轮验收对象是老师的 **5 个 PE 基本静态分析报告、100 条 SHA-256 的平台报告，以及 YARA / Sigma 实验**。已经找到这两组历史教学材料；不需要把旧 MalwareBazaar 120 条候选当作老师的 100 条输入，也不以“20 万个独立原始 PE”阻塞这两章的功能交付。

本次盘点没有读取恶意 PE 或压缩包，没有执行样本、访问第三方 API、读取凭据或更改 VM。以下“历史已有”只表示材料可以复核，不能改写为本轮重新检测成功。

## 验收矩阵

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

## 五个静态案例的历史证据

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

## 输入与证据来源

本地私有证据索引保存在忽略目录 `artifacts/course-acceptance-20261023/`，不纳入公开包。公开文档不包含原始哈希清单、凭据、恶意文件或私有绝对路径。

| 来源 | 可核对的原文件 | 证据作用 |
| --- | --- | --- |
| 既有教学报告 | `sections/part2.tex`、`images/p2_*.png` | 五个 PE 的原分析文字与图像；保留来源，不生成新的扫描结论 |
| 历史 B 组输入与查询 | `results/experiment-3/group-b-sha256.txt`、`group-b-results.json`、`execution-summary.json` | 老师 100 条输入身份、成功数、请求次数及逐条结果 |
| 历史 VT 原响应 | `data/reports/virustotal/` 与报告附件 `evidence/details/hash_query/` | 两处均覆盖同一 100 条 B 组身份；文件存在核验不代替 JSON 内容校验 |
| 历史实验说明 | `docs/experiment-audit.md`、`results/experiment-3/实验报告.md` | 明确 B 组来自老师；2026-09-26 已完成 100 次哈希查询；国家平台请求 0 次 |
| 本轮私有机器索引 | `teaching_evidence_manifest_private.json`、`course_inventory_private.json`、`filename_discovery_private.json` | 原文片段、逐图摘要、身份绑定限制、100 条集合对账及发现范围 |
| 项目研究证据 | [课程历史评测](research/COURSE_EVALUATION_20261022.md)、[原生 SSDeep RC](research/NATIVE_SSDEEP_RESULTS_20261023_PUBLIC.md) | 复用既有工程/研究结果；不把历史测量改写成本轮测试 |

盘点发现范围仅为当前项目和既有 API 项目；先按文件名/元数据查找，排除依赖环境、Git、缓存及重复公开交付树。该次文件名记录分别覆盖 6,496 和 1,567 项；这是发现时快照，后续协作新增文件不会回填这两个计数。上级目录只查看顶层目录/文件名，没有遍历整个用户目录，也没有读取附件、压缩包或 VM 磁盘。

在这个范围内，**没有按文件名找到这五个原始教学 PE，也没有找到 B 组 100 条完整 CVERC 原响应集或 Defender 原事件导出**。这不表示其他磁盘、老师原包或隔离 VM 中不存在；本轮没有为“寻找”而开启 VM 或解包。已找到的教学报告和 B 组 100 条清单不能继续写成缺失。

## 数据角色必须保留

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

## 离线复现与缺口关闭

所有命令从项目根目录运行。以下变量必须指向本机已有私有输入，公开文档不给出该机器路径；若包尚未安装，仅为当前进程设置 `PYTHONPATH=backend`。

```powershell
$LegacyReportRoot = '<已有教学报告根目录，含 sections/ 与 images/>'
$StaticOutput = '<新建五样本私有输出目录>'
.\.venv\Scripts\python.exe -B -m aegisav.teaching_cli import --manifest artifacts/course-acceptance-20261023/teaching_evidence_manifest_private.json --source-root $LegacyReportRoot --output $StaticOutput
```

本轮实际输出 `artifacts/course-acceptance-20261023/five-sample-workbook-final/`：5 个样本、107 个引用图片副本校验通过，每例保存 Markdown、JSON 及原始章节文字；BUG32 的正文缺失 SHA-256 仍为 `null`。这是历史证据适配器的实际运行结果，不能冒称对五个恶意 PE 完成了本轮检测。新的有界原始 PE 分析入口、无害控制验证和字段含义见 [基本静态分析说明](COURSE_STATIC_ANALYSIS.md)。

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

YARA 现有规则来源和历史实扫见 [规则复核](research/YARA_REVIEW_20261010.md)；有针对性的无害离线验证可运行：

```powershell
.\.venv\Scripts\python.exe -B -m pytest backend/tests/test_bundled_yara_rules.py backend/tests/test_reviewed_yara.py backend/tests/test_yara_rules.py -q
.\.venv\Scripts\python.exe -B -m experiments.course_sigma_demo '<全新私有输出目录>'
```

Sigma 案例覆盖、输入字段限制与输出解释见 [课程 Sigma 实验](COURSE_SIGMA_LAB.md)。真实 Windows 进程创建 / Event 1 规则匹配与其他 Sysmon 时间线证据应分别说明；`incomplete` / `not_observed` 不表示安全。[发布就绪盘点](RELEASE_021_COURSE_READINESS.md) 另列 RC、便携运行与尚未完成的发布步骤。

## 本轮完整验证

后端实际完整回归394passed/8skipped，一个既有AnyIO弃用警告。新增无害notepad静态导出成功：315条导入、0导出；SHA/模糊/YARA/ML均no_match，ClamAV明确unavailable。它是已安装良性控制，不是教师恶意样本或独立准确率验证。证据目录为artifacts/course-acceptance-20261023/benign-notepad-fresh。源码课程CLI尚未写入冻结0.2.1rc1 ZIP，便携包不被悄悄更新。
