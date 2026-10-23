# 两条 Sigma 规则的离线课程实验

2026-10-23：现有两条规则足够讲清“日志字段 → 条件匹配 → 可追溯信号 → 不完整证据”的最小实验；不足以代表完整动态检测能力或恶意检出率。这里实际运行的是日志回放，未执行日志里的命令，也没有搭建动态执行沙箱。

## 已有能力和边界

`backend/aegisav/behavior.py` 校验 `rules/sigma/manifest.json` 中的原文件 SHA-256，使用固定 `sigma-offline-v1`、SigmaHQ 提交 `b7920ed31356fb7f6a9275b34737d8604c65bac3` 的两条原始规则，保留作者和 DRL-1.1 许可：

| 规则 | ID | 实验中要观察的条件 |
| --- | --- | --- |
| Suspicious Download Via Certutil.EXE | `19b08b1c-861d-4e75-a1ef-ea0c1baf202b` | 程序映像或 OriginalFileName + 下载参数 + `http` 字符串同时成立 |
| Group Membership Reconnaissance Via Whoami.EXE | `bd8b828d-0dca-48e1-8a63-8a58ecf2644f` | whoami 身份 + groups 参数同时成立 |

两条上游状态均为 `test`。匹配的是文本条件，合法管理员操作也可能命中，不能据此判为恶意。来源为 [Certutil 原规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_certutil_download.yml) 和 [Whoami 原规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_whoami_groups_discovery.yml)。

现有规则执行只映射 Windows `process_creation` 到 Sysmon Event 1；1/3/5/11/12/13/14/22/23/26/255 可作为时间线证据，**解析这些事件不等于给它们配置了 Sigma 检测规则**。支持 AND/OR/NOT、all/1 of、字符串通配符、contains/startswith/endswith/all 和字段缺失三值语义。正则、base64、数值比较、多事件 correlation、时间窗及其他 logsource 未实现；EVTX 和任意 JSONL 不能直接输入。完整输入与资源限制见 [行为分析契约](BEHAVIOR_ANALYSIS.md)。

[Microsoft Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)说明 Event 1 提供进程命令行与进程标识，Event 3 网络记录默认关闭。因此，没有网络事件不能证明没有联网；也不能仅凭进程名建立可靠父子关系。Sigma 的条件与规则状态定义参见 [官方规范](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)。本项目仅实现上述子集。

## 实际可复现的八组无害回放

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

## 现有公开日志回放的用途

`experiments/behavior_public_replay.py` 已固定 OTRF 提交 `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` 的 IE 注册表查询日志。复核现存 `artifacts/stage-f-public-replay-20261019-v2/summary.json`：原始 68 条中 59 条 Sysmon、9 条明确排除；无解析错误，1 个进程，两条规则均 no_match；包含不支持的 Event 7/9/10，故总状态为 incomplete。Worker 清理成功。它说明真实公开日志的格式归一化和覆盖边界，**不是两条规则的真实阳性验证**。本次未重复下载或运行此历史回放。

如需单独重现已有公开回放（会下载日志 ZIP，仅读取受限 JSON 成员），在仓库根目录使用新的 artifacts 子目录：

```powershell
.\.venv\Scripts\python.exe -B -m experiments.behavior_public_replay artifacts/course-public-replay-new
```

上游 [OTRF 固定数据](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip) 与 [该提交 MIT 许可](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/LICENSE)可核对；不要把上游主分支的许可说明代替已固定版本。真实日志的主机名、用户、命令行按私有报告处理。

## 适度扩展建议，尚未接入

先维持两条规则完成课堂验收。后续最多先增加以下两条教学候选；本次没有下载到规则目录、修改 manifest 或改变生产规则：

| 候选 | 官方固定来源与可行性 | 准入要求 |
| --- | --- | --- |
| Security Privileges Enumeration Via Whoami.EXE，`97a80ec7-0e2f-4d05-9ef4-65760e634f6b` | [SigmaHQ 固定规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_whoami_priv_discovery.yml)；已有 Event 1、endswith/contains/all of 可表达 | 原始 YAML、作者/许可/摘要；priv 阳性、user 阴性、缺字段和合法管理员对照 |
| Suspicious Execution of Systeminfo，`0ef56343-059e-4cb6-adc1-4c3c967c5e46` | [SigmaHQ 固定规则](https://github.com/SigmaHQ/sigma/blob/b7920ed31356fb7f6a9275b34737d8604c65bac3/rules/windows/process_creation/proc_creation_win_systeminfo_execution.yml)；仅映像或 OriginalFileName 条件，现有子集可表达 | systeminfo 阳性、其他映像阴性、字段缺失；强调合法资产盘点也会命中 |

可先用合成事件验证语义，再从具有明确许可和来源的公开 Sysmon 日志中挑选确实包含所需字段/行为的记录，记录来源版本、原始/转换后摘要、排除事件、预期匹配和合法活动对照。没有现成对应日志就保留“仅合成验证”，不为了阳性而运行下载/持久化/攻击命令。当前不建议一次导入大规则集、放宽不支持语义，或把 Sigma 信号加入静态恶意阈值。
