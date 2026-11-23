# AegisAV 文档入口

更新：2026-11-22。这里保留现行说明和仍用于复核的聚合证据；逐轮过程在 Git 历史中追溯。
当前源码已合入公开 main，稳定便携包仍为 0.2.0，0.2.1rc1 是独立候选，正式 0.2.1 尚未发布。

| 要做什么 | 唯一入口 |
| --- | --- |
| 安装源码、了解功能与当前缺口 | [项目 README](../README.md) |
| 使用工作台、报告、备份和停启 | [用户手册](USER_GUIDE.md) |
| 配置便携、ClamAV 和排错 | [部署运行手册](DELIVERY_RUNBOOK.md) |
| 配置外置模型、查看适用范围与冻结阈值 | [ML 集成](ML_INTEGRATION.md) |
| 查看稳定包、RC 证据和正式版封板条件 | [发布状态](RELEASE_STATUS.md) |
| 完成五样本、教师 100 SHA、YARA/Sigma 课程验收 | [课程指南](COURSE_GUIDE.md) |
| 导入/查询 VT 报告及 CVERC 人工材料 | [哈希查询](COURSE_HASH_QUERY.md) · [无害输入示例](examples/course-query/README.md) |
| 查看检测效果、数据角色与独立评测准入 | [评测](EVALUATION.md) |
| 查看实际速度、内存、候选收益和退化 | [性能](PERFORMANCE.md) |
| 接手后端、任务状态和存储 | [系统设计](SYSTEM_DESIGN.md) · [任务可靠性](TASK_RELIABILITY.md) |
| 理解离线日志和关联证据契约 | [行为分析](BEHAVIOR_ANALYSIS.md) |
| 确认尚未实现/验证的边界 | [已知限制](KNOWN_LIMITATIONS.md) |

## 证据文件怎样保留

`benchmarks/` 的 JSON 是历史测量，保留各自版本与时间；合并文档没有生成新的准确率或速度结果。
保留项包括评测汇总及其 collection/R6/R7 输入、原生/模型/YARA/Windows 控制结果、规则来源审计，
以及任务、页面、行为、交付的阶段验收摘要。其中规则审计由自动化测试读取，不能当缓存删除。
完整私有报告、教师输入、模型、数据库、ZIP 和 VM 不在公开 Git；本次没有移动或删除这些资产。

## 历史追溯

早期设计、前端原型、逐轮报告、重复浏览器检查和 PROGRESS/EXPERIMENTS 流水账已从当前目录移除。
有效操作与结论已并入上表；完整原文仍可从 [整理前的 docs 快照](https://github.com/Skylar-Jiang/AgeisAV/tree/cd6bb64ea96c1ebde17eecece7854e0fa248a451/docs)
或 `git show cd6bb64ea96c1ebde17eecece7854e0fa248a451:docs/<原文件路径>` 恢复，无需维护另一套“archive”目录。
旧 ML 文档中的“API 无认证”、Vite 设想及逐阶段待办不是当前系统状态。
项目内 `.agents/skills/` 的原文、许可未变；历史 Skill 安装与 UI 审查记录也在该快照。

今后按主题更新现行文件；只有有独有复核价值的新实验才保留机器摘要，不再为每轮工作新增平行交接文档。
