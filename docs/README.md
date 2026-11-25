# AegisAV 文档入口

整理：2026-11-25。稳定便携包仍为 0.2.0，0.2.1rc1 是独立候选，正式 0.2.1 尚未发布。
本次仅整理源码和文档，没有重新运行历史恶意样本实验、改变检测判断或重打包已有 ZIP。

| 要做什么 | 现行说明 |
| --- | --- |
| 安装源码、了解已有功能和当前缺口 | [项目 README](../README.md) |
| 使用、备份、停启与已知限制 | [用户手册](USER_GUIDE.md) |
| 便携安装、外置 ML/ClamAV、排错及正式版封板 | [部署手册](DELIVERY_RUNBOOK.md) |
| 五样本、教师 100 SHA、YARA/Sigma 课程验收 | [课程指南](COURSE_GUIDE.md) |
| VT 查询、缓存续跑与 CVERC 人工材料 | [哈希查询](COURSE_HASH_QUERY.md) · [无害示例](examples/course-query/README.md) |
| 检测效果、数据角色与独立评测准入 | [评测](EVALUATION.md) |
| 扫描耗时、资源、候选收益与退化 | [性能](PERFORMANCE.md) |
| 后端结构、任务状态、限额与持久化 | [系统设计](SYSTEM_DESIGN.md) |
| 离线日志、Sigma 子集与关联证据 | [行为分析](BEHAVIOR_ANALYSIS.md) |

## 必要证据与历史

`benchmarks/` 保留 11 份聚合 JSON：评测及其 collection/R6/R7 输入、模型分箱、原生 SSDeep、
默认性能优化、Windows 控制、YARA 候选和规则来源审计。它们是历史测量，不是本次新检测结果。
规则审计由测试读取；根目录 `PUBLIC_SOURCE_MANIFEST.json` 是便携构建的来源校验输入，不能作为缓存删除。
新的浏览器检查结果写入被忽略的 `output/`，不再追加到正式文档目录。

旧阶段报告、第三方 AI 技能副本、失效私有导出器和一次性工具从当前树移除；必要结论已合并到上表。
原文可从 [本轮清理前的源码](https://github.com/Skylar-Jiang/AgeisAV/tree/8f24f92d16d40e538e82b5cfdf7f39d40220f50a)
及更早提交恢复，不维护另一套 archive 副本。已安装 Python 环境保留，临时脚本及可再生成缓存单独清理。
私有模型、教师材料、数据库、发布包、VM 和快照均未删除；公开仓库不附带这些资产。
