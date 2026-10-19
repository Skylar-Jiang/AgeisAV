# Stage F：可运行离线行为证据（2026-10-19）

## 阶段结论

Stage E **Engineering complete / Research open**，停止 R8/R9 工程迭代，不改变历史实验结论。Stage F 的首版离线导入、规则执行、进程关联、持久报告及 Linen 交互已实际验收；继续进入 Stage G 本地交付准备。独立恶意真值、低 FPR、泛化和泄漏仍属研究 backlog，不以此阻塞行为功能，也没有追认正式 Recall/FPR。

生产静态模型、阈值、YARA、ClamAV、指纹库、融合、静态 Worker 和任务 SQLite schema 均保持原样。新增独立 Sigma 资产和行为报告库，不把行为分数加进静态裁决。原有 6 GiB VM 保持关闭，没有新增 VM、采恶意样本或执行程序。

## 实际功能

- `POST/GET /v1/behavior`、`GET /v1/behavior/{id}`，继承本地认证、同源/回环和无缓存响应。UTF-8 Sysmon XML / 标准化 JSON，原生 EVTX 明确拒绝并提示先导出。
- 1,000 事件 / 4 MiB 上传 / 768 KiB 规范证据 / 20 秒子进程 / 256 MiB；单实例单解析、上传10秒，503/504/422等失败没有阴性报告。独立 SQLite schema1/WAL/FULL/事务/索引及容量保留；不持久保存原始上传，但报告含规范化敏感字段。
- SigmaHQ 固定版本两条 DRL 1.1 规则，保留原 YAML/作者/来源/哈希；支持受测布尔/字符串子集，未知语义、缺字段、未覆盖事件和规则不可用显式分开。
- 按主机/GUID/时间的进程链及有明确闭合且唯一的 PID 回退。重复终止、PID重用、开放竞争生命周期、已终止父边、异主机和乱序均有边界验证；无法归因保留未关联。
- Linen `/linen/behavior/` 真实文件导入、加载/错误/空/不完整状态、规则及事件原字段、进程链、分页/筛选和 JSON 导出。静态详情新增独立行为区域，只有进程创建 SHA256 声明完全相同才关联，明确未验证日志真实性/实际执行。无日志显示 not_observed。

## 真实验证证据

| 检查 | 实际结果 | 限制 |
| --- | --- | --- |
| 合成无害导入 | 6事件、2进程、1 Certutil规则信号，API墙钟约360ms | 描述性夹具，未执行命令；不是恶意真值 |
| 固定 OTRF MIT 公开日志 | 68原始 / 59 Sysmon / 9非Sysmon显式排除；59/59解析、0解析失败、1创建节点 | 两规则无命中；7/9/10事件不支持并保留，因此总体 **incomplete**，不是阴性 |
| 同上真实受限回放 | 约359ms、子进程清理确认 | 无模型/ClamAV调用，不代表多引擎扫描耗时 |
| 浏览器 | 11项通过、0失败、0 pageerror/外部请求 | 1440/1024/768/375/812五尺寸、Chrome实际渲染，reduced-motion；非屏幕阅读器人工认证 |
| 真重启 | 完成导入后强制停止本轮自有服务，再启动；原ID查询JSON完全一致，静态详情仍可交叉打开 | 只恢复已完成报告；进行中导入不续跑，需要重交 |
| 宿主良性静态联调 | notepad五引擎报告维持，4引擎no_match、ClamAV **unavailable** | 未伪装客户机完整五引擎验收，R7客户机历史结果保留 |
| 本地全套 | **321 passed / 6 skipped / 1既有anyio弃用warning** | 跳过现有可选ML条件；没有新测试伪装独立检测实验 |
| 公开筛选分发复测 | **320 passed / 7 skipped / 1既有warning，39.13秒** | 子进程显式绑定公开backend；多跳过1项私有归档证据，ML可选条件跳过保留 |
| 聚焦行为/CLI | 26通过，含实际子进程/超时、重建服务、权限/损坏/future schema | 新行为 Worker 的 Linux 客户机现场验收未做；复用既有监督器，不宣称新现场证据 |
| 前端 | Next.js生产构建与TypeScript通过 | 首次遥测配置EXDEV，关闭本次遥测后成功，无全局配置删除 |

Playwright 脚本 `frontend/scripts/check-behavior.cjs` 使用临时凭据与DB，真实 API 而非 mock；测试 XSS 字符串只作为 `<pre>` 文本、实体拒绝、错误焦点、大小限制、导出、重启及静态报告关联。临时凭据/数据库测试后安全移除，仅本轮自有服务/浏览器终止。截图 `output/playwright/behavior/behavior-{1440,1024,768,375,812}.png` 逐一生成，桌面和375px已视觉复核；初版375px原生文件选择器溢出已定位并修复，失败记录另外保留。

公开日志来源固定 OTRF `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`：[IE版本注册表查询回放](https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry.zip)。脚本只读唯一JSON成员到内存、不提取程序；原记录/转换SHA及版本存忽略的 artifacts。原公开日志/本地报告不进公开仓库。

## 资源实验（非性能提升宣称）

固定构造输入，每组5次、每次新建可终止 Worker，无应用缓存，OS页面缓存未控制；P95用nearest-rank，n=5故取最大值，仅用于本地容量探索。

| 事件数 | 输入字节 | P50 / P95 ms | 采样进程树内存 MiB | 结果一致/失败 |
| --- | --- | --- | --- | --- |
| 6 | 1,662 | 343 / 390 | 36.6 | 5/5一致，0失败 |
| 100 | 27,784 | 359 / 391 | 36.8 | 5/5一致，0失败 |
| 1,000 | 280,685 | 813 / 875 | 38.2 | 5/5一致，0失败 |

采样是 Windows venv launcher **及后代** PeakWorkingSet 的求和，不是严格同时峰值或 cgroup总内存。首轮只读launcher的约4.5MiB低值被判无效，保留原记录，v2修正统计；没有用它做预算或宣称优化。256MiB硬限制与20秒终止保持。收尾观察宿主空闲约8.20GiB、D盘余量96.11GiB，VM进程0、本轮Worker0；Stage F artifacts约425KB，截图另存output。无VM磁盘/快照变化，无正式样本/报告删除。

## 失败、开放问题与后续

- TDD先复现不存在的模块/API；审查再发现并复现重复终止延长生命周期、PID复用、死父节点及开放竞争PID歧义，逐项修复。不是只有pytest数量增长。
- Sigma仅2条测试状态规则，覆盖很窄，不宣称行为检测率。EVTX、其他logsource/高级Sigma correlation、事件7/9/10语义、日志采集完整性/真实性及跨日志生命周期仍开放。
- 进程配额不等于OS权限沙箱。新行为路径本轮在Windows无害日志实测，未通过它处理真实恶意PE或自动执行日志命令。未来Windows执行沙箱必须另行批准。
- 已完成报告持久化；导入不幂等、不自动续跑。存储限额留有余量而非WAL硬配额。用户私有日志需要额外保留/备份管理。
- 正式独立验证/最终集仍0，旧开发集保持观察标签。没有新的静态检出率、Recall/FPR、融合或模型增益声明。
- **Stage G 已启动**：实际可用 `python -m aegisav.behavior_cli`，仓库外新报告、拒绝覆盖、终端不输出事件字段；见 [本地部署](../LOCAL_DEPLOYMENT.md)。下一步交付包、操作/设计手册与最终演示验收；不会以重复F小轮次代替交付。

复现详见 [行为功能文档](../BEHAVIOR_ANALYSIS.md) 与 [E收尾](../STAGE_E_CLOSEOUT.md)。本地原始记录保留在 `artifacts/stage-f-public-replay-20261019-v2`、`artifacts/stage-f-resource-20261019-v2` 和 `output/playwright/behavior`，公开仅筛选源码、合成夹具和无敏感字段摘要。发布采用原公开分支的筛选快进提交，不携带私有研究历史；具体Commit/Push核对随后记入进度收尾。
