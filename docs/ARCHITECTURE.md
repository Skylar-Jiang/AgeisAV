# 阶段 0：架构草案

## 范围与边界

AegisAV 为新的独立仓库。旧 `apicall` 是外部平台报告查询实验，其 SHA-256 数据与平台结论不等同于本地扫描结果；当前不迁移其代码或样本。目标对象为 Windows PE 文件，先支持离线静态检测，动态模块在隔离虚拟机可用后接入。原始样本不能在开发主机或 Web/API 进程中执行。

## 处理流程

`输入 → 大小与 PE 校验 → 单次读取/哈希 → 查缓存 → 各静态引擎独立扫描 → 证据融合 → 按策略排队动态分析 → 报告`

- API 接收文件并创建任务；有界队列控制同时扫描数量。文件内容放在隔离的暂存区，报告只引用 SHA-256 与安全元数据。先不决定 Redis/PostgreSQL，阶段 3 根据并发与恢复实验选用。
- `sha256` 是精确身份与去重键；TLSH/SSDeep 只提供相似候选，不能单凭相似分数判恶意。
- 引擎契约：`engine_id`、`engine_version`、`status`（`matched`/`no_match`/`error`/`timeout`/`unavailable`）、`elapsed_ms`、`evidence[]`、`risk_signal`、`artifact_version`。规则证据含规则 ID、规则版本、命中偏移/模式和来源；AI 证据含模型版本、特征版本与原始分数。静态规则命中不能表述为已观察到的动态行为。
- YARA-X 规则名称优先 `Family_FeatureType_SpecificFeature`，通用规则以 `Generic` 开头，符合标识符语法并尽量不超过 50 字符。独立元数据维护稳定规则 ID、家族、特征类别、描述、作者、来源、版本、可信度、适用范围。Sigma 使用自身 UUID/标题体系。[YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/)支持预编译规则与扫描超时；阶段 1 将验证实际版本行为。
- 融合输出分离“证据”和“裁决”：`malicious`、`suspicious`、`benign`、`undetermined`。初期只允许经验证的高可信精确证据参与明确裁决；弱证据冲突保留 `suspicious`/`undetermined`。校准、阈值及融合方式只在验证集选择，在独立测试集报告结果，不做无依据的平均或投票。
- 动态任务使用独立队列和隔离 Windows VM。先支持 Sysmon 日志导入与 Sigma 离线回放，后续才接真实执行接口。动态证据记录事件时间、来源、事件 ID、规则 ID 和沙箱运行 ID。

## 计划的模块边界

`backend`：API/任务编排；`engines`：哈希、YARA-X、ClamAV、AI、动态适配器；`rules`：YARA-X 与 Sigma 分库存放；`experiments`：数据清单、训练、评测、Benchmark；`frontend`：工作台、任务、证据和实验视图；`docs`：设计与验收记录。阶段 1 才建立业务模块，避免在调研阶段写空壳接口。

## 任务生命周期

`queued → validating → static_running → static_done → [dynamic_queued → dynamic_running] → completed`。输入拒绝为 `rejected`，任务级失败为 `failed`；单引擎错误记录在引擎结果中，不能自动伪装成 `no_match`。超时、重试与取消需要明确幂等边界，阶段 3 依据实测负载确定。

## 当前技术判断

- 沿用 Python/FastAPI 作为服务层候选。官方 [YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/)已有编译、扫描和超时接口。
- ClamAV 优先评估 `clamd` 常驻服务；[官方文档](https://docs.clamav.net/manual/Usage/Scanning.html)说明其多线程扫描与签名库依赖，TCP 端口本身不提供认证，因此只允许本地或隔离网络连接。
- EMBER2024 官方特征 v3 基于 `pefile`，与旧 EMBER 的 LIEF 特征实现不同；不会混用特征版本。[官方 README](https://github.com/FutureComputing4AI/EMBER2024/blob/main/README.md)
- TLSH 对短或低复杂度内容可能无法产生摘要；SSDeep 官方也提示相似命中不能直接证明文件相关性。[TLSH](https://github.com/trendmicro/tlsh)、[SSDeep](https://ssdeep-project.github.io/ssdeep/usage.html)
- 前端沿用 React/Vite 作为候选，页面设计和最终栈在阶段 5 依据设计研究确定。当前不写页面。

## 阶段 1 实际落地（2026-09-28）

- `backend/aegisav/pe.py` 使用 `pefile` 拒绝不可解析或没有节表的输入。API 读取上传字节后传给扫描器，不落盘，也不运行文件；单文件限制 16 MiB。
- `hashes.py` 以 SHA-256 字典做精确检索；TLSH 输出标准 `T1` 格式，SSDeep 由 `ppdeep` 计算。可选相似阈值目前固定为 TLSH 距离 ≤40、SSDeep 相似度 ≥80，只用来列已标记恶意记录的候选，**没有经过数据集校准，不参与恶意裁决**。模糊候选仍逐条线性比较；没有模糊摘要的记录跳过。来源、标签和摘要格式在加载时检查。
- `yara_engine.py` 启动时编译规则与独立元数据，校验名称、重复和语法；每次扫描新建 YARA-X Scanner 并设置超时。`clamav_engine.py` 使用本机 `clamd` 的 `INSTREAM` 协议，启动时探测服务，扫描前刷新版本/签名号作为缓存键；不完整回复和网络异常保持为 `error`、`timeout` 或 `unavailable`。启动后才出现的 `clamd` 服务需要重启 API。生产规则和真实恶意哈希数据尚未导入。
- `scanner.py` 对 YARA-X/ClamAV 使用两个线程并行运行；批量任务使用固定上限线程池。当前以 512 项内存 LRU 缓存完整扫描结果，任何引擎 `error`、`timeout`、`unavailable` 均不缓存。只有可信精确哈希标签可得明确恶意/良性裁决；全阴性为 `undetermined`。批内相同 SHA-256 只扫描一次，返回 `duplicate_of`。跨进程缓存与持久队列属于阶段 3。
- `api.py` 暴露单文件原始字节和最多 20 项的 base64 批量接口。仅建议绑定回环地址，尚无认证、持久任务、流式批量上传或生产级并发配额。`benchmark.py` 测量预加载字节的扫描函数，不能替代端到端上传或多引擎基准。
