# AegisAV

面向课程实验和研究的 **Windows PE 多引擎静态检测与离线行为证据平台**。
程序名为 AegisAV，GitHub 仓库名为 [Skylar-Jiang/AgeisAV](https://github.com/Skylar-Jiang/AgeisAV)。

**状态核对：2026-11-22；最近一轮检测流水线实验：2026-11-01。**
已有可运行的软件、课程工具和独立便携候选；独立恶意检出率、低误报率与跨家族泛化仍待验证。
本项目提供静态分析和离线日志回放，不是实时防护、自动隔离清除或运行恶意软件的动态沙箱。

## 当前版本与交付状态

| 对象 | 当前状态 | 接手时需要注意 |
| --- | --- | --- |
| `main` 源码 | 已集成多引擎平台、Linen、课程 CLI 和经过验证的优化代码 | 源码安装版本字段仍为 `0.2.0`，不等于当前源码与旧 ZIP 完全相同 |
| Windows `0.2.0` ZIP | 保留的稳定便携基线 | 内置 Python 与编译前端；新课程 CLI 和后续优化没有自动回填该包 |
| Windows `0.2.1rc1` ZIP | 独立原生 SSDeep 发布候选，已有便携运行、故障、恢复和回退证据 | **不是正式 `0.2.1`**；未覆盖稳定包，仍需目标课程电脑验收与正式字节封板 |
| 原生 SSDeep | 已完成完整哈希、报告、ABI、进程限制和便携候选验证 | 稳定源码默认仍为 Python；原生后端必须显式选择并提供经过核验的 DLL |
| YARA 编译结果复用 | 2026-11-01 显式工程候选 | 默认仍编译源码；候选要求外部固定摘要，尚未默认启用或装入原 RC ZIP |
| 模型与阈值研究 | 生产配置保持冻结，研究候选单独保存 | 粗化模型、降低分箱候选已因开发检出退化被淘汰，不能重新当作已上线改进 |

便携包是维护者保留的本地交付物，**公开 Git 源码不附带 ZIP、私有模型、样本、报告数据库或 VM**。
首次克隆可以运行基础引擎和无害测试；完整五引擎需要另行配置外置组件。
版本证据见 [发布状态](docs/RELEASE_STATUS.md)，配对速度与退化见 [性能结果](docs/PERFORMANCE.md)。

后续开发从 `main` 创建新的功能分支；不要将带私有研究历史的本地分支直接推送或合入公开仓库。
历史 `export_public_delta` 工具绑定旧公开分支名，清理该分支后须先适配并复核导出目标，不能绕过父提交和敏感内容检查。

## 已有功能

| 模块 | 已实现能力 | 边界 |
| --- | --- | --- |
| PE 基础分析 | 文件有效性/截断检查，SHA-256、TLSH、SSDeep；教学导出可包含文件头、节、导入/导出与可疑字符串线索 | 只解析字节，不加载或执行输入 PE；单文件上限 16 MiB |
| 五引擎静态扫描 | SHA-256 精确参考、TLSH/SSDeep 相似度、246 条带来源的 YARA-X 规则、ClamAV、EMBER2024 LightGBM | 规则/指纹覆盖有限；ClamAV 和 ML 为外置可选组件 |
| Linen 工作台 | 实际上传、批量任务、进度、取消、详情、报告导出、历史、规则/模型只读状态和统计 | `/linen/demo/` 是显式合成演示；真实请求失败不会替换为演示结果 |
| FastAPI 与任务管理 | 本地密钥/会话认证、回环/同源校验、版本化缓存、有界队列、独立扫描进程树、超时和取消 | 本地使用，不作为公网多用户服务部署；进程配额不等于网络/文件系统沙箱 |
| SQLite 持久化 | 静态任务和行为报告保存、历史查询、重启恢复、容量与备份支持 | 上传 PE 字节只在内存；中断任务需重新提交，不会自动续扫 |
| 离线行为分析 | Sysmon XML / 规范 JSON、两条固定 SigmaHQ 规则、进程链、事件证据、静态/行为关联 | 不支持原生 EVTX、自动采集或真实恶意动态执行；日志声明不等于已证实的执行事实 |
| 教学静态报告 | 五样本证据导入、新输入的有界静态解析、Markdown/JSON 导出、Defender 证据引用与缺项记录 | 历史截图和本轮计算分开；没有提供的证据不会伪造为完成 |
| VirusTotal 批量查询 | 独立 SHA-256 CLI，离线缓存、显式在线 GET、限流/退避、超时、续跑、原始 JSON、完整性校验和失败审计 | 只按哈希取报告，不上传或下载样本本体，不接入本地检测裁决 |
| CVERC 材料导入 | 人工报告、来源声明、身份与文件摘要检查 | 当前未启用在线 API；以 VT 为主要查询路线，国家平台缺口单独记录 |

### 检测结果怎样解释

- 只有来源与标签经审定的精确哈希命中可直接支持 `malicious` / `benign` 裁决。
- 模糊哈希、YARA、ClamAV 或 ML 告警产生可疑证据；模型分数不等于校准概率。
- 全部未命中仍可为 `undetermined`，不能表述为“保证安全”。
- `unavailable`、`error`、`timeout`、`not_applicable` 是独立状态，不能当作阴性。
- 以实际 `GET /v1/engines` 为准；仓库有五个适配器，不代表当前机器五个引擎都健康。

## 从源码启动

主要已验平台为 Windows 11 x64 普通用户。需要 Git、Python 3.12、Node.js **20.9 或以上**及 npm。
Node/npm 用于源码前端构建；便携包终端用户无需自行安装 Python 或 Node。

```powershell
git clone https://github.com/Skylar-Jiang/AgeisAV.git
cd AgeisAV

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-win-py312.txt
.\.venv\Scripts\python.exe -m pip install -e . --no-deps

npm --prefix frontend ci
npm --prefix frontend run build

.\.venv\Scripts\python.exe -m experiments.serve_local
```

访问 <http://127.0.0.1:3417/linen/>，按启动日志给出的文件位置读取本机私有访问密钥并连接。
密钥保存在仓库外，不写进前端、URL、提交或报告。启动器只绑定回环；可用 `--port` 选择其他端口。
上述启动器统一托管 API 与构建后的前端，不需要再同时启动占用同一端口的前端开发服务器。

首次克隆缺少 ML 或 ClamAV 时会明确弃权，其他可用引擎仍可工作。
ML 的独立解释器、合法取得的模型和冻结 registry 按 [ML 集成说明](docs/ML_INTEGRATION.md) 配置；
ClamAV 通过本机 `127.0.0.1:3310` 连接已有 sidecar，见 [Windows ClamAV 方案](docs/DELIVERY_RUNBOOK.md)。
不要把研究用完整 VM 脚本当作通用安装器直接运行。

### 使用已有便携包

取得维护者提供的完整 ZIP 及配套摘要后，解压并运行 `Verify-Package.cmd`，再双击 `Start-AegisAV.cmd`。
首次用 `Access-Key.cmd` 读取本机密钥，停止时运行 `Stop-AegisAV.cmd`。
模型、ML 环境、ClamAV 和签名库仍是外置组件；核心 ZIP 不承诺开箱完整五引擎。
详见 [用户手册](docs/USER_GUIDE.md) 和 [部署/故障排除](docs/DELIVERY_RUNBOOK.md)。

## API 与命令行入口

| 入口 | 用途 |
| --- | --- |
| `POST /v1/scan` | 原始 PE 字节单文件扫描，最多 16 MiB |
| `POST /v1/scan/batch` | 同步 Base64 批量扫描，1–20 项 |
| `POST /v1/tasks` | 提交含 `name` / `content_base64` 的异步批量任务 |
| `GET /v1/tasks`、`GET /v1/tasks/{id}` | 历史、状态和报告 |
| `POST /v1/tasks/{id}/cancel` | 取消并终止本次拥有的扫描进程树 |
| `GET /v1/engines`、`GET /v1/statistics` | 实际引擎可用性与运行统计 |

行为接口与会话接口、请求示例及任务可靠性见 [架构](docs/SYSTEM_DESIGN.md)、[行为模块](docs/BEHAVIOR_ANALYSIS.md)、[任务可靠性](docs/TASK_RELIABILITY.md)。
接口需要本地认证，不要将私有访问密钥或 VT 凭据放进命令行参数。

独立工具无需启动网页服务：

```powershell
# 查询 CLI；默认离线，只有 --live 才允许访问 VT 报告端点
.\.venv\Scripts\python.exe -m aegisav.hash_query --help

# 教学静态导出；此示例仅解析已安装的良性 notepad，不执行它
.\.venv\Scripts\python.exe -m aegisav.teaching_cli analyze C:/Windows/System32/notepad.exe `
  --benign-control --source "installed Windows benign control" --output artifacts/teaching-notepad-report

# YARA 规则与元数据校验
.\.venv\Scripts\python.exe -m aegisav.rules_cli --rules rules/yara --metadata rules/yara/metadata.json

# 查看离线行为回放 CLI；内含无害 JSON 夹具
.\.venv\Scripts\python.exe -m aegisav.behavior_cli --help
```

在线 VT 仅从受保护进程环境读取 `VT_API_KEY`（兼容 `VIRUSTOTAL_API_KEY`）。已有报告优先离线导入，
续跑使用原输出目录与 `--resume`；404、限流和查不到的报告保持真实状态。
用法与合规边界见 [SHA 查询说明](docs/COURSE_HASH_QUERY.md)，教学导出见 [静态报告说明](docs/COURSE_GUIDE.md)。

## 课程交付与接手材料

已有五份历史教学静态报告的证据整理、107 张图片引用，以及教师 100 条 SHA-256 的 VT 缓存校验和导出。
这些材料是**私有历史证据**，没有纳入公开仓库，不代表本轮重新扫描了五个恶意 PE 或重新查询了 100 次 VT。
CVERC 的 100 份真实报告仍未补齐；现有阻塞记录不是检测报告。
两条 Sigma 的八个无害合成案例已用于功能验收，不作为真实恶意检出率。

接手时另行取得以下合法授权材料，不要向公开 Git 上传：

| 材料 | 用途与核对点 |
| --- | --- |
| 模型权重、registry、独立 ML 环境配置 | 缺失则 ML 弃权；核对文件摘要、实现版本和冻结阈值 |
| ClamAV runtime、签名库与来源记录 | 核对版本和实际健康状态；签名过期与缺库应单独记录 |
| 原 `0.2.0` / `0.2.1rc1` ZIP、摘要及验收记录 | 区分源码与包内字节；保留分目录回退方案 |
| 教师哈希清单、VT 原始 JSON、五样本来源/截图/Defender 证据 | 补身份绑定、缺项和最终报告；不以模板或自动转录伪装新检测 |
| 私有报告数据库与备份 | 含敏感路径/事件，按部署说明迁移；不要只复制运行中的 SQLite 主文件 |
| 已有隔离 VM 与快照说明 | 原始恶意 PE 仅在该授权环境内静态处理；禁止搬到 Windows/WSL 或执行 |

逐项验收、静态导出、Sigma 实验和演示统一见 [课程指南](docs/COURSE_GUIDE.md)。
雨课堂提交、个人账号状态和最终人工确认不由仓库自动完成。

## 评测现状与下一步

已有 480,000 行 FIT 特征和重复用于选型的 40,000 行开发验证，以及少量已观察恶意代理/良性控制。
它们不能当作新的独立最终集；当前没有足够证据宣称总体准确率、低 FPR 达标或跨家族泛化。
7-Zip、SQLite、singlefilehost 的误报与 Emotet 关联漏检仍需开发分析和独立确认。
“20 万原始 PE”没有完成，也不作为现有两个课程章节交付的前置硬门槛。

近期工程结果分开看待：

- 大文件哈希与引擎重叠已进入默认源码，旧稳定 ZIP 没有自动更新。
- 原生 SSDeep 已进入独立 `0.2.1rc1`；报告与故障验证不等于恶意检测准确率证明。
- YARA bundle 候选的健康 ClamAV 小文件 P50 为 2.656→1.925 秒，但不可用场景的大文件吞吐下降 10.7%，因此未默认启用。
- 粗化模型及同容量低分箱候选已淘汰，不以推理变快掩盖低误报预算下的检出损失。

优先继续：解释大文件 ML 特征提取波动、验证独立便携候选及目标机器首次运行、补可信标签与来源/家族/时间/训练泄漏审计。
影响判断的模型、阈值或融合变更仍需更严格证据。近期工程结果见 [性能](docs/PERFORMANCE.md)，数据角色及模型实验见 [评测](docs/EVALUATION.md)；不同实验的耗时不能混池或相乘。

## 目录与验证

```text
backend/aegisav/   扫描、隔离进程、API、SQLite、行为分析与课程 CLI
backend/tests/     无害夹具及自动化回归
frontend/          Next.js / React / TypeScript / Tailwind 的 Linen 前端
rules/             参考哈希、带来源的 YARA 和 Sigma 规则
distribution/      便携启动脚本、运行时锁定和第三方许可
experiments/       评测、构建与显式候选工具；不是全部都应直接运行
vm/                绑定已有隔离环境的研究脚本，先审查与适配
docs/              按主题维护的现行文档、课程指南与必要聚合证据
models/ artifacts/ output/  本地私有资产与结果，公开 Git 不附带
```

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
npm --prefix frontend run typecheck
```

完整回归需先安装 `.[test]`，其中包括加密归档无害夹具需要的 `pyzipper`；基础启动依赖不包含所有测试依赖。
公开分发缺少私有模型/归档时，相关测试会明确跳过；应查看原因，不将跳过记为检测成功。
完整文档入口见 [docs/README](docs/README.md)。旧阶段报告已合并或从当前目录移除，可通过整理前的 Git 快照恢复。

更多入口：[用户手册](docs/USER_GUIDE.md) · [系统设计](docs/SYSTEM_DESIGN.md) · [已知限制](docs/KNOWN_LIMITATIONS.md) · [文档索引](docs/README.md)。
第三方许可按各自文件保留；AegisAV 自身尚未指定统一开源许可证，不把所有内容默认标为 MIT，模型再分发需另行确认授权。
