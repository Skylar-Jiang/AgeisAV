# Stage F：离线 Windows 行为证据

## 运行

安装既有 Python 3.12 环境及新增固定依赖 `PyYAML==6.0.3`（MIT），重新构建前端：

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-win-py312.txt
$env:NEXT_TELEMETRY_DISABLED='1'
npm --prefix frontend run build
.\.venv\Scripts\python.exe -m experiments.serve_local
```

访问 `http://127.0.0.1:3417/linen/behavior/`，使用现有仓库外本地访问密钥建立会话。示例文件为 `backend/tests/fixtures/sysmon_harmless.json`：**纯合成描述，命令从未执行**。导入后应显示 6 事件、2 进程、1 条 Certutil 规则信号。真实报告与示例文件明确区分，没有自动演示回退。

仅监听回环、同源 API，继承 HttpOnly / SameSite 会话及无缓存响应。不要公开无额外边界的服务。用户真实日志可能含命令行、用户/主机名和路径；按私有材料管理，不提交 Git。此功能不运行日志中的命令，不动态执行 PE。

## 输入契约

字段/事件语义依据 [Microsoft Sysmon 文档](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)，规则字符串和条件依据 [Sigma 规范](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)；本实现只支持下述明确子集。

首版支持 UTF-8 Sysmon `<Event>` / `<Events>` XML（含默认命名空间）及规范化 JSON：

```json
{"events":[{"event_id":1,"provider":"Microsoft-Windows-Sysmon","computer":"synthetic.example.invalid","timestamp":"2026-10-19T00:00:01Z","record_id":"1","fields":{"ProcessGuid":"{fixture}","ProcessId":"40","Image":"C:\\Lab\\inert.exe","CommandLine":"synthetic only, never executed"}}]}
```

JSON 字段名区分大小写，事件字段值为字符串。时间必须带时区；转换 UTC 后保留原时间。XML 读取 System 的来源/主机/事件号/RecordID/TimeCreated 及 EventData 具名字段。拒绝 DTD、实体声明、重复 JSON/Data 字段和非 UTF-8。原始文件 SHA-256、输入序号、RecordID、字段原值与缺失项均可追溯。

**EVTX、任意 JSONL、其他 EDR 导出格式不直接支持**，必须先在可信工具导出 XML 或转换为此契约；禁止调用日志中的转换命令。公开 OTRF 回放脚本展示一种固定、可审计的 JSONL 转换，而非通用隐式兼容。

语义覆盖：1 创建、3 网络、5 终止、11/23/26 文件、12/13/14 注册表、22 DNS、255 传感器错误。其他事件保留字段并列为 unsupported；255 使报告 incomplete。未观察事件不等于该传感器功能已启用、完整或无行为。

## Sigma 语义与来源

两条规则完整保留 SigmaHQ 原始 YAML、作者、链接及 DRL 1.1 许可：

- Suspicious Download Via Certutil.EXE（medium，upstream test）。
- Group Membership Reconnaissance Via Whoami.EXE（medium，upstream test）。

固定 upstream `b7920ed31356fb7f6a9275b34737d8604c65bac3`，清单 `rules/sigma/manifest.json`，资产集 `sigma-offline-v1`。每次受限解析校验原文件 SHA，使用 `yaml.safe_load`；不接受任意规则上传。命中报告保留作者（DRL 要求）、规则 ID、来源、版本、资产 SHA、级别和事件 ID。发现测试状态规则不等于生产准确率已验证。

支持 Windows process_creation 映射 Event 1，字段 map 的 AND、list-of-maps 的 OR、字符串值/列表、默认不区分大小写的 Sigma `*` / `?` 与转义、`contains` / `startswith` / `endswith` / `all`；条件为 selector、括号、and/or/not、all/1 of glob/them。字符串匹配不做分词、编码转换或命令执行。

**不支持** regex/re、windash、base64、cidr、fieldref、数值比较、聚合/时间窗、多事件 correlation、其他 logsource、null/非字符串检测值。逐条完整检查，非命中分支中的不支持项也标 unsupported。缺字段使用三值逻辑，`not missing` 不会变成命中。unsupported / field_incompatible / not_observed / unavailable 与 no_match 分开呈现。

## 进程与静态关联

按主机（大小写不敏感）、ProcessGuid、有效时间建立创建节点。GUID 不跨主机；重复创建产生歧义时不强行合并。终止按时间排序，取最早唯一有效终点，不被重复终止延长；父节点必须覆盖子创建时间。没有 GUID 时，只允许唯一、显式起止且无重叠的 PID 生命周期回退。名称不用于身份，无法关联的事件保留 `process_id:null`。相同时间但无法证明先后顺序的父边保守不建。

从静态详情选择“导入日志并尝试精确关联”。只有 ProcessCreate `Hashes` 的完整 SHA256 与已存在静态报告相同才建立 `log_claimed_sha256`，并列出对应进程节点。**这是导入日志的声明，不是日志真实性验证或该 PE 被实际执行的证明**。缺哈希/原报告缺失/同名文件均不自动关联。静态五引擎、模型分数及融合保持原样，行为信号不加入阈值。

## API / 持久化 / 边界

- `POST /v1/behavior`：原始 XML/规范化 JSON 字节，201 完成报告；可选 `?task=<id>&file=0`。
- `GET /v1/behavior?limit=50&offset=0`：报告摘要；可用 `sha256` 过滤已明确关联的静态报告。
- `GET /v1/behavior/{id}`：完整报告/JSON 导出；受现有认证保护。
- 错误：413 大小超限、422 格式/规范证据超限、408 上传超时、429 背压、504 子进程 deadline、503 进程/库不可用、507 存储保留阈值。失败没有阴性报告。

导入是最多 20 秒的同步受限请求，**不是可恢复扫描任务**；同一实例仅 1 个行为解析，上传限 10 秒/4 MiB，事件上限 1,000，规范化证据上限 768 KiB，字段数≤64、字段长度≤4,096。独立子进程 256 MiB、既有 Windows Job/Linux supervisor 终止语义，输出≤2 MiB；超时按进程终止，不把 Future.cancel 当强制取消。已有静态队列/Worker 未替换。原始上传只在内存/解析进程传递，不另存原日志。

进程和资源限制不等于文件系统/网络权限沙箱。客户机与宿主机的既有安全边界继续适用；本轮只在宿主导入合成/公开授权日志，未声称新行为 Worker 已在 Linux 客户机单独实测，也未扩大其权限。

`AEGISAV_TASK_DB` 同目录的 `*.behavior.sqlite3` 独立库，schema 1：`behavior_reports(id,created_at,status,source_sha256,linked_sha256,report_json)`；created/id 与 linked_sha256 索引。BEGIN IMMEDIATE 初次迁移、单报告事务、WAL、synchronous FULL、busy_timeout 5s、启动 quick_check。损坏或未来 schema 启动失败，保留文件。Unix 新目录0700、DB0600；Windows 继承现有私有目录 ACL，部署方仍需检查账户访问范围。

规范化字段（包括命令行）保存在报告库，不能声称完全不含敏感日志。128 MiB 主库或磁盘余量不足512 MiB停止接收，内存模式最多32报告；不自动删除正式报告。阈值是保留余量，不是含 WAL 的精确硬磁盘配额。服务中断时未完成导入没有“已完成”报告，重启须重新导入；完成报告仍可读取。重试可能生成新报告 ID，不承诺提交幂等。

## 复现与验证

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests/test_behavior.py backend/tests/test_behavior_api.py backend/tests/test_behavior_cli.py -q
.\.venv\Scripts\python.exe -m experiments.behavior_public_replay artifacts/my-public-replay
.\.venv\Scripts\python.exe -m experiments.benchmark_behavior artifacts/my-behavior-benchmark
# Playwright 安装位置通过环境变量指定；仅使用本机已有浏览器
$env:AEGISAV_PLAYWRIGHT_MODULE='<installed playwright module path>'
node frontend/scripts/check-behavior.cjs
```

公开日志：OTRF Security-Datasets，MIT，固定 `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87` 的 IE 注册表查询回放；只读取 ZIP 中唯一受限 JSON 成员到内存，不解压文件到磁盘。结果保存在忽略的 artifacts；不提交原日志、主机标识或私有报告。保留来源、压缩包/成员/转换后 SHA；排除非 Sysmon 事件数显式报告。此测试既不是执行样本，也不是恶意真值评测。

本轮真实结果与截图复核见 [Stage F 报告](research/ROUND_REPORT_20261019_STAGE_F_PUBLIC.md)。EVTX 原生解析、完整 Sigma correlation、日志签名/防篡改采集及任何 Windows 动态执行沙箱均未实现；后者需另行明确授权、安全与资源方案。
