# 课程 SHA-256 报告查询 CLI

独立入口：`python -m aegisav.hash_query`。只读取哈希清单和报告，不读取样本、上传、下载文件本体或执行样本；不接入生产扫描器、不修改规则库和融合阈值。默认离线；联网仅有固定 VT GET 报告端点，无自定义 URL。2026-10-23 的真实验收采用已有缓存，**没有发送新的平台查询**。

## 先复用现有课程成果

审计了同级 `apicall/backend/app/providers/virustotal.py`、`cn_platform.py`、`services/storage.py`、`services/inputs.py` 和 `backend/run_experiment.py`。它们已有 VT 查询、状态归一化、CVERC 四类报告适配和 SQLite 批处理。现有运行脚本会加载 `.env.local`，不能为离线验收直接运行。本次没有读取该文件，也没有使用已有密钥。

本 CLI 复用相同固定 VT GET 协议及 `apicall/data/reports/virustotal/<sha256>.json` 存储约定，增加可独立使用的纯标准库入口、原始响应持久化、完整身份核验和离线缓存迁移。直接导入同级应用会引入外部源码路径、httpx、数据库和 dotenv 配置依赖，因此没有把整个服务复制或嵌入本项目。

老师分配的清单是 `apicall/results/experiment-3/group-b-sha256.txt`，不是 MalwareBazaar 的 120 项训练/查询清单。已有历史结果 `execution-summary.json`、`group-b-results.json` 与缓存应优先复核，避免重复消耗额度。此次逐项离线验收结果：100 个合法且唯一的 SHA-256，100 份缓存同时满足 `data.type=file`、`data.id=输入SHA`、`data.attributes.sha256=输入SHA`，CLI 请求数为 0。结果位于本机 `output/course-query/teacher100-vt/manifest.json`；哈希清单与原始报告留在本机，不作为仓库示例。

## 官方接口与实际限制

核查日期：2026-10-23。

- VT 官方 [获取文件报告](https://docs.virustotal.com/reference/file-info)：`GET https://www.virustotal.com/api/v3/files/{id}`，支持 SHA-256；[认证](https://docs.virustotal.com/reference/authentication)规定 HTTPS 和 `x-apikey` 请求头。
- VT 官方 [Public/Premium 限制](https://docs.virustotal.com/reference/public-vs-premium-api)：Public 4 次/分钟、500 次/天，禁止商用产品/服务及不贡献新文件的商业工作流，也禁止多账号绕过限制；具体账户权益应在账户页确认。这里是独立课程报告工具，不将 Public API 集成进产品。
- 本工具固定相邻请求等待至少 16 秒（含重试）；默认每个输出目录累计最多 400 次请求，`--max-requests` 上限 500。该计数在发送前落盘，跨 `--resume` 持续累计，**不是账号全局或每日配额统计**。其他工具、其他输出目录的用量必须由使用者自行核对，不能通过换目录绕过限额。100 个首次查询至少约 26.4 分钟，重试会更久。
- 超时默认 30 秒；默认最多重试 2 次，仅网络错误、429 和 5xx 重试。退避为 16、32、60 秒封顶；`Retry-After` 支持秒数/HTTP 日期。服务端要求等待不超过 60 秒时，至少等待其要求及本地退避；超过 60 秒时不截短服务端要求、不长时间阻塞进程，而是保存 `deferred_retry_after` 和 Unix UTC 秒数 `not_before`，其余未查询项记 `blocked_retry_after`。在截止时间之前，即使 `--resume --live` 也不会发送请求；截止后可用同一目录恢复。该截止时间也写入审计事件。401/403 停止本批后续请求。404 只记 `not_found`，保留原始错误正文，绝不伪造检测报告或推断良性。
- 同级 `apicall/国家计算机病毒协同分析平台_API接口文档.md` 声明 CVERC 报告使用固定 `POST /api/v1/file/report` 等路径，在 JSON 中放 `apikey` 和 `hash`。它是本地参考文档，无法单凭文件名证明来源。官方 [协同分析平台](https://virus.cverc.org.cn/) 可访问但仅返回需 JavaScript 的应用壳；在官方域名搜索及公开页面中未核实可引用的 API 认证、配额、响应身份绑定说明。[应急中心公开站点](https://www.cverc.org.cn/)包含公告，但此次首页抓取超时。**不能因此断言平台没有 API**；当前只是尚无足够官方证据启用本 CLI 的在线适配。没有探测未公开端点或提交凭据。

## 使用

在 `aegisav` 根目录使用现有虚拟环境。若环境未安装本项目，先仅在当前进程设置 `$env:PYTHONPATH = 'backend'`。输入为 UTF-8/BOM 文本，每行一个 SHA-256；空行和 `#` 开头的注释跳过，统一小写、去重，任何非法行导致整批在请求前失败。

离线复核历史 100 项（不需要密钥）：

```powershell
.venv/Scripts/python.exe -m aegisav.hash_query vt `
  --input D:/2026fall/badcode/apicall/results/experiment-3/group-b-sha256.txt `
  --cache-dir D:/2026fall/badcode/apicall/data/reports/virustotal `
  --output output/course-query/teacher100-vt
```

已有输出加 `--resume`；它先核对 provider、清单及已完成原始报告的 SHA-256，再跳过完成项。失败、限流、超时及未完成项会重试；累计请求预算不会清零。输出目录为单写者，锁文件存在时拒绝操作。进程被强制终止后，仅在确认没有进程运行时移除该目录的 `.hash-query.lock`，再恢复。原始报告校验不通过时保留现场，不自动覆盖。

缓存缺失记 `blocked_offline_cache_miss`，缓存身份不符记 `invalid_report`，不会自动联网。需要查询新清单时，人工确认名单和账户配额后，在受保护的进程环境中配置 `VT_API_KEY`（兼容原应用 `VIRUSTOTAL_API_KEY`），再显式使用 `--live`：

```powershell
.venv/Scripts/python.exe -m aegisav.hash_query vt `
  --input approved-sha256.txt --output output/course-query/new-approved-run `
  --live --timeout 30 --retries 2 --max-requests 400
```

可同时给 `--cache-dir`，有效缓存会先复用。不要把密钥写入命令参数、代码、报告、提交记录或截图；CLI 不加载 dotenv，不打印凭据、请求头、原始异常或响应正文，不跟随 HTTP 重定向。响应若回显当前密钥，磁盘正文将替换为 `[REDACTED]` 并标记 `raw_redacted=true`，这时保存的摘要对应脱敏正文。

## CVERC 手工导入与证据边界

没有可核验接口说明时，执行以下命令会为每个 SHA 留下 `blocked_no_documented_api`，不发送请求，退出码 1。这是阻塞记录，不是 100 项检测完成：

```powershell
.venv/Scripts/python.exe -m aegisav.hash_query cverc `
  --input approved-sha256.txt --output output/course-query/cverc
```

如有通过本人获授权的官方会话取得的报告，可人工整理 JSON 报告（顶层 `sha256` 必须与清单相同）和以下索引。原始官方文件应另行保留；若 JSON 是人工转录，应在 `authentication_method` 中明确写出原件定位及转录过程，不称为原生 API 响应。

```json
[
  {
    "sha256": "<清单中的64位小写SHA-256>",
    "report_file": "reports/<文件名>.json",
    "report_sha256": "<报告JSON原始字节的SHA-256>",
    "provenance": {
      "source_url": "https://virus.cverc.org.cn/",
      "retrieved_at": "<带时区的ISO-8601时间>",
      "authenticated_by": "<获授权查询者身份>",
      "authentication_method": "<本人登录官方平台的方式、原件定位、是否人工转录>"
    }
  }
]
```

```powershell
.venv/Scripts/python.exe -m aegisav.hash_query cverc `
  --input approved-sha256.txt --output output/course-query/cverc `
  --imports authenticated-import-index.json --resume
```

检查索引成员、重复项、官方 HTTPS 域名、禁止 URL 用户口令/查询串、时区、操作者声明、原始字节摘要和报告内 SHA 绑定；报告路径必须位于索引目录内。导入状态明确为 `manual_imported_unverified_origin`：**它仅验证操作者提供的身份声明和内容一致性，不能密码学认证平台签发，也不能证明登录权限或报告结论真实**。没有官方签名/可验证的 API，程序不会宣称手工报告已经平台认证。缺少这些证据时保持阻塞；不能用模板或模拟报告充当真实 CVERC 结果。

## 输出与验收

每个输出目录包含原子替换、刷盘的 `manifest.json`，逐次原始报告 `raw/<sha>/<序号>.json`，以及刷盘追加的 `audit.jsonl`。清单记录每项状态、HTTP 状态、正文路径/摘要、来源或手工 provenance、每次网络错误、累计请求数和时间；发送前先记 `requesting`，强制终止不会丢失已计入的请求。恢复会再次核验完成的 VT 身份和正文摘要；限额内的失败原始响应同样保留。网络响应最多读取 16 MiB 加一个用于判断超限的字节；超限记 `response_too_large`，不解析、不存储正文、不自动重试，在清单和审计中保留失败与大小限制。既有缓存、手工报告和恢复清单单文件上限 16 MiB；SHA 清单和手工导入索引上限 1 MiB，超限在解析前拒绝。文件和清单分别原子写入，并非跨文件事务；崩溃后可能有未被清单引用的原始文件。仅支持一个进程写同一输出目录。

退出码：0 表示所有清单项都处于已绑定报告/明确 404/手工导入状态，**不表示全为阳性或已认证手工来源**；1 表示有阻塞/失败/未完成项；2 表示输入、配置、导入或输出完整性错误。控制台只打印 provider、唯一哈希数量、累计请求数量和状态计数。

无真实样本的使用例见 `docs/examples/course-query/README.md`。针对网络的验收全部使用 mock：

```powershell
.venv/Scripts/python.exe -m pytest backend/tests/test_hash_query.py -q
```

当前实证：老师 100 项 VT 历史缓存已全部离线核验；CVERC 100 项仍无真实报告，本工具不会填充假结果。后续若获得可核验官方 API 文档、账户授权、配额说明和实际响应结构，再审定是否启用仅哈希报告查询适配。当前代码不包含 CVERC 网络请求。

崩溃窗口回归：若原始响应已保存但其清单条目尚未提交，续跑会保留已有原始文件，选择下一空闲序号；不覆盖孤立响应。本轮实际故障回归包含强制中断后的此类恢复。
