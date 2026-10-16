# 2026-10-15：A/B 产品契约与真实联调

## A：状态与部署决定

公开基线为`codex/public-platform-20261014`的`3627d9b`，远程fetch后核对一致。
开始时本地工作区干净；本地`898a43f`相对公开基线的backend/frontend/ml/rules/
experiments/vm/依赖/Skills源码diff为空，未推送收尾记录留在研究分支。
本地两套模型、registry、研究数据和旧报告仍存在；公开快照从未承诺附带权重或私有数据。
本轮保留原模型、特征、规则与冻结阈值，不重新建项目或安装Skills。

生产入口`aegisav.main`默认开启本地访问控制；同一FastAPI源托管Linen静态导出和API，
采用[FastAPI StaticFiles](https://fastapi.tiangolo.com/tutorial/static-files/)方式。
启动器固定127.0.0.1、单Uvicorn进程、关闭代理头信任，不开放CORS或其他监听地址。
随机访问密钥位于仓库外用户配置目录；Linux新文件0600，Windows使用用户LocalAppData继承权限。
密钥不会注入前端构建、URL、浏览器存储或日志。初次输入换取8小时签名HttpOnly/SameSite=Strict
会话；验证有效期与签名，注销删除Cookie，换密钥使旧会话失效。HTTP Cookie仅用于回环开发，
不把此方案称为多用户互联网认证或对不可信本机进程的完整隔离。
CLI可用Bearer；Cookie写请求必须携带同源Origin。请求来源IP与Host须为回环，
跨源Origin、DNS重绑定Host及未认证API/文档请求先于扫描被拒绝。
`create_app`可在单元测试中明确不传密钥；部署必须使用带访问控制的main/启动器。

| 端点 | 实际契约 |
|---|---|
|POST /v1/session|Bearer访问密钥换HttpOnly会话，不返回密钥|
|DELETE /v1/session|同源注销|
|GET /v1/engines|实际资产/适用范围/五引擎可用性；ready不保证所有文件都适用|
|POST /v1/tasks|JSON文件名与Base64；202、422校验、413预算、429背压|
|GET /v1/tasks|最多100任务摘要、文件状态/结论；persistent=false|
|GET /v1/tasks/{id}|原报告、失败、版本、去重关系、已处理文件数与墙钟|
|POST /v1/tasks/{id}/cancel|幂等协作取消；当前文件结束后跳过未开始文件|

保留20文件/16MiB单文件/32MiB任务、4活动任务/64MiB原始字节预留、2上传名额、
1任务Worker。取消不承诺强杀当前静态解析；失败/取消/超时/不可用不计阴性。
当前无任务总截止、无跨重启恢复或幂等提交保证，属于阶段C待完成内容。

## B：可操作交付

默认`/`和`/linen/`接真实API，支持实际读取、提交、文件级进度、取消、查询、搜索、
最近30个文件、逐文件原始证据/版本/耗时、真实模型分数与阈值、JSON导出、缓存标记和注销。
不伪造逐引擎扫描进度；文件扫描尚未返回时明确等待，未知/未完成不作为阴性。
缓存复用时引擎耗时标为原计算，本次文件墙钟单列。没有完整数据分母不输出准确率。

原演示被移到显式`/linen/demo/`和`/linen/demo/detail/`，仍使用同一Linen设计系统，
清晰标记演示、不读文件内容。真实报告缺失、404、解析失败或连接失败不会回退演示数据。
继续保留宽屏比例、自然滚动、记录区轻虚化、键盘操作、减少动效及手机布局。
轮询串行且有请求超时；页面隐藏暂停请求，终态任务停止轮询，组件卸载中止请求。
活动任务404允许清除并继续提交；会话过期后重新认证会恢复活动任务查询。

四个已有Skills实际使用：frontend-design维持选定Linen而不改风格；ui-ux-pro-max查询
accessible authentication并落实粘贴、密码管理器、显式标签；react-best-practices用于
API hook职责、请求清理、派生状态与避免重复并发轮询；web-design-guidelines重新读取
[官方规则](https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md)，
审查焦点、可访问名称、加载/错误反馈、溢出与减少动效。

## 实测边界

本轮仅Windows系统自带良性PE与无害非PE夹具；没有下载、解包或执行恶意文件，没有启动VM。
真实浏览器启动独立回环FastAPI与已安装引擎，SHA独立核对、实际ML推理、重复复用、
无效PE错误、部分报告保留、真实UI取消、JSON下载、刷新、断线恢复、404和过期会话都检查。
故障注入路径在JSON中明确injected=true，不是检测结果；先断言活动任务确实401再验证恢复。
截图包含桌面/手机工作台与真实详情，已人工复核，不以编译代替验收。

首轮真实联调18组通过，扩展取消/恢复后21组通过；首次旧构建无法显示认证预期失败另存。
演示复验最初遇已停止预览服务的连接拒绝，独立记录，随后改用新同源服务。
最终通过数量、失败/跳过和成本以`docs/benchmarks/live_api_check_20261015.json`及
`*_20261015_product_demo.json`为准。后端本地全量176passed/6skipped，1既有anyio弃用警告。
6项跳过继承环境限制，不追称引擎正常；公开快照私有归档证据测试会另有明确skip。

当前Windows实际SHA/fuzzy/YARA-X/LightGBM均返回no_match；ClamAV无本机服务，返回
unavailable而非no_match。ML提供真实分数，未修改0.5通用模型阈值。
同一系统PE重复使用仅算1个独立功能文件，无效/取消夹具不计有效PE。
来源可信度、训练重叠及独立标签未在本轮重新认证，不由功能探针推导Recall、FPR、Precision或P95。
首轮该文件墙钟9202.029ms；最终观测的模型分数、引擎耗时与墙钟另存
`live_api_product_summary_20261015.json`，只作为冷启动瓶颈提示，不是可比性能实验或加速证明。

最终真实联调21组、显式演示31组通过；脚本8文件槽为3份报告行（含重复）、3无害解析错误、
2取消项，仍仅1个独立系统PE。部署3417另回放同一良性PE1次，实际报告已可从工作台打开。
宿主机开始/收尾可用RAM约8.05/6.48GB、D可用111.55/111.52GB，为瞬时值，不归因于本轮；
当前out1690534B、.next196452857B。未测峰值、CPU或磁盘IO，不假报性能提升。
未启动VM，没有运行vmware-vmx进程；本轮未删除快照/数据/模型，未重试此前被拒绝的缓存清理。

## 复现

```powershell
npm --prefix frontend run build
.venv/Scripts/python.exe -m experiments.serve_local
# 访问 http://127.0.0.1:3417/linen/，使用启动器显示路径中的本地访问密钥连接。
# API CLI读取仓库外密钥后使用Authorization: Bearer；不把密钥提交到仓库。
.venv/Scripts/python.exe -m pytest -q
node frontend/scripts/check-live-api.cjs
node frontend/scripts/check-linen-ui.cjs
node frontend/scripts/check-linen-scroll.cjs
node frontend/scripts/check-linen-blur.cjs
```

浏览器脚本使用已有Chrome与环境变量AEGISAV_PLAYWRIGHT_MODULE指定的本机Playwright。
真实联调脚本独占3418，结束关闭自建测试服务/浏览器；3417仅保留用户预览用的轻量服务。
公开源码不含本地模型，因此公开环境会如实显示ML unavailable；不能用假引擎补齐“全绿”。

## 下一阶段

C优先SQLite任务/报告持久化、重启中断语义、幂等提交和进程级任务截止/资源隔离；
先避免线程取消被误称为强制终止。D扩展批量任务、历史、资产和实验页，统计只从实际报告聚合，
不提供虚构准确率。检测研发继续使用既有独立划分与VM安全边界，当前80文件unknown来源
观察不改作最终集。ClamAV完整服务验收应在已配置病毒库的环境重验。

A/B源码c1cdbd3；公开3b742627b53173e1e513f7766ee20cda3fcb6c6b已正常快进Push至
codex/public-platform-20261014，远端SHA核对一致。606文件逐字节核验，2类实际密钥与私有候选排除通过；
模型/规则/ML特征/依赖字节与公开父版本一致。公开副本独立175passed/7skipped，本地176passed/6skipped；
私有研究历史未上传。实际浏览器21+演示31检查完成，测试服务/浏览器退出，仅保留3417用户预览服务。
