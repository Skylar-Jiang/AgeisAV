# Stage G 首项：本地部署与离线回放 CLI

Stage F 功能验收后开始 Stage G 交付准备；独立科学评测继续 open，不能宣称项目最终准确率验收通过。既有本地部署、认证和 Linen 保持不变，新增行为模块没有外部执行服务。

## 部署检查

1. Python 3.12，安装固定依赖；`pip install -e . --no-deps`。新增 PyYAML 6.0.3 及 `rules/sigma` 的完整 YAML/manifest/许可必须随代码部署，不能只复制前端。
2. `npm --prefix frontend ci`，`npm --prefix frontend run build`；Next.js 遥测配置如出现跨设备 rename，可在本次构建设置 `NEXT_TELEMETRY_DISABLED=1`。不要修改别的项目或删除全局配置。
3. 本地启动 `python -m experiments.serve_local`，仅 `127.0.0.1:3417`。访问密钥和 `AEGISAV_TASK_DB` 必须在仓库外，按私有文件设置 ACL。禁止将密钥写进命令行参数、截图或 Git。
4. 使用 `/v1/engines` 查看实际静态资产状态；公开代码未包含私有模型/恶意数据，unavailable 不能伪装成阴性。行为模块不依赖 ML 或 ClamAV 可用，不意味着完整静态引擎已在该宿主部署。
5. 浏览器导入 `backend/tests/fixtures/sysmon_harmless.json`，核对 6 事件、2 进程、1 命中；导出报告、重启后再查。实际自动化验收使用临时本地凭据和数据库，不使用 MalwareBazaar 凭据。
6. 备份停止服务后的任务 SQLite 和同目录 behavior SQLite；运行中备份需 SQLite backup 语义并包含一致性，不只复制 WAL 主文件。原始行为日志自行私有保管；报告数据库也可能包含敏感命令行。

## 无服务 CLI

```powershell
.\.venv\Scripts\python.exe -m aegisav.behavior_cli backend/tests/fixtures/sysmon_harmless.json --output "$env:LOCALAPPDATA\AegisAV\exports\harmless-behavior.json"
```

复用 256 MiB/20 秒受限子进程，不需要加载模型、不执行日志。输出须为仓库外的新文件，不覆盖旧报告；终端只输出状态/事件和命中数量。退出码 0 代表成功产出报告，**不代表安全**；2 为输入/新输出路径拒绝，3 为解析进程失败/超时。CLI 不打开静态任务库，所以 `static_link:not_linked`。

实际测试已覆盖有效导出、禁止覆盖、实体拒绝及仓库内输出拒绝。其余 Stage G 待办：目标部署操作系统的交付包验收、完整操作手册/设计报告、跨环境依赖验证和最终演示；不以此代替独立低 FPR 验证。不上线公网，不启动新 VM 或动态运行真实恶意程序。
