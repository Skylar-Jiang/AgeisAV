# AegisAV

Windows PE 五引擎静态检测平台：SHA-256、TLSH/SSDeep、YARA-X、ClamAV、LightGBM，
统一 FastAPI、版本缓存、有界批量任务、模型发布及现有 VMware 离线静态分析自动化。

这是经筛选的公开源代码快照。完整本地研究历史、私有候选清单、标签证据、原始数据、
API Key、模型权重及 VM 文件没有上传。公开摘要不是独立准确率证明。Stage E 为 Engineering complete / Research open；Stage F 离线行为分析已交付。
来源和当前限制见[进度](docs/PROGRESS.md)、[实验摘要](docs/EXPERIMENTS.md)。

## 本地无害开发

需要Python3.12。安装`requirements-win-py312.txt`和`pip install -e . --no-deps`，
运行`python -m pytest -q`，构建前端后以`python -m experiments.serve_local`启动。
生产入口默认开启仓库外本地访问密钥、HttpOnly会话及同源/回环校验，不应直接暴露到公网；
`/v1/engines`显示真实可用性，缺失工具/模型会弃权。
ClamAV与模型权重需另按部署说明配置。源码测试中的私有归档证据回归在公开分发中明确跳过。

## Linen真实工作台

`frontend`使用Next.js/TypeScript/Tailwind/shadcn；`npm ci`后运行`npm run build`。
仓库根执行`python -m experiments.serve_local`，
访问<http://127.0.0.1:3417/>或<http://127.0.0.1:3417/linen/>。仅保留Linen自然滚动与记录区短时虚化。
已删除其他视觉方案、方案选择器、吸附模式与比较控件。
默认工作台实际读取良性开发文件、提交任务并显示服务返回的报告。首次连接需要启动器打印路径
中的本地访问密钥，不要写入前端构建、URL或Git。显式`/linen/demo/`才使用合成数据且不上传内容。
任务报告和状态已由SQLite持久化，上传字节仍只在内存；重启中的任务标记interrupted，需重新提交，
没有自动续扫。生产取消/截止会终止独立扫描进程树。Schema、额度与备份见[TASK_RELIABILITY](docs/TASK_RELIABILITY.md)。
真实业务页面：`/linen/tasks/`批量任务、`/linen/history/`历史、`/linen/assets/`规则/模型只读状态、
`/linen/statistics/`实际状态/弃权/成本窗口。没有独立标签时不提供正式准确率。
失败、404或连接中断不会回退为演示或阴性。契约、安全边界、测试与限制见
[产品A/B报告](docs/research/ROUND_REPORT_20261015_PRODUCT_AB.md)。
实际Skill应用、浏览器验收及复验见[前端记录](docs/FRONTEND_PROTOTYPES_20261014.md)。

## 安全与复现

真实恶意PE仅在已核验隔离的专用Ubuntu VM内静态处理，禁止执行。
VM脚本目前绑定本项目已有客户机、磁盘标识与冻结研究配置；其他环境必须先审查和适配，
不能直接运行全部脚本。NAT仅用于元数据和加密归档，解包/分析前移除网卡并核验无路由、
无共享/剪贴板/拖放。凭据采用仓库外受保护配置。

五引擎未命中不等于安全；未完成/失败/不适用不计阴性；未知标签不计正式准确率。
原始证据和候选清单需合法授权本地访问，因此公开摘要无法单独复现私有文件上的检测结果。
`PUBLIC_SOURCE_MANIFEST.json`提供本次公开文件字节哈希，不含私有历史。

## 离线行为证据与本地交付

`/linen/behavior/` 支持受限 Sysmon XML / 标准化 JSON 导入、固定 SigmaHQ 规则、进程链、原始事件字段与精确哈希声明关联。无日志不是行为安全，不改变静态裁决。
原生 EVTX 和真实恶意动态执行未启用。示例：`backend/tests/fixtures/sysmon_harmless.json`（纯合成）。
见 [行为功能与边界](docs/BEHAVIOR_ANALYSIS.md)、[Stage E 工程收尾](docs/STAGE_E_CLOSEOUT.md)、[本地部署与 CLI](docs/LOCAL_DEPLOYMENT.md)。

仓库外报告 CLI：`python -m aegisav.behavior_cli input.json --output <private-new-report.json>`。
