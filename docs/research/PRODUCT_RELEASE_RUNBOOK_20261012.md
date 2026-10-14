# 产品发布与回滚：2026-10-12

当前正式 VM 安装 release 为 `c699902f19640593`，运行入口固定到
`/opt/aegisav-product/releases/c699902f19640593`；`current` 是 root 管理的链接。
旧评测目录 `/opt/aegisav-static` 未改；仅复用其固定 Python 依赖环境。

## 发布

1. `python -m experiments.build_ml_bundle` 组装固定官方代码/权重和本地冻结 Win64 权重。
2. `python -m experiments.build_product_release` 产生只含代码、规则和模型的 tar，以及 `artifacts/product-release-latest.json`。不打包 PE。当前压缩包 SHA-256：`a7f7d627cdaefecf65c3183d2a3945352e038a3be3d8660551281f88cc8e5c3a`。
3. 仅在专用 VM 已恢复干净且无样本/批次检查点时，关机后切 Host-only，运行 `vm/Publish-ProductRelease.ps1`。严格固定 SSH 身份、known_hosts、主机名和管理员路径；不硬编码密码。不在含样本的 VM 启用网络。
4. root 安装器验证压缩包摘要、成员白名单、数量/大小、逐文件摘要和禁止链接/路径穿越；只写专用 release 目录。文件 root:root 0444、目录 0555，API 用户不可写。清单和 SHA 是完整性校验，不是发布者数字签名，也不防管理员修改。
5. `aegisav-api.service` 使用 `aegisav-operator`，只绑定 127.0.0.1:8000；ProtectSystem=strict、ProtectHome=yes、NoNewPrivileges、PrivateTmp，IP 只允许 loopback、MemoryMax=3GiB、TasksMax=96、HTTP 并发上限 8。没有通过权限扩大来修复服务启动。
6. 正常关机、`Manage-VM.ps1 -Action Offline`，通过 VMX 和客户机两侧检查隔离。运行 `verify_product_service.py`，包含真实 HTTP、缓存、批次重复、422/413、写拒绝与 ML 故障路径。55 MB 文件通过真实 ML 引擎接口验证；HTTP 仍保持 16 MiB 上限。

## 特征与版本

模型/策略保持旧冻结版本；当前清单 SHA 为
`13f35d8cd69b71e1f07f205b4ec633aafacce80423a10ebf4052293aa100b6f5`，
默认 ML ID 后缀为 `:general`，融合 ID 为 `evidence-or-v1`。
`chunked-histogram-v1` 只替换 ByteHistogram 的 uint8→int64 计数临时数组路径，
以 1 MiB 块整数累加，沿用原 float32 归一化和其余特征。适配器自身摘要也写入清单，
资产/实现变化会使旧缓存失效。模型分数不是经过独立部署校准的概率。

每文件 ML 可丢弃进程、最多并发 2，1.5 GiB 地址空间、60 秒预算保持不变。
缺资产 unavailable、解析/完整性错误 error、真实超时 timeout，均不返回伪造分数，
均作为弃权且不缓存；全阴性仍为 undetermined。

第一次安装 `1cac6ed3ba7a740c` 暴露了 ClamAV 数据库冷启动时 main 永久丢弃适配器的问题。
回归先复现再修复：保留适配器，后续请求继续 probe。旧失败证据保留，修复后重新构建发布。
不再将旧 release 或其 v1 快照作为当前回滚点。

## 快照与恢复

当前推荐 `clean-product-lowmem-off-20261012-v2`，已实际恢复、新 boot 离线启动、
完整重跑服务验证；最后正常关机。仅通过 `vmrun deleteSnapshot` 删除被替代的
`clean-product-lowmem-off-20261012-v1`，未手动删除磁盘/内存文件。
保留阶段 1 v2、ML v2、检查点 v3 三个既有回滚点。恢复前必须关机；
恢复后重新检查 VMX 与客户机隔离，再验证版本、服务、资产权限和扫描。
参见[快照审计](../benchmarks/product_snapshot_validation_20261012.json)和
[恢复后验证](../benchmarks/product_service_snapshot_restore_20261012.json)。

## Worker 复用的下一步

当前没有启用常驻解析 Worker 或批量预测。真实模型预测仅约毫秒级，较大文件的特征、
模糊摘要和首次 ClamAV 扫描耗时更大；只批量调用 LightGBM 不能据此承诺端到端显著增益。
复用解析进程还需验证跨文件状态、RSS 增长、单任务超时终止/替换和故障隔离；
先固定同一文件向量/分数一致性，再对比可丢弃 Worker、有限复用次数和批量推理。
目前两并发提高吞吐但扩大部分文件延迟，不提高默认并发或放宽资源上限。
