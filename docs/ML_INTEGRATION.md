# 外置 ML 集成与冻结路由

整理日期：2026-11-22。当前 API 有认证；以下配置沿用冻结模型，不引入新权重或阈值。

## 选择策略

| 策略 | 原生 Win32 / .NET | 原生 x64 PE | 其他 PE 架构 |
| --- | --- | --- | --- |
| 默认 `general` | 官方通用 PE，阈值 0.5 | 官方通用 PE，阈值 0.5 | `not_applicable` |
| 可选 `win64_low_fpr` | 官方通用 PE，阈值 0.5 | 本地 Win64，阈值 0.9831222501035356 | `not_applicable` |

同时检查 Machine、PE32/PE32+ Magic 和 COM Descriptor。托管 x64 走通用模型；
ARM64/ARM64EC 不因 PE32+ 就套用 Win64。这是训练域的保守范围。
默认策略未自动换成 Win64；可选阈值沿用冻结验证周，不来自本轮良性样本或
已观察最终测试。两种策略都没有部署 FPR 保证，通用模型未独立校准低 FPR。

## 版本与特征接口

`experiments/build_ml_bundle.py` 仅组装已经取得并核对摘要的固定上游提取器、
warning 清单、官方通用权重和本地 Win64 权重，不打包 PE，不使用 pickle。
`models/ember2024/registry.json` 记录完整 SHA-256、2568 维特征、上游和数据修订、
模型版本、适用范围、阈值及来源。注册清单摘要加策略名构成 ML artifact ID，进入缓存键。
装载、缓存复用前、推理前及子进程都核对资产。变更需发布新清单并重启 API。
摘要校验不是发布者签名；正式部署需管理员安装、API 用户不可写的资产。
本轮 VM 功能验证使用单独非特权测试目录，未改变运行中评测的 root 代码。

特征接口接受字节，返回分数、schema 摘要、float32 向量摘要和提取/预测耗时，
不返回完整特征或文件内容。固定校验 LightGBM 4.6.0、NumPy 2.2.6、
scikit-learn 1.6.1、pefile 2024.8.26、signify 0.7.1。完整依赖及 Linux OpenSSL 3
所需既有 oscrypto 修订沿用安装和来源记录。

## 失败、并发和融合

- 每文件使用可丢弃子进程，最多两个并发；默认 60 秒推理预算包含排队、
  启动和模型加载。超时清理另有最多 4 秒预算。Windows 清理 worker 进程树，
  覆盖 venv 启动器创建的第二个 Python；清理无法确认则返回错误并禁用 ML，需重启。
- Linux 子进程限制 1.5 GiB 地址空间、60 秒 CPU、64 KiB 输出文件，禁止 core。
  输出使用短期临时文件，输入 PE 只经 stdin 传递。进程边界不构成恶意文件安全沙箱。
- 不适用为 `not_applicable`；缺资产/依赖为 `unavailable`；解析、维数、有限值、
  完整性和推理异常为 `error`；超时为 `timeout`。缺分数不当 0，不缓存失败，
  不把失败当良性，不返回原始异常文本。
- `fusion.policy_id=evidence-or-v1` 列出阳性与弃权引擎，每引擎保留证据。
  审定恶意 SHA 可裁决恶意，其他阳性形成可疑证据；可信良性 SHA 不能覆盖阳性。
  全阴性仍不等于已证实良性。ML 分数不是已校准的部署恶意概率。

## 源码服务配置

先取得合法授权的 registry、全部权重及匹配的独立 ML Python；公开仓库不提供这些私有资产。

```powershell
$env:AEGISAV_MODEL_DIR = '<absolute model directory containing registry.json>'
$env:AEGISAV_ML_PYTHON = '<absolute ML Python executable>'
$env:AEGISAV_ML_PROFILE = 'general'
.\.venv\Scripts\python.exe -m experiments.serve_local
```

通过已认证 `GET /v1/engines` 核对可用性，再用良性文件验证；状态探测不能代替真实 Worker 依赖检查。
也可安装固定 `.[ml]` 依赖，但必须匹配 registry 所记录实现，不能混用不同 EMBER 特征版本。
便携包用 `aegisav.desktop configure` 写包外配置，见 [部署](DELIVERY_RUNBOOK.md)。
旧 VM root 只读部署过程属于历史研究，不作为 Windows 安装命令；见 Git 历史中的部署运行说明。
Windows/WSL 只用良性控制，真实恶意 PE 仅留既有隔离 Ubuntu VM 静态分析。
