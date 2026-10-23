# 原生 SSDeep 独立发布候选

当前为 `0.2.1rc1` 候选验证，不替换原 `0.2.0` ZIP，不合并 main，不改变模型、阈值、规则或融合。
原生后端仍需明确选择；正常源码及默认稳定构建保持 Python 后端。

## 运行与回退

候选包使用独立文件夹、端口3420、`%LOCALAPPDATA%\AegisAVDesktop-Candidate` 私有目录。
运行 `Start-AegisAV.cmd`，通过 `Access-Key.cmd` 查看候选自己的访问密钥；
`Stop-AegisAV.cmd` 只停止候选自己的实例。回退时停止候选并启动原稳定包，保留两者报告目录。
不要用候选文件覆盖原包，也不要以管理员身份运行。

模型/ML运行环境和 ClamAV 签名库仍为可选外置组件，不在公开便携核心包内。
既有 ML 通过原 `aegisav.desktop configure --model-dir ... --ml-python ...` 配置；
Windows ClamAV 使用独立回环 sidecar，见 [部署与核验](WINDOWS_CLAMAV_SIDECAR_20261022.md)。
未配置的引擎保持 unavailable/弃权，不会变为阴性。

DLL固定在 `app/native/`，加载前核对摘要、PE32+/x64 和ABI1。
服务进程仅核验资产；DLL只在非管理员且已加入本次命名Windows Job的扫描Worker内加载。
依赖搜索限定System32，现有输入16MiB、Job内存2GiB、进程CPU及取消/截止机制保持。
原生配置错误导致失败，不静默改用Python。后端摘要进入缓存身份，报告明确标记ABI/二进制版本。

## 可复现构建

使用已有编译器，不要求最终用户安装编译器或 Node：

```powershell
.venv\Scripts\python.exe -m experiments.build_native_ssdeep --compiler <gcc.exe> --output artifacts/<fresh-native>
.venv\Scripts\python.exe -m experiments.build_windows_delivery --source <reviewed-source-export> --runtime <pinned-runtime.tar.gz> --runtime-lock distribution/runtime-lock.json --native-bundle artifacts/<fresh-native> --output artifacts/<fresh-release>
```

Python运行时仍固定3.12.15；第三方运行库按已安装分发的RECORD校验复制。
包清单包含DLL、源码、署名与许可；单独候选ZIP和摘要不会覆盖稳定ZIP。
DLL未做发行商代码签名，企业WDAC等策略环境仍需另外验收。

## 已完成及后续记录

正常路径回归357passed/8skipped。实际原生故障注入已覆盖ABI拒绝、崩溃、挂起超时、
运行中取消和96MiB Job拒绝256MiB申请；每次清理和后续Worker恢复均通过。
扩展完整哈希、实际五引擎报告、健康/不可用ClamAV分层和打包浏览器验收的最终结果
由本轮后续实验记录补齐；不能把验证中候选描述为已经上线。
课程数据角色与严格验收缺口见 [课程证据](COURSE_EVALUATION_20261022.md)。

2026-10-23最终验收见[NATIVE_SSDEEP_RESULTS_20261023_PUBLIC.md](NATIVE_SSDEEP_RESULTS_20261023_PUBLIC.md)：235完整哈希、11报告对、健康/不可用各9对HTTP、Chrome28项和包内故障5项均已完成。独立RC通过，不等于已上线或已取得独立准确率。
