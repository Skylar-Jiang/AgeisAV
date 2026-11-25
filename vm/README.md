# 既有隔离 Ubuntu VM 的维护与静态分析工具

本目录不是安装 AegisAV 的前提，也不是自动创建 VM 的安装器。Windows 源码/便携安装见 [部署手册](../docs/DELIVERY_RUNBOOK.md)。
这里保留既有专用分析机的隔离检查、静态分析、受限采集和对应测试依赖；旧试验编排与一次性诊断从当前树移除。
没有因本次文件整理启动 VM、改变配置、快照或移动真实样本。

## 使用边界

- 真实恶意 PE 只在已有授权隔离 Ubuntu VM 内静态解析，不执行，不转移到 Windows/WSL。
- 脚本绑定原专用 VM 与环境，不是通用工具；先审查路径、身份、实际资源及当前电源状态。
- 历史 2026-10-17 资源实验使用 6144 MiB 客户机、扫描 cgroup 2 GiB、独立 clamd 2.5 GiB；它不是当前运行态核验或容量保证。
- 宿主保留至少 2 GiB 物理内存余量；不足则延期，不强杀其他进程或新建 VM。
- VMX 检查通过不代表客户机已隔离。真实样本阶段还须核对新 boot 的客户机接口/路由、HGFS、共享、剪贴板、拖放、USB 与 VMCI。
- 任何联网准备必须先恢复无样本的干净环境；签名更新与分析分开，测量冻结版本。已有 VM/快照与私有凭据不属于源文件清理对象。

## 现役入口

```powershell
# 只读状态/前置检查；不将 ready 当作客户机隔离通过
.\vm\Manage-VM.ps1 -Action Status
.\vm\Manage-VM.ps1 -Action CheckOffline
.\vm\Get-TaskGuardReadiness.ps1
```

[样本操作规程](SAMPLE_WORKFLOW.md) 说明既有静态工具、离线导入/结果导出、预算、断点和失败语义。
`Analyze-OfflineArchive.ps1`、`Measure-OfflineBenign.ps1` 与 `Test-OfflineGuestOps.ps1` 是专用环境工具；
不得因文件存在就直接执行，真实实验仍需既有隔离与资源约束。
`tests/` 是无害配置/隔离/快照守卫测试，不执行恶意样本。
后台采集逻辑只为保留的审计/边界回归服务，本次未采集新数据；不得在宿主调用真实样本采集器。

## 追溯旧环境

旧镜像安装、历史快照、一次性部署与资源试验见
[清理前的 VM 源码](https://github.com/Skylar-Jiang/AgeisAV/tree/8f24f92d16d40e538e82b5cfdf7f39d40220f50a/vm)。
旧文档中的主机地址、磁盘路径、签名库和快照名称仅是历史记录，不能直接当成现时事实或操作授权。
密钥、VMX、VMDK、原始恶意文件与研究数据均不随公开源码分发。
