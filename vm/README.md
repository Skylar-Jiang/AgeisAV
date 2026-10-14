# AegisAV VMware 静态分析机

## 当前产品基线（2026-10-12）

当前推荐点 `clean-product-lowmem-off-20261012-v2` 包含 root 只读 release `c699902f19640593`，
已实际恢复、新 boot 隔离检查及完整服务复验，最终正常关机。
过时产品 v1 已经由 VMware 删除，保留下述三个既有回滚点，共四个快照。
部署使用 `Publish-ProductRelease.ps1`，只能在无真实样本的干净 Host-only 准备阶段运行；
正式检测前关机切离线并在客户机验证。操作与边界见
[发布运行说明](../docs/research/PRODUCT_RELEASE_RUNBOOK_20261012.md)。
MalwareBazaar 目前仅 Windows 元数据查询，不下载文件；真实恶意 PE 的新来源导入通道尚待验证。

## 历史检查点与快照维护（2026-10-11）

当前检查点基线是 `clean-tools-ml-checkpoint-off-20261011-v3`，已离线启动并完成厂商 600 文件遍历，
操作见[断点恢复说明](../docs/research/BENIGN_CHECKPOINT_RUNBOOK_20261011.md)。
上一轮 ML 回滚点 `clean-tools-ml-off-20261010-v2` 包含分块 TLSH 修复；
`clean-tools-benign-off-20261003-v2` 保留为更新前的阶段 1 回滚点。
下方安装清单及签名版本属于历史批次。当前 ClamAV daily 为 28148，活动 YARA
为固定来源的 246 条，离线扫描已接入公开 EMBER2024 通用 PE LightGBM 模型。
安装脚本 `Install-MLTools.sh`、官方签名更新脚本 `update-clamav.sh` 只能用于
已恢复且不含真实样本的联网准备阶段；先验证安装，再关机切换隔离、建立并恢复快照。

`Prune-ObsoleteSnapshots.ps1` 默认只读列出计划；`-Apply` 仅允许在专用 VM 真正关机、
已恢复当前干净 ML 基线且两个保留点都存在时，通过 `vmrun deleteSnapshot` 清理
明确过时的三个旧快照。不会传递 `andDeleteChildren`，不会直接删除任何 VMDK/VMEM。
合并后再次核对保留点与空间记录，再验证恢复和离线启动。运行中或挂起状态拒绝清理。
2026-10-11 已通过 VMware 删除 `clean-tools-benign-20261002`、
`clean-tools-benign-off-20261003`、`clean-tools-ml-off-20261010`；
D 盘可用空间增加 8,870,068,224 字节（约 8.26 GiB），VM 目录文件逻辑长度
减少 8,870,654,025 字节。两者均在 VM 关机后测量，未将关机释放的活动内存算入清理收益。
空间会受稀疏文件与宿主机其他活动影响，不能用 60 GB 虚拟盘容量代替实际占用。
记录见 [快照清理审计](../docs/benchmarks/vm_snapshot_cleanup_20261011_081818.json)。
两个保留点均已实际恢复并通过新 boot 的离线探针、无害 ZIP 与良性 PE 扫描；
阶段 1 四引擎和 ML 五引擎均无命中/错误。最终恢复干净 ML 基线并正常关机，
见[恢复验证](../docs/benchmarks/vm_snapshot_validation_20261011.json)。
脚本将执行记录保存在含 UTC 时间的独立 JSON 中，空清理计划不会覆盖原始审计。
保护检查已验证 LF/CRLF 元数据，并拒绝错误或重复的当前快照身份。

## 本机清单（2026-09-28）

- Codex 运行于原生 Windows PowerShell；另有 Ubuntu 22.04 WSL2，但 WSL 不用于处理真实样本。
- VMware Workstation Pro 17.6.2，`D:\VM\vmrun.exe`（1.17.0，build 24409262）；`vmcli.exe` 和 `OVFTool\ovftool.exe` 可用。
- 初查无运行中的 VM。已有 Windows XP 两台、Windows 10 一台、OWASP Broken Web Apps 一台；后者虽标记 Ubuntu，却是故意脆弱的 Web 练习镜像，不用作分析机。两个已登记 Kali 路径失效。
- 专用 VM 位于 `D:\VMs\AegisAV-Ubuntu-24.04\guest\AegisAV-Static-Ubuntu\AegisAV-Static-Ubuntu.vmx`；其他 VM 不纳入脚本操作范围。
- 基础镜像来自 [Ubuntu 24.04 发布版云镜像](https://cloud-images.ubuntu.com/releases/server/24.04/release-20260926/)，OVA SHA-256 为 `513a22ebe3982b9387b038f8a2a6dad1af980d4623dca03511312e55ba620b1a`，与同目录 `SHA256SUMS` 一致。它是 Ubuntu 24.04.5 LTS，无图形桌面。虚拟盘扩容至 60 GB，4 vCPU，8 GB RAM。

## 可复用操作

`Build-Seed.ps1` 从 SSH 公钥生成一次性 cloud-init ISO，安装 OpenSSH、open-vm-tools、ClamAV 和 Python 工具。它不写入密码，禁止 SSH 密码和 root 登录。生成 ISO 依赖 WSL Ubuntu 22.04 的 `cloud-image-utils`；本机已安装。私钥保存在当前 Windows 用户的 `.ssh` 目录中，不能提交 Git。

```powershell
./vm/Build-Seed.ps1 -PublicKeyPath "$env:USERPROFILE\.ssh\aegisav_vm_ed25519.pub" -OutputDirectory 'D:\VMs\AegisAV-Ubuntu-24.04\media\seed'
./vm/Manage-VM.ps1 -Action Status
./vm/Manage-VM.ps1 -Action Start
./vm/Manage-VM.ps1 -Action Stop
./vm/Manage-VM.ps1 -Action HostOnly
./vm/Manage-VM.ps1 -Action Offline
./vm/Manage-VM.ps1 -Action CheckOffline
./vm/Manage-VM.ps1 -Action Snapshot -SnapshotName clean-tools-YYYYMMDD
./vm/Manage-VM.ps1 -Action Revert -SnapshotName clean-tools-YYYYMMDD
./vm/Provision-GuestAccess.ps1
./vm/Test-OfflineGuestOps.ps1
```

网络/VMX 配置切换只在真正关机时执行；`vmrun list` 会遗漏挂起 VM，因此脚本还要求 `vmcli Power query` 返回 `PowerState: off`。`Bootstrap` 使用 NAT 完成首次包安装；良性开发阶段改为 VMware vmnet1 Host-only，经专用 SSH 密钥管理。`Offline` 移除所有虚拟 NIC，关闭共享文件夹、HGFS、剪贴板、拖放、USB 和 VMCI。脚本不会接收其他 VM 的路径。

`vmrun` 支持启动、软关机、快照、恢复、Tools 状态和客户机文件/进程操作。后者要求 `-gu/-gp` 凭据。`Provision-GuestAccess.ps1` 仅在专用 VM 的 Host-only 准备阶段创建无 sudo 权限的 `aegisav-operator`，随机生成口令，以 SSH 标准输入写入客户机；去掉 Windows CRLF 中的回车，防止认证不一致。客户机 SSH 密码及 root 登录仍禁用。

凭据只保存在 `D:\VMs\AegisAV-Ubuntu-24.04\media\operator.credential.xml`，由 Windows DPAPI 加密，ACL 限制当前用户、Administrators 与 SYSTEM；不写入代码、Git 或日志。VMware CLI 运行时口令参数仍可被有权限的本机进程读取，因此只使用专用非特权凭据。它不复用宿主机或其他 VM 的账户。

`Test-OfflineGuestOps.ps1` 先检查离线 VMX，只导入新生成的无害文本，运行固定的 SHA-256/隔离检查命令，再导出摘要和检查文本并核对。它不接收任意 VM、任意客户机命令或真实样本路径。2026-10-03 已在无 NIC/HGFS/VMCI 的状态实测成功，恢复快照后再次成功；不能从 Tools running 状态直接推定这些操作可用。

## 已验证的客户机安装

- Ubuntu 24.04.5 已启动；SSH 仅使用专用 Ed25519 密钥，密码及 root SSH 登录禁用。良性开发阶段 `HostOnly` 在 vmnet1 获取 `192.168.84.128/24`，没有默认路由；`ip route get 1.1.1.1` 返回 `Network is unreachable`。此地址由 DHCP 分配，不能写入脚本作为固定值。
- Python 3.12.3 虚拟环境已离线安装 `pefile`、`tlsh-python`、`ppdeep`、`yara-x` 和应用依赖；系统 `sha256sum` 可用。ClamAV 1.5.4 使用官方签名库 `main 63`、`daily 28137`、`bytecode 339`，`sigtool --info` 验证 CVD 签名；`clamd` 仅监听客体 `127.0.0.1:3310`。EICAR 无害测试文件经 INSTREAM 返回 `Eicar-Test-Signature`；一个签名良性 PE 在四个引擎均返回 `no_match`。
- `setup-guest.sh` 将 `StreamMaxLength/MaxFileSize/MaxEmbeddedPE/PCREMaxFileSize` 设为 64M、`MaxScanSize` 设为 128M，并启用 `AlertExceedsMax`。超限告警在适配层记为未完成，不作为恶意命中。`clamav-freshclam` 在实验与离线模式停用以冻结签名版本；更新只能在无真实样本的联网准备阶段手动执行，完成后记录 CVD 版本、关闭更新服务并重新检查隔离。
- `aegisav-isolation-report.service` 在启动时运行客户机检查，将 PASS/FAIL 写入 `/etc/issue` 供 VMware 截图核验；Host-only 下实际返回 FAIL。新版同时记录 boot ID，查询失败不默认为成功。HGFS 日志明确报告 `HGFS is disabled in the host` 时才认可关闭状态；普通查询错误仍拒绝。[open-vm-tools 官方实现](https://github.com/vmware/open-vm-tools/blob/master/open-vm-tools/hgfsclient/hgfsclient.c)规定此关闭分支退出码为 1，因此不能只按退出码或空输出判断共享状态。主机 VMX 关闭共享设置仍须独立验证。
- 2026-10-02 首个名为 `clean-tools-benign-20261002` 的快照来自挂起状态，包含内存，恢复后显示旧 boot 的报告；**不将它用作关机干净基线**。管理脚本已补足电源状态校验，后续干净快照需真正关机且用新名称创建，并验证恢复后的新 boot ID。
- 2026-10-03 真正关机后建立 `clean-tools-benign-off-20261003`。恢复前后 boot ID 分别为 `a5010720-7aba-44fe-8362-ed3952e0673c`、`5b7b00aa-bd63-4032-a4aa-246a0c2d0acb`，无害文本往返及良性 PE 全扫描均通过。真实样本批次完成后再次恢复，boot ID 为 `1a1de3b2-8376-43d1-97b1-ac60babfda01`，新的隔离检查仍 PASS。证据存于 `docs/benchmarks/vm_offline_*20261003*`。
- `Install-StaticTools.sh` 在良性准备阶段安装 `/opt/aegisav-static`：代码、规则、venv 由 root 所有，扫描账户不能修改。`Analyze-OfflineArchive.ps1` 每次先重复离线探针，直接复制用户已有 ZIP，使用固定的非特权 Python 静态读取程序，只导出固定位置的 JSON 和摘要。没有下载样本功能，不解包叶文件，不调用样本；参数口令不硬编码，宿主机临时密码文件使用受限 ACL 并在 finally 删除。
- 同日审查后修订 VMX 重复键拒绝及归档目录预算（包括 ZIP64 覆盖拒绝），安装修订代码并建立/恢复 `clean-tools-benign-off-20261003-v2`。此快照是当时基线、当前阶段 1 回滚点；新 boot 的无害文本、良性 PE 和 JSON 导出已通过。原始真实扫描仍对应旧快照，版本校验值在 `docs/benchmarks/run_provenance_20261003.json`，不能当作修订代码重新跑过真实样本。

## 真实样本前的隔离门槛

1. 保留无真实样本的干净快照，并记录镜像、软件、ClamAV 数据库和规则版本。
2. 关机执行 `Offline`，再执行 `CheckOffline` 检查 VMX。开机后还须从客体确认仅有 loopback、没有 IPv4/IPv6 路由、没有 HGFS 挂载或共享文件夹；再做良性文件离线导入/结果导出的端到端测试。
3. 检查主客体剪贴板及拖放禁用设置；不通过 SSH 维持恶意样本阶段管理。任何隔离检查失败时禁止导入真实样本。
4. 真实样本只可进入已验证隔离的 VM 存储，不得在 Windows/WSL 新增下载、解包或另存为普通文件；样本不执行。2026-10-03 已通过受控通道分析用户提供的现有压缩包；原始来源未知，结果只能按历史多厂商佐证标签描述，不能当作来源已核验的正式测试集。流程与大小限制见 `SAMPLE_WORKFLOW.md`。
5. 实验报告只导出 SHA-256、标签来源、规则/数据库版本、引擎状态、时延和汇总指标；避免导出样本字节。恢复干净快照后重新核验隔离状态。

单凭 VMX 设置不能证明客体运行时隔离。`CheckOffline` 的成功只表示主机配置检查通过，不可当作真实样本许可。
