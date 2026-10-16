# Stage E 第二轮：真实客户机验收、标签准入与良性 PE / Worker 实验

日期：2026-10-17（Asia/Shanghai；客户机 UTC 日志跨 2026-10-16）。
基于上一轮公开 796398c；私人工作分支保留既有研究记录。
本轮没有更改生产后端、模型、规则、阈值、融合、认证或 Linen。
聚合机器证据：`docs/benchmarks/stage_e2_summary_20261017.json`。逐文件名单、签名、标签及原始报告保留私有，不随公开快照发布。

## 本轮实际变化

| 项目 | 实际结果 | 限制 |
| --- | --- | --- |
| E1 客户机 | 原有 8 GiB VM 真正启动；六组任务/进程/SQLite/五引擎验收通过；128 MiB cgroup 实际 OOM 后恢复通过 | 仅无害故障夹具和良性 PE；未扫描真实恶意文件 |
| 恶意证据 | 固定准入协议；原两例复核，新增三例 probable；另一个双用途候选隔离为 unknown | 共五例 probable，原文件零、high-confidence 零、正式最终可用零 |
| 官方 PE | Python / PuTTY 三个官方包，65 个独特 PE，五引擎全部完成且无阳性 | presumed_benign 代理标签；完整训练/时间/人审未清除 |
| ML 复用实验 | 两次 ABBA 均约 62% 四文件批次 wall 降低，完整特征与分数一致 | 仅两种小型已观察良性 PE；峰值内存增加，未启用生产 |
| 资源 | 原配置不变；工作结束正常关机；六个快照保留 | 已确认过时名单已为空，没有新删除对象 |

## 1. 标签准入及新增证据

`analyst-case-admission-v1` 在新增扫描之前提交为 f94f204，定义 unknown / probable / high-confidence。精确 SHA 的独立主要技术分析可以支持 probable；原文件完整性、严格 PE 校验和可追溯复核才支持 high-confidence 探索性配对分析。最终测试还需要人工接受、未观察结果、预先冻结划分、训练/近重复/时间清除。校验器验证记录的一致性，不能替代对人工声明真实性的审核。九项标签测试通过，没有检测器投票准入或参考库回填。

原 HazyBeacon 与 Win64 reverse-HTTP stager 精确关联保持 probable。新增三例：Ntospy 认证凭据窃取 DLL、Agent Racoon DNS 命令通道、Emotet 凭据盗取链中的精确 DLL。另将 Mimilite 自定义 Mimikatz 工具作为双用途疑点排除，未强行升为恶意。依据分别是 [Unit 42 工具集技术分析](https://unit42.paloaltonetworks.com/new-toolset-targets-middle-east-africa-usa/) 的行为章节及逐项 IoC，和 [第三方软件凭据盗取分析](https://unit42.paloaltonetworks.com/credential-gathering-third-party-software/) 中 Firefox/In the wild 与精确 DLL 对应段落。记录方法是自动化主要来源复核，人工状态 pending。

原两例来源：[HazyBeacon](https://unit42.paloaltonetworks.com/windows-backdoor-for-novel-c2-communication/)；[SAP 入侵案例](https://unit42.paloaltonetworks.com/threat-brief-sap-netweaver-cve-2025-31324/)。报告时间、上传时间、基础设施时间与全球首次发现严格区分。旧 Agent Racoon / Emotet 不能被当作时间外新家族。当前来源集中于一家研究机构，训练及近重复仍待原文件取得后核查；没有有效独立恶意测试样本。CISA Truebot 直接访问返回 403，未据搜索摘要提升标签。

新增 `vm/collect_analyst_cases.py` 仅先准备原两例的小批次采集：在线只下载加密归档，离线受限解包、SHA/PE 核验及标签准入后扫描；独立目录/检查点，至少五秒间隔、本地每天 400 请求安全预算、429 尊重 Retry-After。这个预算不是官方额度声明，仍需服从账户/官方限制。解包沿用 2 MiB 文件输出上限，超限明确失败，不截断特征。此新客户端尚未进行真实网络采集验收。

**采集阻碍：** 自动审批拒绝了读取仓库外 DPAPI 密钥并传入客户机的命令，未提供具体原因；整条命令未执行，未绕过。已请用户手动配置客户机权限 0600 的 `/home/aegisav-operator/mb-auth.key`。本轮 MalwareBazaar 请求零、下载零、恶意原始文件零；不能宣称突破了原始恶意数据瓶颈。其余工作连续推进。

## 2. 原有 VM 实测、安全与可执行资源方案

开始可用宿主机 RAM 12,473,942,016 B，高于 10 GiB（8 GiB VM + 2 GiB 保留）门槛。采用选项 A：不改 8192 MiB / 4 vCPU 配置，启动原 VM。客户机初始可用约 7.33 GiB；root / corpus 可用约 48.32 / 10.79 GiB。

真实冷切换 Offline → NAT → Offline；通过已有在线防火墙，SSH 与原扫描服务保持 inactive。NAT 无样本下载。离线 VMware Tools 客户机操作两次通过；最终客户机仅 lo、无默认/外部路由，HGFS 禁用；VMX 共享数零、剪贴板和拖放禁用。工具管理无须维持 SSH。没有真实 PE 在宿主机/WSL 暂存或执行。

新代码仅放独立 staging 目录；原产品 current release `c699902f19640593` 不变。无害测试 service 以 operator 运行，限制 cgroup 总 RAM/无 swap/TasksMax/CPU/Runtime，`OOMPolicy=kill` 和 KillMode=control-group，NoNewPrivileges / ProtectSystem / ProtectHome 等保留；真实 corpus 路径不可访问。验证包括：

1. pidfd 监护：SIGSTOP 解析器、owner death、队列/文件 deadline、RLIMIT_AS，嵌套五项通过。
2. 真正 SIGKILL 任务 owner，清理其解析器及后代；SQLite 重启 interrupted / resubmit_required，幂等重试不伪造续扫，配额归零。
3. 正在运行取消及解析器崩溃的终态持久化、重启查询、资源归还。
4. 新 ProcessScanner 真正调用五引擎扫描良性 PE；完整 2568 维特征 SHA 与精确分数保持一致，服务子进程重启后报告一致。
5. SQLite schema 1 / integrity_check=ok / 0600；65 文件正式实验 DB 再次只读完整性通过。
6. 128 MiB 总 cgroup，两个各 90 MiB 无害子进程实际触发 oom-kill，父子均 SIGKILL、cgroup.procs 消失；之后重新执行完整六组验收成功。

另外逐资产核对冻结 manifest、root 归属/无可写权限/operator 不可写，模型 probe 通过。ClamAV 1.5.4 / 库 28148 对无害 EICAR 真实报 Eicar-Test-Signature（2.394 ms）。这证明检测调用可执行，不等于真实恶意召回验证。

选项 B 仍只是有预算的待确认备选：本轮空闲系统约 0.45 GiB，ClamAV 当前约 1.11 GiB/峰值 1.27 GiB、硬限 2.5 GiB，65 文件扫描进程树峰值 0.47 GiB。按扫描硬预算 2 GiB + Clam 2.5 GiB + 系统约 0.5 GiB + 余量约 0.5 GiB，6 GiB 可以研究严格串行负载；大型/畸形 PE 与并发 OOM 尚未验证，不能把小文件实测作为降配保证。若要改为 6 GiB，须先获确认，再在原 VM 重做 OOM/大文件/并发验收；宿主机仍保留 2 GiB。不推荐 4 GiB。本轮 A 已成功，不需降配。

## 3. 官方良性 PE 与五引擎配对扫描

新增官方来源：[Python 3.13.9](https://www.python.org/downloads/release/python-3139/) amd64/win32 嵌入包、[PuTTY 0.83](https://www.chiark.greenend.org.uk/~sgtatham/putty/releases/0.83.html) x64 包。保存 HTTPS 来源/包及成员 SHA/版本/签名/下载头。只静态读取，从未运行。三包约 24.71 MB，65 个 unique PE：36 Win64 / 29 Win32；65 个签名有效，其中 62 为预期主要发行者，三件是签名为 Microsoft 的捆绑 VC runtime，单独记录。

已知历史精确重叠一件，因此 SHA 新增 64；固定 TLSH≤40 / SSDeep≥80 筛查形成 58 个连通分量，13 件与先前文件关联，52 件未发现该筛查关联。筛查不等于独立性证明。本地 Win64 fit/validation/test SHA 成员匹配均零，不等于已清除全部作者训练集。所有文件仍是 presumed_benign，没有正式最终测试准入。

在原 VM 离线，以原冻结资产逐文件完整扫描 **65/65**：SHA、模糊、YARA-X、ClamAV、LightGBM 均 **65 no_match / 0 positive / 0 abstention**；文件失败、超时均零。剔除已知精确重叠后 64 件仍零阳性，但不能报告正式 FPR；没有可靠恶意分母，Recall/Precision/F1/低 FPR Recall 均不适用。即使假定 65 独立真良性，零阳性的单侧 95% 二项上界仍约 4.50%，实际来源/近重复相关性进一步限制推断，不能宣称 FPR≤0.1%。

本轮没有新增规则/模型或检测覆盖提升证据；没有按这些新结果调参。YARA 的非 ransomware 覆盖及模糊库多样性研究，应在标签可用的验证集内对比版本后选择。全引擎阴性不能作为新的良性真值。

## 4. 扫描成本与 Worker 可重复实验

65 文件实测 wall 168.82555 s，约 0.385 文件/s，CPU 160.516 s；扫描 service 整个进程树峰值 501,841,920 B（478.6 MiB）。ClamAV 是另一个 cgroup，峰值 1,367,556,096 B，不能漏算为扫描总内存，也不能把两者非同时峰值相加称实际联合峰值。应用结果缓存逐文件冷，OS/Clam 缓存未清；未强清系统页缓存。

| 计时 | P50 ms | P95 ms |
| --- | ---: | ---: |
| wrapper 含轮询/调度 | 2208.64 | 5106.66 |
| SHA | 0.205 | 5.842 |
| fuzzy | 27.058 | 940.333 |
| YARA-X | 12.736 | 53.570 |
| ClamAV | 305.620 | 1446.963 |
| ML 含边界 | 1012.289 | 2533.801 |

线性插值分位数。引擎时间有重叠，不相加为 pipeline；与前轮 80 件数据不同，不声称端到端提速。旧 v1 文件 elapsed_ms 是 wrapper；后续脚本现分别保留 SQLite elapsed_ms 与 wrapper_elapsed_ms，并标记 restored_report，防止恢复查询被误算为高速扫描，旧结果未重写。

`benchmark_ml_guard_reuse.py` 使用两种先前已观察小型良性 PE（Win32/Win64），每种重复两次，每批四文件，顺序 fresh / batch / batch / fresh。每次分别执行 ABBA，结果：

| 试验 | fresh 四文件 wall ms | batch 四文件 wall ms | 均值 wall 降低 |
| --- | --- | --- | ---: |
| v1 | 4903.29 / 4803.96 | 1826.27 / 1827.73 | 62.36% |
| v2 | 5055.27 / 5106.14 | 1927.91 / 1877.86 | 62.55% |

每批所有完整特征哈希、模型分数、阈值、模型/特征版本一致。复用只保留 Python 导入，模型/特征器/资产校验每文件仍重新加载。v2 10 ms 采样：fresh cgroup 峰值约 117.1/117.2 MiB，batch 132.5/132.2 MiB；kernel 全试验峰值 132.5 MiB。范围含基准父进程/监护/Worker及计费页缓存，不含 clamd；采样可能漏瞬时峰值，RSS 不同口径不得混比。

v1/v2 的短定时取消可能发生在导入期间，保留这一限制；另执行 v3 guard-only，先确认 Worker 与无害后代同进程组并存活，再触发取消/截止，二项均验证进程组为空。没有把批次 wall/4 冒称单文件 P50/P95，没有声称全五引擎吞吐提高。

暂不替换生产：此方案尚不是带逐文件 deadline 的常驻队列，且只有两个小文件；未测长队列、异常后的状态污染、大文件/并发及重启边界。下一步扩大无害文件大小/架构测试，再决定是否集成；当前净收益只是可重复的小规模 ML 进程边界实验。

## 5. 失败、修复、测试与资源收尾

真实失败保留：systemd 255 不支持 MemoryOOMGroup 属性（未运行测试），改用受支持 OOMPolicy=kill 并实际核验 memory.oom.group=1；ProtectHome 拒绝读取 home 中凭据存在性，保留限制，把检查放到 root launcher；一项只读命令选错 Python 路径，改用系统 python3 后 SQLite 完整性通过。未以失败计阴性。

审查发现两个实验恢复缺口：非原子 JSON 与恢复计时，以及无法确认任务终态仍可能继续。新增原子/fsync 检查点 helper 与五项无害测试；后者先以夹具复现两次提交/completed=True，再显式熔断为 not_attempted/completed=False。独立复查 14 相关测试通过。正式 65 件 v1 原始成功扫描未更改，不虚称它已执行后续修订版本。

全套 **226 passed / 6 skipped / 1 既有 anyio 弃用 warning，22.59 s**。没有改 UI，不重复浏览器验收。客户机六组、OOM 后恢复、模型/EICAR、新 65 文件、两次 ABBA、后代 ready 后清理均为真正运行证据。

工作完成停掉本轮 transient service 和启动的 ClamAV，确认原扫描/采集/API 服务无任务，原 VM soft 关机，运行 VM 为零。收尾主机可用 RAM 12,343,099,392 B；C/D 可用 29,456,986,112 / 109,784,596,480 B。客户机关机前 root/corpus 可用 51,783,208,960 / 11,586,310,144 B；保留源包、原 PE、正式 SQLite/结果与原始日志，无需清除 Linux 文件缓存。

快照使用 VMware 只读盘点：六个，原已确认过时名单三个均已不存在，待删零。本轮未新建、恢复或删除快照，未直接操作 vmdk/vmem。VM 运行时目录 apparent 约 20.25 GB（包含临时内存文件，不能当快照可回收容量）；关机后 D 空间充足。对未确认的中间回滚点，不仅凭名称删除，若后续确需合并须列出对象/风险/收益再确认。

## 复现与后续

```powershell
.venv/Scripts/python.exe -m pytest -q
./vm/Get-TaskGuardReadiness.ps1
./vm/Test-OfflineGuestOps.ps1
./vm/Prune-ObsoleteSnapshots.ps1   # 只读，勿直接恢复旧快照
.venv/Scripts/python.exe -m experiments.collect_official_runtime_pe
.venv/Scripts/python.exe -m experiments.audit_runtime_candidates
```

客户机 `validate_stage_e_guard.py`、`inert_tree_oom.py`、`verify_stage_e_assets.py`、`scan_official_runtime_pe.py`、`benchmark_ml_guard_reuse.py` 需要既有 staging、冻结模型、非特权 transient service 限制及本地良性清单。不要直接在宿主机执行 Linux 脚本，也不要省略隔离校验。聚合证据保存实际输入/脚本版本与日志哈希；private 原始证据位置见本地 artifacts。v3 guard-only 与 v1/v2 性能原始版本分开保留。

下一轮：客户机凭据配置后先小批次两例加密下载→离线完整性/准入→真正配对扫描，新增三例按预先审核版本纳入下一批；补独立人工审核、训练/近重复/时间边界及来源多样性。真实恶意库仍严格限定 VM 离线。继续官方良性多来源扩展及更广泛的受限 Worker 实验，不用已观察样本选择最终阈值。E1 本轮完成，E2 仍缺可信独立原始恶意数据，E3 无准确率增益，E4 有实验收益尚未生产化。
