# 公开实验摘要：2026-10-14

## 2026-10-19：Stage E 工程收尾 → Stage F 实际交付 → Stage G 启动

Stage E **Engineering complete / Research open**，不开展 R8/R9 作为前置；冻结五引擎、模型/阈值、静态规则/参考库/融合和 VM 不变。独立验证/最终集准入仍 0，正式 Recall/FPR 不可报告。历史证据完整保留，研究 backlog 见 STAGE_E_CLOSEOUT.md。

Stage F 已实现受限子进程 Sysmon XML/规范 JSON、两条固定 SigmaHQ/DRL 规则（明确子集/弃权）、主机/GUID/闭合 PID 生命周期关联、独立 SQLite 报告、认证 API、Linen 导入/证据/导出/静态精确哈希声明关联。无日志 not_observed，行为不加入静态裁决。纯合成 6 事件/2 进程/1 命中；公开 MIT 日志 59 Sysmon 事件全部解析、两规则未命中，含不支持事件故总体 incomplete，非阴性/非准确率。真实浏览器 11 检查含 5 尺寸、无横溢、实体拒绝、XSS 文本、实际服务强制重启/持久报告恢复；ClamAV 在宿主 unavailable 如实显示，不重复 VM 评测。

1,000 事件 5 次受限解析 P50/P95=0.813/0.875秒，采样进程树约38.2MiB（非严格峰值），输出一致、0失败；不宣称生产 Worker 加速。Windows 首版采样仅看 venv launcher 的错误低值保留为无效证据，修正后按后代进程树测量。全套本地321通过/6跳过，公开筛选分发320通过/7跳过（含1项额外私有证据排除），均仅1既有anyio警告。Stage G 首项已交付仓库外、不覆盖的受限回放 CLI 及本地部署指南；下一步交付包/操作手册/最终演示，科学研究开放。详见 research/ROUND_REPORT_20261019_STAGE_F_PUBLIC.md。


## Stage E R7 — 2026-10-19, actual guest intake and full pairing

See [R7 report](research/ROUND_REPORT_20261019_STAGE_E_R7_PUBLIC.md). Original6GiBVM actually acquired5new strictPE(three technical-family tags/two sources;3automated operational high-confidence,2family-disputed unknown).24API requests,5/5encrypted downloads;Offline-only raw analysis. Fullsame-version five-engine+frozen-routing study298/298(286official controls+12technical/proxy cases),0missing engines/abstention. Control signals general5/routed1; technical/proxy signals10/12both; new4/5both. **Not formal Recall/FPR**. Emotet and a disputed newWin64case still miss; Win327-Zip alert remains.

New37official rawPE/seven projects;12package digests/37strictPEverified,17Valid/20NotSigned. All37unscored:23source candidates/six groups,14development-component source files. No protected candidate scored; strict validation/final0. General/routed feature hashes equal298/298; R6-to-guest260hashes identical. YARA digest discrepancy reproduced as OS file ordering,248assets unchanged. Release267assets intact. Local295passed/6skipped;post-review4/4harmless guest guard checks;VM off/Offline,6snapshots retained;no production model/rule/threshold/Worker/UI change. Paired researchP50/P95=3.157/7.877s,treepeak567MiB/separateclamd1.29GiB;no controlled performance gain claim.

Earlier entries below are historical; current product retains authenticated API, SQLite recovery and accepted Linen integration.


旧冻结开发归档和新MalwareBazaar批次均不能重新包装为独立最终测试。
已完成新批次同80原始PE配对、缓存关闭、串行新Worker、固定发布和原阈值：

| 引擎/策略 | 阳性信号 | 阴性 | 未采集弃权 |
|---|---:|---:|---:|
| SHA-256 |0|80|11|
| TLSH/SSDeep |0|80|11|
| YARA-X |0|80|11|
| ClamAV |20|60|11|
| LightGBM |76|4|11|
| OR |76|4|11|
| 双来源 corroborated |20|60|11|

56文件仅ML提供信号；本批OR较ML新增0。所有标签unknown，
Recall/Precision/F1/FPR/AUC/固定低FPR Recall及其准确率置信区间均不可计算。
不得把76/80当Recall。11失败不计阴性，原始失败原因与尝试历史保留在私有证据。

80文件扫描P50/P95为3.126/7.375秒（含Worker启动，不含解包）；总323.140秒，
约0.248文件/秒。扫描cgroup峰值550199296B（含ML子进程），独立clamd峰值1372381184B；
扫描CPU317.438秒。cgroup观察开始晚于启动22秒，扫描服务最终峰值另核对一致。
两服务峰值相加不是同时瞬时占用。文件最大8.29MB，不能与更大旧批次直接宣称加速。

原生模糊哈希研究：24无害边界输入、6固定良性PE×ABBA=24测量、24旧开发PE，
完整TLSH/SSDeep逐字节一致。良性文件哈希计算部分中位加速15.38–41.38倍，
排除IO/启动，不是完整服务加速。产品尚未启用原生库，分发许可义务仍需确认。

公开JSON仅包含聚合摘要和发布身份；逐文件清单、标签、私有原始结果未上传。
完整研究结果保留本地，缺少可独立核实真值仍是正式验收的主要限制。

## 2026-10-15：Linen单一方案收尾

仅保留自然滚动与记录区轻虚化，其他方案及吸附对比代码删除。
合成UI的真实浏览器11+12+6=29组检查通过，构建/类型检查通过，依赖审计0漏洞。
源码减少29473 B，静态产物减少286304 B；缓存增加17317352 B，手动清理被自动审批拒绝，
没有宣称整体磁盘净释放或检测性能提高。无新增样本/模型/规则/阈值变化。
复现与实际限制见[单一方案收尾](FRONTEND_LINEN_CLEANUP_20261015.md)。

2026-10-15 R2：工作台比例调整后31组浏览器检查通过；1920×1080下标题72.96px，
分析框800.39×540px。包含9视口与键盘/加载/虚化回退，构建/类型检查通过。
只使用合成UI，未测扫描成本或准确率；旧版29组与最初47组均为各自历史版本。

## 2026-10-15：产品A/B真实联调

核对公开3627d9b与本地源码一致，私有模型/数据保留。默认Linen工作台/详情已接真实同源FastAPI，
新增本地认证、实际上传/查询/文件级进度/协作取消/错误与报告导出；演示独立于/linen/demo/。
本地176passed/6skipped，真实浏览器21组+显式演示31组通过，构建/类型检查通过。
脚本8文件槽=3报告行（含去重）/3无害解析错误/2取消；独立良性PE仅1个。另在3417部署服务回放同一良性文件1次。
SHA/fuzzy/YARA-X/ML均no_match，Windows ClamAV unavailable明确弃权；不是Recall/FPR证据。
活动任务404与401恢复问题经审查修复且通过故障注入复验，未改模型/规则/特征/阈值。
任务仍内存型、无总截止与重启恢复；C阶段优先轻量持久化、幂等与进程截止，D再扩展完整业务页。
详细契约、运行命令与资源边界见[产品A/B报告](research/ROUND_REPORT_20261015_PRODUCT_AB.md)。

## 2026-10-16：Stage C 任务可靠性

SQLite Schema 1、原子报告/状态、持久化幂等、重启 interrupted 语义、任务/文件截止和独立扫描进程已实现。
原始上传字节不持久化，不宣称自动续扫。Windows Job / Linux pidfd 监护清理，仅使用良性及无害夹具。
后端190passed/6skipped，实际服务重启/故障10组、真实API浏览器21组、Linux无害隔离5项通过。
独立良性PE仍1个，四引擎no_match、ClamAV不可用；没有新增准确率证据。
详见 docs/TASK_RELIABILITY.md 与 docs/research/ROUND_REPORT_20261016_TASK_C.md。
C完成后继续D实际任务/历史、资产状态与运行统计，不编辑冻结阈值。

## 2026-10-16：Stage D 实际业务界面

C公开9ab71be已正常Push；SQLite/恢复/截止/进程隔离通过真实验收。
D新增实际批量任务、持久化历史、规则/模型只读状态及运行统计页面，保留Linen。
双模型路由及冻结阈值分别展示，246条原有YARA规则分页；没有新增检测资产或调整策略。
本地192passed/6skipped，四页面浏览器23组与工作台/详情21组通过，构建/类型检查通过。
D验收备份库23任务/25文件槽：2报告/14错误/6取消/1中断/2超时，独立良性PE仍1个。
没有独立标签时不显示准确率；失败、弃权和不同哈希的统计独立性明确说明。
详细范围、资源、失败及下一步见 research/ROUND_REPORT_20261016_PRODUCT_D.md。

D公开 fedcc943402d622678c188ac695e7dccbdc3d07e 已安全Push并核对；公开191passed/7skipped，
636发布文件/2密钥排除/冻结资产一致性通过，未上传私有历史或改main。
现有VM仍关闭；只读资源前置检查 deferred_memory，8GiB客户机加2GiB宿主机保留门槛未满足。
客户机新进程层尚未验证，不宣称E完成。保留3417认证预览与真实良性持久报告，无闲置扫描Worker。

## 2026-10-16：Stage E 首轮冻结结果与独立性审计

资源门槛仍未满足：8GiB VM+2GiB保留要求10GiB，可用6.41GiB；VM保持关闭、配置未变。
保存报告重算80个第二批PE：ML76/Clam20/其余0/OR76，11下载失败保留弃权；标签均unknown，不报告Recall。
80文件形成61筛查簇，6簇11文件关联历史数据；排除关联后69扫描ML65/Clam12/OR65。
149官方良性候选形成81筛查簇，完整训练/时间与标签仍不足；新增2个主要案例证据候选但原文件0、标签升级0。
新增聚合诊断CLI与20项无害测试，全套212passed/6skipped；ML未归因开销P50约1.222s，仅定位，未改Worker。
未改后端、模型、规则、阈值或Linen；E1客户机验收及新独立配对评测尚未完成。
报告：research/ROUND_REPORT_20261016_STAGE_E.md。

E首轮公开 f1c602be675bcb5b8107d4829ce4ffbd1037638d 已正常快进Push，远端核对一致。
公开副本211passed/7skipped，642文件逐字节核验、2类密钥及私有候选SHA排除通过；
后端运行层/ML/规则/依赖与d434f49字节一致，仅新增诊断测试。客户机验证与新独立原PE实验未执行。


## 2026-10-17：Stage E 第二轮实测

原 8GiB VM 满足10GiB主机门槛，完成真实 pidfd/取消/截止/owner SIGKILL/SQLite 六组无害验收及128MiB cgroup OOM后恢复；模型只读完整性/EICAR通过，最终正常关机。
固定 analyst-case-admission-v1；五例 probable（原两例+新增三例）、一例双用途 unknown隔离；新恶意原文件/high-confidence/正式最终样本均0。凭据传入被自动审批拒绝（原因未提供），未绕过，本轮MalwareBazaar请求0；待手动客户机配置。
三个官方Python/PuTTY包65PE（64SHA新增/58筛查簇/13件先前关联），签名65有效但仍为presumed_benign。五引擎65/65完成、全部no_match、无失败/弃权；不能宣称正式FPR或Recall。
扫描wall168.83s/进程树峰值478.6MiB，独立clamd峰值1.27GiB；两次无害ML ABBA约62%批次wall降低、完整特征/分数一致、内存约+15MiB，生产未启用。
226passed/6skipped/1既有warning；实验检查点增加终态不明熔断/原子写/恢复计时，生产层/规则/模型/UI不变。六快照保留、已确认待删0。
详见 research/ROUND_REPORT_20261017_STAGE_E_R2.md 与 benchmarks/stage_e2_summary_20261017.json。下一步取原PE并做人审/独立性清除，扩大无害Worker文件集。


## 2026-10-17：Stage E R3 真实原始 PE 与冻结模型复查

用户完成人工凭据配置，客户机 LoadCredential 真实认证通过；未读取 Windows API-Key DPAPI。5候选/6请求/4不可获取/1原始PE完整性通过；操作性high-confidence1、人审完成0、正式独立最终样本0。
同原PE五引擎均no_match、零引擎失败/弃权，融合undetermined；没有回填哈希或改冻结阈值。已有Win64 profile在同66PE上完整特征一致，仍全部no_match，新增检出0，生产未启用。
单文件任务3.937s、编排3.968s、总wrapper4.061s；扫描树峰值365.18MiB，独立Clam1.255GiB。ML-only66文件84.154s/226.28MiB，不作为性能优化结论。正式Recall/FPR仍无充分条件。
原VM离线分析启动满足10GiB门槛，最终正常关机、六快照保留；凭据保存在客户机root0600，仅客户端LoadCredential读取。详见research/ROUND_REPORT_20261017_STAGE_E_R3_PUBLIC.md；私有标签与原始结果不公开。


## 2026-10-17：Stage E R4（部分交付，原VM等待资源）

新增15精确技术证据候选，4机构/6报告家族；尚未API查询或取得新恶意原始PE，probable15/high-confidence新增0/正式最终0。新增四来源官方良性13PE（11Win64/2Win32），8签名Valid/2NotSigned/3UnknownError；没有执行PE。精确重复0；当前内部12簇、计入已记录历史中介11组件，排除既有关联后10文件/9组件。28候选本地Win64 fit/validation/test SHA交集均0；完整训练/近重复/人审仍未清除。
旧漏检案例元数据诊断：参考库4条/恶意模糊2条，TLSH最近454>40、SSDeep最高0<80，支持覆盖不足；没有回填SHA或调低阈值。YARA246条中212来自ransomware；跨OS规则指纹差异被证实来自Path排序而非规则丢失。7条独立研究规则在13新良性上0阳性/0超时，仅YARA63ms，未验证恶意增益或正式FPR。
259passed/6skipped/1既有warning，18重点与独立审查通过。新诊断工具绑定原模型/特征/阈值并保留incompatible状态，但尚未客户机执行；本轮五引擎配对新增0，ML漏检根因和Clam具体覆盖仍未证实。主机可用约6.9–7.3GiB，未达到原10GiB门槛，原VM未启动、账号/凭据/快照/配置/生产资产未变。详见research/ROUND_REPORT_20261017_STAGE_E_R4_PUBLIC.md；私有明细另行保留。


## 2026-10-17：Stage E R4 实际离线评测（发布核验于2026-10-18）

原VM经用户批准改为6GiB，保留宿主机2GiB余量、8GiB启动门槛及原扫描/ClamAV配额。新增3个原始恶意开发PE（2家族、2近重复筛查组件），13个四项目官方presumed_benign PE；最终配对16文件五引擎均为相同已知版本。ML阳性3/3与2/13；ClamAV2/3与0/13；其他引擎0。0扫描失败/弃权；10不可获取和2超尺寸候选单列，不计阴性。

冻结Win64 profile影子研究保留3个恶意阳性，官方候选阳性2→1；16特征摘要一致。不是正式Recall/FPR或泛化增益；人审0、最终集准入0，不启用生产策略。旧Emotet完整2568维与模型版本/分数一致，14规则模式均缺失；新增7研究规则对该案例无增益。首轮Clam版本unknown和回环配置中断均保留，另建结果/SQLite补验通过。

版本确认3文件P50/P95=2.531/3.678s，树峰值371.62MiB；13官方控制4.945/9.709s，349.19MiB，Clam约1.263GiB。没有Worker替换或公平性能提升声明。267资产/SQLite校验通过，无OOM；VM正常关闭、六快照保留，只清理约31MB冗余传输归档。详见[公开研究报告](research/ROUND_REPORT_20261017_STAGE_E_R4_VM_PUBLIC.md)及stage_e4_vm_summary_20261017.json。


## 2026-10-18：Stage E R5 实际数据与误报研究

两个已观察7-Zip安装器重新取官方发布字节、发布摘要与原件均一致，均NotSigned；按发布者来源标签属于操作性误报，独立人工最终准入待办。2568完整向量/模型/分数复现，未发现特征版本错误；大SFX叠加区和header正SHAP关联不是因果结论。旧Emotet未重复重算、仍漏检。

13技术候选查询16请求（>=5s间隔）：3原始PE取得、10hash_not_found；实际2机构/2家族（2StealC V2、1新增FormBook），自动技术证据high-confidence3、人审0、正式独立验证/最终0。两个原2MiB排除候选经专用16MiB有界采集成功，15/15无害客户机故障夹具通过；生产扫描/报告限制不变。

新增19官方PE/6项目（PuTTY、SQLite、Python、Rufus、Inno Setup、WinSCP），15签名有效/4NotSigned；13扫描、6隔离候选未评分。原18有6历史近邻关联；WinSCP训练精确重叠审计晚于扫描，独立性不作预先确认。局部Win64训练/验证/测试SHA零重叠，完整通用训练及近重复独立性未知。

同16原始文件/相同已知五引擎版本：开发恶意ML3/Clam2/其他0，presumed_benign控制ML2/其他0；2SQLite潜在误报。既有冻结Win64路由研究保持恶意3→3、控制阳性2→0，16特征摘要/5回退一致；未训练/新试阈值/激活生产。零扫描失败与引擎弃权；未获得与未评分绝不计阴性。不报告正式Recall/FPR/低FPR达标。

恶意任务P50/P95=3.287/4.463s，扫描树378.71MiB，独立clamd1.261GiB；控制3.286/11.442s、树峰值未采集，不声称公平加速。保留6GiB串行/8GiB主机启动门槛/2GiB余量，3SQLite quick_check通过、最终分析boot未见OOM。仅清除116262453字节可再生成无害夹具及可信传输重复件，6快照/正式样本模型结果保留，VM正常关机。

本地282passed/6skipped/1既有warning。详见research/ROUND_REPORT_20261018_STAGE_E_R5_PUBLIC.md与benchmarks/stage_e5_summary_20261018.json。下一步独立标签人审、完整训练/时间审计、更多可取得跨家族技术案例；保留未观察隔离队列。正式泛化与极低误报验收仍未完成，生产模型/阈值/规则/融合/Worker/Linen均不变。


## 2026-10-18：Stage E R6 规模化候选与具体准入冻结

新增368个官方PE/8项目/17发行包，发布摘要17/17、成员SHA/大小/PE复核368/368；346签名有效/22未签。类别含2安装器、5桌面、95原生DLL、47CLI、219托管DLL；77x86/69x64/222AnyCPU。全部未评分。SDK+WinMerge346文件，占约94%，不当作独立样本数。

1,966旧指纹+368新文件全局图包含691旧旧桥接边；新旧精确/近重复0，新316筛查簇。局部Win64训练/验证/测试精确重叠0，通用完整训练/近训练未知。冻结358拟验证文件/5软件发行父组、two sealed candidates封存最终候选、8同已观察发行组留开发；R5六个隔离候选保护不变。十例人工审核包v4已准备并集中询问，含具名358成员清单与审计摘要；标签/整组用途授权分开，人工字段仍空，准入0。

新增4机构主IOC元数据目录8,651唯一SHA、626文本/许可blob校验通过；17精确payload角色候选/7案例文本/2机构仍待原件与人审。不是新增原始恶意PE，也不把related URL当精确报告。当前MalwareBazaar请求0/新恶意原件0，availability-first受限采集脚本准备但未部署/客户机验收，不声称获取率改善。额外PeaZip元数据HTTP403限流记录，未反复请求。

主机可用5.46GiB未达8GiB门槛；其他编译项目WSL约300MiB不能补缺口，未终止，原6GiB VM保持关闭/Offline、六快照保留。原始官方包/样本/私有证据均保留，生产全栈/模型/规则/阈值/融合不变。新验证/开发评分均0，没有7-Zip/SQLite/Emotet独立增益或正式低FPR指标。请求的只读代码审查因工具额度失败，不声称通过；采集层保持未启用。

本地285passed/6skipped/1既有warning；3新selector测试只是边界验证，主要进展为真实数据和准入路径。详见research/ROUND_REPORT_20261018_STAGE_E_R6_PUBLIC.md、DATASET_ADMISSION_R6.md及stage_e6_summary_20261018.json。下一步实际人审/限定组授权、主机资源满足后的现有VM可获得性发现与多家族原件采集，再执行预定义验证；正式Stage E验收仍开放。


### R6 用户指示后的限定探索实验（取代普通实验等待签字）

用户明确区分自动来源审核、operational/proxy探索与严格独立评测；没有提供M01–M04签字，也未批准358严格验证。普通自动审核/探索不再等待逐项批准。评分前按源组冻结260探索（SDK250/CMake8/fd2）与98未评分保留；two sealed candidates、R5quarantine6保持封存。260评分后永久observed_exploratory_development，历史冻结保留并由观察日志明确覆盖，不能升级未观察验证。

260/260已完成：通用ML1阳性、既有Win64路由0；新案例是官方SDK singlefilehost.exe通用0.703215/路由0.413887。260完整特征摘要一致，241通用回退分数/阈值一致；专用Win64实际用于19文件，托管.NET和Win32没有强行套用。SHA/模糊/YARA各0/260；ClamAV260未执行，绝不当阴性。无扫描/可用引擎弃权。宿主YARA c86b0a888539baf5不同于旧客户机55ccec8463af1166，单列，不能称完整同版本五引擎实验。

串行受限Windows研究任务wall404.266s；两ML配置合计每文件P50/P95=0.250/1.393s，三非ML阶段0.016/0.205s，不是服务P95或性能提升声明。ML树1.5GiB、非ML树512MiB上限，结束后worker清理正常；完整峰值未测。未修改生产Worker/模型/规则/阈值/融合。3软件父组且SDK占250/260，仅报告operational控制阳性与策略差异，非正式FPR/Recall，也没有7Zip/SQLite/Emotet独立增益。

98保留文件与260探索之间无已知近重复组件桥接，封存组也无桥接；上游完整训练/近训练、时间新颖性、恶意独立准入仍不足。后续直接推进允许的自动研究，严格人审仅用于真正独立/最终准入，不再让普通实验被审批阻塞。
