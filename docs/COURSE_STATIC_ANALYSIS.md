# 五个教学样本静态分析交付

模块只导出静态证据，永不运行输入文件。生产模型、规则、阈值、API和便携版本不改变。

## 已有真实材料

旁边apicall的output/latex-report/sections/part2.tex已有WannaCrypt0r、hrtg、BUG32、yhzll、BossDaMajor五章及107张引用截图。
完整历史PDF仍在原项目；本轮保留其来源，不重读/解包恶意原件，也不重新在Windows运行Defender扫描。
本轮私有索引与五份Markdown/JSON工作簿位于artifacts/course-acceptance-20261023。
历史结果不是本轮五引擎检测；工作簿中各引擎如无同身份真实报告，保持not_observed。
截图摘要只能证明本轮复制一致，不能证明历史截图真实性或样本绑定。chapter_order_only关联尤其不能当作独立身份验证。

工作簿列出样本身份、来源、原始截图摘要/引用、Defender状态、PE结构/节/导入导出记录、字符串、逐引擎状态、结论和未完成项。
原始TeX章节一并保留，不把自动转录或平台页面文字伪装成新解析结果。
BUG32在正文缺完整SHA256，截图有相关身份记录，仍需分析者核对；不自动猜填。

## 复现已有五份工作簿

以下索引由本轮盘点产生，包含私有原始身份与截图引用，不进入公开Git历史。

```powershell
.venv\Scripts\python.exe -m aegisav.teaching_cli import --manifest artifacts/course-acceptance-20261023/teaching_evidence_manifest_private.json --source-root D:/2026fall/badcode/apicall/output/latex-report --output artifacts/course-acceptance-20261023/five-sample-workbook-v2
```

输出必须是新目录；导入前核对全部截图的路径、类型、大小与SHA256。任何越界/摘要不匹配均拒绝，不静默删掉失败证据。
当前导入上限5个样本、每件16MiB、证据合计128MiB；原始JSON索引上限1MiB。支持PNG/JPG/文本/JSON/XML/TeX，不接收可执行附件。

## 新输入与实际静态分析

没有教师材料时可创建明确未填写的五槽模板；本项目已找到材料，无需把模板当作实际结果。

```powershell
.venv\Scripts\python.exe -m aegisav.teaching_cli template --output artifacts/teacher-five-empty.json
.venv\Scripts\python.exe -m aegisav.teaching_cli analyze C:/Windows/System32/notepad.exe --benign-control --source "installed Windows benign control" --output artifacts/teaching-notepad-fresh
```

新解析复用现有ProcessScanner进程限制与生产扫描器，提取PE头、节/熵、最多2048条导入和2048条导出、最多128条ASCII可疑字符串线索（明确不是裁决），输出SHA/TLSH/SSDeep和五引擎真实报告。超时/解析失败不补阴性。
无效PE、超16MiB和已有输出拒绝；hrtg约39.84MiB超出既有产品限制，本轮只整理历史证据，不扩大生产限制或截断PE进行伪扫描。

真实恶意PE仅能在既有隔离Ubuntu VM中静态处理，不能复制到Windows/WSL：

```bash
python -m aegisav.teaching_cli analyze /existing/vm/path/teacher.exe --existing-isolated-ubuntu-vm --source 'teacher original; document provenance' --output /private/new-teaching-report
```

该选项记录操作者对既有隔离环境的声明，并拒绝Windows/WSL；不是VM身份的远程证明。
未启动、创建、修改VM或快照。未导入Defender原始证据时明确保持未提供；不会启动Defender、上传样本或调用任何PE。
雨课堂提交由用户在确认真实证据及未完成项后进行，本轮没有自动提交或冒认已提交。
