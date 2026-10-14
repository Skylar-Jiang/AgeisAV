# Skills 来源与验证（2026-09-28）

## 2026-10-14 实际应用补充

Linen滚动改进继续使用四官方Skill：UI/UX实际检索滚动/减少动效/键盘，
Web指南重新获取并用于粘性导航偏移、无JS回退、可见焦点、URL状态和观察器清理审查。
仅CSS原生proximity吸附与IntersectionObserver一次呈现，不引入滚动劫持/视差或重型动画库。
代码审查与真实原生滚轮、键盘、媒体偏好等证据见`LINEN_SCROLL_REVIEW_20261014.md`。

四个前端官方Skill本轮均重新完整读取，并与固定官方GitHub提交逐字节核对一致，
不是仅登记名称。校验SHA与加载记录见`SKILL_VERIFICATION_20261014.json`。
已实际应用于两套Next.js深色原型、UI/UX本地检索及代码/浏览器审查；具体规则落点、
被拒绝的不合适推荐、18项浏览器通过记录见`FRONTEND_PROTOTYPES_20261014.md`。
原先Vite设想未实施；当前使用Next静态导出，现有后端未因原型改变。

安装范围：本项目的 `.agents/skills/`；未执行第三方仓库的安装脚本、`npm install` 或 `pip install`。使用 Codex 自带的 `skill-installer` 下载器按固定 commit 获取到临时目录，审查后复制完整 Skill 目录。该下载器只下载、校验路径并复制文件；其脚本本身已事先阅读。Git commit 是固定版本依据，Skill 自报的 `1.0.0` 仅作补充。

| Skill | 来源及固定 commit | 许可证核查 | 用途 / 阶段 | 依赖与审查结论 |
| --- | --- | --- | --- | --- |
| [frontend-design](https://github.com/anthropics/skills/tree/33375500bcea98d610eb30ce10ac4e59b89c390d/skills/frontend-design) | `anthropics/skills` `33375500bcea98d610eb30ce10ac4e59b89c390d` | 目录内 `LICENSE.txt` 为 Apache-2.0 | 阶段 5，先写视觉方案再实现 | 纯文档；不执行脚本。 |
| [ui-ux-pro-max](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill/tree/09170eec67eefd46a7ae85de61b40c194020f997/.claude/skills/ui-ux-pro-max) | `nextlevelbuilder/ui-ux-pro-max-skill` `09170eec67eefd46a7ae85de61b40c194020f997` | 仓库根 `LICENSE` 为 MIT，已随目录保存 | 阶段 5，信息架构、设计系统、UX 与响应式检索 | 检索脚本使用 Python 标准库；可选 `--persist` 会写入项目，需指定输出目录；数据维护脚本当前不用。原文示例使用 `CLAUDE_PLUGIN_ROOT`，本项目运行时改用 `.agents/skills/ui-ux-pro-max/scripts/search.py` 的实际路径。 |
| [react-best-practices](https://github.com/vercel-labs/agent-skills/tree/063bee94c3f4df8453406c830b0a7df0f2860278/skills/react-best-practices) | `vercel-labs/agent-skills` `063bee94c3f4df8453406c830b0a7df0f2860278` | `SKILL.md` 标 MIT，仓库 README 声明 MIT；仓库无独立 LICENSE 文件 | 阶段 5，React 数据请求、渲染和包体审查 | 纯文档和规则；按当前 Vite/React 架构只应用适用规则。Skill 自报版本 `1.0.0`。 |
| [web-design-guidelines](https://github.com/vercel-labs/agent-skills/tree/063bee94c3f4df8453406c830b0a7df0f2860278/skills/web-design-guidelines) | 同上 | 仓库 README 声明 MIT；无独立 LICENSE 文件 | 阶段 5，页面可用性和无障碍审查 | `SKILL.md` 要求审查时获取[外部指南](https://github.com/vercel-labs/web-interface-guidelines/blob/e3d624baaf29dc1fc645aff3e38f03e564d2d6b1/command.md)。指南会更新；正式审查时记录其实际 commit。Skill 自报版本 `1.0.0`。 |
| [fastapi](https://github.com/fastapi/fastapi/tree/192b12197eb04c2b4a691cce7d87261b21716714/fastapi/.agents/skills/fastapi) | `fastapi/fastapi` `192b12197eb04c2b4a691cce7d87261b21716714` | 仓库根 `LICENSE` 为 MIT，已随目录保存 | 阶段 1 起，接口、依赖注入、响应模型和并发边界 | 官方维护，纯文档及参考资料；其建议是版本相关的，实施前核对项目实际 FastAPI 版本。 |

## 其他领域的搜索结论

- Python/FastAPI：采用上表官方 FastAPI Skill。
- 机器学习实验：检索了 [Hugging Face Skills](https://github.com/huggingface/skills)；现有训练和评测 Skill 主要面向 Hugging Face Hub、LLM 或云端 Jobs，与本项目 EMBER2024/LightGBM 本地实验不直接匹配，暂不安装。阶段 2 以 EMBER2024 官方基线和实验协议为准。
- 自动化测试：本机已有 `test-driven-development` 与 `verification-before-completion` Skills；阶段 1 起使用，不重复复制到项目。测试框架本身以 pytest/前端测试套件的官方文档为准。
- 安全审查：本机已有 OpenAI `security-best-practices` Skill；阶段 7 使用，并单独审查样本处理与沙箱隔离。
- 技术文档：本机已有 `academic-research-suite` 等研究写作资源；优先维护本项目 `docs/` 的来源、决策和复现命令，不增加泛用文档 Skill。
- 性能优化：已安装 Vercel React Skill；后端性能工作以真实 P50/P95、吞吐量和资源监测为触发条件，暂未找到适配本项目且比官方工具文档更合适的专用 Skill。

## 安装验证

五个目录均有合法的 `SKILL.md`。已阅读五份使用说明，审查 UI/UX 检索脚本的导入与文件写入路径。项目级 UI/UX 检索在 Python 3.12 上实际运行，`malware analyst evidence table --domain ux` 返回 1 条可核对的表格响应式建议；无外部依赖安装、无项目文件写入。Codex [官方文档](https://learn.chatgpt.com/docs/build-skills)说明会自动发现 `.agents/skills` 变更；若界面未出现新 Skill，重启 Codex 后再进行需要它的前端阶段。

阶段 1 实际使用本机 `test-driven-development` 指导 PE/哈希、规则、ClamAV、API 和缓存功能按失败用例再实现；使用 `verification-before-completion` 对完整 pytest、真实 HTTP 调用和基准结果作实测核对；FastAPI Skill 用于 API 路由与请求边界设计。`requesting-code-review` 用于阶段 1 原型独立审查，结论记入进度记录。
