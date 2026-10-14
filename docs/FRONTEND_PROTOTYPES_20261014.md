# 前端研究与两套原型计划

最新决策（2026-10-15）：用户要求只保留Linen自然滚动与轻虚化。
其余视觉路由、选择器及吸附模式已删除。本文以下两套原型与滚动对比均为历史实验，
旧路线不再可预览；已保存的旧指标不代表当前版本的测试数。当前见[单一方案收尾](FRONTEND_LINEN_CLEANUP_20261015.md)。

## 用户反馈后的第二版方向（2026-10-14）

用户明确拒绝Slate/Obsidian，要求Claude官网般简单、精致且有高级动效。
旧版保留复现，不作为选定方案。新原型采用Paper（居中、文件入口优先）与Linen（偏左、阅读式布局）
两个浅色变体，范围仍只有工作台/详情，不扩展业务页。
已读取[Claude官方首页](https://claude.com/)；自动浏览器访问超时，不能宣称已完整核验其实时视觉。
以用户指定的克制、留白、自然排版为设计约束，不复制Claude商标/插画或声称像素级还原。

Token：Paper背景#f6f4ef/内容#fffefa/文字#292723/次级#69645c/动作#954a35/边界#ddd8cf；
Linen背景#eeefe9/内容#fafbf6/文字#292d27/次级#60665b/动作#49613f/边界#d3d8cc。
衬线标题（系统Songti/SimSun与Georgia）、Geist正文、Geist Mono数据，正文14–16px、
标题40–52px；主输入容器22px圆角、其他区域仅分割线，拒绝指标卡片和侧栏堆叠。
签名元素是5段静态分析进度：从文件选择自然过渡到引擎状态，再到可展开证据。
动效只用transform/opacity的错峰进入、按钮微位移和状态替换，尊重reduced-motion。

```text
轻量顶栏：AegisAV / 工作台 / 示例详情 / 方案切换
Paper：居中标题 → 文件选择容器 → 最近记录 → 简短边界说明
Linen：左侧标题与说明 | 右侧文件选择 → 宽幅最近记录
详情：大标题 → 一行结论 → 五引擎展开证据 | 简洁文件概览
```

自审：保留用户要求的暖色与留白，但避免把检测产品做成聊天框；文件操作与弃权证据仍是主任务。
新版尚待真实浏览器验收与用户选择，旧版18项通过不代表新版已验收。

新版实测已完成：4路由×4宽度=16布局检查、2组交互、1组动效/减少动效检查，
共19通过/0失败，0控制台错误、0上传和外部请求。截图人工检查了桌面工作台、详情及375px页面。
新证据`frontend_prototype_revision_check_20261014.json`；旧证据保留，不互相替代。
新预览为<http://127.0.0.1:3417/paper/>与<http://127.0.0.1:3417/linen/>，详情路径在其后加`detail/`。
新截图在`output/playwright/{paper,linen}-{workspace,detail}-{1440,768,375,812}.png`，
`paper-motion-scanning.png`记录进行中的5段演示状态。运行预览可看到错峰进入、按钮微位移和进度过渡。
新布局不使用大型动效依赖，CSS动画只使用transform/opacity，减少动效时animation:none实测通过。
审查修复复制失败不可见/成功状态残留，以及Win32示例错误不适用；新示例改为不支持的ARM64。
复验脚本默认只检查第二版，旧版仅保留复现；仍等待用户视觉确认，未开始全业务页面。

仅交付扫描工作台与检测详情的视觉原型，等待用户选择后再扩展所有业务页面。
演示数据始终标记；不接触恶意PE、不读取本地封存清单、不展示伪造正式指标。

## Skills实际核验

四个官方Skill均已安装在`.agents/skills/`，本轮重新读取完整SKILL.md并与官方固定提交逐字节核对，
全部相同，见`SKILL_VERIFICATION_20261014.json`。无需重装，不执行第三方安装脚本。
UI/UX脚本仅标准库本地CSV检索；本轮不使用persist/force或项目外写入。
第一次cybersecurity搜索返回Cyberpunk/霓虹，不符合用户要求，明确拒绝；
收窄SaaS analytics dashboard后采纳Data-Dense Dashboard的信息密度，拒绝其营销落地页结构。
另实际检索键盘表格、Skip Link、Next.js静态导出和Client Component边界。
Vercel性能规则实际应用于直接导入、静态页面/交互组件分离、避免不必要Effect与重型图表依赖。
Web Interface Guidelines使用本轮新取规则，实施后逐文件记录修正与浏览器证据。

## 设计研究

- [Linear产品界面](https://linear.app/features)：借鉴紧凑导航、低对比层级边界与任务优先结构；不复制营销页面。
- [Vercel指南](https://vercel.com/design/guidelines)：键盘/清晰焦点、URL状态、等宽数字、冗余状态文字、减少动效。
- [VirusTotal报告文档](https://docs.virustotal.com/docs/file-reports)：当前文档URL不可访问，不能宣称已核验新页面视觉；
  只使用五引擎结果对比和证据展开这一任务需求本身，后续核查可访问官方报告说明。
- [Next静态导出](https://nextjs.org/docs/app/guides/static-exports)：采用Next.js/TypeScript/Tailwind/shadcn，
  构建后静态资源可由现有Python服务部署，不新增常驻SSR进程；交互演示仅在客户端叶组件。

## 方向对比与Token

| | A Slate / 证据工作台 | B Obsidian / 分析实验室 |
|---|---|---|
| 结构 | 左侧导航，文件队列+上下文面板；详情以五引擎表格为主 | 顶部导航，宽幅文件账本；详情以证据分栏+成本图为主 |
| 视觉 | 冷灰、蓝色动作、细边界、较高密度 | 暖炭黑、琥珀动作、开放留白、分析文档感 |
| 背景/面板/边界 | #0d1017 / #151923 / #2b3343 | #111210 / #1b1c18 / #34372e |
| 正文/次级/动作 | #eef2f9 / #a1adc1 / #a7bfff | #f1f0e9 / #b1b5a7 / #e6c58c |
| 字体 | Geist Sans；SHA/数字用Geist Mono | 系统中文与Geist Sans，较大标题；数据用Geist Mono |
| 区别 | 适合持续批量处置和快速复核 | 适合深入查看单文件证据与分析过程 |

所有颜色来自语义CSS Token；4/8/12/16/24/32px间距、6/10px圆角，动效仅opacity/transform，
明确prefers-reduced-motion。375/768/1440px检查；移动导航改横排，工作台单栏。

```text
PrototypeChooser
  SlateWorkspace / SlateDetail
  ObsidianWorkspace / ObsidianDetail
    Button / Badge / Input / Field / Alert / Skeleton / Empty
    DemoFileQueue / EngineLedger / EvidenceDisclosure / CostFigure
    PreviewStateControls（明确标记演示）
```

风险修正：避免仅换色→改变导航/信息布局；避免假正式指标→全局演示标签；
避免卡片堆砌→文件账本+少量上下文；避免低对比→实测文本Token对比；
避免视觉静态截图→搜索、演示扫描、详情、证据展开、JSON导出均可交互。

## 实测验收与预览

两方向各有工作台和详情共4路由。真实 Chrome / Playwright 在1440×1000、768×1024、
375×812、812×375检查：16组合通过，另2组交互通过，0控制台错误、0上传或外部请求。
交互包含搜索/空状态/恢复、加载、失败/重试、只选择文件名、演示进度、非PE详情、
证据展开、演示JSON导出和键盘Skip Link。对4对主要语义文本Token实测对比度均≥4.5，
这不是完整WCAG合规认证。桌面与手机截图已人工查看。

初轮375px工作台有2个溢出失败，原始结果另存；根因是表头绝对定位的sr-only文本
越出静态定位的横向滚动容器。将容器设为position:relative后重新完整检查通过；
未用隐藏body溢出遮掩问题。表格仍在自身容器内横向滚动。
另修复静态导出Next预取路径404：原型使用普通锚点整页导航，尚未引入生产API代理。
字体自托管，TS skipLibCheck=false；生产构建、类型检查及npm audit（0漏洞）通过。
shadcn CLI仅作为开发工具使用，移除不必要的运行时CLI依赖链，保留官方生成组件源码。

本地预览：仓库根执行

```powershell
.\.venv\Scripts\python.exe -m http.server 3417 --bind 127.0.0.1 --directory frontend/out
```

- 对比入口：<http://127.0.0.1:3417/>
- A：<http://127.0.0.1:3417/slate/>，<http://127.0.0.1:3417/slate/detail/>
- B：<http://127.0.0.1:3417/obsidian/>，<http://127.0.0.1:3417/obsidian/detail/>
- 证据：`docs/benchmarks/frontend_prototype_check_20261014.json`；失败原记录`*_initial_*.json`。
- 16张实际PNG：`output/playwright/{slate,obsidian}-{workspace,detail}-{1440,768,375,812}.png`。

复验：先在frontend目录`npm ci`、`npm run typecheck`、`npm run build`，启动以上静态服务，
再`node scripts/check-prototypes.cjs`。脚本支持AEGISAV_PLAYWRIGHT_MODULE指定本地Playwright模块，
使用已安装Chrome，不自动下载浏览器。未安装模块时应明确安装Playwright开发依赖。

## Skills代码审查落点

- Anthropic：两种结构不同的方向，克制单色动作、字体/层级统一；不批量生成未批准页面。
- UI/UX：采用信息密度与键盘检索建议，拒绝霓虹/营销结构；表格局部滚动、长名称截断/详情换行。
- Vercel React：服务端壳/页面与最小客户端交互边界，按组件直接导入，搜索结果派生而非Effect同步，
  本地字体，不为演示条图加载大型图表或动效库。
- Web Guidelines：输入label、明确按钮、语义标题/表格/figure、可见焦点、Skip Link、aria-live/alert、
  reduced-motion、状态文字和失败重试；修正静态预取错误与真实窄屏溢出。

视觉方向尚未获用户确认；原型不是已接入API的完整产品。后端与隔离检测工作继续推进。
