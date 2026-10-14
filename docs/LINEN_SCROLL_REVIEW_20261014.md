# Linen：完整状态与滚动体验对比

2026-10-15当前版本：只保留自然滚动，吸附模式与比较控件已删除；
下面的两模式比较及47项测试属于历史版本。当前复验见[单一方案收尾](FRONTEND_LINEN_CLEANUP_20261015.md)。

最新选择：用户已确定自然滚动版。本轮加入限定在记录区域的轻微虚化过渡：
滚动进入时3px→清晰（620ms），记录就绪时3px→清晰（500ms）；不对整页或导航做虚化。
慢加载占位2px模糊且停止装饰性脉冲，搜索与加载文字在虚化区域外保持清晰。
真实记录在加载时移除，避免把旧检测结果误作新结果；`aria-busy`与可见加载状态保持一致。
键盘聚焦立即清除虚化，减少动效设置禁用所有新增filter/动画。

“原型状态预览 → 慢加载（演示）”明确模拟1.8秒异步等待；切换状态/卸载取消计时，
不用于真实API请求，不引入人为最低加载时长。当前仍为合成演示，不宣称已联调真实服务。
此处按用户显式要求采用短时CSS filter，覆盖Web指南通常仅用transform/opacity的建议；
不使用全页backdrop-filter、永久will-change或新增动效依赖，也不声称未经测量的FPS或GPU性能。
本轮专项脚本`frontend/scripts/check-linen-blur.cjs`直接检查实际浏览器滤镜、取消、焦点和媒体回退。
结果为`docs/benchmarks/linen_blur_check_20261014.json`，截图位于`output/playwright/linen-blur/`。

虚化专项实际6通过/0失败，另滚动22项与原型19项回归全部通过，共47检查；
生产构建/类型检查通过，依赖审计0漏洞。实际捕获加载中、虚化中间帧、就绪清晰截图。
键盘聚焦立即清晰，取消后旧计时不会覆盖错误状态，减少动效禁用占位及结果虚化。
首次发现CSS选择器使用未设置的data-loading，改为实际aria-busy后修复；
精确blur(3px)断言曾采到2.83984px中间帧，已增加目标状态等待，没有放宽终态要求。
首次功能失败记录另存linen_blur_initial_20261014.json；动画中间值采用真实浏览器动画暂停检查，
不是FPS或完整性能基准。无新增检测数据或模型/规则改动。

用户已选择Linen亚麻视觉，不再等待配色选择。本轮只研究完整工作台的滚动组织，
继续使用明确标记的合成演示数据，不读取/上传文件，不改变后端、模型、规则和冻结实验。

## 设计与实现

同一页面两种模式，保留相同功能、内容和Token，避免比较被其他视觉差异干扰。

- `http://127.0.0.1:3417/linen/?scroll=reveal`：自然滚动，记录区进入视野后呈现一次。
- `http://127.0.0.1:3417/linen/?scroll=snap`：原生CSS `y proximity`轻吸附。
- 顶栏直接切换，URL保存模式，原生History API支持后退；不重新加载或丢弃已选文件名。
- 桌面≥1024×720：80px固定位置顶栏；首屏是完整文件选择/扫描状态，第二屏是完整记录/搜索/状态预览。
- 使用min-height而非锁死高度，长文件名和较多输入可正常增长与滚动，不做嵌套滚动容器。
- 手机、平板、低矮窗口和减少动效模式使用自然滚动；减少动效同时直接显示最终内容。
- 没有滚轮/触摸事件拦截、滚动位置监听、视差、强制逐屏跳转或新增动效依赖。
- SSR默认内容可见；无JS或不支持IntersectionObserver时记录保持可读，CSS锚点偏移不依赖JS。
- 键盘聚焦记录区时立即显示，不让渐入遮住焦点。

## 研究与Skills实际使用

重新读取并应用项目官方frontend-design、Vercel react-best-practices与web-design-guidelines；
UI/UX本地脚本检索`scroll animation reduced motion keyboard navigation`，采纳减少动效与普通锚点导航，
拒绝scroll-jacking建议或强制视差。主Skill指导保持LinenToken、任务主操作优先及最少客户端边界。
独立只读审查关注生命周期清理、键盘、SSR、内容增长与媒体回退；未发现有证据的P1/P2，
其建议的1024×720边界及无JS锚点检查已补入实际浏览器测试。

参考：[原生滚动吸附](https://developer.mozilla.org/en-US/docs/Web/CSS/Reference/Properties/scroll-snap-type)、
[Next原生History API](https://nextjs.org/docs/app/getting-started/linking-and-navigating#native-history-api)、
[本轮获取的Web Interface Guidelines](https://raw.githubusercontent.com/vercel-labs/web-interface-guidelines/main/command.md)。
规则落点：原生按钮/aria-pressed、可见焦点、滚动偏移、减少动效、transform/opacity、URL状态、
服务器页面与最小客户端控件分离、观察器/媒体监听清理。

## 复验

```powershell
cd frontend
npm run build
# 静态预览服务已在仓库根用Python http.server绑定127.0.0.1:3417。
node scripts/check-linen-scroll.cjs
```

Playwright脚本支持AEGISAV_PLAYWRIGHT_MODULE指定现有模块，使用已安装Chrome，不下载浏览器。
结果：`docs/benchmarks/linen_scroll_check_20261014.json`；原始缺失功能失败记录另存`*_initial_*`。
截图：`output/playwright/linen-scroll/{snap,reveal}-{start,records}-{1440,1366,1920,1024}.png`，
另有375/768/812宽度记录截图。

## 实测结果与推荐

滚动专项22项通过/0失败：2模式×7视口（1440×900、1366×768、1920×1080、
1024×720、768×1024、375×812、812×375），以及8组模式/URL后退/原生滚轮/键盘/
减少动效/非法参数/无JS/20个长文件名检查。桌面两屏的主操作、最后一条记录和页脚全部在各自视口内；
0横向溢出、0控制台错误、0上传或外部请求。现有原型回归19项也全部通过。
生产构建、TypeScript及npm audit（0漏洞）通过。截图人工检查1440双状态、375手机和1024×720边界。

采用**完整状态布局 + 自然滚动触发**作为默认：保留完整首屏与记录屏构图，
查看记录时可在任意位置停留，后续更长任务列表与证据内容也容易扩展。
轻吸附版更适合演示两个状态之间的切换，保留顶部开关供用户直接比较；未使用mandatory强制吸附。
自然滚动版只在第一次进入记录区时呈现，回到上屏再向下不会反复隐藏已读内容。

失败与修正如实保留：首次缺少功能出现0项通过/超时（初始JSON已存）；
Chrome将默认proximity序列化为`y`，测试修正为语义等价；
平板页面余量不足以将记录顶到最上方，测试按自然布局可达性检查；
键盘锚点平滑滚动与无JS页面的rAF轮询会导致过早断言/超时，分别等待实际几何位置和使用Node侧有界轮询。
代码审查另发现无JS下锚点偏移原依赖effect，已改为CSS `:has(.linen-workspace)`保证无需JS也能避开顶栏。
没有放宽最终“内容可达、焦点可见、无剪裁”的验收要求。

本轮未修改检测器或采集样本；仅前端源码、演示数据交互及发布白名单发生变更。
VM保持关闭，Node构建堆上限1536MiB，正式截图/测试证据保留，回环静态预览继续供用户查看。
