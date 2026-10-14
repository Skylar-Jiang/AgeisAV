# Linen：完整状态与滚动体验对比

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
