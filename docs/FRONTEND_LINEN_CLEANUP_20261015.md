# Linen 单一视觉方案收尾 · 2026-10-15

## 决策与实现

按用户要求，只保留Linen亚麻、自然滚动及限定记录区的短时虚化。
删除Paper/Slate/Obsidian的6个页面、旧PrototypeShell与Workspace、方案选择首页、
两模式滚动控件、吸附CSS、查询参数切换和对应比较测试。旧方案可从Git历史追溯，
正式实验记录保留，并在原型/滚动文档顶部标注历史版本。

首页直接显示Linen；原有`/linen/`及`/linen/detail/`链接继续可用。
滚动效果改为小型LinenReveal组件，不再读取滚动模式或修改URL。
保留加载、空、错误、慢加载取消、键盘聚焦立即清晰、减少动效与无JS回退，
文件选择仍只读取文件名，所有内容明确为合成演示，未接真实API。

## 实测与审查

- `npm --prefix frontend run build`、`npm --prefix frontend run typecheck`通过。
- `npm --prefix frontend audit --omit=dev`：0漏洞。
- `node frontend/scripts/check-single-design.cjs`通过，拒绝的路由无源码/静态导出。
- `check-linen-ui.cjs`：11组通过，含8个页面/视口组合、交互、动效与新首页/6个旧路由404。
- `check-linen-scroll.cjs`：12组通过，含7视口、真实滚轮、完整首屏/记录屏、键盘焦点、
  减少动效、无JS与20个长文件名。自然滚动无吸附。
- `check-linen-blur.cjs`：6组通过，检查真实filter、中间帧、加载文字清晰、移除旧结果、
  取消后不覆盖错误、键盘与减少动效。浏览器合计29组通过、0失败、0跳过。

对保留界面仍有完整回归；历史47项包含已删除方案与两模式比较，不能沿用为当前测试数量。
初次连接失败源于此前预览服务已停止；重启后修正标题换行形成可访问名称空白的测试断言。
对应失败记录单独保留`frontend_linen_initial*`、`linen_natural_initial_20261015.json`，
最终通过记录没有覆盖历史失败证据。

实际查看375px工作台与1440px详情截图，未见溢出、重叠或不一致。
截图保存在`output/playwright/linen-*`、`linen-scroll/`、`linen-blur/`，可由脚本重建。
测试调用本机安装的Chrome；此前浏览器工具截图导出受路径限制，继续采用现有Playwright回归。
测试浏览器均在finally关闭，仅保留回环静态预览服务。

继续应用四个已核验官方Skills：frontend-design保留选定风格与删减装饰；
ui-ux-pro-max查询并落实focus-not-obscured，核验移动布局与对比度；
Vercel React指导缩小客户端组件、移除不再需要的参数/Suspense；
Web Interface Guidelines重新读取官方最新规则并审查标签、焦点、动效与内容溢出。
用户明确要求的短时filter仍覆盖通常仅使用transform/opacity的建议，不新增动效库。
独立只读审查未发现有证据的P1/P2；发现的旧metadata描述已修正并重新构建验证。

## 空间与资源：如实区分源码、产物和缓存

基线为本轮前HEAD `1eca589`；详细字节记录见
`docs/benchmarks/frontend_linen_cleanup_20261015.json`。

| 对象 | 前 | 后 | 变化 |
|---|---:|---:|---:|
| 前端源码（Git/LF口径） |256856 B|227383 B|减少29473 B|
| 当前静态导出 |1868801 B|1582497 B|减少286304 B|
| 当前.next缓存 |162909570 B|180226922 B|增加17317352 B|

递归清理已核定前端缓存的PowerShell操作被自动审批拒绝，返回`blocked by policy`，
没有更具体原因；该整条命令未执行，未换工具绕过。因此旧公开导出的.next缓存118632581 B、
旧out 1926679 B仍保留。正常Next构建重建当前out，已移除旧路由；
不能声称本轮释放了全部缓存或整个项目的磁盘净占用下降。

宿主机收尾瞬时可用RAM 9948004352 B，C/D可用30347468800/120905789440 B；
它们随其他项目变化，不归因于此次代码精简。未测浏览器峰值RAM、CPU或FPS，不作性能增益结论。
未启动ML/扫描Worker或VM，未触碰恶意样本、模型、规则、快照、正式数据或Git历史。
本轮没有新的检测实验；已完成80个新批次PE的unknown标签观察仍不能作为正式Recall/FPR。

## 复现与下一步

```powershell
npm --prefix frontend ci
npm --prefix frontend run build
.venv/Scripts/python.exe -m http.server 3417 --bind 127.0.0.1 --directory frontend/out
# 另一终端设置本机Playwright模块路径，然后执行：
node frontend/scripts/check-single-design.cjs
node frontend/scripts/check-linen-ui.cjs
node frontend/scripts/check-linen-scroll.cjs
node frontend/scripts/check-linen-blur.cjs
```

本机预览：<http://127.0.0.1:3417/>。后续沿唯一Linen方向接入真实API和业务页，
继续保持独立检测评测、固定阈值与VM静态分析边界。
本轮公开发布采用筛选源码快照，只快进现有公开分支，研究历史与私有清单不上传。
