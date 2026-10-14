# AegisAV

Windows PE 五引擎静态检测平台：SHA-256、TLSH/SSDeep、YARA-X、ClamAV、LightGBM，
统一 FastAPI、版本缓存、有界批量任务、模型发布及现有 VMware 离线静态分析自动化。

这是经筛选的公开源代码快照。完整本地研究历史、私有候选清单、标签证据、原始数据、
API Key、模型权重及 VM 文件没有上传。公开摘要不是独立准确率证明；阶段1尚未正式验收。
来源和当前限制见[进度](docs/PROGRESS.md)、[实验摘要](docs/EXPERIMENTS.md)。

## 本地无害开发

需要Python3.12。安装`requirements-win-py312.txt`和`pip install -e . --no-deps`，
运行`python -m pytest -q`，再以`uvicorn aegisav.main:app --host 127.0.0.1 --port 8000`启动。
API没有身份认证，不应直接暴露到公网；`/v1/engines`显示真实可用性，缺失工具/模型会弃权。
ClamAV与模型权重需另按部署说明配置。源码测试中的私有归档证据回归在公开分发中明确跳过。

## 前端视觉原型

`frontend`使用Next.js/TypeScript/Tailwind/shadcn；`npm ci`后运行`npm run build`。
仓库根执行`python -m http.server 3417 --bind 127.0.0.1 --directory frontend/out`，
访问<http://127.0.0.1:3417/>或<http://127.0.0.1:3417/linen/>。仅保留Linen自然滚动与记录区短时虚化。
已删除其他视觉方案、方案选择器、吸附模式与比较控件。
原型仅使用明确标记的合成演示数据，不读取或上传文件，后续扩展业务页面与真实API联调。
实际Skill应用、浏览器验收及复验见[前端记录](docs/FRONTEND_PROTOTYPES_20261014.md)。

## 安全与复现

真实恶意PE仅在已核验隔离的专用Ubuntu VM内静态处理，禁止执行。
VM脚本目前绑定本项目已有客户机、磁盘标识与冻结研究配置；其他环境必须先审查和适配，
不能直接运行全部脚本。NAT仅用于元数据和加密归档，解包/分析前移除网卡并核验无路由、
无共享/剪贴板/拖放。凭据采用仓库外受保护配置。

五引擎未命中不等于安全；未完成/失败/不适用不计阴性；未知标签不计正式准确率。
原始证据和候选清单需合法授权本地访问，因此公开摘要无法单独复现私有文件上的检测结果。
`PUBLIC_SOURCE_MANIFEST.json`提供本次公开文件字节哈希，不含私有历史。
