'use client';
import { useSearchParams } from 'next/navigation';
import { RefreshCw } from 'lucide-react';
import { Button } from './ui/button';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';
import { AssetInventory, bytesText, engines, statusText } from '@/lib/api';
import { useApi } from '@/lib/use-api';

export function AssetStatus() {
  const parameters = useSearchParams();
  const rawOffset = Number(parameters.get('rules') ?? 0);
  const offset = Number.isInteger(rawOffset) ? Math.max(0, Math.min(1000000, rawOffset)) : 0;
  const resource = useApi<AssetInventory>('/v1/engines');
  if (resource.status === 'unauthorized') return <LocalAccess onConnected={resource.reload}/>;
  const data = resource.data;
  return <section className="product-section"><div className="page-heading"><div><p className="section-context">版本可追溯 · 配置只读</p><h1>规则与模型</h1><p>来自本机服务的资产清单与可用性，不修改冻结阈值。</p></div><Button variant="outline" onClick={resource.reload}><RefreshCw aria-hidden="true"/>重新核验</Button></div>
    {resource.status === 'error' && <div role="alert" className="service-error">{resource.error}<Button variant="outline" onClick={resource.reload}>重试</Button></div>}
    {!data ? resource.status === 'loading' ? <Skeleton className="h-32 w-full"/> : <p>未获得资产清单，请重新核验服务。</p> : <>
      <section className="asset-ledger"><h2>五引擎运行状态</h2>{engines.map(engine => { const item = data.engines.find(row => row.id === engine.id); return <div className="asset-row" key={engine.id}><div><strong>{engine.name}</strong><span>{engine.kind}</span></div><span>{item?.status === 'ready' ? '就绪' : item ? statusText[item.status] ?? item.status : '未返回（弃权）'}</span><code translate="no">{item?.artifact_version ?? '未配置资产版本'}</code></div>; })}</section>
      <div className="product-columns"><section className="product-panel"><h2>冻结模型配置</h2>{data.ml ? <><dl className="product-metadata"><div><dt>配置</dt><dd>{data.ml.profile}</dd></div><div><dt>特征维数</dt><dd>{data.ml.feature_dim ?? '未返回'}</dd></div><div><dt>特征实现</dt><dd translate="no">{data.ml.feature_implementation ?? '未返回'}</dd></div><div><dt>资产完整性</dt><dd>{data.ml.assets_valid ? '校验通过' : '不可用，扫描时弃权'}</dd></div></dl><p>当前路由：Win32 / .NET → {data.ml.routing.win32}；Win64 → {data.ml.routing.win64}。其他架构弃权。</p>{Object.entries(data.ml.models).map(([id, model]) => <details key={id} className="model-route" open={id === 'general' || data.ml?.profile === 'win64_low_fpr'}><summary>{id === 'general' ? '通用 PE 模型' : 'Win64 模型'} · {Object.values(data.ml!.routing).includes(id) ? '当前使用' : '已安装，当前未启用'}</summary><dl className="product-metadata"><div><dt>模型版本</dt><dd translate="no">{model.version}</dd></div><div><dt>适用范围</dt><dd>{model.scope.join(' / ')}</dd></div><div><dt>冻结阈值</dt><dd className="numeric">{model.threshold}</dd></div></dl></details>)}</> : <p>未配置 ML 资产，不能提供模型判断。</p>}<p className="report-limits">分数不是恶意概率。冻结阈值不代表本机部署已经达到低 FPR 目标。</p></section>
      <section className="product-panel"><h2>服务与资源策略</h2><dl className="product-metadata"><div><dt>服务版本</dt><dd translate="no">{data.service_release ?? '未发布'}</dd></div><div><dt>融合策略</dt><dd>{data.fusion_policy ?? 'evidence-or-v1'}</dd></div><div><dt>报告存储</dt><dd>{data.task_limits.persistent ? 'SQLite 持久化' : '仅内存'}</dd></div><div><dt>文件 / 任务截止</dt><dd>{data.task_limits.file_timeout_seconds ?? '—'} / {data.task_limits.task_deadline_seconds ?? '—'} 秒</dd></div><div><dt>扫描内存额度</dt><dd>{data.task_limits.memory_bytes ? bytesText(data.task_limits.memory_bytes) : '未提供'}</dd></div><div><dt>取消机制</dt><dd>{data.task_limits.cancellation === 'process_tree' ? '独立进程树终止' : '协作取消'}</dd></div><div><dt>哈希参考记录</dt><dd>{data.hash_reference_count.toLocaleString('zh-CN')}</dd></div></dl><p className="report-limits">就绪表示当前配置可用，具体文件仍可能超时、错误或不适用。此处不提供自动下载规则或在线修改模型操作。</p></section></div>
      <section className="product-panel"><h2>已加载 YARA 规则 · {data.rules.count.toLocaleString('zh-CN')}</h2><p className="section-description">保留来源、版本与适用范围。规则数量不能代表检测质量，每页显示20条。</p>{data.rules.entries.length ? <><div className="rule-list">{data.rules.entries.slice(offset, offset + 20).map(rule => <details key={rule.rule_id}><summary><code translate="no">{rule.rule_id}</code><span>{rule.version}</span></summary><dl className="product-metadata"><div><dt>来源</dt><dd translate="no">{rule.source}</dd></div><div><dt>范围</dt><dd>{String(rule.scope)}</dd></div><div><dt>置信标记</dt><dd>{String(rule.confidence)}</dd></div></dl></details>)}</div><nav className="product-pagination" aria-label="规则分页">{offset > 0 ? <a href={`/linen/assets/?rules=${Math.max(0, offset - 20)}`}>上一页规则</a> : <span>已到首条规则</span>}<span>{Math.min(offset + 1, data.rules.count)}–{Math.min(offset + 20, data.rules.count)} / {data.rules.count}</span>{offset + 20 < data.rules.count && <a href={`/linen/assets/?rules=${offset + 20}`}>下一页规则</a>}</nav></> : <p>没有已加载规则；检测报告将保留不可用状态。</p>}</section>
    </>}</section>;
}
