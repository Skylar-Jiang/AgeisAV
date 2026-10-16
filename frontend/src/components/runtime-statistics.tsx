'use client';
import { RefreshCw } from 'lucide-react';
import { Button } from './ui/button';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';
import { bytesText, engines, RuntimeStatistics as Statistics, statusText } from '@/lib/api';
import { useApi } from '@/lib/use-api';
const milliseconds = (value: number | null | undefined) => value == null ? '—' : value.toLocaleString('zh-CN', { maximumFractionDigits: 1 }) + ' ms';

export function RuntimeStatistics() {
  const resource = useApi<Statistics>('/v1/statistics');
  if (resource.status === 'unauthorized') return <LocalAccess onConnected={resource.reload}/>;
  const data = resource.data;
  return <section className="product-section"><div className="page-heading"><div><p className="section-context">实际服务记录 · 有限统计范围</p><h1>运行统计</h1><p>查看任务状态、弃权与扫描成本。运行记录不等于准确率实验。</p></div><Button variant="outline" onClick={resource.reload}><RefreshCw aria-hidden="true"/>刷新统计</Button></div>
    {resource.status === 'error' && <div className="service-error" role="alert">{resource.error}<Button variant="outline" onClick={resource.reload}>重试</Button></div>}
    {!data ? resource.status === 'loading' ? <Skeleton className="h-32 w-full"/> : <p>未获得运行统计，请重试。没有数据时不显示零值指标。</p> : <>
      <dl className="runtime-overview"><div><dt>累计任务</dt><dd className="numeric">{data.task_count.toLocaleString('zh-CN')}</dd></div><div><dt>累计文件槽</dt><dd className="numeric">{data.file_count.toLocaleString('zh-CN')}</dd></div><div><dt>处理中任务</dt><dd className="numeric">{data.pending}</dd></div><div><dt>已保留上传字节</dt><dd className="numeric">{bytesText(data.reserved_bytes)}</dd></div></dl>
      <div className="product-columns"><section className="product-panel"><h2>任务状态</h2><dl className="product-metadata">{Object.entries(data.task_statuses).map(([status, count]) => <div key={status}><dt>{statusText[status] ?? status}</dt><dd className="numeric">{count}</dd></div>)}</dl>{!data.task_count && <p>尚无任务，提交良性文件后开始记录。</p>}</section><section className="product-panel"><h2>文件状态</h2><dl className="product-metadata">{Object.entries(data.file_statuses).map(([status, count]) => <div key={status}><dt>{statusText[status] ?? status}</dt><dd className="numeric">{count}</dd></div>)}</dl><p className="report-limits">失败、中断、取消及超时单独保留，不算作阴性或成功报告。</p></section></div>
      <section className="product-panel"><h2>最近文件的扫描成本</h2><p className="section-description">按提交顺序最近最多 {data.recent.limit} 个文件槽；当前 {data.recent.files} 个，{data.recent.reports} 份报告、{data.recent.distinct_report_sha256} 个不同报告 SHA。不同哈希不代表统计独立。</p><dl className="product-metadata"><div><dt>已尝试文件墙钟 P50 / P95</dt><dd>{milliseconds(data.recent.file_wall.p50_ms)} / {milliseconds(data.recent.file_wall.p95_ms)}</dd></div><div><dt>墙钟记录数 / 缓存报告数</dt><dd>{data.recent.file_wall.n} / {data.recent.cached_reports}</dd></div></dl>
        <div className="statistics-table-wrap" tabIndex={0} role="region" aria-label="五引擎状态与成本，可横向滚动"><table className="statistics-table"><caption>相同报告窗口内的引擎状态与原始计算成本</caption><thead><tr><th scope="col">引擎</th><th scope="col">返回状态</th><th scope="col">弃权 / 报告</th><th scope="col">P50</th><th scope="col">P95</th></tr></thead><tbody>{engines.map(engine => { const item = data.recent.engines[engine.id]; return <tr key={engine.id}><th scope="row">{engine.name}</th><td>{Object.entries(item.statuses).map(([status, count]) => `${statusText[status] ?? (status === 'missing' ? '缺失证据' : status)} ${count}`).join(' · ') || '无记录'}</td><td className="numeric">{item.abstentions} / {data.recent.reports}</td><td className="numeric">{milliseconds(item.cost.p50_ms)}</td><td className="numeric">{milliseconds(item.cost.p95_ms)}</td></tr>; })}</tbody></table></div><p className="report-limits">缓存/任务内去重报告保留原计算耗时；引擎可并行，不能相加为总时延。此处混合文件大小和冷/热状态，属于运行诊断，不作公平吞吐量或性能增益结论。</p></section>
      <section className="product-panel evaluation-empty"><h2>独立检测评测</h2><p>当前任务数据库没有独立核实的标签及冻结划分，尚不能计算 Recall、Precision、FPR、F1、ROC-AUC 或 PR-AUC。</p><p>需要在隔离 VM 中完成可追溯、去重且严格划分的配对评测，再导入经过审核的正式汇总。恶意来源阳性比例不作为 Recall，少量零误报不证明 FPR ≤ 0.1%。</p></section><p className="report-limits">统计生成于 {new Date(data.generated_at).toLocaleString('zh-CN')} · {data.persistent ? 'SQLite 正式任务记录' : '仅当前内存记录'}</p>
    </>}</section>;
}
