'use client';
import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ArrowRight, RefreshCw } from 'lucide-react';
import { Button } from './ui/button';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';
import { api, bytesText, ScanTask, statusText, terminal } from '@/lib/api';
import { useApi } from '@/lib/use-api';

export function TaskLedger({ history = false }: { history?: boolean }) {
  const parameters = useSearchParams();
  const rawOffset = Number(parameters.get('offset') ?? 0);
  const offset = Number.isInteger(rawOffset) ? Math.max(0, Math.min(1000000, rawOffset)) : 0;
  const state = history ? 'terminal' : parameters.get('state') === 'active' ? 'active' : 'all';
  const route = history ? '/linen/history/' : '/linen/tasks/';
  const resource = useApi<{ tasks: ScanTask[]; persistent: boolean }>(`/v1/tasks?limit=21&offset=${offset}&state=${state}`, 3000);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [notice, setNotice] = useState('');
  async function cancel(id: string) {
    setCancelling(id); setNotice('');
    try { await api(`/v1/tasks/${id}/cancel`, { method: 'POST' }); resource.reload(); setNotice('取消请求已记录，已完成报告保留。'); }
    catch (error) { setNotice(error instanceof Error ? error.message : '取消请求失败'); }
    finally { setCancelling(null); }
  }
  if (resource.status === 'unauthorized') return <LocalAccess onConnected={resource.reload}/>;
  const jobs = resource.data?.tasks.slice(0, 20) ?? [];
  return <section className="product-section">
    <div className="page-heading"><div><p className="section-context">{history ? '保留每一次判断' : '受控队列 · 逐文件进度'}</p><h1>{history ? '历史记录' : '批量任务'}</h1><p>{history ? '已结束的任务与报告，中断和失败也完整保留。' : '最多20个文件一批。完成、错误与未完成检测分别记录。'}</p></div><div className="product-actions"><Button variant="outline" onClick={resource.reload}><RefreshCw aria-hidden="true"/>刷新</Button><a className="text-action" href="/linen/">提交新扫描<ArrowRight aria-hidden="true"/></a></div></div>
    {!history && <nav className="product-tabs" aria-label="任务状态筛选"><a href={route} aria-current={state === 'all' ? 'page' : undefined}>全部任务</a><a href={route + '?state=active'} aria-current={state === 'active' ? 'page' : undefined}>处理中</a></nav>}
    <p role="status" aria-live="polite">{notice}</p>
    {resource.status === 'error' && <div className="service-error" role="alert">{resource.error}<Button variant="outline" onClick={resource.reload}>重新读取</Button></div>}
    {resource.status === 'loading' ? <Skeleton className="h-32 w-full"/> : resource.status === 'error' && !resource.data ? <p>未获得任务清单，请重新读取；连接失败不代表没有任务。</p> : jobs.length ? <div className="task-ledger">{jobs.map(job => <details key={job.id} className="task-entry" open={!terminal(job.status)}><summary><div><strong>{statusText[job.status] ?? job.status}</strong><span>{new Date(job.created_at).toLocaleString('zh-CN')} · {job.total} 个文件</span></div><span className="numeric">已处理 {job.finished} / {job.total}</span><span className="expand-indicator" aria-hidden="true">+</span></summary><div className="task-entry-body"><code className="task-identity" translate="no">任务 {job.id}</code><progress aria-label={`任务 ${job.id} 文件进度`} max={job.total} value={job.finished}/>{job.status === 'interrupted' && <p>服务重启后上传字节已丢失，已完成报告保留。请重新选择未完成文件，作为新任务提交。</p>}{job.status === 'timed_out' && <p>任务超过截止时间；未完成项没有检测结论。</p>}
      <ul>{job.files.map((file, index) => <li key={index}><a href={`/linen/detail/?task=${job.id}&file=${index}`}><span>{file.name}</span><span>{bytesText(file.size_bytes)}</span><strong>{statusText[file.verdict ?? file.status] ?? file.status}</strong><ArrowRight aria-hidden="true"/></a></li>)}</ul>{!terminal(job.status) && <Button variant="outline" onClick={() => cancel(job.id)} disabled={cancelling === job.id || job.status === 'cancelling'}>{cancelling === job.id || job.status === 'cancelling' ? '正在取消…' : '取消未完成扫描'}</Button>}</div></details>)}</div> : <div className="live-empty"><h2>{state === 'active' ? '当前没有处理中任务' : history ? '还没有已结束的任务' : '还没有扫描任务'}</h2><p>从工作台提交良性 PE。不会自动填入演示结果。</p></div>}
    <nav className="product-pagination" aria-label="任务分页">{offset > 0 ? <a href={`${route}?offset=${Math.max(0, offset - 20)}&state=${state}`}>上一页</a> : <span>已到最新记录</span>}<span>每页最多20个任务</span>{(resource.data?.tasks.length ?? 0) > 20 && <a href={`${route}?offset=${offset + 20}&state=${state}`}>下一页</a>}</nav>
    <p className="report-limits">{resource.data?.persistent ? '报告已持久化。重启后可查询已完成报告，未完成文件需要重新提交。' : '当前服务没有启用持久化。'}取消、超时、解析失败与弃权不代表文件安全。</p>
  </section>;
}
