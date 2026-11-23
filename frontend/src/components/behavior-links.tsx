'use client';
import { useApi } from '@/lib/use-api';
import { BehaviorSummary, behaviorStatus } from '@/lib/behavior';
import { Button } from './ui/button';

export function BehaviorLinks({ sha256, task, fileIndex }: { sha256: string; task: string; fileIndex: number }) {
  const resource = useApi<{ reports: BehaviorSummary[] }>(`/v1/behavior?sha256=${sha256}`);
  return <section className="product-panel behavior-links"><h2>离线行为证据</h2><p>行为分析独立于静态裁决。仅按日志声明的精确 SHA-256 关联，不证明日志真实性或实际执行。</p>{resource.status === 'loading' ? <p role="status">正在查询行为报告…</p> : resource.status === 'error' || resource.status === 'unauthorized' ? <p role="alert">行为报告不可用，不计作阴性。<Button variant="ghost" onClick={resource.reload}>重新查询</Button></p> : resource.data?.reports.length ? <ul>{resource.data.reports.map(row => <li key={row.id}><a className="text-action" href={'/linen/behavior/?report=' + row.id}>{behaviorStatus[row.status]} · {new Date(row.created_at).toLocaleString('zh-CN')}</a></li>)}</ul> : <p>not_observed · 没有与此 SHA-256 关联的行为日志，不能判定行为安全。</p>}<a className="text-action" href={`/linen/behavior/?task=${task}&file=${fileIndex}`}>导入日志并尝试精确关联</a></section>;
}
