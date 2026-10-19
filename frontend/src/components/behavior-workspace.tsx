'use client';
import { useRef, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Download, FileClock, Upload } from 'lucide-react';
import { api, bytesText } from '@/lib/api';
import { BehaviorReport, BehaviorSummary, behaviorStatus } from '@/lib/behavior';
import { useApi } from '@/lib/use-api';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';

export function BehaviorWorkspace() {
  const parameters = useSearchParams(), router = useRouter();
  const identity = parameters.get('report') ?? '';
  const task = parameters.get('task') ?? '', fileIndex = Number(parameters.get('file') ?? 0);
  const list = useApi<{ reports: BehaviorSummary[]; persistent: boolean }>('/v1/behavior');
  const detail = useApi<BehaviorReport>(/^[a-f0-9]{32}$/.test(identity) ? `/v1/behavior/${identity}` : null);
  const [selected, setSelected] = useState<File | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const errorRef = useRef<HTMLParagraphElement>(null);
  if (list.status === 'unauthorized' || detail.status === 'unauthorized') return <LocalAccess onConnected={() => { list.reload(); detail.reload(); }}/>;
  const linkQuery = /^[a-f0-9]{32}$/.test(task) && Number.isInteger(fileIndex) && fileIndex >= 0 && fileIndex < 20 ? `?task=${task}&file=${fileIndex}` : '';
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setError('');
    if (!selected || selected.size > 4 * 1024 ** 2 || selected.size === 0) {
      setError('请选择非空的 Sysmon XML 或标准化 JSON，文件不能超过 4 MB。');
      requestAnimationFrame(() => errorRef.current?.focus()); return;
    }
    setBusy(true);
    try {
      const report = await api<BehaviorReport>('/v1/behavior' + linkQuery, { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: selected });
      router.push('/linen/behavior/?report=' + report.id); list.reload();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : '导入失败，未获得分析结论。');
      requestAnimationFrame(() => errorRef.current?.focus());
    } finally { setBusy(false); }
  }
  return <section className="product-section behavior-workspace"><div className="page-heading"><div><p className="section-context">离线日志 · 不执行任何程序</p><h1>把行为，留在证据里。</h1><p>导入 Windows Sysmon 记录，查看规则信号与进程链。未观察到行为不等于安全。</p></div><Badge variant="outline">独立于静态裁决</Badge></div>
    <form className="behavior-import product-panel" onSubmit={submit} aria-busy={busy}>
      <div><h2><Upload aria-hidden="true"/>导入行为日志</h2><p id="behavior-help">UTF-8 XML 或标准化 JSON · 最多 4 MB / 1,000 个事件。EVTX 请先在可信工具中导出 XML。日志可能包含命令行、用户名与路径，仅在本机分析。</p>{linkQuery && <p>本次尝试关联选定的静态报告；只接受进程创建事件中的精确 SHA-256，不根据文件名推断。</p>}</div>
      <div className="behavior-upload-controls"><label htmlFor="behavior-file">Sysmon 日志文件</label><input id="behavior-file" type="file" name="behavior-file" accept=".xml,.json" aria-describedby="behavior-help behavior-error" aria-invalid={Boolean(error)} disabled={busy} onChange={event => { setSelected(event.target.files?.[0] ?? null); setError(''); }}/><Button disabled={busy || !selected} type="submit">{busy ? '正在受限进程中分析…' : '分析日志'}</Button></div>
      <p id="behavior-error" ref={errorRef} tabIndex={-1} role="alert">{error}</p>
      <p className="report-limits">原始文件不持久保存；规范化证据和命令行会写入本地私有报告库。单次解析限时 20 秒、内存 256 MB。服务中断时需重新导入。</p>
    </form>
    {identity ? detail.data ? <BehaviorEvidence key={detail.data.id} report={detail.data}/> : detail.status === 'error' ? <div className="service-error" role="alert">{detail.error}<Button variant="outline" onClick={detail.reload}>重新读取报告</Button></div> : <Skeleton className="h-32 w-full"/> : <div className="behavior-empty"><FileClock aria-hidden="true"/><h2>等待一份行为记录</h2><p>当前没有打开行为日志，状态为 not_observed。静态检测仍独立运行。</p></div>}
    <section className="product-panel"><h2>本地行为报告</h2>{list.status === 'error' ? <div role="alert">{list.error}<Button variant="outline" onClick={list.reload}>刷新历史</Button></div> : !list.data ? <p role="status">正在读取报告历史…</p> : list.data.reports.length === 0 ? <p>还没有已保存的行为报告。</p> : <><p className="report-limits">最近 50 份 · {list.data.persistent ? '重启后可查询' : '内存模式，重启后不保留'} · 无正式准确率指标</p><ul className="behavior-history">{list.data.reports.map(row => <li key={row.id}><a href={'/linen/behavior/?report=' + row.id} aria-current={identity === row.id ? 'page' : undefined}><time dateTime={row.created_at}>{new Date(row.created_at).toLocaleString('zh-CN')}</time><code>{row.id.slice(0, 12)}</code><span>{behaviorStatus[row.status] ?? row.status}</span></a></li>)}</ul></>}</section>
  </section>;
}

function BehaviorEvidence({ report }: { report: BehaviorReport }) {
  const [filter, setFilter] = useState(''), [page, setPage] = useState(0), [processPage, setProcessPage] = useState(0);
  const rows = report.events.filter(event => !filter || event.process_id === filter || event.id === filter);
  function show(value: string) { setFilter(value); setPage(0); }
  function download() {
    const url = URL.createObjectURL(new Blob([JSON.stringify({ data_origin: 'local_api', behavior: report }, null, 2)], { type: 'application/json' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'aegisav-behavior.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  return <article className="behavior-evidence" aria-label="行为分析报告"><div className="region-heading"><div><h2>行为证据</h2><p>{behaviorStatus[report.status] ?? report.status} · {report.elapsed_ms.toFixed(1)} ms</p></div><Button variant="outline" onClick={download}><Download aria-hidden="true"/>导出行为 JSON</Button></div>
    <p className="report-limits">规则信号需要复核，不能证明恶意性。未命中、字段缺失与未采集事件均不能证明安全；静态阈值和融合策略未改变。</p>
    <dl className="product-metadata behavior-metadata"><div><dt>日志 SHA-256</dt><dd><code>{report.source.sha256}</code></dd></div><div><dt>解析器 / 格式</dt><dd>{report.parser_version} / {report.source.format}</dd></div><div><dt>输入 / 解析 / Sysmon</dt><dd>{report.coverage.input_events} / {report.coverage.parsed_events} / {report.coverage.sysmon_events} 个事件 · {bytesText(report.source.size_bytes)}</dd></div><div><dt>事件覆盖</dt><dd>{report.coverage.observed_event_ids.join(', ') || '未观察到'}</dd></div><div><dt>未观察到的支持事件</dt><dd>{report.coverage.unobserved_event_ids.join(', ') || '无'}；未验证传感器配置和日志完整性</dd></div><div><dt>不支持的事件 / 缺字段</dt><dd>{report.coverage.unsupported_event_ids.join(', ') || '无'} / {report.coverage.missing_field_events} 个事件</dd></div></dl>
    <section className="product-panel"><h2>与静态报告的关联</h2><p>{behaviorStatus[report.static_link.status]}。{report.static_link.status === 'log_claimed_sha256' ? '只验证导入日志声明的哈希相同；未验证日志真实性，也不把行为归结为该文件已被执行。' : '未找到可核验的精确哈希关联，不按相同名称自动归因。'}</p>{report.static_link.task_id && <a className="text-action" href={`/linen/detail/?task=${report.static_link.task_id}&file=${report.static_link.file_index}`}>查看关联的静态报告</a>}</section>
    {report.parse_errors.length > 0 && <section className="product-panel" role="alert"><h2>部分事件解析失败</h2><ul>{report.parse_errors.map(row => <li key={row.index}>输入序号 {row.index}：{row.reason}</li>)}</ul></section>}
    <section className="product-panel"><h2>Sigma 规则与适用范围</h2>{report.rules_error && <p role="alert">{report.rules_error}，没有行为检测结论。</p>}<div className="rule-list">{report.rules.map(rule => <details key={rule.rule_id} open={rule.event_ids.length > 0}><summary><strong>{rule.title}</strong><span>{behaviorStatus[rule.status] ?? rule.status}</span></summary><dl className="product-metadata"><div><dt>严重程度 / 资产版本</dt><dd>{rule.level} / {rule.asset_version}</dd></div><div><dt>规则 ID</dt><dd>{rule.rule_id}</dd></div><div><dt>作者</dt><dd>{rule.author}</dd></div><div><dt>来源 / 许可</dt><dd><a href={rule.source} target="_blank" rel="noopener noreferrer">SigmaHQ 固定版本</a> / {rule.license}</dd></div><div><dt>资产 SHA-256</dt><dd><code>{rule.asset_sha256}</code></dd></div></dl>{rule.reason && <p>{rule.reason}</p>}<div className="product-actions">{rule.event_ids.map(id => <Button variant="outline" key={id} onClick={() => show(id)}>查看证据 {id}</Button>)}</div></details>)}</div></section>
    <section className="product-panel"><h2>进程链</h2><p className="report-limits">按主机、ProcessGuid 与时间关联；PID 仅在唯一且有明确起止的生命周期内回退。同名进程不会合并。</p>{report.processes.length === 0 ? <p>没有可建立生命周期的进程创建事件。</p> : <><div className="behavior-processes">{report.processes.slice(processPage * 50, processPage * 50 + 50).map(process => <div className="behavior-process" key={process.id}><span className="numeric">{process.parent_id ? `${process.parent_id} → ` : ''}{process.id}</span><div><strong>{process.image ?? '缺失进程名称'}</strong><small>{process.computer} · PID {process.pid ?? '未知'} · {process.start}</small><code>{process.guid ?? '无 GUID；仅允许有界 PID 关联'}</code></div><Button variant="outline" onClick={() => show(process.id)}>查看 {process.event_ids.length} 个事件</Button></div>)}</div><div className="product-pagination"><Button variant="ghost" disabled={processPage === 0} onClick={() => setProcessPage(value => value - 1)}>上一组进程</Button><span>{processPage + 1} / {Math.ceil(report.processes.length / 50)}</span><Button variant="ghost" disabled={(processPage + 1) * 50 >= report.processes.length} onClick={() => setProcessPage(value => value + 1)}>下一组进程</Button></div></>}</section>
    <section className="product-panel" id="behavior-events"><div className="region-heading"><h2>原始字段与事件时间</h2><Button variant="outline" onClick={() => show('')}>显示全部事件</Button></div><p role="status">{filter ? `筛选 ${filter} · ` : ''}共 {rows.length} 个事件；每页 25 个。</p><div className="behavior-event-list">{rows.slice(page * 25, page * 25 + 25).map(event => <details key={event.id} open={Boolean(filter)}><summary><span>{event.id} · Sysmon {event.event_id} · {event.kind}</span><time>{event.timestamp ?? '时间缺失'}</time></summary><p>来源：{event.provider ?? '未知'} / {event.computer ?? '主机缺失'} / Record {event.record_id ?? '缺失'} / 输入序号 {event.input_index}。{event.process_id ? `关联 ${event.process_id}` : '进程关联证据不足'}</p>{event.missing_fields.length > 0 && <p>缺失字段：{event.missing_fields.join(', ')}</p>}<pre tabIndex={0} aria-label={`事件 ${event.id} 原始字段`}>{JSON.stringify(event.fields, null, 2)}</pre></details>)}</div><div className="product-pagination"><Button variant="ghost" disabled={page === 0} onClick={() => setPage(value => value - 1)}>上一页事件</Button><span>{page + 1} / {Math.max(1, Math.ceil(rows.length / 25))}</span><Button variant="ghost" disabled={(page + 1) * 25 >= rows.length} onClick={() => setPage(value => value + 1)}>下一页事件</Button></div></section>
  </article>;
}
