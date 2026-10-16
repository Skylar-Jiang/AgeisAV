'use client';
import { useRef, useState } from 'react';
import { ArrowDown, ArrowUp, ArrowUpRight, ArrowRight, File as FileIcon, Plus, Search } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';
import { api, bytesText, encodeFiles, engines, Inventory, ScanTask, statusText, terminal } from '@/lib/api';
import { useApi } from '@/lib/use-api';

export function LiveWorkspace() {
  const history = useApi<{ tasks: ScanTask[]; persistent: boolean }>('/v1/tasks', 3000);
  const inventory = useApi<Inventory>('/v1/engines');
  const [selected, setSelected] = useState<File[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const active = useApi<ScanTask>(activeId ? `/v1/tasks/${activeId}` : null, 1000);
  const [search, setSearch] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [notice, setNotice] = useState('');
  const [failure, setFailure] = useState('');
  const picker = useRef<HTMLInputElement>(null);
  const submissionKey = useRef<string | null>(null);
  const connected = history.status === 'ready';
  const job = active.data;
  const working = Boolean(activeId && active.errorStatus !== 404 && (!job || !terminal(job.status)));
  const rows = (history.data?.tasks ?? []).flatMap(task => task.files.map((file, index) => ({ file, task, index }))).filter(row => row.file.name.toLowerCase().includes(search.toLowerCase())).slice(0, 30);
  const limits = inventory.data?.task_limits;
  function reconnect() { history.reload(); inventory.reload(); if (activeId) active.reload(); }
  async function submit() {
    setSubmitting(true); setFailure(''); setNotice('正在读取所选良性文件并提交到本机服务…');
    try {
      submissionKey.current ??= crypto.randomUUID();
      const created = await api<ScanTask>('/v1/tasks', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': submissionKey.current }, body: JSON.stringify(await encodeFiles(selected)) });
      setActiveId(created.id); setSelected([]); if (picker.current) picker.current.value = '';
      submissionKey.current = null;
      setNotice('任务已提交。进度以服务返回的文件状态为准。'); history.reload();
    } catch (error) { setFailure(error instanceof Error ? error.message : '提交失败'); setNotice(''); }
    finally { setSubmitting(false); }
  }
  async function cancel() {
    if (!activeId) return;
    setCancelling(true); setFailure('');
    try { await api(`/v1/tasks/${activeId}/cancel`, { method: 'POST' }); active.reload(); setNotice(inventory.data?.task_limits.cancellation === 'process_tree' ? '取消请求已记录，将终止当前扫描进程并保留已完成报告。' : '已请求协作取消：当前文件结束后停止，已完成的报告保留。'); }
    catch (error) { setFailure(error instanceof Error ? error.message : '取消失败'); }
    finally { setCancelling(false); }
  }
  return <>
    <section className="calm-intro" id="linen-start"><div className="calm-intro-copy"><span className="calm-eyebrow">文件静态分析</span><h1>从一个文件，<br/>看清每一条证据。</h1><p>让五个引擎各自判断。<br/>把结论、分歧和未完成的检测，一起留下。</p></div>
      <div className="file-composer" data-running={working || submitting}><div className="composer-top"><span>开始分析</span><span>本地服务 · 不执行文件</span></div>
        {history.status === 'unauthorized' ? <LocalAccess onConnected={reconnect}/> : <>
          <div className="composer-content"><div className="file-emblem" aria-hidden="true"><FileIcon/><span/><span/><span/></div><h2>{selected.length ? `${selected.length} 个文件已就绪` : '你的下一个文件，放在这里。'}</h2><p>{selected.length ? selected.map(file => file.name).join('、') : '选择良性 EXE、DLL 或 SYS，展开真实检测证据。'}</p></div>
          <input ref={picker} type="file" hidden multiple accept=".exe,.dll,.sys" aria-label="选择待扫描文件" onChange={event => {
            const files = Array.from(event.target.files ?? []);
            submissionKey.current = null;
            if (files.length > (limits?.max_files ?? 20) || files.some(file => file.size > (limits?.max_file_bytes ?? 16 * 1024 ** 2)) || files.reduce((sum, file) => sum + file.size, 0) > (limits?.max_task_bytes ?? 32 * 1024 ** 2)) {
              setSelected([]); event.target.value = ''; setFailure('文件超出预算：最多20个、单文件16 MiB、总计32 MiB。');
            } else { setSelected(files); setFailure(''); }
          }}/>
          <div className="composer-actions"><Button variant="outline" onClick={() => picker.current?.click()} disabled={!connected || submitting}><Plus aria-hidden="true"/>选择文件</Button><span>最多20个 · 单文件16 MiB</span><Button onClick={submit} disabled={!connected || selected.length === 0 || submitting || working}>{submitting ? '正在提交…' : '开始扫描'}<ArrowRight aria-hidden="true"/></Button></div>
          <ol className="calm-engine-steps live-engine-steps" aria-label="服务引擎可用性">{engines.map(engine => { const state = inventory.data?.engines.find(item => item.id === engine.id)?.status; return <li key={engine.id} title={state ?? '尚未查询'}><i aria-hidden="true"/>{engine.name}<span>{state === 'ready' ? '就绪' : state === 'unavailable' ? '不可用' : '待核验'}</span></li>; })}</ol>
        </>}
        <p className="calm-notice" role="status" aria-live="polite">{notice || '本机开发仅上传良性文件。真实恶意样本继续留在隔离 Ubuntu VM 内。'}</p>
        {failure && <p className="service-error" role="alert">{failure}</p>}
        {history.status === 'error' && <div className="service-error" role="alert">{history.error}<Button variant="outline" onClick={reconnect}>重新连接</Button></div>}
      </div><a href="#linen-records" className="linen-section-link">查看最近分析<ArrowDown aria-hidden="true"/></a>
    </section>
    <section className="calm-history" id="linen-records"><div className="calm-history-heading"><div><h2>最近的分析</h2><p>来自本机服务的真实任务，显示最近30个文件。</p></div><label className="live-search"><span className="sr-only">搜索文件名</span><Search aria-hidden="true"/><Input name="file-search" placeholder="搜索文件名…" autoComplete="off" value={search} onChange={event => setSearch(event.target.value)}/></label></div>
      {activeId && <section className="task-progress" aria-label="当前扫描任务"><div><strong>{job ? statusText[job.status] ?? job.status : '正在读取任务…'}</strong><span>{job ? `已处理 ${job.finished} / ${job.total} 个文件` : '等待服务返回进度'}</span></div><progress aria-label="文件处理进度" max={job?.total ?? 1} value={job?.finished ?? 0}/>
        {working && <Button variant="outline" onClick={cancel} disabled={cancelling || job?.cancel_requested}>{cancelling || job?.cancel_requested ? '正在取消…' : '取消任务'}</Button>}
        {job?.status === 'cancelling' && <p>{inventory.data?.task_limits.cancellation === 'process_tree' ? '正在终止当前扫描进程及其子进程。' : '当前文件完成后停止后续扫描。'}取消项没有检测结论。</p>}
        {job?.status === 'interrupted' && <p role="status">服务已重启。已完成报告保留，上传文件未暂存；请重新选择未完成文件，作为新任务提交。</p>}
        {job?.status === 'timed_out' && <p role="status">任务已超过截止时间。未完成项没有检测结论，可重新选择文件提交。</p>}
        {active.status === 'unauthorized' && <p role="alert">会话已过期，请重新认证后读取任务。<Button variant="outline" onClick={reconnect}>重新认证</Button></p>}
        {active.status === 'error' && <p role="alert">{active.errorStatus === 404 ? '任务已不存在，可能服务已重启。未完成文件不能计为阴性。' : active.error}{active.errorStatus === 404 ? <Button variant="outline" onClick={() => { setActiveId(null); setNotice('已清除失效的活动任务，可重新选择文件提交。'); }}>清除失效任务</Button> : <Button variant="outline" onClick={active.reload}>刷新任务</Button>}</p>}
        {job?.files.map((file, index) => <a key={index} href={`/linen/detail/?task=${job.id}&file=${index}`}><span>{file.name}</span><span>{statusText[file.status] ?? file.status}</span></a>)}
      </section>}
      <p className="records-loading-status" role="status" aria-live="polite">{history.status === 'loading' ? '正在读取真实任务…' : history.status === 'error' ? '连接已中断，以下为上次返回的记录；请重新连接。' : ''}</p>
      <div className="linen-records-content" aria-busy={history.status === 'loading'}>{history.status === 'loading' ? <div className="skeleton-list" aria-hidden="true">{[0, 1, 2].map(index => <Skeleton key={index} className="h-14 w-full"/>)}</div> : rows.length ? <ul className="calm-file-list">{rows.map(({ task, file, index }) => <li key={`${task.id}-${index}`}><a href={`/linen/detail/?task=${task.id}&file=${index}`} aria-label={`查看 ${file.name} 检测详情`}><FileIcon className="history-file-icon" aria-hidden="true"/><div className="calm-file-name"><strong>{file.name}</strong><span>{bytesText(file.size_bytes)} · {new Date(task.created_at).toLocaleString('zh-CN')}</span></div><span className="result-label" data-status={file.verdict === 'suspicious' ? '需要复核' : file.status === 'error' ? '解析失败' : ''}>{statusText[file.verdict ?? file.status] ?? file.status}</span><ArrowUpRight className="history-open" aria-hidden="true"/></a></li>)}</ul> : <div className="live-empty"><h3>{history.status === 'unauthorized' ? '连接后查看本机任务' : search ? '没有匹配的分析记录' : '还没有扫描记录'}</h3><p>{search ? '试试其他文件名。' : '选择良性 PE 开始扫描。这里不会自动填充演示结果。'}</p></div>}</div>
      <p className="calm-history-note">未命中不代表安全。失败、超时、取消与引擎不适用均单独保留。</p><div className="linen-history-footer"><span className="calm-history-note">{history.data?.persistent ? '任务报告已持久化' : '当前任务仅保存在服务内存中，重启后无法恢复。'}</span>{connected && <Button variant="ghost" onClick={async () => { try { await api('/v1/session', { method: 'DELETE' }); setActiveId(null); setSelected([]); history.reload(); inventory.reload(); } catch (error) { setFailure(error instanceof Error ? error.message : '断开失败'); } }}>断开会话</Button>}<a href="#linen-start" className="linen-section-link">返回开始分析<ArrowUp aria-hidden="true"/></a></div>
    </section>
  </>;
}
