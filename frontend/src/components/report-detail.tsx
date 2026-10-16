'use client';
import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ArrowLeft, Copy, Download, FileCode2, ShieldAlert } from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Skeleton } from './ui/skeleton';
import { LocalAccess } from './local-access';
import { CostFigure } from './cost-figure';
import { bytesText, engines, ScanTask, statusText } from '@/lib/api';
import { useApi } from '@/lib/use-api';

export function ReportDetail() {
  const parameters = useSearchParams();
  const id = parameters.get('task') ?? '';
  const index = Number(parameters.get('file') ?? '0');
  const resource = useApi<ScanTask>(/^[a-f0-9]{32}$/.test(id) ? `/v1/tasks/${id}` : null, 1000);
  const [notice, setNotice] = useState('');
  const back = <a href="/linen/" className="back-link"><ArrowLeft aria-hidden="true"/>返回扫描工作台</a>;
  if (!/^[a-f0-9]{32}$/.test(id)) return <>{back}<h1>选择一份检测报告</h1><p className="section-description">从工作台的真实任务中打开文件详情。此处不会自动展示演示报告。</p></>;
  if (resource.status === 'unauthorized') return <>{back}<LocalAccess onConnected={resource.reload}/></>;
  if (!resource.data) return <>{back}<h1>{resource.status === 'error' ? '报告暂不可用' : '正在读取报告…'}</h1>{resource.status === 'error' ? <div role="alert" className="service-error">{resource.error}<Button variant="outline" onClick={resource.reload}>重新读取</Button></div> : <Skeleton className="h-32 w-full"/>}</>;
  const file = Number.isInteger(index) && index >= 0 ? resource.data.files[index] : undefined;
  if (!file) return <>{back}<h1>没有这个文件的报告</h1><p>请返回任务列表重新选择文件。</p></>;
  const report = file.report;
  const costs = engines.map(engine => ({ id: engine.id, name: engine.name, time: report?.engines[engine.id]?.elapsed_ms ?? 0 }));
  function download() {
    const blob = new Blob([JSON.stringify({ data_origin: 'local_api', task_id: id, file, final_evaluation: false }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob), anchor = document.createElement('a');
    anchor.href = url; anchor.download = 'aegisav-report.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  return <>{back}<div className="page-heading report-heading"><div><p className="section-context">真实文件检测详情</p><h1><FileCode2 aria-hidden="true"/>{file.name}</h1><p>{bytesText(file.size_bytes)} · {statusText[file.status] ?? file.status}</p></div><Button variant="outline" onClick={download}><Download aria-hidden="true"/>导出 JSON</Button></div>
    {resource.status === 'error' && <div role="alert" className="service-error">连接中断，显示上次返回的报告。{resource.error}<Button variant="outline" onClick={resource.reload}>刷新报告</Button></div>}
    {!report ? <div className="live-empty" role="status"><h2>{statusText[file.status] ?? file.status}</h2><p>{file.status === 'interrupted' ? '服务重启后上传字节已丢失。请返回工作台重新选择文件，作为新任务提交。' : file.status === 'timed_out' ? '扫描进程超过截止时间并已终止。此文件没有检测结论。' : file.error ?? '等待服务完成当前文件。引擎尚未返回报告，不计为阴性。'}</p><p>未获得检测报告，不能据此判断文件安全。</p></div> : <>
      <div className="verdict-band"><ShieldAlert aria-hidden="true"/><div><h2>{statusText[report.verdict] ?? report.verdict}</h2><p>来源为本机五引擎服务。未命中或不可用均不能证明安全；结论不等于独立真值。</p></div><Badge variant="outline">{report.cached ? '缓存复用' : '本次计算'}</Badge></div>
      <div className="file-fingerprint"><span>SHA-256</span><code translate="no">{report.sha256}</code><Button variant="ghost" size="icon" aria-label="复制 SHA-256" onClick={async () => { try { await navigator.clipboard.writeText(report.sha256); setNotice('SHA-256 已复制'); } catch { setNotice('剪贴板不可用，请选择并复制 SHA-256。'); } }}><Copy aria-hidden="true"/></Button><span role="status">{notice}</span></div>
      <div className="detail-layout"><section className="engine-region"><div className="region-heading"><h2>五引擎证据</h2><Badge variant="secondary">真实服务报告</Badge></div><p className="section-description">保留命中、未命中、超时、错误、不可用与不适用。分数不是校准后的恶意概率。</p>
        <div className="engine-ledger">{engines.map(engine => {
          const result = report.engines[engine.id];
          return <details key={engine.id} className="engine-row" open={engine.id === 'lightgbm'}><summary><div className="engine-mark">{engine.id === 'lightgbm' ? 'ML' : engine.name[0]}</div><div className="engine-name"><strong>{engine.name}</strong><span>{engine.kind}</span></div><span className="result-label" data-status={result?.status === 'matched' ? '需要复核' : result?.status === 'timeout' ? '超时' : ''}>{result ? statusText[result.status] ?? result.status : '未返回（弃权）'}</span><span className="engine-duration numeric">{result ? result.elapsed_ms.toLocaleString('zh-CN', { maximumFractionDigits: 1 }) + ' ms' : '—'}</span><span className="expand-indicator" aria-hidden="true">+</span></summary>
            <div className="engine-evidence"><dl><div><dt>引擎版本</dt><dd translate="no">{result?.engine_version ?? '未返回'}</dd></div><div><dt>资产版本</dt><dd translate="no">{result?.artifact_version ?? '未配置'}</dd></div></dl>{result?.evidence.length ? <pre tabIndex={0} aria-label={`${engine.name} 原始证据`}>{JSON.stringify(result.evidence, null, 2)}</pre> : <p>无返回证据；请结合引擎状态阅读，不能据此认定安全。</p>}
              {result?.score != null && <div className="score-track" aria-label={`模型分数 ${result.score}，非恶意概率`}><span>模型分数</span><strong>{result.score.toFixed(6)}</strong><div><i style={{ width: `${Math.max(0, Math.min(100, result.score * 100))}%` }}/></div><small>冻结阈值：{result.threshold ?? '未返回'} · 非恶意概率</small></div>}</div></details>;
        })}</div></section><aside className="detail-context"><CostFigure engines={costs}/><section className="file-metadata"><h2>文件与策略</h2><dl><div><dt>文件类型</dt><dd>PE · 服务已解析</dd></div><div><dt>数字签名</dt><dd>未独立验证</dd></div><div><dt>本次文件墙钟</dt><dd>{file.elapsed_ms?.toLocaleString('zh-CN', { maximumFractionDigits: 1 }) ?? '未记录'} ms</dd></div><div><dt>融合策略</dt><dd>{report.fusion?.policy_id ?? '未返回'}</dd></div><div><dt>模型配置</dt><dd>{report.engines.lightgbm?.profile ?? '未配置'}</dd></div><div><dt>独立标签</dt><dd>Unknown</dd></div>{file.duplicate_of != null && <div><dt>任务内去重</dt><dd>复用第 {file.duplicate_of + 1} 个文件</dd></div>}</dl></section><p className="report-limits">{report.cached ? '缓存复用时，各引擎耗时来自原始计算。本次文件墙钟单独记录。' : '引擎可并行执行，耗时不能相加为总时延。'}本报告没有独立真值分母，不提供正式 Recall 或 FPR。</p></aside></div>
    </>}</>;
}
