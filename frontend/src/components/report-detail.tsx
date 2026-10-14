'use client';
import { useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { ArrowLeft, Download, ShieldAlert, Copy, Check, FileCode2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { demoEngines, demoHash, demoFiles } from './demo-data';
import { CostFigure } from './cost-figure';
import type { Direction } from './prototype-shell';

export function ReportDetail({ direction }: { direction: Direction }) {
  const parameters = useSearchParams();
  const requested = Number(parameters.get('file') ?? '0');
  const selected = Number.isInteger(requested) && requested >= 0 && requested < demoFiles.length ? requested : 0;
  const file = demoFiles[selected];
  const hash = selected === 0 ? demoHash : String(selected).repeat(64);
  const engines = selected === 0 ? demoEngines : demoEngines.map(engine => ({ ...engine,
    status: selected === 3 ? '未执行' : selected === 2 && engine.id === 'ml' ? '不适用' : '未命中',
    time: selected === 3 ? 0 : engine.time,
    evidence: selected === 3 ? '非 PE 文件，未进入检测引擎，不计为阴性。' : selected === 2 && engine.id === 'ml' ? '演示模型不适用，保留弃权。' : '演示未命中。未命中不能证明文件安全。' }));
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState('');
  async function copy() {
    try { await navigator.clipboard.writeText(hash); setCopied(true); setCopyError(''); }
    catch { setCopied(false); setCopyError('剪贴板不可用，请从下方选择并复制 SHA-256。'); }
  }
  function exportReport() {
    const blob = new Blob([JSON.stringify({ demo: true, final_evaluation: false, filename: file.name, sha256: hash, engines }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob); const link = document.createElement('a');
    link.href = url; link.download = 'aegisav-demo-report.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
  return <>
    <a href={`/${direction}/`} className="back-link"><ArrowLeft aria-hidden="true"/>返回扫描工作台</a>
    <div className="page-heading report-heading"><div><p className="section-context">文件检测详情</p><h1><FileCode2 aria-hidden="true"/>{file.name}</h1><p>{file.architecture} · {file.size} <span className="heading-separator">/</span> 演示报告</p></div><Button variant="outline" onClick={exportReport}><Download data-icon="inline-start" aria-hidden="true"/>导出 JSON</Button></div>
    <div className="verdict-band"><ShieldAlert aria-hidden="true"/><div><h2>{file.status}</h2><p>{selected === 0 ? "2 个引擎提供可疑证据，1 个引擎未完成。结论不等于已确认恶意。" : file.evidence + "。这是合成 UI 演示，不提供安全保证。"}</p></div><Badge variant="outline">缓存命中 · 演示</Badge></div>
    <div className="file-fingerprint"><span>SHA-256</span><code translate="no">{hash}</code><Button variant="ghost" size="icon" aria-label="复制 SHA-256" onClick={copy}>{copied ? <Check aria-hidden="true"/> : <Copy aria-hidden="true"/>}</Button><span role="status" className={copyError ? "notice" : "sr-only"}>{copied ? 'SHA-256 已复制' : copyError}</span></div>
    <div className="detail-layout"><section className="engine-region"><div className="region-heading"><h2>五引擎证据</h2><Badge variant="secondary">证据分级 / 演示</Badge></div><p className="section-description">每个判断保留来源、版本、适用范围和未完成原因。</p>
      <div className="engine-ledger">{engines.map(engine => <details key={engine.id} className="engine-row" open={engine.id === 'ml' && selected === 0}><summary><div className="engine-mark" data-engine={engine.id}>{engine.id === 'sha256' ? '#' : engine.id === 'ml' ? 'ML' : engine.name[0]}</div><div className="engine-name"><strong>{engine.name}</strong><span>{engine.kind}</span></div><span className="result-label" data-status={engine.status}>{engine.status}</span><span className="engine-duration numeric">{engine.time.toLocaleString('zh-CN')} ms</span><span className="expand-indicator" aria-hidden="true">+</span></summary><div className="engine-evidence"><p>{engine.evidence}</p><dl><div><dt>资产版本</dt><dd>{engine.version}</dd></div><div><dt>标签证据</dt><dd>合成 UI 夹具，非独立真值</dd></div></dl>{engine.id === 'ml' && selected === 0 ? <div className="score-track" aria-label="演示模型分数0.931，非校准概率"><span>演示模型分数</span><strong>0.931</strong><div><i/></div><small>不是恶意概率</small></div> : null}</div></details>)}</div>
    </section><aside className="detail-context"><CostFigure engines={engines}/><section className="file-metadata"><div className="region-heading"><h2>文件概览</h2></div><dl><div><dt>文件类型</dt><dd>{selected === 3 ? "非 PE" : "PE32+ executable"}</dd></div><div><dt>架构</dt><dd>{file.architecture}</dd></div><div><dt>模型范围</dt><dd>{selected === 3 ? "未执行" : selected === 2 ? "General PE（架构不适用）" : "General PE（演示）"}</dd></div><div><dt>数字签名</dt><dd>未验证</dd></div><div><dt>总耗时</dt><dd className="numeric">{file.time}（演示）</dd></div><div><dt>标签</dt><dd>Unknown</dd></div></dl></section><p className="report-limits">没有独立标签与充分良性分母，本报告不提供正式 Recall 或 FPR 结论。</p></aside></div>
  </>;
}
