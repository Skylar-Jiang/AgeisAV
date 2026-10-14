'use client';
import { useRef, useState } from 'react';
import { Upload, File, ArrowUpRight, Layers, Check, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Empty, EmptyHeader, EmptyTitle, EmptyDescription } from '@/components/ui/empty';
import { demoFiles } from './demo-data';
import type { Direction } from './prototype-shell';
type PreviewState = 'normal' | 'loading' | 'empty' | 'error';

export function Workspace({ direction }: { direction: Direction }) {
  const [search, setSearch] = useState('');
  const [preview, setPreview] = useState<PreviewState>('normal');
  const [selected, setSelected] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState('');
  const picker = useRef<HTMLInputElement>(null);
  const files = demoFiles.filter(file => file.name.toLowerCase().includes(search.toLowerCase()));
  async function demonstrate() {
    setRunning(true); setNotice('演示扫描进行中…');
    await new Promise(resolve => setTimeout(resolve, 900));
    setRunning(false); setNotice('演示完成。文件内容未读取，也未发送到检测服务。');
  }
  return <>
    <div className="page-heading"><div><p className="section-context">文件分析</p><h1>扫描工作台</h1><p>从文件到证据，让每一次检测都可解释。</p></div><Badge variant="outline"><span className="context-dot"/>静态分析模式</Badge></div>
    <div className="workspace-layout">
      <section className="workspace-primary">
        <div className="upload-zone"><div className="upload-icon"><Upload aria-hidden="true"/></div><div><h2>开始一次文件分析</h2><p>选择 PE 文件，查看五引擎的判断与证据。</p></div>
          <FieldGroup className="hidden"><Field><FieldLabel htmlFor={`files-${direction}`}>选择演示文件</FieldLabel><input ref={picker} id={`files-${direction}`} type="file" accept=".exe,.dll,.sys" multiple onChange={event => { setSelected(Array.from(event.target.files ?? []).map(file => file.name)); setNotice('已选择文件名。原型不会读取或上传文件内容。'); }}/></Field></FieldGroup>
          <div className="upload-actions"><Button onClick={() => picker.current?.click()} variant="outline"><Upload data-icon="inline-start" aria-hidden="true"/>选择文件</Button><Button onClick={demonstrate} disabled={running}>{running ? '演示扫描中…' : '演示扫描'}<ArrowUpRight data-icon="inline-end" aria-hidden="true"/></Button></div>
          <p className="upload-limits">PE · 单文件 16 MB · 每批最多 20 个 · 演示不上传文件</p>
          {selected.length > 0 ? <p className="selected-file-list">已选择：{selected.join('、')}</p> : null}
          <p className="notice" role="status" aria-live="polite">{notice}</p>
        </div>
        <section className="queue-region"><div className="region-heading"><h2>分析记录 <span>{demoFiles.length}</span></h2><span>演示批次 / UI-001</span></div>
          <FieldGroup><Field orientation="horizontal"><FieldLabel htmlFor={`search-${direction}`} className="sr-only">搜索文件名</FieldLabel><div className="search-input"><Search aria-hidden="true"/><Input id={`search-${direction}`} value={search} onChange={event => setSearch(event.target.value)} placeholder="搜索文件名…" autoComplete="off"/></div><Badge variant="secondary">全部文件</Badge></Field></FieldGroup>
          {preview === 'loading' ? <div className="skeleton-list" aria-label="记录加载中">{[1, 2, 3].map(row => <Skeleton key={row} className="h-14 w-full"/>)}</div> : preview === 'error' ? <Alert variant="destructive"><AlertTitle>记录加载失败</AlertTitle><AlertDescription>这是失败状态预览。<Button variant="outline" onClick={() => setPreview('normal')}>重试</Button></AlertDescription></Alert> : preview === 'empty' || files.length === 0 ? <Empty><EmptyHeader><EmptyTitle>没有匹配的分析记录</EmptyTitle><EmptyDescription>清除搜索，或选择文件开始分析。</EmptyDescription></EmptyHeader><Button variant="outline" onClick={() => { setSearch(''); setPreview('normal'); }}>显示演示记录</Button></Empty> : <div className="table-scroll"><table className="file-table"><thead><tr><th>文件</th><th>判断</th><th>证据</th><th>耗时</th><th><span className="sr-only">操作</span></th></tr></thead><tbody>{files.map(file => <tr key={file.name}><td><div className="file-identity"><File aria-hidden="true"/><div><a href={`/${direction}/detail/?file=${demoFiles.indexOf(file)}`}>{file.name}</a><small>{file.architecture} <span>/</span> {file.size}</small></div></div></td><td><span className="result-label" data-status={file.status}>{file.status}</span></td><td>{file.evidence}</td><td className="numeric">{file.time}</td><td><a href={`/${direction}/detail/?file=${demoFiles.indexOf(file)}`} className="row-open" aria-label={`查看 ${file.name} 检测详情`}><ArrowUpRight aria-hidden="true"/></a></td></tr>)}</tbody></table></div>}
        </section>
      </section>
      <aside className="workspace-context"><section><Layers aria-hidden="true"/><h2>五引擎，独立证据</h2><p>将规则、模型与特征库的结果放在同一上下文中复核。</p><ul className="engine-checklist">{['SHA-256 精确哈希', 'TLSH / SSDeep 相似性', 'YARA-X 规则', 'ClamAV 病毒特征库', 'LightGBM 静态模型'].map(name => <li key={name}><Check aria-hidden="true"/>{name}</li>)}</ul><span className="subtle-note">此处展示能力范围，非服务可用性探针。</span></section>
        <section className="interpretation"><h2>先看证据，再下结论</h2><p>未命中不等于安全。超时、解析失败和模型不适用都会保留，便于复核。</p><a href={`/${direction}/detail/`}>查看示例检测详情<ArrowUpRight aria-hidden="true"/></a></section>
      </aside>
    </div>
    <div className="preview-controls"><label htmlFor={`preview-${direction}`}>原型状态预览</label><select id={`preview-${direction}`} value={preview} onChange={event => setPreview(event.target.value as PreviewState)}><option value="normal">正常</option><option value="loading">加载中</option><option value="empty">空状态</option><option value="error">失败</option></select><span>仅用于视觉与交互评审</span></div>
  </>;
}
