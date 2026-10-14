'use client';
import { useRef, useState } from 'react';
import { ArrowUpRight, Plus, File, Check, ArrowRight, Search, ArrowDown, ArrowUp } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Field, FieldLabel } from '@/components/ui/field';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { Skeleton } from '@/components/ui/skeleton';
import { Empty, EmptyHeader, EmptyTitle, EmptyDescription } from '@/components/ui/empty';
import { demoFiles } from './demo-data';

export function CalmWorkspace({ direction }: { direction: 'paper' | 'linen' }) {
  const [selected, setSelected] = useState<string[]>([]);
  const [search, setSearch] = useState('');
  const [preview, setPreview] = useState('normal');
  const [step, setStep] = useState(-1);
  const [running, setRunning] = useState(false);
  const [notice, setNotice] = useState('');
  const picker = useRef<HTMLInputElement>(null);
  const files = demoFiles.filter(file => file.name.toLowerCase().includes(search.toLowerCase()));
  async function demonstrate() {
    setRunning(true); setNotice('演示扫描进行中…');
    for (let index = 0; index < 5; index++) {
      setStep(index);
      await new Promise(resolve => setTimeout(resolve, 300));
    }
    setStep(5); setRunning(false); setNotice('演示完成。文件内容未读取，也未发送到检测服务。');
  }
  const previewControls = <div className="preview-controls"><label htmlFor={`preview-${direction}`}>原型状态预览</label><select id={`preview-${direction}`} value={preview} onChange={event=>setPreview(event.target.value)}><option value="normal">正常</option><option value="loading">加载中</option><option value="empty">空状态</option><option value="error">失败</option></select></div>;
  return <>
    <section className="calm-intro" id={direction === 'linen' ? 'linen-start' : undefined}><div className="calm-intro-copy"><span className="calm-eyebrow">文件静态分析</span><h1>从一个文件，<br/>看清每一条证据。</h1><p>让五个引擎各自判断。<br/>把结论、分歧和未完成的检测，一起留下。</p></div>
      <div className="file-composer" data-running={running}><div className="composer-top"><span>开始分析</span><span>仅静态 · 演示</span></div>
        <div className="composer-content"><div className="file-emblem" aria-hidden="true"><File/><span/><span/><span/></div><h2>{selected.length ? '文件已就绪' : '你的下一个文件，放在这里。'}</h2><p>{selected.length ? `已选择：${selected.join('、')}` : '选择 EXE、DLL 或 SYS，展开检测证据。'}</p></div>
        <input type="file" hidden ref={picker} aria-label="选择演示文件" accept=".exe,.dll,.sys" multiple onChange={event => { setSelected(Array.from(event.target.files ?? []).map(file => file.name)); setNotice('已选择文件名。原型不会读取或上传文件内容。'); }}/>
        <div className="composer-actions"><Button variant="outline" onClick={() => picker.current?.click()}><Plus aria-hidden="true"/>选择文件</Button><span>最多 20 个 · 单文件 16 MB</span><Button onClick={demonstrate} disabled={running}>{running ? '演示扫描中…' : '演示扫描'}<ArrowRight aria-hidden="true"/></Button></div>
        <ol className="calm-engine-steps" aria-label="演示引擎进度">{['SHA-256','相似性','YARA-X','ClamAV','LightGBM'].map((name,index) => <li key={name} data-phase={step > index ? 'done' : step === index ? 'active' : 'idle'}>{step > index ? <Check aria-hidden="true"/> : <i aria-hidden="true"/>}{name}</li>)}</ol>
        <p className="calm-notice" role="status" aria-live="polite">{notice || '原型仅展示交互。文件不会被读取或上传。'}</p>
      </div>
      {direction === 'linen' ? <a href="#linen-records" className="linen-section-link">查看最近分析<ArrowDown aria-hidden="true"/></a> : null}
    </section>
    <section className="calm-history" id={direction === 'linen' ? 'linen-records' : undefined}><div className="calm-history-heading"><div><h2>最近的分析</h2><p>合成演示记录，所有判断都可以展开。</p></div><Field orientation="horizontal"><FieldLabel htmlFor={`search-${direction}`} className="sr-only">搜索文件名</FieldLabel><Search aria-hidden="true"/><Input id={`search-${direction}`} placeholder="搜索文件名…" autoComplete="off" value={search} onChange={event => setSearch(event.target.value)}/></Field></div>
      {preview === 'loading' ? <div aria-label="记录加载中" className="skeleton-list">{[0,1,2].map(n=><Skeleton key={n} className="h-14 w-full"/>)}</div> : preview === 'error' ? <Alert variant="destructive"><AlertTitle>记录加载失败</AlertTitle><AlertDescription>这是失败状态预览。<Button variant="outline" onClick={()=>setPreview('normal')}>重试</Button></AlertDescription></Alert> : preview === 'empty' || files.length === 0 ? <Empty><EmptyHeader><EmptyTitle>没有匹配的分析记录</EmptyTitle><EmptyDescription>清除搜索，或选择文件开始分析。</EmptyDescription></EmptyHeader><Button variant="outline" onClick={()=>{setSearch('');setPreview('normal');}}>显示演示记录</Button></Empty> : <ul className="calm-file-list">{files.map(file=><li key={file.name}><a href={`/${direction}/detail/?file=${demoFiles.indexOf(file)}`} aria-label={`查看 ${file.name} 检测详情`}><File className="history-file-icon" aria-hidden="true"/><div className="calm-file-name"><strong>{file.name}</strong><span>{file.architecture} · {file.size}</span></div><span className="result-label" data-status={file.status}>{file.status}</span><span className="numeric calm-file-time">{file.time}</span><ArrowUpRight className="history-open" aria-hidden="true"/></a></li>)}</ul>}
      <p className="calm-history-note">未命中不代表安全。超时、失败与模型不适用，始终单独保留。</p>
      {direction === 'linen' ? <><div className="linen-history-footer">{previewControls}<a href="#linen-start" className="linen-section-link">返回开始分析<ArrowUp aria-hidden="true"/></a></div><p className="linen-state-footer">静态分析，不执行文件。视觉原型，未连接检测 API。</p></> : null}
    </section>
    {direction !== 'linen' ? previewControls : null}
  </>;
}
