export function CostFigure({ engines, demo = false }: { engines: { id: string; name: string; time: number }[]; demo?: boolean }) {
  const maximum = Math.max(1, ...engines.map(engine => engine.time));
  return <figure className="cost-figure"><figcaption><h2>扫描开销</h2><span>{demo ? '演示耗时' : '引擎耗时'} · ms</span></figcaption>
    <div className="chart-ticks" aria-hidden="true"><span>0</span><span>{(maximum / 2).toLocaleString('zh-CN', { maximumFractionDigits: 1 })}</span><span>{maximum.toLocaleString('zh-CN', { maximumFractionDigits: 1 })}</span></div>
    <ol>{engines.map(engine => <li key={engine.id}><span>{engine.name}</span><div className="bar-track"><div className="bar-fill" style={{ width: `${Math.max(0, Math.min(100, engine.time / maximum * 100))}%` }}/></div><strong>{engine.time.toLocaleString('zh-CN', { maximumFractionDigits: 1 })}</strong></li>)}</ol>
    <p>各引擎可能并行运行，不能求和作为总扫描时延。</p></figure>;
}
