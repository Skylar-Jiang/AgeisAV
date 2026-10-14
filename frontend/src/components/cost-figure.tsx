import { demoEngines } from './demo-data';
export function CostFigure({ engines = demoEngines }: { engines?: typeof demoEngines }) {
  return <figure className="cost-figure"><figcaption><h2>扫描开销</h2><span>演示耗时 · ms</span></figcaption>
    <div className="chart-ticks" aria-hidden="true"><span>0</span><span>1,200</span><span>2,400</span></div>
    <ol>{engines.map(engine => <li key={engine.id}><span>{engine.name}</span><div className="bar-track"><div className="bar-fill" style={{ width: `${engine.time === 0 ? 0 : Math.max(1, engine.time / 24)}%` }}/></div><strong>{engine.time.toLocaleString('zh-CN')}</strong></li>)}</ol>
    <p>各引擎可能并行运行，不能求和作为总扫描时延。</p></figure>;
}
