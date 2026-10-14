import { ArrowUpRight } from 'lucide-react';
import { Badge } from '@/components/ui/badge';

export function CalmShell({ direction, view, children }: { direction: 'paper' | 'linen'; view: 'workspace' | 'detail'; children: React.ReactNode }) {
  return <div className={`prototype-shell calm-shell theme-${direction}`}>
    <a href="#main-content" className="skip-link">跳到主要内容</a>
    <header className="calm-header"><a href={`/${direction}/`} className="calm-brand" translate="no">aegis<span>AV</span><i aria-hidden="true"/></a>
      <nav aria-label="主要导航"><a href={`/${direction}/`} aria-current={view === 'workspace' ? 'page' : undefined}>工作台</a><a href={`/${direction}/detail/`} aria-current={view === 'detail' ? 'page' : undefined}>示例详情</a><a href="/">切换方案<ArrowUpRight aria-hidden="true"/></a></nav>
      <Badge variant="outline">演示数据</Badge></header>
    <main id="main-content" tabIndex={-1} className="main-content calm-main">{children}</main>
    <footer className="calm-footer"><span>静态分析，不执行文件。</span><span>视觉原型 · 未连接检测 API</span></footer>
  </div>;
}
