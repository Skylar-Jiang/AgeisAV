import { Shield, ScanLine, FileSearch, ArrowLeftRight } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

export type Direction = 'slate' | 'obsidian' | 'paper' | 'linen';
export function PrototypeShell({ direction, view, children }: { direction: Direction; view: 'workspace' | 'detail'; children: React.ReactNode }) {
  const name = direction === 'slate' ? 'Slate' : 'Obsidian';
  return <div className={cn('prototype-shell dark', `theme-${direction}`)}>
    <a href="#main-content" className="skip-link">跳到主要内容</a>
    <aside className="app-navigation">
      <a href={`/${direction}/`} className="brand"><Shield aria-hidden="true"/><span translate="no">AegisAV<small>静态分析平台</small></span></a>
      <div className="nav-context"><span className="context-dot"/>研究工作空间<span className="context-shortcut">本地</span></div>
      <nav aria-label="主要导航">
        <a href={`/${direction}/`} aria-current={view === 'workspace' ? 'page' : undefined}><ScanLine aria-hidden="true"/>扫描工作台</a>
        <a href={`/${direction}/detail/`} aria-current={view === 'detail' ? 'page' : undefined}><FileSearch aria-hidden="true"/>检测详情</a>
        <a href="/"><ArrowLeftRight aria-hidden="true"/>对比视觉方案</a>
      </nav>
      <div className="nav-foot"><Shield aria-hidden="true"/><div>仅静态分析<small>不执行上传文件</small></div></div>
    </aside>
    <div className="app-main">
      <header className="app-topbar"><span>{view === 'workspace' ? '文件分析 / 扫描工作台' : '文件分析 / 检测详情'}</span><div><Badge variant="outline">{name} 方案</Badge><Badge variant="secondary">演示数据</Badge></div></header>
      <main id="main-content" className="main-content" tabIndex={-1}>{children}</main>
      <footer className="app-footer"><span>AegisAV · 五引擎证据协同</span><span>设计原型，未连接检测 API</span></footer>
    </div>
  </div>;
}
