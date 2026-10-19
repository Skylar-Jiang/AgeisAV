import { Badge } from '@/components/ui/badge';

export function CalmShell({ view, children, demo = false }: { view: 'workspace' | 'detail' | 'tasks' | 'history' | 'assets' | 'statistics' | 'behavior'; children: React.ReactNode; demo?: boolean }) {
  const linenWorkspace = view === 'workspace';
  return <div className={`calm-shell theme-linen${linenWorkspace ? ' linen-workspace' : ''}`}>
    <a href="#main-content" className="skip-link">跳到主要内容</a>
    <header className="calm-header"><a href="/linen/" className="calm-brand" translate="no">aegis<span>AV</span><i aria-hidden="true"/></a>
      <nav aria-label="主要导航"><a href={demo ? '/linen/demo/' : '/linen/'} aria-current={view === 'workspace' ? 'page' : undefined}>工作台</a>{demo ? <><a href="/linen/demo/detail/" aria-current={view === 'detail' ? 'page' : undefined}>示例详情</a><a href="/linen/">真实工作台</a></> : <><a href="/linen/tasks/" aria-current={view === 'tasks' ? 'page' : undefined}>批量任务</a><a href="/linen/history/" aria-current={view === 'history' ? 'page' : undefined}>历史记录</a><a href="/linen/assets/" aria-current={view === 'assets' ? 'page' : undefined}>规则与模型</a><a href="/linen/behavior/" aria-current={view === 'behavior' ? 'page' : undefined}>行为证据</a><a href="/linen/statistics/" aria-current={view === 'statistics' ? 'page' : undefined}>运行统计</a><a href="/linen/demo/">演示预览</a></>}</nav>
      <Badge variant="outline">{demo ? '演示数据' : view === 'behavior' ? '本地离线回放' : '本地静态分析'}</Badge></header>
    <main id="main-content" tabIndex={-1} className="main-content calm-main">{children}</main>
    {!linenWorkspace ? <footer className="calm-footer"><span>静态分析，不执行文件。</span><span>{demo ? '合成演示 · 未连接检测 API' : '真实 API · 未完成检测不计阴性'}</span></footer> : null}
  </div>;
}
